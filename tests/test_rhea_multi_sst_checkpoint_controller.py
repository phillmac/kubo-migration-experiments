"""Offline only: fake host + real independent cloud verifier/decoder/finalizer.

The synthetic anchor patch is confined to test memory; production pins/CLI have
no test token or bypass. No subprocess or network is used by the fake host.
"""
import base64
from contextlib import ExitStack, contextmanager
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_checkpoint_controller as c
import rhea_multi_sst_recovery_inspector as recovery

spec = importlib.util.spec_from_file_location('controller_cloud_fixtures', ROOT / 'tests/test_verify_rhea_multi_sst_candidate.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def identity(pid):
    return {'pid': pid, 'start_ticks': 900 + pid, 'boot_id': '12345678-1234-1234-1234-123456789abc',
            'exe_sha256': c.raw_sha(b'offline synthetic executable')}


def go_files(report):
    files = {'pending.json': {'schema': report['schema'], 'phase': 'executing', 'request': report['request']},
             'closed.json': report}
    for index, unit in enumerate(report['units'], 1):
        before = {key: unit[prefix + 'before'] for key, prefix in (
            ('marked', 'marked_'), ('files', 'sst_files_'), ('bytes', 'sst_bytes_'),
            ('inventory_sha256', 'sst_inventory_sha256_'))}
        before['format'] = unit['before_format']
        files[f'unit-{index:03d}-intent.json'] = {'index': index, 'before': before, 'picker_plan': unit['picker_plan']}
        files[f'unit-{index:03d}-receipt.json'] = unit
    return {name: base64.b64encode(c.canonical(value)).decode('ascii') for name, value in files.items()}


class FakeHost:
    version = c.ADAPTER_VERSION

    def __init__(self):
        self.fixture = fixtures.BatchFixture('before-markers')
        self.calls, self.writer_calls = [], 0
        self.locked = False
        self.reader = identity(100)
        self.writer_identity = identity(200)
        self.source_process = identity(300)
        self.guards = {key: c.raw_sha(('offline fixture ' + key).encode()) for key in c.GUARD_KEYS}
        self.guards.update(checkpoint=c.digest(self.fixture.previous), ledger=c.verifier.proof.LEDGER_SHA256)
        self.resources = dict(cache_bytes=0, free_bytes=c.verifier.LIMITS['minimum_free_bytes'],
                              queue_bytes=0, queue_files=0, errors=0, transferring=0)
        self.intent = dict(schema=2, generation=14, unit_count=2, previous_checkpoint=self.fixture.previous,
            previous_checkpoint_sha256=c.digest(self.fixture.previous), guards=self.guards,
            source_pins_sha256=c.digest(c.SOURCE_PINS), adapter_version=self.version,
            deployment_sha256=self.guards['deployment'], admission_sha256=c.raw_sha(b'offline admission fixture'),
            go_binary_sha256=self.source_process['exe_sha256'],
            request=self.fixture.report['request'], reader_identity=self.reader)
        old = self.fixture.previous['remote_metadata']
        # Exact old metadata payloads, including objects no longer latest.
        old_bytes = {name: self.fixture.s3.get_object(Bucket=c.verifier.BUCKET,
                     Key=c.verifier.PREFIX + name, VersionId=pin['version_id'])['Body'].read()
                     for name, pin in old.items()}
        self.writer = dict(report=self.fixture.report, source_process=self.source_process,
            binary_sha256=self.source_process['exe_sha256'], exit_code=0, stopped=True,
            monitor_complete=True, health=self.resources, go_files=go_files(self.fixture.report))
        self.snapshot = dict(metadata=c.encode_metadata(self.fixture.metadata), previous_metadata=c.encode_metadata(old_bytes),
                             hashes=self.fixture.hashes, closed_report_sha256=c.digest(self.fixture.report), markers_withheld=True)
        report = dict(fixtures.state_fields(self.fixture.after, self.fixture.after), action='inspect',
                      compactions=[], sst_diff=fixtures.delta({}, {}),
                      io=dict(sst_write_bytes=0, metadata_write_bytes=0,
                              max_sst_write_bytes=c.verifier.MAX_OUTPUT, max_metadata_write_bytes=c.verifier.MAX_METADATA))
        self.reopened = dict(reader_identity=identity(400), report=report, metadata=c.encode_metadata(self.fixture.metadata))
        self.reject_admission = False
        self.partial_state_proven = True

    @contextmanager
    def exclusive(self):
        c.require(not self.locked, 'host busy')
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def authenticate_admission(self, intent):
        c.require(self.locked and not self.reject_admission and intent == self.intent, 'admission signature mismatch')
        self.calls.append('admission')

    def preflight(self, intent):
        self.calls.append('preflight')
        return dict(reader_identity=self.reader, locked=self.locked, writer_stopped=True)

    def protected_guards(self):
        return copy.deepcopy(self.guards)

    def queue_health(self):
        return copy.deepcopy(self.resources)

    def handoff(self, intent):
        self.calls.append('handoff')
        return dict(writer_identity=self.writer_identity, reader_stopped=True, markers_withheld=True,
                    binary_sha256=self.source_process['exe_sha256'])

    def run_go_monitored(self, request, monitor):
        monitor()
        self.calls.append('writer')
        self.writer_calls += 1
        return copy.deepcopy(self.writer)

    def snapshot_closed(self, writer):
        self.calls.append('snapshot')
        return copy.deepcopy(self.snapshot)

    def drain_stop(self, snapshot):
        self.calls.append('drain')
        return dict(health=copy.deepcopy(self.resources), writer_stopped=True, writer_identity=self.writer_identity)

    def cloud_read(self):
        self.calls.append('cloud-read')
        return self.fixture.s3

    def baseline_ledger(self):
        return self.fixture.ledger

    def publish_markers(self, before, metadata):
        self.calls.append('publish')
        self.fixture.s3.add(c.verifier.PREFIX + self.fixture.new_marker, metadata[self.fixture.new_marker], 'new-published-marker')
        return dict(before_sha256=c.digest(before), published=before['changed_markers'])

    def reopen_readonly(self):
        self.calls.append('reopen')
        return copy.deepcopy(self.reopened)


class Observer:
    """Read-only interface: has no writer, marker publisher or journal methods."""
    def __init__(self, host):
        self.host = host
        self.observations = dict(guards=host.protected_guards(), locked=True, writer_stopped=True,
            admission_verified=True, source_pins_sha256=host.intent['source_pins_sha256'],
            source_process=host.source_process, writer_identity=host.writer_identity)

    def exclusive_read_lock(self):
        return self.host.exclusive()

    def observe(self, intent):
        return copy.deepcopy(self.observations)

    def independent_snapshot(self):
        return dict(writer=copy.deepcopy(self.host.writer), snapshot=copy.deepcopy(self.host.snapshot),
                    partial_state_proven=self.host.partial_state_proven)

    def cloud_read(self):
        return self.host.fixture.s3

    def baseline_ledger(self):
        return self.host.fixture.ledger

    def reopen_observation(self):
        return copy.deepcopy(self.host.reopened)


class Interrupted(RuntimeError):
    pass


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        os.chmod(self.temp, 0o700)
        self.store = c.Store(self.temp)
        self.host = FakeHost()
        v, fixture = c.verifier, self.host.fixture
        self.stack.enter_context(patch.object(v, 'GENERATION13_SHA256', c.digest(fixture.previous)))
        self.stack.enter_context(patch.object(v.proof.base, 'EXPECTED_SSTS', len(fixture.baseline)))
        self.stack.enter_context(patch.object(v.proof.base, 'EXPECTED_SST_BYTES', sum(fixture.baseline.values())))
        self.stack.enter_context(patch.object(v.proof.base, 'EXPECTED_INVENTORY', v.proof.base.inventory_digest(fixture.baseline)))

    def run_engine(self, fail=None):
        def failpoint(phase):
            if phase == fail:
                raise Interrupted(phase)
        return c.Engine(self.store, self.host, failpoint).run(copy.deepcopy(self.host.intent))

    def read(self, name):
        return c.parse(self.store.read(name + '.json'))

    def test_two_units_real_two_proofs_and_reopen(self):
        cert = self.run_engine()
        self.assertEqual((cert['generation'], cert['batch_checkpoint_count'], cert['physical_rewrite_total']), (14, 1, 11))
        self.assertEqual(self.host.writer_calls, 1)
        self.assertNotEqual(self.read('before_proved')['proof_pass_id'], self.read('final_proved')['proof_pass_id'])
        self.assertEqual(self.host.calls.count('publish'), 1)
        order = [self.host.calls.index(x) for x in ('writer', 'snapshot', 'drain', 'publish', 'reopen')]
        self.assertEqual(order, sorted(order))
        with self.store.lock(existing=True):
            _, state = self.store.audit()
        self.assertEqual((state['generation'], state['pending']), (14, None))
        for path in Path(self.temp).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_one_unit_success_is_one_checkpoint_and_one_physical_rewrite(self):
        host, v = self.host, c.verifier
        fixture = host.fixture
        fixture.report, fixture.after, fixture.hashes = fixtures.make_report(
            fixture.before, ((1, 40, 117),), maximum=1)
        unused = v.PREFIX + '000041.sst'
        fixture.s3.latest.pop(unused)
        fixture.s3.history = {key: value for key, value in fixture.s3.history.items() if key[0] != unused}
        retained = v.PREFIX + '000002.sst'
        fixture.s3.deleted.pop(retained)
        fixture.s3.delete_history = {key: value for key, value in fixture.s3.delete_history.items() if key[0] != retained}
        fixture.s3.latest[retained] = fixture.s3.history[retained, 'base-000002.sst'][0]
        fixture.metadata[fixture.new_manifest] = fixtures.manifest(fixture.after, 49)
        fixture.s3.add(v.PREFIX + fixture.new_manifest, fixture.metadata[fixture.new_manifest], 'new-single-manifest')
        host.intent.update(unit_count=1, request=fixture.report['request'])
        host.writer.update(report=fixture.report, go_files=go_files(fixture.report))
        host.snapshot.update(metadata=c.encode_metadata(fixture.metadata), hashes=fixture.hashes,
                             closed_report_sha256=c.digest(fixture.report))
        host.reopened['metadata'] = c.encode_metadata(fixture.metadata)
        host.reopened['report'].update(fixtures.state_fields(fixture.after, fixture.after))
        certificate = self.run_engine()
        self.assertEqual((certificate['generation'], certificate['physical_rewrite_total']), (14, 10))

    def test_every_phase_failpoint_no_recovery_writer_or_mutation(self):
        # Each phase is durable. Interruption after any boundary never resumes.
        for phase in c.PHASES[1:]:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700)
                store = c.Store(directory)
                host = FakeHost()
                def stop(actual):
                    if actual == phase:
                        raise Interrupted(actual)
                with self.assertRaises(Interrupted):
                    c.Engine(store, host, stop).run(copy.deepcopy(host.intent))
                before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
                count = host.writer_calls
                outcome = recovery.inspect(directory, Observer(host))
                self.assertEqual(host.writer_calls, count)
                self.assertEqual(before, {p.name: p.read_bytes() for p in Path(directory).iterdir()})
                expected = recovery.CERTIFIABLE if phase in ('reopened', 'certified') else recovery.MANUAL
                self.assertEqual(outcome['decision'], expected, outcome)

    def test_replay_refused_even_after_success(self):
        self.run_engine()
        with self.assertRaisesRegex(c.Refusal, 'replay'):
            self.run_engine()
        self.assertEqual(self.host.writer_calls, 1)

    def test_exact_legacy_anchor_unpatched(self):
        raw = (ROOT / 'docs/evidence/rhea-batch2-000013-certificate-20261107.json').read_bytes()
        self.assertEqual(c.raw_sha(raw), '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774')
        with patch.object(c.verifier, 'GENERATION13_SHA256', c.raw_sha(raw)):
            self.assertEqual(c.verifier._predecessor(json.loads(raw), c.raw_sha(raw)), 1)
            with self.assertRaises(c.verifier.VerificationError):
                c.validate_intent(self.host.intent)

    def test_admission_version_identity_and_pin_mismatch_before_writer(self):
        cases = ('admission', 'version', 'identity', 'pin', 'guard', 'anchor', 'units')
        for case in cases:
            with self.subTest(case=case):
                host = FakeHost()
                if case == 'admission': host.reject_admission = True
                if case == 'version': host.version = 'uninstalled'
                if case == 'identity': host.intent['reader_identity'] = identity(101)
                if case == 'pin': host.intent['source_pins_sha256'] = '0' * 64
                if case == 'guard': host.guards['production_state'] = '0' * 64; host.intent = copy.deepcopy(host.intent); host.intent['guards']['production_state'] = '1' * 64
                if case == 'anchor': host.intent['previous_checkpoint_sha256'] = '0' * 64
                if case == 'units': host.intent['unit_count'] = True
                with self.assertRaises((c.Refusal, c.verifier.VerificationError)):
                    c.Engine(self.store, host).run(copy.deepcopy(host.intent))
                self.assertEqual(host.writer_calls, 0)

    def test_queue_and_free_space_bounds_prevent_writer(self):
        for key, value in [('cache_bytes', c.verifier.LIMITS['cache_bytes'] + 1), ('free_bytes', 1),
                           ('queue_bytes', c.verifier.LIMITS['backlog_bytes'] + 1), ('queue_files', 257),
                           ('errors', 1), ('free_bytes', True)]:
            with self.subTest(key=key):
                self.host.resources[key] = value
                with self.assertRaises(c.Refusal): self.run_engine()
                self.assertEqual(self.host.writer_calls, 0)
                self.host.resources[key] = FakeHost().resources[key]

    def test_monitor_checks_during_writer(self):
        def bad(request, monitor):
            self.host.resources['errors'] = 1
            monitor()
        self.host.run_go_monitored = bad
        with self.assertRaisesRegex(c.Refusal, 'bound'): self.run_engine()
        self.assertEqual(self.read('journal')['phase'], 'writer_intent')
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)

    def test_partial_first_or_second_commit_never_certified(self):
        for partial in (0, 1, 2):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700)
                host = FakeHost()
                host.writer['report'] = copy.deepcopy(host.writer['report'])
                host.writer['report'].update(closed=partial != 0, error='interrupted', stop_reason='recovery-required')
                host.writer['report']['units'] = host.writer['report']['units'][:partial]
                host.writer['go_files'] = go_files(host.writer['report'])
                with self.assertRaisesRegex(c.Refusal, 'partial'):
                    c.Engine(c.Store(directory), host).run(copy.deepcopy(host.intent))
                decision = recovery.inspect(directory, Observer(host))
                self.assertEqual(decision['decision'], recovery.RESTORE, decision)
                self.assertEqual(host.writer_calls, 1)
                self.assertNotIn('publish', host.calls)

    def test_lost_first_or_second_commit_receipt_stays_manual(self):
        for committed in (1, 2):
            with self.subTest(committed=committed), tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700)
                host = FakeHost()
                def lost(request, monitor):
                    host.writer_calls += 1
                    raise OSError('child exited after commit, report lost')
                host.run_go_monitored = lost
                with self.assertRaises(OSError):
                    c.Engine(c.Store(directory), host).run(copy.deepcopy(host.intent))
                self.assertEqual(recovery.inspect(directory, Observer(host))['decision'], recovery.MANUAL)
                self.assertEqual(host.writer_calls, 1)
                self.assertNotIn('publish', host.calls)

    def test_partial_without_independent_reconciliation_is_manual(self):
        self.host.writer['report'] = copy.deepcopy(self.host.writer['report'])
        self.host.writer['report']['closed'] = False
        self.host.partial_state_proven = False
        with self.assertRaises(c.Refusal): self.run_engine()
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)

    def test_missing_go_unit_receipt_is_manual(self):
        self.host.writer['go_files'].pop('unit-002-receipt.json')
        with self.assertRaisesRegex(c.Refusal, 'Go file receipts'): self.run_engine()
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)

    def test_snapshot_hash_or_lineage_mismatch(self):
        for field in ('hashes', 'previous_metadata', 'closed_report_sha256'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700)
                host = FakeHost()
                host.snapshot[field] = {} if field != 'closed_report_sha256' else '0' * 64
                with self.assertRaises((c.Refusal, c.verifier.VerificationError)):
                    c.Engine(c.Store(directory), host).run(copy.deepcopy(host.intent))
                self.assertNotIn('publish', host.calls)

    def test_data_uploads_must_drain(self):
        original = self.host.drain_stop
        def busy(snapshot):
            value = original(snapshot)
            value['health']['transferring'] = 1
            return value
        self.host.drain_stop = busy
        with self.assertRaisesRegex(c.Refusal, 'drained'): self.run_engine()
        self.assertNotIn('publish', self.host.calls)

    def test_marker_timeout_after_publication_is_uncertainty(self):
        original = self.host.publish_markers
        def uncertain(before, metadata):
            original(before, metadata)
            raise OSError('lost publication response')
        self.host.publish_markers = uncertain
        with self.assertRaises(OSError): self.run_engine()
        outcome = recovery.inspect(self.temp, Observer(self.host))
        self.assertEqual(outcome['decision'], recovery.MANUAL)
        self.assertEqual(outcome['phase'], 'marker_intent')
        self.assertEqual(self.host.calls.count('publish'), 1)
        self.assertFalse((Path(self.temp) / 'certified.json').exists())

    def test_final_cloud_changed_marker_rejected(self):
        original = self.host.publish_markers
        def wrong(before, metadata):
            value = original(before, metadata)
            self.host.fixture.s3.add(c.verifier.PREFIX + 'intruder', b'x', 'unexpected')
            return value
        self.host.publish_markers = wrong
        with self.assertRaises(c.verifier.VerificationError): self.run_engine()
        self.assertFalse((Path(self.temp) / 'certified.json').exists())

    def test_reused_proof_id_refuses_certification(self):
        with patch.object(c.verifier.secrets, 'token_hex', return_value='a' * 32):
            with self.assertRaisesRegex(c.verifier.VerificationError, 'reused'): self.run_engine()
        self.assertFalse((Path(self.temp) / 'certified.json').exists())

    def test_readonly_reopen_required(self):
        self.host.reopened['report']['io']['metadata_write_bytes'] = 1
        with self.assertRaises(c.verifier.VerificationError): self.run_engine()
        self.assertFalse((Path(self.temp) / 'certified.json').exists())

    def test_concurrent_run_and_inspection_refuse(self):
        with self.store.lock():
            other = c.Store(self.temp)
            with self.assertRaisesRegex(c.Refusal, 'concurrent'):
                with other.lock(): pass
            self.assertEqual(recovery.inspect(self.temp)['decision'], recovery.MANUAL)
        self.assertEqual(self.host.writer_calls, 0)

    def test_unauthorized_transition_and_stale_cas_refuse(self):
        with self.store.lock():
            state = self.store.begin(self.host.intent)
            with self.assertRaisesRegex(c.Refusal, 'unauthorized'):
                self.store.advance(c.digest(state), 'writer_intent', {})
            with self.assertRaisesRegex(c.Refusal, 'compare-and-swap'):
                self.store.advance('0' * 64, 'handoff_intent', {})

    def test_receipt_tampering_and_lost_receipt_are_manual(self):
        self.run_engine()
        path = Path(self.temp) / 'snapshot.json'
        original = path.read_bytes()
        path.write_bytes(b'{}\n')
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)
        path.write_bytes(original)
        path.unlink()
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)

    def test_orphan_stage_and_torn_atomic_rename_are_manual(self):
        with self.assertRaises(Interrupted): self.run_engine('writer_intent')
        for name in ('writer_closed.json', 'stage-004.json', 'journal.next'):
            path = Path(self.temp) / name
            path.write_bytes(b'{}\n')
            os.chmod(path, 0o600)
            self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)
            path.unlink()

    def test_crash_between_stage_fsync_and_journal_rename_is_manual(self):
        replace = c.os.replace
        calls = []
        def crash(source, target):
            calls.append(source)
            if len(calls) == 2:
                raise OSError('interrupted rename')
            return replace(source, target)
        with patch.object(c.os, 'replace', side_effect=crash), self.assertRaises(OSError):
            self.run_engine()
        self.assertTrue((Path(self.temp) / 'stage-001.json').exists())
        self.assertTrue((Path(self.temp) / 'journal.next').exists())
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)
        self.assertEqual(self.host.writer_calls, 0)

    def test_marker_receipt_fsync_failure_never_repeats_publication(self):
        put = self.store.put
        def fail(name, value):
            if name == 'markers_published.json':
                raise OSError('receipt fsync failed')
            return put(name, value)
        with patch.object(self.store, 'put', side_effect=fail), self.assertRaises(OSError):
            self.run_engine()
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)
        self.assertEqual(self.host.calls.count('publish'), 1)
        self.assertEqual(self.host.writer_calls, 1)

    def test_safe_readonly_inspection_is_idempotent(self):
        self.run_engine()
        files = {p.name: p.read_bytes() for p in Path(self.temp).iterdir()}
        for _ in range(2):
            decision = recovery.inspect(self.temp, Observer(self.host))
            self.assertEqual(decision['decision'], recovery.CERTIFIABLE, decision)
        self.assertEqual(files, {p.name: p.read_bytes() for p in Path(self.temp).iterdir()})
        self.assertEqual(self.host.writer_calls, 1)

    def test_missing_independent_prerequisites_are_manual(self):
        self.run_engine()
        self.assertEqual(recovery.inspect(self.temp)['decision'], recovery.MANUAL)
        for field in ('locked', 'writer_stopped', 'admission_verified', 'source_process', 'guards'):
            observer = Observer(self.host)
            observer.observations.pop(field)
            self.assertEqual(recovery.inspect(self.temp, observer)['decision'], recovery.MANUAL)

    def test_actual_retained_file_mismatch_is_manual(self):
        self.run_engine()
        self.host.snapshot = copy.deepcopy(self.host.snapshot)
        self.host.snapshot['hashes'] = {}
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)

    def test_unavailable_cloud_and_marker_version_change_are_manual(self):
        self.run_engine()
        observer = Observer(self.host)
        observer.cloud_read = lambda: (_ for _ in ()).throw(OSError('offline'))
        self.assertEqual(recovery.inspect(self.temp, observer)['decision'], recovery.MANUAL)
        self.host.fixture.s3.add(c.verifier.PREFIX + self.host.fixture.new_marker, b'', 'changed-marker-version')
        self.assertEqual(recovery.inspect(self.temp, Observer(self.host))['decision'], recovery.MANUAL)

    def test_file_and_directory_security(self):
        target = Path(self.temp) / 'file'
        target.write_bytes(b'{}\n')
        os.chmod(target, 0o644)
        with self.assertRaises(c.Refusal): self.store.read('file')
        target.unlink()
        target.symlink_to(ROOT / 'README.md')
        with self.assertRaises(c.Refusal): self.store.read('file')
        target.unlink()
        os.chmod(self.temp, 0o755)
        with self.assertRaises(c.Refusal): c.Store(self.temp)
        os.chmod(self.temp, 0o700)

    def test_installation_and_cli_fail_closed_no_adapter(self):
        self.assertIsNone(c.INSTALLED_ADAPTER_SHA256)
        self.assertIsNone(c.ADMISSION_PUBLIC_KEY_SHA256)
        with self.assertRaises(c.Refusal): c.installation_preflight()
        for args in (['apply'], ['apply', '--evidence', self.temp], ['preflight']):
            with self.subTest(args=args), patch('sys.stdout', new_callable=io.StringIO):
                if args[0] == 'preflight': self.assertEqual(c.main(args), 2)
                else:
                    with patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as caught:
                        c.main(args)
                    self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.host.writer_calls, 0)

    def test_inspection_cli_refuses_to_signal_success_without_observer(self):
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(c.main(['inspect', '--evidence', self.temp]), 2)
        self.assertEqual(json.loads(output.getvalue())['decision'], recovery.MANUAL)
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(recovery.main([self.temp]), 2)
        self.assertEqual(json.loads(output.getvalue())['decision'], recovery.MANUAL)
        self.assertEqual(self.host.writer_calls, 0)

    def test_source_pin_check_detects_mismatch(self):
        self.assertEqual(c.source_pins(ROOT), c.digest(c.SOURCE_PINS))
        with patch.object(c, 'SOURCE_PINS', {'scripts/verify_rhea_multi_sst_candidate.py': '0' * 64}):
            with self.assertRaisesRegex(c.Refusal, 'pin mismatch'): c.source_pins(ROOT)

    def test_provisioning_contract_never_grants_live_permission(self):
        manifest = dict(schema=2, scope='rhea-multi-sst-root-install', install=str(c.INSTALL),
            base_commit=c.BASE_COMMIT, adapter_version=c.ADAPTER_VERSION,
            source_pins_sha256=c.digest(c.SOURCE_PINS), guards=self.host.guards,
            boot_id=self.host.reader['boot_id'], artifacts={name: c.raw_sha(('offline ' + name).encode())
                for name in ('rhea_multi_sst_checkpoint_controller.py', 'rhea_multi_sst_recovery_inspector.py', 'host-adapter.py', 'writer', 'admission.pub')})
        self.assertEqual(c.validate_provisioning_manifest(manifest), c.digest(manifest))
        with self.assertRaises(c.Refusal): c.installation_preflight()
        for key, value in [('install', self.temp), ('base_commit', 'unreviewed'),
                           ('adapter_version', 'dynamic'), ('artifacts', {})]:
            bad = copy.deepcopy(manifest)
            bad[key] = value
            with self.assertRaises(c.Refusal): c.validate_provisioning_manifest(bad)


if __name__ == '__main__':
    unittest.main()
