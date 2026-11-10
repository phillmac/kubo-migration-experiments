"""Local-only proof binding, read-only wiring, cancellation, and receipt tests."""
from contextlib import contextmanager, ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = module('verify_rhea_post_reboot.py', 'post_reboot_proof_tests')
c = module('run_rhea_full_clone_steps.py', 'post_reboot_original_controller_tests')
comparison = module('run_rhea_integrated_verification_profile.py', 'post_reboot_comparison_tests')
equivalence = module('run_rhea_full_clone_verification_profile.py', 'post_reboot_equivalence_tests')


def evidence(name):
    return json.loads((ROOT / 'docs/evidence' / name).read_bytes())


def context():
    bundle = evidence('rhea-full-clone-pacing-certified-20261104.json')
    state = evidence('rhea-bounded-adoption-state-after-20261106.json')
    identity = {'boot_id': 'fixture-new-boot', 'kernel': 'fixture-new-kernel', 'observed_unix': 900.0,
        'reader': {'process': {'pid': 41, 'start_ticks': 11, 'boot_id': 'fixture-new-boot'}},
        'production': {'production_process': {'pid': 42, 'start_ticks': 12, 'boot_id': 'fixture-new-boot'},
                       'rc_server': {'process': {'pid': 43, 'start_ticks': 13, 'boot_id': 'fixture-new-boot'}}},
        'protected_inputs': {str(m.INSTALL): {'sha256': 'a' * 64, 'bytes': 17},
                             str(m.HEALTH): {'sha256': m.HEALTH_SHA, 'bytes': 19}}}
    original = SimpleNamespace(BUCKET='fixed-lab-bucket', PREFIX='rhea/pebbleds/',
        LEDGER_SHA256='38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96')
    w = SimpleNamespace(LEDGER=m.TRUST / 'wasabi-lab-baseline-version-ledger-20261102.jsonl.gz',
                        load_ledger=Mock(return_value=object()))
    raw = m.canonical(identity)
    return {'c': c, 'w': w, 'v': original, 'bundle': bundle, 'cert': state['checkpoint'],
            'adopted_state': state, 'identity': identity, 'identity_raw': raw,
            'identity_sha256': m.sha(raw)}


def observation(ctx, observed=1001.0):
    identity = ctx['identity']
    return {'schema': 1, 'scope': 'post-reboot-health', 'observed_unix': observed,
        'boot_id': identity['boot_id'], 'kernel': identity['kernel'], 'identity_sha256': ctx['identity_sha256'],
        'state_sha256': m.STATE_SHA, 'checkpoint_sha256': m.CERT_SHA, 'pins_sha256': m.PINS_SHA,
        'generation': 9, 'rewrites': 5, 'pending': None, 'state': c.checkpoint_state(ctx['cert']),
        'reader_process': copy.deepcopy(identity['reader']['process']),
        'production_service_process': copy.deepcopy(identity['production']['production_process']),
        'production_rc_process': copy.deepcopy(identity['production']['rc_server']['process']),
        'production_rc_checked': True, 'writer_mount_and_socket_absent': True,
        'reader_and_writer_caches_retained': True, 'protected_anchors_unchanged': True,
        'writer': {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                   'Result': 'success', 'ExecMainStatus': '0'},
        'production_disk_cache': {'bytesUsed': 1234, 'uploadsQueued': 0,
            'uploadsInProgress': 0, 'erroredFiles': 0, 'outOfSpace': False}}


def retained_fixture(ctx):
    measured = evidence('rhea-bounded-adoption-acceptance-metrics-20261106.json')
    metrics = {'schema': 1, 'scope': m.SCOPE + '-metrics', 'identity_sha256': ctx['identity_sha256'],
        **{key: measured[key] for key in ('metrics', 'enumeration', 'listing_guard', 'sdk', 'process_peak_rss_kib')},
        'invocation': {'started_unix': 1002.0, 'finished_unix': 1080.0}}
    result = evidence('rhea-bounded-adoption-acceptance-result-20261106.json')
    result['verified_unix'] = 1040.0
    intent = m.intent_value(ctx, m.source_pins(ctx), observation(ctx), 1000.0)
    blobs = {'intent.json': m.canonical(intent), 'result.json': m.canonical(result),
             'metrics.json': m.canonical(metrics)}
    done = dict(intent, scope=m.SCOPE + '-completed', verified=True, completed_unix=1082.0,
        intent_sha256=m.sha(blobs['intent.json']), result_sha256=m.sha(blobs['result.json']),
        metrics_sha256=m.sha(blobs['metrics.json']), semantic_projection_sha256=m.PROJECTION_SHA,
        host_after=observation(ctx, 1081.0), wall_seconds=metrics['metrics']['wall_seconds'],
        overall_seconds=82.0, workers_drained=True, sdk_clients_closed=True)
    blobs['completed.json'] = m.canonical(done)
    return blobs


def reseal(blobs):
    done = json.loads(blobs['completed.json'])
    for field, name in (('intent_sha256', 'intent'), ('result_sha256', 'result'), ('metrics_sha256', 'metrics')):
        done[field] = m.sha(blobs[name + '.json'])
    blobs['completed.json'] = m.canonical(done)
    return blobs


class RetainedProofTests(unittest.TestCase):
    def setUp(self):
        self.health_pin = patch.object(m, 'HEALTH_SHA', 'b' * 64)
        self.health_pin.start()
        self.addCleanup(self.health_pin.stop)

    def test_exact_historical_result_and_metrics_validate_without_io(self):
        ctx = context()
        blobs = retained_fixture(ctx)
        with patch.object(m, 'read_protected', side_effect=AssertionError('filesystem forbidden')), \
                patch.object(m, 'exact_module', side_effect=AssertionError('imports forbidden')):
            done = m.validate_retained(ctx, blobs, comparison=comparison, equivalence=equivalence)
        self.assertEqual(done['semantic_projection_sha256'], m.PROJECTION_SHA)
        self.assertFalse(done['journal_mutated'] or done['pebble_open_performed'])

    def test_raw_and_canonical_writer_pins_are_preserved_separately(self):
        ctx = context()
        refs = m.expected_references(ctx)
        writer = ctx['bundle']['evidence']['000009-step-writer']
        self.assertNotEqual(writer['sha256'], writer['canonical_sha256'])
        self.assertEqual(refs['000009-step-writer']['sha256'], writer['sha256'])
        self.assertEqual(len(refs), 13)
        self.assertEqual(set(refs['000009-step-writer']), {'path', 'sha256', 'bytes'})
        ctx['bundle']['evidence']['000009-step-writer']['path'] = 'different/writer.json'
        with self.assertRaisesRegex(RuntimeError, 'reference differs'):
            m.expected_references(ctx)

    def test_resealed_semantic_counter_source_health_and_flag_changes_are_refused(self):
        cases = (
            ('result.json', lambda v: v.update(pebble_reopen_verified=True)),
            ('result.json', lambda v: v.update(sst_count=1)),
            ('metrics.json', lambda v: v['metrics']['s3']['get_object'].update(calls=9)),
            ('metrics.json', lambda v: v['enumeration'].update(workers=1)),
            ('completed.json', lambda v: v['source_sha256'].update(verifier='0' * 64)),
            ('completed.json', lambda v: v.update(workers_drained=False)),
            ('completed.json', lambda v: v['host_after']['reader_process'].update(pid=99)),
            ('completed.json', lambda v: v['host_after']['production_disk_cache'].update(uploadsQueued=1)),
            ('completed.json', lambda v: v['host_after']['writer'].update(MainPID='999')),
            ('intent.json', lambda v: v.update(journal_mutated=0)),
        )
        for name, mutate in cases:
            with self.subTest(name=name, mutate=mutate):
                ctx = context()
                blobs = retained_fixture(ctx)
                value = json.loads(blobs[name])
                mutate(value)
                blobs[name] = m.canonical(value)
                reseal(blobs)
                with self.assertRaises((RuntimeError, AssertionError)):
                    m.validate_retained(ctx, blobs, comparison=comparison, equivalence=equivalence)

    def test_unknown_or_noncanonical_receipt_is_refused(self):
        ctx = context()
        blobs = retained_fixture(ctx)
        for changed in (dict(blobs, extra=b'{}\n'), dict(blobs, **{'result.json': blobs['result.json'] + b' '})):
            with self.assertRaises(RuntimeError):
                m.validate_retained(ctx, changed, comparison=comparison, equivalence=equivalence)


@contextmanager
def local_directory():
    with tempfile.TemporaryDirectory() as name, ExitStack() as stack:
        root = Path(name)
        ops = root / 'ops'
        ops.mkdir(mode=0o700)

        def protected(path, *, mode=0o600, missing=False):
            relative = path.relative_to(root)
            current = root
            for part in (None, *relative.parts):
                if part is not None:
                    current = current / part
                try:
                    info = current.lstat()
                except FileNotFoundError:
                    m.require(missing and current == path, 'protected ancestor is missing')
                    return None
                m.require(info.st_uid == os.getuid() and not stat.S_ISLNK(info.st_mode)
                          and not info.st_mode & 0o022, 'local path protection differs')
                if current != path:
                    m.require(stat.S_ISDIR(info.st_mode), 'local ancestor is not a directory')
            m.require(stat.S_IMODE(info.st_mode) == mode, 'protected leaf mode differs')
            m.require(stat.S_ISDIR(info.st_mode) if mode == 0o700 else
                      stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'protected leaf type differs')
            return info

        for key, value in {'OPS': ops, 'DIRECTORY': ops / 'verification', 'protected': protected,
                           'HEALTH_SHA': 'b' * 64}.items():
            stack.enter_context(patch.object(m, key, value))
        rt = SimpleNamespace(host=SimpleNamespace(locked=True), _sync_dir=Mock())
        yield SimpleNamespace(root=root, ops=ops, rt=rt, stack=stack)


class ReceiptTests(unittest.TestCase):
    def test_fresh_directory_and_exclusive_receipts_never_overwrite(self):
        with local_directory() as env:
            ctx = {'rt': env.rt}
            m.create_directory(ctx)
            m.write_new(ctx, 'intent.json', b'{}\n')
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                m.write_new(ctx, 'intent.json', b'changed')
            with self.assertRaisesRegex(RuntimeError, 'already attempted'):
                m.create_directory(ctx)
            self.assertEqual((m.DIRECTORY / 'intent.json').read_bytes(), b'{}\n')
            self.assertEqual(stat.S_IMODE((m.DIRECTORY / 'intent.json').stat().st_mode), 0o600)
            for name in ('../state.json', 'writer.json'):
                with self.assertRaises(RuntimeError):
                    m.write_new(ctx, name, b'{}\n')
            env.rt.host.locked = False
            with self.assertRaises(RuntimeError):
                m.write_new(ctx, 'result.json', b'{}\n')


class WiringTests(unittest.TestCase):
    @contextmanager
    def fixture(self, *, failure=None, cancelled=False, changed_after=False):
        with local_directory() as env:
            ctx = context()
            ctx['rt'] = env.rt
            events = []
            candidate = SimpleNamespace(__file__=str(m.SOURCES['verifier'][0]), **vars(ctx['v']))
            new_rt = SimpleNamespace(verifier=candidate, load_state=Mock(return_value=ctx['adopted_state']),
                cloud=Mock(side_effect=AssertionError('new runtime cloud forbidden')),
                guard=Mock(side_effect=AssertionError('writer guard forbidden')))
            inputs = {'previous': {'generation': 8}, 'expected': ctx['cert'], 'writer': {'action': 'step'},
                'created': {'fixture.sst': {'size': 1}}, 'metadata': {'LOCK': b''}, 'ledger_blob': b'fixture ledger',
                'reads': SimpleNamespace(unchanged=Mock(side_effect=lambda: events.append('inputs-unchanged')))}
            captured = evidence('rhea-bounded-adoption-acceptance-metrics-20261106.json')

            @contextmanager
            def cloud():
                events.append('cloud-enter')
                try:
                    yield object()
                finally:
                    events.append('cloud-close')
            env.rt.cloud = cloud
            observations = 0

            def observe(*args, **kwargs):
                nonlocal observations
                observations += 1
                events.append('health-' + str(observations))
                value = observation(ctx, time.time())
                if changed_after and observations == 2:
                    value['reader_process']['pid'] += 1
                return value
            health = SimpleNamespace(observe=Mock(side_effect=observe))
            guard = SimpleNamespace(audit=lambda: copy.deepcopy(captured['listing_guard']))
            compare = SimpleNamespace(Cancellation=comparison.Cancellation, cancelled=comparison.cancelled,
                GuardedClient=Mock(return_value=guard), validate_pass=comparison.validate_pass)

            def profile(verifier, guarded, ledger, previous, writer, metadata, created, mode, parent_sha, **kwargs):
                events.append('verify-four')
                self.assertIs(verifier, candidate)
                self.assertIs(guarded, guard)
                self.assertEqual((previous, writer, metadata, created, mode),
                    (inputs['previous'], inputs['writer'], inputs['metadata'], inputs['created'], 'final'))
                self.assertEqual(parent_sha, c.digest(inputs['previous']))
                self.assertEqual(kwargs['enumeration_workers'], 4)
                self.assertEqual(set(kwargs), {'metrics', 'enumeration_workers', 'enumeration_stop', 'enumeration_metrics'})
                kwargs['metrics'].update(copy.deepcopy(captured['metrics']))
                kwargs['metrics']['wall_seconds'] = 0.0
                kwargs['enumeration_metrics'].update(copy.deepcopy(captured['enumeration']))
                if failure:
                    raise failure
                if cancelled:
                    kwargs['enumeration_stop'].set()
                value = evidence('rhea-bounded-adoption-acceptance-result-20261106.json')
                value['verified_unix'] = time.time()
                return value, kwargs['metrics']

            profiler = SimpleNamespace(profile_verify_generation=Mock(side_effect=profile))
            modules = {m.SOURCES['controller'][0]: SimpleNamespace(Runtime=lambda: new_rt),
                m.HELPERS['comparison'][0]: compare, m.HELPERS['profiler'][0]: profiler,
                m.HELPERS['equivalence'][0]: equivalence}
            original_read = m.read_protected

            def read(path):
                return c.canonical(ctx['adopted_state']) if path == m.STATE else original_read(path)

            for key, value in {'read_protected': read, 'exact_module': lambda path, digest, name: modules[path],
                    'load_inputs': lambda ctx: inputs, 'unchanged_sources': Mock(side_effect=lambda *args: events.append('sources')),
                    'sdk_observation': lambda client: captured['sdk']}.items():
                env.stack.enter_context(patch.object(m, key, value))
            signals = env.stack.enter_context(patch.object(m.signal, 'signal', return_value=signal.SIG_DFL))
            alarm = env.stack.enter_context(patch.object(m.signal, 'alarm'))
            env.stack.enter_context(patch.object(m.resource, 'setrlimit'))
            yield SimpleNamespace(env=env, ctx=ctx, health=health, events=events, new_rt=new_rt,
                                  profiler=profiler, signals=signals, alarm=alarm)

    def test_one_final_proof_uses_original_cloud_and_closes_before_after_health(self):
        with self.fixture() as f:
            result = m.verify_current(f.health, f.ctx)
            self.assertTrue(result['verified'])
            self.assertEqual(f.profiler.profile_verify_generation.call_count, 1)
            f.new_rt.cloud.assert_not_called()
            f.new_rt.guard.assert_not_called()
            self.assertLess(f.events.index('verify-four'), f.events.index('cloud-close'))
            self.assertLess(f.events.index('cloud-close'), f.events.index('health-2'))
            done = m.json_object((m.DIRECTORY / 'completed.json').read_bytes())
            self.assertFalse(done['journal_mutated'] or done['checkpoint_replaced'] or done['pebble_open_performed'])
            self.assertTrue(done['workers_drained'] and done['sdk_clients_closed'])
            self.assertEqual(f.alarm.call_args_list[-1].args, (0,))
            self.assertEqual(f.signals.call_count, 8)

    def test_sdk_failure_cancel_or_changed_identity_never_complete_or_retry(self):
        error = OSError('credential-looking text must not enter evidence')
        for options in ({'failure': error}, {'cancelled': True}, {'changed_after': True}):
            with self.subTest(options=options), self.fixture(**options) as f:
                with self.assertRaises((OSError, RuntimeError)) as raised:
                    m.verify_current(f.health, f.ctx)
                if options.get('failure'):
                    self.assertIs(raised.exception, error)
                self.assertEqual(f.profiler.profile_verify_generation.call_count, 1)
                self.assertIn('cloud-close', f.events)
                self.assertFalse((m.DIRECTORY / 'completed.json').exists())
                self.assertFalse((m.DIRECTORY / 'result.json').exists())
                text = (m.DIRECTORY / 'failure.json').read_text()
                self.assertNotIn(str(error), text)
                self.assertEqual(f.alarm.call_args_list[-1].args, (0,))

    def test_source_mismatch_refuses_before_cloud_or_receipt_directory(self):
        with self.fixture() as f, patch.object(m, 'unchanged_sources', side_effect=RuntimeError('source changed')):
            with self.assertRaisesRegex(RuntimeError, 'source changed'):
                m.verify_current(f.health, f.ctx)
            self.assertFalse(m.DIRECTORY.exists())
            self.assertNotIn('cloud-enter', f.events)
            f.profiler.profile_verify_generation.assert_not_called()

    def test_signal_setup_failure_restores_installed_handlers(self):
        stop = comparison.Cancellation()
        with patch.object(m.signal, 'signal', return_value=signal.SIG_DFL) as signals, \
                patch.object(m.signal, 'alarm') as alarm, \
                patch.object(m.resource, 'setrlimit', side_effect=OSError('fixture limit failure')):
            with self.assertRaises(OSError):
                with m.deadline(stop):
                    self.fail('failed setup entered protected work')
            self.assertEqual(signals.call_count, 8)
            alarm.assert_called_once_with(0)


if __name__ == '__main__':
    unittest.main()
