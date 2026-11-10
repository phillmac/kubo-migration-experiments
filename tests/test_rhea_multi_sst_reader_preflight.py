"""Offline only. Archived real-shaped evidence; live children are always mocked."""
from contextlib import contextmanager
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_reader_preflight as r
import rhea_multi_sst_root_host_adapter as host
import rhea_multi_sst_signed_admission as admission


def fixture():
    directory = ROOT / 'docs/evidence'
    done_raw = (directory / 'rhea-batch2-reader-finalization-20261107.json').read_bytes()
    done = json.loads(done_raw)
    raw = (directory / 'rhea-batch2-fresh-health-20261110.json').read_bytes()
    report = json.loads(raw)
    mount = done['reader']['mount']
    line = ('87 29 0:73 / ' + r.READER_MOUNT + ' ' + ','.join(mount['options'])
            + ' - fuse.rclone ' + mount['source'] + ' rw,user_id=0,group_id=0')
    witness = dict(boot_id=report['boot_id'], kernel=report['kernel'],
        processes={k: copy.deepcopy(report[k]) for k in
                   ('reader_process', 'production_service_process', 'production_rc_process')},
        reader_cgroup='0::/system.slice/' + r.READER_UNIT + '\n',
        reader_cmdline=['/usr/bin/rclone', '--config',
            '/root/.config/rclone/rhea-pebble-lab-reader-20261102.conf', 'mount',
            'rhea_pebble_lab_reader:' + admission.BUCKET + '/rhea', r.READER_MOUNT,
            '--read-only', '--cache-dir', r.CACHES[0]],
        reader_exe='/usr/bin/rclone', reader_exe_sha256='a' * 64, mountinfo=[line],
        open_users=[], cache_identities={p: dict(device=8, inode=i+100) for i, p in enumerate(r.CACHES)},
        protected_files=dict(r.PROTECTED_PINS), stop_present=False, writer_socket_present=False,
        file_identities={p: dict(device=8, inode=i+200, size=1024, mtime_ns=1, ctime_ns=1)
                         for i, p in enumerate(r.PROTECTED_PINS)})
    return dict(raw=raw, source_path=str(r.HEALTH),
        source_raw=(ROOT / 'scripts/rhea_batch2_health.py').read_bytes(),
        restored_raw=r.canonical(done['reader']), finalization_raw=done_raw,
        certificates=[(directory / name).read_bytes() for name, _, _ in r.CERTIFICATES],
        close_raw=(directory / 'rhea-full-clone-failed-close-certified-20261103.json').read_bytes(),
        witness=witness)


class ReaderEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.evidence = fixture()
        self.report = json.loads(self.evidence['raw'])
        self.now = self.report['observed_unix'] + 1
        self.after = self.changed_report(lambda d: d.update(observed_unix=self.now - .5))

    def validate(self, evidence=None, **kwargs):
        return r.validate_evidence(self.evidence if evidence is None else evidence,
                                   now=kwargs.get('now', self.now))

    def changed_report(self, change):
        evidence = copy.deepcopy(self.evidence)
        report = json.loads(evidence['raw'])
        change(report)
        evidence['raw'] = r.canonical(report)
        return evidence

    def test_archived_receipt_and_thirteen_certificates(self):
        result = self.validate()
        self.assertEqual(result['binding']['generation'], 13)
        self.assertEqual(result['binding']['cap'], 9)
        self.assertFalse(result['admission'])
        self.assertFalse(result['controller_ready'])
        self.assertEqual(len(self.evidence['certificates']), 13)
        self.assertEqual(len(self.report['certified_stages']), 4)

    def test_exact_state_and_legacy_ceiling(self):
        for key, value in [('generation', 14), ('rewrites', 10), ('maximum_rewrites', 10),
                           ('pending', {}), ('checkpoint_sha256', '0'*64), ('schema', True)]:
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d.update({key: value})))

    def test_state_inventory_count_marked_bytes_and_format(self):
        for key, value in [('count', 93696), ('marked', 93685), ('bytes', 7786594079551),
                           ('inventory', 'f'*64), ('format', '014')]:
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d['state'].update({key: value})))

    def test_all_immutable_health_fields_are_enforced(self):
        # Exercise every retained field, not merely selected happy-path booleans.
        for key in r.IMMUTABLE_REPORT:
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d.update({key: 'tampered'})))

    def test_bad_reader_pid_start_boot_and_kernel(self):
        for key, value in [('pid', 78503), ('start_ticks', '5054052'), ('boot_id', 'bad')]:
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d['reader_process'].update({key: value})))
        for key in ['boot_id', 'kernel']:
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d.update({key: 'different'})))

    def test_wrong_restoration_hash_or_terminal_receipt(self):
        for key in ['restored_raw', 'finalization_raw']:
            bad = copy.deepcopy(self.evidence)
            bad[key] += b' '
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_rc_backlog_errors_and_missing_counters(self):
        for key, value in [('bytesUsed', 1), ('uploadsQueued', 1), ('uploadsInProgress', 1),
                           ('erroredFiles', 1), ('outOfSpace', True), ('uploadsQueued', False)]:
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d['production_disk_cache'].update({key: value})))
        with self.assertRaises(r.Refusal):
            self.validate(self.changed_report(lambda d: d['production_disk_cache'].pop('erroredFiles')))

    def test_free_space_threshold_and_types(self):
        self.validate(self.changed_report(lambda d: d.update(free_bytes=2*1024**4)))
        for value in [2*1024**4-1, True, None, float(2*1024**4)]:
            with self.subTest(value=value), self.assertRaises(r.Refusal):
                self.validate(self.changed_report(lambda d: d.update(free_bytes=value)))

    def test_source_path_and_exact_bytes(self):
        for key, value in [('source_path', '/tmp/health.py'), ('source_raw', b'print("ok")')]:
            bad = copy.deepcopy(self.evidence)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_chain_length_order_and_each_certificate_tampering(self):
        for index in range(13):
            bad = copy.deepcopy(self.evidence)
            bad['certificates'][index] += b' '
            with self.subTest(index=index), self.assertRaises(r.Refusal):
                self.validate(bad)
        for change in [lambda c: c.pop(), lambda c: c.reverse(), lambda c: c.append(c[-1])]:
            bad = copy.deepcopy(self.evidence)
            change(bad['certificates'])
            with self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_failed_close_bridge_tampering(self):
        self.evidence['close_raw'] += b' '
        with self.assertRaises(r.Refusal):
            self.validate()

    def test_health_stage_suffix_order_length_and_writer_tampering(self):
        for change in [lambda d: d['certified_stages'].reverse(),
                       lambda d: d['certified_stages'].pop(),
                       lambda d: d['certified_stages'][-1].update(writer_sha256='f'*64),
                       lambda d: d['certified_stages'][-1].update(created_files=True)]:
            with self.assertRaises(r.Refusal):
                self.validate(self.changed_report(change))

    def test_freshness_limit_and_future_nonfinite_clock(self):
        self.validate(now=self.report['observed_unix'] + 120)
        for now in [self.report['observed_unix'] + 120.001, self.report['observed_unix'] - .1,
                    float('nan'), float('inf'), True]:
            with self.subTest(now=now), self.assertRaises(r.Refusal):
                self.validate(now=now)

    def test_duplicate_unknown_missing_and_nonfinite_json(self):
        for raw in [self.evidence['raw'].replace(b'"schema": 1', b'"schema": 1, "schema": 1'),
                    b'{"observed_unix":NaN}', b'[]', b'bad-json']:
            self.assertNotEqual(raw, self.evidence['raw'])
            bad = dict(self.evidence, raw=raw)
            with self.assertRaises(r.Refusal):
                self.validate(bad)
        for change in [lambda d: d.update(success=True), lambda d: d.pop('kernel')]:
            with self.assertRaises(r.Refusal):
                self.validate(self.changed_report(change))

    def test_success_booleans_cannot_replace_evidence(self):
        with self.assertRaises(r.Refusal):
            r.validate_evidence(dict(success=True, admission=True), now=self.now)

    def test_independent_reader_and_production_processes(self):
        for key in ['reader_process', 'production_service_process', 'production_rc_process']:
            bad = copy.deepcopy(self.evidence)
            bad['witness']['processes'][key]['start_ticks'] = '999'
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_missing_separate_reader_command_and_service(self):
        for key, value in [('reader_cgroup', '0::/system.slice/writer.service'),
                           ('reader_cmdline', ['/usr/bin/rclone', 'mount', r.WRITER_MOUNT]),
                           ('reader_exe', '/tmp/rclone')]:
            bad = copy.deepcopy(self.evidence)
            bad['witness'][key] = value
            with self.subTest(key=key), self.assertRaises(r.Refusal):
                self.validate(bad)
        for flag in ['--read-only', '--config', '--cache-dir']:
            bad = copy.deepcopy(self.evidence)
            bad['witness']['reader_cmdline'].remove(flag)
            with self.subTest(flag=flag), self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_mount_absent_alternate_duplicate_and_writer_mount(self):
        line = self.evidence['witness']['mountinfo'][0]
        for rows in [[], [line, line], [line.replace(r.READER_MOUNT, '/mnt/alternate')],
                     [line, line.replace(r.READER_MOUNT, r.WRITER_MOUNT)],
                     [line.replace('fuse.rclone', 'ext4')], ['malformed']]:
            bad = copy.deepcopy(self.evidence)
            bad['witness']['mountinfo'] = rows
            with self.subTest(rows=rows), self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_protected_files_cache_and_stop_sentinel(self):
        for change in [lambda w: w['protected_files'].update({str(r.HEALTH): '0'*64}),
                       lambda w: w['cache_identities'].pop(r.CACHES[0]),
                       lambda w: w['file_identities'].pop(str(r.HEALTH)),
                       lambda w: w.update(stop_present=True),
                       lambda w: w.update(writer_socket_present=True),
                       lambda w: w.update(open_users=[{'pid': 999}])]:
            bad = copy.deepcopy(self.evidence)
            change(bad['witness'])
            with self.assertRaises(r.Refusal):
                self.validate(bad)

    def test_exact_report_byte_hash_and_mount_identity_in_seal(self):
        first = self.validate()
        second = self.validate(dict(self.evidence, raw=r.canonical(self.report)))
        self.assertNotEqual(first['evidence_seal_sha256'], second['evidence_seal_sha256'])
        bad = copy.deepcopy(self.evidence)
        bad['witness']['mountinfo'][0] = bad['witness']['mountinfo'][0].replace('87 29', '88 29')
        third = self.validate(bad)
        self.assertNotEqual(first['evidence_seal_sha256'], third['evidence_seal_sha256'])

    def test_prior_report_mismatch_and_time_regression(self):
        arguments = {k:v for k,v in self.evidence.items() if k != 'witness'}
        r.validate_report(**arguments, now=self.now, prior_report_raw=self.evidence['raw'])
        for prior in [self.changed_report(lambda d: d['reader_process'].update(pid=1))['raw'],
                      self.changed_report(lambda d: d.update(observed_unix=self.now))['raw']]:
            with self.assertRaises(r.Refusal):
                r.validate_report(**arguments, now=self.now, prior_report_raw=prior)

    def test_planner_success_has_only_nonexecutable_proposals(self):
        plan = r.plan_handoff(self.evidence, self.after, now=self.now)
        self.assertEqual(plan['state'], 'plan-only-ready')
        self.assertTrue(plan['dry_run_go'])
        self.assertFalse(plan['execution_allowed'])
        self.assertFalse(plan['admission'])
        self.assertFalse(plan['mutations_performed'])
        self.assertEqual(plan['preserved_caches'], list(r.CACHES))
        self.assertEqual(len(plan['steps']), 6)
        self.assertTrue(all(not row['executable'] and row['expected_postconditions'] for row in plan['steps']))

    def test_planner_writer_alive_stop_new_users_rc_backlog_production_change(self):
        changed = [self.changed_report(lambda d: d.update(writer_process=d['reader_process'])),
                   self.changed_report(lambda d: d['production_disk_cache'].update(uploadsQueued=1)),
                   self.changed_report(lambda d: d['production_service_process'].update(pid=123))]
        for key, value in [('open_users', [dict(pid=99)]), ('stop_present', True),
                           ('writer_socket_present', True), ('boot_id', 'other')]:
            bad = copy.deepcopy(self.evidence)
            bad['witness'][key] = value
            changed.append(bad)
        for after in changed:
            with self.subTest(after=after['witness']['stop_present']):
                plan = r.plan_handoff(self.evidence, after, now=self.now)
                self.assertEqual(plan['state'], 'blocked')
                self.assertFalse(plan['dry_run_go'])

    def test_planner_reader_mount_file_and_cache_toctou(self):
        for change in [lambda w: w['processes']['reader_process'].update(pid=2),
                       lambda w: w['cache_identities'][r.CACHES[0]].update(inode=999),
                       lambda w: w['file_identities'][str(r.HEALTH)].update(inode=999),
                       lambda w: w['mountinfo'].__setitem__(0, w['mountinfo'][0].replace('87 29', '88 29')),
                       lambda w: w.update(reader_exe_sha256='b'*64)]:
            after = copy.deepcopy(self.after)
            change(after['witness'])
            plan = r.plan_handoff(self.evidence, after, now=self.now)
            self.assertEqual(plan['state'], 'blocked')

    def test_planner_stale_time_regression_and_forged_seal(self):
        for before, after in [(self.evidence, self.evidence), (self.evidence, {'admission': True}),
                              (self.evidence, self.changed_report(lambda d: d.update(observed_unix=self.now-2))),
                              (self.validate(), self.validate())]:
            self.assertFalse(r.plan_handoff(before, after, now=self.now)['dry_run_go'])
        self.assertFalse(r.plan_handoff(self.evidence, self.evidence, now=self.now+121)['dry_run_go'])

    def test_planner_never_verifies_admission_or_consumes_nonce_or_runs_child(self):
        with patch.object(admission, 'verify_production', side_effect=AssertionError('no admission')), \
             patch.object(admission, 'consume_production_nonce', side_effect=AssertionError('no nonce')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('pure planner')):
            self.assertTrue(r.plan_handoff(self.evidence, self.after, now=self.now)['dry_run_go'])
        for name in ['nonce', 'admission', 'success']:
            bad = dict(self.evidence, **{name: True})
            self.assertFalse(r.plan_handoff(bad, self.evidence, now=self.now)['dry_run_go'])


class ProbeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.evidence = fixture()
        self.report = json.loads(self.evidence['raw'])
        self.now = self.report['observed_unix']
        files = {str(r.HEALTH): self.evidence['source_raw'], str(r.RESTORED): self.evidence['restored_raw'],
                 str(r.FINALIZATION): self.evidence['finalization_raw'], str(r.CLOSE): self.evidence['close_raw']}
        files.update({str(r.TRUST/path): raw for (_, path, _), raw in
                      zip(r.CERTIFICATES, self.evidence['certificates'])})
        self.snapshot = dict(files=files, witness=self.evidence['witness'], lock=dict(device=8, inode=2))

    @contextmanager
    def offline_probe(self, *, snapshots=None, child=None):
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(r.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(r.socket, 'gethostname', return_value='rhea'))
            stack.enter_context(patch.object(r, '_unlocked_identity', return_value=dict(device=8, inode=2)))
            stack.enter_context(patch.object(r, '_snapshot', side_effect=snapshots or [self.snapshot, self.snapshot]))
            stack.enter_context(patch.object(r, '_validate_interpreter'))
            stack.enter_context(patch.object(r.time, 'time', side_effect=[self.now-1, self.now+1]))
            stack.enter_context(patch.object(r.time, 'monotonic', side_effect=[10, 12, 12]))
            command = stack.enter_context(patch.object(r.subprocess, 'run', return_value=child or
                types.SimpleNamespace(returncode=0, stdout=self.evidence['raw'], stderr=b'')))
            yield command

    def test_probe_exact_child_clean_environment_and_no_lock_acquisition(self):
        with self.offline_probe() as command, patch.object(fcntl, 'flock', side_effect=AssertionError('never flock')):
            observed = r.probe_reader_restored()
        argv = command.call_args.args[0]
        self.assertEqual(argv, ['/usr/bin/python3', '-I', '-B', str(r.HEALTH), '--phase',
                                'reader-restored', '--reader-sha256', r.RESTORED_SHA256])
        self.assertEqual(command.call_count, 1)
        env = command.call_args.kwargs['env']
        self.assertEqual(set(env), {'PATH', 'HOME', 'LANG', 'LC_ALL'})
        self.assertFalse(observed['admission'])
        self.assertFalse(observed['controller_ready'])

    def test_probe_nonroot_or_wrong_host_has_no_child(self):
        with patch.object(r.os, 'geteuid', return_value=1000), patch.object(subprocess, 'run') as child:
            with self.assertRaises(r.Refusal):
                r.probe_reader_restored()
            child.assert_not_called()
        with patch.object(r.os, 'geteuid', return_value=0), \
             patch.object(r.socket, 'gethostname', return_value='offline'), patch.object(subprocess, 'run') as child:
            with self.assertRaises(r.Refusal):
                r.probe_reader_restored()
            child.assert_not_called()

    def test_probe_held_lock_has_no_child(self):
        with self.offline_probe() as child, \
             patch.object(r, '_unlocked_identity', side_effect=r.Refusal('lock held')):
            with self.assertRaises(r.Refusal):
                r.probe_reader_restored()
            child.assert_not_called()

    def test_probe_tampered_source_and_same_bytes_inode_substitution_before_child(self):
        from contextlib import nullcontext
        metadata = dict(st_dev=8, st_ino=2, st_size=1024, st_mtime_ns=1, st_ctime_ns=1)
        for data, later in [(b'untrusted source', metadata),
                            (self.evidence['source_raw'], dict(metadata, st_ino=3))]:
            with patch.object(admission, 'protected_directory', return_value=nullcontext(10)), \
                 patch.object(admission, 'read_at', return_value=data), \
                 patch.object(r.os, 'stat', side_effect=[types.SimpleNamespace(**metadata),
                                                       types.SimpleNamespace(**later)]), \
                 patch.object(r.subprocess, 'run') as child:
                with self.assertRaises(r.Refusal):
                    r._snapshot()
                child.assert_not_called()

    def test_real_kernel_lock_contention_and_self_held_lock(self):
        # An actual disposable flock; root ownership alone is injected in memory.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'writer.lock'
            path.touch(mode=0o600)
            @contextmanager
            def directory(_):
                fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    yield fd
                finally:
                    os.close(fd)
            original = os.fstat
            def root_metadata(fd):
                info = original(fd)
                return types.SimpleNamespace(**{k:getattr(info,k) for k in
                    ['st_mode', 'st_nlink', 'st_dev', 'st_ino']}, st_uid=0, st_gid=0)
            with patch.object(r, 'LOCK', path), patch.object(admission, 'protected_directory', directory), \
                 patch.object(r.os, 'fstat', side_effect=root_metadata):
                with path.open('rb') as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaisesRegex(r.Refusal, 'already held'):
                        r._unlocked_identity()
                    fcntl.flock(stream, fcntl.LOCK_UN)
                self.assertGreater(r._unlocked_identity()['inode'], 0)

    def test_probe_toctou_changed_file_or_process(self):
        for key in ['files', 'witness', 'lock']:
            changed = copy.deepcopy(self.snapshot)
            changed[key]['injected-change'] = 'changed'
            with self.subTest(key=key), self.offline_probe(snapshots=[self.snapshot, changed]), \
                 self.assertRaises(r.Refusal):
                r.probe_reader_restored()

    def test_probe_child_failure_stale_or_timeout(self):
        for child in [types.SimpleNamespace(returncode=1, stdout=self.evidence['raw'], stderr=b''),
                      types.SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'refusal'),
                      types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')]:
            with self.offline_probe(child=child), self.assertRaises(r.Refusal):
                r.probe_reader_restored()
        bad = copy.deepcopy(self.report)
        bad['observed_unix'] = self.now - 121
        with self.offline_probe(child=types.SimpleNamespace(returncode=0, stdout=r.canonical(bad), stderr=b'')), \
             self.assertRaises(r.Refusal):
            r.probe_reader_restored()
        with self.offline_probe() as child:
            child.side_effect = subprocess.TimeoutExpired('fixed-health', 120)
            with self.assertRaises(r.Refusal):
                r.probe_reader_restored()

    def test_adapter_reader_mode_never_calls_writer_guard(self):
        adapter = object.__new__(host.RootHostAdapter)
        adapter._mode = 'reader-restored'
        adapter._locked = True
        adapter.host = types.SimpleNamespace(locked=True, guard=lambda *_: self.fail('writer guard called'))
        for call in [adapter.observe_host, lambda: adapter.preflight({}), adapter.protected_guards,
                     adapter.observe_reader_restored]:
            with self.assertRaises(r.Refusal):
                call()

    def test_reader_mode_cannot_regress_to_signed_admission_or_burn_nonce(self):
        adapter = object.__new__(host.RootHostAdapter)
        adapter._mode = 'reader-restored'
        adapter._locked = True
        adapter._admission = None
        adapter.host = types.SimpleNamespace(locked=True)
        with patch.object(admission, 'verify_production') as verify, \
             patch.object(admission, 'consume_production_nonce') as consume:
            with self.assertRaises(r.Refusal):
                adapter.authenticate_admission({})
            verify.assert_not_called()
            consume.assert_not_called()

    def test_adapter_reader_method_checks_installation_and_pinned_module(self):
        adapter = object.__new__(host.RootHostAdapter)
        adapter._locked = False
        adapter.host = types.SimpleNamespace(locked=False)
        adapter.deployment = {'artifacts': {'reader_preflight': 'a'*64}}
        observation = dict(mode='reader-restored', admission=False, controller_ready=False)
        reader = types.SimpleNamespace(probe_reader_restored=lambda: observation)
        with patch.object(host, 'validate_installation', return_value=adapter.deployment) as install, \
             patch.object(host, '_load_exact', return_value=reader) as load:
            self.assertEqual(adapter.observe_reader_restored(), observation)
        self.assertEqual(install.call_count, 2)
        self.assertEqual(load.call_args.args[:2],
                         (host.INSTALL / host.ARTIFACTS['reader_preflight'][0], 'a'*64))
        self.assertEqual(adapter._mode, 'reader-restored')

    def test_all_mutation_methods_and_cli_stay_disabled(self):
        adapter = object.__new__(host.RootHostAdapter)
        with patch.object(subprocess, 'run', side_effect=AssertionError('no child')), \
             patch('sys.stdout', new_callable=io.StringIO):
            for name in ['handoff', 'run_go_monitored', 'drain_stop', 'publish_markers', 'reopen_readonly']:
                with self.assertRaises(admission.Refusal):
                    getattr(adapter, name)({})
            self.assertEqual(r.main([]), 2)
            self.assertEqual(host.main(), 2)
        self.assertIsNone(admission.PUBLIC_KEY_SHA256)
        self.assertIsNone(host.PROVISION_PUBLIC_KEY_SHA256)

    def test_offline_cli_distinguishes_valid_report_from_admission(self):
        directory = ROOT / 'docs/evidence'
        with patch.object(r.time, 'time', return_value=self.now), \
             patch.object(r, 'probe_reader_restored', side_effect=AssertionError('no live probe')), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(r.main(['--verify-report', str(directory/'rhea-batch2-fresh-health-20261110.json'),
                                     '--evidence-dir', str(directory)]), 0)
            value = json.loads(output.getvalue())
            self.assertFalse(value['admission'])
            self.assertEqual(value['decision'], 'not admission')
        with patch.object(r.time, 'time', return_value=self.now+121), \
             patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(r.main(['--verify-report', str(directory/'rhea-batch2-fresh-health-20261110.json'),
                                     '--evidence-dir', str(directory)]), 2)


if __name__ == '__main__':
    unittest.main()
