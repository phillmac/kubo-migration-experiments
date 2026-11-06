import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('batch2_mount_tests', Path(__file__).parents[1] / 'scripts/rhea_batch2_mount_lifecycle.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class ReaderStopTests(unittest.TestCase):
    def failed(self):
        return {'LoadState': 'loaded', 'ActiveState': 'failed', 'SubState': 'failed',
                'MainPID': '0', 'Result': 'exit-code', 'ExecMainCode': '1', 'ExecMainStatus': '143',
                'User': '', 'Group': '', 'DropInPaths': '', 'NeedDaemonReload': 'no'}

    def test_only_known_intentional_exit_can_be_reset(self):
        self.assertEqual(m.classify_reader_stop(self.failed(), process_absent=True, mount_absent=True),
                         'reset-known-exit143')
        for field, value in [('ExecMainStatus', '1'), ('ExecMainCode', '2'), ('Result', 'signal'),
                             ('User', 'ubuntu'), ('Group', 'root'), ('DropInPaths', '/tmp/extra'),
                             ('NeedDaemonReload', 'yes'), ('MainPID', '4415')]:
            with self.subTest(field=field):
                row = self.failed(); row[field] = value
                with self.assertRaises(RuntimeError):
                    m.classify_reader_stop(row, process_absent=True, mount_absent=True)

    def test_exit143_never_overrides_live_process_or_mount(self):
        for process, mount in [(False, True), (True, False), (False, False)]:
            with self.assertRaises(RuntimeError):
                m.classify_reader_stop(self.failed(), process_absent=process, mount_absent=mount)

    def test_collected_unit_is_distinct_from_failed_or_deactivating(self):
        row = {'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'}
        self.assertEqual(m.classify_reader_stop(row, process_absent=True, mount_absent=True), 'collected')
        row['ActiveState'] = 'deactivating'
        with self.assertRaises(RuntimeError):
            m.classify_reader_stop(row, process_absent=True, mount_absent=True)


class FinalAdmissionTests(unittest.TestCase):
    def test_only_the_explicit_complete_endpoint_can_be_finalized(self):
        for generation in range(10, 14):
            state = {'generation': generation, 'rewrites': generation - 4, 'pending': None,
                     'checkpoint': {'generation': generation}}
            m.validate_final_generation(state, generation)
            for key, value in [('generation', generation - 1), ('rewrites', generation - 5),
                               ('pending', {'phase': 'closed'}), ('checkpoint', {'generation': generation - 1})]:
                altered = copy.deepcopy(state); altered[key] = value
                with self.subTest(generation=generation, key=key), self.assertRaises(RuntimeError):
                    m.validate_final_generation(altered, generation)
        for generation in (9, 14, True, '10'):
            with self.assertRaises(RuntimeError):
                m.validate_final_generation({}, generation)

    def test_reader_report_must_be_read_only_and_exact(self):
        expected = {'format': '013', 'marked': 93689, 'count': 93697, 'bytes': 12345}
        report = {'scope': 'lab-reader-only', 'read_only': True, 'format_major_version': '013',
                  'marked_files': 93689, 'sst_count': 93697, 'sst_bytes': 12345}
        m.validate_reader_inspection(report, expected)
        for key, value in [('scope', 'writer'), ('read_only', False), ('format_major_version', '014'),
                           ('marked_files', 93690), ('sst_count', 93696), ('sst_bytes', 12346)]:
            altered = dict(report); altered[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m.validate_reader_inspection(altered, expected)

    def test_signals_latch_without_raising_in_child_construction(self):
        with mock.patch.object(m, 'STOP_REQUESTED', False):
            m.interrupted(signal.SIGTERM, None)
            self.assertTrue(m.STOP_REQUESTED)
            with self.assertRaises(RuntimeError):
                m.cancellation_point()


class InspectorCleanupTests(unittest.TestCase):
    def child(self, code):
        return subprocess.Popen([sys.executable, '-u', '-c', code], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

    def close_streams(self, child):
        for stream in (child.stdout, child.stderr):
            if stream is not None: stream.close()

    def test_completed_child_is_reaped_without_signals(self):
        child = self.child('pass')
        try:
            child.wait(timeout=5)
            result = m.stop_read_only_child(child, grace_seconds=0.2)
            self.assertEqual(result, {'term_sent': False, 'kill_sent': False})
            self.assertEqual(child.returncode, 0)
        finally:
            self.close_streams(child)

    def test_live_read_only_child_receives_term_and_is_reaped(self):
        child = self.child("import time; print('ready',flush=True); time.sleep(30)")
        try:
            self.assertEqual(child.stdout.readline(), b'ready\n')
            result = m.stop_read_only_child(child, grace_seconds=0.2)
            self.assertTrue(result['term_sent'])
            self.assertFalse(result['kill_sent'])
            self.assertEqual(child.returncode, -signal.SIGTERM)
            with self.assertRaises(ProcessLookupError): os.killpg(child.pid, 0)
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=5)
            self.close_streams(child)

    def test_term_ignoring_read_only_child_gets_kill_then_reap(self):
        child = self.child("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(30)")
        try:
            self.assertEqual(child.stdout.readline(), b'ready\n')
            result = m.stop_read_only_child(child, grace_seconds=0.05)
            self.assertTrue(result['term_sent'])
            self.assertTrue(result['kill_sent'])
            self.assertEqual(child.returncode, -signal.SIGKILL)
            with self.assertRaises(ProcessLookupError): os.killpg(child.pid, 0)
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=5)
            self.close_streams(child)

    def test_group_lookup_exit_race_still_reaps(self):
        child = mock.Mock(pid=999999, returncode=None)
        child.poll.side_effect = [None, None, 0]
        child.wait.return_value = 0
        with mock.patch.object(m.os, 'getpgid', side_effect=ProcessLookupError), \
                mock.patch.object(m.os, 'killpg') as kill_group:
            result = m.stop_read_only_child(child, grace_seconds=0.1)
        self.assertFalse(result['term_sent'])
        self.assertEqual(child.wait.call_count, 2)
        kill_group.assert_not_called()
        child.kill.assert_not_called()

    def test_unverifiable_group_does_not_skip_owned_pid_cleanup(self):
        child = self.child("import time; print('ready',flush=True); time.sleep(30)")
        try:
            self.assertEqual(child.stdout.readline(), b'ready\n')
            with mock.patch.object(m.os, 'getpgid', return_value=-1), self.assertRaises(RuntimeError):
                m.stop_read_only_child(child, grace_seconds=0.2)
            self.assertEqual(child.returncode, -signal.SIGKILL)
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=5)
            self.close_streams(child)

    def test_unreapable_child_is_reported_with_bounded_waits(self):
        child = mock.Mock(pid=999999, returncode=None)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired('fixed-inspector', 0.01)
        with mock.patch.object(m.os, 'getpgid', return_value=child.pid), \
                mock.patch.object(m.os, 'getsid', return_value=child.pid), \
                mock.patch.object(m.os, 'killpg'), self.assertRaises(subprocess.TimeoutExpired):
            m.stop_read_only_child(child, grace_seconds=0.01)
        self.assertTrue(child.kill.called)
        self.assertTrue(all(call.kwargs.get('timeout') == 0.01 for call in child.wait.call_args_list))

    def test_receipt_error_after_spawn_still_reaps_and_records_timing(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            executable = directory / 'reader-inspector'
            executable.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(30)\n')
            executable.chmod(0o755)
            created, records = [], {}
            real_popen = subprocess.Popen
            def popen(*args, **kwargs):
                process = real_popen(*args, **kwargs); created.append(process); return process
            def write(where, name, value, **kwargs):
                if name == 'reader-inspect-process.json': raise OSError('receipt fault')
                records[name] = value
            rt = types.SimpleNamespace(_process_identity=lambda pid: {'pid': pid}, _sync_dir=lambda path: None)
            w = types.SimpleNamespace(CLEAN_ENV={'PATH': '/usr/bin:/bin'}, secure_path=lambda *a, **k: None,
                                      read_protected=lambda path, **kw: Path(path).read_bytes())
            ctx = {'rt': rt, 'w': w, 'c': types.SimpleNamespace(json_object=lambda raw: {}),
                   'old': types.SimpleNamespace(INSPECTOR=executable, READER_DB=directory)}
            op = m.Operations(types.SimpleNamespace(writer_absent=lambda ctx: None), ctx)
            op.write = write
            with mock.patch.object(m, 'INSPECTOR_SHA', hashlib.sha256(executable.read_bytes()).hexdigest()), \
                    mock.patch.object(m.subprocess, 'Popen', side_effect=popen), self.assertRaises(RuntimeError):
                op.inspect_reader(directory)
            self.assertEqual(len(created), 1)
            self.assertIsNotNone(created[0].returncode)
            timing = records['reader-inspect-timing.json']
            self.assertTrue(timing['child_reaped'])
            self.assertTrue(timing['child_and_group_absent'])
            self.assertEqual(timing['execution_error_type'], 'OSError')


if __name__ == '__main__':
    unittest.main()
