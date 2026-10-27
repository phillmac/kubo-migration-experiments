import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import measure_migration_writes as m


class MeasurementTests(unittest.TestCase):
    def test_counts_actual_successful_bytes_not_requested(self):
        parsed = m.parse_trace(['write(5</tmp/lab/repo/pebbleds/1.sst>, ""..., 100) = 50\n'], '/tmp/lab/repo')
        self.assertEqual(parsed['repo_write_bytes'], 50)
        self.assertEqual(parsed['bytes_by_kind'], {'sst': 50})

    def test_overwrite_and_deleted_counted_stdout_excluded(self):
        trace = ('write(5</tmp/lab/repo/pebbleds/a.sst>, ""..., 10) = 10\n'
                 'pwrite64(5</tmp/lab/repo/pebbleds/a.sst>, ""..., 4, 0) = 4\n'
                 'writev(6</tmp/lab/repo/pebbleds/b.log (deleted)>, [], 2) = 8\n'
                 'write(1<pipe:[123]>, ""..., 99) = 99\n'
                 'write(9</tmp/lab/report.json>, ""..., 31) = 31\n')
        parsed = m.parse_trace([trace], '/tmp/lab/repo')
        self.assertEqual(parsed['repo_write_bytes'], 22)
        self.assertEqual(parsed['bytes_by_kind'], {'sst': 14, 'wal': 8})

    def test_prefix_collision_not_counted(self):
        parsed = m.parse_trace(['write(5</tmp/repo-other/test>, ""..., 5) = 5\n'], '/tmp/repo')
        self.assertEqual(parsed['repo_write_bytes'], 0)

    def test_failed_writes_not_counted(self):
        parsed = m.parse_trace(['write(5</tmp/repo/test>, ""..., 5) = -1 EIO (Input/output error)\n'], '/tmp/repo')
        self.assertEqual(parsed['repo_write_bytes'], 0)

    def test_resumed_call(self):
        trace = 'write(5</tmp/repo/test>, ""..., 5 <unfinished ...>\n<... write resumed>) = 5\n'
        self.assertEqual(m.parse_trace([trace], '/tmp/repo')['repo_write_bytes'], 5)

    def test_incomplete_trace_refused(self):
        with self.assertRaises(m.Refusal):
            m.parse_trace(['write(5</tmp/repo/test>, ""..., 5 <unfinished ...>\n'], '/tmp/repo')

    def test_unknown_fd_refused(self):
        with self.assertRaises(m.Refusal): m.parse_trace(['write(5, ""..., 5) = 5\n'], '/tmp/repo')

    def test_shared_writable_repo_mapping_refused(self):
        with self.assertRaises(m.Refusal):
            m.parse_trace(['mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, 5</tmp/repo/test>, 0) = 4096\n'], '/tmp/repo')

    def test_readonly_repo_mapping_allowed(self):
        self.assertEqual(m.parse_trace(['mmap(NULL, 4096, PROT_READ, MAP_SHARED, 5</tmp/repo/test>, 0) = 4096\n'], '/tmp/repo')['repo_write_bytes'], 0)

    def test_async_io_refused(self):
        with self.assertRaises(m.Refusal): m.parse_trace(['io_uring_enter(3, 1, 0, 0, NULL, 0) = 1\n'], '/tmp/repo')

    def test_copy_destination_used(self):
        trace = ('copy_file_range(5</tmp/source>, [0], 6</tmp/repo/copy>, [0], 500, 0) = 500\n'
                 'sendfile(7</tmp/repo/copy2>, 5</tmp/source>, NULL, 200) = 200\n')
        self.assertEqual(m.parse_trace([trace], '/tmp/repo')['repo_write_bytes'], 700)

    def test_churn_not_net_size(self):
        before = {'a': {'size': 100, 'allocated': 4096, 'sha256': 'old'}}
        after = {'b': {'size': 100, 'allocated': 4096, 'sha256': 'new'}}
        diff = m.changed_files(before, after)
        self.assertEqual(diff['net_apparent_growth_bytes'], 0)
        self.assertEqual(diff['surviving_new_or_changed_file_bytes'], 100)

    def test_fixture_is_deterministic_and_nonrepeating(self):
        with tempfile.TemporaryDirectory() as d:
            p, q = Path(d)/'p', Path(d)/'q'
            a, b = m.make_fixture(p, 2, 'test'), m.make_fixture(q, 2, 'test')
            self.assertEqual(a, b)
            content = p.read_bytes()
            self.assertEqual(len(content), 2*m.MIB)
            self.assertNotEqual(content[:m.MIB], content[m.MIB:])
            self.assertEqual(hashlib.sha256(content).hexdigest(), a)


if __name__ == '__main__': unittest.main()
