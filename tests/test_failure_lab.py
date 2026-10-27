import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from failure_lab import Refusal, file_sizes, require, validate_pressure_mount
from pin_stream_lab import cbor_head, cid, cid_text, make_car, varint


class FaultBoundaryTests(unittest.TestCase):
    def test_require_stops_on_false(self):
        with self.assertRaises(Refusal):
            require(False, 'stop')
    def test_pressure_directory_is_not_automatically_a_mount(self):
        with tempfile.TemporaryDirectory() as root:
            mount = Path(root) / 'limited'; mount.mkdir()
            with self.assertRaises(Refusal):
                validate_pressure_mount(root, mount)
    def test_arbitrary_mount_path_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(Refusal):
                validate_pressure_mount(root, Path('/tmp'))
    def test_pressure_symlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            link = Path(root) / 'limited'; link.symlink_to('/tmp')
            with self.assertRaises(Refusal):
                validate_pressure_mount(root, link)
    def test_size_samples_count_allocated_separately(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'fixture'; p.write_bytes(b'abc')
            rows = file_sizes(root)
            self.assertEqual(rows['fixture']['size'], 3)
            self.assertEqual(rows['fixture']['allocated'], p.stat().st_blocks * 512)
    def test_varints(self):
        self.assertEqual(varint(0), b'\0')
        self.assertEqual(varint(128), b'\x80\x01')
        self.assertEqual(varint(4096), b'\x80\x20')
        with self.assertRaises(Refusal): varint(-1)
    def test_cbor_lengths(self):
        self.assertEqual(cbor_head(4, 16), b'\x90')
        self.assertEqual(cbor_head(4, 64), b'\x98\x40')
        self.assertEqual(cbor_head(4, 4096), b'\x99\x10\0')
        with self.assertRaises(Refusal): cbor_head(4, 65536)
    def test_cid_has_expected_digest(self):
        value = cid(b'fixture', 0x55)
        self.assertEqual(value[:4], b'\x01\x55\x12\x20')
        self.assertEqual(value[4:], hashlib.sha256(b'fixture').digest())
        self.assertTrue(cid_text(value).startswith('bafkrei'))
    def test_car_fixture_is_deterministic(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = Path(root) / 'a', Path(root) / 'b'
            _, _, roots = make_car(a, 64)
            make_car(b, 64)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertEqual(len(set(roots)), 64)
            with self.assertRaises(FileExistsError): make_car(a, 64)
    def test_car_bound(self):
        with self.assertRaises(Refusal): make_car('/nonexistent', 100000)


if __name__ == '__main__': unittest.main()
