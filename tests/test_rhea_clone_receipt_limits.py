"""Clone proof receipts have a larger bounded envelope on both sides of a restart."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_clone_batch_runner as runner

host = runner.host


class CloneReceiptLimits(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / '000024'
        self.state.mkdir()
        # Run the root journal's regular-file checks as the unprivileged CI owner.
        for target, name, value in (
            (host, 'BATCH_JOURNAL', self.root), (host, 'TRIAL_RECEIPT_BYTES', 32),
            (host, 'BATCH_PROOF_BYTES', 128), (host.iam.p, 'OWNER', os.getuid()),
            (host.iam.p, 'directory', lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY)),
        ):
            selected = patch.object(target, name, value)
            selected.start()
            self.addCleanup(selected.stop)

    def test_numbered_receipts_round_trip_and_repeat_save_at_exact_limit(self):
        for name in ('before-publication.json', 'final-remote.json', 'checkpoint.json'):
            path = self.state / name
            value = {'data': 'a' * (128 - len(runner.c.canonical({'data': ''})))}
            runner.prep.save(path, value)
            self.assertEqual(path.stat().st_size, 128)
            self.assertEqual(host.read(path), value)
            runner.prep.save(path, value)
            with self.assertRaisesRegex(RuntimeError, 'retained record differs'):
                runner.prep.save(path, {'data': 'changed'})

    def test_larger_envelope_only_applies_to_numbered_history_bearing_files(self):
        for path in (self.root / 'checkpoint.json', self.state / 'completed.json',
                     self.state / 'ordinary' / 'final-remote.json',
                     self.root / '00024' / 'before-publication.json',
                     self.root / '１２３４５６' / 'checkpoint.json',
                     self.root.parent / '000024' / 'checkpoint.json'):
            self.assertEqual(host.receipt_limit(path), 32, path)
        for name, limit in (('checkpoint.json', 128), ('completed.json', 32)):
            path = self.state / name
            value = {'data': 'a' * (limit + 1 - len(runner.c.canonical({'data': ''})))}
            with self.assertRaisesRegex(RuntimeError, 'exceeds size limit'):
                runner.prep.save(path, value)
            self.assertFalse(path.exists())
            path.write_bytes(runner.c.canonical(value))
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, 'invalid trial receipt'):
                host.read(path)

    def test_rejects_insecure_files_and_duplicate_json_keys(self):
        path = self.state / 'checkpoint.json'
        path.write_bytes(b'{"a":1,"a":2}')
        path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'duplicate JSON key'):
            host.read(path)
        link = self.state / 'final-remote.json'
        link.symlink_to(path)
        with self.assertRaises(OSError):
            host.read(link)
        link.unlink()
        os.link(path, link)
        with self.assertRaisesRegex(RuntimeError, 'invalid trial receipt'):
            host.read(path)
        link.unlink()
        path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'invalid trial receipt'):
            host.read(path)
