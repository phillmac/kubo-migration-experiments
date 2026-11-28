import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import rhea_clone_retiring_cycle as cycle


class RetirementCycleTests(unittest.TestCase):
    def setUp(self):
        self.parent = dict(generation=22, sha256='p')
        self.head = dict(generation=23, previous_checkpoint_sha256='p', sha256='successor')
        self.request = dict(generation=23, parent='p', retire=21, certificate='target')
        self.intent = dict(parent=self.parent, generation=23, request=self.request, release='release', worker='worker',
                           production_sha256=cycle.r.c.digest({'queue': 0}))

    def test_only_the_immediate_certified_successor_triggers(self):
        self.assertFalse(cycle.has_successor(self.parent, self.intent))
        self.assertTrue(cycle.has_successor(self.head, self.intent))
        for head in (dict(self.head, previous_checkpoint_sha256='other'), dict(self.head, generation=24),
                     dict(self.parent, sha256='changed', previous_checkpoint_sha256='old')):
            with self.assertRaises(RuntimeError):
                cycle.has_successor(head, self.intent)

    def test_waits_until_the_checkpoint_unit_finishes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(cycle.r, 'ROOT', Path(tmp)), \
                patch.object(cycle.r.host, 'read', side_effect=[self.parent, self.head, self.head, self.head]), \
                patch.object(cycle.r.h, 'output', side_effect=['deactivating', 'inactive']), \
                patch.object(cycle.time, 'sleep') as sleep:
            cycle.observe_successor(self.intent)
        self.assertEqual(sleep.call_count, 2)

    def test_failed_writer_cannot_arm_reclamation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            started = root/'000023'/'writer-launch.json'
            started.parent.mkdir()
            started.touch()
            with patch.object(cycle.r, 'ROOT', root), patch.object(cycle.r.host, 'read', return_value=self.parent), \
                    patch.object(cycle.r.h, 'output', return_value='inactive'), self.assertRaises(RuntimeError):
                cycle.observe_successor(self.intent)

    def test_different_retirement_target_cannot_reuse_an_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder/'armed.json').touch()
            with patch.object(cycle.r.host, 'read', return_value=self.intent):
                self.assertEqual(cycle.arm(folder, self.request), self.intent)
                with self.assertRaises(RuntimeError):
                    cycle.arm(folder, dict(self.request, retire=20))

    def test_incomplete_or_writable_successor_never_reclaims(self):
        cert = dict(remote_generation_verified=True, pebble_reopen_verified=True,
                    reopen={'io': dict(sst_write_bytes=0, metadata_write_bytes=0)})
        cases = [dict(cert, remote_generation_verified=False), dict(cert, pebble_reopen_verified=False)]
        for kind in ('metadata_write_bytes', 'sst_write_bytes'):
            changed = copy.deepcopy(cert)
            changed['reopen']['io'][kind] = 1
            cases.append(changed)
        for invalid in cases:
            fake = MagicMock(production={'queue': 0})
            with patch.object(cycle.r, 'read_head', return_value=(self.head, invalid)), \
                    patch.object(cycle.r, 'release', return_value=('release', 'worker')), \
                    patch.object(cycle.stage, 'Stage', return_value=fake), self.assertRaises(RuntimeError):
                cycle.reclaim(Path('/unused'), self.intent)
            fake.reclaim.assert_not_called()

    def test_completed_cycle_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp)/'rhea-clone-retiring-cycles'/'000023'
            store.mkdir(parents=True)
            (store/'completed.json').touch()
            result = dict(intent_sha256=cycle.r.c.digest(self.intent))
            with patch.object(cycle.r, 'ROOT', Path(tmp)/'checkpoints'), patch.object(cycle.r.host, 'mkdir'), \
                    patch.object(cycle, 'arm', return_value=self.intent), patch.object(cycle.r.host, 'read', return_value=result), \
                    patch.object(cycle, 'reclaim') as reclaim:
                self.assertEqual(cycle.run(self.request), result)
                reclaim.assert_not_called()
