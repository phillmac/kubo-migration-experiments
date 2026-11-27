"""Exercise the transfer window and the existing exact-key recovery boundary."""
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_clone_batch_runner as runner
import run_rhea_clone_batch as launcher
from test_rhea_gen14_create_only_checkpoint import VersionedStore


class TableStore(VersionedStore):
    def head_object(self, **kwargs):
        row, = self.versions
        assert row['Key'] == kwargs['Key']
        return dict(VersionId=row['VersionId'], ETag=row['ETag'], ContentLength=row['Size'])

    def get_object(self, **kwargs):
        result = self.head_object(**kwargs)
        assert result['VersionId'] == kwargs['VersionId']
        return dict(result, Body=io.BytesIO(b'table'))


class ParallelTransfers(unittest.TestCase):
    def setUp(self):
        self.names = [f'{i:06d}.sst' for i in range(1, 10)]
        self.pin = dict(size=5, sha256=runner.c.raw_sha(b'table'))
        self.hashes = dict.fromkeys(self.names, self.pin)

    def test_four_transfers_overlap_without_sharing_a_busy_client(self):
        clients = [object() for _ in range(4)]
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        active, completed = set(), []
        def upload(client, name, pin):
            with lock:
                self.assertNotIn(client, active)
                active.add(client)
            if name in self.names[:4]:
                barrier.wait(timeout=10)
            with lock:
                active.remove(client)
                completed.append(name)
        runner.transfer_ssts(self.hashes, clients, upload)
        self.assertCountEqual(completed, self.names)
        self.assertFalse(active)

    def test_reconcile_mixed_put_outcomes_and_unstarted_keys(self):
        stores = {name: TableStore() for name in self.names}
        first, second = self.names[:2]
        barrier = threading.Barrier(2)
        original_put = stores[first].put_object
        def lose_reply(**kwargs):
            barrier.wait(timeout=10)
            original_put(**kwargs)
            raise TimeoutError('reply lost after create')
        def no_create(**kwargs):
            barrier.wait(timeout=10)
            raise TimeoutError('request failed before create')
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(runner.host, 'put', lambda path, obj: path.write_bytes(runner.c.canonical(obj))), \
             patch.object(runner.host, 'read', lambda path: json.loads(path.read_bytes())):
            state = Path(tmp)
            for name in self.names:
                (state/name).write_bytes(b'table')
            def send(reconcile):
                def upload(client, name, pin):
                    cloud = stores[name]
                    return runner.pilot.conditional_upload(cloud, cloud, 'owner', 'writer', state/name,
                                                          pin, state=state, reconcile_missing=reconcile)
                runner.transfer_ssts(self.hashes, [object(), object()], upload)
            with patch.object(stores[first], 'put_object', lose_reply), \
                 patch.object(stores[second], 'put_object', no_create), self.assertRaises(TimeoutError):
                send(False)
            self.assertEqual(len(list(state.glob('put-*.intent.json'))), 2)
            self.assertFalse(list(state.glob('put-*.receipt.json')))
            self.assertEqual((stores[first].puts, stores[second].puts), (1, 0))
            send(True)
            self.assertTrue((state/f'put-{second}.reconciled-empty.json').exists())
            self.assertFalse((state/f'put-{first}.reconciled-empty.json').exists())
            self.assertEqual(len(list(state.glob('put-*.receipt.json'))), len(stores))
            self.assertTrue(all(store.puts == 1 for store in stores.values()))

    def test_invalid_names_and_worker_counts_never_submit_a_transfer(self):
        upload = Mock()
        for n in (0, 5, True, 1.5):
            with self.assertRaises(RuntimeError):
                runner.sst_worker_count(n)
        for name in ('MANIFEST-000101', 'marker.manifest.000018.MANIFEST-000101', '../000001.sst'):
            with self.assertRaises(RuntimeError):
                runner.transfer_ssts({**self.hashes, name: self.pin}, [object(), object()], upload)
        upload.assert_not_called()

    def test_jump_signer_checks_the_requested_upload_width(self):
        head = dict(sha256='parent', generation=17)
        binding = dict(scope=launcher.SCOPE, target=launcher.TARGET, anchor_sha256=launcher.ANCHOR,
                       generation=18, previous_checkpoint_sha256='parent', release_sha256='release',
                       worker_sha256='worker', limits=runner.bulk.limits_for(18), sst_workers=4,
                       request=dict(maximum_units=64, before=dict(format='013', marked=1)),
                       first_inputs=['table'], production=dict(queue=0, uploadsInProgress=0, erroredFiles=0))
        launcher.validate(binding, head, 18, 'release', 'worker', sst_workers=4)
        for value in (None, 1, 5, True):
            with self.assertRaises(RuntimeError):
                launcher.validate(dict(binding, sst_workers=value), head, 18, 'release', 'worker', sst_workers=4)
