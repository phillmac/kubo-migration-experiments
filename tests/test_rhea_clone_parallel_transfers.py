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


class ProofReads(unittest.TestCase):
    def setUp(self):
        self.names = [f'{i:06d}.sst' for i in range(1, 9)]
        self.contents = {n: n.encode() for n in self.names}
        self.latest = {runner.proof.PREFIX+n: dict(VersionId='v-'+n, Size=len(data), ETag='"'+n+'"')
                       for n, data in self.contents.items()}
        self.hashes = {n: dict(size=len(data), sha256=runner.c.raw_sha(data)) for n, data in self.contents.items()}

    def readers(self, bad=None, *, block=False):
        barrier = threading.Barrier(4)
        clients = [Mock(spec=['get_object', 'head_object']) for _ in range(4)]
        for client in clients:
            def head(*, Bucket, Key):
                self.assertEqual(Bucket, runner.proof.v.BUCKET)
                row = self.latest[Key]
                version = 'stale' if bad == 'head' and Key.endswith(self.names[0]) else row['VersionId']
                return dict(VersionId=version, ContentLength=row['Size'], ETag=row['ETag'])

            def get(*, Bucket, Key, VersionId):
                name = Key[len(runner.proof.PREFIX):]
                self.assertEqual(VersionId, self.latest[Key]['VersionId'])
                if block and name in self.names[:4]:
                    barrier.wait(timeout=10)
                row = self.latest[Key]
                data = self.contents[name]
                if bad == 'hash' and name == self.names[0]:
                    data = b'x' * len(data)
                version = 'stale' if bad == 'version' and name == self.names[0] else VersionId
                return dict(VersionId=version, ContentLength=len(data), ETag=row['ETag'], Body=io.BytesIO(data))

            client.get_object.side_effect = get
            client.head_object.side_effect = head
        return clients

    def test_proofs_fetch_each_pinned_version_again_and_measure_overlap(self):
        proofs = []
        for _ in range(2):
            clients = self.readers(block=True)
            pins, metrics = runner.bulk.hash_proof_ssts(clients, self.hashes, self.latest, self.hashes)
            proofs.append(pins)
            report = dict(created_sst_versions=pins, sst_read_metrics=metrics)
            runner.bulk.check_read_metrics(report, 4)
            self.assertTrue(all(c.get_object.called and c.head_object.called for c in clients))
            keys = [call.kwargs['Key'] for c in clients for call in c.get_object.call_args_list]
            self.assertCountEqual(keys, self.latest)
            first = [metrics['intervals_ns'][name] for name in self.names[:4]]
            self.assertLess(max(a for a, _ in first), min(b for _, b in first))
            for n, pin in pins.items():
                self.assertEqual(pin['sha256'], self.hashes[n]['sha256'])
                self.assertEqual(pin['version_id'], self.latest[runner.proof.PREFIX+n]['VersionId'])
            with self.assertRaises(RuntimeError):
                runner.bulk.check_read_metrics(report, 1)
            with self.assertRaises(RuntimeError):
                runner.bulk.check_read_metrics(dict(report, created_sst_versions={}), 4)
            with self.assertRaises(RuntimeError):
                runner.bulk.check_read_metrics(dict(report, sst_read_metrics=dict(metrics, workers=1)), 1)
        self.assertEqual(proofs[0], proofs[1])

    def test_later_pass_rejects_wrong_body_version_and_latest_head(self):
        runner.bulk.hash_proof_ssts(self.readers(), self.hashes, self.latest, self.hashes)
        for failure in ('hash', 'version', 'head'):
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                runner.bulk.hash_proof_ssts(self.readers(failure), self.hashes, self.latest, self.hashes)

    def test_generation_19_signs_readers_independently_of_uploaders(self):
        head = dict(sha256='parent', generation=18)
        binding = dict(scope=launcher.SCOPE, target=launcher.TARGET, anchor_sha256=launcher.ANCHOR,
                       generation=19, previous_checkpoint_sha256='parent', release_sha256='release',
                       worker_sha256='worker', limits=runner.bulk.limits_for(19), sst_workers=4, proof_workers=2,
                       request=dict(maximum_units=64, before=dict(format='013', marked=1)),
                       first_inputs=['table'], production=dict(queue=0, uploadsInProgress=0, erroredFiles=0))
        launcher.validate(binding, head, 19, 'release', 'worker', sst_workers=4, proof_workers=2)
        for value in (None, True, 0, 1, 4, 5):
            with self.assertRaises(RuntimeError):
                launcher.validate(dict(binding, proof_workers=value), head, 19, 'release', 'worker',
                                  sst_workers=4, proof_workers=2)
