"""Offline partial effects occur ONLY in test fakes; no production replay path."""
import copy
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_version_snapshot as s
import rhea_multi_sst_checkpoint_controller as c
import rhea_multi_sst_recovery_inspector as recovery
import test_rhea_multi_sst_checkpoint_controller as pilot


class ReadOnlyVersionClient:
    """GET-only fake; has no put/delete/list mutation surface."""
    def __init__(self, bodies):
        self.bodies, self.calls, self.streams = bodies, [], []

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        name = kwargs['Key'].removeprefix(s.PREFIX)
        body = self.bodies[name]
        stream = io.BytesIO(body)
        self.streams.append(stream)
        return dict(Body=stream, VersionId='v-' + name, ETag='"etag-' + name + '"', ContentLength=len(body))


class VersionSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = c.Store(self.tmp.name)
        self.bodies = {'CURRENT': b'MANIFEST-000001\n',
                       'MANIFEST-000001': b'\x00\xfforiginal\r\n\x00' * (s.CHUNK // 5)}
        self.pins = {name: dict(version_id='v-' + name, etag='etag-' + name, size=len(body), sha256=c.raw_sha(body))
                     for name, body in self.bodies.items()}
        self.client = ReadOnlyVersionClient(self.bodies)

    def capture(self):
        with self.store.lock():
            return s.capture(self.store, self.client, self.pins)

    def test_exact_original_body_and_version_ids_retained_and_reconciled(self):
        self.capture()
        self.assertEqual(s.audit(self.store, self.pins), self.bodies)
        before = {p.name: p.read_bytes() for p in Path(self.tmp.name).iterdir()}
        result = s.reconcile(self.store, self.client, self.pins)
        self.assertFalse(result['full_enumeration_proven'])
        self.assertFalse(result['writer_replay_allowed'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in Path(self.tmp.name).iterdir()})
        self.assertTrue(all(body.closed for body in self.client.streams))
        self.assertEqual(len(self.client.calls), 4)
        for call in self.client.calls:
            self.assertEqual(call['Bucket'], s.BUCKET)
            self.assertTrue(call['VersionId'].startswith('v-'))
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in Path(self.tmp.name).iterdir()))

    def test_no_latest_get_no_unknown_names_or_null_versions(self):
        for key, value in [('version_id', 'null'), ('version_id', ''), ('size', True),
                           ('sha256', 'bad'), ('etag', '"quoted"')]:
            pins = copy.deepcopy(self.pins)
            pins['CURRENT'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.Refusal):
                s.validate_pins(pins)
        for name in ('../CURRENT', 'rhea/pebbleds/CURRENT', '000001.sst', '/CURRENT'):
            with self.subTest(name=name), self.assertRaises(c.Refusal):
                s.validate_pins({name: self.pins['CURRENT']})

    def test_requires_store_lock(self):
        with self.assertRaises(c.Refusal):
            s.capture(self.store, self.client, self.pins)

    def test_fragmented_reads_preserve_bounded_exact_chunks(self):
        class Fragmented(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 8191))
        body = self.bodies['MANIFEST-000001']
        chunks = list(s._pieces(Fragmented(body), len(body)))
        self.assertEqual(b''.join(chunks), body)
        self.assertEqual(len(chunks), (len(body) + s.CHUNK - 1) // s.CHUNK)
        self.assertTrue(all(len(piece) == s.CHUNK for piece in chunks[:-1]))

    def test_audit_rejects_excess_chunks_before_reading_bodies(self):
        self.capture()
        path = Path(self.tmp.name) / 'version-snapshot.json'
        value = c.parse(path.read_bytes())
        ref = value['objects']['CURRENT']
        ref['chunks'] *= 100
        path.write_bytes(c.canonical(value))
        with self.assertRaises(c.Refusal):
            s.audit(self.store, self.pins)

    def test_wrong_version_size_etag_delete_marker_closes_body(self):
        for key, value in [('VersionId', 'other'), ('ContentLength', True), ('ETag', '"other"'), ('DeleteMarker', True)]:
            original = self.client.get_object
            def wrong(**kwargs):
                response = original(**kwargs)
                response[key] = value
                return response
            with self.subTest(key=key), patch.object(self.client, 'get_object', side_effect=wrong), self.assertRaises(c.Refusal):
                s._get(self.client, 'CURRENT', self.pins['CURRENT'])
            self.assertTrue(self.client.streams[-1].closed)

    def test_truncated_longer_and_wrong_body_fail_closed(self):
        for body in (b'', self.bodies['CURRENT'] + b'x', b'x' * len(self.bodies['CURRENT'])):
            with self.subTest(body=body), tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                store = c.Store(tmp)
                client = ReadOnlyVersionClient(dict(self.bodies, CURRENT=body))
                with store.lock(), self.assertRaises(c.Refusal):
                    s.capture(store, client, self.pins)
                self.assertTrue(client.streams[-1].closed)
                with self.assertRaises(FileNotFoundError):
                    store.read('version-snapshot.json')

    def test_snapshot_is_one_attempt_even_after_success(self):
        self.capture()
        calls = len(self.client.calls)
        with self.assertRaises(c.Refusal):
            self.capture()
        self.assertEqual(len(self.client.calls), calls)

    def test_chunk_fsync_crash_retains_orphan_and_forbids_recapture(self):
        original = self.store.put_raw
        def crash(name, raw):
            result = original(name, raw)
            if name.endswith('.bin'):
                raise OSError('simulated crash after chunk fsync, before reference')
            return result
        with patch.object(self.store, 'put_raw', side_effect=crash), self.assertRaises(OSError):
            self.capture()
        before = {p.name: p.read_bytes() for p in Path(self.tmp.name).iterdir()}
        with self.assertRaises(c.Refusal):
            self.capture()
        self.assertEqual(before, {p.name: p.read_bytes() for p in Path(self.tmp.name).iterdir()})
        with self.assertRaises(FileNotFoundError):
            s.audit(self.store, self.pins)

    def test_snapshot_tampering_and_substituted_independent_pin_refuse(self):
        self.capture()
        pins = copy.deepcopy(self.pins)
        pins['CURRENT']['version_id'] = 'different-original-version'
        with self.assertRaises(c.Refusal):
            s.audit(self.store, pins)
        chunk = next(Path(self.tmp.name).glob('version-*.bin'))
        chunk.write_bytes(b'tampered')
        with self.assertRaises(c.Refusal):
            s.audit(self.store, self.pins)

    def test_fresh_get_changes_cannot_reconcile_old_body(self):
        self.capture()
        self.client.bodies = dict(self.bodies, CURRENT=b'x' * len(self.bodies['CURRENT']))
        with self.assertRaises(c.Refusal):
            s.reconcile(self.store, self.client, self.pins)


class PartialBoundaryTests(unittest.TestCase):
    # Reuse only fixture setup/helpers, not inherited historical test methods.
    setUp = pilot.ControllerTests.setUp
    run_engine = pilot.ControllerTests.run_engine

    def assert_manual_and_no_replay(self):
        observer = pilot.Observer(self.host)
        before_calls = list(self.host.calls)
        before_files = {p.name: p.read_bytes() for p in Path(self.temp).iterdir()}
        for _ in range(2):
            result = recovery.inspect(self.temp, observer)
            self.assertEqual(result['decision'], recovery.MANUAL)
            self.assertFalse(result['writer_replay_allowed'])
            self.assertFalse(result['mutations_performed'])
        self.assertEqual(before_calls, self.host.calls)
        self.assertEqual(before_files, {p.name: p.read_bytes() for p in Path(self.temp).iterdir()})
        with self.assertRaises(c.Refusal):
            self.run_engine()
        self.assertEqual(before_calls.count('writer'), self.host.calls.count('writer'))

    def test_service_stopped_before_handoff_receipt(self):
        physical = {'reader_running': True}
        def stop_then_crash(intent):
            physical['reader_running'] = False
            raise pilot.Interrupted('service stop succeeded; no receipt')
        with patch.object(self.host, 'handoff', side_effect=stop_then_crash), self.assertRaises(pilot.Interrupted):
            self.run_engine()
        self.assertFalse(physical['reader_running'])
        self.assertFalse((Path(self.temp) / 'writer_ready.json').exists())
        self.assert_manual_and_no_replay()

    def test_writer_mount_started_before_handoff_receipt(self):
        physical = {'writer_mount': None}
        def mount_then_crash(intent):
            physical['writer_mount'] = copy.deepcopy(self.host.writer_identity)
            raise pilot.Interrupted('mount started; receipt missing')
        with patch.object(self.host, 'handoff', side_effect=mount_then_crash), self.assertRaises(pilot.Interrupted):
            self.run_engine()
        self.assertIsNotNone(physical['writer_mount'])
        self.assertEqual(self.host.writer_calls, 0)
        self.assert_manual_and_no_replay()

    def test_first_compaction_committed_without_go_or_controller_receipt(self):
        physical = {'commits': 0}
        def compact_then_crash(request, monitor):
            monitor()
            self.host.calls.append('writer')
            self.host.writer_calls += 1
            physical['commits'] = 1
            raise pilot.Interrupted('MANIFEST fsynced after first compaction; receipt absent')
        with patch.object(self.host, 'run_go_monitored', side_effect=compact_then_crash), self.assertRaises(pilot.Interrupted):
            self.run_engine()
        self.assertEqual(physical['commits'], 1)
        self.assertFalse((Path(self.temp) / 'writer_closed.json').exists())
        self.assert_manual_and_no_replay()

    def test_upload_queued_with_marker_withheld_before_drain_receipt(self):
        physical = {'queued': 0, 'markers_withheld': True}
        def queue_then_crash(snapshot):
            physical['queued'] = 1
            raise pilot.Interrupted('data upload queued; no drain receipt')
        with patch.object(self.host, 'drain_stop', side_effect=queue_then_crash), self.assertRaises(pilot.Interrupted):
            self.run_engine()
        self.assertEqual(physical, dict(queued=1, markers_withheld=True))
        self.assertNotIn('publish', self.host.calls)
        self.assert_manual_and_no_replay()

    def test_marker_publication_succeeded_but_receipt_missing(self):
        original = self.host.publish_markers
        def publish_then_crash(before, metadata):
            original(before, metadata)
            raise pilot.Interrupted('publication uncertain to controller')
        with patch.object(self.host, 'publish_markers', side_effect=publish_then_crash), self.assertRaises(pilot.Interrupted):
            self.run_engine()
        self.assertEqual(self.host.calls.count('publish'), 1)
        self.assertTrue((Path(self.temp) / 'marker_intent.json').exists())
        self.assertFalse((Path(self.temp) / 'markers_published.json').exists())
        self.assert_manual_and_no_replay()


if __name__ == '__main__':
    unittest.main()
