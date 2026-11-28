"""Isolated fakes for denied cache retries, shutdown/quarantine and publication."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_rclone_rehearsal as r
import rhea_gen14_publication_recovery as recovery

SECRET = 'OFFLINE-WRITER-SECRET-CANARY'
WRITER = dict(role='writer', endpoint=r.p.S3_ENDPOINT, region='ca-central-1',
              AccessKeyId='OFFLINEWRITERKEY00001', SecretAccessKey=SECRET)


class Journal:
    def __init__(self): self.records = {}
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def exists(self, name): return name in self.records
    def read(self, name): return copy.deepcopy(self.records[name])
    def write(self, name, value):
        assert name not in self.records
        assert SECRET not in repr(value)
        self.records[name] = copy.deepcopy(value)


class Clock:
    value = 0
    def now(self): return self.value
    def sleep(self, seconds): self.value += seconds


class Host:
    def __init__(self, events):
        self.events, self.samples, self.stopped = events, 0, False
        self.tries = 2
        self.error_count = 2
        self.queue_uploading = False
        self.stop_failure = False
        self.observe_failure = False
        self.proof_failure = None
        self.proof_calls = 0
        self.fixed_proof = dict(writer_stopped=True, unmounted=True, open_references=0,
            restart_paths_blocked=True, quarantine='/fake/private/quarantine',
            cache_quarantined=True, dirty_payload_preserved=True,
            cache_manifest_sha256='1' * 64)

    def prepare(self, writer):
        assert writer == WRITER
        self.events.append('prepare-writer')
    def start(self): self.events.append('start-writer')
    def write(self, name, payload):
        assert (name, payload) in ((r.DATA, r.PAYLOAD), (r.DIRTY, r.DIRTY_PAYLOAD))
        self.events.append('write-' + name)
    def observe(self):
        self.events.append('observe-writer')
        if self.observe_failure: raise RuntimeError(SECRET)
        self.samples += 1
        return dict(queue=[dict(name=r.DIRTY, id=7, size=len(r.DIRTY_PAYLOAD),
                               tries=self.tries, uploading=self.queue_uploading, delay=5)],
                    uploads_in_progress=int(self.queue_uploading), uploads_queued=1,
                    access_denials=self.error_count)
    def defer_dirty(self, row):
        assert row['name'] == r.DIRTY and not row['uploading']
        self.events.append('defer-dirty')
    def stop_and_quarantine(self):
        self.events.append('stop-quarantine')
        self.stopped = True
        if self.stop_failure: raise RuntimeError(SECRET)
        return self.proof()
    def proof(self):
        self.events.append('writer-proof')
        assert self.stopped, 'proof before writer stopped'
        self.proof_calls += 1
        result = self.fixed_proof.copy()
        if self.proof_failure is not None: result[self.proof_failure] = False
        return result


class Cloud:
    def __init__(self, events):
        self.events, self.history_calls, self.mpu_checks, self.published = events, 0, 0, False
        self.changed_history = False
        self.outstanding_upload = False
        self.uploaded = True
        self.admin = types.SimpleNamespace(close=lambda: None)
        self.baseline = [dict(key='fixed-CURRENT', version='v1', latest=True, sha256='0' * 64)]
    def history(self):
        self.events.append('read-history')
        self.history_calls += 1
        value = copy.deepcopy(self.baseline)
        if self.changed_history and self.history_calls > 1: value[0]['version'] = 'unexpected'
        return value
    def no_uploads(self):
        self.events.append('check-multipart')
        self.mpu_checks += 1
        if self.outstanding_upload and self.mpu_checks > 1: raise r.REFUSAL('unconfirmed upload')
    def data_absent(self): self.events.append('data-absent')
    def data_uploaded(self):
        self.events.append('data-readback')
        return 'data-version-1' if self.uploaded else None
    def publish(self, baseline):
        assert 'stop-quarantine' in self.events
        assert self.history_calls == 2 and self.mpu_checks == 2
        assert baseline == self.baseline
        self.events.append('publisher-put')
        self.published = True
        return dict(version_id='published-version', protected_versions=2, history_sha256='2' * 64)


class RehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rclone-rehearsal-FAKE-')
        self.addCleanup(self.temp.cleanup)
        self.enterContext(patch.object(r, 'STATE', Path(self.temp.name) / 'state'))
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.enterContext(patch.object(socket, 'create_connection', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.events = []
        self.host, self.cloud, self.journal = Host(self.events), Cloud(self.events), Journal()
        self.clock = Clock()
        self.enterContext(patch.object(r, 'WAIT_SECONDS', 3))

    def exercise(self):
        return r.rehearse(self.host, self.cloud, self.journal, WRITER,
                          now=self.clock.now, sleep=self.clock.sleep)

    def test_publication_requires_denial_retries_complete_quarantine_and_history(self):
        result = self.exercise()
        self.assertEqual(result['result'], 'PASS')
        self.assertTrue(result['writer_cache_quarantined'])
        self.assertEqual(result['denied_upload_attempts'], 2)
        self.assertLess(self.events.index('defer-dirty'), self.events.index('stop-quarantine'))
        self.assertLess(self.events.index('stop-quarantine'), self.events.index('publisher-put'))
        self.assertEqual(self.cloud.mpu_checks, 3)
        self.assertFalse(result['production_cutover_authorized'])
        for name in self.journal.records:
            if name.endswith('.intent.json'):
                self.assertIn(name.replace('.intent.', '.receipt.'), self.journal.records)

    def test_zero_or_one_retry_and_missing_explicit_denial_cannot_pass(self):
        for tries, errors in ((0, 2), (1, 2), (2, 0), (2, 1)):
            with self.subTest(tries=tries, errors=errors):
                self.host.tries, self.host.error_count = tries, errors
                with self.assertRaises(r.REFUSAL): self.exercise()
                self.assertTrue(self.host.stopped)
                self.assertFalse(self.cloud.published)
                self.assertIn('08-observe-0000.receipt.json', self.journal.records)
                self.events = []
                self.host, self.cloud, self.journal = Host(self.events), Cloud(self.events), Journal()
                self.clock = Clock()

    def test_data_upload_is_required_before_publisher(self):
        self.cloud.uploaded = False
        with self.assertRaises(r.REFUSAL): self.exercise()
        self.assertTrue(self.host.stopped)
        self.assertFalse(self.cloud.published)

    def test_inflight_dirty_upload_is_not_quiescence(self):
        self.host.queue_uploading = True
        with self.assertRaises(r.REFUSAL): self.exercise()
        self.assertTrue(self.host.stopped)
        self.assertFalse(self.cloud.published)

    def test_observation_failure_still_stops_and_quarantines(self):
        self.host.observe_failure = True
        with self.assertRaises(RuntimeError): self.exercise()
        self.assertTrue(self.host.stopped)
        self.assertFalse(self.cloud.published)

    def test_shutdown_failure_blocks_publisher(self):
        self.host.stop_failure = True
        with self.assertRaises(RuntimeError): self.exercise()
        self.assertFalse(self.cloud.published)

    def test_every_required_stop_proof_blocks_publisher_when_missing(self):
        for field in ('writer_stopped', 'unmounted', 'restart_paths_blocked',
                      'cache_quarantined', 'dirty_payload_preserved'):
            with self.subTest(field=field):
                self.host.proof_failure = field
                with self.assertRaises(r.REFUSAL): self.exercise()
                self.assertFalse(self.cloud.published)
                self.events = []
                self.host, self.cloud, self.journal = Host(self.events), Cloud(self.events), Journal()
                self.clock = Clock()

    def test_open_handles_block_publisher(self):
        self.host.fixed_proof['open_references'] = 1
        with self.assertRaises(r.REFUSAL): self.exercise()
        self.assertFalse(self.cloud.published)

    def test_outstanding_test_mpu_blocks_publisher(self):
        self.cloud.outstanding_upload = True
        with self.assertRaises(r.REFUSAL): self.exercise()
        self.assertFalse(self.cloud.published)

    def test_any_protected_history_change_blocks_publisher(self):
        self.cloud.changed_history = True
        with self.assertRaises(r.REFUSAL): self.exercise()
        self.assertFalse(self.cloud.published)

    def test_late_writer_proof_change_blocks_publisher(self):
        proof = self.host.proof
        def changed_proof():
            value = proof()
            if self.host.proof_calls >= 3: value['writer_stopped'] = False
            return value
        self.host.proof = changed_proof
        with self.assertRaises(r.REFUSAL): self.exercise()
        self.assertFalse(self.cloud.published)

    def test_failure_report_is_redacted_cached_and_never_restarts_writer(self):
        self.host.observe_failure = True
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        self.enterContext(patch.dict(os.environ))
        with patch.object(r, 'Journal', return_value=self.journal), \
             patch.object(r, 'load_context', return_value=(WRITER, self.cloud, '1' * 64)), \
             patch.object(r, 'NativeHost', return_value=self.host), \
             patch.object(r.os, 'getuid', return_value=0), \
             patch.object(r.os, 'geteuid', return_value=0):
            output = io.StringIO()
            with redirect_stdout(output): self.assertEqual(r.main(['run']), 2)
            value = json.loads(output.getvalue())
            self.assertEqual(value['result'], 'REFUSED')
            self.assertFalse(value['actual_rehearsal_proven'])
            self.assertNotIn(SECRET, output.getvalue())
            calls = list(self.events)
            self.assertEqual(r.run('run'), value)
            self.assertEqual(self.events, calls)


class NativeHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-rclone-FAKE-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.paths = r.HostPaths(self.base)
        self.host = r.NativeHost(self.paths, r.REMOTE, expected_dirty={r.DIRTY: r.DIRTY_PAYLOAD})
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.enterContext(patch.object(r, 'mount_present', return_value=False))
        self.refs = self.enterContext(patch.object(r, 'references', return_value=[]))
        self.enterContext(patch.object(r.p, 'OWNER', os.getuid()))
        def directory(path, *, create=False, private=False):
            self.assertTrue(path == self.base or path.is_relative_to(self.base))
            if create: path.mkdir(mode=0o700, exist_ok=True)
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.enterContext(patch.object(r.p, 'directory', directory))

    def cache_fixture(self):
        self.host.prepare(WRITER)
        path = self.paths.cache / 'vfs' / 'iam_writer' / 'fixture' / r.DIRTY
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_bytes(r.DIRTY_PAYLOAD)
        path.chmod(0o600)
        return path

    def test_writer_only_config_rejects_publisher_and_multiline_values(self):
        raw = r.writer_config(WRITER, r.REMOTE)
        self.assertEqual(raw.count(b'[iam_writer]'), 1)
        self.assertIn(b'no_check_bucket = true', raw)
        self.assertNotIn(b'publisher', raw)
        for patch_value in (dict(role='publisher'), dict(SecretAccessKey=SECRET + '\n[other]')):
            with self.subTest(patch_value=patch_value):
                with self.assertRaises(r.REFUSAL):
                    r.writer_config(dict(WRITER, **patch_value), r.REMOTE)

    def test_command_has_private_paths_authenticated_loopback_and_no_cloud_keys(self):
        self.host.password = 'OFFLINE-RC-PASSWORD'
        args, env = self.host.command()
        self.assertIn('127.0.0.1:5574', args)
        self.assertNotIn('--daemon', args)
        self.assertNotIn('--rc-no-auth', args)
        self.assertNotIn('OFFLINE-RC-PASSWORD', repr(args))
        self.assertNotIn(SECRET, repr(args) + repr(env))
        self.assertEqual(env['RCLONE_RC_PASS'], 'OFFLINE-RC-PASSWORD')
        self.assertEqual(set(env), {'PATH', 'HOME', 'LC_ALL', 'RCLONE_RC_USER', 'RCLONE_RC_PASS'})
        self.assertEqual(args[args.index('--config') + 1], str(self.paths.config))
        self.assertEqual(args[args.index('--cache-dir') + 1], str(self.paths.cache))

    def test_quarantine_retains_dirty_bytes_and_blocks_original_restart_paths(self):
        self.cache_fixture()
        result = self.host.stop_and_quarantine()
        self.assertTrue(result['dirty_payload_preserved'])
        self.assertTrue(result['restart_paths_blocked'])
        for path in (self.paths.cache, self.paths.config, self.paths.auth, self.paths.mount):
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(SECRET, path.read_text())
        retained = self.paths.quarantine / 'cache/vfs/iam_writer/fixture' / r.DIRTY
        self.assertEqual(retained.read_bytes(), r.DIRTY_PAYLOAD)
        self.assertIn(SECRET, (self.paths.quarantine / 'writer.conf').read_text())
        self.assertEqual(stat.S_IMODE(self.paths.quarantine.stat().st_mode), 0o700)
        self.assertEqual(self.host.proof(), result)

    def test_missing_dirty_payload_cannot_prove_quarantine(self):
        self.host.prepare(WRITER)
        with self.assertRaises(r.REFUSAL): self.host.stop_and_quarantine()

    def test_quarantined_cache_tampering_invalidates_proof(self):
        self.cache_fixture()
        self.host.stop_and_quarantine()
        retained = self.paths.quarantine / 'cache/vfs/iam_writer/fixture' / r.DIRTY
        retained.write_bytes(b'changed')
        with self.assertRaises(r.REFUSAL): self.host.proof()

    def test_restored_writer_config_cannot_masquerade_as_restart_blocker(self):
        self.cache_fixture()
        self.host.stop_and_quarantine()
        self.paths.config.write_bytes(r.writer_config(WRITER, r.REMOTE))
        with self.assertRaises(r.REFUSAL): self.host.proof()

    def test_open_references_prevent_cache_move(self):
        self.cache_fixture()
        self.refs.return_value = [dict(pid=123, kind='descriptor')]
        with self.assertRaises(r.REFUSAL): self.host.stop_and_quarantine()
        self.assertTrue(self.paths.cache.is_dir())

    def test_fuse_write_has_timeout_and_no_ambient_or_cloud_credentials(self):
        self.host.process = types.SimpleNamespace(poll=lambda: None)
        with patch.object(r, 'mount_present', return_value=True), \
             patch.object(r.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.host.write(r.DIRTY, r.DIRTY_PAYLOAD)
            self.assertEqual(run.call_args.kwargs['timeout'], 20)
            self.assertEqual(run.call_args.kwargs['input'], r.DIRTY_PAYLOAD)
            self.assertEqual(set(run.call_args.kwargs['env']), {'PATH', 'HOME', 'LC_ALL'})
            with self.assertRaises(r.REFUSAL): self.host.write('arbitrary', b'x')
            with self.assertRaises(r.REFUSAL): self.host.write(r.DATA, b'x' * 1025)
            self.assertEqual(run.call_count, 1)

    def test_vfs_queue_schema_cache_scope_and_explicit_denials(self):
        self.host.process = types.SimpleNamespace(poll=lambda: None, pid=123)
        self.host.vfs_fs = r.REMOTE.fs
        queue = dict(queued=[dict(name=r.DIRTY, id=4, tries=2, uploading=False)])
        stats = dict(diskCache=dict(path=str(self.paths.cache / 'vfs'),
            pathMeta=str(self.paths.cache / 'vfsMeta'), outOfSpace=False, bytesUsed=200,
            uploadsQueued=1, uploadsInProgress=0))
        with patch.object(r, 'listener_owned', return_value=True), \
             patch.object(self.host, 'rc', side_effect=lambda method, params: (200, queue if method == 'vfs/queue' else stats)), \
             patch.object(self.host, 'log_denials', return_value=2):
            self.assertEqual(self.host.observe()['access_denials'], 2)
            stats['diskCache']['path'] = str(self.paths.cache / '../production')
            with self.assertRaises(r.REFUSAL): self.host.observe()

    def test_actual_vfs_identity_accepts_only_one_bound_backend(self):
        actual = r.REMOTE.fs.replace('iam_writer:', 'iam_writer{aB3_-}:')
        with patch.object(self.host, 'rc', return_value=(200, dict(vfses=[actual]))) as rc:
            self.host.bind_vfs()
            self.assertEqual(self.host.vfs_fs, actual)
            rc.assert_called_once_with('vfs/list')
        for names in ([], [actual, actual], ['other:' + actual.split(':', 1)[1]],
                      [r.REMOTE.fs + '-wrong'], [r.REMOTE.fs + '/../outside']):
            with self.subTest(names=names):
                with patch.object(self.host, 'rc', return_value=(200, dict(vfses=names))):
                    with self.assertRaises(r.REFUSAL): self.host.bind_vfs()


def response(**kwargs):
    return dict(ResponseMetadata=dict(HTTPStatusCode=200, RetryAttempts=0), **kwargs)


class CloudAdmin:
    def __init__(self):
        self.rows = [dict(Key=r.REMOTE.prefix + r.DIRTY, VersionId='current-v1', IsLatest=True),
                     dict(Key=r.REMOTE.prefix + r.p.admin.MARKER, VersionId='marker-old', IsLatest=False),
                     dict(Key=r.REMOTE.prefix + r.p.admin.MARKER, VersionId='marker-now', IsLatest=True)]
        self.bodies = {'current-v1': b'original CURRENT', 'marker-old': b'earlier test',
                       'marker-now': b'fresh extended-test marker'}
        self.deleted, self.truncated, self.invalid_read_version = [], False, False
        self.multipart = {bucket: [] for bucket in (r.p.admin.TEST_BUCKET, r.p.admin.CONTROL_BUCKET)}
        self.multipart_calls, self.reads, self.streams = [], [], []
    def list_object_versions(self, **kwargs):
        assert kwargs == dict(Bucket=r.REMOTE.bucket, ExpectedBucketOwner='123456789012',
                             Prefix=r.REMOTE.prefix, MaxKeys=1000)
        return response(Versions=copy.deepcopy(self.rows), DeleteMarkers=self.deleted,
                        IsTruncated=self.truncated)
    def get_object(self, **kwargs):
        assert kwargs['Bucket'] == r.REMOTE.bucket and kwargs['ExpectedBucketOwner'] == '123456789012'
        version = kwargs.get('VersionId') or next(
            row['VersionId'] for row in self.rows if row['Key'] == kwargs['Key'] and row['IsLatest'])
        stream = io.BytesIO(self.bodies[version])
        self.streams.append(stream)
        self.reads.append(copy.deepcopy(kwargs))
        return response(Body=stream, VersionId='null' if self.invalid_read_version else version,
                        ETag='"etag-' + version + '"')
    def list_multipart_uploads(self, **kwargs):
        assert kwargs['Bucket'] in self.multipart
        assert kwargs['ExpectedBucketOwner'] == '123456789012' and kwargs['MaxUploads'] == 1000
        assert 'Prefix' not in kwargs
        self.multipart_calls.append(kwargs['Bucket'])
        return response(Uploads=self.multipart[kwargs['Bucket']], IsTruncated=False)


class CloudChecksTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.enterContext(patch.object(socket, 'create_connection', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.admin = CloudAdmin()
        self.factory = Mock(side_effect=AssertionError('PUBLISHER MUST REMAIN UNLOADED'))
        self.cloud = r.Cloud('123456789012', self.admin, self.factory)

    def test_history_derives_fresh_body_etag_and_reads_all_previous_versions(self):
        history = self.cloud.history()
        self.assertEqual(len(history), 3)
        current = next(row for row in history if row['version'] == 'marker-now')
        self.assertEqual(current['sha256'], r.p.sha(b'fresh extended-test marker'))
        self.assertEqual(current['etag'], '"etag-marker-now"')
        self.assertEqual({row['VersionId'] for row in self.admin.reads}, set(self.admin.bodies))
        self.assertTrue(all(stream.closed for stream in self.admin.streams))
        self.factory.assert_not_called()

    def test_truncated_deleted_ambiguous_or_invalid_version_history_is_refused(self):
        cases = ('truncated', 'deleted', 'duplicate', 'missing-latest', 'null-version', 'oversized')
        for case in cases:
            with self.subTest(case=case):
                admin = CloudAdmin()
                if case == 'truncated': admin.truncated = True
                if case == 'deleted': admin.deleted = [dict(Key=r.REMOTE.prefix + r.DIRTY, VersionId='delete')]
                if case == 'duplicate': admin.rows.append(admin.rows[0].copy())
                if case == 'missing-latest': admin.rows[0]['IsLatest'] = False
                if case == 'null-version': admin.invalid_read_version = True
                if case == 'oversized': admin.bodies['current-v1'] = b'x' * 1025
                cloud = r.Cloud('123456789012', admin, self.factory)
                with self.assertRaises(r.REFUSAL): cloud.history()
                self.assertTrue(all(stream.closed for stream in admin.streams))
        self.factory.assert_not_called()

    def test_no_uploads_checks_both_entire_disposable_buckets(self):
        self.cloud.no_uploads()
        self.assertEqual(self.admin.multipart_calls, [r.p.admin.TEST_BUCKET, r.p.admin.CONTROL_BUCKET])
        self.admin.multipart[r.p.admin.CONTROL_BUCKET] = [dict(Key='outside-prefix', UploadId='orphan')]
        with self.assertRaises(r.REFUSAL): self.cloud.no_uploads()
        self.factory.assert_not_called()

    def publisher(self, *, corrupt_old=False, missing_version=False):
        publisher = Mock()
        def put(**kwargs):
            self.assertEqual(kwargs, dict(Bucket=r.REMOTE.bucket, ExpectedBucketOwner='123456789012',
                Key=r.REMOTE.prefix + r.p.admin.MARKER, Body=r.PUBLISH_PAYLOAD, IfMatch='"etag-marker-now"'))
            for row in self.admin.rows:
                if row['Key'] == kwargs['Key']: row['IsLatest'] = False
            self.admin.rows.append(dict(Key=kwargs['Key'], VersionId='published-v1', IsLatest=True))
            self.admin.bodies['published-v1'] = r.PUBLISH_PAYLOAD
            if corrupt_old: self.admin.bodies['marker-old'] = b'corrupted historical marker'
            return response(**({} if missing_version else dict(VersionId='published-v1')))
        publisher.put_object.side_effect = put
        self.factory.side_effect = None
        self.factory.return_value = publisher
        self.enterContext(patch.object(r.live, 'ConditionalS3', side_effect=lambda client: client))
        return publisher

    def test_conditional_publisher_uses_fresh_etag_then_preserves_all_history(self):
        baseline = self.cloud.history()
        publisher = self.publisher()
        result = self.cloud.publish(baseline)
        self.assertEqual(result['version_id'], 'published-v1')
        self.assertEqual(result['protected_versions'], 4)
        self.factory.assert_called_once_with()
        publisher.close.assert_called_once_with()

    def test_conditional_publication_refuses_historical_mutation_or_missing_receipt(self):
        for corrupt, missing in ((True, False), (False, True)):
            with self.subTest(corrupt=corrupt, missing=missing):
                self.admin = CloudAdmin()
                self.cloud = r.Cloud('123456789012', self.admin, self.factory)
                baseline = self.cloud.history()
                publisher = self.publisher(corrupt_old=corrupt, missing_version=missing)
                with self.assertRaises(r.REFUSAL): self.cloud.publish(baseline)
                publisher.close.assert_called_once_with()


class LostAcknowledgementTests(unittest.TestCase):
    def setUp(self):
        self.admin, self.journal, self.publisher = CloudAdmin(), Journal(), Mock()
        self.cloud = r.Cloud('123456789012', self.admin, None)
        self.enterContext(patch.object(r.live, 'ConditionalS3', side_effect=lambda client: client))
        self.close_proof, self.plan = 'f' * 64, 'a' * 64

    def publish(self, case):
        def put(**kwargs):
            intent = self.journal.read('lost-ack-' + case + '.intent.json')
            self.assertEqual(kwargs, self.cloud.params(intent['key'], Body=b'', **intent['condition']))
            key = kwargs['Key']
            for row in self.admin.rows:
                if row['Key'] == key:
                    row['IsLatest'] = False
            self.admin.rows.append(dict(Key=key, VersionId='lost-ack-version', IsLatest=True))
            self.admin.bodies['lost-ack-version'] = b''
            return response()  # The version receipt is unavailable to the caller.
        self.publisher.put_object.side_effect = put
        with self.assertRaises(SystemExit) as caught:
            recovery.send_once(self.journal, self.cloud, case, self.plan, self.close_proof,
                               lambda: self.publisher, crash=sys.exit)
        self.assertEqual(caught.exception.code, recovery.LOST_ACK_EXIT)
        self.assertEqual(len(self.journal.records), 1)

    def observe(self, case):
        return recovery.observe(self.journal, self.cloud, case, self.plan, self.close_proof)

    def test_existing_marker_after_lost_acknowledgement(self):
        self.publish('replace')
        out = self.observe('replace')
        self.assertEqual(out['decision'], 'EXPECTED_VERSION_OBSERVED')
        self.assertEqual(out['observed_version'], 'lost-ack-version')
        self.assertFalse(out['retry_allowed'] or out['checkpoint_certified'])
        with self.assertRaises(r.REFUSAL):
            recovery.send_once(self.journal, self.cloud, 'replace', self.plan, self.close_proof,
                               lambda: self.fail('reloaded publisher after pending intent'))
        self.publisher.put_object.assert_called_once()

    def test_create_only_and_newer_competing_version(self):
        self.publish('create')
        self.assertEqual(self.observe('create')['condition'], 'IfNoneMatch')
        self.admin.rows[-1]['IsLatest'] = False
        self.admin.rows.append(dict(Key=recovery.CREATE, VersionId='competing', IsLatest=True))
        self.admin.bodies['competing'] = b''
        out = self.observe('create')
        self.assertEqual(out['decision'], 'CONFLICTING_HISTORY')
        self.assertFalse(out['retry_allowed'])
        self.assertIsNone(out['observed_version'])

    def test_unchanged_baseline_rejects_replay_and_changed_intent(self):
        baseline = self.cloud.history(extra_key=recovery.CREATE)
        self.journal.write('lost-ack-create.intent.json',
                           recovery.make_intent('create', baseline, self.plan, self.close_proof))
        out = self.observe('create')
        self.assertEqual(out['decision'], 'BASELINE_UNCHANGED')
        self.assertFalse(out['retry_allowed'])
        self.journal.records['lost-ack-create.intent.json']['condition'] = {'IfMatch': '*'}
        with self.assertRaises(r.REFUSAL):
            self.observe('create')

    def test_changed_old_or_new_payload_and_old_latest_conflict(self):
        self.publish('replace')
        for ver in ('current-v1', 'marker-old', 'lost-ack-version'):
            with self.subTest(version=ver), patch.dict(self.admin.bodies, {ver: b'different'}):
                self.assertEqual(self.observe('replace')['decision'], 'CONFLICTING_HISTORY')
        self.admin.rows[-2]['IsLatest'] = True
        self.admin.rows[-1]['IsLatest'] = False
        self.assertEqual(self.observe('replace')['decision'], 'CONFLICTING_HISTORY')

    def test_change_between_passes_refuses_a_receipt(self):
        self.publish('create')
        after = self.cloud.history(extra_key=recovery.CREATE)
        with patch.object(self.cloud, 'history', side_effect=[after, after[:-1]]):
            with self.assertRaises(r.REFUSAL):
                self.observe('create')


if __name__ == '__main__':
    unittest.main()
