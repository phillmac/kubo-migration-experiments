"""Offline fake authenticated RC + complete version-history Wasabi scenarios.

No credentials, SDK, subprocess, writer invocation or network. Synthetic anchor
patches exist in test memory only. Fake peer credentials model RealHost's pinned
SO_PEERCRED API; they do not claim real authentication or live isolation.
"""
from contextlib import ExitStack
import copy
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_marker_gate as g
import rhea_multi_sst_marker_gate_inspector as inspector

spec = importlib.util.spec_from_file_location('marker_gate_cloud_fixtures', ROOT / 'tests/test_verify_rhea_multi_sst_candidate.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


def identity():
    p = g.w.PROFILES['full-clone']
    return dict(process=dict(pid=303, start_ticks=9087,
                    boot_id='12345678-1234-1234-1234-123456789abc', exe_sha256=g.c.raw_sha(b'fake executable')),
        mount=dict(mountinfo='synthetic offline exact mountinfo tuple', target=str(p.mountpoint), source=p.remote),
        rc=dict(path=str(p.rc_socket), device=7, inode=99, peer_pid=303, peer_uid=0, peer_gid=0),
        source=p.remote, cache=dict(path=str(p.cache), device=7, inode=100),
        cloud=dict(Account='123456789012', Arn='arn:aws:iam::123456789012:user/rhea-pebble-lab-20261101',
                   UserId='rhea-pebble-lab-20261101'))


class FakeAuthenticatedRC:
    """Actual RC field names and peer checks; one-shot denial policy is FAKE."""
    def __init__(self, batch, client, store, isolation):
        self.batch, self.client, self.store = batch, client, store
        self.identity = identity()
        self.peer = (303, 0, 0)
        self.rows, self.staged, self.calls = {}, {}, []
        self.lock = threading.RLock()
        self.isolation_sha256 = g.c.digest(isolation)
        self.batch_sha256 = batch.sha256
        self.stop, self.free_bytes, self.bytes_used = False, 2 * 1024**4, 0
        self.observation_hook = None
        self.rc_hook = None
        self.rc_response = {}
        self.observation_calls = 0
        self.deadline = time.monotonic() + 3600
        dirty = dict(batch.hashes)
        dirty.update({name: dict(size=len(data), sha256=g.c.raw_sha(data)) for name, data in batch.metadata.items()
                      if name != 'LOCK' and batch.old_metadata.get(name) != data})
        for index, name in enumerate(sorted(dirty), 1):
            size = dirty[name]['size']
            self.rows[index] = dict(id=index, name='pebbleds/' + name, size=size, expiry=3600., uploading=False,
                                    tries=0, delay=3600.)
            if name in batch.changed:
                self.staged[index] = name, b'', 'publication-' + name
            else:
                key = g.v.PREFIX + name
                old = client.latest.pop(key)
                _, data = client.history.pop((key, old['VersionId']))
                self.staged[index] = name, data, old['VersionId']

    def observe(self):
        with self.lock:
            g.require(self.peer == (self.identity['process']['pid'], 0, 0), 'fake SO_PEERCRED rejected')
            started = time.monotonic()
            self.observation_calls += 1
            if self.observation_hook:
                self.observation_hook(self)
            rows = copy.deepcopy(list(self.rows.values()))
            for row in rows:
                row['expiry'] = self.deadline - time.monotonic()
            return dict(identity=copy.deepcopy(self.identity), rc=dict(pid=self.peer[0],
                stats=dict(fs=g.w.PROFILES['full-clone'].remote, diskCache=dict(bytesUsed=self.bytes_used,
                    uploadsQueued=sum(not r['uploading'] for r in rows),
                    uploadsInProgress=sum(r['uploading'] for r in rows), erroredFiles=0, outOfSpace=False)),
                queue=dict(queue=rows)), started=started, finished=time.monotonic(), free_bytes=self.free_bytes,
                stop=self.stop, batch_sha256=self.batch_sha256, isolation_sha256=self.isolation_sha256)

    def rc(self, profile, method, parameters, *, expected_pid, durable_intent):
        with self.lock:
            g.require(self.peer == (expected_pid, 0, 0), 'fake SO_PEERCRED rejected mutation')
            g.require(profile == g.w.PROFILES['full-clone'] and method == 'vfs/queue-set-expiry'
                      and parameters['expiry'] == g.w.QUEUE_EXPIRIES['expedite'], 'unscoped fake mutation')
            intents = [g.c.parse(self.store.read(p.name)) for p in self.store.path.glob('gate-mutation-*-intent.json')]
            g.require(durable_intent in intents and durable_intent['batch_sha256'] == self.batch.sha256,
                      'no durable generation-bound mutation intent')
            item_id = parameters['id']
            self.calls.append((item_id, self.rows[item_id]['name'], copy.deepcopy(durable_intent)))
            if self.rc_hook:
                self.rc_hook(self)
            name, data, version = self.staged[item_id]
            if name in self.batch.changed:
                g.require(durable_intent['before_sha256'] is not None, 'fake denial: no prepublication proof')
            self.client.add(g.v.PREFIX + name, data, version)
            self.rows.pop(item_id)
            return self.rc_response

    def unguarded_upload_marker(self, *, delete_after=False):
        name = self.batch.changed[0]
        self.client.add(g.v.PREFIX + name, b'', 'illicit-early-marker-version')
        if delete_after:
            self.client.delete(g.v.PREFIX + name)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        os.chmod(directory, 0o700)
        self.store = g.c.Store(directory)
        self.stack.enter_context(self.store.lock())
        self.fx = f.BatchFixture('before-markers')
        v = g.v
        self.stack.enter_context(patch.object(v, 'GENERATION13_SHA256', g.c.digest(self.fx.previous)))
        self.stack.enter_context(patch.object(v.proof.base, 'EXPECTED_SSTS', len(self.fx.baseline)))
        self.stack.enter_context(patch.object(v.proof.base, 'EXPECTED_SST_BYTES', sum(self.fx.baseline.values())))
        self.stack.enter_context(patch.object(v.proof.base, 'EXPECTED_INVENTORY', v.proof.base.inventory_digest(self.fx.baseline)))
        old = {name: self.fx.s3.get_object(Bucket=v.BUCKET, Key=v.PREFIX + name, VersionId=pin['version_id'])['Body'].read()
               for name, pin in self.fx.previous['remote_metadata'].items()}
        self.old = old
        self.batch = g.ClosedBatch.build(self.fx.metadata, old, self.fx.report, self.fx.hashes, self.fx.previous)
        self.policy = g.TimingPolicy(.02, 120, 60, 10, 300, 900)
        now = time.monotonic()
        self.isolation = dict(mechanism='preopen-marker-put-denial', identity_sha256=g.c.digest(identity()),
            batch_sha256=self.batch.sha256, enforced_since=now - 20, writer_opened=now - 19,
            writer_closed=now - 5, valid_until=now + 10000, policy_sha256=g.c.raw_sha(b'offline fake denial policy'))
        self.guard = self.new_guard()
        # Reconstruct the fake pre-open marker state, with old marker still latest.
        self.preopen = g.marker_history(self.fx.s3)
        self.preopen = [row for row in self.preopen if not row['delete']]
        for row in self.preopen:
            row['latest'] = True
        self.host = FakeAuthenticatedRC(self.batch, self.fx.s3, self.store, self.isolation)
        self.pilot = g.OfflinePilot(self.store, self.batch, self.guard, self.host, self.fx.s3,
                                   self.fx.ledger, self.preopen)
        self.restored = dict(writer_stopped=True, queue_clean=True, reader_identity=dict(identity()['process'], pid=404),
                             reader_mount_read_only=True, stop=False)
        self.reopen = dict(f.state_fields(self.fx.after, self.fx.after), action='inspect', compactions=[],
            sst_diff=f.delta({}, {}), io=dict(sst_write_bytes=0, metadata_write_bytes=0,
                max_sst_write_bytes=v.MAX_OUTPUT, max_metadata_write_bytes=v.MAX_METADATA))

    def new_guard(self):
        return g.QueueGuard(self.batch, identity(), self.isolation, self.policy)

    def inspect(self, **kwargs):
        params = dict(observe_restored=lambda: copy.deepcopy(self.restored), reopen=self.reopen,
                      reopened_metadata=self.batch.metadata)
        params.update(kwargs)
        return inspector.inspect_attempt(self.store, self.fx.s3, self.fx.ledger, **params)

    def sample(self, transform=lambda e: None):
        e = self.host.observe()
        transform(e)
        return self.guard.sample(e, time.monotonic())

    def run_fails(self, pattern=None):
        with self.assertRaisesRegex(Exception, pattern or '.'):
            self.pilot.run()

    def test_actual_pinned_sources_unchanged(self):
        g.source_pins(ROOT)

    def test_real_two_full_proofs_data_first_publication_and_independent_inspection(self):
        result = self.pilot.run()
        self.assertEqual(result['stage'], 'remote-proved')
        self.assertFalse(result['live_success'])
        self.assertNotEqual(result['before']['proof_pass_id'], result['final']['proof_pass_id'])
        order = [(g.historical.upload_priority(name), name) for _, name, _ in self.host.calls]
        self.assertEqual(order, sorted(order))
        self.assertEqual(order[-1][0], 5)
        self.assertEqual(self.inspect()['decision'], 'certifiable-offline-candidate')
        self.assertFalse(self.inspect()['live_certification_allowed'])

    def test_snapshot_is_copied_and_not_caller_mutable(self):
        digest = self.batch.sha256
        self.fx.metadata[self.batch.changed[0]] = b'changed'
        self.fx.hashes.clear()
        self.fx.report.clear()
        self.assertEqual(digest, self.batch.sha256)
        self.assertEqual(self.batch.metadata[self.batch.changed[0]], b'')

    def test_closed_batch_rejects_wrong_current(self):
        metadata = dict(self.batch.metadata, CURRENT=b'MANIFEST-999999\n')
        with self.assertRaisesRegex(Exception, 'CURRENT'):
            g.ClosedBatch.build(metadata, self.old, self.fx.report, self.fx.hashes, self.fx.previous)

    def test_closed_batch_rejects_nonempty_marker(self):
        metadata = dict(self.batch.metadata)
        metadata[self.batch.changed[0]] = b'bad'
        with self.assertRaises(Exception):
            g.ClosedBatch.build(metadata, self.old, self.fx.report, self.fx.hashes, self.fx.previous)

    def test_closed_batch_rejects_old_snapshot_tampering(self):
        self.old['CURRENT'] += b'bad'
        with self.assertRaisesRegex(Exception, 'gen13 raw'):
            g.ClosedBatch.build(self.batch.metadata, self.old, self.fx.report, self.fx.hashes, self.fx.previous)

    def test_closed_batch_rejects_wrong_anchor(self):
        previous = dict(self.fx.previous, generation=12)
        with self.assertRaisesRegex(Exception, 'gen13 anchor'):
            g.ClosedBatch.build(self.batch.metadata, self.old, self.fx.report, self.fx.hashes, previous)

    def test_no_poll_only_isolation(self):
        self.isolation['mechanism'] = 'poll-and-defer'
        with self.assertRaisesRegex(Exception, 'insufficient'):
            self.new_guard()

    def test_post_open_defer_is_not_isolation(self):
        self.isolation['enforced_since'] = self.isolation['writer_opened'] + .01
        with self.assertRaisesRegex(Exception, 'before writable'):
            self.new_guard()

    def test_forged_admitted_boolean_has_no_api(self):
        with self.assertRaises(TypeError):
            g.QueueGuard(self.batch, identity(), self.isolation, self.policy, admitted=True)
        with self.assertRaises(TypeError):
            g.RootQueueRuntime(admitted=True)

    def test_timing_values_have_no_defaults(self):
        with self.assertRaises(TypeError):
            g.TimingPolicy()
        with self.assertRaises(Exception):
            g.TimingPolicy(.1, .2, .3, .01, 10, 50)

    def test_auto_writeback_marker_before_controls(self):
        self.host.unguarded_upload_marker()
        self.run_fails('early marker')
        self.assertEqual(self.host.calls, [])

    def test_hidden_early_marker_then_delete(self):
        self.host.unguarded_upload_marker(delete_after=True)
        self.run_fails('unexpected remote marker versions')

    def test_unexpected_old_remote_marker_version(self):
        self.fx.s3.add(g.v.PREFIX + self.fx.format_marker, b'', 'unexpected-format-overwrite')
        self.run_fails('unexpected remote marker version')

    def test_preopen_marker_already_uploaded(self):
        self.preopen.append(dict(name=self.batch.changed[0], version_id='preexisting', delete=False,
                                 latest=True, size=0, etag='"abc"'))
        with self.assertRaises(Exception):
            g.check_marker_history(self.batch, self.preopen, self.preopen, {})

    def test_short_ttl_race(self):
        self.host.deadline = time.monotonic() + .01
        self.run_fails('short queue expiry')

    def test_duplicate_queue_id(self):
        e = self.host.observe()
        e['rc']['queue']['queue'][1]['id'] = e['rc']['queue']['queue'][0]['id']
        with self.assertRaisesRegex(Exception, 'queue id'):
            g.classify_queue(self.batch, e['rc'])

    def test_duplicate_queue_name(self):
        e = self.host.observe()
        e['rc']['queue']['queue'][1]['name'] = e['rc']['queue']['queue'][0]['name']
        with self.assertRaisesRegex(Exception, 'queue name'):
            g.classify_queue(self.batch, e['rc'])

    def test_queue_id_reuse(self):
        self.sample()
        rows = list(self.host.rows.values())
        rows[0]['name'], rows[1]['name'] = rows[1]['name'], rows[0]['name']
        rows[0]['size'], rows[1]['size'] = rows[1]['size'], rows[0]['size']
        with self.assertRaisesRegex(Exception, 'id reuse'):
            self.sample()

    def test_name_requeued_with_new_id(self):
        self.sample()
        row = self.host.rows.pop(1)
        row['id'] = 909
        self.host.rows[909] = row
        with self.assertRaises(Exception):
            self.sample()

    def test_missing_unselected_queue_row(self):
        self.sample()
        self.host.rows.pop(1)
        with self.assertRaisesRegex(Exception, 'automatic writeback'):
            self.sample()

    def test_dirty_file_outside_closed_generation(self):
        self.host.rows[1]['name'] = 'pebbleds/009999.sst'
        self.run_fails('outside immutable')

    def test_dirty_size_changed(self):
        self.host.rows[1]['size'] += 1
        self.run_fails('outside immutable')

    def test_dirty_snapshot_digest_changed(self):
        self.host.batch_sha256 = g.c.raw_sha(b'changed after close')
        self.run_fails('changed after snapshot')

    def test_cache_pressure(self):
        self.host.bytes_used = 96 * 1024**3 + 1
        self.run_fails('cache pressure')

    def test_free_space_pressure(self):
        self.host.free_bytes -= 1
        self.run_fails('free space')

    def test_stale_queue(self):
        with self.assertRaisesRegex(Exception, 'stale'):
            self.sample(lambda e: e.update(started=e['started'] - self.guard.policy.maximum_age - 2))

    def test_monitor_gap(self):
        self.sample()
        self.guard.last_stamp -= self.guard.policy.maximum_gap + 2
        with self.assertRaisesRegex(Exception, 'monitoring gap'):
            self.sample()

    def test_replayed_observation(self):
        e = self.host.observe()
        self.guard.sample(e, time.monotonic())
        with self.assertRaisesRegex(Exception, 'replayed'):
            self.guard.sample(e, time.monotonic())

    def test_expiry_changed_without_intent(self):
        self.sample()
        self.host.deadline += self.guard.policy.expiry_slack * 3 + 1
        with self.assertRaisesRegex(Exception, 'expiry changed'):
            self.sample()

    def test_unselected_upload_in_progress(self):
        self.host.rows[1]['uploading'] = True
        self.run_fails('transfer in progress')

    def test_marker_upload_started_mid_proof(self):
        original = g.v.verify_generation
        def verify(*args, **kwargs):
            marker = next(row for row in self.host.rows.values() if row['name'].endswith(self.batch.changed[0]))
            marker['uploading'] = True
            return original(*args, **kwargs)
        with patch.object(g.v, 'verify_generation', side_effect=verify):
            self.run_fails()
        self.assertFalse(any(name.endswith(self.batch.changed[0]) for _, name, _ in self.host.calls))

    def test_automatic_retry_detected(self):
        self.host.rows[1]['tries'] = 1
        self.run_fails('automatic retry')

    def test_stop_sentinel(self):
        self.host.stop = True
        self.run_fails('stop sentinel')

    def test_boot_replacement(self):
        self.host.identity['process']['boot_id'] = '00000000-0000-0000-0000-000000000000'
        self.run_fails('identity changed')

    def test_pid_replacement(self):
        self.host.peer = (999, 0, 0)
        self.run_fails('SO_PEERCRED')

    def test_start_tick_replacement(self):
        self.host.identity['process']['start_ticks'] += 1
        self.run_fails('identity changed')

    def test_socket_inode_replacement(self):
        self.host.identity['rc']['inode'] += 1
        self.run_fails('identity changed')

    def test_mount_replacement(self):
        self.host.identity['mount']['mountinfo'] += 'replaced'
        self.run_fails('identity changed')

    def test_cache_source_replacement(self):
        self.host.identity['cache']['inode'] += 1
        self.run_fails('identity changed')

    def test_cloud_identity_replacement(self):
        self.host.identity['cloud']['UserId'] = 'different'
        self.run_fails('identity changed')

    def test_isolation_changed(self):
        self.host.isolation_sha256 = g.c.raw_sha(b'different')
        self.run_fails('isolation policy changed')

    def test_isolation_expired(self):
        self.isolation['valid_until'] = time.monotonic() - 1
        self.guard = self.new_guard()
        self.pilot.guard = self.guard
        self.host.isolation_sha256 = g.c.digest(self.isolation)
        self.run_fails('isolation expired')

    def test_wrong_rc_filesystem(self):
        with self.assertRaises(Exception):
            self.sample(lambda e: e['rc']['stats'].update(fs='production:rhea'))

    def test_non_atomic_rc_counters(self):
        with self.assertRaisesRegex(Exception, 'stale RC'):
            self.sample(lambda e: e['rc']['stats']['diskCache'].update(uploadsQueued=0))

    def test_missing_or_nonfinite_expiry_fields(self):
        for value in (None, float('nan'), float('inf'), True, '3600'):
            with self.subTest(value=value):
                e = self.host.observe()
                e['rc']['queue']['queue'][0]['expiry'] = value
                with self.assertRaises(Exception):
                    g.classify_queue(self.batch, e['rc'])

    def test_bool_id_and_missing_tries_rejected(self):
        e = self.host.observe()
        e['rc']['queue']['queue'][0]['id'] = True
        with self.assertRaises(Exception):
            g.classify_queue(self.batch, e['rc'])
        e = self.host.observe()
        del e['rc']['queue']['queue'][0]['tries']
        with self.assertRaises(Exception):
            g.classify_queue(self.batch, e['rc'])

    def test_backlog_file_cap(self):
        allowed = {f'{i:06d}.sst': {'size': 1, 'sha256': '0' * 64} for i in range(257)}
        batch = g.ClosedBatch(self.batch.metadata_items, self.batch.old_items, self.batch.report_raw,
                              g.c.canonical(allowed), self.batch.previous_raw)
        e = self.host.observe()['rc']
        e['queue']['queue'] = [dict(id=i+1, name='pebbleds/' + name, size=1, expiry=30., delay=30.,
                                    tries=0, uploading=False) for i, name in enumerate(allowed)]
        e['stats']['diskCache']['uploadsQueued'] = 257
        with self.assertRaisesRegex(Exception, 'queue cap'):
            g.classify_queue(batch, e)

    def test_backlog_byte_cap(self):
        name = '999999.sst'
        batch = g.ClosedBatch(self.batch.metadata_items, self.batch.old_items, self.batch.report_raw,
            g.c.canonical({name: {'size': g.MAX_BYTES + 1, 'sha256': '0'*64}}), self.batch.previous_raw)
        e = self.host.observe()['rc']
        e['queue']['queue'] = [dict(id=1, name='pebbleds/' + name, size=g.MAX_BYTES+1, expiry=30., delay=30.,
                                     tries=0, uploading=False)]
        e['stats']['diskCache']['uploadsQueued'] = 1
        with self.assertRaisesRegex(Exception, 'queue cap'):
            g.classify_queue(batch, e)

    def test_unchanged_marker_dirty(self):
        row = next(row for row in self.host.rows.values() if row['name'].endswith(self.batch.changed[0]))
        row['name'] = 'pebbleds/' + self.fx.format_marker
        self.run_fails('unchanged or unexpected')

    def test_crash_after_intent_before_rc_has_no_retry(self):
        self.pilot.failpoint = lambda phase: (_ for _ in ()).throw(RuntimeError('crash')) if phase == 'after-intent' else None
        self.run_fails('crash')
        self.assertEqual(self.host.calls, [])
        self.assertTrue(list(self.store.path.glob('*mutation*-intent.json')))
        self.assertFalse(list(self.store.path.glob('*mutation*-receipt.json')))
        self.assertTrue(self.pilot.poisoned)
        self.run_fails('never replay')
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_crash_after_rc_before_receipt_has_no_retry(self):
        self.pilot.failpoint = lambda phase: (_ for _ in ()).throw(RuntimeError('crash')) if phase == 'after-rc' else None
        self.run_fails('crash')
        self.assertEqual(len(self.host.calls), 1)
        self.assertFalse(list(self.store.path.glob('*mutation*-receipt.json')))
        self.run_fails('never replay')
        self.assertEqual(len(self.host.calls), 1)

    def test_uncertain_expiry_result_poisons_attempt(self):
        self.host.rc_response = {'unknown': 'applied-or-not'}
        self.run_fails('ambiguous RC')
        self.assertTrue(self.pilot.poisoned)
        self.assertEqual(len(self.host.calls), 1)
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_rc_timeout_after_mutation_never_retried(self):
        original = self.host.rc
        def rc(*args, **kwargs):
            original(*args, **kwargs)
            raise TimeoutError('uncertain timeout')
        self.host.rc = rc
        self.run_fails('timeout')
        self.assertEqual(len(self.host.calls), 1)
        self.run_fails('never replay')

    def test_durable_file_and_directory_fsync_precede_each_mutation(self):
        original_fsync = os.fsync
        events = []
        def fsync(fd):
            original_fsync(fd)
            events.append('fsync')
        def hook(host):
            self.assertGreaterEqual(events.count('fsync'), 2)
            events.clear()
        self.host.rc_hook = hook
        with patch.object(os, 'fsync', side_effect=fsync):
            self.pilot.run()
        self.assertGreater(len(self.host.calls), 2)

    def test_partial_marker_publication_is_preserved(self):
        def fail(phase):
            if phase == 'after-rc' and any(name.endswith(self.batch.changed[0]) for _, name, _ in self.host.calls):
                raise RuntimeError('crash after marker')
        self.pilot.failpoint = fail
        self.run_fails('crash after marker')
        self.assertIn(g.v.PREFIX + self.batch.changed[0], self.fx.s3.latest)
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')
        calls = len(self.host.calls)
        self.run_fails('never replay')
        self.assertEqual(calls, len(self.host.calls))

    def test_wrong_version_head_before_publication(self):
        original = self.fx.s3.head_object
        def head(**kwargs):
            result = original(**kwargs)
            if self.pilot.stage == 'publishing' and kwargs['Key'].endswith('CURRENT'):
                result['VersionId'] = 'wrong-latest-version'
            return result
        self.fx.s3.head_object = head
        self.run_fails()
        self.assertFalse(any(name.endswith(self.batch.changed[0]) for _, name, _ in self.host.calls))

    def test_wrong_get_version_after_marker_publication(self):
        original = self.fx.s3.get_object
        def get(**kwargs):
            result = original(**kwargs)
            if kwargs['Key'].endswith(self.batch.changed[0]):
                result['VersionId'] = 'wrong-body-version'
            return result
        self.fx.s3.get_object = get
        self.run_fails('GET identity')
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_wrong_marker_get_bytes(self):
        original = self.fx.s3.get_object
        def get(**kwargs):
            result = original(**kwargs)
            if kwargs['Key'].endswith(self.batch.changed[0]):
                result['Body'] = io.BytesIO(b'bad')
            return result
        self.fx.s3.get_object = get
        self.run_fails('longer than expected')

    def test_marker_overwritten_between_get_and_second_head(self):
        original = self.fx.s3.get_object
        def get(**kwargs):
            result = original(**kwargs)
            if kwargs['Key'].endswith(self.batch.changed[0]):
                self.fx.s3.add(kwargs['Key'], b'', 'racing-overwrite')
            return result
        self.fx.s3.get_object = get
        self.run_fails('HEAD identity')

    def test_identical_full_proof_pass_ids_rejected(self):
        with patch.object(g.v.secrets, 'token_hex', return_value='a' * 32):
            self.run_fails('pass ID reused')
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_two_proofs_with_disagreeing_inventory_not_certifiable(self):
        self.pilot.run()
        self.reopen['sst_inventory_sha256_after'] = '0' * 64
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_after_writer_stop_and_reader_restore(self):
        self.pilot.run()
        self.assertEqual(self.inspect()['decision'], 'certifiable-offline-candidate')
        self.restored['writer_stopped'] = False
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_rw_reader_named_reader_is_not_write_proof(self):
        self.pilot.run()
        self.restored['reader_mount_read_only'] = False
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_reader_changes_mid_inspector_full_proof(self):
        self.pilot.run()
        calls = []
        def observe():
            calls.append(1)
            value = copy.deepcopy(self.restored)
            if len(calls) > 3:
                value['reader_identity']['pid'] += 1
            return value
        self.assertEqual(self.inspect(observe_restored=observe)['decision'], 'preserve/manual-inspection')

    def test_long_verification_monitor_continues_independently(self):
        # CI scheduling can starve the observer during heavy concurrent suites.
        # These bounds apply to this synthetic test ONLY; the live gate has
        # no default timing policy and still requires signed host evidence.
        self.guard.policy = g.TimingPolicy(.02, 120, 60, 10, 300, 900)
        original = g.v.verify_generation
        samples = []
        def verify(*args, **kwargs):
            before = self.host.observation_calls
            time.sleep(.3)
            samples.append(self.host.observation_calls - before)
            return original(*args, **kwargs)
        with patch.object(g.v, 'verify_generation', side_effect=verify):
            self.pilot.run()
        self.assertTrue(all(count >= 2 for count in samples))

    def test_stop_during_long_verification(self):
        original = g.v.verify_generation
        def verify(*args, **kwargs):
            self.host.stop = True
            time.sleep(.03)
            return original(*args, **kwargs)
        with patch.object(g.v, 'verify_generation', side_effect=verify):
            self.run_fails()
        self.assertFalse(any(name.endswith(self.batch.changed[0]) for _, name, _ in self.host.calls))

    def test_proof_runtime_budget(self):
        self.guard.policy = g.TimingPolicy(.005, 2, 1, .05, 10, .001)
        original = g.v.verify_generation
        def verify(*args, **kwargs):
            time.sleep(.01)
            return original(*args, **kwargs)
        with patch.object(g.v, 'verify_generation', side_effect=verify):
            self.run_fails()

    def test_inspector_does_not_change_evidence_or_cloud(self):
        self.pilot.run()
        files = {path.name: path.read_bytes() for path in self.store.path.iterdir()}
        history = copy.deepcopy(self.fx.s3.history)
        self.inspect()
        self.assertEqual(files, {path.name: path.read_bytes() for path in self.store.path.iterdir()})
        self.assertEqual(history, self.fx.s3.history)

    def test_inspector_rejects_orphan_artifact(self):
        self.pilot.run()
        self.store.put('orphan.json', {})
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_inspector_rejects_remote_version_changed_after_publication(self):
        self.pilot.run()
        self.fx.s3.add(g.v.PREFIX + self.batch.changed[0], b'', 'later-unexpected-version')
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_empty_attempt_preserve(self):
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_root_mutating_entrypoints_unconditionally_disabled(self):
        runtime = object.__new__(g.RootQueueRuntime)
        for name in ('authenticate_marker_admission', 'open_writer', 'selected_queue_expiry', 'publish_markers', 'restore_reader'):
            with self.subTest(name=name), self.assertRaisesRegex(Exception, 'STOP PROPOSAL'):
                getattr(runtime, name)()

    def test_nonroot_observation_refuses_before_any_host_action(self):
        with patch.object(g.os, 'geteuid', return_value=123), patch.object(g.root, 'RootHostAdapter') as constructor:
            with self.assertRaisesRegex(Exception, 'root required'):
                g.RootQueueRuntime()
            constructor.assert_not_called()

    def test_cli_and_provisioning_stay_disabled(self):
        self.assertEqual(g.main(), 2)
        self.assertEqual(inspector.main(), 2)
        self.assertIsNone(g.root.PROVISION_PUBLIC_KEY_SHA256)
        self.assertIsNone(g.admission.PUBLIC_KEY_SHA256)
        self.assertIsNone(g.c.INSTALLED_ADAPTER_SHA256)


if __name__ == '__main__':
    unittest.main()
