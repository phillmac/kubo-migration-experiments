#!/usr/bin/env python3
"""Gen14 marker gate primitives and OFFLINE closed-batch pilot.

No writer, credentials, installer, service action or live mutation CLI. Pure
records are evidence *models*, never authentication/admission capabilities.
RootQueueRuntime authenticates real observations; its mutations always refuse.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import math
import os
from pathlib import Path
import stat
import threading
import time

import rhea_multi_sst_checkpoint_controller as c
import rhea_multi_sst_root_host_adapter as root
import rhea_multi_sst_signed_admission as admission
import rhea_multi_sst_reader_bridge as bridge
import rhea_wasabi_lab_mount as w
import run_rhea_full_clone_steps_batch2 as historical

require, Refusal = c.require, c.Refusal
v = c.verifier
BASE_COMMIT = 'c1d54ee94f81793d2dbbd13e9502f888b0935b32'
WRITER_LOCK = '/run/rhea-wasabi-lab/writer.lock'
# Bounds are inherited safety ceilings, NOT evidence of a safe polling/TTL value.
MAX_BYTES, MAX_FILES = 768 * 1024**2, 256
EXTRA_PINS = {
    'scripts/rhea_multi_sst_signed_admission.py': '604970652d468d65008dc0b0b10367f6e8007de2f3fc2807b9b47f3e82e23574',
    'scripts/rhea_multi_sst_reader_bridge.py': '89040772aa5363469ede36f188f5217aaa266a4fbd3f9b25762430f8f81b5aa0',
    'scripts/rhea_multi_sst_root_host_adapter.py': 'a6f3b0c52b6b29569ace4ffc1ed076bc04a58e85d9287bdf1d98316bc473c0eb',
    'scripts/rhea_multi_sst_version_snapshot.py': '3072e888f69e6172ba116e5dd5daf339bf232ec51d50d41661fa7f3cdfa2da65',
    'scripts/run_rhea_full_clone_steps_batch2.py': 'b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828',
}


def source_pins(directory):
    c.source_pins(directory)
    for name, pin in dict(EXTRA_PINS, **bridge.TRANSITIVE_SOURCE_PINS).items():
        path = Path(directory) / name
        require(not path.is_symlink() and c.raw_sha(path.read_bytes()) == pin,
                'marker gate dependency changed: ' + name)
    require(c.raw_sha((Path(directory) / 'scripts/rhea_wasabi_lab_mount.py').read_bytes())
            == root.WRAPPER_SHA256, 'historical RealHost changed')


def number(value, label, *, positive=False):
    require(type(value) in (int, float) and math.isfinite(value)
            and (value > 0 if positive else value >= 0), label)
    return value


@dataclass(frozen=True)
class TimingPolicy:
    """No production defaults; every value needs independent deployment evidence."""
    poll_seconds: float
    maximum_gap: float
    maximum_age: float
    expiry_slack: float
    minimum_marker_ttl: float
    maximum_proof_seconds: float

    def __post_init__(self):
        for value in vars(self).values():
            number(value, 'invalid timing evidence', positive=True)
        require(self.poll_seconds < self.maximum_gap
                and self.maximum_age <= self.maximum_gap
                and self.expiry_slack < self.minimum_marker_ttl
                and self.minimum_marker_ttl > self.maximum_gap + self.maximum_age,
                'timing evidence cannot cover observation gap')


@dataclass(frozen=True)
class ClosedBatch:
    """Copy bytes once; caller mutations cannot alter a planned generation."""
    metadata_items: tuple
    old_items: tuple
    report_raw: bytes
    hashes_raw: bytes
    previous_raw: bytes

    @classmethod
    def build(cls, metadata, old_metadata, report, hashes, previous):
        c.metadata_bounds(metadata)
        c.metadata_bounds(old_metadata)
        require(previous.get('generation') == 13 and previous.get('remote_generation_verified') is True
                and previous.get('pebble_reopen_verified') is True
                and c.digest(previous) == v.GENERATION13_SHA256, 'exact certified gen13 anchor required')
        require(set(old_metadata) == set(previous['remote_metadata']), 'incomplete gen13 raw snapshot')
        for name, pin in previous['remote_metadata'].items():
            require(len(old_metadata[name]) == pin['size'] and c.raw_sha(old_metadata[name]) == pin['sha256'],
                    'gen13 raw metadata differs')
        info = v.proof._marker_info(metadata)
        old_info = v.proof._marker_info(old_metadata)
        require(metadata.get('CURRENT') == old_metadata.get('CURRENT') == b'MANIFEST-000000\n'
                and metadata.get('LOCK', b'') == b''
                and info['after_format'] == old_info['after_format'] == '013',
                'CURRENT/LOCK/format differs from gen14 scope')
        changed = v.proof.changed_marker_names(previous, metadata)
        require(changed == [info['manifest_marker']], 'gen14 changes exactly one MANIFEST marker')
        before, bs = v.proof._decode_tables(old_metadata[old_info['manifest']])
        after, ats = v.proof._decode_tables(metadata[info['manifest']])
        v.validate_batch(report, before, after, bs, ats, '013', '013', hashes)
        require(report.get('physical_compactions') == 2 and report['request']['maximum_units'] == 2,
                'this gate is restricted to the two-unit clone pilot')
        return cls(tuple(sorted(metadata.items())), tuple(sorted(old_metadata.items())),
                   c.canonical(report), c.canonical(hashes), c.canonical(previous))

    @property
    def metadata(self):
        return dict(self.metadata_items)

    @property
    def old_metadata(self):
        return dict(self.old_items)

    @property
    def previous(self):
        return c.parse(self.previous_raw)

    @property
    def report(self):
        return c.parse(self.report_raw)

    @property
    def hashes(self):
        return c.parse(self.hashes_raw)

    @property
    def changed(self):
        return tuple(v.proof.changed_marker_names(self.previous, self.metadata))

    @property
    def allowed(self):
        return {**{name: len(data) for name, data in self.metadata_items},
                **{name: pin['size'] for name, pin in self.hashes.items()}}

    @property
    def binding(self):
        return dict(generation=14, previous_sha256=c.raw_sha(self.previous_raw),
                    report_sha256=c.raw_sha(self.report_raw), hashes_sha256=c.raw_sha(self.hashes_raw),
                    metadata={name: dict(size=len(data), sha256=c.raw_sha(data))
                              for name, data in self.metadata_items}, changed=list(self.changed))

    @property
    def sha256(self):
        return c.digest(self.binding)

    def retained(self):
        return dict(binding=self.binding, metadata=c.encode_metadata(self.metadata),
                    previous_metadata=c.encode_metadata(self.old_metadata), report=self.report,
                    hashes=self.hashes, previous=self.previous)


def validate_identity(identity):
    require(type(identity) is dict and set(identity) == {'process', 'mount', 'rc', 'source', 'cache', 'cloud'},
            'complete process/mount/socket/source/cache/cloud identity required')
    c.process_tuple(identity['process'])
    mount, rc = identity['mount'], identity['rc']
    p = w.PROFILES['full-clone']
    require(type(mount) is dict and set(mount) == {'mountinfo', 'target', 'source'}
            and mount['target'] == str(p.mountpoint) and w.remote_matches(p, mount['source'])
            and type(mount['mountinfo']) is str and mount['mountinfo'], 'exact mount identity missing')
    require(type(rc) is dict and set(rc) == {'path', 'device', 'inode', 'peer_pid', 'peer_uid', 'peer_gid'}
            and rc['path'] == str(p.rc_socket) and rc['peer_pid'] == identity['process']['pid']
            and type(rc['device']) is int and rc['device'] >= 0
            and type(rc['inode']) is int and rc['inode'] > 0
            and type(rc['peer_pid']) is int and type(rc['peer_uid']) is type(rc['peer_gid']) is int
            and rc['peer_uid'] == rc['peer_gid'] == 0, 'authenticated RC peer tuple missing')
    cache = identity['cache']
    require(identity['source'] == p.remote and type(cache) is dict
            and set(cache) == {'path', 'device', 'inode'} and cache['path'] == str(p.cache)
            and type(cache['device']) is int and cache['device'] >= 0
            and type(cache['inode']) is int and cache['inode'] > 0, 'cache/source substitution')
    w.validate_identity(identity['cloud'])


def validate_isolation(evidence, identity, batch):
    """Structural OFFLINE model only. This does NOT verify a policy signature.

    A real adapter must prove pre-open, process-independent denial of *all*
    marker PUT/copy/multipart paths and durable one-shot release. Polling, a long
    writeback flag, or an RC defer receipt cannot establish this invariant.
    """
    require(type(evidence) is dict and set(evidence) == {'mechanism', 'identity_sha256', 'batch_sha256',
                'enforced_since', 'writer_opened', 'writer_closed', 'valid_until', 'policy_sha256'},
            'complete pre-open isolation evidence required')
    require(evidence['mechanism'] == 'preopen-marker-put-denial'
            and evidence['identity_sha256'] == c.digest(identity) and evidence['batch_sha256'] == batch.sha256
            and type(evidence['policy_sha256']) is str and c.HEX.fullmatch(evidence['policy_sha256']),
            'early isolation unproven; polling/RC expiry is insufficient')
    for key in ('enforced_since', 'writer_opened', 'writer_closed', 'valid_until'):
        number(evidence[key], 'invalid isolation clock')
    require(evidence['enforced_since'] < evidence['writer_opened'] <= evidence['writer_closed']
            < evidence['valid_until'], 'isolation was not active before writable DB open')


@dataclass(frozen=True)
class QueueRow:
    item_id: int
    name: str
    size: int
    expiry: float
    uploading: bool
    tries: int
    delay: float
    priority: int


def classify_queue(batch, observation):
    """Actual pinned RC schema: expiry/delay are RELATIVE seconds, not dates."""
    p = w.PROFILES['full-clone']
    w.validate_stats(p, observation)
    disk = observation['stats']['diskCache']
    require(type(disk.get('bytesUsed')) is int and 0 <= disk['bytesUsed'] <= 96 * 1024**3
            and disk['erroredFiles'] == 0 and disk['outOfSpace'] is False, 'cache pressure or upload errors')
    rows, ids, names = [], set(), set()
    for row in observation['queue']['queue']:
        require(type(row) is dict and set(row) == {'id', 'name', 'size', 'expiry', 'uploading', 'tries', 'delay'},
                'unknown/missing RC queue fields')
        item_id, name, size = row['id'], row['name'], row['size']
        require(type(item_id) is int and 0 < item_id < 2**63 and item_id not in ids,
                'duplicate/invalid queue id')
        require(type(name) is str and name not in names and name.startswith('pebbleds/'),
                'duplicate/invalid queue name')
        basename = name[len('pebbleds/'):]
        require(basename in batch.allowed and type(size) is int and size == batch.allowed[basename],
                'dirty file is outside immutable closed batch')
        priority = historical.upload_priority(name)  # exact historical marker classes
        require(type(row['uploading']) is bool and type(row['tries']) is int and row['tries'] >= 0,
                'invalid upload/attempt state')
        require(type(row['expiry']) in (int, float) and math.isfinite(row['expiry']), 'invalid relative expiry')
        number(row['delay'], 'invalid queue delay')
        if priority >= 5:
            require(basename in batch.changed, 'unchanged or unexpected dirty marker')
        rows.append(QueueRow(item_id, name, size, row['expiry'], row['uploading'], row['tries'], row['delay'], priority))
        ids.add(item_id)
        names.add(name)
    require(len(rows) <= MAX_FILES and sum(row.size for row in rows) <= MAX_BYTES, 'queue cap exceeded')
    require(disk['uploadsInProgress'] == sum(row.uploading for row in rows)
            and disk['uploadsQueued'] == sum(not row.uploading for row in rows), 'non-atomic/stale RC queue counters')
    return tuple(sorted(rows, key=lambda row: (row.priority, row.name)))


def validate_proof_binding(batch, proof, mode):
    require(type(proof) is dict and proof.get('schema') == v.CERTIFICATE_SCHEMA
            and proof.get('scope') == v.SCOPE and proof.get('mode') == mode
            and proof.get('generation') == 14 and proof.get('batch_checkpoint_count') == 1
            and proof.get('anchor_checkpoint_sha256') == v.GENERATION13_SHA256
            and proof.get('previous_checkpoint_sha256') == c.raw_sha(batch.previous_raw)
            and proof.get('go_report_sha256') == c.raw_sha(batch.report_raw)
            and proof.get('closed_output_hashes_sha256') == c.raw_sha(batch.hashes_raw)
            and proof.get('limits') == v.LIMITS and proof.get('enumeration_workers') == 4
            and proof.get('remote_generation_verified') is (mode == 'final')
            and proof.get('pebble_reopen_verified') is False
            and proof.get('changed_markers') == list(batch.changed)
            and type(proof.get('proof_pass_id')) is str
            and len(proof['proof_pass_id']) == 32
            and all(ch in '0123456789abcdef' for ch in proof['proof_pass_id']),
            'full proof does not bind immutable gen14 batch')
    expected = set(batch.metadata) - (set(batch.changed) if mode == 'before-markers' else set())
    require(set(proof['remote_metadata']) == expected, 'proof metadata inventory differs from closed batch')
    for name, pin in proof['remote_metadata'].items():
        data = batch.metadata[name]
        require(type(pin['size']) is int and pin['size'] == len(data) and pin['sha256'] == c.raw_sha(data)
                and type(pin['version_id']) is str and pin['version_id'] not in ('', 'null')
                and type(pin['etag']) is str and pin['etag'], 'proof metadata pin differs from closed bytes')


@dataclass(frozen=True)
class GateState:
    """Pure irreversible stage chain. Receipts are bytes, never caller-owned dicts.

    Passing evidence advances a MODEL; it grants no host or signing authority.
    Any preserve transition is terminal, with no writer/marker replay edge.
    """
    batch_sha256: str
    phase: str = 'closed'
    before_raw: bytes = b''
    publication_raw: bytes = b''
    final_raw: bytes = b''

    def advance(self, batch, event, evidence):
        require(batch.sha256 == self.batch_sha256, 'state generation/batch changed')
        require(self.phase not in ('preserve/manual-inspection', 'remote-proved'), 'terminal state cannot replay')
        if event == 'preserve':
            return GateState(self.batch_sha256, 'preserve/manual-inspection', self.before_raw,
                             self.publication_raw, self.final_raw)
        expected = {'closed': 'data-drained', 'data-drained': 'before-proved',
                    'before-proved': 'published', 'published': 'remote-proved'}
        require(expected.get(self.phase) == event, 'illegal marker gate stage transition')
        if event == 'data-drained':
            require(type(evidence) is tuple and all(isinstance(row, QueueRow) and row.priority >= 5
                    and not row.uploading and row.tries == 0 for row in evidence)
                    and {row.name[len('pebbleds/'):] for row in evidence} == set(batch.changed),
                    'data drain requires exact withheld marker queue')
            return GateState(self.batch_sha256, event)
        if event == 'before-proved':
            validate_proof_binding(batch, evidence, 'before-markers')
            return GateState(self.batch_sha256, event, c.canonical(evidence))
        before = c.parse(self.before_raw)
        if event == 'published':
            require(type(evidence) is dict and set(evidence) == set(batch.changed), 'incomplete marker publication')
            for name, pin in evidence.items():
                require(type(pin) is dict and set(pin) == {'version_id', 'etag', 'size', 'sha256'}
                        and type(pin['version_id']) is str and pin['version_id'] not in ('', 'null')
                        and type(pin['etag']) is str and pin['etag'] and type(pin['size']) is int
                        and pin['size'] == 0 and pin['sha256'] == c.raw_sha(b''), 'unverified marker identity')
            return GateState(self.batch_sha256, event, self.before_raw, c.canonical(evidence))
        validate_proof_binding(batch, evidence, 'final')
        require(before['proof_pass_id'] != evidence['proof_pass_id'], 'full proof pass ID reused')
        # Every deterministic verifier output must agree, except the declared
        # mode, completion bit, clock/nonce and newly published metadata pins.
        variable = {'mode', 'remote_generation_verified', 'verified_unix', 'proof_pass_id', 'remote_metadata'}
        require({k: val for k, val in before.items() if k not in variable}
                == {k: val for k, val in evidence.items() if k not in variable}, 'two full proof passes disagree')
        for name, pin in before['remote_metadata'].items():
            require(evidence['remote_metadata'].get(name) == pin, 'input version changed between proof passes')
        for name, pin in c.parse(self.publication_raw).items():
            require(evidence['remote_metadata'][name] == pin, 'final marker differs from publication identity')
        return GateState(self.batch_sha256, event, self.before_raw, self.publication_raw, c.canonical(evidence))


class QueueGuard:
    """Sticky, thread-safe continuous observation model; no authority boolean."""
    def __init__(self, batch, identity, isolation, policy):
        validate_identity(identity)
        validate_isolation(isolation, identity, batch)
        self.batch, self.policy = batch, policy
        self.identity_raw, self.isolation_raw = c.canonical(identity), c.canonical(isolation)
        self.lock = threading.RLock()
        self.failure = None
        self.last_stamp = None
        self.deadlines, self.ids, self.names, self.active = {}, {}, {}, set()
        self.release = None
        self.rows = ()

    def check(self):
        require(self.failure is None, self.failure or 'guard failed')

    def sample(self, envelope, now):
        with self.lock:
            self.check()
            try:
                self._sample(envelope, now)
                return self.rows
            except Exception as exc:
                self.failure = 'continuous queue guard failed: ' + str(exc)
                raise

    def _sample(self, e, now):
        require(type(e) is dict and set(e) == {'identity', 'rc', 'started', 'finished', 'free_bytes',
                    'stop', 'batch_sha256', 'isolation_sha256'}, 'incomplete authenticated observation')
        require(c.canonical(e['identity']) == self.identity_raw, 'boot/process/mount/socket/cloud identity changed')
        require(e['batch_sha256'] == self.batch.sha256, 'closed files changed after snapshot')
        require(e['isolation_sha256'] == c.raw_sha(self.isolation_raw), 'isolation policy changed')
        require(e['stop'] is False, 'user stop sentinel')
        number(now, 'invalid monitor clock')
        number(e['started'], 'invalid observation start')
        require(e['started'] <= e['finished'] <= now and now - e['started'] <= self.policy.maximum_age,
                'stale/slow RC observation')
        isolation = c.parse(self.isolation_raw)
        require(isolation['writer_closed'] <= e['started'] < isolation['valid_until'] - self.policy.maximum_gap,
                'isolation expired or writer still open')
        if self.last_stamp is not None:
            require(self.last_stamp < e['finished'] and e['finished'] - self.last_stamp <= self.policy.maximum_gap,
                    'continuous monitoring gap or replayed observation')
        require(type(e['free_bytes']) is int and e['free_bytes'] >= 2 * 1024**4, 'free space exhausted')
        require(e['rc'].get('pid') == c.parse(self.identity_raw)['process']['pid'], 'RC peer PID changed')
        rows = classify_queue(self.batch, e['rc'])
        current = {row.item_id for row in rows}
        require(self.active - current <= ({self.release.item_id} if self.release else set()),
                'unselected dirty file disappeared; possible automatic writeback')
        for row in rows:
            require(self.last_stamp is None or row.item_id in self.ids,
                    'new dirty queue row appeared after closed snapshot')
            key = (row.name, row.size)
            require(self.ids.get(row.item_id, key) == key and self.names.get(row.name, row.item_id) == row.item_id,
                    'queue id reuse or name requeued')
            require(row.item_id not in self.ids or row.item_id in self.active, 'retired queue id reappeared')
            self.ids[row.item_id], self.names[row.name] = key, row.item_id
            selected = self.release is not None and row.item_id == self.release.item_id
            if not selected:
                require(not row.uploading and row.tries == 0, 'unselected transfer in progress or automatic retry')
                floor = self.policy.minimum_marker_ttl if row.priority >= 5 else self.policy.maximum_gap
                require(row.expiry > floor + now - e['started'], 'unexpected/short queue expiry')
                # Queue() computes its relative expiry somewhere BETWEEN the
                # two sample bounds. Intersect deadline intervals; using the
                # finish time as an exact instant falsely flags slow RC reads.
                low = e['started'] + row.expiry - self.policy.expiry_slack
                high = e['finished'] + row.expiry + self.policy.expiry_slack
                if row.item_id in self.deadlines:
                    old_low, old_high = self.deadlines[row.item_id]
                    low, high = max(low, old_low), min(high, old_high)
                    require(low <= high, 'queue expiry changed without a durable intent')
                self.deadlines[row.item_id] = (low, high)
            else:
                require(row.tries <= 1, 'selected upload automatically retried')
        self.active, self.rows, self.last_stamp = current, rows, e['finished']

    def data_drained(self):
        self.check()
        require(not any(row.priority < 5 or row.uploading for row in self.rows), 'data not drained')
        require({row.name[len('pebbleds/'):] for row in self.rows} == set(self.batch.changed),
                'changed markers missing from isolated queue')

    def clean(self):
        self.check()
        require(not self.rows, 'queue not fully drained')


class ContinuousMonitor:
    """Independent observer during blocking S3 work; failure latches permanently.

    A blocked RC read cannot be interrupted here. check() detects loss of fresh
    samples before *any* next action. No callback can turn a timeout into success.
    This worker never mutates RC, S3 or services.
    """
    def __init__(self, guard, observe, *, clock=time.monotonic):
        self.guard, self.observe, self.clock = guard, observe, clock
        self.done = threading.Event()
        self.worker = None
        self.error = None

    def pulse(self):
        with self.guard.lock:
            self.guard.check()
            self.guard.sample(self.observe(), self.clock())

    def check(self):
        self.guard.check()
        require(self.error is None, 'independent observer failed')
        require(self.guard.last_stamp is not None
                and 0 <= self.clock() - self.guard.last_stamp <= self.guard.policy.maximum_gap,
                'independent observer stalled')

    def is_set(self):
        try:
            self.check()
        except Exception:
            return True
        return False

    def _work(self):
        while not self.done.wait(self.guard.policy.poll_seconds):
            try:
                self.pulse()
            except Exception as exc:
                self.error = exc
                return

    def __enter__(self):
        self.pulse()
        self.worker = threading.Thread(target=self._work, daemon=True, name='offline-marker-queue-observer')
        self.worker.start()
        return self

    def __exit__(self, *args):
        self.done.set()
        self.worker.join(timeout=self.guard.policy.maximum_age)
        require(not self.worker.is_alive(), 'observer blocked; preserve attempt')
        if args[0] is None:
            self.check()


def marker_history(client, *, stop=None):
    """Fresh full version enumeration, including NON-latest and deleted markers.

    Supplemental to, never a substitute for, the two four-worker full proofs.
    """
    snapshot, _ = v.proof.enumerator.scan_versions(client, bucket=v.BUCKET, prefix='rhea/',
        workers=1, max_pages=v.proof.ENUMERATION_MAX_PAGES,
        max_rows=v.proof.ENUMERATION_MAX_ROWS, stop_event=stop)
    records = []
    for field, deleting in (('Versions', False), ('DeleteMarkers', True)):
        for row in snapshot[field].values():
            key = row['Key']
            if not key.startswith(v.PREFIX + 'marker.'):
                continue
            name = key[len(v.PREFIX):]
            require(historical.upload_priority('pebbleds/' + name) >= 5, 'unknown remote marker class')
            value = dict(name=name, version_id=row['VersionId'], delete=deleting, latest=row['IsLatest'])
            if not deleting:
                require(row['Size'] == 0, 'nonempty remote marker')
                value.update(size=row['Size'], etag=row['ETag'])
            records.append(value)
    return sorted(records, key=lambda row: (row['name'], row['version_id']))


def check_marker_history(batch, preopen, fresh, published):
    """No concealed early uploads, extra overwrites or lost historical versions."""
    def indexed(rows):
        require(type(rows) is list, 'marker history missing')
        result = {}
        for row in rows:
            expected = {'name', 'version_id', 'delete', 'latest'} | (set() if row.get('delete') else {'size', 'etag'})
            require(type(row) is dict and set(row) == expected
                    and type(row['delete']) is bool and type(row['latest']) is bool
                    and type(row['version_id']) is str and row['version_id'] not in ('', 'null')
                    and historical.upload_priority('pebbleds/' + row['name']) >= 5,
                    'malformed marker history')
            key = row['name'], row['version_id']
            require(key not in result, 'duplicate marker version')
            result[key] = {k: value for k, value in row.items() if k != 'latest'}
        return result
    baseline, current = indexed(preopen), indexed(fresh)
    require(all(current.get(key) == row for key, row in baseline.items()), 'historical marker version lost/changed')
    old_names = {name for name in batch.old_metadata if name.startswith('marker.')}
    old_latest = {row['name']: row for row in preopen if row['latest'] and not row['delete']}
    require(set(old_latest) == old_names, 'pre-open marker latest set differs from certified gen13')
    for name in old_names:
        pin = batch.previous['remote_metadata'][name]
        require((old_latest[name]['version_id'], old_latest[name]['size'], old_latest[name]['etag'])
                == (pin['version_id'], pin['size'], pin['etag']), 'pre-open marker version differs from gen13')
    require(not any(row['name'] in batch.changed for row in preopen), 'marker uploaded before pre-open isolation')
    removed = old_names - set(batch.metadata)
    additions = [row for key, row in current.items() if key not in baseline]
    for name in removed:
        found = [row for row in additions if row['name'] == name]
        require(len(found) == 1 and found[0]['delete'], 'removed marker needs exactly one closed-batch tombstone')
    require(set(published) <= set(batch.changed), 'unexpected published marker')
    for name in batch.changed:
        found = [row for row in additions if row['name'] == name]
        require(len(found) == (1 if name in published else 0) and all(not row['delete'] for row in found),
                'early marker upload or unexpected remote marker versions')
        if found:
            require(found[0]['version_id'] == published[name]['version_id']
                    and found[0]['etag'] == published[name]['etag'] and found[0]['size'] == 0,
                    'published marker identity differs')
    require(all(row['name'] in removed | set(published) for row in additions), 'unexpected remote marker version')
    latest = [row for row in fresh if row['latest'] and not row['delete']]
    require({row['name'] for row in latest} == (old_names - removed) | set(published),
            'remote latest marker set changed')
    for name in old_names - removed:
        require(next(row for row in latest if row['name'] == name)['version_id']
                == old_latest[name]['version_id'], 'unchanged marker overwritten')


def exact_latest(client, name, pin, expected, *, checkpoint=lambda: None):
    """Fresh latest HEAD, version GET, latest HEAD; exact ETag/length/body/version."""
    require(type(expected) is bytes and len(expected) == pin['size']
            and c.raw_sha(expected) == pin['sha256'], 'immutable expected bytes differ')
    def head():
        checkpoint()
        value = client.head_object(Bucket=v.BUCKET, Key=v.PREFIX + name)
        require(type(value.get('ContentLength')) is int
                and (value.get('VersionId'), value.get('ETag'), value['ContentLength'])
                == (pin['version_id'], pin['etag'], pin['size'])
                and value.get('DeleteMarker', False) is False, 'fresh latest HEAD identity differs')
    head()
    checkpoint()
    response = client.get_object(Bucket=v.BUCKET, Key=v.PREFIX + name, VersionId=pin['version_id'])
    body = response.get('Body')
    try:
        require(type(response.get('ContentLength')) is int
                and (response.get('VersionId'), response.get('ETag'), response['ContentLength'])
                == (pin['version_id'], pin['etag'], pin['size'])
                and response.get('DeleteMarker', False) is False, 'version GET identity differs')
        offset = 0
        while offset < len(expected):
            checkpoint()
            data = body.read(min(1024**2, len(expected) - offset))
            require(type(data) is bytes and data and expected[offset:offset + len(data)] == data,
                    'version GET body differs')
            offset += len(data)
        require(body.read(1) == b'', 'version GET body longer than expected')
    finally:
        if body is not None:
            body.close()
    head()
    return dict(pin)


class OfflinePilot:
    """Functional DI rehearsal AFTER writer close; cannot open/replay a writer.

    transport is an offline fake implementing observe() and rc(). It models
    both independently enforced marker denial and one-shot selected release.
    Never connect this rehearsal transport to an actual root host: no signature
    verifier or installed denial mechanism authorizes it. Root API below refuses.
    """
    def __init__(self, store, batch, guard, transport, client, ledger, preopen_history, *,
                 clock=time.monotonic, failpoint=lambda name: None):
        self.store, self.batch, self.guard = store, batch, guard
        self.transport, self.client, self.ledger = transport, client, ledger
        self.preopen_raw = c.canonical({'rows': preopen_history})
        self.clock, self.failpoint = clock, failpoint
        self.sequence = 0
        self.published = {}
        self.stage = 'closed'
        self.state = GateState(batch.sha256)
        self.before = None
        self.poisoned = False

    def _history(self, monitor):
        monitor.check()
        fresh = marker_history(self.client, stop=monitor)
        check_marker_history(self.batch, c.parse(self.preopen_raw)['rows'], fresh, self.published)
        monitor.check()
        return fresh

    def _expire(self, row, monitor):
        """O_EXCL + file/dir fsync BEFORE exactly one fake RC mutation; no retry."""
        require(not self.poisoned, 'uncertain mutation; preserve/manual inspection')
        def selected_fresh():
            require(any((fresh.item_id, fresh.name, fresh.size, fresh.uploading, fresh.tries)
                        == (row.item_id, row.name, row.size, False, 0) for fresh in self.guard.rows),
                    'selected queue tuple changed')
        monitor.pulse()
        selected_fresh()
        if row.priority >= 5:
            require(self.stage == 'publishing' and self.state.phase == 'before-proved'
                    and self.before is not None, 'marker release before full proof')
            self.guard.data_drained()
            self._history(monitor)
            v.recheck_publication_inputs(self.client, self.before, c.digest(self.before))
            for name, pin in self.before['remote_metadata'].items():
                exact_latest(self.client, name, pin, self.batch.metadata[name], checkpoint=monitor.check)
            self._history(monitor)
        # Long cloud proofs/rechecks stay OUTSIDE the monitor lock. Only the
        # one-shot local intent/RC operation occupies it; freshness is checked
        # again after fsync, and an overlong RC round trip poisons the attempt.
        with self.guard.lock:
            envelope = self.transport.observe()
            self.guard.sample(envelope, self.clock())
            selected_fresh()
            w.validate_queue_selection(w.PROFILES['full-clone'], envelope['rc'],
                item_id=row.item_id, name=row.name, size=row.size,
                pid=c.parse(self.guard.identity_raw)['process']['pid'], expiry='expedite')
            monitor.check()
            self.sequence += 1
            stem = f'gate-mutation-{self.sequence:04d}'
            observation_sha = self.store.put(stem + '-observation.json', envelope)
            intent = dict(schema=1, generation=14, batch_sha256=self.batch.sha256,
                observation_sha256=observation_sha,
                before_sha256=c.digest(self.before) if self.before else None,
                identity_sha256=c.raw_sha(self.guard.identity_raw),
                selected=dict(id=row.item_id, name=row.name, size=row.size),
                method='vfs/queue-set-expiry', parameters=dict(id=row.item_id, expiry=w.QUEUE_EXPIRIES['expedite']),
                automatic_retry=False)
            self.poisoned = True
            self.store.put(stem + '-intent.json', intent)
            self.failpoint('after-intent')
            monitor.check()
            self.guard.release = row
            response = self.transport.rc(w.PROFILES['full-clone'], intent['method'], intent['parameters'],
                expected_pid=c.parse(self.guard.identity_raw)['process']['pid'], durable_intent=intent)
            require(response == {} and type(response) is dict, 'ambiguous RC response; never retry')
            self.failpoint('after-rc')
            monitor.check()
            monitor.pulse()
            require(row.item_id not in self.guard.active, 'upload not settled; preserve, no implicit wait/retry')
            self.guard.release = None
        pin = None
        if row.priority >= 5:
            name = row.name[len('pebbleds/'):]
            head = self.client.head_object(Bucket=v.BUCKET, Key=v.PREFIX + name)
            require(type(head.get('VersionId')) is str and head['VersionId'] not in ('', 'null')
                    and type(head.get('ETag')) is str and head['ETag'], 'published marker version missing')
            pin = dict(version_id=head['VersionId'], etag=head['ETag'], size=0, sha256=c.raw_sha(b''))
            exact_latest(self.client, name, pin, b'', checkpoint=monitor.check)
            self.published[name] = pin
            self._history(monitor)
        monitor.check()
        self.store.put(stem + '-receipt.json', dict(intent_sha256=c.digest(intent), rc=response, marker=pin))
        self.failpoint('after-receipt')
        self.poisoned = False

    def _proof(self, mode, monitor):
        started = self.clock()
        class Cancellation:
            def is_set(inner):
                return monitor.is_set() or self.clock() - started > self.guard.policy.maximum_proof_seconds
        proof = v.verify_generation(self.client, self.ledger, self.batch.previous, self.batch.report,
            self.batch.metadata, self.batch.hashes, mode, c.raw_sha(self.batch.previous_raw),
            enumeration_workers=4, enumeration_stop=Cancellation())
        require(self.clock() - started <= self.guard.policy.maximum_proof_seconds, 'full proof exceeded reviewed bound')
        monitor.pulse()
        self._history(monitor)
        return proof

    def run(self):
        try:
            return self._run()
        except BaseException:
            self.poisoned = True
            if self.state.phase not in ('preserve/manual-inspection', 'remote-proved'):
                self.state = self.state.advance(self.batch, 'preserve', {})
            raise

    def _run(self):
        require(self.store.locked and {p.name for p in self.store.path.iterdir()} == {'lock'},
                'locked dedicated empty attempt required; never replay')
        require(self.guard.batch == self.batch, 'guard/batch mismatch')
        self.store.put('gate-attempt-intent.json', dict(schema=1, batch_sha256=self.batch.sha256,
            identity=c.parse(self.guard.identity_raw), isolation=c.parse(self.guard.isolation_raw),
            timing=vars(self.guard.policy), preopen_history=c.parse(self.preopen_raw)['rows']))
        retained = self.store.pack_receipt('snapshot', self.batch.retained())
        self.store.put('gate-batch.json', retained)
        with ContinuousMonitor(self.guard, self.transport.observe, clock=self.clock) as monitor:
            self._history(monitor)
            self.stage = 'draining'
            while any(row.priority < 5 for row in self.guard.rows):
                self._expire(next(row for row in self.guard.rows if row.priority < 5), monitor)
            self.guard.data_drained()
            self.state = self.state.advance(self.batch, 'data-drained', self.guard.rows)
            drained = self.transport.observe()
            self.guard.sample(drained, self.clock())
            self.store.put('gate-drained-observation.json', drained)
            self.stage = 'before-proof'
            prepublication = self._history(monitor)
            self.store.put('gate-prepublication.json', dict(batch_sha256=self.batch.sha256, history=prepublication))
            self.before = self._proof('before-markers', monitor)
            self.state = self.state.advance(self.batch, 'before-proved', self.before)
            self.store.put('gate-before-proof.json', self.before)
            self.stage = 'publishing'
            for name in self.batch.changed:
                monitor.pulse()
                row = next((row for row in self.guard.rows if row.name == 'pebbleds/' + name), None)
                require(row is not None, 'unverified marker upload; no implicit retry')
                self._expire(row, monitor)
            self.guard.clean()
            self.state = self.state.advance(self.batch, 'published', self.published)
            self.store.put('gate-publication.json', dict(batch_sha256=self.batch.sha256,
                before_sha256=c.digest(self.before), published=self.published))
            self.stage = 'final-proof'
            final = self._proof('final', monitor)
            self.state = self.state.advance(self.batch, 'remote-proved', final)
            self.store.put('gate-final-proof.json', final)
            # No reopen/start here: the independent inspector must validate a
            # separately obtained read-only reopen AND reader restoration.
            self.stage = 'remote-proved'
            return dict(stage=self.stage, batch_sha256=self.batch.sha256, before=self.before, final=final,
                        certifiable=False, live_success=False)


class RootQueueRuntime:
    """Future root-only read observations using the actual pinned RealHost API.

    Installation/admission provisioning remains absent. No DI host, admitted
    boolean, caller-selected paths, or credential arguments enter this class.
    Even a signed reader bridge only retains a STOP PROPOSAL; it grants no
    marker denial, DB open, expiry, publication or controller authority here.
    """
    def __init__(self):
        require(os.geteuid() == 0, 'root required')
        self.adapter = root.RootHostAdapter()
        self.host, self.profile = self.adapter.host, self.adapter.profile
        self._lock_identity = None

    @contextmanager
    def exclusive(self):
        with self.adapter.exclusive():  # pinned shared writer.lock, no second lock domain
            info = Path(WRITER_LOCK).lstat()
            self._lock_identity = dict(device=info.st_dev, inode=info.st_ino)
            try:
                bridge.owned_lock(self.host, self._lock_identity)
                yield
            finally:
                self._lock_identity = None

    def observe_queue(self):
        self.adapter._require_lock()
        require(self._lock_identity is not None, 'marker observer lock context required')
        bridge.owned_lock(self.host, self._lock_identity)
        require(not historical.STOP_FILE.exists() and not historical.STOP_FILE.is_symlink(), 'user stop sentinel')
        require(root.validate_installation() == self.adapter.deployment, 'installation changed')
        legacy = self.adapter._legacy()
        host, p = self.host, self.profile
        host.guard(p, True)
        host.no_open_users(p)
        services = {name: host.service(name) for name in (*w.PROD_OFF, w.PROD_MOUNT, w.READER, p.unit)}
        pid = host.unit_identity(p, services[p.unit], active=True)
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        process = root.process_identity(pid, w.RCLONE, boot)
        lines = Path('/proc/self/mountinfo').read_text().splitlines()
        mounts = [line for line in lines if len(line.split()) > 4 and line.split()[4] == str(p.mountpoint)]
        require(len(mounts) == 1, 'exact writer mount missing')
        parsed = w.mount_rows(mounts[0])
        require(len(parsed) == 1 and w.remote_matches(p, parsed[0]['source']), 'mount source changed')
        cache_before = p.cache.lstat()
        require(stat.S_ISDIR(cache_before.st_mode) and cache_before.st_uid == cache_before.st_gid == 0
                and stat.S_IMODE(cache_before.st_mode) == 0o700, 'unsafe cache directory')
        socket_before = p.rc_socket.lstat()
        require(stat.S_ISSOCK(socket_before.st_mode) and socket_before.st_uid == socket_before.st_gid == 0
                and stat.S_IMODE(socket_before.st_mode) == 0o600, 'unsafe RC socket')
        started = time.monotonic()
        observed = host.observe(p)  # RealHost.rc SO_PEERCRED on BOTH stats and queue
        socket_after = p.rc_socket.lstat()
        require(observed['pid'] == pid and (socket_before.st_dev, socket_before.st_ino)
                == (socket_after.st_dev, socket_after.st_ino)
                and socket_after.st_uid == socket_after.st_gid == 0
                and stat.S_IMODE(socket_after.st_mode) == 0o600, 'RC socket/PID replaced')
        identity = dict(process=process, mount=dict(mountinfo=mounts[0], target=str(p.mountpoint), source=parsed[0]['source']),
            rc=dict(path=str(p.rc_socket), device=socket_before.st_dev, inode=socket_before.st_ino,
                    peer_pid=pid, peer_uid=0, peer_gid=0), source=p.remote,
            cache=dict(path=str(p.cache), device=cache_before.st_dev, inode=cache_before.st_ino),
            cloud=host.read_admission(p)['identity'])
        validate_identity(identity)
        require(root.process_identity(pid, w.RCLONE, boot) == process
                and mounts[0] in Path('/proc/self/mountinfo').read_text().splitlines()
                and all(host.service(name) == state for name, state in services.items())
                and self.adapter._legacy() == legacy
                and root.validate_installation() == self.adapter.deployment, 'host changed during RC observation')
        require(host.unit_identity(p, host.service(p.unit), active=True) == pid, 'rclone process tuple replaced')
        cache_after = p.cache.lstat()
        require((cache_before.st_dev, cache_before.st_ino, cache_before.st_mode, cache_before.st_uid, cache_before.st_gid)
                == (cache_after.st_dev, cache_after.st_ino, cache_after.st_mode, cache_after.st_uid, cache_after.st_gid),
                'cache directory replaced')
        bridge.owned_lock(self.host, self._lock_identity)
        require(not historical.STOP_FILE.exists() and not historical.STOP_FILE.is_symlink(), 'user stop sentinel')
        space = os.statvfs(p.cache)
        return dict(identity=identity, rc=observed, started=started, finished=time.monotonic(),
                    free_bytes=space.f_bavail * space.f_frsize, controller_ready=False,
                    isolation_proven=False, execution_allowed=False)

    def _refuse(self, *args, **kwargs):
        raise Refusal('live marker gate disabled: separately signed installation/admission and pre-open marker denial absent; '
                      'reader bridge is STOP PROPOSAL only')

    authenticate_marker_admission = _refuse
    open_writer = _refuse
    selected_queue_expiry = _refuse
    publish_markers = _refuse
    restore_reader = _refuse


def main():
    print('REFUSED: offline marker gate library only; no live controller, queue expiry or marker publication CLI')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
