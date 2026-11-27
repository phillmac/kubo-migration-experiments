#!/usr/bin/env python3
"""Offline-injected checkpoint engine. NOT DEPLOYED / NOT LIVE TESTED.

No subprocess, SDK, adapter loader or live writer entrypoint exists here. The
Protocol is a security contract for a separately reviewed future installation.
Recovery is deliberately a different, read-only module; run() is never resume().
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, ContextManager, Protocol

BASE_COMMIT = '1548aa364c784199dece84ca968bea5ec582ae16'
INSTALL = Path('/root/.local/share/rhea-multi-sst-controller-v2')
ADAPTER_VERSION = 'rhea-multi-sst-root-host-v2.1'
# Deliberately unprovisioned. No env var, CLI flag, import path or token fills these.
INSTALLED_ADAPTER_SHA256 = None
ADMISSION_PUBLIC_KEY_SHA256 = None
MAX_FILE = 32 * 1024**2
BLOB_CHUNK = 16 * 1024**2
HEX = re.compile(r'[0-9a-f]{64}\Z')
GUARD_KEYS = {'legacy_journal', 'legacy_pins', 'protected_source', 'production_state',
              'deployment', 'ledger', 'checkpoint'}
PHASES = ('admitted', 'handoff_intent', 'writer_ready', 'writer_intent', 'writer_closed',
          'snapshot', 'drain_intent', 'data_drained', 'before_proved', 'marker_intent',
          'markers_published', 'final_proved', 'reopen_intent', 'reopened', 'certified')


class Refusal(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


def raw_sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value):
    return raw_sha(canonical(value))


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite JSON')))
    require(isinstance(value, dict), 'JSON object required')
    return value


def source_pins(root):
    """Immutable baseline dependencies, not a generated caller-selected allowlist."""
    expected = SOURCE_PINS
    for name, wanted in expected.items():
        path = Path(root) / name
        require(not path.is_symlink() and raw_sha(path.read_bytes()) == wanted,
                'source/pin mismatch: ' + name)
    return digest(expected)


def load_verifier():
    root = source_root()
    source_pins(root)
    path = root / 'scripts/verify_rhea_multi_sst_candidate.py'
    spec = importlib.util.spec_from_file_location('checkpoint_candidate_verifier', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_root():
    return (INSTALL / 'sources' if Path(__file__).absolute() == INSTALL / 'rhea_multi_sst_checkpoint_controller.py'
            else Path(__file__).resolve().parents[1])


def validate_provisioning_manifest(manifest):
    """Structural provisioning contract, NEVER a signature/readiness assertion.

    A future provisioner must verify an independent detached signature BEFORE
    using this manifest, retain it O_EXCL/0600 under INSTALL, and check actual
    bytes/ownership of every artifact and source. No provisioner is shipped.
    No self-generated key, digest, boolean or caller path grants admission.
    """
    require(set(manifest) == {'schema', 'scope', 'install', 'base_commit', 'adapter_version',
            'source_pins_sha256', 'artifacts', 'guards', 'boot_id'}, 'provisioning schema mismatch')
    require(type(manifest['schema']) is int and manifest['schema'] == 2
            and manifest['scope'] == 'rhea-multi-sst-root-install'
            and manifest['install'] == str(INSTALL) and manifest['base_commit'] == BASE_COMMIT
            and manifest['adapter_version'] == ADAPTER_VERSION
            and manifest['source_pins_sha256'] == digest(SOURCE_PINS), 'fixed provisioning binding mismatch')
    artifacts = manifest['artifacts']
    require(set(artifacts) == {'rhea_multi_sst_checkpoint_controller.py', 'rhea_multi_sst_recovery_inspector.py', 'host-adapter.py', 'writer', 'admission.pub'}
            and all(isinstance(value, str) and HEX.fullmatch(value) for value in artifacts.values()),
            'every exact installed artifact/key digest required')
    guards(manifest['guards'], manifest['guards'])
    require(manifest['guards']['checkpoint'] == verifier.GENERATION13_SHA256
            and manifest['guards']['ledger'] == verifier.proof.LEDGER_SHA256
            and isinstance(manifest['boot_id'], str)
            and re.fullmatch(r'[0-9a-f-]{36}', manifest['boot_id']), 'provisioning anchor/boot mismatch')
    return digest(manifest)


def private_path(path, directory=False, root_only=False):
    """Reject links, shared paths, wrong owner, hard links and loose file modes."""
    path = Path(path).absolute()
    uid = 0 if root_only else os.geteuid()
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'linked parent')
        # /tmp is allowed for offline stores, never for the fixed installation.
        require(not info.st_mode & 0o022 or
                (not root_only and ancestor == Path('/tmp') and info.st_mode & stat.S_ISVTX),
                'writable parent')
        if root_only:
            require(info.st_uid == 0, 'nonroot parent')
    info = path.lstat()
    require(info.st_uid == uid and not stat.S_ISLNK(info.st_mode), 'untrusted owner/link')
    require(stat.S_ISDIR(info.st_mode) if directory else
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'untrusted file type/links')
    require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), 'private mode required')


class Store:
    """One atomic journal, immutable intent/receipts and a write-ahead stage chain.

    Caller holds lock() across every read/CAS. An interrupted immutable write or
    rename leaves an orphan, which audit refuses; no auto-repair or clobbering.
    Files are created once (O_EXCL, 0600), then file+directory fsynced. A journal
    rename is the only replacement. Previous-state hashes bind every stage.
    """
    def __init__(self, directory):
        self.path = Path(directory).absolute()
        private_path(self.path, directory=True)
        self.locked = False

    def sync(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self, name):
        require(re.fullmatch(r'[a-z0-9_.-]+', name), 'invalid evidence name')
        path = self.path / name
        private_path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE, 'oversize evidence')
        return raw

    def put(self, name, value):
        return self.put_raw(name, canonical(value))

    def put_raw(self, name, raw):
        require(self.locked, 'store lock required')
        require(len(raw) <= MAX_FILE and re.fullmatch(r'[a-z0-9_.-]+', name), 'invalid receipt')
        fd = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self.sync()
        require(self.read(name) == raw, 'receipt readback mismatch')
        return raw_sha(raw)

    def pack_receipt(self, phase, receipt):
        if phase not in ('snapshot', 'reopened'):
            return receipt
        # Real gen13 metadata is already larger than a small JSON receipt.
        # Retain bounded binary chunks separately, with exact hash references.
        value = copy.deepcopy(receipt)
        for key in ('metadata', 'previous_metadata'):
            if key not in value:
                continue
            metadata = decode_metadata(value[key])
            metadata_bounds(metadata)
            value[key] = {}
            for name, data in metadata.items():
                chunks = []
                for offset in range(0, len(data), BLOB_CHUNK):
                    chunk = data[offset:offset + BLOB_CHUNK]
                    sha = raw_sha(chunk)
                    blob = 'blob-' + sha + '.bin'
                    if (self.path / blob).exists():
                        require(self.read(blob) == chunk, 'existing immutable chunk differs')
                    else:
                        self.put_raw(blob, chunk)
                    chunks.append(sha)
                value[key][name] = {'size': len(data), 'sha256': raw_sha(data), 'chunks': chunks}
        return {'storage_schema': 1, 'value': value}

    def unpack_receipt(self, phase, stored):
        if phase not in ('snapshot', 'reopened'):
            return stored, set()
        require(set(stored) == {'storage_schema', 'value'} and stored['storage_schema'] == 1,
                'invalid chunked receipt schema')
        value, names = copy.deepcopy(stored['value']), set()
        for key in ('metadata', 'previous_metadata'):
            if key not in value:
                continue
            metadata = {}
            require(len(value[key]) <= verifier.proof.base.MAX_METADATA_FILES, 'too many retained metadata files')
            total = 0
            for name, ref in value[key].items():
                require(set(ref) == {'size', 'sha256', 'chunks'} and type(ref['size']) is int
                        and 0 <= ref['size'] <= verifier.proof.base.MAX_METADATA_BYTES
                        and isinstance(ref['chunks'], list)
                        and len(ref['chunks']) == (ref['size'] + BLOB_CHUNK - 1) // BLOB_CHUNK,
                        'invalid metadata chunk references')
                total += ref['size']
                require(total <= verifier.proof.base.MAX_METADATA_TOTAL, 'retained metadata exceeds bound')
                pieces = []
                for sha in ref['chunks']:
                    require(isinstance(sha, str) and HEX.fullmatch(sha), 'invalid blob digest')
                    blob = 'blob-' + sha + '.bin'
                    names.add(blob)
                    chunk = self.read(blob)
                    require(0 < len(chunk) <= BLOB_CHUNK and raw_sha(chunk) == sha, 'immutable blob hash mismatch')
                    pieces.append(chunk)
                data = b''.join(pieces)
                require(len(data) == ref['size'] and raw_sha(data) == ref['sha256'], 'metadata file hash mismatch')
                metadata[name] = data
            metadata_bounds(metadata)
            value[key] = encode_metadata(metadata)
        return value, names

    def receipt(self, phase):
        return self.unpack_receipt(phase, parse(self.read(phase + '.json')))[0]

    @contextmanager
    def lock(self, *, existing=False):
        require(not self.locked, 'nested store lock')
        name = self.path / 'lock'
        if not existing:
            try:
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                os.close(fd)
                self.sync()
        private_path(name)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Refusal('concurrent run or inspection') from exc
            self.locked = True
            yield
        finally:
            self.locked = False
            os.close(fd)

    def begin(self, intent):
        require(set(p.name for p in self.path.iterdir()) == {'lock'}, 'attempt replay; preserve evidence')
        intent_hash = self.put('intent.json', intent)
        state = dict(schema=2, seq=0, phase='admitted', previous_state_sha256=None,
                     intent_sha256=intent_hash, receipts={}, generation=13,
                     physical_rewrite_total=9, pending={'generation': 14, 'unit_count': intent['unit_count']})
        self.put('stage-000.json', state)
        self._replace(state)
        return state

    def _replace(self, state):
        self.put('journal.next', state)
        os.replace(self.path / 'journal.next', self.path / 'journal.json')
        self.sync()

    def audit(self):
        require(self.locked, 'store lock required')
        raw = self.read('journal.json')
        current = parse(raw)
        require(canonical(current) == raw and current.get('schema') == 2
                and type(current.get('seq')) is int and 0 <= current['seq'] < len(PHASES), 'invalid journal')
        intent_raw = self.read('intent.json')
        intent = parse(intent_raw)
        names = {'intent.json', 'journal.json', 'lock'}
        prior = None
        for index in range(current['seq'] + 1):
            name = f'stage-{index:03d}.json'
            names.add(name)
            stage_raw = self.read(name)
            stage = parse(stage_raw)
            require(canonical(stage) == stage_raw and stage.get('seq') == index
                    and stage.get('schema') == 2 and stage.get('phase') == PHASES[index]
                    and stage.get('intent_sha256') == raw_sha(intent_raw)
                    and stage.get('previous_state_sha256') == (digest(prior) if prior else None),
                    'stage chain/CAS mismatch')
            expected_receipts = set(PHASES[1:index + 1])
            require(set(stage.get('receipts', {})) == expected_receipts, 'missing/unrelated receipts')
            for phase, wanted in stage['receipts'].items():
                receipt_name = phase + '.json'
                names.add(receipt_name)
                require(raw_sha(self.read(receipt_name)) == wanted, 'receipt hash mismatch')
                _, blobs = self.unpack_receipt(phase, parse(self.read(receipt_name)))
                names.update(blobs)
                if prior and phase in prior['receipts']:
                    require(prior['receipts'][phase] == wanted, 'receipt changed across stages')
            if stage['phase'] == 'certified':
                cert = parse(self.read('certified.json'))
                require(stage.get('generation') == 14 and stage.get('pending') is None
                        and stage.get('physical_rewrite_total') == cert['physical_rewrite_total'],
                        'certified journal mismatch')
            else:
                require(stage.get('generation') == 13 and stage.get('physical_rewrite_total') == 9
                        and stage.get('pending') == {'generation': 14, 'unit_count': intent['unit_count']},
                        'premature journal advancement')
            prior = stage
        require(prior == current and set(p.name for p in self.path.iterdir()) == names,
                'orphan/torn receipt or stage; independent inspection required')
        return intent, current

    def advance(self, expected, phase, receipt):
        _, current = self.audit()
        require(digest(current) == expected, 'previous-state SHA compare-and-swap failed')
        index = current['seq'] + 1
        require(index < len(PHASES) and phase == PHASES[index], 'unauthorized phase transition')
        receipt_hash = self.put(phase + '.json', self.pack_receipt(phase, receipt))
        new = copy.deepcopy(current)
        new.update(seq=index, phase=phase, previous_state_sha256=expected)
        new['receipts'][phase] = receipt_hash
        if phase == 'certified':
            require(receipt.get('generation') == 14 and receipt.get('pebble_reopen_verified') is True
                    and receipt.get('remote_generation_verified') is True, 'uncertified result')
            new.update(generation=14, pending=None, physical_rewrite_total=receipt['physical_rewrite_total'])
        self.put(f'stage-{index:03d}.json', new)
        self._replace(new)
        return new


def process_tuple(value):
    require(isinstance(value, dict) and set(value) == {'pid', 'start_ticks', 'boot_id', 'exe_sha256'}
            and type(value['pid']) is int and value['pid'] > 1
            and type(value['start_ticks']) is int and value['start_ticks'] > 0
            and isinstance(value['boot_id'], str) and re.fullmatch(r'[0-9a-f-]{36}', value['boot_id'])
            and isinstance(value['exe_sha256'], str) and HEX.fullmatch(value['exe_sha256']),
            'unauthenticated process tuple')
    return value


def health(value, *, drained=False):
    limits = verifier.LIMITS
    for key in ('cache_bytes', 'free_bytes', 'queue_bytes', 'queue_files', 'errors', 'transferring'):
        require(type(value.get(key)) is int and value[key] >= 0, 'invalid queue/resource evidence')
    require(value['cache_bytes'] <= limits['cache_bytes']
            and value['free_bytes'] >= limits['minimum_free_bytes']
            and value['queue_bytes'] <= limits['backlog_bytes']
            and value['queue_files'] <= limits['backlog_files'] and value['errors'] == 0,
            'queue/cache/free-space bound violated')
    if drained:
        require(value['queue_bytes'] == value['queue_files'] == value['transferring'] == 0,
                'data uploads have not drained')


def guards(actual, expected):
    require(isinstance(expected, dict) and set(expected) == GUARD_KEYS
            and all(isinstance(x, str) and HEX.fullmatch(x) for x in expected.values())
            and actual == expected, 'protected source/checkpoint/deployment guard mismatch')


def encode_metadata(metadata):
    return {name: base64.b64encode(data).decode('ascii') for name, data in metadata.items()}


def decode_metadata(metadata):
    require(isinstance(metadata, dict), 'metadata snapshot missing')
    return {name: base64.b64decode(data, validate=True) for name, data in metadata.items()}


def metadata_bounds(metadata):
    base = verifier.proof.base
    require(isinstance(metadata, dict) and 0 < len(metadata) <= base.MAX_METADATA_FILES
            and all(isinstance(name, str) and base.META_NAME.fullmatch(name)
                    and isinstance(data, bytes) and len(data) <= base.MAX_METADATA_BYTES
                    for name, data in metadata.items())
            and sum(map(len, metadata.values())) <= base.MAX_METADATA_TOTAL,
            'retained metadata bounds/name mismatch')


def validate_intent(intent):
    require(set(intent) == {'schema', 'generation', 'unit_count', 'previous_checkpoint',
            'previous_checkpoint_sha256', 'guards', 'source_pins_sha256', 'adapter_version',
            'deployment_sha256', 'admission_sha256', 'go_binary_sha256', 'request', 'reader_identity'}, 'intent schema mismatch')
    require(type(intent['schema']) is int and intent['schema'] == 2 and type(intent['generation']) is int
            and intent['generation'] == 14 and type(intent['unit_count']) is int
            and intent['unit_count'] in (1, 2), 'only one generation-14 batch of one/two units')
    previous = intent['previous_checkpoint']
    require(verifier._predecessor(previous, intent['previous_checkpoint_sha256']) == 1,
            'only exact generation-13 anchor admitted')
    require(intent['source_pins_sha256'] == digest(SOURCE_PINS)
            and intent['adapter_version'] == ADAPTER_VERSION, 'source/adapter version mismatch')
    guards(intent['guards'], intent['guards'])
    require(intent['guards']['checkpoint'] == intent['previous_checkpoint_sha256']
            and intent['guards']['ledger'] == verifier.proof.LEDGER_SHA256
            and intent['guards']['deployment'] == intent['deployment_sha256'], 'intent guard lineage mismatch')
    for key in ('deployment_sha256', 'admission_sha256', 'go_binary_sha256'):
        require(isinstance(intent[key], str) and HEX.fullmatch(intent[key]), 'missing sealed ' + key)
    process_tuple(intent['reader_identity'])
    request = intent['request']
    expected = {'format': '013', 'marked': previous['marked_after'], 'files': previous['sst_count'],
                'bytes': previous['sst_bytes'], 'inventory_sha256': previous['sst_inventory_sha256']}
    require(set(request) == {'maximum_units', 'before', 'initial_plan_sha256'}
            and type(request['maximum_units']) is int and request['maximum_units'] == intent['unit_count']
            and digest(request['before']) == digest(expected)
            and isinstance(request['initial_plan_sha256'], str)
            and HEX.fullmatch(request['initial_plan_sha256']), 'batch request/predecessor mismatch')


def validate_closed(writer, intent):
    report = writer['report']
    process_tuple(writer['source_process'])
    require(writer['source_process']['exe_sha256'] == writer['binary_sha256'] == intent['go_binary_sha256']
            and writer['source_process']['boot_id'] == intent['reader_identity']['boot_id']
            and writer['exit_code'] == 0 and type(writer['exit_code']) is int
            and writer.get('stopped') is True and writer.get('monitor_complete') is True,
            'writer identity/exit/continuous monitor missing')
    health(writer['health'])
    require(report.get('closed') is True and not report.get('error') and not report.get('attempted_unit')
            and report.get('stop_reason') in ('unit-limit', 'no-marked-files', 'next-unit-budget')
            and digest(report.get('request')) == digest(intent['request'])
            and type(report.get('physical_compactions')) is int
            and 1 <= report['physical_compactions'] <= intent['unit_count']
            and len(report['units']) == report['physical_compactions'],
            'partial/ambiguous/unclosed Go batch; never retry writer')
    # Retain actual Go sink files, not just stdout claiming a successful close.
    files = writer['go_files']
    expected = {'pending.json', 'closed.json'}
    for index in range(1, len(report['units']) + 1):
        expected.update({f'unit-{index:03d}-intent.json', f'unit-{index:03d}-receipt.json'})
    require(set(files) == expected, 'missing/unrelated Go file receipts')
    decoded = {name: parse(base64.b64decode(raw, validate=True)) for name, raw in files.items()}
    require(decoded['closed.json'] == report and decoded['pending.json'] == {
            'schema': verifier.WRITER_SCHEMA, 'phase': 'executing', 'request': intent['request']},
            'Go closed/pending receipt differs from report')
    for index, unit in enumerate(report['units'], 1):
        require(decoded[f'unit-{index:03d}-receipt.json'] == unit, 'Go unit receipt differs')
        planned = decoded[f'unit-{index:03d}-intent.json']
        state = {key: unit.get(prefix + 'before') for key, prefix in (
            ('marked', 'marked_'), ('files', 'sst_files_'),
            ('bytes', 'sst_bytes_'), ('inventory_sha256', 'sst_inventory_sha256_'))}
        state['format'] = unit['before_format']
        require(type(planned.get('index')) is int and planned['index'] == index
                and planned.get('picker_plan') == unit['picker_plan'] and planned.get('before') == state,
                'Go unit intent lineage differs')


def validate_snapshot(snapshot, writer, intent):
    require(snapshot.get('closed_report_sha256') == digest(writer['report'])
            and snapshot.get('markers_withheld') is True, 'snapshot not bound to closed batch')
    metadata = decode_metadata(snapshot['metadata'])
    old = decode_metadata(snapshot['previous_metadata'])
    metadata_bounds(metadata)
    metadata_bounds(old)
    pins = intent['previous_checkpoint']['remote_metadata']
    require(set(old) == set(pins), 'retained predecessor metadata incomplete')
    for name, pin in pins.items():
        require(len(old[name]) == pin['size'] and raw_sha(old[name]) == pin['sha256'],
                'retained predecessor metadata hash mismatch')
    before, bs = verifier.proof._decode_tables(old[intent['previous_checkpoint']['manifest']])
    markers = verifier.proof._marker_info(metadata)
    after, ats = verifier.proof._decode_tables(metadata[markers['manifest']])
    verifier.validate_batch(writer['report'], before, after, bs, ats, '013', '013', snapshot['hashes'])
    require(writer['report']['before']['inventory_sha256'] == intent['previous_checkpoint']['sst_inventory_sha256'],
            'snapshot predecessor inventory mismatch')
    return metadata


class HostAdapter(Protocol):
    """Future ROOT-ONLY exact-version adapter; no implementation shipped.

    All methods operate under one host lock also excluding historical controllers.
    authenticate_admission must verify an independently installed signature over
    the ENTIRE intent, boot/mount/process/RC/cloud identities, binary/source/pins,
    nonce and exact idle gen13 journal. Signature verification is not a bool flag
    supplied by a CLI caller. The nonce is durably consumed before handoff.
    preflight/guard/health must authenticate identities, production freeze and
    protected files, not trust RC labels. Read-only credentials serve cloud_read.
    handoff stops the exact reader, seals an exclusive writer mount, defers ALL
    changed markers before ANY uploads and returns an authenticated identity.
    run_go_monitored invokes exactly one sealed Go child; continuously checks RC,
    free space/cache/queue, protected source/process tuple, per-unit Go evidence,
    cooperative stop sentinel, waits for that child/close without restart/kill.
    snapshot_closed retains immutable closed metadata, output hashes, ALL prior
    checkpoint metadata and raw Go files. drain_stop uploads only data, observes
    zero transfers/queue/errors, stops exact writer mount and proves no writer.
    publish_markers uses exclusive conditional publication only after a fresh
    read-only HEAD recheck; any unknown result is uncertainty, NEVER retried.
    reopen_readonly starts an authenticated reader without write/compaction.
    No method may restore, mutate historical cap9 or start Kubo/walker.
    """
    version: str
    def exclusive(self) -> ContextManager: ...
    def authenticate_admission(self, intent: dict) -> None: ...
    def preflight(self, intent: dict) -> dict: ...
    def protected_guards(self) -> dict: ...
    def queue_health(self) -> dict: ...
    def handoff(self, intent: dict) -> dict: ...
    def run_go_monitored(self, request: dict, monitor: Callable[[], None]) -> dict: ...
    def snapshot_closed(self, writer: dict) -> dict: ...
    def drain_stop(self, snapshot: dict) -> dict: ...
    def cloud_read(self): ...
    def baseline_ledger(self) -> dict: ...
    def publish_markers(self, before: dict, metadata: dict) -> dict: ...
    def reopen_readonly(self) -> dict: ...


class Engine:
    """Single attempt engine for DI/offline tests. No resume entrypoint."""
    def __init__(self, store, host: HostAdapter, failpoint=lambda phase: None):
        self.store, self.host, self.failpoint = store, host, failpoint

    def run(self, intent):
        intent = copy.deepcopy(intent)
        validate_intent(intent)
        require(self.host.version == ADAPTER_VERSION, 'exact adapter version required')
        with self.store.lock(), self.host.exclusive():
            self.host.authenticate_admission(copy.deepcopy(intent))
            preflight = self.host.preflight(copy.deepcopy(intent))
            require(preflight.get('reader_identity') == intent['reader_identity']
                    and preflight.get('locked') is True and preflight.get('writer_stopped') is True,
                    'preflight reader/lock/writer identity mismatch')
            self.check(intent)
            state = self.store.begin(intent)

            def step(phase, receipt):
                nonlocal state
                state = self.store.advance(digest(state), phase, receipt)
                self.failpoint(phase)

            step('handoff_intent', {'preflight': preflight})
            ready = self.host.handoff(copy.deepcopy(intent))
            process_tuple(ready['writer_identity'])
            require(ready.get('reader_stopped') is True and ready.get('markers_withheld') is True,
                    'unsafe handoff/marker isolation')
            require(ready.get('binary_sha256') == intent['go_binary_sha256']
                    and ready['writer_identity']['boot_id'] == intent['reader_identity']['boot_id'],
                    'handoff executable/boot differs from admission')
            self.check(intent)
            step('writer_ready', ready)
            step('writer_intent', {'request': intent['request'], 'writer_identity': ready['writer_identity']})
            writer = self.host.run_go_monitored(copy.deepcopy(intent['request']), lambda: self.check(intent))
            # Persist failure/partial results BEFORE validation; they remain inspection evidence.
            step('writer_closed', writer)
            validate_closed(writer, intent)
            require(writer['binary_sha256'] == ready['binary_sha256'], 'unsealed Go executable')
            snapshot = self.host.snapshot_closed(writer)
            step('snapshot', snapshot)
            metadata = validate_snapshot(snapshot, writer, intent)
            self.check(intent)
            step('drain_intent', {'snapshot_sha256': digest(snapshot)})
            drained = self.host.drain_stop(snapshot)
            step('data_drained', drained)
            health(drained['health'], drained=True)
            require(drained.get('writer_stopped') is True
                    and drained.get('writer_identity') == ready['writer_identity'], 'writer stop identity missing')
            self.check(intent)
            params = dict(ledger=self.host.baseline_ledger(), previous_checkpoint=intent['previous_checkpoint'],
                          go_report=writer['report'], metadata_bytes=metadata, created_sst_hashes=snapshot['hashes'],
                          previous_checkpoint_sha256=intent['previous_checkpoint_sha256'], enumeration_workers=4)
            before = verifier.verify_generation(self.host.cloud_read(), mode='before-markers', **params)
            step('before_proved', before)
            self.check(intent)
            verifier.recheck_publication_inputs(self.host.cloud_read(), before, digest(before))
            step('marker_intent', {'before_sha256': digest(before), 'changed_markers': before['changed_markers']})
            publication = self.host.publish_markers(before, metadata)
            step('markers_published', publication)
            require(publication.get('before_sha256') == digest(before)
                    and publication.get('published') == before['changed_markers'], 'publication receipt mismatch')
            self.check(intent)
            final = verifier.verify_generation(self.host.cloud_read(), mode='final', **params)
            step('final_proved', final)
            step('reopen_intent', {'final_sha256': digest(final)})
            reopened = self.host.reopen_readonly()
            step('reopened', reopened)
            process_tuple(reopened['reader_identity'])
            require(reopened['reader_identity']['boot_id'] == intent['reader_identity']['boot_id']
                    and reopened['reader_identity']['exe_sha256'] == intent['reader_identity']['exe_sha256'],
                    'reader reopen boot/executable mismatch')
            certificate = verifier.finalize_checkpoint(before, final, reopened['report'],
                                                       decode_metadata(reopened['metadata']))
            require(certificate['generation'] == 14 and certificate['batch_checkpoint_count'] == 1
                    and certificate['physical_rewrite_total'] == 9 + writer['report']['physical_compactions'],
                    'generation/physical lineage mismatch')
            self.check(intent)
            step('certified', certificate)
            return certificate

    def check(self, intent):
        guards(self.host.protected_guards(), intent['guards'])
        health(self.host.queue_health())


def installation_preflight():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL / 'rhea_multi_sst_checkpoint_controller.py',
            'apply requires fixed root-owned private installation; development checkout cannot apply')
    private_path(INSTALL, directory=True, root_only=True)
    private_path(INSTALL / 'rhea_multi_sst_checkpoint_controller.py', root_only=True)
    # Fail CLOSED even if this candidate is copied to the fixed path.
    require(INSTALLED_ADAPTER_SHA256 is not None and ADMISSION_PUBLIC_KEY_SHA256 is not None,
            'no independently installed exact-version root host adapter or admission verification key')
    raise Refusal('live adapter integration and interruption tests are not implemented')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='status', choices=('status', 'inspect', 'preflight', 'apply'))
    parser.add_argument('--evidence', type=Path, help='read-only offline inspection directory only')
    args = parser.parse_args(argv)
    try:
        if args.action == 'apply':
            require(args.evidence is None, 'no caller-selected live state path')
            installation_preflight()
        elif args.action == 'inspect':
            require(args.evidence is not None, 'inspect requires retained offline --evidence')
            from rhea_multi_sst_recovery_inspector import CERTIFIABLE, inspect
            finding = inspect(args.evidence)
            print(json.dumps(finding, sort_keys=True))
            return 0 if finding['decision'] == CERTIFIABLE else 2
        else:
            require(args.evidence is None, '--evidence is inspect-only')
            pin = source_pins(source_root())
            print(json.dumps({'status': 'NOT DEPLOYED / NOT LIVE TESTED', 'live_apply': False,
                  'source_pins_sha256': pin, 'base_commit': BASE_COMMIT,
                  'blocker': 'root adapter, installed signed deployment/admission and live failure qualification missing'}))
            return 2 if args.action == 'preflight' else 0
    except (Refusal, OSError, ValueError) as exc:
        parser.exit(2, 'REFUSED: ' + str(exc) + '\n')
    return 0


# Frozen starting sources; controller/inspector bytes must ALSO be pinned by a
# future independently signed root installation manifest (no self-signing).
SOURCE_PINS = {
    'cmd/pebble-format-v1/go.mod': '197f1cc07d2e4fa5fee8b2d2106fa48cde5f4b022024769e3f09973e992d8761',
    'cmd/pebble-format-v1/multistep/batch.go': 'af0b4d74d0f4cf36d16cdef457e7de8725aba2690bf9556de7425c00d9c98f24',
    'cmd/pebble-format-v1/multistep/batch_test.go': '28d675389e45d7ecd563757c7cb6f936e5f830c17e233a7fb0feb2d070319fdd',
    'cmd/pebble-format-v1/multistep/budget.go': 'cc0a93b168d50a53b81fba7c5c21f62350cda999f8c0124099b4a7eadbe7cd40',
    'cmd/pebble-format-v1/multistep/budget_test.go': 'd4ab919c75f3e3f2c5f6e985398824136aaa0404ce5353dc2691f6a2a13808d1',
    'cmd/pebble-format-v1/multistep/journal.go': 'a8e6e4fbab2f7f85ad37ca9dc09d815b7d6ce087ea509ff5564a1e44559ed988',
    'cmd/pebble-format-v1/multistep/main.go': 'd74e13eaf7ccca6a82637c89811e7e7de3716f8a88f6ce3d8daf722b7f25d57c',
    'cmd/pebble-format-v1/multistep/state.go': 'b79da5167a3b826cbb6711a44c53fc338e3f0e475cfe914e8e0585c3e4113003',
    'cmd/pebble-format-v1/multistep/unit.go': '2e8f193a7795d4fab02e2ff38f209973e469fcad9f61510d5e8f1f501103aec4',
    'cmd/pebble-format-v1/patches/demo_single_rewrite.go': 'd97e293d27f65915fe6f2f64af5e259813873a6c11b496ced1df1c10f35b1396',
    'docs/evidence/rhea-batch2-000013-certificate-20261107.json': '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774',
    'scripts/rhea_batch2_health.py': '2781718c06389a0753cc23b6ff39d97bac388f492399dbb1bb637d57dbf4db1e',
    'scripts/rhea_batch2_mount_lifecycle.py': '05cd168d15d6d686e989e5b882920e1ac69d0efd92461b8adbf9f6aed5c39726',
    'scripts/rhea_batch2_one_step.py': '8675a466e731c1baae952e77eb622a03de1259738de4f962b92c503dade12e12',
    'scripts/rhea_batch2_policy_transition.py': 'ce38f0b38da8f7824af42685cb57b17f89f75c64a30d5cf931cfd115dca19723',
    'scripts/run_rhea_full_clone_steps_batch2.py': 'b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828',
    'scripts/verify_rhea_full_clone.py': 'e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849',
    'scripts/verify_rhea_full_clone_bounded.py': '43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796',
    'scripts/verify_rhea_multi_sst_candidate.py': 'ae3f5e64d113de07563c073f5a649ed7b53b40fbd008afa2db04c1fb29f2d3b1',
}
verifier = load_verifier()

if __name__ == '__main__':
    raise SystemExit(main())
