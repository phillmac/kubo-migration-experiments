#!/usr/bin/env python3
"""Fixed read-only serial/concurrent/serial listing comparison for generation 9.

The external launcher owns the hard process deadline.  This module never changes
the installed migration toolchain, opens Pebble, or replaces its checkpoint.
"""
from __future__ import annotations

import datetime
import gc
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'enumeration-profile-20261105'
INSTALL = OPS / 'compare.py'
OLD_OPS = TRUST / 'verification-profile-20261105'
HEALTH = OLD_OPS / 'health.py'
HEALTH_SHA = '617108d7b87b9879c622fcf22bc4ddf47ae258f680625cd4119661338c47a3f8'
PROFILER = OLD_OPS / 'profile_rhea_full_clone_verification.py'
PROFILER_SHA = '282643a0f8a209681c984d236ddc594978951faad25e0bb7b80be33f2975e741'
REPLAY = OLD_OPS / 'replay.py'
REPLAY_SHA = '6660de99fce5982bfcb66975b0e3869b891825a5d07942ea4a29bf56a2e125a1'
SCANNER = OPS / 'enumerate_rhea_versions.py'
SCANNER_SHA = '512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359'
MAX_PAGES = 512
MAX_ROWS = 500_000
SOFT_SECONDS = 660
MAX_ADDRESS_BYTES = 2 * 1024**3
LIST_PREFIX = 'rhea/'
SDK_VERSION = '1.34.46'
SDK_HANDLERS_SHA = '3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def emit(value):
    try:
        print(json.dumps(value), flush=True)
    except OSError:
        pass


class Cancellation:
    """A signal handler only latches this flag; it never unwinds SDK cleanup."""
    def __init__(self):
        self.latched = False

    def set(self):
        self.latched = True

    def is_set(self):
        return self.latched


def cancelled(stop):
    require(not stop.is_set(), 'read-only comparison cancelled or expired')


def typed(value):
    """Unambiguous representation, including every field of raw SDK records."""
    if value is None:
        return ['null']
    if type(value) is bool:
        return ['bool', value]
    if type(value) is int:
        return ['int', value]
    if type(value) is str:
        return ['str', value]
    if isinstance(value, datetime.datetime):
        require(value.tzinfo is not None and value.utcoffset() is not None, 'naive SDK datetime')
        return ['datetime', value.astimezone(datetime.timezone.utc).isoformat(timespec='microseconds')]
    if type(value) is list:
        return ['list', [typed(item) for item in value]]
    if type(value) is dict:
        require(all(type(key) is str for key in value), 'nonstring SDK metadata key')
        return ['dict', [[key, typed(value[key])] for key in sorted(value)]]
    raise RuntimeError('unsupported SDK metadata type')


def snapshot_digest(snapshot):
    require(type(snapshot) is dict and set(snapshot) == {'Versions', 'DeleteMarkers'}, 'snapshot shape differs')
    digest = hashlib.sha256(b'rhea-full-version-snapshot-typed-v1\n')
    for kind in ('Versions', 'DeleteMarkers'):
        require(type(snapshot[kind]) is dict, 'snapshot map differs')
        for identity in sorted(snapshot[kind]):
            row = snapshot[kind][identity]
            require(type(row) is dict and identity == (row.get('Key'), row.get('VersionId')), 'snapshot identity differs')
            raw = json.dumps([kind, typed(row)], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            digest.update(raw + b'\n')
    return digest.hexdigest()


def snapshot_counts(snapshot):
    return {'versions': len(snapshot['Versions']), 'delete_markers': len(snapshot['DeleteMarkers']),
            'latest_versions': sum(row.get('IsLatest') is True for row in snapshot['Versions'].values()),
            'latest_delete_markers': sum(row.get('IsLatest') is True for row in snapshot['DeleteMarkers'].values())}


def serial_snapshot(s3, *, bucket, prefix, stop, metrics):
    """Independent reference: exhaust the SDK paginator used by the old verifier."""
    cancelled(stop)
    start, cpu = time.perf_counter(), time.process_time()
    metrics.update({'pages': 0, 'rows_received': 0, 'version_rows': 0, 'delete_rows': 0,
                    'retry_metadata_present': 0, 'retry_metadata_missing': 0, 'sdk_retries': 0,
                    'max_sdk_retries': 0, 'exhausted': False, 'iterator_seconds': 0.0})
    snapshot = {'Versions': {}, 'DeleteMarkers': {}}
    seen = set()
    terminal = False
    pages = iter(s3.get_paginator('list_object_versions').paginate(Bucket=bucket, Prefix=prefix))
    try:
        while True:
            cancelled(stop)
            require(terminal or metrics['pages'] < MAX_PAGES, 'reference page budget exceeded')
            tick = time.perf_counter()
            try:
                page = next(pages)
            except StopIteration:
                require(terminal and metrics['pages'] > 0, 'SDK walk did not reach terminal page')
                metrics['exhausted'] = True
                break
            finally:
                metrics['iterator_seconds'] += time.perf_counter() - tick
            cancelled(stop)
            require(not terminal and type(page) is dict and type(page.get('IsTruncated')) is bool,
                    'invalid SDK paginator termination')
            require(metrics['pages'] < MAX_PAGES, 'reference page budget exceeded')
            metrics['pages'] += 1
            terminal = not page['IsTruncated']
            require(not page.get('CommonPrefixes') and not page.get('Delimiter'), 'reference unexpectedly grouped keys')
            require(page.get('Name') == bucket and page.get('Prefix') == prefix, 'reference scope changed')
            response = page.get('ResponseMetadata', {})
            retries = response.get('RetryAttempts')
            if type(retries) is int and retries >= 0:
                metrics['retry_metadata_present'] += 1
                metrics['sdk_retries'] += retries
                metrics['max_sdk_retries'] = max(metrics['max_sdk_retries'], retries)
            else:
                metrics['retry_metadata_missing'] += 1
            for kind in ('Versions', 'DeleteMarkers'):
                rows = page.get(kind, [])
                require(type(rows) is list, 'reference rows are not a list')
                for row in rows:
                    require(type(row) is dict, 'reference row is not an object')
                    key, version = row.get('Key'), row.get('VersionId')
                    require(type(key) is str and key.startswith(prefix) and type(version) is str and version
                            and type(row.get('IsLatest')) is bool, 'invalid reference row identity')
                    identity = (key, version)
                    require(identity not in seen, 'duplicate reference object version')
                    seen.add(identity)
                    metrics['rows_received'] += 1
                    require(metrics['rows_received'] <= MAX_ROWS, 'reference row budget exceeded')
                    metrics['version_rows' if kind == 'Versions' else 'delete_rows'] += 1
                    snapshot[kind][identity] = dict(row)
        cancelled(stop)
        return snapshot
    finally:
        metrics['wall_seconds'] = time.perf_counter() - start
        metrics['process_cpu_seconds'] = time.process_time() - cpu


class SnapshotPaginator:
    def __init__(self, snapshot, bucket, prefix):
        self.snapshot, self.bucket, self.prefix = snapshot, bucket, prefix
        self.used = False

    def paginate(self, **kwargs):
        require(kwargs == {'Bucket': self.bucket, 'Prefix': self.prefix} and not self.used,
                'snapshot paginator scope or reuse differs')
        self.used = True
        # This is explicitly synthetic in the receipt. No SDK ResponseMetadata
        # is fabricated or recycled from the earlier remote listing calls.
        yield {'Versions': list(self.snapshot['Versions'].values()),
               'DeleteMarkers': list(self.snapshot['DeleteMarkers'].values())}


class SnapshotClient:
    """Read-only replay adapter. Only GET/HEAD access the remote service."""
    def __init__(self, s3, snapshot, bucket, prefix, stop=None):
        self._s3, self._snapshot, self._bucket, self._prefix = s3, snapshot, bucket, prefix
        self._stop = stop if stop is not None else Cancellation()
        self.paginator_created = False

    def get_paginator(self, name):
        require(name == 'list_object_versions' and not self.paginator_created, 'unsupported or repeated snapshot listing')
        self.paginator_created = True
        return SnapshotPaginator(self._snapshot, self._bucket, self._prefix)

    def _read(self, method, kwargs):
        cancelled(self._stop)
        require(kwargs.get('Bucket') == self._bucket and type(kwargs.get('Key')) is str
                and kwargs['Key'].startswith(self._prefix), 'remote replay read outside fixed scope')
        require(set(kwargs) <= {'Bucket', 'Key', 'VersionId'}, 'unexpected replay read parameters')
        if 'VersionId' in kwargs:
            require(type(kwargs['VersionId']) is str and kwargs['VersionId'], 'invalid replay version identifier')
        return getattr(self._s3, method)(**kwargs)

    def get_object(self, **kwargs):
        return self._read('get_object', kwargs)

    def head_object(self, **kwargs):
        return self._read('head_object', kwargs)

    def __getattr__(self, name):
        raise RuntimeError('operation outside read-only snapshot interface')


def load_health():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root installation required')
    for path in (*reversed(HEALTH.parents), HEALTH):
        info = path.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'health path is not protected')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            'health source type differs')
    with os.fdopen(os.open(HEALTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        raw = stream.read(16 * 1024**2 + 1)
    require(len(raw) <= 16 * 1024**2 and sha(raw) == HEALTH_SHA, 'health source digest differs')
    module = types.ModuleType('rhea_enumeration_health')
    module.__file__ = str(HEALTH)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(HEALTH), 'exec'), module.__dict__)
    return module


def write_new(ctx, name, value):
    c, w, rt = (ctx[key] for key in ('c', 'w', 'rt'))
    path = OPS / name
    require(path.parent == OPS and path.name == name, 'receipt path outside fixed namespace')
    w.secure_path(path, leaf_mode=0o600, missing=True)
    raw = c.canonical(value)
    require(len(raw) <= c.MAX_JSON, 'receipt exceeds bound')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    rt._sync_dir(OPS)
    return sha(raw)


def main():
    require(sys.argv[1:] == ['--compare-current'], 'explicit read-only comparison required')
    started_unix, started_tick = time.time(), time.perf_counter()
    h = load_health()
    scanner = h.exact_module(SCANNER, SCANNER_SHA, 'rhea_exhaustive_enumerator')
    profiler = h.exact_module(PROFILER, PROFILER_SHA, 'rhea_enumeration_verifier_profiler')
    replay = h.exact_module(REPLAY, REPLAY_SHA, 'rhea_enumeration_original_replay')
    ctx = h.load()
    f, c, rt, w, v = (ctx[key] for key in ('f', 'c', 'rt', 'w', 'v'))
    with rt.lock():
        w.secure_path(OPS, leaf_mode=0o700)
        w.secure_path(INSTALL, leaf_mode=0o600)
        for name in ('intent.json', 'host-before.json', 'host-after.json', 'verifier-result.json',
                     'completed.json', 'failure.json'):
            path = OPS / name
            w.secure_path(path, leaf_mode=0o600, missing=True)
            require(not path.exists() and not path.is_symlink(), 'comparison evidence already exists')
        before = h.observe(ctx, authenticated_rc=True)
        before_sha = write_new(ctx, 'host-before.json', before)
        reads = f.ReadSet(c, w)
        refs = ctx['bundle']['evidence']

        def evidence(role, path):
            pin = refs[role]
            require(pin['path'] == str(path.relative_to(TRUST)), 'retained evidence path differs')
            raw = reads.raw(role, path, expected=pin['sha256'])
            require(len(raw) == pin['bytes'], 'retained evidence size differs')
            return raw

        previous = c.json_object(evidence('000008-step-certificate', c.STATE_ROOT / 'checkpoints/000008-step.json'))
        expected = c.json_object(evidence('000009-step-certificate', c.STATE_ROOT / 'checkpoints/000009-step.json'))
        stage = c.STATE_ROOT / 'stages/000009-step'
        writer = c.json_object(evidence('000009-step-writer', stage / 'writer.json'))
        created = c.json_object(evidence('000009-step-created-sst-hashes', stage / 'created-sst-hashes.json'))
        require(expected == ctx['cert'] and expected['previous_checkpoint_sha256'] == c.digest(previous)
                and expected['go_report_sha256'] == c.digest(writer)
                and expected['closed_output_hashes_sha256'] == c.digest(created), 'retained replay bindings differ')
        snapshot_path = stage / 'snapshot'
        w.secure_path(snapshot_path, leaf_mode=0o700)
        require({p.name for p in snapshot_path.iterdir()} == set(expected['remote_metadata']), 'snapshot filenames differ')
        metadata = {}
        for name, pin in expected['remote_metadata'].items():
            raw = evidence('000009-snapshot-' + name, snapshot_path / name)
            require(len(raw) == pin['size'] and sha(raw) == pin['sha256'], 'snapshot metadata differs')
            metadata[name] = raw
        ledger_raw = reads.raw('immutable-baseline-ledger', w.LEDGER, expected=v.LEDGER_SHA256)
        require(ledger_raw == ctx['ledger_blob'], 'immutable ledger differs')
        ledger = w.load_ledger(ledger_raw)
        keys = sorted((key for key in ledger if key.endswith('.sst')), key=lambda key: key.encode('utf-8'))
        require(len(keys) == 93_697, 'baseline SST boundary population differs')
        boundaries = tuple(keys[len(keys) * part // 4] for part in (1, 2, 3))
        require(all(key.startswith(LIST_PREFIX) for key in boundaries), 'boundary outside fixed prefix')
        code = {'runner': sha(w.read_protected(INSTALL, mode=0o600)), 'scanner': SCANNER_SHA,
                'health': HEALTH_SHA, 'profiler': PROFILER_SHA, 'equivalence_runner': REPLAY_SHA,
                'controller': f.CONTROLLER_SHA, 'verifier': f.VERIFIER_SHA,
                'decoder': f.DECODER_SHA, 'wrapper': f.WRAPPER_SHA, 'go': f.GO_SHA}
        intent = {'schema': 1, 'scope': 'read-only-generation-nine-version-enumeration-comparison',
                  'started_unix': started_unix, 'generation': 9, 'rewrites': 5,
                  'source_commit': 'c389aa103a28cd5144db9e3afd53353528d47146',
                  'state_sha256': h.STATE_SHA, 'checkpoint_sha256': h.CERT_SHA,
                  'code_sha256': code, 'retained_inputs': reads.references, 'host_before_sha256': before_sha,
                  'scan_order': ['sdk-serial-before', 'four-disjoint-ranges-concurrent', 'sdk-serial-after'],
                  'boundary_keys': boundaries, 'interval_convention': '(lower,upper]; first and last unbounded',
                  'workers': 4, 'max_pages_per_scan': MAX_PAGES, 'max_received_rows_per_scan': MAX_ROWS,
                  'soft_deadline_seconds': SOFT_SECONDS, 'address_space_limit_bytes': MAX_ADDRESS_BYTES,
                  'database_writer_invoked': False, 'pebble_open_performed': False,
                  'checkpoint_replacement_permitted': False, 'production_verifier_changed': False}
        intent_sha = write_new(ctx, 'intent.json', intent)
        metrics = {'serial_before': {}, 'parallel': {}, 'serial_after': {}, 'verifier_replay': {}}
        stop = Cancellation()
        phase = 'probe-resource-and-signal-setup'
        previous_alarm = previous_term = None
        try:
            previous_alarm = signal.signal(signal.SIGALRM, lambda signum, frame: stop.set())
            previous_term = signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
            resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_BYTES, MAX_ADDRESS_BYTES))
            signal.alarm(SOFT_SECONDS)
            phase = 'cloud-identity'
            with rt.cloud() as s3:
                import boto3
                import botocore
                import botocore.handlers
                config = s3.meta.config
                sdk = {'boto3': boto3.__version__, 'botocore': botocore.__version__,
                       'botocore_handlers_sha256': sha(Path(botocore.handlers.__file__).read_bytes()),
                       'connect_timeout': config.connect_timeout, 'read_timeout': config.read_timeout,
                       'max_pool_connections': config.max_pool_connections, 'retries': dict(config.retries)}
                require(sdk['boto3'] == sdk['botocore'] == SDK_VERSION
                        and sdk['botocore_handlers_sha256'] == SDK_HANDLERS_SHA, 'SDK runtime source differs')
                require(config.connect_timeout == 10 and config.read_timeout == 30
                        and config.max_pool_connections >= 4 and config.retries.get('mode') == 'standard'
                        and config.retries.get('total_max_attempts') == 3, 'SDK timeout/retry contract differs')
                cancelled(stop)
                phase = 'sdk-serial-before'
                first = serial_snapshot(s3, bucket=v.BUCKET, prefix=LIST_PREFIX, stop=stop, metrics=metrics['serial_before'])
                first_digest = snapshot_digest(first)
                emit({'phase_completed': phase, 'metrics': metrics['serial_before']})
                phase = 'four-ranges-concurrent'
                candidate, parallel_metrics = scanner.scan_versions(s3, bucket=v.BUCKET, prefix=LIST_PREFIX,
                    boundaries=boundaries, workers=4, max_pages=MAX_PAGES, max_rows=MAX_ROWS, stop_event=stop)
                metrics['parallel'] = parallel_metrics
                cancelled(stop)
                require(candidate == first, 'parallel records differ from independent initial SDK walk')
                candidate_digest = snapshot_digest(candidate)
                require(candidate_digest == first_digest, 'parallel snapshot digest differs')
                emit({'phase_completed': phase, 'metrics': metrics['parallel']})
                del first
                gc.collect()
                phase = 'sdk-serial-after'
                last = serial_snapshot(s3, bucket=v.BUCKET, prefix=LIST_PREFIX, stop=stop, metrics=metrics['serial_after'])
                require(last == candidate, 'final SDK walk differs from parallel records')
                last_digest = snapshot_digest(last)
                require(last_digest == candidate_digest, 'final snapshot digest differs')
                counts = snapshot_counts(candidate)
                require(counts == {'versions': 93_763, 'delete_markers': 54,
                                   'latest_versions': 93_708, 'latest_delete_markers': 54}, 'generation-nine row counts differ')
                emit({'phase_completed': phase, 'metrics': metrics['serial_after']})
                del last
                gc.collect()
                cancelled(stop)
                phase = 'unchanged-verifier-over-candidate-snapshot'
                adapter = SnapshotClient(s3, candidate, v.BUCKET, LIST_PREFIX, stop)
                verify_start = time.time()
                result, verification_metrics = profiler.profile_verify_generation(v, adapter, ledger, previous,
                    writer, metadata, created, 'final', c.digest(previous), metrics=metrics['verifier_replay'])
                verify_finish = time.time()
                cancelled(stop)
                replay.equivalent(c, expected, result, verify_start, verify_finish)
                require(snapshot_digest(candidate) == candidate_digest, 'candidate records mutated during replay')
                require(verification_metrics['s3']['get_object']['calls'] == 10
                        and verification_metrics['s3']['head_object']['calls'] == 14
                        and verification_metrics['body']['bytes_returned'] == 114_660_926,
                        'unchanged verifier live-read counts differ')
            # Every worker has joined before cloud exit or host-lock release.
            cancelled(stop)
            phase = 'postchecks'
            after = h.observe(ctx, authenticated_rc=True)
            after_sha = write_new(ctx, 'host-after.json', after)
            require(all(before[key] == after[key] for key in
                        ('reader_process', 'production_service_process', 'production_rc_process')),
                    'host process identities changed')
            reads.unchanged()
            require(all(sha(w.read_protected(path, mode=0o600)) == digest for path, digest in
                        ((INSTALL, code['runner']), (SCANNER, SCANNER_SHA), (HEALTH, HEALTH_SHA),
                         (PROFILER, PROFILER_SHA), (REPLAY, REPLAY_SHA))),
                    'comparison source changed')
            result_sha = write_new(ctx, 'verifier-result.json', result)
            cancelled(stop)
            completed = dict(intent, scope='read-only-generation-nine-version-enumeration-measurement',
                completed_unix=time.time(), intent_sha256=intent_sha, sdk=sdk,
                snapshot_counts=counts, snapshot_digest_algorithm='typed-sdk-row-v1',
                snapshot_sha256={'serial_before': first_digest, 'parallel': candidate_digest, 'serial_after': last_digest},
                exact_raw_record_equality=True, exact_verifier_semantic_equivalence=True,
                semantic_projection_sha256=replay.PROJECTION_SHA, verifier_result_sha256=result_sha,
                verifier_listing_source='one synthetic in-memory page containing the previously captured parallel snapshot',
                verifier_live_reads={'GET': 10, 'HEAD': 14, 'GET_body_bytes': 114_660_926},
                metrics=metrics, host_before=before, host_after=after, host_after_sha256=after_sha,
                process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                elapsed_through_postchecks_seconds=time.perf_counter() - started_tick,
                checkpoint_replaced=False, installed_migration_toolchain_changed=False,
                limitations=['Single serial/concurrent/serial comparison on a frozen generation; order/cache effects not isolated.',
                             'No atomic remote snapshot guarantee; serial equality brackets the candidate observation.',
                             'Verifier replay uses captured candidate rows; it is not an additional fresh remote enumeration.',
                             'No controller deployment, write, fresh Pebble reopen, or production cutover.'])
            receipt_sha = write_new(ctx, 'completed.json', completed)
        except BaseException as exc:
            write_new(ctx, 'failure.json', {'schema': 1, 'failed_unix': time.time(), 'phase': phase,
                'error_type': type(exc).__name__, 'intent_sha256': intent_sha, 'partial_metrics': metrics,
                'cancellation_latched': stop.is_set(), 'database_writer_invoked': False, 'checkpoint_replaced': False})
            raise
        finally:
            signal.alarm(0)
            if previous_alarm is not None:
                signal.signal(signal.SIGALRM, previous_alarm)
            if previous_term is not None:
                signal.signal(signal.SIGTERM, previous_term)
        emit({'completed': True, 'receipt_sha256': receipt_sha, 'snapshot_sha256': candidate_digest,
              'counts': counts, 'metrics': metrics, 'host_preserved': True})


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Read-only enumeration comparison did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
