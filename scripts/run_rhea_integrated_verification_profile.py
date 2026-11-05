#!/usr/bin/env python3
"""Fixed read-only full-verifier comparison on certified generation nine.

Run the installed serial verifier, the bounded candidate, and the installed
serial verifier again. Every pass enumerates the live prefix and performs its
own complete GET/HEAD/payload proof. The existing lock, health guard and retained
inputs remain authoritative. No writer, publication, reopen or adoption occurs.
An external supervisor owns the hard process deadline and always reaps its child.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import threading
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'integrated-verification-profile-20261105'
INSTALL = OPS / 'compare.py'
OLD_OPS = TRUST / 'verification-profile-20261105'
HEALTH = OLD_OPS / 'health.py'
HEALTH_SHA = '617108d7b87b9879c622fcf22bc4ddf47ae258f680625cd4119661338c47a3f8'
REPLAY = OLD_OPS / 'replay.py'
REPLAY_SHA = '6660de99fce5982bfcb66975b0e3869b891825a5d07942ea4a29bf56a2e125a1'
CANDIDATE = OPS / 'verify_rhea_full_clone_bounded.py'
CANDIDATE_SHA = '43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796'
PROFILER = OPS / 'profile_rhea_full_clone_verification.py'
PROFILER_SHA = 'e0fd6cbfc1e6a44830a550cc4993fd486a1d23df29c4d127879c16dc2a84cccd'
SCANNER = OPS / 'enumerate_rhea_versions.py'
SCANNER_SHA = '512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359'
DECODER = OPS / 'verify_rhea_lab_format3.py'
DECODER_SHA = 'edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b'
MAX_PAGES = 512
MAX_ROWS = 500_000
SOFT_SECONDS = 780
MAX_ADDRESS_BYTES = 2 * 1024**3
LIST_PREFIX = 'rhea/'
SDK_VERSION = '1.34.46'
SDK_HANDLERS_SHA = '3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2'
PASS_ORDER = ('serial_before', 'bounded_candidate', 'serial_after')


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
    """Signals latch cancellation; they never unwind an SDK call or executor."""
    def __init__(self):
        self.latched = False

    def set(self):
        self.latched = True

    def is_set(self):
        return self.latched


def cancelled(stop):
    require(not stop.is_set(), 'read-only verification cancelled or expired')


class GuardedPaginator:
    """Bound the old SDK walk without replacing its rows or cursor handling."""
    def __init__(self, owner, paginator):
        self.owner, self.paginator, self.used = owner, paginator, False

    def paginate(self, **kwargs):
        require(kwargs == {'Bucket': self.owner.bucket, 'Prefix': LIST_PREFIX}
                and not self.used, 'paginator scope or reuse differs')
        self.used = True
        cancelled(self.owner.stop)
        pages = iter(self.paginator.paginate(**kwargs))
        terminal = False
        while True:
            cancelled(self.owner.stop)
            if not terminal:
                self.owner.reserve()
            try:
                page = next(pages)
            except StopIteration:
                require(terminal, 'SDK enumeration ended without terminal page')
                self.owner.serial_exhausted = True
                return
            cancelled(self.owner.stop)
            require(not terminal and type(page) is dict and type(page.get('IsTruncated')) is bool,
                    'invalid SDK enumeration termination')
            require(page.get('Name') == self.owner.bucket and page.get('Prefix') == LIST_PREFIX
                    and not page.get('CommonPrefixes') and not page.get('Delimiter'), 'SDK enumeration scope differs')
            self.owner.receive(page)
            terminal = not page['IsTruncated']
            yield page


class GuardedClient:
    """Only fixed-prefix reads; all listing paths share explicit request bounds."""
    def __init__(self, s3, bucket, stop):
        self.s3, self.bucket, self.stop = s3, bucket, stop
        self.lock = threading.Lock()
        self.requests, self.rows = 0, 0
        self.paginator_created = False
        self.serial_exhausted = False

    def reserve(self):
        with self.lock:
            cancelled(self.stop)
            require(self.requests < MAX_PAGES, 'listing request budget exceeded')
            self.requests += 1

    def receive(self, page):
        require(type(page) is dict and all(type(page.get(name, [])) is list
                for name in ('Versions', 'DeleteMarkers')), 'listing record arrays differ')
        count = sum(len(page.get(name, [])) for name in ('Versions', 'DeleteMarkers'))
        with self.lock:
            self.rows += count
            require(self.rows <= MAX_ROWS, 'received listing row budget exceeded')

    def get_paginator(self, name):
        cancelled(self.stop)
        with self.lock:
            require(name == 'list_object_versions' and not self.paginator_created
                    and self.requests == 0, 'unsupported or repeated listing paginator')
            self.paginator_created = True
        return GuardedPaginator(self, self.s3.get_paginator(name))

    def list_object_versions(self, **kwargs):
        require(not self.paginator_created and kwargs.get('Bucket') == self.bucket
                and kwargs.get('Prefix') == LIST_PREFIX and kwargs.get('MaxKeys') == 1000
                and set(kwargs) <= {'Bucket', 'Prefix', 'MaxKeys', 'KeyMarker', 'VersionIdMarker'},
                'direct listing scope differs')
        if 'KeyMarker' in kwargs:
            require(type(kwargs['KeyMarker']) is str and kwargs['KeyMarker'].startswith(LIST_PREFIX),
                    'listing key marker outside prefix')
        if 'VersionIdMarker' in kwargs:
            require('KeyMarker' in kwargs and type(kwargs['VersionIdMarker']) is str
                    and kwargs['VersionIdMarker'], 'invalid listing version marker')
        self.reserve()
        page = self.s3.list_object_versions(**kwargs)
        cancelled(self.stop)
        self.receive(page)
        return page

    def _read(self, method, kwargs):
        cancelled(self.stop)
        require(kwargs.get('Bucket') == self.bucket and type(kwargs.get('Key')) is str
                and kwargs['Key'].startswith(LIST_PREFIX)
                and set(kwargs) <= {'Bucket', 'Key', 'VersionId'}, 'object read outside fixed scope')
        if 'VersionId' in kwargs:
            require(type(kwargs['VersionId']) is str and kwargs['VersionId'], 'invalid read version identifier')
        # Once GET returns a body, the verifier owns its finally-close. Do not
        # raise on cancellation between that return and transfer of ownership.
        return getattr(self.s3, method)(**kwargs)

    def get_object(self, **kwargs):
        return self._read('get_object', kwargs)

    def head_object(self, **kwargs):
        return self._read('head_object', kwargs)

    def audit(self):
        with self.lock:
            return {'logical_listing_requests_reserved': self.requests, 'received_rows': self.rows,
                    'sdk_paginator_created': self.paginator_created, 'sdk_paginator_exhausted': self.serial_exhausted,
                    'max_pages': MAX_PAGES, 'max_received_rows': MAX_ROWS}

    def __getattr__(self, name):
        raise RuntimeError('operation outside fixed read-only verification interface')


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
    module = types.ModuleType('rhea_integrated_verification_health')
    module.__file__ = str(HEALTH)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(HEALTH), 'exec'), module.__dict__)
    return module


def write_new(ctx, name, value):
    c, w, rt = (ctx[key] for key in ('c', 'w', 'rt'))
    path = OPS / name
    require(path.parent == OPS and path.name == name, 'receipt outside fixed namespace')
    w.secure_path(path, leaf_mode=0o600, missing=True)
    raw = c.canonical(value)
    require(len(raw) <= c.MAX_JSON, 'receipt exceeds bound')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    rt._sync_dir(OPS)
    return sha(raw)


def validate_pass(metrics, enumeration, audit, *, candidate):
    require(metrics.get('verifier_returned') is True and metrics.get('denied_operations') == 0,
            'verifier did not complete within read-only interface')
    require(metrics['functions']['_collect_latest']['calls'] == 1
            and all(row['failed_calls'] == 0 for row in metrics['functions'].values()),
            'verification proof function failed or enumeration repeated')
    require(audit['max_pages'] == MAX_PAGES and audit['max_received_rows'] == MAX_ROWS
            and 0 < audit['logical_listing_requests_reserved'] <= MAX_PAGES
            and 0 < audit['received_rows'] <= MAX_ROWS, 'listing guard bounds differ')
    for method, count in (('get_object', 10), ('head_object', 14)):
        stats = metrics['s3'][method]
        require(stats['calls'] == count and stats['failed_calls'] == 0, 'live verification read counts differ')
    body = metrics['body']
    require(body['bytes_returned'] == 114_660_926 and body['opened'] == body['closed'] == body['close_calls'] == 10
            and body['read_failures'] == body['close_failures'] == 0, 'live verification payload proof differs')
    serial = metrics['s3']['list_object_versions']
    direct = metrics['s3']['list_object_versions_direct']
    require(direct['in_flight'] == 0 and 0 <= direct['max_in_flight'] <= 4,
            'listing worker calls did not drain or exceeded concurrency')
    if candidate:
        require(serial['paginator_creations'] == serial['paginations'] == serial['pages'] == 0
                and not audit['sdk_paginator_created'] and not audit['sdk_paginator_exhausted'],
                'candidate unexpectedly used SDK paginator')
        require(enumeration['complete'] is True and enumeration['workers'] == enumeration['range_count'] == 4
                and enumeration['retained_versions'] == 93_763 and enumeration['retained_delete_markers'] == 54,
                'candidate did not complete exhaustive expected ranges')
        require(direct['max_in_flight'] >= 1 and enumeration['max_pages'] == MAX_PAGES
                and enumeration['max_rows'] == MAX_ROWS
                and enumeration['version_rows'] + enumeration['delete_marker_rows']
                    - enumeration['discarded_rows'] == 93_817,
                'candidate bounds or complete retained record count differ')
        ranges = enumeration['ranges']
        require([row['index'] for row in ranges] == [0, 1, 2, 3]
                and [row['termination'] for row in ranges] == ['upper-crossed'] * 3 + ['exhausted'],
                'candidate range completion differs')
        for key in ('requests', 'pages', 'version_rows', 'delete_marker_rows', 'retained_versions',
                    'retained_delete_markers', 'discarded_rows', 'responses_with_retry_metadata',
                    'reported_retry_attempts', 'api_wall_seconds'):
            require(enumeration[key] == sum(row[key] for row in ranges), 'candidate range totals differ')
        require(enumeration['max_reported_retry_attempts'] == max(row['max_reported_retry_attempts'] for row in ranges),
                'candidate range retry maximum differs')
        require(direct['failed_calls'] == 0 and direct['calls'] == direct['pages'] == enumeration['requests']
                == enumeration['pages'] == audit['logical_listing_requests_reserved'], 'direct listing call counts differ')
        require(direct['version_rows'] == enumeration['version_rows']
                and direct['delete_marker_rows'] == enumeration['delete_marker_rows']
                and audit['received_rows'] == direct['version_rows'] + direct['delete_marker_rows'],
                'direct listing received row counts differ')
        require(all(direct[key] == enumeration[key] for key in
                    ('responses_with_retry_metadata', 'reported_retry_attempts', 'max_reported_retry_attempts')),
                'candidate SDK retry measurements disagree')
    else:
        require(not enumeration and direct['calls'] == direct['pages'] == 0
                and direct['max_in_flight'] == 0
                and serial['paginator_creations'] == serial['paginations'] == serial['exhaustions'] == 1
                and serial['pages'] == audit['logical_listing_requests_reserved']
                and serial['failed_advances'] == serial['setup_failures'] == 0
                and audit['sdk_paginator_created'] and audit['sdk_paginator_exhausted'],
                'baseline did not exhaust exactly one SDK enumeration')
        require(serial['version_rows'] == 93_763 and serial['delete_marker_rows'] == 54
                and audit['received_rows'] == 93_817, 'baseline version inventory count differs')


def main():
    require(sys.argv[1:] == ['--compare-current'], 'explicit full read-only comparison required')
    started_unix, started_tick = time.time(), time.perf_counter()
    h = load_health()
    # Secure/hash-check both dependencies before the candidate can import them.
    scanner = h.exact_module(SCANNER, SCANNER_SHA, 'rhea_integrated_scanner_precheck')
    decoder = h.exact_module(DECODER, DECODER_SHA, 'rhea_integrated_decoder_precheck')
    candidate = h.exact_module(CANDIDATE, CANDIDATE_SHA, 'rhea_integrated_candidate')
    profiler = h.exact_module(PROFILER, PROFILER_SHA, 'rhea_integrated_profiler')
    replay = h.exact_module(REPLAY, REPLAY_SHA, 'rhea_integrated_equivalence')
    ctx = h.load()
    f, c, rt, w, old = (ctx[key] for key in ('f', 'c', 'rt', 'w', 'v'))
    require(candidate.BUCKET == old.BUCKET and candidate.PREFIX == old.PREFIX
            and candidate.LEDGER_SHA256 == old.LEDGER_SHA256, 'candidate verification scope differs')
    with rt.lock():
        w.secure_path(OPS, leaf_mode=0o700)
        for name in ('intent.json', 'host-before.json', 'host-after.json', 'completed.json', 'failure.json',
                     *(name + '-result.json' for name in PASS_ORDER)):
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
                and expected['closed_output_hashes_sha256'] == c.digest(created), 'retained proof inputs differ')
        snapshot_path = stage / 'snapshot'
        w.secure_path(snapshot_path, leaf_mode=0o700)
        require({p.name for p in snapshot_path.iterdir()} == set(expected['remote_metadata']), 'snapshot filenames differ')
        metadata = {}
        for name, pin in expected['remote_metadata'].items():
            raw = evidence('000009-snapshot-' + name, snapshot_path / name)
            require(len(raw) == pin['size'] and sha(raw) == pin['sha256'], 'snapshot metadata differs')
            metadata[name] = raw
        require(len(metadata) == 8 and sum(map(len, metadata.values())) == 31_560_396, 'snapshot totals differ')
        ledger_raw = reads.raw('immutable-baseline-ledger', w.LEDGER, expected=old.LEDGER_SHA256)
        require(ledger_raw == ctx['ledger_blob'] and len(ledger_raw) == 4_574_902, 'immutable ledger differs')
        ledger_tick = time.perf_counter()
        ledger = w.load_ledger(ledger_raw)
        ledger_seconds = time.perf_counter() - ledger_tick
        code = {'runner': sha(w.read_protected(INSTALL, mode=0o600)), 'scanner': SCANNER_SHA,
                'candidate_verifier': CANDIDATE_SHA, 'profiler': PROFILER_SHA, 'candidate_decoder': DECODER_SHA,
                'health': HEALTH_SHA, 'equivalence_runner': REPLAY_SHA, 'controller': f.CONTROLLER_SHA,
                'installed_verifier': f.VERIFIER_SHA, 'decoder': f.DECODER_SHA, 'wrapper': f.WRAPPER_SHA, 'go': f.GO_SHA}
        source_paths = ((INSTALL, code['runner']), (SCANNER, SCANNER_SHA), (CANDIDATE, CANDIDATE_SHA),
                        (PROFILER, PROFILER_SHA), (DECODER, DECODER_SHA), (HEALTH, HEALTH_SHA), (REPLAY, REPLAY_SHA))
        require(all(sha(w.read_protected(path, mode=0o600)) == digest for path, digest in source_paths),
                'probe source differs before comparison')
        intent = {'schema': 1, 'scope': 'read-only-generation-nine-integrated-verifier-comparison',
                  'started_unix': started_unix, 'generation': 9, 'rewrites': 5,
                  'source_parent_commit': 'cddd8043fc4b751500d91dec313cbbcc0f0fd10c',
                  'state_sha256': h.STATE_SHA, 'checkpoint_sha256': h.CERT_SHA,
                  'parent_checkpoint_sha256': c.digest(previous), 'pacing_bundle_sha256': h.BUNDLE_SHA,
                  'code_sha256': code, 'retained_inputs': reads.references, 'host_before_sha256': before_sha,
                  'pass_order': list(PASS_ORDER), 'mode': 'final', 'candidate_workers': 4,
                  'max_pages_per_pass': MAX_PAGES, 'max_received_rows_per_pass': MAX_ROWS,
                  'soft_deadline_seconds': SOFT_SECONDS, 'address_space_limit_bytes': MAX_ADDRESS_BYTES,
                  'database_writer_invoked': False, 'pebble_open_performed': False,
                  'checkpoint_replacement_permitted': False, 'production_verifier_changed': False}
        intent_sha = write_new(ctx, 'intent.json', intent)
        metrics, results, result_hashes, intervals, audits = {}, {}, {}, {}, {}
        enumeration = {}
        stop = Cancellation()
        phase = 'probe-resource-and-signal-setup'
        previous_alarm = previous_term = None
        try:
            previous_alarm = signal.signal(signal.SIGALRM, lambda signum, frame: stop.set())
            previous_term = signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
            resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_BYTES, MAX_ADDRESS_BYTES))
            signal.alarm(SOFT_SECONDS)
            phase = 'cloud-identity'
            cloud_tick = time.perf_counter()
            with rt.cloud() as s3:
                client_ready_tick = time.perf_counter()
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
                for label in PASS_ORDER:
                    cancelled(stop)
                    phase = label
                    is_candidate = label == 'bounded_candidate'
                    guarded = GuardedClient(s3, old.BUCKET, stop)
                    metrics[label] = {}
                    options = {'enumeration_workers': 4, 'enumeration_stop': stop,
                               'enumeration_metrics': enumeration} if is_candidate else {}
                    started = time.time()
                    result, _ = profiler.profile_verify_generation(candidate if is_candidate else old, guarded,
                        ledger, previous, writer, metadata, created, 'final', c.digest(previous),
                        metrics=metrics[label], **options)
                    finished = time.time()
                    cancelled(stop)
                    replay.equivalent(c, expected, result, started, finished)
                    audit = guarded.audit()
                    validate_pass(metrics[label], enumeration if is_candidate else {}, audit, candidate=is_candidate)
                    results[label], audits[label] = result, audit
                    intervals[label] = {'started_unix': started, 'finished_unix': finished}
                    result_hashes[label] = write_new(ctx, label + '-result.json', result)
                    reads.unchanged()
                    emit({'phase_completed': label, 'metrics': metrics[label],
                          'enumeration': enumeration if is_candidate else {}, 'guard': audit,
                          'semantic_projection_sha256': replay.PROJECTION_SHA})
                finished_passes_tick = time.perf_counter()
            # scan_versions always joins every worker before exiting this client.
            cloud_closed_tick = time.perf_counter()
            cancelled(stop)
            phase = 'postchecks'
            projections = [{key: value for key, value in results[label].items() if key != 'verified_unix'}
                           for label in PASS_ORDER]
            require(all(c.canonical(projection) == c.canonical(projections[0]) for projection in projections),
                    'complete verifier semantic results differ')
            after = h.observe(ctx, authenticated_rc=True)
            after_sha = write_new(ctx, 'host-after.json', after)
            require(all(before[key] == after[key] for key in
                        ('reader_process', 'production_service_process', 'production_rc_process')), 'host identities changed')
            reads.unchanged()
            require(all(sha(w.read_protected(path, mode=0o600)) == digest for path, digest in source_paths),
                    'probe source changed')
            cancelled(stop)
            completed = dict(intent, scope='read-only-generation-nine-integrated-verifier-measurement',
                completed_unix=time.time(), intent_sha256=intent_sha, sdk=sdk,
                exact_verifier_semantic_equivalence=True, semantic_projection_sha256=replay.PROJECTION_SHA,
                verifier_result_sha256=result_hashes, invocation_intervals=intervals,
                metrics=metrics, candidate_enumeration=enumeration, listing_guards=audits,
                host_before=before, host_after=after, host_after_sha256=after_sha,
                process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                timing_seconds={'ledger_decode': ledger_seconds, 'cloud_client_and_identity': client_ready_tick - cloud_tick,
                    'three_verifications_and_between_pass_checks': finished_passes_tick - client_ready_tick,
                    'cloud_client_close': cloud_closed_tick - finished_passes_tick,
                    'overall_through_postchecks': time.perf_counter() - started_tick},
                expected_live_reads_per_pass={'GET': 10, 'HEAD': 14, 'GET_body_bytes': 114_660_926,
                    'new_sst_body_bytes': 67_320_929, 'metadata_body_bytes': 47_339_997},
                checkpoint_replaced=False, installed_migration_toolchain_changed=False, production_preserved=True,
                limitations=['Single ordered serial/candidate/serial comparison; order, connection reuse and cache effects not isolated.',
                    'Every final pass uses fresh remote enumeration and GET/HEAD/payload reads; results are not atomic remote snapshots.',
                    'Live measurement is final mode only; prepublication mode is covered by controlled tests because current markers are published.',
                    'No controller deployment, marker publication, queue drain, fresh Pebble reopen, new rewrite or production cutover.'])
            receipt_sha = write_new(ctx, 'completed.json', completed)
        except BaseException as exc:
            write_new(ctx, 'failure.json', {'schema': 1, 'failed_unix': time.time(), 'phase': phase,
                'error_type': type(exc).__name__, 'intent_sha256': intent_sha, 'partial_metrics': metrics,
                'partial_enumeration': enumeration, 'cancellation_latched': stop.is_set(),
                'database_writer_invoked': False, 'checkpoint_replaced': False})
            raise
        finally:
            signal.alarm(0)
            if previous_alarm is not None:
                signal.signal(signal.SIGALRM, previous_alarm)
            if previous_term is not None:
                signal.signal(signal.SIGTERM, previous_term)
        emit({'completed': True, 'receipt_sha256': receipt_sha, 'semantic_projection_sha256': replay.PROJECTION_SHA,
              'wall_seconds': {name: metrics[name]['wall_seconds'] for name in PASS_ORDER},
              'result_sha256': result_hashes, 'host_preserved': True})


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Read-only integrated verification did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
