#!/usr/bin/env python3
"""One fresh read-only final proof of the unchanged post-reboot generation nine.

The caller supplies the exact protected identity receipt digest. This process
uses the original runtime's lock and cloud clients, the installed adopted pure
verifier, and immutable generation-eight/nine inputs. Only new proof receipts
are written. No writer, Pebble open, journal update, or automatic retry exists.
An external supervisor must enforce the hard deadline and reap this process;
cooperative cancellation does not interrupt an in-flight SDK request.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'post-reboot-20261106'
INSTALL = OPS / 'verify.py'
HEALTH = OPS / 'health.py'
HEALTH_SHA = '4ccc2010e92a7e5202ef76a6f104af887246fa1e828b480d6b3bfcbcb63cb36f'
DIRECTORY = OPS / 'verification'
STATE = TRUST / 'full-clone-steps/state.json'
STATE_SHA = '22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2'
CERT_SHA = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
PINS_SHA = '684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c'
PROJECTION_SHA = '0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57'
SCOPE = 'rhea-post-reboot-generation-nine-verification'
SOURCES = {
    'controller': (TRUST / 'run_rhea_full_clone_steps_bounded.py',
        '56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a'),
    'verifier': (TRUST / 'verify_rhea_full_clone_bounded.py',
        '43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796'),
    'scanner': (TRUST / 'enumerate_rhea_versions.py',
        '512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359'),
    'decoder': (TRUST / 'verify_rhea_lab_format3.py',
        'edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b'),
}
HELPERS = {
    'comparison': (TRUST / 'integrated-verification-profile-20261105/compare.py',
        '4437ac23d767a5164d42f1c8bb33caf21f7e35c10ab1853ce54f3ce104c4c913'),
    'profiler': (TRUST / 'integrated-verification-profile-20261105/profile_rhea_full_clone_verification.py',
        'e0fd6cbfc1e6a44830a550cc4993fd486a1d23df29c4d127879c16dc2a84cccd'),
    'equivalence': (TRUST / 'verification-profile-20261105/replay.py',
        '6660de99fce5982bfcb66975b0e3869b891825a5d07942ea4a29bf56a2e125a1'),
}
MAX_FILE = 16 * 1024**2
SOFT_SECONDS = 420
MAX_ADDRESS_BYTES = 2 * 1024**3
MAX_PAGES = 512
MAX_ROWS = 500_000
SDK_VERSION = '1.34.46'
SDK_HANDLERS_SHA = '3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2'
RECEIPTS = frozenset(('intent.json', 'result.json', 'metrics.json', 'completed.json', 'failure.json'))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def json_object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    require(type(result) is dict and canonical(result) == raw, 'canonical JSON object required')
    return result


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def protected(path, *, mode=0o600, missing=False):
    require(path.is_absolute(), 'absolute protected path required')
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            require(missing and part == path, 'protected ancestor is missing')
            return None
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'path ownership or protection differs')
        if part != path:
            require(stat.S_ISDIR(info.st_mode), 'protected ancestor is not a directory')
        else:
            require(stat.S_IMODE(info.st_mode) == mode, 'protected leaf mode differs')
            require(stat.S_ISDIR(info.st_mode) if mode == 0o700 else
                    stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'protected leaf type differs')
    return info


def read_protected(path):
    before = protected(path)
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(all(getattr(info, key) == getattr(before, key) for key in fields),
                'protected file changed before open')
        raw = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
        require(all(getattr(info, key) == getattr(after, key) for key in fields)
                and len(raw) == info.st_size <= MAX_FILE, 'protected file changed or exceeds bound')
    final = protected(path)
    require(all(getattr(final, key) == getattr(after, key) for key in fields), 'protected file changed after read')
    return raw


def exact_module(path, digest, name):
    raw = read_protected(path)
    require(sha(raw) == digest, 'protected source digest differs')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def source_pins(ctx):
    pins = {role: digest for role, (path, digest) in {**SOURCES, **HELPERS}.items()}
    for role, path in (('runner', INSTALL), ('health', HEALTH)):
        pin = ctx['identity']['protected_inputs'][str(path)]
        require(type(pin) is dict and set(pin) == {'sha256', 'bytes'}
                and type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256'])
                and type(pin['bytes']) is int and 0 < pin['bytes'] <= MAX_FILE, 'identity source pin differs')
        pins[role] = pin['sha256']
    require(pins['health'] == HEALTH_SHA, 'identity health source differs')
    return pins


def unchanged_sources(ctx, pins):
    paths = {role: path for role, (path, unused) in {**SOURCES, **HELPERS}.items()}
    paths.update(runner=INSTALL, health=HEALTH)
    for role, path in paths.items():
        raw = read_protected(path)
        require(sha(raw) == pins[role], 'proof source changed')
        if role in ('runner', 'health'):
            require(len(raw) == ctx['identity']['protected_inputs'][str(path)]['bytes'], 'identity source size differs')


def expected_references(ctx):
    root = ctx['c'].STATE_ROOT
    stage = root / 'stages/000009-step'
    paths = {
        '000008-step-certificate': root / 'checkpoints/000008-step.json',
        '000009-step-certificate': root / 'checkpoints/000009-step.json',
        '000009-step-writer': stage / 'writer.json',
        '000009-step-created-sst-hashes': stage / 'created-sst-hashes.json',
        **{'000009-snapshot-' + name: stage / 'snapshot' / name for name in ctx['cert']['remote_metadata']},
    }
    refs = {}
    for role, path in paths.items():
        pin = ctx['bundle']['evidence'][role]
        require({'path', 'sha256', 'bytes'} <= set(pin) <= {'path', 'sha256', 'bytes', 'canonical_sha256'}
                and pin['path'] == str(path.relative_to(TRUST)), 'retained evidence reference differs')
        refs[role] = {key: pin[key] for key in ('path', 'sha256', 'bytes')}
    refs['immutable-baseline-ledger'] = {'path': str(ctx['w'].LEDGER.relative_to(TRUST)),
        'sha256': ctx['v'].LEDGER_SHA256, 'bytes': 4_574_902}
    require(len(refs) == 13, 'retained evidence count differs')
    return refs


def load_inputs(ctx):
    f, c, w = (ctx[key] for key in ('f', 'c', 'w'))
    reads = f.ReadSet(c, w)
    refs = expected_references(ctx)
    data = {}
    for role, pin in refs.items():
        raw = reads.raw(role, TRUST / pin['path'], expected=pin['sha256'])
        require(len(raw) == pin['bytes'], 'retained evidence size differs')
        data[role] = raw
    previous = c.json_object(data['000008-step-certificate'])
    expected = c.json_object(data['000009-step-certificate'])
    writer = c.json_object(data['000009-step-writer'])
    created = c.json_object(data['000009-step-created-sst-hashes'])
    require(expected == ctx['cert'] and sha(data['000009-step-certificate']) == CERT_SHA
            and expected['previous_checkpoint_sha256'] == c.digest(previous)
            and expected['go_report_sha256'] == c.digest(writer)
            and expected['closed_output_hashes_sha256'] == c.digest(created), 'retained proof inputs differ')
    snapshot = c.STATE_ROOT / 'stages/000009-step/snapshot'
    w.secure_path(snapshot, leaf_mode=0o700)
    require({p.name for p in snapshot.iterdir()} == set(expected['remote_metadata']), 'snapshot filenames differ')
    metadata = {}
    for name, pin in expected['remote_metadata'].items():
        raw = data['000009-snapshot-' + name]
        require(len(raw) == pin['size'] and sha(raw) == pin['sha256'], 'closed snapshot differs')
        metadata[name] = raw
    require(len(metadata) == 8 and sum(map(len, metadata.values())) == 31_560_396, 'snapshot totals differ')
    ledger_blob = data['immutable-baseline-ledger']
    require(ledger_blob == ctx['ledger_blob'] and reads.references == refs, 'ledger or retained references differ')
    return {'previous': previous, 'expected': expected, 'writer': writer, 'created': created,
            'metadata': metadata, 'ledger_blob': ledger_blob, 'reads': reads}


def validate_observation(ctx, observation):
    identity = ctx['identity']
    exact = {'schema': 1, 'boot_id': identity['boot_id'], 'kernel': identity['kernel'],
        'identity_sha256': ctx['identity_sha256'], 'state_sha256': STATE_SHA, 'checkpoint_sha256': CERT_SHA,
        'pins_sha256': PINS_SHA, 'generation': 9, 'rewrites': 5, 'pending': None,
        'state': ctx['c'].checkpoint_state(ctx['cert']), 'reader_process': identity['reader']['process'],
        'production_service_process': identity['production']['production_process'],
        'production_rc_process': identity['production']['rc_server']['process'],
        'production_rc_checked': True, 'writer_mount_and_socket_absent': True,
        'reader_and_writer_caches_retained': True, 'protected_anchors_unchanged': True}
    require(type(observation) is dict and all(type(observation.get(k)) is type(value)
            and observation[k] == value for k, value in exact.items()), 'post-reboot health summary differs')
    require(finite(observation['observed_unix']) and observation['observed_unix'] >= identity['observed_unix'],
            'health observation timing differs')
    writer = observation['writer']
    require(all(writer.get(key) == value for key, value in
                {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                 'Result': 'success', 'ExecMainStatus': '0'}.items()), 'writer is not cleanly stopped')
    disk = observation['production_disk_cache']
    require(type(disk) is dict and type(disk.get('bytesUsed')) is int and disk['bytesUsed'] >= 0
            and all(type(disk.get(key)) is int and disk[key] == 0
                    for key in ('uploadsQueued', 'uploadsInProgress', 'erroredFiles'))
            and disk.get('outOfSpace') is False, 'authenticated production queue is not clean')


def intent_value(ctx, pins, before, started):
    return {'schema': 1, 'scope': SCOPE + '-intent', 'started_unix': started,
        'identity_sha256': ctx['identity_sha256'], 'boot_id': ctx['identity']['boot_id'],
        'state_sha256': STATE_SHA, 'checkpoint_sha256': CERT_SHA, 'pins_sha256': PINS_SHA,
        'generation': 9, 'rewrites': 5, 'pending': None, 'source_sha256': pins,
        'retained_inputs': expected_references(ctx), 'host_before': before, 'mode': 'final', 'workers': 4,
        'max_pages': MAX_PAGES, 'max_received_rows': MAX_ROWS, 'soft_deadline_seconds': SOFT_SECONDS,
        'address_space_limit_bytes': MAX_ADDRESS_BYTES, 'database_writer_invoked': False,
        'pebble_open_performed': False, 'journal_mutated': False, 'checkpoint_replaced': False}


def validate_sdk(sdk):
    require(type(sdk) is dict and set(sdk) == {'boto3', 'botocore', 'botocore_handlers_sha256',
            'connect_timeout', 'read_timeout', 'max_pool_connections', 'retries'}
            and sdk['boto3'] == sdk['botocore'] == SDK_VERSION
            and sdk['botocore_handlers_sha256'] == SDK_HANDLERS_SHA, 'SDK runtime source differs')
    require(sdk['connect_timeout'] == 10 and sdk['read_timeout'] == 30
            and type(sdk['max_pool_connections']) is int and sdk['max_pool_connections'] >= 4
            and sdk['retries'] == {'mode': 'standard', 'total_max_attempts': 3}, 'SDK timeout/retry contract differs')


def sdk_observation(s3):
    import boto3
    import botocore
    import botocore.handlers
    config = s3.meta.config
    result = {'boto3': boto3.__version__, 'botocore': botocore.__version__,
        'botocore_handlers_sha256': sha(Path(botocore.handlers.__file__).read_bytes()),
        'connect_timeout': config.connect_timeout, 'read_timeout': config.read_timeout,
        'max_pool_connections': config.max_pool_connections, 'retries': dict(config.retries)}
    validate_sdk(result)
    return result


def validate_retained(ctx, blobs, *, comparison, equivalence):
    """Validate four retained proof files without filesystem, host, or SDK calls."""
    require(set(blobs) == {'intent.json', 'result.json', 'metrics.json', 'completed.json'}
            and all(type(raw) is bytes and len(raw) <= MAX_FILE for raw in blobs.values()), 'proof receipt set differs')
    values = {name: json_object(raw) for name, raw in blobs.items()}
    intent, result, measured, done = (values[name + '.json'] for name in ('intent', 'result', 'metrics', 'completed'))
    pins = source_pins(ctx)
    before = intent['host_before']
    validate_observation(ctx, before)
    require(finite(intent['started_unix']) and ctx['identity']['observed_unix'] <= intent['started_unix']
            <= before['observed_unix'] and canonical(intent) == canonical(intent_value(ctx, pins, before, intent['started_unix'])),
            'proof intent differs')
    require(set(measured) == {'schema', 'scope', 'identity_sha256', 'metrics', 'enumeration', 'listing_guard',
            'sdk', 'invocation', 'process_peak_rss_kib'} and type(measured['schema']) is int
            and measured['schema'] == 1 and measured['scope'] == SCOPE + '-metrics'
            and measured['identity_sha256'] == ctx['identity_sha256'], 'metrics receipt binding differs')
    validate_sdk(measured['sdk'])
    invocation = measured['invocation']
    require(set(invocation) == {'started_unix', 'finished_unix'} and all(finite(v) for v in invocation.values())
            and before['observed_unix'] <= invocation['started_unix'] <= invocation['finished_unix'],
            'verifier invocation timing differs')
    require(equivalence.PROJECTION_SHA == PROJECTION_SHA, 'equivalence helper scope differs')
    equivalence.equivalent(ctx['c'], ctx['cert'], result, invocation['started_unix'], invocation['finished_unix'])
    comparison.validate_pass(measured['metrics'], measured['enumeration'], measured['listing_guard'], candidate=True)
    require(type(measured['process_peak_rss_kib']) is int and measured['process_peak_rss_kib'] > 0,
            'peak memory measurement differs')
    after = done['host_after']
    validate_observation(ctx, after)
    require(invocation['finished_unix'] <= after['observed_unix'] <= done['completed_unix']
            and finite(done['completed_unix']) and finite(done['overall_seconds']) and done['overall_seconds'] >= 0
            and finite(done['wall_seconds']) and 0 <= done['wall_seconds'] <= done['overall_seconds']
            and done['wall_seconds'] == measured['metrics']['wall_seconds'], 'proof completion timing differs')
    expected = dict(intent, scope=SCOPE + '-completed', verified=True,
        intent_sha256=sha(blobs['intent.json']), result_sha256=sha(blobs['result.json']),
        metrics_sha256=sha(blobs['metrics.json']), semantic_projection_sha256=PROJECTION_SHA,
        host_after=after, completed_unix=done['completed_unix'], wall_seconds=done['wall_seconds'],
        overall_seconds=done['overall_seconds'], workers_drained=True, sdk_clients_closed=True)
    require(canonical(done) == canonical(expected), 'proof completion or immutable receipt hashes differ')
    return done


@contextmanager
def deadline(stop):
    previous = {}
    try:
        for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda signum, frame: stop.set())
        resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_BYTES, MAX_ADDRESS_BYTES))
        signal.alarm(SOFT_SECONDS)
        yield
    finally:
        signal.alarm(0)
        for signum, handler in reversed(tuple(previous.items())):
            signal.signal(signum, handler)


def create_directory(ctx):
    require(ctx['rt'].host.locked, 'proof receipts require the original lifecycle lock')
    protected(OPS, mode=0o700)
    require(protected(DIRECTORY, mode=0o700, missing=True) is None, 'post-reboot proof was already attempted')
    os.mkdir(DIRECTORY, 0o700)
    ctx['rt']._sync_dir(DIRECTORY)
    ctx['rt']._sync_dir(OPS)


def write_new(ctx, name, raw):
    require(ctx['rt'].host.locked and name in RECEIPTS and type(raw) is bytes and len(raw) <= MAX_FILE,
            'unlocked, unknown, or oversized proof receipt')
    protected(DIRECTORY, mode=0o700)
    path = DIRECTORY / name
    require(protected(path, missing=True) is None, 'proof receipt already exists')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    ctx['rt']._sync_dir(DIRECTORY)
    require(read_protected(path) == raw, 'proof receipt readback differs')
    return sha(raw)


def verify_current(health, ctx):
    rt, c, old = (ctx[key] for key in ('rt', 'c', 'v'))
    require(rt.host.locked, 'post-reboot verification requires the original lifecycle lock')
    require(sha(ctx['identity_raw']) == ctx['identity_sha256'], 'identity receipt bytes differ')
    pins = source_pins(ctx)
    unchanged_sources(ctx, pins)
    # Validate protected dependencies before Runtime imports the candidate.
    installed = exact_module(*SOURCES['controller'], 'post_reboot_installed_controller')
    new_rt = installed.Runtime()  # Only source/binding validation; its host is never used.
    state_raw = read_protected(STATE)
    require(sha(state_raw) == STATE_SHA and c.canonical(new_rt.load_state()) == state_raw
            and c.json_object(state_raw) == ctx['adopted_state'], 'adopted state or installed runtime differs')
    candidate = new_rt.verifier
    require(Path(candidate.__file__) == SOURCES['verifier'][0] and candidate.BUCKET == old.BUCKET
            and candidate.PREFIX == old.PREFIX and candidate.LEDGER_SHA256 == old.LEDGER_SHA256,
            'installed verification scope differs')
    modules = {role: exact_module(path, digest, 'post_reboot_' + role)
               for role, (path, digest) in HELPERS.items()}
    comparison, profiler, replay = (modules[role] for role in ('comparison', 'profiler', 'equivalence'))
    stop = comparison.Cancellation()
    metrics, enumeration = {}, {}
    started_unix, tick = time.time(), time.perf_counter()
    phase, created_directory = 'before-health', False
    with deadline(stop):
        try:
            before = health.observe(ctx, authenticated_rc=True)
            validate_observation(ctx, before)
            comparison.cancelled(stop)
            phase = 'retained-inputs'
            inputs = load_inputs(ctx)
            ledger = ctx['w'].load_ledger(inputs['ledger_blob'])
            comparison.cancelled(stop)
            create_directory(ctx)
            created_directory = True
            intent = intent_value(ctx, pins, before, started_unix)
            intent_raw = canonical(intent)
            write_new(ctx, 'intent.json', intent_raw)
            phase = 'cloud-identity'
            with rt.cloud() as s3:
                sdk = sdk_observation(s3)
                comparison.cancelled(stop)
                guarded = comparison.GuardedClient(s3, old.BUCKET, stop)
                phase = 'installed-final-verification'
                started = time.time()
                result, unused = profiler.profile_verify_generation(candidate, guarded, ledger,
                    inputs['previous'], inputs['writer'], inputs['metadata'], inputs['created'], 'final',
                    c.digest(inputs['previous']), metrics=metrics, enumeration_workers=4,
                    enumeration_stop=stop, enumeration_metrics=enumeration)
                finished = time.time()
                comparison.cancelled(stop)
                replay.equivalent(c, inputs['expected'], result, started, finished)
                audit = guarded.audit()
                comparison.validate_pass(metrics, enumeration, audit, candidate=True)
            # scan_versions joins its workers before return or exception; cloud closes both clients.
            comparison.cancelled(stop)
            phase = 'after-health'
            after = health.observe(ctx, authenticated_rc=True)
            validate_observation(ctx, after)
            inputs['reads'].unchanged()
            unchanged_sources(ctx, pins)
            require(read_protected(STATE) == state_raw, 'journal changed during read-only proof')
            comparison.cancelled(stop)
            measured = {'schema': 1, 'scope': SCOPE + '-metrics', 'identity_sha256': ctx['identity_sha256'],
                'metrics': metrics, 'enumeration': enumeration, 'listing_guard': audit, 'sdk': sdk,
                'invocation': {'started_unix': started, 'finished_unix': finished},
                'process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
            result_raw, metrics_raw = canonical(result), canonical(measured)
            done = dict(intent, scope=SCOPE + '-completed', verified=True, completed_unix=time.time(),
                intent_sha256=sha(intent_raw), result_sha256=sha(result_raw), metrics_sha256=sha(metrics_raw),
                semantic_projection_sha256=PROJECTION_SHA, host_after=after,
                wall_seconds=metrics['wall_seconds'], overall_seconds=time.perf_counter() - tick,
                workers_drained=True, sdk_clients_closed=True)
            blobs = {'intent.json': intent_raw, 'result.json': result_raw,
                     'metrics.json': metrics_raw, 'completed.json': canonical(done)}
            validate_retained(ctx, blobs, comparison=comparison, equivalence=replay)
            comparison.cancelled(stop)
            phase = 'proof-receipts'
            write_new(ctx, 'result.json', result_raw)
            write_new(ctx, 'metrics.json', metrics_raw)
            comparison.cancelled(stop)
            completion_sha = write_new(ctx, 'completed.json', blobs['completed.json'])
            return {'verified': True, 'identity_sha256': ctx['identity_sha256'],
                'state_sha256': STATE_SHA, 'checkpoint_sha256': CERT_SHA,
                'completion_sha256': completion_sha, 'semantic_projection_sha256': PROJECTION_SHA}
        except BaseException as exc:
            if created_directory:
                failure = {'schema': 1, 'scope': SCOPE + '-failure', 'failed_unix': time.time(),
                    'identity_sha256': ctx['identity_sha256'], 'state_sha256': STATE_SHA,
                    'checkpoint_sha256': CERT_SHA, 'phase': phase, 'error_type': type(exc).__name__,
                    'partial_metrics': metrics, 'partial_enumeration': enumeration,
                    'cancellation_latched': stop.is_set(), 'database_writer_invoked': False,
                    'pebble_open_performed': False, 'journal_mutated': False}
                try:
                    write_new(ctx, 'failure.json', canonical(failure))
                except BaseException:
                    pass  # Preserve the original failure; the supervisor retains process evidence.
            raise


def main():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root installation required')
    require(len(sys.argv) == 3 and sys.argv[1] == '--identity-sha256'
            and re.fullmatch('[0-9a-f]{64}', sys.argv[2]), 'exact protected identity digest required')
    health = exact_module(HEALTH, HEALTH_SHA, 'rhea_post_reboot_health')
    ctx = health.load(manifest_sha256=sys.argv[2])
    with ctx['rt'].lock():
        result = verify_current(health, ctx)
    try:
        print(json.dumps(result), flush=True)
    except OSError:
        pass  # A diagnostic sink cannot undo durable proof receipts.


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        try:
            print('Post-reboot read-only proof did not complete (' + type(exc).__name__
                  + '). Inspect retained evidence before any further action.', file=sys.stderr)
        except OSError:
            pass
        raise SystemExit(1) from None
