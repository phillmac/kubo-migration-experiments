#!/usr/bin/env python3
"""Fixed generation-nine bounded-verifier installation and acceptance adapter.

Only --apply and explicit --resume can install the three reviewed sources, their
new pins, and the two-field journal binding. The journal is the sole activation
commit. All original sources and pins remain immutable. A fresh final proof uses
the installed pure verifier under the original reader-active host lock. No
writer, writable-mount guard, marker publication, Go tool, or Pebble open runs.
The separately reviewed supervisor owns the hard deadline and child reaping.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import tempfile
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'bounded-adoption-20261106'
INSTALL = OPS / 'run.py'
STATE = TRUST / 'full-clone-steps/state.json'
PARENT_COMMIT = '8fa1c296bbe1e8c3687710ddcf1a72c36510b4cb'
DEPLOYMENT_SCOPE = 'fixed-generation-nine-bounded-verifier-deployment'
ACCEPTANCE_SCOPE = 'installed-bounded-verifier-generation-nine-acceptance'
PAYLOAD_NAMES = frozenset(('run.py', 'health.py', 'transaction.py', 'controller-candidate.py',
    'verifier-candidate.py', 'scanner-candidate.py', 'expected-state-before.json', 'expected-pins-before.json'))
TARGETS = {'controller': TRUST / 'run_rhea_full_clone_steps_bounded.py',
           'verifier': TRUST / 'verify_rhea_full_clone_bounded.py',
           'scanner': TRUST / 'enumerate_rhea_versions.py',
           'pins': TRUST / 'full-clone-bounded-step-pins.json'}
RECEIPTS = frozenset(('state-before.json', 'pins-before.json', 'intent.json', 'completed.json'))
FIXED_PAYLOAD_HASHES = {
    'controller-candidate.py': '56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a',
    'verifier-candidate.py': '43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796',
    'scanner-candidate.py': '512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359',
    'expected-state-before.json': '7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1',
    'expected-pins-before.json': '0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575',
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
SDK_VERSION = '1.34.46'
SDK_HANDLERS_SHA = '3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2'


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


def read_protected(path, *, missing=False):
    before = protected(path, missing=missing)
    if before is None:
        return None
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                'protected file changed before open')
        raw = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(info, key) == getattr(after, key) for key in fields)
                and len(raw) == info.st_size <= MAX_FILE, 'protected file changed or exceeds bound')
    final = protected(path)
    require(all(getattr(final, key) == getattr(after, key) for key in fields), 'protected file changed after read')
    return raw


def sync_dir(path):
    protected(path, mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def immutable_write(path, raw):
    """Create exclusively, or reseal an exact file after interrupted fsync."""
    require(type(raw) is bytes and len(raw) <= MAX_FILE, 'immutable write exceeds bound')
    prior = read_protected(path, missing=True)
    require(prior is None or prior == raw, 'immutable destination already differs')
    if prior is None:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    sync_dir(path.parent)
    require(read_protected(path) == raw, 'immutable write readback differs')
    return sha(raw)


def private_dir(path):
    info = protected(path, mode=0o700, missing=True)
    if info is None:
        os.mkdir(path, 0o700)
    protected(path, mode=0o700)
    sync_dir(path)
    sync_dir(path.parent)


def exact_module(path, digest, name):
    raw = read_protected(path)
    require(sha(raw) == digest, 'protected source digest differs')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def load_deployment():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root installation required')
    protected(OPS, mode=0o700)
    raw = read_protected(OPS / 'deployment.json')
    deployment = json_object(raw)
    require(set(deployment) == {'schema', 'scope', 'source_commit', 'parent_commit', 'payloads'}
            and type(deployment['schema']) is int and deployment['schema'] == 1
            and deployment['scope'] == DEPLOYMENT_SCOPE and deployment['parent_commit'] == PARENT_COMMIT
            and type(deployment['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', deployment['source_commit'])
            and deployment['source_commit'] != PARENT_COMMIT, 'deployment provenance differs')
    pins = deployment['payloads']
    require(type(pins) is dict and set(pins) == PAYLOAD_NAMES, 'deployment payload set differs')
    payloads = {}
    for name, pin in pins.items():
        require(type(pin) is dict and set(pin) == {'sha256', 'bytes'} and type(pin['sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) and type(pin['bytes']) is int
                and 0 < pin['bytes'] <= MAX_FILE, 'deployment payload pin differs')
        blob = read_protected(OPS / name)
        require(len(blob) == pin['bytes'] and sha(blob) == pin['sha256'], 'staged payload differs')
        if name in FIXED_PAYLOAD_HASHES:
            require(pin['sha256'] == FIXED_PAYLOAD_HASHES[name], 'reviewed immutable payload differs')
        payloads[name] = blob
    return raw, deployment, payloads


class Adapter:
    def __init__(self, health, ctx, deployment_raw, deployment, payloads):
        self.health, self.ctx = health, ctx
        self.deployment_raw, self.deployment, self.payloads = deployment_raw, deployment, payloads

    def lock(self):
        return self.ctx['rt'].lock()

    def now(self):
        return time.time()

    def unchanged(self):
        require(read_protected(OPS / 'deployment.json') == self.deployment_raw
                and all(read_protected(OPS / name) == raw for name, raw in self.payloads.items()),
                'deployment payload changed')

    def state_bytes(self):
        return read_protected(STATE, missing=True)

    def target_bytes(self, role):
        require(role in TARGETS, 'unknown fixed target role')
        return read_protected(TARGETS[role], missing=True)

    def receipt_bytes(self, name):
        require(name in RECEIPTS, 'unknown fixed receipt')
        return read_protected(OPS / name, missing=True)

    def write_new(self, name, raw):
        require(name in RECEIPTS and self.ctx['rt'].host.locked, 'unlocked or unknown receipt write')
        self.unchanged()
        return immutable_write(OPS / name, raw)

    def install_new(self, role, raw):
        require(role in TARGETS and self.ctx['rt'].host.locked, 'unlocked or unknown source install')
        self.unchanged()
        return immutable_write(TARGETS[role], raw)

    def replace_state(self, expected_raw, new_raw):
        require(self.ctx['rt'].host.locked, 'state activation requires the original host lock')
        self.unchanged()
        require(self.state_bytes() == expected_raw, 'state activation preimage differs')
        protected(STATE.parent, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix='.bounded-adoption-', dir=STATE.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(new_raw)
                stream.flush()
                os.fsync(stream.fileno())
            require(self.state_bytes() == expected_raw, 'state changed before activation')
            os.replace(temporary, STATE)
            sync_dir(STATE.parent)
            require(self.state_bytes() == new_raw, 'activated state readback differs')
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
                sync_dir(STATE.parent)

    def seal_state(self, expected_raw):
        """Reseal visible activation after interruption before directory fsync."""
        require(self.ctx['rt'].host.locked, 'state reseal requires the original host lock')
        self.unchanged()
        require(self.state_bytes() == expected_raw, 'state reseal endpoint differs')
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_dir(STATE.parent)
        require(self.state_bytes() == expected_raw, 'state changed during reseal')

    def observe(self, phase, intent_sha256=None):
        self.unchanged()
        if phase == 'after' and self.receipt_bytes('completed.json') is not None:
            result = self.health.check_completed(self.ctx)
            require(result['intent_sha256'] == intent_sha256, 'completed health intent differs')
            return result
        return self.health.observe(self.ctx, phase=phase, authenticated_rc=True, intent_sha256=intent_sha256)

    def _attempt(self):
        root = OPS / 'acceptance'
        private_dir(root)
        existing = []
        for path in root.iterdir():
            require(re.fullmatch(r'[0-9]{6}', path.name) and path.name != '000000', 'unknown acceptance directory')
            protected(path, mode=0o700)
            existing.append(int(path.name))
        attempt = max(existing, default=0) + 1
        require(attempt <= 999_999 and sorted(existing) == list(range(1, attempt)), 'acceptance sequence differs')
        path = root / f'{attempt:06d}'
        require(protected(path, mode=0o700, missing=True) is None, 'acceptance attempt already exists')
        private_dir(path)
        return attempt, path

    def verify(self, intent_sha256):
        require(self.ctx['rt'].host.locked, 'acceptance requires the original host lock')
        self.unchanged()
        h, ctx = self.health, self.ctx
        f, c, rt, w, old = (ctx[key] for key in ('f', 'c', 'rt', 'w', 'v'))
        before = self.observe('after', intent_sha256)
        new = exact_module(TARGETS['controller'], FIXED_PAYLOAD_HASHES['controller-candidate.py'],
                           'bounded_adoption_acceptance_controller')
        new_rt = new.Runtime()  # Only source/binding validation; never its host/profile/cloud.
        require(c.canonical(new_rt.load_state()) == self.state_bytes(), 'installed runtime state differs')
        candidate = new_rt.verifier
        require(Path(candidate.__file__) == TARGETS['verifier'] and candidate.BUCKET == old.BUCKET
                and candidate.PREFIX == old.PREFIX and candidate.LEDGER_SHA256 == old.LEDGER_SHA256,
                'installed candidate scope differs')
        modules = {role: exact_module(path, digest, 'bounded_adoption_' + role)
                   for role, (path, digest) in HELPERS.items()}
        comparison, profiler, replay = (modules[key] for key in ('comparison', 'profiler', 'equivalence'))
        require(replay.PROJECTION_SHA == h.PROJECTION_SHA, 'semantic proof reference differs')
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
        started_unix, started_tick = time.time(), time.perf_counter()
        ledger = w.load_ledger(ledger_raw)
        attempt, directory = self._attempt()

        def receipt(name, value):
            require(name in ('intent.json', 'result.json', 'metrics.json', 'completed.json', 'failure.json'),
                    'unknown acceptance receipt')
            return immutable_write(directory / name, c.canonical(value))

        intent = {'schema': 1, 'scope': ACCEPTANCE_SCOPE + '-intent', 'attempt': attempt,
            'started_unix': started_unix, 'adoption_intent_sha256': intent_sha256,
            'source_commit': self.deployment['source_commit'], 'state_sha256': sha(self.state_bytes()),
            'checkpoint_sha256': h.CERT_SHA, 'parent_checkpoint_sha256': c.digest(previous),
            'code_sha256': {role: digest for role, (path, digest) in HELPERS.items()},
            'installed_sources': {role: sha(self.target_bytes(role)) for role in TARGETS},
            'retained_inputs': reads.references, 'host_before': before, 'mode': 'final', 'workers': 4,
            'max_pages': 512, 'max_received_rows': 500_000, 'soft_deadline_seconds': SOFT_SECONDS,
            'address_space_limit_bytes': MAX_ADDRESS_BYTES, 'database_writer_invoked': False,
            'pebble_open_performed': False, 'checkpoint_replacement_permitted': False}
        acceptance_intent_sha = receipt('intent.json', intent)
        metrics, enumeration = {}, {}
        stop = comparison.Cancellation()
        phase = 'resource-and-signal-setup'
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
                guarded = comparison.GuardedClient(s3, old.BUCKET, stop)
                comparison.cancelled(stop)
                phase = 'installed-final-verification'
                started = time.time()
                result, unused = profiler.profile_verify_generation(candidate, guarded, ledger, previous, writer,
                    metadata, created, 'final', c.digest(previous), metrics=metrics,
                    enumeration_workers=4, enumeration_stop=stop, enumeration_metrics=enumeration)
                finished = time.time()
                comparison.cancelled(stop)
                replay.equivalent(c, expected, result, started, finished)
                audit = guarded.audit()
                comparison.validate_pass(metrics, enumeration, audit, candidate=True)
            # The bounded scanner has joined all workers before either SDK client closes.
            comparison.cancelled(stop)
            phase = 'postchecks'
            after = self.observe('after', intent_sha256)
            require(all(before[key] == after[key] for key in ('state_sha256', 'state', 'reader_process',
                'production_service_process', 'production_rc_process')), 'checkpoint or host identities changed')
            reads.unchanged()
            self.unchanged()
            require(all(sha(read_protected(path)) == digest for path, digest in HELPERS.values()),
                    'acceptance helper changed')
            comparison.cancelled(stop)
            result_sha = receipt('result.json', result)
            metrics_sha = receipt('metrics.json', {'schema': 1, 'scope': ACCEPTANCE_SCOPE + '-metrics',
                'attempt': attempt, 'adoption_intent_sha256': intent_sha256, 'metrics': metrics,
                'enumeration': enumeration, 'listing_guard': audit, 'sdk': sdk,
                'invocation': {'started_unix': started, 'finished_unix': finished},
                'process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
            completed = dict(intent, scope=ACCEPTANCE_SCOPE + '-completed', completed_unix=time.time(),
                intent_sha256=acceptance_intent_sha, result_sha256=result_sha, metrics_sha256=metrics_sha,
                verified=True, semantic_projection_sha256=replay.PROJECTION_SHA, host_after=after,
                wall_seconds=metrics['wall_seconds'], overall_seconds=time.perf_counter() - started_tick,
                checkpoint_replaced=False, workers_drained=True, sdk_clients_closed=True,
                database_writer_invoked=False, pebble_open_performed=False)
            completed_sha = receipt('completed.json', completed)
            return {'schema': 1, 'verified': True, 'attempt': attempt,
                'path': str(directory.relative_to(OPS)), 'checkpoint_sha256': h.CERT_SHA,
                'semantic_projection_sha256': replay.PROJECTION_SHA, 'result_sha256': result_sha,
                'metrics_sha256': metrics_sha, 'receipt_sha256': completed_sha}
        except BaseException as exc:
            receipt('failure.json', {'schema': 1, 'scope': ACCEPTANCE_SCOPE + '-failure', 'attempt': attempt,
                'failed_unix': time.time(), 'phase': phase, 'error_type': type(exc).__name__,
                'adoption_intent_sha256': intent_sha256, 'intent_sha256': acceptance_intent_sha,
                'partial_metrics': metrics, 'partial_enumeration': enumeration,
                'cancellation_latched': stop.is_set(), 'database_writer_invoked': False, 'pebble_open_performed': False})
            raise
        finally:
            signal.alarm(0)
            if previous_alarm is not None:
                signal.signal(signal.SIGALRM, previous_alarm)
            if previous_term is not None:
                signal.signal(signal.SIGTERM, previous_term)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in ('--check', '--apply', '--resume'),
            'explicit fixed adoption action required')
    action = sys.argv[1][2:]
    raw, deployment, payloads = load_deployment()
    pins = deployment['payloads']
    health = exact_module(OPS / 'health.py', pins['health.py']['sha256'], 'bounded_adoption_health')
    engine = exact_module(OPS / 'transaction.py', pins['transaction.py']['sha256'], 'bounded_adoption_transaction')
    ctx = health.load()
    provenance = {'schema': 1, 'source_commit': deployment['source_commit'], 'deployment_sha256': sha(raw),
        'recipe_sha256': pins['run.py']['sha256'], 'engine_sha256': pins['transaction.py']['sha256'],
        'health_sha256': pins['health.py']['sha256']}
    sources = {role: payloads[role + '-candidate.py'] for role in ('controller', 'verifier', 'scanner')}
    plan = engine.build_plan(payloads['expected-state-before.json'], payloads['expected-pins-before.json'], sources, provenance)
    adapter = Adapter(health, ctx, raw, deployment, payloads)
    result = engine.Transaction(adapter, plan).run(action)
    summary = {'completed': result.get('scope') == engine.COMPLETED_SCOPE or result.get('phase') == 'completed',
               'action': action, 'phase': result.get('phase', 'completed'), 'state_sha256': result['state_sha256']}
    if summary['completed']:
        summary.update(completion_sha256=sha(adapter.receipt_bytes('completed.json')), verification=result['verification'])
    try:
        print(json.dumps(summary), flush=True)
    except OSError:
        pass  # Completion is already durable; a diagnostic sink cannot undo it.


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Bounded adoption did not complete (' + type(exc).__name__ + '). Inspect retained evidence before an explicit resume.', file=sys.stderr)
        raise SystemExit(1) from None
