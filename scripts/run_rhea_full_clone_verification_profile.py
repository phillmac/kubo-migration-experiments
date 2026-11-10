#!/usr/bin/env python3
"""One read-only timed replay of the unchanged generation-nine final verifier."""
from __future__ import annotations

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
OPS = TRUST / 'verification-profile-20261105'
INSTALL = OPS / 'replay.py'
HEALTH = OPS / 'health.py'
HEALTH_SHA = '617108d7b87b9879c622fcf22bc4ddf47ae258f680625cd4119661338c47a3f8'
PROFILE = OPS / 'profile_rhea_full_clone_verification.py'
PROFILE_SHA = '282643a0f8a209681c984d236ddc594978951faad25e0bb7b80be33f2975e741'
HEALTH_BEFORE_SHA = 'f28cd11a2a2765c1b2e4bc031a41219b4b85fc24b2e9ad039fdf281e589b1de5'
PROJECTION_SHA = '0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57'
MAX_SECONDS = 600


class ProbeDeadline(BaseException):
    """Unwind a timed read-only probe without entering SDK exception retries."""


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_health():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root replay installation required')
    for path in (*reversed(HEALTH.parents), HEALTH):
        info = path.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'health source not protected')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            'health source mode differs')
    with os.fdopen(os.open(HEALTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        raw = stream.read(16 * 1024**2 + 1)
    require(len(raw) <= 16 * 1024**2 and sha(raw) == HEALTH_SHA, 'health source digest differs')
    module = types.ModuleType('rhea_verification_replay_health')
    module.__file__ = str(HEALTH)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(HEALTH), 'exec'), module.__dict__)
    return module


def equivalent(c, expected, result, started, finished):
    require(result.get('pebble_reopen_verified') is False, 'replay must not claim a fresh Pebble reopen')
    require(type(result.get('verified_unix')) in (int, float)
            and started <= result['verified_unix'] <= finished, 'replay verification time outside invocation')
    require(expected.get('generation') == 9 and expected.get('pebble_reopen_verified') is True,
            'historical certificate lacks generation/reopen')
    historical = {k: value for k, value in expected.items()
                  if k not in ('generation', 'reopen', 'reopen_scope', 'verified_unix')}
    historical['pebble_reopen_verified'] = False
    actual = {k: value for k, value in result.items() if k != 'verified_unix'}
    require(c.canonical(actual) == c.canonical(historical), 'fresh final verification differs from certified generation9')
    require(c.digest(actual) == PROJECTION_SHA, 'semantic projection differs from independently reviewed digest')


def main():
    require(sys.argv[1:] == ['--verify-current'], 'explicit read-only verification required')
    started_unix, start_tick = time.time(), time.perf_counter()
    h = load_health()
    profiler = h.exact_module(PROFILE, PROFILE_SHA, 'rhea_read_only_verification_profiler')
    ctx = h.load()
    f, c, rt, w, v = (ctx[k] for k in ('f', 'c', 'rt', 'w', 'v'))
    with rt.lock():
        outputs = ('replay-intent.json', 'replay-verifier-result.json', 'replay-completed.json',
                   'replay-failure.json', 'replay-host-before.json', 'replay-host-after.json')
        for name in outputs:
            path = OPS / name
            w.secure_path(path, leaf_mode=0o600, missing=True)
            require(not path.exists() and not path.is_symlink(), 'read-only replay evidence already exists')
        reads = f.ReadSet(c, w)
        anchor = reads.json('fresh-health-before', OPS / 'health-before.json', expected=HEALTH_BEFORE_SHA)
        require(anchor['state_sha256'] == h.STATE_SHA and anchor['checkpoint_sha256'] == h.CERT_SHA
                and anchor['production_rc_checked'] is True and anchor['protected_anchors_unchanged'] is True,
                'fresh health anchor differs')
        before = h.observe(ctx, authenticated_rc=False)
        before_sha = h.write_new(ctx, OPS / 'replay-host-before.json', before)
        refs = ctx['bundle']['evidence']

        def evidence(role, path):
            pin = refs[role]
            require(pin['path'] == str(path.relative_to(TRUST)), 'retained evidence path differs')
            raw = reads.raw(role, path, expected=pin['sha256'])
            require(len(raw) == pin['bytes'], 'retained evidence length differs')
            return raw

        previous = c.json_object(evidence('000008-step-certificate', c.STATE_ROOT / 'checkpoints/000008-step.json'))
        expected = c.json_object(evidence('000009-step-certificate', c.STATE_ROOT / 'checkpoints/000009-step.json'))
        stage = c.STATE_ROOT / 'stages/000009-step'
        writer = c.json_object(evidence('000009-step-writer', stage / 'writer.json'))
        created = c.json_object(evidence('000009-step-created-sst-hashes', stage / 'created-sst-hashes.json'))
        require(expected == ctx['cert'] and expected['previous_checkpoint_sha256'] == c.digest(previous)
                and expected['go_report_sha256'] == c.digest(writer)
                and expected['closed_output_hashes_sha256'] == c.digest(created), 'retained replay input bindings differ')
        metadata = {}
        snapshot = stage / 'snapshot'
        w.secure_path(snapshot, leaf_mode=0o700)
        require({p.name for p in snapshot.iterdir()} == set(expected['remote_metadata']), 'retained snapshot names differ')
        for name, pin in expected['remote_metadata'].items():
            raw = evidence('000009-snapshot-' + name, snapshot / name)
            require(len(raw) == pin['size'] and sha(raw) == pin['sha256'], 'snapshot does not match certificate metadata')
            metadata[name] = raw
        require(len(metadata) == 8 and sum(map(len, metadata.values())) == 31_560_396,
                'generation-nine snapshot totals differ')
        ledger_raw = reads.raw('immutable-baseline-ledger', w.LEDGER, expected=v.LEDGER_SHA256)
        require(ledger_raw == ctx['ledger_blob'] and len(ledger_raw) == 4_574_902, 'immutable ledger differs')
        ledger_tick = time.perf_counter()
        ledger = w.load_ledger(ledger_raw)
        ledger_seconds = time.perf_counter() - ledger_tick
        code = {'health': HEALTH_SHA, 'profiler': PROFILE_SHA,
                'runner': sha(w.read_protected(INSTALL, mode=0o600)),
                'controller': f.CONTROLLER_SHA, 'verifier': f.VERIFIER_SHA, 'decoder': f.DECODER_SHA,
                'wrapper': f.WRAPPER_SHA, 'go': f.GO_SHA}
        require(sha(w.read_protected(PROFILE, mode=0o600)) == PROFILE_SHA, 'profiler source changed')
        intent = {'schema': 1, 'scope': 'read-only-generation-nine-final-verification-replay',
                  'started_unix': started_unix, 'generation': 9, 'rewrites': 5,
                  'state_sha256': h.STATE_SHA, 'checkpoint_sha256': h.CERT_SHA,
                  'parent_checkpoint_sha256': c.digest(previous), 'pacing_bundle_sha256': h.BUNDLE_SHA,
                  'expected_projection_sha256': PROJECTION_SHA, 'code_sha256': code,
                  'retained_inputs': reads.references, 'host_before_sha256': before_sha,
                  'deadline_seconds': MAX_SECONDS, 'database_writer_invoked': False,
                  'pebble_open_performed': False, 'checkpoint_replacement_permitted': False}
        intent_sha = h.write_new(ctx, OPS / 'replay-intent.json', intent)
        metrics = {}
        phase = 'cloud-identity-and-final-verification'
        try:
            def expired(signum, frame):
                raise ProbeDeadline('read-only verification deadline reached')

            previous_handler = signal.signal(signal.SIGALRM, expired)
            signal.alarm(MAX_SECONDS)
            cloud_tick = time.perf_counter()
            try:
                with rt.cloud() as s3:
                    client_ready_tick = time.perf_counter()
                    verify_started_unix = time.time()
                    result, metrics = profiler.profile_verify_generation(
                        v, s3, ledger, previous, writer, metadata, created, 'final', c.digest(previous), metrics=metrics)
                    verify_finished_unix = time.time()
                    verify_finished_tick = time.perf_counter()
                cloud_closed_tick = time.perf_counter()
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous_handler)
            phase = 'exact-semantic-equivalence'
            equivalent(c, expected, result, verify_started_unix, verify_finished_unix)
            require(metrics.get('schema') == 1 and metrics.get('verifier_returned') is True
                    and metrics.get('denied_operations') == 0, 'profiler completion counters differ')
            listing = metrics['s3']['list_object_versions']
            require(listing['paginations'] == listing['paginator_creations'] == listing['exhaustions'] == 1
                    and listing['pages'] > 0 and listing['failed_advances'] == listing['setup_failures'] == 0,
                    'profile did not complete exactly one version enumeration')
            require(metrics['s3']['get_object']['calls'] == 10 and metrics['s3']['head_object']['calls'] == 14
                    and metrics['s3']['get_object']['failed_calls'] == metrics['s3']['head_object']['failed_calls'] == 0,
                    'logical final-verifier request counts differ')
            require(metrics['body']['opened'] == metrics['body']['closed'] == 10
                    and metrics['body']['bytes_returned'] == 114_660_926
                    and metrics['body']['read_failures'] == metrics['body']['close_failures'] == 0,
                    'logical final-verifier payload counters differ')
            reads.unchanged()
            result_sha = h.write_new(ctx, OPS / 'replay-verifier-result.json', result)
            phase = 'post-replay-host-health'
            after = h.observe(ctx, authenticated_rc=True)
            after_sha = h.write_new(ctx, OPS / 'replay-host-after.json', after)
            require(before['reader_process'] == after['reader_process']
                    and before['production_service_process'] == after['production_service_process']
                    and before['production_rc_process'] == after['production_rc_process'], 'host identities changed during replay')
            reads.unchanged()
            require(sha(w.read_protected(PROFILE, mode=0o600)) == PROFILE_SHA
                    and sha(w.read_protected(HEALTH, mode=0o600)) == HEALTH_SHA
                    and sha(w.read_protected(INSTALL, mode=0o600)) == code['runner'], 'probe source changed')
            completed = {'schema': 1, 'scope': 'read-only-generation-nine-final-verification-profile',
                         'started_unix': started_unix, 'completed_unix': time.time(),
                         'unchanged_verifier_source_commit': '08a1c49918659b10b26e3119304d50eb9ee90a6e',
                         'generation': 9, 'rewrites': 5, 'state': c.checkpoint_state(expected),
                         'state_sha256': h.STATE_SHA, 'checkpoint_sha256': h.CERT_SHA,
                         'parent_checkpoint_sha256': c.digest(previous), 'pacing_bundle_sha256': h.BUNDLE_SHA,
                         'intent_sha256': intent_sha, 'verifier_result_sha256': result_sha,
                         'semantic_projection_sha256': PROJECTION_SHA, 'exact_semantic_equivalence': True,
                         'comparison_exceptions': {'time_field_excluded_from_semantic_comparison': ['verified_unix'],
                             'controller_only_historical_fields': ['generation', 'reopen', 'reopen_scope'],
                             'historical_pebble_reopen_verified': True, 'replay_pebble_reopen_verified': False},
                         'code_sha256': code, 'retained_inputs': reads.references,
                         'host_before': before, 'host_after': after,
                         'host_before_sha256': before_sha, 'host_after_sha256': after_sha,
                         'metrics': metrics,
                         'timing_seconds': {'ledger_decode': ledger_seconds,
                             'cloud_client_and_identity': client_ready_tick - cloud_tick,
                             'profiled_final_verifier': verify_finished_tick - client_ready_tick,
                             'cloud_client_close': cloud_closed_tick - verify_finished_tick,
                             'overall_through_final_checks': time.perf_counter() - start_tick},
                         'process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                         'expected_logical_operations': {'get_object': 10, 'head_object': 14,
                             'complete_version_enumerations': 1, 'get_body_bytes': 114_660_926,
                             'new_sst_body_bytes': 67_320_929, 'metadata_body_bytes': 47_339_997,
                             'duplicate_prior_manifest_get_bytes': 15_779_601},
                         'database_writer_invoked': False, 'pebble_open_performed': False,
                         'checkpoint_replaced': False, 'installed_migration_toolchain_changed': False,
                         'production_preserved': True, 'limitation':
                             'One current final-pass replay; no publication, queue drain, fresh Pebble reopen, or cold-cache throughput measurement.'}
            digest = h.write_new(ctx, OPS / 'replay-completed.json', completed)
        except BaseException as exc:
            failure = {'schema': 1, 'scope': 'read-only-generation-nine-profile-failure', 'failed_unix': time.time(),
                       'phase': phase, 'error_type': type(exc).__name__, 'intent_sha256': intent_sha,
                       'state_sha256': h.STATE_SHA, 'checkpoint_sha256': h.CERT_SHA,
                       'partial_metrics': metrics, 'database_writer_invoked': False, 'checkpoint_replaced': False}
            h.write_new(ctx, OPS / 'replay-failure.json', failure)
            raise
        # The committed successful receipt remains authoritative if stdout closes.
        try:
            print(json.dumps({'completed': True, 'receipt_sha256': digest, 'verifier_result_sha256': result_sha,
                              'projection_sha256': PROJECTION_SHA, 'timing_seconds': completed['timing_seconds'],
                              'metrics': metrics, 'host_preserved': True}), flush=True)
        except OSError:
            pass


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Read-only verification replay did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
