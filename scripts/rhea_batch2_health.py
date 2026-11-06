#!/usr/bin/env python3
"""Read-only phase checks for the fixed second bounded rewrite window.

Historical proof is validated against its retained preimage, never by changing
an old guard. Current policy and closed generations are checked independently.
The caller holds the lifecycle lock; this module starts no service or process,
opens no database, changes no queue, and never admits a restarted mount silently.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import urllib.request

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'pacing-batch2-20261107'
INSTALL = OPS / 'health.py'
ENGINE = OPS / 'transaction.py'
ENGINE_SHA = 'ce38f0b38da8f7824af42685cb57b17f89f75c64a30d5cf931cfd115dca19723'
REBOOT = TRUST / 'post-reboot-20261106'
REBOOT_HEALTH = REBOOT / 'health.py'
REBOOT_HEALTH_SHA = '4ccc2010e92a7e5202ef76a6f104af887246fa1e828b480d6b3bfcbcb63cb36f'
REBOOT_VERIFY_SHA = 'f1395771c687e95fae241ed90fe633b9546a1d1bb9c4493f024306a4f3c06f63'
REBOOT_COMPLETED_SHA = '64c805f7b51950853303c7de4b39ae75c449243913af5f083f98ece9fbda0ade'
IDENTITY_SHA = '3821f719ebc3b31df7cb77b02e516e3da2f11db5044df040f6be1129a9a14e67'
OLD_STATE_SHA = '22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2'
NEW_STATE_SHA = '0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9'
OLD_PINS_SHA = '684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c'
NEW_PINS_SHA = '1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363'
CERT_SHA = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
CONTROLLER = TRUST / 'run_rhea_full_clone_steps_batch2.py'
CONTROLLER_SHA = 'b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828'
DECODER_SHA = 'edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b'
PINS = TRUST / 'full-clone-batch2-step-pins.json'
STATE = TRUST / 'full-clone-steps/state.json'
BOOT_ID = '6fc54ca7-d64a-4125-98fa-d0a728485237'
KERNEL = '6.8.0-149-generic'
SCOPE = 'rhea-batch2-closed-generation-health'
PHASES = ('policy-before', 'policy-after', 'reader-stopped', 'writer-active',
          'writer-stopped', 'reader-restored')
DEPLOYMENT_FILES = frozenset(('controller-candidate.py', 'expected-state-before.json',
    'expected-pins-before.json', 'health.py', 'transaction.py', 'run.py', 'mounts.py', 'one-step.py'))
HEX = re.compile(r'[0-9a-f]{64}')
MAX_JSON = 16 * 1024**2


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def exact_module(path, digest, name):
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'unprotected health dependency')
        if part != path:
            require(stat.S_ISDIR(info.st_mode), 'health dependency ancestor is not a directory')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            'health dependency mode differs')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON and sha(raw) == digest, 'health dependency digest differs')
    result = types.ModuleType(name)
    result.__file__ = str(path)
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def absent(path):
    return not path.exists() and not path.is_symlink()


def _retained_adoption(ctx, reads):
    """Validate saved adoption bytes without its old-state or old-PID observer."""
    h, r, c = ctx['h'], ctx['reboot'], ctx['c']
    directory = r.ADOPTION
    before_raw = reads.raw('adoption-state-before', directory / 'state-before.json', expected=h.BASELINE_STATE_SHA)
    pins_raw = reads.raw('adoption-pins-before', directory / 'pins-before.json', expected=h.OLD_PINS_SHA)
    intent_raw = reads.raw('adoption-intent', directory / 'intent.json', expected=r.ADOPTION_INTENT_SHA)
    intent = c.json_object(intent_raw)
    require(canonical(intent) == intent_raw, 'historical adoption intent is not canonical')
    unused_before, state, pins = h.expected_transition(before_raw)
    require(sha(canonical(state)) == OLD_STATE_SHA and sha(canonical(pins)) == OLD_PINS_SHA
            and state['checkpoint'] == ctx['cert'], 'historical adopted endpoint differs')
    artifacts = h.artifact_manifest(pins)
    h.validate_intent(intent, before_raw, pins_raw, artifacts)
    for field, name in (('deployment_sha256', 'deployment.json'), ('recipe_sha256', 'run.py'),
                        ('engine_sha256', 'transaction.py'), ('health_sha256', 'health.py')):
        reads.raw('adoption-provenance-' + name, directory / name, expected=intent['provenance'][field])
    payloads = {name: reads.raw('adoption-payload-' + name, directory / name) for name in (
        'expected-state-before.json', 'expected-pins-before.json', 'controller-candidate.py',
        'verifier-candidate.py', 'scanner-candidate.py', 'health.py', 'transaction.py', 'run.py')}
    deployment = reads.json('adoption-deployment', directory / 'deployment.json')
    h.validate_deployment(deployment, intent, payloads)
    for role, pin in artifacts.items():
        raw = reads.raw('adoption-installed-' + role, TRUST / pin['path'], expected=pin['sha256'])
        require(len(raw) == pin['bytes'], 'preserved adoption artifact length differs')
    done = reads.json('adoption-completed', directory / 'completed.json', expected=r.ADOPTION_COMPLETED_SHA)
    verification = h.validate_completed(done, intent, r.ADOPTION_INTENT_SHA)
    accepted = directory / verification['path']
    require(absent(accepted / 'failure.json'), 'historical adoption proof has a failure receipt')
    blobs = {name + '.json': reads.raw('adoption-acceptance-' + name, accepted / (name + '.json'))
             for name in ('intent', 'result', 'metrics', 'completed')}
    for field, name in (('result_sha256', 'result.json'), ('metrics_sha256', 'metrics.json'),
                        ('receipt_sha256', 'completed.json')):
        require(sha(blobs[name]) == verification[field], 'historical adoption acceptance differs')
    measurement = h.validate_acceptance(ctx, blobs, intent, done, verification)
    comparison = exact_module(*h.HELPERS['comparison'], 'batch2_retained_comparison')
    comparison.validate_pass(measurement['metrics'], measurement['enumeration'],
                             measurement['listing_guard'], candidate=True)
    return state, pins, comparison


def _retained_post_reboot(ctx, reads, comparison):
    r, h, c = ctx['reboot'], ctx['h'], ctx['c']
    parking = reads.json('parking-completed', r.PARK / 'completed.json', expected=r.PARK_SHA)
    require(parking.get('boot_id') == r.OLD_BOOT_ID and parking.get('generation') == 9
            and parking.get('rewrites') == 5 and parking.get('pending') is None
            and parking.get('rclone_processes') == []
            and parking.get('rclone_mounts_all_observed_namespaces') == [], 'parking endpoint differs')
    raw = reads.raw('post-reboot-identity', r.IDENTITY, expected=IDENTITY_SHA)
    receipts = {name: reads.raw('post-reboot-' + name, REBOOT / name) for name in r.RECEIPTS}
    identity = r.validate_identity(ctx, c.json_object(raw), receipts)
    for path in r.INPUTS:
        r.read_input(path, identity['protected_inputs'][str(path)])
    saved = reads.raw('production-saved-inspect', r.SAVED_INSPECT, expected=r.SAVED_INSPECT_SHA)
    ctx.update(identity=identity, identity_raw=raw, identity_sha256=IDENTITY_SHA, saved_inspect=saved)
    require(absent(REBOOT / 'verification/failure.json'), 'post-reboot proof has a failure receipt')
    blobs = {name + '.json': reads.raw('post-reboot-proof-' + name, REBOOT / 'verification' / (name + '.json'),
             expected=REBOOT_COMPLETED_SHA if name == 'completed' else None)
             for name in ('intent', 'result', 'metrics', 'completed')}
    runner = exact_module(r.VERIFY, REBOOT_VERIFY_SHA, 'batch2_retained_post_reboot_verifier')
    equivalence = exact_module(*h.HELPERS['equivalence'], 'batch2_retained_equivalence')
    runner.validate_retained(ctx, blobs, comparison=comparison, equivalence=equivalence)
    runner.unchanged_sources(ctx, runner.source_pins(ctx))
    for role, pin in runner.expected_references(ctx).items():
        raw = reads.raw('post-reboot-input-' + role, TRUST / pin['path'], expected=pin['sha256'])
        require(len(raw) == pin['bytes'], 'post-reboot retained input length differs')
    ctx['post_reboot_completed'] = c.json_object(blobs['completed.json'])


def load():
    """Load immutable proof; the current mutable journal is read only in observe."""
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root batch2 health required')
    reboot = exact_module(REBOOT_HEALTH, REBOOT_HEALTH_SHA, 'batch2_post_reboot_health')
    h = exact_module(reboot.ADOPTION_HEALTH, reboot.ADOPTION_HEALTH_SHA, 'batch2_adoption_health')
    ctx = dict(h.load(), h=h, reboot=reboot)
    c, w = ctx['c'], ctx['w']
    w.secure_path(OPS, leaf_mode=0o700)
    w.secure_path(INSTALL, leaf_mode=0o600)
    reads = ctx['f'].ReadSet(c, w)
    state, pins, comparison = _retained_adoption(ctx, reads)
    ctx.update(adopted_state=state, adopted_pins=pins)
    _retained_post_reboot(ctx, reads, comparison)
    engine = exact_module(ENGINE, ENGINE_SHA, 'batch2_policy_engine_health')
    reads.raw('batch2-policy-engine', ENGINE, expected=ENGINE_SHA)
    reads.raw('batch2-health', INSTALL)
    after_raw, pins_raw = engine.expected_transition(canonical(state), canonical(pins))
    require(sha(after_raw) == NEW_STATE_SHA and sha(pins_raw) == NEW_PINS_SHA,
            'batch2 policy endpoints differ')
    ctx.update(history_reads=reads, engine=engine, admitted_state=c.json_object(after_raw),
               batch2_pins=c.json_object(pins_raw), batch=None)
    if not absent(CONTROLLER):
        ctx['batch'] = exact_module(CONTROLLER, CONTROLLER_SHA, 'batch2_controller_health')
    _unchanged(ctx)
    return ctx


def _unchanged(ctx):
    ctx['h']._unchanged(ctx, {})  # No evolving state path is passed as an old preimage.
    ctx['history_reads'].unchanged()
    for path in ctx['reboot'].INPUTS:
        ctx['reboot'].read_input(path, ctx['identity']['protected_inputs'][str(path)])


def bind_runtime(ctx, rt):
    """Use a caller's complete pinned batch2 runtime under its own real lock."""
    batch = ctx['batch']
    require(batch is not None and isinstance(rt, batch.Runtime), 'runtime is not the pinned batch2 class')
    w = rt.wrapper
    require(rt.binding == ctx['admitted_state']['binding'] and rt.pins == ctx['batch2_pins']
            and rt.profile is w.PROFILES['full-clone'] and type(rt.host) is w.RealHost,
            'runtime binding or wrapper/profile ownership differs')
    require(sha(w.read_protected(batch.WRAPPER)) == batch.WRAPPER_SHA256
            and sha(w.read_protected(CONTROLLER, mode=0o600)) == CONTROLLER_SHA
            and sha(w.read_protected(PINS, mode=0o600)) == NEW_PINS_SHA,
            'runtime source or deployment pins differ')
    return dict(ctx, rt=rt, w=w, c=batch, v=rt.verifier)


def _policy(ctx, reads, phase, intent_sha256):
    c, engine = ctx['c'], ctx['engine']
    state_raw = reads.raw('current-state', STATE)
    state = c.json_object(state_raw)
    require(canonical(state) == state_raw, 'current journal is not canonical')
    before = phase == 'policy-before'
    if before:
        require(state_raw == canonical(ctx['adopted_state']), 'policy preimage changed')
    expected_targets = {CONTROLLER: (CONTROLLER_SHA, None), PINS: (NEW_PINS_SHA, canonical(ctx['batch2_pins']))}
    for path, (digest, expected) in expected_targets.items():
        if before and absent(path):
            continue
        raw = reads.raw('batch2-target-' + path.name, path, expected=digest)
        require(expected is None or raw == expected, 'batch2 target bytes differ')
    intent_path = OPS / 'intent.json'
    if before and intent_sha256 is None and absent(intent_path):
        return state, OLD_PINS_SHA, None
    intent_raw = reads.raw('policy-intent', intent_path)
    if intent_sha256 is not None:
        require(type(intent_sha256) is str and HEX.fullmatch(intent_sha256)
                and sha(intent_raw) == intent_sha256, 'policy intent digest differs')
    intent = c.json_object(intent_raw)
    provenance = intent['provenance']
    for field, name in (('deployment_sha256', 'deployment.json'), ('recipe_sha256', 'run.py'),
                        ('engine_sha256', 'transaction.py'), ('health_sha256', 'health.py')):
        reads.raw('policy-provenance-' + name, OPS / name, expected=provenance[field])
    require(provenance['engine_sha256'] == ENGINE_SHA, 'policy engine provenance differs')
    deployment = reads.json('policy-deployment', OPS / 'deployment.json')
    require(set(deployment) == {'schema', 'scope', 'source_commit', 'parent_commit', 'payloads'}
            and type(deployment['schema']) is int and deployment['schema'] == 1
            and deployment['scope'] == 'fixed-generation-nine-batch2-policy-deployment'
            and deployment['source_commit'] == provenance['source_commit']
            and deployment['parent_commit'] == '10a088d5f3de8e3c1e555e6b1848f224dbd79451'
            and set(deployment['payloads']) == DEPLOYMENT_FILES, 'policy deployment scope differs')
    payloads = {}
    for name, pin in deployment['payloads'].items():
        require(type(pin) is dict and set(pin) == {'sha256', 'bytes'}
                and type(pin['bytes']) is int and 0 < pin['bytes'] <= MAX_JSON, 'policy payload pin differs')
        raw = reads.raw('policy-payload-' + name, OPS / name, expected=pin['sha256'])
        require(len(raw) == pin['bytes'], 'policy payload length differs')
        payloads[name] = raw
    old_state = reads.raw('policy-state-before', OPS / 'state-before.json', expected=OLD_STATE_SHA)
    old_pins = reads.raw('policy-pins-before', OPS / 'pins-before.json', expected=OLD_PINS_SHA)
    require(payloads['expected-state-before.json'] == old_state
            and payloads['expected-pins-before.json'] == old_pins, 'staged policy preimages differ')
    plan = engine.build_plan(old_state, old_pins, {'controller': payloads['controller-candidate.py']}, provenance)
    engine.validate_intent(intent_raw, plan)
    done = None
    if phase not in ('policy-before', 'policy-after') or intent_sha256 is None:
        done_raw = reads.raw('policy-completed', OPS / 'completed.json')
        done = engine.validate_completed(done_raw, intent_raw, plan)
    if phase == 'policy-after':
        require(state_raw == plan.state_after, 'postpolicy journal exceeds the two-leaf transition')
        candidate = exact_module(CONTROLLER, CONTROLLER_SHA, 'batch2_policy_runtime_validation')
        new_rt = candidate.Runtime()  # Binding validation only; host work keeps ctx's original tuple.
        require(new_rt.binding == ctx['admitted_state']['binding'] and new_rt.pins == ctx['batch2_pins']
                and new_rt.load_state() == state == ctx['admitted_state'],
                'installed batch2 runtime does not accept the exact policy endpoint')
    elif not before:
        require(state.get('binding') == ctx['admitted_state']['binding'], 'active batch2 binding differs')
    return state, OLD_PINS_SHA if before else NEW_PINS_SHA, done


def validate_link(c, v, previous, current, writer, exit_report, hashes, before, after, before_stats, after_stats, baseline):
    """Pure retained-success linkage, limited to the four new generations."""
    generation = previous['generation'] + 1
    require(10 <= generation <= 13 and current.get('schema') == 1
            and current.get('scope') == 'fixed-disposable-full-clone-stage'
            and current.get('bucket') == c.BUCKET and current.get('prefix') == c.PREFIX
            and current.get('generation') == generation and current.get('action') == 'step'
            and current.get('mode') == 'final' and current.get('remote_generation_verified') is True
            and current.get('pebble_reopen_verified') is True, 'batch2 certificate is not final')
    require(current.get('previous_checkpoint_sha256') == c.digest(previous)
            and current.get('go_report_sha256') == c.digest(writer)
            and current.get('closed_output_hashes_sha256') == c.digest(hashes), 'batch2 chain hashes differ')
    require(type(exit_report.get('returncode')) is int and exit_report['returncode'] == 0
            and exit_report.get('monitor_failure') is None and exit_report.get('budget_stop_present') is False,
            'batch2 writer did not close successfully under monitoring')
    old_state, new_state = c.checkpoint_state(previous), c.checkpoint_state(current)
    plan = writer.get('picker_plan')
    c.validate_result(writer, 'step', old_state, plan)
    c.validate_inspection(current['reopen'], new_state)
    created, retired = v._validate_stage(writer, before, after, before_stats, after_stats, '013', '013', hashes)
    candidate = 'pebble-lab-candidate-v1\ninput-level\t{}\noutput-level\t{}\n'.format(plan['input_level'], plan['output_level'])
    candidate += ''.join(f"{row['number']}\t{row['size']}\n" for row in sorted(retired.values(), key=lambda row: row['number']))
    bound = ('fullclone-plan-v1\nformat\t{format}\nmarked\t{marked}\ninventory\t{inventory}\ncandidate\t'.format(**old_state)
             + sha(candidate.encode()) + '\n')
    require(plan.get('candidate_sha256') == sha(candidate.encode())
            and plan.get('plan_sha256') == sha(bound.encode())
            and writer.get('expected_plan_sha256') == sha(bound.encode()), 'canonical picker binding differs')
    old_pins, old_lineage = v._lineage(previous, baseline)
    current_pins, lineage = v._lineage(current, baseline)
    require({name: row['size'] for name, row in before.items()} == {name: pin['size'] for name, pin in old_pins.items()}
            and {name: row['size'] for name, row in after.items()} == {name: pin['size'] for name, pin in current_pins.items()},
            'closed inventory differs from cumulative lineage')
    expected_lineage = copy.deepcopy(old_lineage)
    require(not set(created) & (set(baseline) | set(old_lineage['created'])), 'output reused a historical name')
    new_versions = current.get('created_sst_versions')
    require(isinstance(new_versions, dict) and set(new_versions) == set(created), 'created version subset differs')
    for name in created:
        require(new_versions[name] == lineage['created'][name]
                and all(new_versions[name][key] == hashes[name][key] for key in ('size', 'sha256')),
                'created payload proof differs')
        expected_lineage['created'][name] = new_versions[name]
    for name in retired:
        expected_lineage['retired'][name] = old_pins[name]
    expected_lineage['rewrite_operations'] += 1
    require(lineage == expected_lineage and lineage['rewrite_operations'] == generation - 4,
            'cumulative lineage changed outside this one selected unit')
    require(current.get('decoder_sha256') == DECODER_SHA and current.get('ledger_sha256') == v.LEDGER_SHA256
            and current.get('unchanged_sst_payload_bytes_downloaded') == 0
            and current.get('unchanged_sst_versions') == len(old_pins) - len(retired)
            and current.get('new_sst_payload_bytes_downloaded') == sum(row['size'] for row in created.values()),
            'remote verification accounting/provenance differs')
    require(current['format_marker'] == previous['format_marker']
            and current['remote_metadata'][current['format_marker']] == previous['remote_metadata'][previous['format_marker']],
            'format013 marker identity changed')
    retirement = current.get('retired_sst_states')
    require(isinstance(retirement, dict) and set(retirement) == set(lineage['retired']), 'retirement receipt subset differs')
    for name, value in retirement.items():
        require((value.get('state') == 'unchanged-unreferenced-latest' and value.get('version_id') == lineage['retired'][name]['version_id'])
                or (value.get('state') == 'latest-delete-marker' and isinstance(value.get('delete_marker_version_id'), str)
                    and value['delete_marker_version_id'] not in ('', 'null')), 'invalid retired SST state')
    return created, retired


def validate_progress(ctx, reads, state):
    c, v, f = ctx['c'], ctx['v'], ctx['f']
    require(type(state) is dict and set(state) == {'schema', 'binding', 'checkpoint', 'generation', 'rewrites', 'pending'}
            and type(state['schema']) is int and state['schema'] == 1
            and state['binding'] == ctx['admitted_state']['binding']
            and type(state['generation']) is int and 9 <= state['generation'] <= 13
            and type(state['rewrites']) is int and state['rewrites'] == state['generation'] - 4
            and state['pending'] is None, 'batch2 health requires a closed bounded generation')
    previous = ctx['cert']
    require(sha(canonical(previous)) == CERT_SHA, 'generation-nine anchor differs')
    if state['generation'] == 9:
        require(state == ctx['admitted_state'], 'generation-nine state changed outside policy')
        return []
    baseline = v._baseline_pins(ctx['w'].load_ledger(ctx['ledger_blob']))
    before, before_stats = f.retained_snapshot(c, v, reads, previous, 9)
    stages = []
    for generation in range(10, state['generation'] + 1):
        label = f'{generation:06d}-step'
        current = reads.json(label + '-certificate', c.STATE_ROOT / 'checkpoints' / (label + '.json'))
        directory = c.STATE_ROOT / 'stages' / label
        writer = reads.json(label + '-writer', directory / 'writer.json')
        exit_report = reads.json(label + '-process-exit', directory / 'process-exit.json')
        hashes = reads.json(label + '-created-sst-hashes', directory / 'created-sst-hashes.json')
        after, after_stats = f.retained_snapshot(c, v, reads, current, generation)
        created, retired = validate_link(c, v, previous, current, writer, exit_report, hashes,
            before, after, before_stats, after_stats, baseline)
        stages.append({'generation': generation, 'checkpoint_sha256': c.digest(current),
                       'writer_sha256': c.digest(writer), 'created_files': len(created), 'retired_files': len(retired)})
        previous, before, before_stats = current, after, after_stats
    require(state['checkpoint'] == previous, 'journal checkpoint differs from retained batch2 chain')
    return stages


def production_observation(ctx):
    return ctx['reboot'].production_observation(ctx)


def writer_absent(ctx):
    return ctx['old'].writer_absent(ctx['rt'])


def reader_observation(ctx, expected):
    observed = ctx['old'].reader_observation(ctx['rt'], expected['process']['pid'])
    require(observed == expected, 'reader changed from the explicitly sealed identity')
    return observed


def _reader_absent(ctx):
    rt, w, old = ctx['rt'], ctx['w'], ctx['old']
    service = rt.host.service(old.READER_UNIT)
    require(service.get('LoadState') in ('loaded', 'not-found') and service.get('ActiveState') == 'inactive'
            and service.get('SubState') == 'dead' and service.get('MainPID') == '0', 'reader is not fully stopped')
    rows = w.mount_rows(Path('/proc/self/mountinfo').read_text())
    require(not any(row['target'] == str(old.READER_MOUNT) for row in rows), 'reader mount remains')
    original = ctx['identity']['reader']['process']
    try:
        require(rt._process_identity(original['pid']) != original, 'original reader process remains')
    except FileNotFoundError:
        pass
    return service


def _mount_identity(ctx, reads, phase, writer_sha256, reader_sha256, state):
    c = ctx['c']
    if phase in ('policy-before', 'policy-after'):
        return ctx['identity']['reader']
    if phase == 'writer-active':
        require(absent(OPS / 'start-failure.json'), 'writer startup requires explicit failure reconciliation')
        if writer_sha256 is None:
            done = reads.json('mount-start-completed', OPS / 'start-completed.json')
            writer_sha256 = done.get('writer_started_sha256')
        else:
            done = None
            require(state['generation'] == 9, 'provisional writer identity is limited to startup')
        require(type(writer_sha256) is str and HEX.fullmatch(writer_sha256), 'sealed writer receipt digest required')
        started = reads.json('mount-writer-started', OPS / 'writer-started.json', expected=writer_sha256)
        require(started.get('state_sha256') == NEW_STATE_SHA and started.get('checkpoint_sha256') == CERT_SHA
                and type(started.get('observation')) is dict, 'writer startup does not bind the policy endpoint')
        identity = ctx['reboot'].process_identity(started.get('process'))
        require(started['observation'].get('pid') == identity['pid'], 'writer startup PID differs')
        ctx['w'].validate_stats(ctx['rt'].profile, started['observation'])
        ctx['w'].clean_queue(started['observation']['stats'], started['observation']['queue'])
        if done is not None:
            require(done.get('writer_process') == identity and done.get('state_sha256') == NEW_STATE_SHA
                    and done.get('checkpoint_sha256') == CERT_SHA and done.get('verified') is True,
                    'writer completion differs from its sealed startup identity')
        return identity
    if phase == 'reader-restored':
        directory = OPS / 'finalization'
        require(absent(directory / 'failure.json'), 'reader restoration requires explicit failure reconciliation')
        if reader_sha256 is None:
            done = reads.json('mount-finalization-completed', directory / 'completed.json')
            reader_sha256 = done.get('reader_restored_sha256')
            require(done.get('state_sha256') == c.digest(state)
                    and done.get('checkpoint_sha256') == c.digest(state['checkpoint'])
                    and done.get('verified') is True, 'restored reader completion binds another generation')
        require(type(reader_sha256) is str and HEX.fullmatch(reader_sha256), 'sealed reader receipt digest required')
        restored = reads.json('mount-reader-restored', directory / 'reader-restored.json', expected=reader_sha256)
        ctx['reboot'].process_identity(restored.get('process'))
        require(restored['process'] != ctx['identity']['reader']['process'], 'restoration reused the pre-stop identity')
        return restored
    return None


def _production_rc(ctx):
    rc, w = ctx['rc'], ctx['w']
    helper = rc.exact_module(rc.HELPER, rc.HELPER_SHA256, 'batch2_authenticated_production_rc', protected=False)
    require(helper.API == rc.API and helper.CLIENT == rc.CLIENT, 'authenticated RC helper scope differs')
    w.secure_path(rc.CLIENT, leaf_mode=0o600)
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}), rc.NoRedirect()))
    stats = helper.call_rc('vfs/stats', {'fs': rc.FS}, client=rc.CLIENT)
    queue = helper.call_rc('vfs/queue', {'fs': rc.FS}, client=rc.CLIENT)
    rc.validate_rc(stats, queue)
    w.clean_queue(stats, queue)
    return {key: stats['diskCache'][key] for key in
            ('bytesUsed', 'uploadsQueued', 'uploadsInProgress', 'erroredFiles', 'outOfSpace')}


def observe(ctx, *, phase, intent_sha256=None, writer_sha256=None, reader_sha256=None, authenticated_rc=True):
    require(phase in PHASES, 'unknown batch2 health phase')
    rt, w, c, old = (ctx[key] for key in ('rt', 'w', 'c', 'old'))
    require(rt.host.locked and not rt.stop_present(), 'batch2 health requires the protected idle lock')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT_ID
            and os.uname().release == KERNEL, 'sealed boot or kernel changed')
    require(writer_sha256 is None or phase == 'writer-active', 'writer pin supplied for another phase')
    require(reader_sha256 is None or phase == 'reader-restored', 'reader pin supplied for another phase')
    _unchanged(ctx)
    reads = ctx['f'].ReadSet(c, w)
    state, pins_sha, unused_policy = _policy(ctx, reads, phase, intent_sha256)
    stages = [] if phase == 'policy-before' else validate_progress(ctx, reads, state)
    expected = _mount_identity(ctx, reads, phase, writer_sha256, reader_sha256, state)
    reader = writer_process = lab = None
    if phase == 'writer-active':
        _reader_absent(ctx)
        require(rt._process_identity(expected['pid']) == expected, 'writer changed from its sealed startup identity')
        rt.pid = expected['pid']
        lab = rt.guard(new_work=False, clean=True)
        require(lab['pid'] == expected['pid'], 'authenticated writer peer differs')
        writer_process = expected
        writer = rt.host.service(rt.profile.unit)
        old.no_other_lab_users(rt, expected['pid'])
    else:
        writer = writer_absent(ctx)
        if phase in ('policy-before', 'policy-after', 'reader-restored'):
            reader = reader_observation(ctx, expected)
            old.no_other_lab_users(rt, reader['process']['pid'])
        else:
            _reader_absent(ctx)
            old.no_other_lab_users(rt, 0)
    production = production_observation(ctx)
    disk = _production_rc(ctx) if authenticated_rc else None
    require(production_observation(ctx) == production, 'production identity changed during observation')
    if reader is not None:
        reader_observation(ctx, expected)
    elif writer_process is not None:
        _reader_absent(ctx)
        require(rt._process_identity(writer_process['pid']) == writer_process, 'writer restarted during observation')
        rt.host.unit_identity(rt.profile, rt.host.service(rt.profile.unit), active=True)
    else:
        _reader_absent(ctx)
    if writer_process is None:
        writer_absent(ctx)
    require(all(path.is_dir() for path in (rt.profile.cache, old.READER_CACHE, ctx['reboot'].PRODUCTION_CACHE)),
            'retained cache directory missing')
    require(not rt.stop_present() and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT_ID,
            'stop sentinel or boot changed during health observation')
    reads.unchanged()
    _unchanged(ctx)
    return {'schema': 1, 'scope': SCOPE, 'phase': phase, 'observed_unix': time.time(),
        'boot_id': BOOT_ID, 'kernel': KERNEL, 'identity_sha256': IDENTITY_SHA,
        'post_reboot_verification_sha256': REBOOT_COMPLETED_SHA, 'baseline_state_sha256': OLD_STATE_SHA,
        'state_sha256': c.digest(state), 'pins_sha256': pins_sha,
        'checkpoint_sha256': c.digest(state['checkpoint']), 'generation': state['generation'],
        'rewrites': state['rewrites'], 'pending': None, 'state': c.checkpoint_state(state['checkpoint']),
        'maximum_rewrites': state['binding']['limits']['maximum_rewrites'], 'certified_stages': stages,
        'reader_process': None if reader is None else reader['process'], 'writer_process': writer_process,
        'production_service_process': production['production_process'],
        'production_rc_process': production['rc_server']['process'],
        'production_rc_checked': authenticated_rc, 'production_disk_cache': disk,
        'production_identity_sha256': sha(canonical(production)),
        'production_rc_identity_sha256': sha(canonical(production['rc_server'])),
        'writer': {key: writer[key] for key in ('ActiveState', 'SubState', 'MainPID', 'Result', 'ExecMainStatus')},
        'writer_mount_and_socket_absent': writer_process is None,
        'lab_disk_cache': None if lab is None else lab['stats']['diskCache'],
        'reader_and_writer_caches_retained': True, 'kubo_and_walker_inactive': True,
        'walker_unit_file_state': 'disabled', 'free_bytes': rt.free_bytes(), 'protected_anchors_unchanged': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=PHASES)
    parser.add_argument('--intent-sha256')
    parser.add_argument('--writer-sha256')
    parser.add_argument('--reader-sha256')
    args = parser.parse_args()
    ctx = load()
    with ctx['rt'].lock():
        observed = observe(ctx, phase=args.phase, intent_sha256=args.intent_sha256,
                           writer_sha256=args.writer_sha256, reader_sha256=args.reader_sha256)
    try:
        print(json.dumps(observed), flush=True)
    except OSError:
        pass


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        try:
            print('Batch2 health refused (' + type(exc).__name__ + '). Preserve evidence before further action.', file=sys.stderr)
        except OSError:
            pass
        raise SystemExit(1) from None
