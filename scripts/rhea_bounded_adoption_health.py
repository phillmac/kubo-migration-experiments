#!/usr/bin/env python3
"""Fixed read-only health for the generation-nine bounded-verifier adoption.

Bootstrap uses the unchanged historical controller and its own wrapper/host.
Current state is accepted only by an explicit before/after observation under
that host's lock. The new Runtime is used only to validate installed bindings;
no writable-mount guard, Go tool, service action, or Pebble open is invoked.
The permanent --check entry point additionally requires completed adoption
and its retained exact final-verification evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
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
OPS = TRUST / 'bounded-adoption-20261106'
INSTALL = OPS / 'health.py'
FINALIZER = TRUST / 'pacing-20261104/finalize.py'
FINALIZER_SHA = '3e522bae660ded45fb0160e122fd46c711fd5460b9b5b4d1e9234ae0786ebad2'
OLD_HEALTH = TRUST / 'verification-profile-20261105/health.py'
OLD_HEALTH_SHA = '617108d7b87b9879c622fcf22bc4ddf47ae258f680625cd4119661338c47a3f8'
# Original files and their historical pins are never replaced by this adoption.
OLD_CONTROLLER = TRUST / 'run_rhea_full_clone_steps.py'
OLD_CONTROLLER_SHA = '7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb'
OLD_VERIFIER = TRUST / 'verify_rhea_full_clone.py'
OLD_VERIFIER_SHA = 'e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849'
OLD_PINS = TRUST / 'full-clone-step-pins.json'
OLD_PINS_SHA = '0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575'
NEW_CONTROLLER = TRUST / 'run_rhea_full_clone_steps_bounded.py'
NEW_CONTROLLER_SHA = '56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a'
NEW_VERIFIER = TRUST / 'verify_rhea_full_clone_bounded.py'
NEW_VERIFIER_SHA = '43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796'
SCANNER = TRUST / 'enumerate_rhea_versions.py'
SCANNER_SHA = '512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359'
DECODER = TRUST / 'verify_rhea_lab_format3.py'
DECODER_SHA = 'edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b'
NEW_PINS = TRUST / 'full-clone-bounded-step-pins.json'
STATE = TRUST / 'full-clone-steps/state.json'
BASELINE_STATE_SHA = '7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1'
CERT_SHA = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
BUNDLE_SHA = 'accbfa2151490cef4dcba979ff3c5ad89f07923a105586c648d008720bf1b51e'
COMPLETION_SHA = 'e2cbae5c26f9b757321146edc94e9459b9cd7de2f82ea52605efec9ad84078f5'
ADMISSION_SHA = 'a7a4b918549d24a4988259e8cf43091ec8267f8e9f7a1ffcfecf9cea2647e8ec'
GO_SHA = '1bc58ef8ca76a97fc9886d90f4a3df4fdd3d07549403988e3798834a61207125'
WRAPPER_SHA = '76635430d99daa65a816dc1ae444145bbdfe844559b4b4bed2e30fbae0302545'
SEED_SHA = 'a7438699846ca71af61ad7c7622f9807be2846273c75fd3559730a51988f1eaf'
PROJECTION_SHA = '0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57'
PARENT_COMMIT = '8fa1c296bbe1e8c3687710ddcf1a72c36510b4cb'
ACCEPTANCE_SCOPE = 'installed-bounded-verifier-generation-nine-acceptance'
HELPERS = {
    'comparison': (TRUST / 'integrated-verification-profile-20261105/compare.py',
                   '4437ac23d767a5164d42f1c8bb33caf21f7e35c10ab1853ce54f3ce104c4c913'),
    'profiler': (TRUST / 'integrated-verification-profile-20261105/profile_rhea_full_clone_verification.py',
                 'e0fd6cbfc1e6a44830a550cc4993fd486a1d23df29c4d127879c16dc2a84cccd'),
    'equivalence': (TRUST / 'verification-profile-20261105/replay.py',
                    '6660de99fce5982bfcb66975b0e3869b891825a5d07942ea4a29bf56a2e125a1'),
}
INTENT_SCOPE = 'fixed-generation-nine-bounded-verifier-adoption-intent'
COMPLETED_SCOPE = 'fixed-generation-nine-bounded-verifier-adoption-completed'
HEALTH_SCOPE = 'generation-nine-bounded-adoption-health'
HEX = re.compile(r'[0-9a-f]{64}')
MAX_JSON = 16 * 1024**2
LIMITS = {'input_bytes': 256 * 1024**2, 'sst_output_bytes': 512 * 1024**2,
          'metadata_write_bytes': 64 * 1024**2, 'cache_bytes': 96 * 1024**3,
          'minimum_free_bytes': 2 * 1024**4, 'backlog_bytes': 768 * 1024**2,
          'backlog_files': 256, 'maximum_rewrites': 5}
INTENT_KEYS = {'schema', 'scope', 'started_unix', 'provenance', 'generation', 'rewrites',
               'checkpoint_sha256', 'old_state_sha256', 'new_state_sha256',
               'old_pins_sha256', 'new_pins_sha256', 'old_binding', 'new_binding',
               'artifacts', 'before'}
COMPLETED_KEYS = {'schema', 'scope', 'completed_unix', 'intent_sha256', 'generation',
                  'rewrites', 'checkpoint_sha256', 'state_sha256', 'pins_sha256',
                  'artifacts', 'after', 'verification', 'resumed',
                  'state_replaced_this_run', 'database_writer_invoked', 'pebble_open_performed'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def exact_module(path, digest, name):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'source path differs')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'source path is not protected')
        require(stat.S_ISDIR(info.st_mode) if part != path else
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'source type or mode differs')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON and sha(raw) == digest, 'source digest differs')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def old_pins():
    return {'schema': 1, 'controller_sha256': OLD_CONTROLLER_SHA,
            'go_sha256': GO_SHA, 'verifier_sha256': OLD_VERIFIER_SHA}


def expected_transition(before_raw):
    """Derive the only permitted state/pins delta from the exact old journal."""
    require(sha(before_raw) == BASELINE_STATE_SHA, 'state preimage is not the certified baseline')
    require(HEX.fullmatch(NEW_CONTROLLER_SHA) is not None, 'new controller pin is not final')
    before = json.loads(before_raw)
    binding = dict(old_pins(), wrapper_sha256=WRAPPER_SHA, seed_sha256=SEED_SHA,
                   bucket='rhea-pebble-lab-20261101-39037c6f01', prefix='rhea/', limits=LIMITS)
    require(set(before) == {'schema', 'binding', 'checkpoint', 'generation', 'rewrites', 'pending'}
            and before['schema'] == 1 and before['binding'] == binding
            and before['generation'] == 9 and before['rewrites'] == 5 and before['pending'] is None,
            'certified baseline policy differs')
    require(sha(canonical(before['checkpoint'])) == CERT_SHA, 'baseline checkpoint differs')
    after = copy.deepcopy(before)
    after['binding'].update(controller_sha256=NEW_CONTROLLER_SHA, verifier_sha256=NEW_VERIFIER_SHA)
    pins = dict(old_pins(), controller_sha256=NEW_CONTROLLER_SHA, verifier_sha256=NEW_VERIFIER_SHA)
    return before, after, pins


def artifact_manifest(pins):
    return {
        'controller': {'path': NEW_CONTROLLER.name, 'sha256': NEW_CONTROLLER_SHA, 'bytes': 49_144},
        'verifier': {'path': NEW_VERIFIER.name, 'sha256': NEW_VERIFIER_SHA, 'bytes': 35_063},
        'scanner': {'path': SCANNER.name, 'sha256': SCANNER_SHA, 'bytes': 16_289},
        'pins': {'path': NEW_PINS.name, 'sha256': sha(canonical(pins)), 'bytes': len(canonical(pins))},
    }


def validate_intent(intent, before_raw, pins_before_raw, artifacts):
    before, after, pins = expected_transition(before_raw)
    require(artifacts == artifact_manifest(pins), 'adoption artifact manifest differs')
    require(sha(pins_before_raw) == OLD_PINS_SHA and json.loads(pins_before_raw) == old_pins(),
            'historical deployment pins preimage differs')
    require(type(intent) is dict and set(intent) == INTENT_KEYS, 'adoption intent schema differs')
    expected = {'schema': 1, 'scope': INTENT_SCOPE, 'generation': 9, 'rewrites': 5,
                'checkpoint_sha256': CERT_SHA, 'old_state_sha256': BASELINE_STATE_SHA,
                'new_state_sha256': sha(canonical(after)), 'old_pins_sha256': OLD_PINS_SHA,
                'new_pins_sha256': sha(canonical(pins)), 'old_binding': before['binding'],
                'new_binding': after['binding'], 'artifacts': artifacts}
    require(all(type(intent.get(k)) is type(v) and intent[k] == v for k, v in expected.items()),
            'intent is not the exact reviewed binding transition')
    require(finite_number(intent['started_unix']), 'invalid intent time')
    provenance = intent['provenance']
    require(type(provenance) is dict and set(provenance) == {
        'schema', 'source_commit', 'deployment_sha256', 'recipe_sha256', 'engine_sha256', 'health_sha256'},
        'intent provenance schema differs')
    require(type(provenance['schema']) is int and provenance['schema'] == 1
            and type(provenance['source_commit']) is str
            and re.fullmatch(r'[0-9a-f]{40}', provenance['source_commit'])
            and all(type(provenance[k]) is str and HEX.fullmatch(provenance[k])
                    for k in ('deployment_sha256', 'recipe_sha256', 'engine_sha256', 'health_sha256')),
            'intent provenance pins differ')
    validate_guard_summary(intent['before'], phase='before', state_sha=BASELINE_STATE_SHA,
                           pins_sha=OLD_PINS_SHA)
    return before, after, pins


def validate_guard_summary(value, *, phase, state_sha, pins_sha):
    expected = {'schema': 1, 'scope': HEALTH_SCOPE, 'phase': phase, 'generation': 9, 'rewrites': 5,
                'checkpoint_sha256': CERT_SHA, 'state_sha256': state_sha, 'pins_sha256': pins_sha,
                'baseline_state_sha256': BASELINE_STATE_SHA}
    require(type(value) is dict and all(type(value.get(k)) is type(v) and value[k] == v
                                      for k, v in expected.items()),
            'health summary is bound to another phase or checkpoint')
    require(value.get('production_rc_checked') is True and value.get('protected_anchors_unchanged') is True
            and value.get('writer_mount_and_socket_absent') is True
            and value.get('reader_and_writer_caches_retained') is True
            and value.get('kubo_and_walker_inactive') is True
            and value.get('walker_unit_file_state') == 'disabled', 'health summary is not a clean frozen generation')
    require(canonical(value.get('production_disk_cache')) == canonical({'bytesUsed': 0, 'uploadsQueued': 0,
            'uploadsInProgress': 0, 'erroredFiles': 0, 'outOfSpace': False}), 'production RC summary is not clean')
    require(value.get('writer') == {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
            'Result': 'success', 'ExecMainStatus': '0'}, 'writer summary is not stopped cleanly')


def validate_deployment(deployment, intent, payloads):
    expected = {'expected-state-before.json': BASELINE_STATE_SHA, 'expected-pins-before.json': OLD_PINS_SHA,
                'controller-candidate.py': NEW_CONTROLLER_SHA, 'verifier-candidate.py': NEW_VERIFIER_SHA,
                'scanner-candidate.py': SCANNER_SHA, 'health.py': intent['provenance']['health_sha256'],
                'transaction.py': intent['provenance']['engine_sha256'],
                'run.py': intent['provenance']['recipe_sha256']}
    require(type(deployment) is dict and set(deployment) == {
        'schema', 'scope', 'source_commit', 'parent_commit', 'payloads'}, 'deployment manifest schema differs')
    require(type(deployment['schema']) is int and deployment['schema'] == 1
            and deployment['scope'] == 'fixed-generation-nine-bounded-verifier-deployment'
            and deployment['source_commit'] == intent['provenance']['source_commit']
            and deployment['source_commit'] != PARENT_COMMIT
            and deployment['parent_commit'] == PARENT_COMMIT, 'deployment provenance differs')
    require(type(deployment['payloads']) is dict and set(deployment['payloads']) == set(expected)
            and set(payloads) == set(expected), 'deployment payload names differ')
    for name, digest in expected.items():
        pin, raw = deployment['payloads'][name], payloads[name]
        require(type(pin) is dict and set(pin) == {'sha256', 'bytes'}
                and type(pin['bytes']) is int and pin['bytes'] == len(raw)
                and pin['sha256'] == sha(raw) == digest, 'deployment payload differs: ' + name)


def load():
    """Load only original immutable anchors; current state may be before or after."""
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root installation required')
    f = exact_module(FINALIZER, FINALIZER_SHA, 'bounded_adoption_historical_finalizer')
    c, unused_wrapper, unused_verifier, old, rc = f.bootstrap()
    require(f.CONTROLLER_SHA == OLD_CONTROLLER_SHA and f.VERIFIER_SHA == OLD_VERIFIER_SHA
            and c.PINS == OLD_PINS and c.VERIFIER == OLD_VERIFIER and c.LIMITS == LIMITS,
            'historical bootstrap differs')
    rt = c.Runtime()
    w, v = rt.wrapper, rt.verifier
    w.secure_path(INSTALL, leaf_mode=0o600)
    w.secure_path(OPS, leaf_mode=0o700)
    paths = {
        'certificate': (c.STATE_ROOT / 'checkpoints/000009-step.json', CERT_SHA),
        'completion': (f.EVIDENCE / 'completed.json', COMPLETION_SHA),
        'bundle': (f.OPS / 'pacing-certified.json', BUNDLE_SHA),
        'admission': (w.ADMISSIONS / 'full-clone.json', ADMISSION_SHA),
        'old_pins': (OLD_PINS, OLD_PINS_SHA),
    }
    retained = {}
    for role, (path, digest) in paths.items():
        raw = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
        require(sha(raw) == digest, 'historical anchor differs: ' + role)
        retained[role] = raw
    cert = c.json_object(retained['certificate'])
    done, bundle = (c.json_object(retained[k]) for k in ('completion', 'bundle'))
    require(done['state_sha256'] == BASELINE_STATE_SHA and done['checkpoint_sha256'] == CERT_SHA
            and bundle['state_sha256'] == BASELINE_STATE_SHA and bundle['checkpoint_sha256'] == CERT_SHA,
            'historical receipts bind another generation')
    binary = w.read_protected(w.RCLONE)
    config = w.read_protected(w.CONFIG, mode=0o600)
    ledger_blob = w.read_protected(w.LEDGER)
    require(sha(binary) == w.RCLONE_SHA256 and sha(ledger_blob) == v.LEDGER_SHA256,
            'rclone or immutable ledger differs')
    rt.host.fingerprints = tuple(sha(raw) for raw in (binary, config, ledger_blob))
    admission = rt.host.read_admission(rt.profile)
    require(admission == c.json_object(retained['admission']), 'admission differs')
    protected = {path: sha(w.read_protected(path, mode=0o600)) for path in (w.CONFIG, old.READER_CONFIG)}
    sources = {OLD_CONTROLLER: OLD_CONTROLLER_SHA, c.WRAPPER: WRAPPER_SHA,
               OLD_VERIFIER: OLD_VERIFIER_SHA, c.TOOL: GO_SHA, DECODER: DECODER_SHA,
               old.INSPECTOR: f.INSPECTOR_SHA, FINALIZER: FINALIZER_SHA,
               f.OLD_FINALIZER: f.OLD_FINALIZER_SHA, f.OLD_RC: f.OLD_RC_SHA,
               OLD_HEALTH: OLD_HEALTH_SHA,
               INSTALL: sha(w.read_protected(INSTALL, mode=0o600))}
    sources.update({path: digest for path, digest in HELPERS.values()})
    require(all(sha(w.read_protected(path)) == digest for path, digest in sources.items()),
            'protected historical executable differs')
    return {'f': f, 'c': c, 'rt': rt, 'w': w, 'v': v, 'old': old, 'rc': rc,
            'paths': paths, 'retained': retained, 'cert': cert, 'done': done, 'bundle': bundle,
            'ledger_blob': ledger_blob, 'admission': admission, 'protected_configs': protected,
            'protected_sources': sources}


def _unchanged(ctx, phase_files):
    c, w = ctx['c'], ctx['w']
    for role, (path, unused_digest) in ctx['paths'].items():
        require(w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON) == ctx['retained'][role],
                'historical anchor changed: ' + role)
    for path, raw in phase_files.items():
        require(w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON) == raw, 'adoption input changed')
    require(all(sha(w.read_protected(path, mode=0o600)) == digest
                for path, digest in ctx['protected_configs'].items()), 'configuration changed')
    require(all(sha(w.read_protected(path)) == digest for path, digest in ctx['protected_sources'].items()),
            'protected executable changed')


def _phase_files(ctx, phase, intent_sha256):
    c, rt, w = ctx['c'], ctx['rt'], ctx['w']
    require(phase in ('before', 'after'), 'unknown adoption health phase')
    files = {STATE: w.read_protected(STATE, mode=0o600, max_bytes=c.MAX_JSON)}
    state = c.json_object(files[STATE])
    if phase == 'before':
        require(sha(files[STATE]) == BASELINE_STATE_SHA, 'before state is not the certified baseline')
        rt.validate_state(state)
        if intent_sha256 is None:
            return files, state, OLD_PINS_SHA
    require(type(intent_sha256) is str and HEX.fullmatch(intent_sha256), 'after observation requires exact intent identity')
    for name in ('state-before.json', 'pins-before.json', 'intent.json'):
        files[OPS / name] = w.read_protected(OPS / name, mode=0o600, max_bytes=c.MAX_JSON)
    require(sha(files[OPS / 'intent.json']) == intent_sha256, 'durable intent digest differs')
    before, expected, pins = expected_transition(files[OPS / 'state-before.json'])
    artifacts = artifact_manifest(pins)
    intent = c.json_object(files[OPS / 'intent.json'])
    require(canonical(intent) == files[OPS / 'intent.json'], 'intent is not canonical')
    validate_intent(intent, files[OPS / 'state-before.json'], files[OPS / 'pins-before.json'], artifacts)
    for field, name in (('deployment_sha256', 'deployment.json'), ('recipe_sha256', 'run.py'),
                        ('engine_sha256', 'transaction.py'), ('health_sha256', 'health.py')):
        path = OPS / name
        files[path] = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
        require(sha(files[path]) == intent['provenance'][field], 'adoption provenance source differs')
    deployment = c.json_object(files[OPS / 'deployment.json'])
    payloads = {}
    for name in ('expected-state-before.json', 'expected-pins-before.json', 'controller-candidate.py',
                 'verifier-candidate.py', 'scanner-candidate.py', 'health.py', 'transaction.py', 'run.py'):
        path = OPS / name
        files[path] = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
        payloads[name] = files[path]
    validate_deployment(deployment, intent, payloads)
    if phase == 'before':
        # The transaction engine validates absent-or-exact partial installs.
        # This old-state health check must not require all targets to exist.
        return files, state, OLD_PINS_SHA
    for role, pin in artifacts.items():
        path = TRUST / pin['path']
        raw = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
        require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'],
                'installed adoption artifact differs: ' + role)
        files[path] = raw
    require(files[STATE] == canonical(expected) and files[NEW_PINS] == canonical(pins),
            'current state or pins exceed the reviewed binding delta')
    new = exact_module(NEW_CONTROLLER, NEW_CONTROLLER_SHA, 'bounded_adoption_installed_controller')
    require(new.PINS == NEW_PINS and new.VERIFIER == NEW_VERIFIER and new.STATE_ROOT == c.STATE_ROOT
            and new.LIMITS == c.LIMITS == LIMITS and new.MAX_REWRITES == 5 and new.MAX_GENERATION == 9,
            'new controller changes scope or limits')
    new_rt = new.Runtime()  # Validation only: never use its host, lock or profile for helper calls.
    require(new_rt.load_state() == expected and new_rt.binding == expected['binding'] and new_rt.pins == pins,
            'new runtime does not accept the exact reviewed state binding')
    require(state['checkpoint'] == ctx['cert'], 'certificate changed during adoption')
    return files, state, sha(canonical(pins))


def observe(ctx, *, phase, authenticated_rc=True, intent_sha256=None):
    f, c, rt, w, old, rc = (ctx[k] for k in ('f', 'c', 'rt', 'w', 'old', 'rc'))
    require(rt.host.locked and not rt.stop_present(), 'health observation requires idle protected lock')
    files, state, pins_sha = _phase_files(ctx, phase, intent_sha256)
    _unchanged(ctx, files)
    writer = old.writer_absent(rt)
    expected_reader = ctx['done']['reader']['process']
    reader = old.reader_observation(rt, expected_reader['pid'])
    require(reader['process'] == expected_reader, 'restored reader identity changed')
    old.no_other_lab_users(rt, expected_reader['pid'])
    before = rc.production_observation(rt, old)
    f.same_production(ctx['done']['production'], before, w)
    disk = None
    if authenticated_rc:
        helper = rc.exact_module(rc.HELPER, rc.HELPER_SHA256, 'bounded_adoption_authenticated_rc', protected=False)
        require(helper.API == rc.API and helper.CLIENT == rc.CLIENT, 'RC helper scope differs')
        w.secure_path(rc.CLIENT, leaf_mode=0o600)
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}), rc.NoRedirect()))
        stats = helper.call_rc('vfs/stats', {'fs': rc.FS}, client=rc.CLIENT)
        queue = helper.call_rc('vfs/queue', {'fs': rc.FS}, client=rc.CLIENT)
        rc.validate_rc(stats, queue)
        w.clean_queue(stats, queue)
        disk = {k: stats['diskCache'][k] for k in
                ('bytesUsed', 'uploadsQueued', 'uploadsInProgress', 'erroredFiles', 'outOfSpace')}
    after = rc.production_observation(rt, old)
    f.same_production(before, after, w)
    require(old.reader_observation(rt, expected_reader['pid'])['process'] == expected_reader,
            'reader changed during health observation')
    old.writer_absent(rt)
    require(rt.profile.cache.is_dir() and old.READER_CACHE.is_dir(), 'retained cache directory missing')
    require(not rt.stop_present(), 'stop sentinel appeared')
    _unchanged(ctx, files)
    return {'schema': 1, 'scope': HEALTH_SCOPE, 'phase': phase, 'observed_unix': time.time(),
            'generation': 9, 'rewrites': 5, 'state': c.checkpoint_state(ctx['cert']),
            'state_sha256': sha(files[STATE]), 'pins_sha256': pins_sha,
            'baseline_state_sha256': BASELINE_STATE_SHA, 'checkpoint_sha256': CERT_SHA,
            'pacing_bundle_sha256': BUNDLE_SHA, 'intent_sha256': intent_sha256,
            'reader_process': reader['process'], 'writer_mount_and_socket_absent': True,
            'writer': {k: writer[k] for k in ('ActiveState', 'SubState', 'MainPID', 'Result', 'ExecMainStatus')},
            'reader_and_writer_caches_retained': True, 'free_bytes': rt.free_bytes(),
            'production_service_process': after['production_process'],
            'production_rc_process': after['rc_server']['process'],
            'production_identity_sha256': c.digest(after), 'production_rc_identity_sha256': c.digest(after['rc_server']),
            'kubo_and_walker_inactive': True, 'walker_unit_file_state': after['walker_unit_file_state'],
            'production_rc_checked': authenticated_rc, 'production_disk_cache': disk,
            'protected_anchors_unchanged': True}


def validate_completed(completed, intent, intent_sha256):
    require(type(completed) is dict and set(completed) == COMPLETED_KEYS, 'completion schema differs')
    expected = {'schema': 1, 'scope': COMPLETED_SCOPE, 'intent_sha256': intent_sha256,
                'generation': 9, 'rewrites': 5, 'checkpoint_sha256': CERT_SHA,
                'state_sha256': intent['new_state_sha256'], 'pins_sha256': intent['new_pins_sha256'],
                'artifacts': intent['artifacts'], 'database_writer_invoked': False, 'pebble_open_performed': False}
    require(all(type(completed.get(k)) is type(v) and completed[k] == v for k, v in expected.items()),
            'completion differs from the exact intended adoption')
    require(finite_number(completed['completed_unix']) and completed['completed_unix'] >= intent['started_unix']
            and type(completed['resumed']) is bool and type(completed['state_replaced_this_run']) is bool,
            'completion timing or resume flags differ')
    validate_guard_summary(completed['after'], phase='after', state_sha=intent['new_state_sha256'],
                           pins_sha=intent['new_pins_sha256'])
    require(completed['after'].get('intent_sha256') == intent_sha256, 'after guard intent differs')
    require(all(completed['after'].get(k) == intent['before'].get(k) for k in
                ('state', 'reader_process', 'production_service_process', 'production_rc_process')),
            'adoption changed the database or existing process identities')
    verification = completed['verification']
    require(type(verification) is dict and set(verification) == {
        'schema', 'verified', 'attempt', 'path', 'checkpoint_sha256', 'semantic_projection_sha256',
        'result_sha256', 'metrics_sha256', 'receipt_sha256'}, 'verification reference schema differs')
    require(type(verification['schema']) is int and verification['schema'] == 1
            and verification['verified'] is True and type(verification['attempt']) is int
            and 1 <= verification['attempt'] <= 999999
            and verification['path'] == f"acceptance/{verification['attempt']:06d}"
            and verification['checkpoint_sha256'] == CERT_SHA
            and verification['semantic_projection_sha256'] == PROJECTION_SHA
            and all(type(verification[k]) is str and HEX.fullmatch(verification[k])
                    for k in ('result_sha256', 'metrics_sha256', 'receipt_sha256')),
            'verification reference is not the exact accepted checkpoint')
    return verification


def validate_acceptance(ctx, blobs, adoption, completed, verification):
    """Reconcile the retained acceptance chain; this performs no remote reads."""
    c = ctx['c']
    records = {name: c.json_object(raw) for name, raw in blobs.items()}
    require(all(canonical(records[name]) == raw for name, raw in blobs.items()),
            'acceptance evidence is not canonical')
    intent, done, measurement, result = (records[name] for name in
                                        ('intent.json', 'completed.json', 'metrics.json', 'result.json'))
    adoption_sha = completed['intent_sha256']
    common = {'schema': 1, 'attempt': verification['attempt'], 'adoption_intent_sha256': adoption_sha,
              'source_commit': adoption['provenance']['source_commit'],
              'state_sha256': adoption['new_state_sha256'], 'checkpoint_sha256': CERT_SHA,
              'parent_checkpoint_sha256': ctx['cert']['previous_checkpoint_sha256'],
              'code_sha256': {role: pin[1] for role, pin in HELPERS.items()},
              'installed_sources': {role: pin['sha256'] for role, pin in adoption['artifacts'].items()},
              'mode': 'final', 'workers': 4, 'max_pages': 512, 'max_received_rows': 500_000,
              'soft_deadline_seconds': 420, 'address_space_limit_bytes': 2 * 1024**3,
              'database_writer_invoked': False, 'pebble_open_performed': False,
              'checkpoint_replacement_permitted': False}
    require(set(intent) == set(common) | {'scope', 'started_unix', 'retained_inputs', 'host_before'}
            and intent['scope'] == ACCEPTANCE_SCOPE + '-intent'
            and all(type(intent.get(k)) is type(v) and intent[k] == v for k, v in common.items()),
            'acceptance intent differs from installed adoption')
    roles = {'000008-step-certificate', '000009-step-certificate', '000009-step-writer',
             '000009-step-created-sst-hashes', 'immutable-baseline-ledger'}
    roles.update('000009-snapshot-' + name for name in ctx['cert']['remote_metadata'])
    expected_refs = {role: {k: ctx['bundle']['evidence'][role][k] for k in ('path', 'sha256', 'bytes')}
                     for role in roles}
    require(intent['retained_inputs'] == expected_refs and len(expected_refs) == 13,
            'acceptance retained input identities differ')
    extra = {'completed_unix', 'intent_sha256', 'result_sha256', 'metrics_sha256', 'verified',
             'semantic_projection_sha256', 'host_after', 'wall_seconds', 'overall_seconds',
             'checkpoint_replaced', 'workers_drained', 'sdk_clients_closed'}
    require(set(done) == set(intent) | extra and done['scope'] == ACCEPTANCE_SCOPE + '-completed'
            and all(type(done.get(k)) is type(v) and done[k] == v for k, v in intent.items() if k != 'scope'),
            'acceptance completion does not preserve its intent')
    links = {'intent_sha256': sha(blobs['intent.json']), 'result_sha256': verification['result_sha256'],
             'metrics_sha256': verification['metrics_sha256'], 'semantic_projection_sha256': PROJECTION_SHA,
             'verified': True, 'workers_drained': True, 'sdk_clients_closed': True, 'checkpoint_replaced': False}
    require(all(type(done.get(k)) is type(v) and done[k] == v for k, v in links.items()),
            'acceptance completion linkage or lifecycle flags differ')
    require(set(measurement) == {'schema', 'scope', 'attempt', 'adoption_intent_sha256', 'metrics',
                               'enumeration', 'listing_guard', 'sdk', 'invocation', 'process_peak_rss_kib'}
            and type(measurement['schema']) is int and measurement['schema'] == 1
            and measurement['scope'] == ACCEPTANCE_SCOPE + '-metrics'
            and type(measurement['attempt']) is int and measurement['attempt'] == verification['attempt']
            and measurement['adoption_intent_sha256'] == adoption_sha, 'acceptance metrics identity differs')
    interval = measurement['invocation']
    require(type(interval) is dict and set(interval) == {'started_unix', 'finished_unix'}
            and all(finite_number(value) for value in interval.values())
            and finite_number(intent['started_unix']) and finite_number(done['completed_unix'])
            and adoption['started_unix'] <= intent['started_unix'] <= interval['started_unix']
            <= interval['finished_unix'] <= done['completed_unix'] <= completed['completed_unix'],
            'acceptance invocation timing differs')
    require(finite_number(done['wall_seconds']) and finite_number(done['overall_seconds'])
            and done['wall_seconds'] == measurement['metrics']['wall_seconds']
            and done['overall_seconds'] >= done['wall_seconds'], 'acceptance timing summary differs')
    require(type(measurement['process_peak_rss_kib']) is int and measurement['process_peak_rss_kib'] > 0,
            'acceptance RSS observation differs')
    for observation in (intent['host_before'], done['host_after']):
        validate_guard_summary(observation, phase='after', state_sha=adoption['new_state_sha256'],
                               pins_sha=adoption['new_pins_sha256'])
        require(observation.get('intent_sha256') == adoption_sha
                and all(observation.get(k) == completed['after'].get(k) for k in
                        ('state', 'reader_process', 'production_service_process', 'production_rc_process')),
                'acceptance changed host or checkpoint identities')
    require(finite_number(result.get('verified_unix')) and result.get('pebble_reopen_verified') is False
            and interval['started_unix'] <= result['verified_unix'] <= interval['finished_unix'],
            'acceptance result timestamp or reopen flag differs')
    projection = {k: v for k, v in result.items() if k != 'verified_unix'}
    reference = {k: v for k, v in ctx['cert'].items()
                 if k not in {'generation', 'reopen', 'reopen_scope', 'verified_unix'}}
    reference['pebble_reopen_verified'] = False
    require(projection == reference and sha(canonical(projection)) == PROJECTION_SHA,
            'retained acceptance result differs from the certified semantic projection')
    return measurement


def check_completed(ctx):
    """Permanent read-only check; incomplete transitions are never accepted here."""
    c, w, rt = ctx['c'], ctx['w'], ctx['rt']
    require(rt.host.locked, 'completed adoption check requires the protected lock')
    raw = w.read_protected(OPS / 'completed.json', mode=0o600, max_bytes=c.MAX_JSON)
    done = c.json_object(raw)
    require(canonical(done) == raw, 'adoption completion is not canonical')
    intent_raw = w.read_protected(OPS / 'intent.json', mode=0o600, max_bytes=c.MAX_JSON)
    intent = c.json_object(intent_raw)
    intent_sha = sha(intent_raw)
    observation = observe(ctx, phase='after', intent_sha256=intent_sha)
    verification = validate_completed(done, intent, intent_sha)
    require(all(observation.get(k) == done['after'].get(k) for k in
                ('state', 'reader_process', 'production_service_process', 'production_rc_process')),
            'completed adoption process identities or database state changed')
    proof_files, protected_proofs = {}, {}
    for field, name in (('result_sha256', 'result.json'), ('metrics_sha256', 'metrics.json'),
                        ('receipt_sha256', 'completed.json')):
        path = OPS / verification['path'] / name
        blob = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
        require(sha(blob) == verification[field], 'retained acceptance proof differs')
        proof_files[name] = blob
        protected_proofs[path] = blob
    path = OPS / verification['path'] / 'intent.json'
    proof_files['intent.json'] = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
    protected_proofs[path] = proof_files['intent.json']
    failed = OPS / verification['path'] / 'failure.json'
    require(not failed.exists() and not failed.is_symlink(), 'accepted attempt also has a failure receipt')
    measurement = validate_acceptance(ctx, proof_files, intent, done, verification)
    helper_path, helper_sha = HELPERS['comparison']
    comparison = exact_module(helper_path, helper_sha, 'bounded_adoption_retained_metrics')
    comparison.validate_pass(measurement['metrics'], measurement['enumeration'],
                             measurement['listing_guard'], candidate=True)
    require(w.read_protected(OPS / 'completed.json', mode=0o600, max_bytes=c.MAX_JSON) == raw
            and w.read_protected(OPS / 'intent.json', mode=0o600, max_bytes=c.MAX_JSON) == intent_raw,
            'adoption completion changed during observation')
    phase_files, unused_state, unused_pins = _phase_files(ctx, 'after', intent_sha)
    phase_files.update(protected_proofs)
    _unchanged(ctx, phase_files)
    return dict(observation, completed_sha256=sha(raw), verification=verification)


def main():
    require(sys.argv[1:] == ['--check'], 'explicit completed-adoption check required')
    ctx = load()
    with ctx['rt'].lock():
        print(json.dumps(check_completed(ctx)), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Bounded adoption health check did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
