#!/usr/bin/env python3
"""Read-only host/checkpoint guard for the separately receipted gen9 timing probe."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types
import urllib.request

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'verification-profile-20261105'
INSTALL = OPS / 'health.py'
FINALIZER = TRUST / 'pacing-20261104/finalize.py'
FINALIZER_SHA = '3e522bae660ded45fb0160e122fd46c711fd5460b9b5b4d1e9234ae0786ebad2'
STATE_SHA = '7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1'
CERT_SHA = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
BUNDLE_SHA = 'accbfa2151490cef4dcba979ff3c5ad89f07923a105586c648d008720bf1b51e'
COMPLETION_SHA = 'e2cbae5c26f9b757321146edc94e9459b9cd7de2f82ea52605efec9ad84078f5'
ADMISSION_SHA = 'a7a4b918549d24a4988259e8cf43091ec8267f8e9f7a1ffcfecf9cea2647e8ec'
PINS_SHA = '0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_module(path, digest, name):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'source path differs')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'source path is not protected')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, 'source file mode/type differs')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        raw = stream.read(16 * 1024**2 + 1)
    require(len(raw) <= 16 * 1024**2 and sha(raw) == digest, 'source digest differs')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def load():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root installation required')
    f = exact_module(FINALIZER, FINALIZER_SHA, 'profile_health_finalizer')
    c, unused_wrapper, unused_verifier, old, rc = f.bootstrap()
    rt = c.Runtime()
    w, v = rt.wrapper, rt.verifier
    w.secure_path(INSTALL, leaf_mode=0o600)
    w.secure_path(OPS, leaf_mode=0o700)
    paths = {
        'state': (c.STATE_ROOT / 'state.json', STATE_SHA),
        'certificate': (c.STATE_ROOT / 'checkpoints/000009-step.json', CERT_SHA),
        'completion': (f.EVIDENCE / 'completed.json', COMPLETION_SHA),
        'bundle': (f.OPS / 'pacing-certified.json', BUNDLE_SHA),
        'admission': (w.ADMISSIONS / 'full-clone.json', ADMISSION_SHA),
        'pins': (c.PINS, PINS_SHA),
    }
    retained = {}
    for role, (path, digest) in paths.items():
        raw = w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON)
        require(sha(raw) == digest, 'protected anchor differs: ' + role)
        retained[role] = raw
    state, cert = (c.json_object(retained[k]) for k in ('state', 'certificate'))
    c.require(state['generation'] == 9 and state['rewrites'] == 5 and state['pending'] is None,
              'generation-nine checkpoint is not idle')
    rt.validate_state(state)
    require(state['checkpoint'] == cert and c.digest(cert) == CERT_SHA, 'certificate/state disagreement')
    done, bundle = (c.json_object(retained[k]) for k in ('completion', 'bundle'))
    require(done['state_sha256'] == STATE_SHA and done['checkpoint_sha256'] == CERT_SHA
            and bundle['state_sha256'] == STATE_SHA and bundle['checkpoint_sha256'] == CERT_SHA,
            'final receipts bind another checkpoint')
    binary = w.read_protected(w.RCLONE)
    config = w.read_protected(w.CONFIG, mode=0o600)
    ledger_blob = w.read_protected(w.LEDGER)
    require(sha(binary) == w.RCLONE_SHA256 and sha(ledger_blob) == v.LEDGER_SHA256,
            'rclone or immutable ledger differs')
    rt.host.fingerprints = tuple(sha(raw) for raw in (binary, config, ledger_blob))
    admission = rt.host.read_admission(rt.profile)
    require(admission == c.json_object(retained['admission']), 'admission differs')
    protected = {path: sha(w.read_protected(path, mode=0o600)) for path in (w.CONFIG, old.READER_CONFIG)}
    sources = {c.TRUST / 'run_rhea_full_clone_steps.py': f.CONTROLLER_SHA,
               c.WRAPPER: f.WRAPPER_SHA, c.VERIFIER: f.VERIFIER_SHA, c.TOOL: f.GO_SHA,
               TRUST / 'verify_rhea_lab_format3.py': f.DECODER_SHA,
               old.INSPECTOR: f.INSPECTOR_SHA, FINALIZER: FINALIZER_SHA}
    require(all(sha(w.read_protected(path)) == digest for path, digest in sources.items()),
            'protected executable differs')
    return {'f': f, 'c': c, 'rt': rt, 'w': w, 'v': v, 'old': old, 'rc': rc,
            'paths': paths, 'retained': retained, 'state': state, 'cert': cert,
            'done': done, 'bundle': bundle, 'ledger_blob': ledger_blob,
            'admission': admission, 'protected_configs': protected, 'protected_sources': sources}


def observe(ctx, *, authenticated_rc=True):
    f, c, rt, w, old, rc = (ctx[k] for k in ('f', 'c', 'rt', 'w', 'old', 'rc'))
    require(rt.host.locked and not rt.stop_present(), 'probe requires idle protected lock')
    for role, (path, digest) in ctx['paths'].items():
        require(w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON) == ctx['retained'][role],
                'protected anchor changed: ' + role)
    require(all(sha(w.read_protected(path, mode=0o600)) == digest
                for path, digest in ctx['protected_configs'].items()), 'configuration changed')
    writer = old.writer_absent(rt)
    expected_reader = ctx['done']['reader']['process']
    reader = old.reader_observation(rt, expected_reader['pid'])
    require(reader['process'] == expected_reader, 'restored reader identity changed')
    old.no_other_lab_users(rt, expected_reader['pid'])
    before = rc.production_observation(rt, old)
    f.same_production(ctx['done']['production'], before, w)
    disk = None
    if authenticated_rc:
        helper = rc.exact_module(rc.HELPER, rc.HELPER_SHA256, 'profile_health_authenticated_rc', protected=False)
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
    for role, (path, digest) in ctx['paths'].items():
        require(w.read_protected(path, mode=0o600, max_bytes=c.MAX_JSON) == ctx['retained'][role],
                'protected anchor changed during observation: ' + role)
    require(all(sha(w.read_protected(path, mode=0o600)) == digest
                for path, digest in ctx['protected_configs'].items()), 'configuration changed during observation')
    require(all(sha(w.read_protected(path)) == digest for path, digest in ctx['protected_sources'].items()),
            'protected executable changed during observation')
    return {'schema': 1, 'scope': 'generation-nine-read-only-probe-host-health', 'observed_unix': time.time(),
            'generation': 9, 'rewrites': 5, 'state': c.checkpoint_state(ctx['cert']),
            'state_sha256': STATE_SHA, 'checkpoint_sha256': CERT_SHA, 'pacing_bundle_sha256': BUNDLE_SHA,
            'reader_process': reader['process'], 'writer_mount_and_socket_absent': True,
            'writer': {k: writer[k] for k in ('ActiveState', 'SubState', 'MainPID', 'Result', 'ExecMainStatus')},
            'reader_and_writer_caches_retained': True, 'free_bytes': rt.free_bytes(),
            'production_service_process': after['production_process'],
            'production_rc_process': after['rc_server']['process'],
            'production_identity_sha256': c.digest(after), 'production_rc_identity_sha256': c.digest(after['rc_server']),
            'kubo_and_walker_inactive': True, 'walker_unit_file_state': after['walker_unit_file_state'],
            'production_rc_checked': authenticated_rc, 'production_disk_cache': disk,
            'protected_anchors_unchanged': True}


def write_new(ctx, path, value):
    rt, c, w = (ctx[k] for k in ('rt', 'c', 'w'))
    require(path.parent == OPS, 'receipt destination outside probe directory')
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
    require(sys.argv[1:] == ['--check'], 'explicit read-only check required')
    ctx = load()
    with ctx['rt'].lock():
        result = observe(ctx)
        digest = write_new(ctx, OPS / 'health-before.json', result)
        print(json.dumps({'receipt': result, 'sha256': digest}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Read-only health check did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
