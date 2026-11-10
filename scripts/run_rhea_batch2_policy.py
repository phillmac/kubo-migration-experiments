#!/usr/bin/env python3
"""Fixed generation-nine second-batch policy adapter; no database/service action.

Only --apply or explicit --resume installs the reviewed successor controller and
its pins, then atomically activates the exact controller/hash and cap5-to9 journal
change. Existing sources, pins and checkpoint9 remain untouched. The original
Runtime owns the lifecycle lock and host/Profile pair throughout; the new health
module checks the restored reader/production identities and retained proof before
and after. There is no SDK client, S3 proof callback, Go invocation or mount change.
Root stages the fixed namespace after source review/CI and owns supervision.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'pacing-batch2-20261107'
INSTALL = OPS / 'run.py'
STATE = TRUST / 'full-clone-steps/state.json'
PARENT_COMMIT = '10a088d5f3de8e3c1e555e6b1848f224dbd79451'
DEPLOYMENT_SCOPE = 'fixed-generation-nine-batch2-policy-deployment'
PAYLOAD_NAMES = frozenset(('run.py', 'health.py', 'transaction.py', 'mounts.py', 'one-step.py',
    'controller-candidate.py', 'expected-state-before.json', 'expected-pins-before.json'))
OLD_STATE_SHA256 = '22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2'
NEW_STATE_SHA256 = '0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9'
OLD_PINS_SHA256 = '684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c'
NEW_PINS_SHA256 = '1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363'
CONTROLLER_SHA256 = 'b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828'
ENGINE_SHA256 = 'ce38f0b38da8f7824af42685cb57b17f89f75c64a30d5cf931cfd115dca19723'
HEALTH_SHA256 = '2781718c06389a0753cc23b6ff39d97bac388f492399dbb1bb637d57dbf4db1e'
TARGETS = {'controller': TRUST / 'run_rhea_full_clone_steps_batch2.py',
           'pins': TRUST / 'full-clone-batch2-step-pins.json'}
TARGET_HASHES = {'controller': CONTROLLER_SHA256, 'pins': NEW_PINS_SHA256}
RECEIPTS = frozenset(('state-before.json', 'pins-before.json', 'intent.json', 'completed.json'))
FIXED_PAYLOAD_HASHES = {
    'controller-candidate.py': CONTROLLER_SHA256,
    'expected-state-before.json': OLD_STATE_SHA256,
    'expected-pins-before.json': OLD_PINS_SHA256,
    'transaction.py': ENGINE_SHA256,
    'health.py': HEALTH_SHA256,
}
MAX_FILE = 16 * 1024**2


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
        require(type(raw) is bytes and sha(raw) == TARGET_HASHES[role], 'fixed install bytes differ')
        return immutable_write(TARGETS[role], raw)

    def replace_state(self, expected_raw, new_raw):
        require(self.ctx['rt'].host.locked, 'state activation requires the original host lock')
        self.unchanged()
        require(type(expected_raw) is type(new_raw) is bytes
                and sha(expected_raw) == OLD_STATE_SHA256 and sha(new_raw) == NEW_STATE_SHA256,
                'fixed state transition bytes differ')
        require(self.state_bytes() == expected_raw, 'state activation preimage differs')
        protected(STATE.parent, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix='.batch2-policy-', dir=STATE.parent)
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
        require(type(expected_raw) is bytes and sha(expected_raw) == NEW_STATE_SHA256,
                'fixed state reseal bytes differ')
        require(self.state_bytes() == expected_raw, 'state reseal endpoint differs')
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_dir(STATE.parent)
        require(self.state_bytes() == expected_raw, 'state changed during reseal')

    def observe(self, phase, intent_sha256=None):
        require(phase in ('policy-before', 'policy-after'), 'unknown fixed policy phase')
        self.unchanged()
        return self.health.observe(self.ctx, phase=phase, authenticated_rc=True,
                                   intent_sha256=intent_sha256)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in ('--check', '--apply', '--resume'),
            'explicit fixed policy action required')
    action = sys.argv[1][2:]
    raw, deployment, payloads = load_deployment()
    pins = deployment['payloads']
    health = exact_module(OPS / 'health.py', pins['health.py']['sha256'], 'batch2_policy_health')
    engine = exact_module(OPS / 'transaction.py', pins['transaction.py']['sha256'], 'batch2_policy_transaction')
    ctx = health.load()
    provenance = {'schema': 1, 'source_commit': deployment['source_commit'], 'deployment_sha256': sha(raw),
        'recipe_sha256': pins['run.py']['sha256'], 'engine_sha256': pins['transaction.py']['sha256'],
        'health_sha256': pins['health.py']['sha256']}
    plan = engine.build_plan(payloads['expected-state-before.json'], payloads['expected-pins-before.json'],
                             {'controller': payloads['controller-candidate.py']}, provenance)
    adapter = Adapter(health, ctx, raw, deployment, payloads)
    result = engine.Transaction(adapter, plan).run(action)
    completed = result.get('scope') == engine.COMPLETED_SCOPE or result.get('phase') == 'completed'
    summary = {'completed': completed, 'action': action, 'phase': result.get('phase', 'completed'),
               'state_sha256': result['state_sha256'], 'database_writer_invoked': False,
               'pebble_open_performed': False, 'service_action_performed': False}
    if completed:
        summary.update(pins_sha256=NEW_PINS_SHA256,
            completed_sha256=result.get('completed_sha256') or sha(canonical(result)))
    try:
        print(json.dumps(summary), flush=True)
    except OSError:
        pass  # A failed diagnostic sink cannot undo a durable completion.


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Batch2 policy did not complete (' + type(exc).__name__
              + '). Inspect retained evidence before an explicit resume.', file=sys.stderr)
        raise SystemExit(1) from None
