#!/usr/bin/env python3
"""Root-only, pinned read-only host observations. NOT DEPLOYED / NOT LIVE TESTED.

No installation, service change, writer, drain, publication or recovery execution
is implemented. CLI refuses even observations until independent host review.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import stat
import sys
import time
import types

import rhea_multi_sst_signed_admission as a

INSTALL = a.INSTALL
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
WRAPPER = TRUST / 'rhea_wasabi_lab_mount.py'
WRAPPER_SHA256 = '76635430d99daa65a816dc1ae444145bbdfe844559b4b4bed2e30fbae0302545'
LEGACY_JOURNAL = TRUST / 'full-clone-steps/state.json'
LEGACY_PINS = TRUST / 'full-clone-batch2-step-pins.json'
LEGACY_PINS_SHA256 = '1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363'
BASE_COMMIT = '5e3130097c1f02de944bf17403912fcb3b365537'
VERSION = 'rhea-multi-sst-root-host-v2.1'
PROVISION_PUBLIC_KEY = INSTALL / 'deployment.pub'
# No automatic provisioning or installed-test escape hatch. Independent review
# must supply independently signed deployment/installation bytes and key pins.
PROVISION_PUBLIC_KEY_SHA256 = None
PROVISION_KEY_NOT_BEFORE = None
PROVISION_KEY_NOT_AFTER = None
ARTIFACTS = {
    'controller': ('rhea_multi_sst_checkpoint_controller.py', 0o600),
    'recovery': ('rhea_multi_sst_recovery_inspector.py', 0o600),
    'adapter': ('rhea_multi_sst_root_host_adapter.py', 0o600),
    'signed_admission': ('rhea_multi_sst_signed_admission.py', 0o600),
    'writer': ('writer', 0o700),
    'admission_key': ('admission.pub', 0o600),
}
HISTORICAL_ARTIFACTS = {
    'controller': 'a1052de93dfec5e839ff0f3ff44b54f51d67c31fc2bc89f0c49f41e34d706f7d',
    'recovery': 'df8a75787e5c232d05fee37edd4458faec8b5022daaddcdac971bb79bdcb6f5f',
}


def _object(raw):
    """Historical JSON need not have this new signing format's canonical bytes."""
    import json
    def unique(pairs):
        result = {}
        for key, value in pairs:
            a.require(key not in result, 'duplicate historical key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: a.require(False, 'nonfinite historical JSON'))
    a.require(type(value) is dict, 'historical object required')
    return value


def _pins_from_controller(raw):
    values = [node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == 'SOURCE_PINS' for target in node.targets)]
    a.require(len(values) == 1, 'frozen source table missing')
    pins = ast.literal_eval(values[0])
    a.require(type(pins) is dict and pins and all(type(k) is str and type(v) is str
              and a.HEX.fullmatch(v) for k, v in pins.items()), 'invalid frozen source table')
    return pins


def _signed_manifest(raw, signature, key, *, scope, now):
    value = a.parse(raw)
    a.require(value.get('scope') == scope, 'manifest scope mismatch')
    a.verify_detached(raw, signature, key, key_sha256=PROVISION_PUBLIC_KEY_SHA256,
                      domain=a.DEPLOYMENT_DOMAIN)
    a.require(all(type(v) is int for v in (value.get('issued'), value.get('expires'),
                  PROVISION_KEY_NOT_BEFORE, PROVISION_KEY_NOT_AFTER))
              and PROVISION_KEY_NOT_BEFORE <= value['issued'] <= now < value['expires'] <= PROVISION_KEY_NOT_AFTER,
              'future/expired deployment/installation/key')
    return value


def validate_installation():
    """Read fixed root paths and verify independent signatures before imports.

    Both manifests must be independently issued. Signatures authorize their
    contents; each artifact is then checked against its signed exact byte pin.
    No manifest digest is embedded in an artifact it hashes (no circular pins).
    """
    a.require(os.geteuid() == 0 and socket.gethostname().split('.')[0].lower() == 'rhea', 'root on Rhea required')
    a.require(Path(__file__).absolute() == INSTALL / ARTIFACTS['adapter'][0]
              and Path(a.__file__).absolute() == INSTALL / ARTIFACTS['signed_admission'][0], 'fixed installed module paths required')
    a.require(all(value is not None for value in (PROVISION_PUBLIC_KEY_SHA256,
              PROVISION_KEY_NOT_BEFORE, PROVISION_KEY_NOT_AFTER,
              a.PUBLIC_KEY_SHA256, a.KEY_NOT_BEFORE, a.KEY_NOT_AFTER)),
              'independent deployment, installation and key provisioning absent')
    with a.protected_directory(INSTALL, private=True):
        pass
    key = a.protected_read(PROVISION_PUBLIC_KEY)
    a.require(a.sha(key) != a.PUBLIC_KEY_SHA256, 'separate deployment and admission keys required')
    now = int(time.time())
    deployment_raw = a.protected_read(INSTALL / 'deployment.json')
    installation_raw = a.protected_read(INSTALL / 'installation.json')
    deployment = _signed_manifest(deployment_raw,
        a.protected_read(INSTALL / 'deployment.sig', limit=64), key,
        scope='rhea-root-deployment-v1', now=now)
    installation = _signed_manifest(installation_raw,
        a.protected_read(INSTALL / 'installation.sig', limit=64), key,
        scope='rhea-root-installation-v1', now=now)
    common = {'schema', 'scope', 'issued', 'expires', 'host', 'boot_id', 'install', 'base_commit',
              'artifacts', 'source_pins_sha256', 'legacy_journal_sha256'}
    a.require(set(deployment) == common and set(installation) == common | {'deployment_sha256'}, 'manifest schema mismatch')
    for value in (deployment, installation):
        a.require(type(value['schema']) is int and value['schema'] == 1 and value['host'] == 'rhea'
                  and value['install'] == str(INSTALL) and value['base_commit'] == BASE_COMMIT
                  and value['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'deployment host/boot/source binding mismatch')
        a.require(set(value['artifacts']) == set(ARTIFACTS)
                  and all(type(pin) is str and a.HEX.fullmatch(pin) for pin in value['artifacts'].values()),
                  'complete artifact pins required')
        for field in ('source_pins_sha256', 'legacy_journal_sha256'):
            a.require(type(value[field]) is str and a.HEX.fullmatch(value[field]), 'manifest digest missing')
    a.require(installation['deployment_sha256'] == a.sha(deployment_raw)
              and installation['issued'] >= deployment['issued']
              and all(installation[k] == deployment[k] for k in common - {'scope', 'issued', 'expires'}),
              'installation/deployment mismatch')
    for role, (name, mode) in ARTIFACTS.items():
        a.require(a.sha(a.protected_read(INSTALL / name, mode=mode, limit=32 * 1024**2))
                  == deployment['artifacts'][role], 'installed artifact mismatch: ' + role)
    a.require(all(deployment['artifacts'][role] == pin for role, pin in HISTORICAL_ARTIFACTS.items()),
              'historical controller/inspector bytes changed')
    a.require(deployment['artifacts']['admission_key'] == a.PUBLIC_KEY_SHA256, 'admission key binding differs')
    controller = a.protected_read(INSTALL / ARTIFACTS['controller'][0])
    pins = _pins_from_controller(controller)
    a.require(a.sha(a.canonical(pins)) == deployment['source_pins_sha256'], 'source table binding mismatch')
    for name, pin in pins.items():
        a.require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'invalid source path')
        a.require(a.sha(a.protected_read(INSTALL / 'sources' / name, limit=32 * 1024**2)) == pin,
                  'installed frozen source mismatch: ' + name)
    a.require(a.sha(a.protected_read(WRAPPER)) == WRAPPER_SHA256, 'historical wrapper pin mismatch')
    return dict(deployment, _deployment_sha256=a.sha(deployment_raw),
                _installation_sha256=a.sha(installation_raw))


def _load_exact(path, pin, name):
    # Execute precisely the validated bytes, never import a second read or pyc.
    raw = a.protected_read(path)
    a.require(a.sha(raw) == pin, 'pinned module changed')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module  # dataclasses needs the module during execution
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def process_identity(pid, expected_executable, boot_id):
    a.require(type(pid) is int and pid > 1, 'missing process PID')
    proc = Path('/proc') / str(pid)
    def start():
        # comm may contain spaces and parentheses; fields after the LAST ')' start at field 3.
        fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        a.require(fields[0] not in ('Z', 'X'), 'dead process')
        return int(fields[19])  # starttime is field 22
    before = start()
    a.require((proc / 'exe').resolve() == expected_executable, 'process executable substituted')
    exe_sha = a.sha(a.protected_read(expected_executable, mode=0o700, limit=32 * 1024**2))
    a.require(start() == before and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id,
              'process/boot changed during identity read')
    return {'pid': pid, 'start_ticks': before, 'boot_id': boot_id, 'exe_sha256': exe_sha}


def queue_health_from_observation(observation, space):
    """Strict clean-queue subset; unknown/malformed counters never mean zero."""
    disk = observation['stats']['diskCache']
    for key in ('bytesUsed', 'uploadsQueued', 'uploadsInProgress', 'erroredFiles'):
        a.require(type(disk.get(key)) is int and disk[key] >= 0, 'missing/invalid RC counter: ' + key)
    a.require(disk.get('outOfSpace') is False and observation['queue'].get('queue') == []
              and all(disk[key] == 0 for key in ('uploadsQueued', 'uploadsInProgress', 'erroredFiles')),
              'queue not clean; byte backlog cannot be proven')
    health = dict(cache_bytes=disk['bytesUsed'], free_bytes=space.f_bavail * space.f_frsize,
                  queue_bytes=0, queue_files=0, errors=0, transferring=0)
    a.require(health['cache_bytes'] <= 96 * 1024**3 and health['free_bytes'] >= 2 * 1024**4,
              'cache/free-space bound exceeded')
    return health


class RootHostAdapter:
    version = VERSION

    def __init__(self):
        # There are no constructor DI parameters, fake hosts or installed test flags.
        self.deployment = validate_installation()
        self.wrapper = _load_exact(WRAPPER, WRAPPER_SHA256, '_rhea_multi_sst_pinned_historical_wrapper')
        self.controller = _load_exact(INSTALL / ARTIFACTS['controller'][0],
            HISTORICAL_ARTIFACTS['controller'], '_rhea_multi_sst_pinned_checkpoint_controller')
        self.host = self.wrapper.RealHost()
        self.profile = self.wrapper.PROFILES['full-clone']
        self._locked = False
        self._admission = None

    def _require_lock(self):
        a.require(self._locked and self.host.locked, 'exclusive RealHost writer lock required')

    @contextmanager
    def exclusive(self):
        a.require(not self._locked, 'nested host lock')
        # RealHost.lock uses /run/rhea-wasabi-lab/writer.lock, O_NOFOLLOW,
        # root 0600, exclusive nonblocking flock; shared with historical writers.
        with self.host.lock():
            self._locked = True
            try:
                yield
            finally:
                self._locked = False
                self._admission = None

    def _legacy(self):
        raw = a.protected_read(LEGACY_JOURNAL, limit=16 * 1024**2)
        a.require(a.sha(raw) == self.deployment['legacy_journal_sha256'], 'exact legacy journal changed')
        state = _object(raw)
        a.require(set(state) == {'schema', 'binding', 'checkpoint', 'generation', 'rewrites', 'pending'}
                  and type(state['generation']) is int and state['generation'] == 13
                  and type(state['rewrites']) is int and state['rewrites'] == 9 and state['pending'] is None
                  and state['binding']['limits']['maximum_rewrites'] == 9
                  and a.sha(a.canonical(state['checkpoint'])) == a.ANCHOR, 'legacy gen13/cap9/pending-null mismatch')
        a.require(a.sha(a.protected_read(LEGACY_PINS)) == LEGACY_PINS_SHA256, 'legacy deployment pins changed')
        return raw

    def observe_host(self):
        """Real locked observations; this is NOT a controller readiness assertion.

        Historical guard verifies protected rclone/config/ledger, frozen units,
        mounts/processes and fresh authenticated STS/bucket versioning identity.
        It does not independently prove all protected production source bytes.
        """
        self._require_lock()
        a.require(validate_installation() == self.deployment, 'deployment changed')
        legacy = self._legacy()
        self.host.guard(self.profile, True)
        self.host.no_open_users(self.profile)
        services = {name: self.host.service(name) for name in
                    (*self.wrapper.PROD_OFF, self.wrapper.PROD_MOUNT, self.wrapper.READER, self.profile.unit)}
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        pid = self.host.unit_identity(self.profile, services[self.profile.unit], active=True)
        process = process_identity(pid, self.wrapper.RCLONE, boot)
        rows = self.wrapper.mount_rows(Path('/proc/self/mountinfo').read_text())
        mounts = [row for row in rows if row['target'] == str(self.profile.mountpoint)]
        a.require(len(mounts) == 1, 'exact mount missing')
        # Include mount ID/device/parent/options lost by the historical parser.
        lines = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                 if len(line.split()) > 4 and line.split()[4] == str(self.profile.mountpoint)]
        a.require(len(lines) == 1, 'exact raw mount identity missing')
        mount = dict(mounts[0], mountinfo=lines[0])
        info = self.profile.rc_socket.lstat()
        a.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
                  and not info.st_mode & 0o077, 'unsafe RC socket')
        observation = self.host.observe(self.profile)  # SO_PEERCRED checked on BOTH RC reads
        a.require(observation['pid'] == pid, 'RC process changed')
        rc = dict(path=str(self.profile.rc_socket), device=info.st_dev, inode=info.st_ino,
                  peer_pid=pid, peer_uid=0, peer_gid=0)
        after = self.profile.rc_socket.lstat()
        a.require((info.st_dev, info.st_ino) == (after.st_dev, after.st_ino), 'RC socket replaced')
        journal = self.host.read_admission(self.profile)
        a.require(journal is not None, 'historical authenticated cloud identity missing')
        health = queue_health_from_observation(observation, os.statvfs(self.profile.cache))
        a.require(process_identity(pid, self.wrapper.RCLONE, boot) == process, 'mount process changed')
        a.require(lines[0] in Path('/proc/self/mountinfo').read_text().splitlines(), 'mount replaced during observation')
        a.require(all(self.host.service(name) == state for name, state in services.items()),
                  'service identity changed during observation')
        self.host.no_open_users(self.profile)
        a.require(a.protected_read(LEGACY_JOURNAL, limit=16 * 1024**2) == legacy, 'legacy changed during observation')
        return dict(host='rhea', boot_id=boot, legacy_journal_sha256=a.sha(legacy), health=health,
                    identities=dict(mount=mount, rc=rc, process=process, cloud=journal['identity'], services=services),
                    protected_source_bytes_proven=False, controller_ready=False)

    def _binding(self, intent, observed):
        self.controller.validate_intent(intent)
        pins = self.deployment['artifacts']
        # Existing intent.admission_sha256 is an authorization descriptor hash,
        # never a hash of claims which themselves hash the full intent.
        descriptor = dict(scope='rhea-gen14-one-batch', deployment_sha256=self.deployment['_deployment_sha256'],
                          installation_sha256=self.deployment['_installation_sha256'])
        a.require(intent['deployment_sha256'] == self.deployment['_deployment_sha256']
                  and intent['admission_sha256'] == a.sha(a.canonical(descriptor))
                  and intent['go_binary_sha256'] == pins['writer']
                  and intent['source_pins_sha256'] == self.deployment['source_pins_sha256']
                  and intent['adapter_version'] == VERSION
                  and intent['previous_checkpoint_sha256'] == a.ANCHOR, 'intent installation mismatch')
        return dict(schema=1, scope='rhea-gen14-one-batch', intent_sha256=a.sha(a.canonical(intent)),
                    anchor=dict(generation=13, cap=9, pending=None, checkpoint_sha256=a.ANCHOR,
                                legacy_journal_sha256=observed['legacy_journal_sha256']),
                    units=intent['unit_count'], host=observed['host'], boot_id=observed['boot_id'],
                    installation=dict(deployment=self.deployment['_deployment_sha256'],
                                      installed_manifest=self.deployment['_installation_sha256'],
                                      writer=pins['writer'], controller=pins['controller'], adapter=pins['adapter'],
                                      signed_admission=pins['signed_admission'], source_pins=intent['source_pins_sha256']),
                    target=dict(bucket=a.BUCKET, prefix='rhea/'), identities=observed['identities'])

    def authenticate_admission(self, intent):
        self._require_lock()
        a.require(self._admission is None, 'duplicate admission in lock session')
        observed = self.observe_host()
        raw = a.protected_read(INSTALL / 'admission.json')
        signature = a.protected_read(INSTALL / 'admission.sig', limit=64)
        verified = a.verify_production(raw, signature, expected_binding=self._binding(intent, observed), intent=intent)
        # Burn before journal intent; interruption never permits an automatic retry.
        a.consume_production_nonce(verified, self.host)
        self._admission = verified

    def queue_health(self):
        return self.observe_host()['health']

    def preflight(self, intent):
        self.observe_host()
        raise a.Refusal('reader handoff and full protected-source proof pending reviewed integration')

    def protected_guards(self):
        self.observe_host()
        raise a.Refusal('full protected-source/production byte guards pending reviewed integration')

    def _refuse(self, *args, **kwargs):
        raise a.Refusal('live mutation/closed-state/cloud-proof integration disabled pending complete review')

    handoff = _refuse
    run_go_monitored = _refuse
    drain_stop = _refuse
    publish_markers = _refuse
    reopen_readonly = _refuse
    snapshot_closed = _refuse
    cloud_read = _refuse
    baseline_ledger = _refuse


class ReadOnlyRecoveryObserver:
    """Independently rereads host state, but NEVER supplies a completion proof.

    Only observes an already active, admitted full-clone mount. Stopped, unknown,
    changed or absent mount states refuse. No cloud snapshot reconciliation.
    """
    def __init__(self):
        self._adapter = RootHostAdapter()

    def exclusive_read_lock(self):
        return self._adapter.exclusive()

    def observe(self, intent):
        observed = self._adapter.observe_host()
        return dict(decision='preserve/manual-inspection', host_observation=observed,
                    reason='independent source, closed-state and cloud version proof unavailable',
                    writer_replay_allowed=False, mutations_performed=False)

    independent_snapshot = RootHostAdapter._refuse
    cloud_read = RootHostAdapter._refuse
    baseline_ledger = RootHostAdapter._refuse
    reopen_observation = RootHostAdapter._refuse


def main():
    print('REFUSED: NOT DEPLOYED / NOT LIVE TESTED; no live CLI or mutation integration')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
