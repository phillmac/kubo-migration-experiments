#!/usr/bin/env python3
"""Locked reader-restored integration; NO service or database mutation API.

Not installed or live tested. The CLI always refuses. Independent provisioning
must sign bridge.json in addition to the existing deployment/installation pair.
The historical health CHILD is used outside the lock; its pinned library's
read-only observer is called directly inside the historical runtime's lock.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import time

import rhea_multi_sst_signed_admission as a
import rhea_multi_sst_root_host_adapter as h
import rhea_multi_sst_reader_preflight as p

INSTALL = a.INSTALL
SELF = INSTALL / 'rhea_multi_sst_reader_bridge.py'
MANIFEST = INSTALL / 'bridge.json'
EVIDENCE = INSTALL / 'reader-bridge-gen14'
SCOPE = 'rhea-gen14-reader-bridge-v1'
BASE_COMMIT = 'e8941f178ac3f7639e5fe1e8f8751e553312dcab'
READER_EXE_SHA256 = 'dc1ec3109000e4d36c8d14efac6d4c4158d1b860853cb75c09dcc9f6dded420b'
TRANSITIVE_SOURCE_PINS = {
    'scripts/verify_rhea_lab_format3.py': 'edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b',
    'scripts/enumerate_rhea_versions.py': '512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359',
}


def exact(left, right, reason):
    a.require(a.canonical(left) == a.canonical(right), reason)


def owned_lock(host, expected):
    """Check the exact existing inode and current PID's kernel flock record.

    This does not create a lock, change permissions, or acquire a second lock.
    A contended lock owned by a different process is insufficient.
    """
    a.require(host.locked is True, 'historical runtime must hold writer.lock')
    with a.protected_directory(p.LOCK.parent, private=True) as directory:
        a.read_at(directory, p.LOCK.name)
        fd = os.open(p.LOCK.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(fd)
            exact(dict(device=info.st_dev, inode=info.st_ino), expected, 'historical lock replaced')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise a.Refusal('historical writer lock not excluded')
            token = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
            own = False
            for line in Path('/proc/locks').read_text().splitlines():
                fields = line.split()
                if len(fields) >= 6 and fields[1:5] == ['FLOCK', 'ADVISORY', 'WRITE', str(os.getpid())]:
                    major, minor, inode = fields[5].split(':')
                    own |= (int(major, 16), int(minor, 16), int(inode)) == token
            a.require(own, 'current PID does not own the exact writer.lock')
            current = os.stat(p.LOCK.name, dir_fd=directory, follow_symlinks=False)
            a.require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'lock path replaced')
        finally:
            os.close(fd)


def validate_manifest(value, deployment, *, now, boot):
    """Schema/bindings only; caller must authenticate the exact bytes first."""
    a.require(type(value) is dict and set(value) == {'schema', 'scope', 'issued', 'expires',
        'host', 'boot_id', 'base_commit', 'bridge_sha256', 'deployment_sha256',
        'installation_sha256', 'protected_files'}, 'bridge manifest schema mismatch')
    exact({key: value[key] for key in ('schema', 'scope', 'host', 'boot_id', 'base_commit',
                                      'deployment_sha256', 'installation_sha256')},
          dict(schema=1, scope=SCOPE, host='rhea', boot_id=boot, base_commit=BASE_COMMIT,
               deployment_sha256=deployment['_deployment_sha256'],
               installation_sha256=deployment['_installation_sha256']), 'bridge installation binding mismatch')
    a.require(all(type(v) is int for v in (value['issued'], value['expires'], now,
                  h.PROVISION_KEY_NOT_BEFORE, h.PROVISION_KEY_NOT_AFTER))
              and h.PROVISION_KEY_NOT_BEFORE <= value['issued'] <= now < value['expires'] <= h.PROVISION_KEY_NOT_AFTER,
              'bridge manifest/key expired or future')
    a.require(type(value['bridge_sha256']) is str and a.HEX.fullmatch(value['bridge_sha256']), 'bridge digest missing')
    files = value['protected_files']
    a.require(type(files) is dict and 0 < len(files) <= 512, 'complete protected file inventory required')
    for name, pin in files.items():
        a.require(type(name) is str and Path(name).is_absolute() and '..' not in Path(name).parts
                  and type(pin) is dict and set(pin) == {'bytes', 'sha256'}
                  and type(pin['bytes']) is int and 0 <= pin['bytes'] <= 512 * 1024**2
                  and type(pin['sha256']) is str and a.HEX.fullmatch(pin['sha256']), 'invalid protected file pin')


def protected_inventory(ctx, manifest):
    """Verify complete bytes, including public production inputs by old policy.

    No caller can omit a mandatory source/config/ledger/journal. Historical
    public aliases have their original owner/mode/symlink policy; the separately
    signed hashes still bind their FULL bytes. No secret bytes enter receipts.
    """
    w, reboot = ctx['w'], ctx['reboot']
    required = (set(map(str, ctx['protected_sources'])) | set(map(str, ctx['protected_configs']))
                | set(map(str, reboot.INPUTS)) | set(p.PROTECTED_PINS)
                | {str(w.RCLONE), str(w.CONFIG), str(w.LEDGER), str(p.STATE), str(p.PINS),
                   str(h.TRUST / 'run_rhea_full_clone_steps_batch2.py')})
    files = manifest['protected_files']
    a.require(set(files) == required, 'missing or unexpected protected source files')
    for name, pin in files.items():
        path = Path(name)
        if path in reboot.INPUTS:
            exact(pin, ctx['identity']['protected_inputs'][name], 'historical production input pin differs')
            reboot.read_input(path, pin)  # streaming FULL byte verification, exact original policy
        else:
            raw = w.read_protected(path, max_bytes=512 * 1024**2)
            a.require(len(raw) == pin['bytes'] and a.sha(raw) == pin['sha256'], 'protected bytes changed: ' + name)
        if name in p.PROTECTED_PINS:
            a.require(pin['sha256'] == p.PROTECTED_PINS[name], 'historical reader anchor pin changed')
    return a.sha(a.canonical(files))


def locked_witness():
    """Fresh /proc/file/cache inspection, with NO health child or lock acquire."""
    identities = {}
    for name, pin in p.PROTECTED_PINS.items():
        path = Path(name)
        with a.protected_directory(path.parent) as directory:
            before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            raw = a.read_at(directory, path.name, limit=p.MAX_BYTES)
            after = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            def identity(info):
                return dict(device=info.st_dev, inode=info.st_ino, size=info.st_size,
                            mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
            exact(identity(before), identity(after), 'protected inode changed')
            a.require(a.sha(raw) == pin, 'protected historical bytes changed')
            identities[name] = identity(after)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    processes = {key: p._process(p.IMMUTABLE_REPORT[key]['pid'], boot) for key in
                 ('reader_process', 'production_service_process', 'production_rc_process')}
    proc = Path('/proc') / str(processes['reader_process']['pid'])
    exe = str((proc / 'exe').resolve(strict=True))
    a.require(exe == '/usr/bin/rclone', 'reader executable substituted')
    caches = {}
    for name in p.CACHES:
        with a.protected_directory(Path(name)) as directory:
            info = os.fstat(directory)
            caches[name] = dict(device=info.st_dev, inode=info.st_ino)
    return dict(boot_id=boot, kernel=os.uname().release, processes=processes,
        reader_cgroup=(proc / 'cgroup').read_text(),
        reader_cmdline=(proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
        reader_exe=exe, reader_exe_sha256=a.sha(a.protected_read(Path(exe), mode=0o755, limit=64 * 1024**2)),
        mountinfo=p._lab_mounts(), open_users=p._open_users(processes['reader_process']['pid']),
        cache_identities=caches, protected_files=dict(p.PROTECTED_PINS), file_identities=identities,
        stop_present=os.path.lexists(p.STOP), writer_socket_present=os.path.lexists(p.WRITER_SOCKET))


def reconcile_reader(before, report_raw, witness, *, now):
    """Pure comparison of outside witness with independently collected locked IO."""
    original = p.validate_evidence(before, now=now)
    current = dict(before, raw=report_raw, witness=witness)
    fresh = p.validate_evidence(current, now=now)
    first, second = p.object_json(before['raw']), p.object_json(report_raw)
    a.require(first['observed_unix'] < second['observed_unix'] <= now, 'locked report must be fresh and later')
    exact(before['witness'], witness, 'reader/production/mount/cache/protected identity changed under lock')
    a.require(witness['reader_exe_sha256'] == READER_EXE_SHA256, 'reader binary hash differs from pinned production input')
    return dict(outside_sha256=original['evidence_seal_sha256'],
                locked_sha256=fresh['evidence_seal_sha256'], reader=witness['processes']['reader_process'],
                witness_sha256=a.sha(a.canonical(witness)))


def verify_claims(raw, signature, key, *, binding, now):
    """New scope binds a parked reader; never fabricate a writer RC identity."""
    claims = a.parse(raw)
    a.require(set(claims) == set(binding) | {'issued', 'expires', 'nonce'}, 'bridge claims schema differs')
    exact({name: claims[name] for name in binding}, binding, 'signed reader/intent/source/identity mismatch')
    issued, expires = claims['issued'], claims['expires']
    a.require(all(type(v) is int for v in (issued, expires, now, a.KEY_NOT_BEFORE, a.KEY_NOT_AFTER))
              and a.KEY_NOT_BEFORE <= issued <= now < expires <= a.KEY_NOT_AFTER
              and 0 < expires - issued <= a.MAX_LIFETIME, 'bridge admission/key future or expired')
    nonce = claims['nonce']
    a.require(type(nonce) is str and a.HEX.fullmatch(nonce)
              and len(set(bytes.fromhex(nonce))) >= 8, 'invalid bridge nonce')
    a.verify_detached(raw, signature, key, key_sha256=a.PUBLIC_KEY_SHA256, domain=a.DOMAIN)
    return a.VerifiedAdmission(raw, signature, nonce, expires)


def validate_proposal(intent, deployment, observed):
    """A separate proposal format; not the incompatible historical Engine intent."""
    a.require(type(intent) is dict and set(intent) == {'schema', 'scope', 'generation', 'unit_count',
        'physical_rewrite_base', 'previous_checkpoint_sha256', 'request', 'go_binary_sha256',
        'deployment_sha256', 'installation_sha256', 'bridge_manifest_sha256', 'reader'},
        'complete bridge proposal required')
    exact({k: intent[k] for k in set(intent) - {'request'}},
          dict(schema=1, scope='rhea-gen14-two-unit-proposal-v1', generation=14, unit_count=2,
               physical_rewrite_base=9, previous_checkpoint_sha256=a.ANCHOR,
               go_binary_sha256=deployment['artifacts']['writer'],
               deployment_sha256=deployment['_deployment_sha256'],
               installation_sha256=deployment['_installation_sha256'],
               bridge_manifest_sha256=observed['bridge_manifest_sha256'],
               reader=observed['reader']), 'proposal installation/reader/lineage differs')
    request = intent['request']
    a.require(type(request) is dict and set(request) == {'maximum_units', 'before', 'initial_plan_sha256'},
              'exact batch request required')
    state = p.IMMUTABLE_REPORT['state']
    exact(dict(maximum_units=request['maximum_units'], before=request['before']),
          dict(maximum_units=2, before=dict(format=state['format'], marked=state['marked'], files=state['count'],
                                          bytes=state['bytes'], inventory_sha256=state['inventory'])),
          'proposal request changes gen13 state or two-unit bound')
    a.require(type(request['initial_plan_sha256']) is str and a.HEX.fullmatch(request['initial_plan_sha256']),
              'exact reviewed initial Go plan digest required')


def handoff_plan(intent, deployment, observed):
    """Pure control specification, never authorization or an executable recipe.

    A signed proposal may be retained; writer start is still blocked because
    the historical writeback timer does not establish marker isolation. This
    model deliberately cannot turn a caller's success boolean into readiness.
    """
    validate_proposal(intent, deployment, observed)
    return dict(schema=1, state='proposal-only', execution_allowed=False, automatic_retry=False,
        intent_sha256=a.sha(a.canonical(intent)), controls=[
            dict(action='stop-exact-reader', unit=p.READER_UNIT, process=observed['reader']['reader'],
                 mount=p.READER_MOUNT, intent='reader-stop-intent.json',
                 receipt='reader-stopped.json', executable=False,
                 postconditions=['original PID absent, no replacement accepted', 'reader mount absent',
                                 'no new lab users', 'all retained cache device/inodes unchanged',
                                 'production and protected source unchanged']),
            dict(action='start-one-writer', unit='rhea-pebble-lab-full-clone-20261102.service',
                 mount=p.WRITER_MOUNT, cache=p.CACHES[1], rc_socket=str(p.WRITER_SOCKET),
                 rclone=str(h.TRUST / 'rclone-v1.68.1'),
                 rclone_sha256='3afdc72c395651badd72426cc218b0420249ceb10960c03b539939e56e60bf2e',
                 historical_unit_sha256='193fd66756a7c3b2c340dc8f7e0868d54767a2877f83dfcd18160564ebff1dfe',
                 intents=['writer-stage-intent.json', 'writer-start-intent.json'],
                 receipt='writer-started.json', executable=False,
                 postconditions=['new exact PID/start/boot/executable and raw mount identity',
                                 'RC peer/socket inode authenticated', 'same signed lab cloud identity',
                                 'marker isolation continuously proven before any database open'])],
        blockers=['historical lifecycle CLI limited to gen9 startup',
                  'independent marker withholding and continuous monitor unavailable',
                  'gen14 controller, Go command, drain/publication/reopen and host recovery unavailable'])


class ReaderBridge:
    """Concrete read-only guard and durable proposal, never a HostAdapter.

    No injected host, path, clock, key, fake flag or environment override. The
    only host context is the exact historical health library's own Runtime.
    No API here can stop a service, mount a writer, or launch Go.
    """
    def __init__(self):
        a.require(Path(__file__).absolute() == SELF, 'fixed bridge installation required')
        self.deployment = h.validate_installation()
        a.require(Path(p.__file__).absolute() == INSTALL / h.ARTIFACTS['reader_preflight'][0],
                  'fixed installed reader-preflight module required')
        self.raw = a.protected_read(MANIFEST)
        self.manifest = a.parse(self.raw)
        a.verify_detached(self.raw, a.protected_read(INSTALL / 'bridge.sig', limit=64),
            a.protected_read(h.PROVISION_PUBLIC_KEY), key_sha256=h.PROVISION_PUBLIC_KEY_SHA256,
            domain=a.DEPLOYMENT_DOMAIN)
        self._installation()
        self.adapter = h.RootHostAdapter(mode='reader-restored')
        exact(self.adapter.deployment, self.deployment, 'adapter installation changed during bootstrap')
        self.health = h._load_exact(p.HEALTH, p.HEALTH_SHA256, '_rhea_bridge_exact_historical_health')
        self._active = False

    def _installation(self):
        exact(h.validate_installation(), self.deployment, 'installation changed')
        a.require(a.protected_read(MANIFEST) == self.raw, 'bridge manifest changed')
        validate_manifest(self.manifest, self.deployment, now=int(time.time()),
                          boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        a.require(a.sha(a.protected_read(SELF)) == self.manifest['bridge_sha256'], 'bridge installed bytes changed')
        for name, pin in TRANSITIVE_SOURCE_PINS.items():
            a.require(a.sha(a.protected_read(INSTALL / 'sources' / name)) == pin,
                      'transitive installed source changed: ' + name)

    @contextmanager
    def locked(self):
        a.require(not self._active, 'bridge lock session already active')
        self._installation()
        # Health subprocess takes writer.lock itself. There is NO held lock here.
        outside = self.adapter.observe_reader_restored()['evidence']
        lock = p._unlocked_identity()
        ctx = self.health.load()  # original immutable library constructs its original runtime
        with ctx['rt'].lock():
            self._active = True
            self.ctx, self.outside, self.lock_identity = ctx, outside, lock
            try:
                yield self.observe()
            finally:
                self._active = False
                self.ctx = self.outside = self.lock_identity = None

    def observe(self):
        a.require(self._active, 'locked bridge session required')
        host = self.ctx['rt'].host
        owned_lock(host, self.lock_identity)
        self._installation()
        inventory = protected_inventory(self.ctx, self.manifest)
        before = locked_witness()
        # Direct pinned read-only observer. NEVER health.main(), probe(), guard()
        # or another lock(). It also authenticates production RC and frozen units.
        report = self.health.observe(self.ctx, phase='reader-restored', reader_sha256=p.RESTORED_SHA256)
        after = locked_witness()
        exact(before, after, 'identity changed during locked health observation')
        reconciled = reconcile_reader(self.outside, a.canonical(report), after, now=time.time())
        w = self.ctx['w']
        s3, sts = host.cloud(w.parse_config(w.read_protected(w.CONFIG, mode=0o600).decode()))
        try:
            cloud = w.verify_cloud_identity(s3, sts)  # authenticated STS + versioning; read-only
            exact(cloud, self.ctx['admission']['identity'], 'historical cloud identity changed')
        finally:
            s3.close()
            sts.close()
        exact(locked_witness(), after, 'identity changed during cloud verification')
        p.fresh(report['observed_unix'], time.time())
        p.fresh(p.object_json(self.outside['raw'])['observed_unix'], time.time())
        exact(protected_inventory(self.ctx, self.manifest), inventory, 'protected source changed')
        self._installation()
        owned_lock(host, self.lock_identity)
        return dict(schema=1, scope=SCOPE, host='rhea', boot_id=after['boot_id'],
                    bridge_manifest_sha256=a.sha(self.raw), protected_files_sha256=inventory,
                    reader=dict(reader=reconciled['reader'], witness_sha256=reconciled['witness_sha256']),
                    cloud=cloud, legacy_journal_sha256=p.PROTECTED_PINS[str(p.STATE)],
                    lock=self.lock_identity, controller_ready=False, execution_allowed=False)

    def retain_stop_proposal(self, intent):
        """Consume signed nonce and fsync intent then stop-PROPOSAL; no stop call.

        A crash at any write or after nonce consumption poisons the attempt. No
        retry/resume/repair path. Evidence directory must be preinstalled empty.
        """
        observed = self.observe()
        validate_proposal(intent, self.deployment, observed)
        # Hold the EXACT canonical full request; signature covers every field.
        intent_raw = a.canonical(intent)
        binding = dict(observed, intent_sha256=a.sha(intent_raw), units=2,
                       target=dict(bucket=a.BUCKET, prefix='rhea/'))
        claims_raw = a.protected_read(INSTALL / 'reader-admission.json')
        signature = a.protected_read(INSTALL / 'reader-admission.sig', limit=64)
        verified = verify_claims(claims_raw, signature, a.protected_read(a.PUBLIC_KEY),
                                 binding=binding, now=int(time.time()))
        with a.protected_directory(EVIDENCE, private=True) as directory:
            a.require(os.listdir(directory) == [], 'existing bridge attempt; preserve, never replay')
            exact(self.observe(), observed, 'signed bridge identity changed before nonce consumption')
            a.consume_production_nonce(verified, self.ctx['rt'].host)
            for name, raw in (('intent.json', intent_raw), ('admission.json', claims_raw),
                              ('admission.sig', signature), ('locked-observation.json', a.canonical(observed)),
                              ('reader-stop-intent.json', a.canonical(dict(schema=1, intent_sha256=a.sha(intent_raw),
                                  claims_sha256=a.sha(claims_raw), observation_sha256=a.sha(a.canonical(observed)),
                                  unit=p.READER_UNIT, reader=observed['reader']['reader'],
                                  action='stop-exact-reader', executable=False, automatic_retry=False,
                                  handoff_plan=handoff_plan(intent, self.deployment, observed))))):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, 'wb', closefd=False) as stream:
                        a.require(stream.write(raw) == len(raw), 'short bridge evidence write')
                        stream.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory)
                a.require(a.read_at(directory, name) == raw, 'bridge evidence readback differs')
        return dict(recorded=True, service_actions=0, execution_allowed=False, controller_ready=False)


def main():
    print('REFUSED: reader bridge library only; no live CLI, service actions or writer entrypoint')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
