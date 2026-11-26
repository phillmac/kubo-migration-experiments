"""One signed generation-13 reader stop, denied generation-14 launch, and read-only restore."""
import errno
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types

BASE = Path('/root/.local/share')
INSTALL = BASE / 'rhea-gen14-signed-handoff-20261127'
if __name__ == '__main__':
    if Path(__file__) != INSTALL / 'rhea_gen14_signed_handoff.py' or os.geteuid() != 0:
        raise SystemExit('fixed root installation required')
    sys.path.insert(0, str(INSTALL))

import rhea_gen14_clone_credentials as clone
import rhea_gen14_rclone_rehearsal as rehearsal
import rhea_gen14_reader_reopen as reopen
import rhea_multi_sst_reader_preflight as preflight
import rhea_multi_sst_signed_admission as admission

require = admission.require
RELEASE_KEY = '1e795ba5e4727de5c5ad7d3500afeb0c0bc5bb4f0510195a1333b18ed1f13e6f'
HANDOFF_KEY = '8ae285df7e903cad9b2806f1f96d53060b4d968863a2436d062a8a45ef7a9102'
WORKER_SHA = 'fac0d0971fa93ccb33db4e02937e777a8395b0ee95644201adedb1d660451347'
PREPARED = 'a54deaacf378bc8e14d2a95f349bec6bddc0cc3ac59ea8f13785bf1d77786a8b'
RC_SHA = '337b809357fcf73ae100a0bbb3d3a8099dd6d568dd4bc58cc01eff8191ce59af'
RC_HELPER = Path('/home/ubuntu/pebble-recovery-analysis/controlled-quiesce-user-20261031/rhea_wasabi_rc_stage.py')
READER = preflight.READER_UNIT
WRITER = 'rhea-gen14-denied-worker-20261127.service'
DB = preflight.WRITER_MOUNT + '/pebbleds'
PRODUCTION = 'rhea-ipfs-wasabi-rclone-mount.service'
INACTIVE = ('rhea-pebble-lab-full-clone-20261102.service', 'rhea-ipfs-wasabi-kubo.service',
            'rhea-broken-pin-walk-20261026.service')
CACHE = Path('/data/rhea-pebble-lab-reader-cache-fast-20261102')
NEW_CACHE = '/run/rhea-gen14-parked-reader'
TRIAL = clone.TRIAL / 'signed-reader-handoff'
SCOPE = 'rhea-clone-reader-handoff-deny-before-db-open-v1'
COMMON = ['/usr/bin/rclone', '--config', '/root/.config/rclone/rhea-pebble-lab-reader-20261102.conf',
          '--s3-no-check-bucket', '--s3-no-head-object', '--use-server-modtime', '--fast-list',
          'mount', reopen.REMOTE, reopen.MOUNT]
OLD_ARGS = COMMON + ['--cache-dir', str(CACHE), '--vfs-cache-mode', 'full', '--vfs-cache-max-size',
                     '24G', '--vfs-cache-max-age', '30m', '--vfs-read-chunk-size', '8M',
                     '--vfs-read-chunk-size-limit', '32M', '--vfs-read-ahead', '0', '--buffer-size',
                     '4M', '--dir-cache-time', '12h', '--attr-timeout', '10m', '--poll-interval',
                     '0', '--stats', '5m', '--log-level', 'NOTICE']
NEW_ARGS = COMMON + ['--read-only', '--vfs-cache-mode', 'off', '--cache-dir', NEW_CACHE,
                     '--buffer-size', '4M', '--poll-interval', '0', '--stats', '5m', '--log-level', 'NOTICE']
MODULES = {'rhea_gen14_signed_handoff', 'rhea_gen14_clone_credentials', 'rhea_gen14_rclone_rehearsal',
           'rhea_gen14_reader_reopen', 'rhea_multi_sst_reader_preflight', 'rhea_multi_sst_signed_admission',
           'rhea_gen14_create_iam_credentials', 'rhea_gen14_live_iam_acceptance',
           'rhea_gen14_recover_iam_policy', 'rhea_gen14_iam_admin_acceptance', 'rhea_multi_sst_marker_iam'}


def verify_release():
    raw = admission.protected_read(INSTALL / 'release.json')
    admission.verify_detached(raw, admission.protected_read(INSTALL / 'release.sig'),
                              admission.protected_read(INSTALL / 'release.pub'), key_sha256=RELEASE_KEY,
                              domain=admission.DEPLOYMENT_DOMAIN)
    manifest = admission.parse(raw)
    require(set(manifest) == {'scope', 'files'} and manifest['scope'] == SCOPE, 'wrong release scope')
    files = manifest['files']
    require(set(files) == {name + '.py' for name in MODULES} | {'worker', 'inspector'}
            and files['worker'] == WORKER_SHA and files['inspector'] == reopen.INSPECTOR_SHA,
            'wrong release contents')
    for name, expected in files.items():
        require(reopen.digest_file(INSTALL / name) == expected, 'release file differs: ' + name)
    return admission.sha(raw)


def checked_claims(raw, sig, pub, expected, now):
    claims = admission.parse(raw)
    require(set(claims) == {'binding', 'issued', 'expires', 'nonce'} and admission.canonical(claims['binding']) == admission.canonical(expected)
            and claims['binding']['scope'] == SCOPE, 'signed handoff binding differs')
    require(all(type(claims[k]) is int for k in ('issued', 'expires')) and
            claims['issued'] <= now < claims['expires'] <= claims['issued'] + admission.MAX_LIFETIME,
            'expired or future handoff')
    nonce = claims['nonce']
    require(type(nonce) is str and admission.HEX.fullmatch(nonce)
            and len(set(bytes.fromhex(nonce))) >= 8, 'invalid handoff nonce')
    admission.verify_detached(raw, sig, pub, key_sha256=HANDOFF_KEY, domain=admission.DOMAIN)
    return admission.VerifiedAdmission(raw, sig, nonce, claims['expires'])


def output(args, timeout=25):
    return subprocess.check_output(args, stdin=subprocess.DEVNULL, timeout=timeout, text=True).strip()


def main_pid(unit):
    return int(output(['/usr/bin/systemctl', 'show', '--value', '-p', 'MainPID', unit]))


def process(pid, executable='/usr/bin/rclone', expected_sha=reopen.RCLONE_SHA):
    require(pid > 1, 'missing service process')
    proc = Path('/proc') / str(pid)
    require(os.readlink(proc / 'exe') == executable
            and reopen.digest_file(proc / 'exe') == expected_sha, 'unexpected mount executable')
    return dict(pid=pid, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                start_ticks=int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]),
                exe_sha256=expected_sha)


def mount_row(target, proc='/proc/self'):
    rows = [row for row in (Path(proc) / 'mountinfo').read_text().splitlines() if row.split()[4] == target]
    rows = [row for row in rows if ' - fuse.rclone ' in row]
    require(len(rows) <= 1, 'ambiguous FUSE mount')
    return rows[0] if rows else None


def reader(restored):
    ident = process(main_pid(READER))
    proc = Path('/proc') / str(ident['pid'])
    cmd = (proc / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
    require(cmd == (NEW_ARGS if restored else OLD_ARGS), 'reader command differs')
    row = mount_row(reopen.MOUNT)
    require(row and mount_row(reopen.MOUNT, proc) == row and bool(os.statvfs(reopen.MOUNT).f_flag & os.ST_RDONLY) == restored,
            'host and reader mount disagree')
    backend = row.split(' - ')[1].split()[1]
    require(re.fullmatch(r'rhea_pebble_lab_reader(?:\{[A-Za-z0-9_-]+\})?:rhea-pebble-lab-20261101-39037c6f01/rhea', backend)
            and ('ro' if restored else 'rw') in row.split()[5].split(','), 'reader source or mount mode changed')
    return dict(process=ident, mount=row, argv_sha256=admission.sha(admission.canonical(cmd)))


def clean_reader_cache():
    meta = CACHE / 'vfsMeta'
    require(meta.is_dir(), 'reader cache metadata missing')
    count = 0
    paths = set()
    data = CACHE / 'vfs'
    for path in meta.rglob('*'):
        if path.is_dir():
            continue
        require(stat.S_ISREG(path.lstat().st_mode) and json.loads(path.read_bytes())['Dirty'] is False,
                'unknown or dirty parked reader cache record')
        paths.add(path.relative_to(meta))
        count += 1
    require(data.is_dir() and all(p.is_dir() or (stat.S_ISREG(p.lstat().st_mode)
            and p.relative_to(data) in paths) for p in data.rglob('*')), 'untracked reader cache data')
    return count


def production():
    require(all(main_pid(u) == 0 for u in INACTIVE) and not preflight.STOP.exists(),
            'clone writer, production Kubo, walker or stop sentinel present')
    unit_pid = main_pid(PRODUCTION)
    ident = process(unit_pid, '/usr/bin/bash', 'bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1')
    require(reopen.digest_file(Path('/proc') / str(unit_pid) / 'cmdline') ==
            '47af2d2ff2b6ba4e42d65efd0873858b740480c2a36fbd01fbd6cbcb239c5292', 'production launcher differs')
    cid = '2652b474858a0c2f15771e03d20abbc028230a8bc61cd5662c484a458258adeb'
    container, image, pid, running = output(['/usr/bin/docker', 'inspect', '--format',
         '{{.Id}} {{.Image}} {{.State.Pid}} {{.State.Running}}', cid]).split()
    require(container == cid and image == 'sha256:268697ccbe46e17c721c080b04669d04c69b0eec791bbb4cc08449d59de13404'
            and running == 'true', 'production mount container changed')
    mount_process = process(int(pid), '/usr/bin/rclone', rehearsal.RCLONE_SHA256)
    # Execute exactly the reviewed bytes, including if the source path changes afterwards.
    code = RC_HELPER.read_bytes()
    require(admission.sha(code) == RC_SHA, 'production RC helper changed')
    helper = types.ModuleType('readonly_rc')
    helper.__file__ = str(RC_HELPER)
    exec(compile(code, str(RC_HELPER), 'exec'), helper.__dict__)
    fs = {'fs': 'wasabi-ca-central-1:ipfs-remote-mount/rhea'}
    stats = helper.call_rc('vfs/stats', fs, client=helper.CLIENT)
    queue = helper.call_rc('vfs/queue', fs, client=helper.CLIENT)
    counters = {k: stats['diskCache'][k] for k in ('uploadsInProgress', 'uploadsQueued', 'erroredFiles')}
    require(stats['fs'] == fs['fs'] and queue['queue'] == [] and all(v == 0 for v in counters.values())
            and stats['diskCache']['outOfSpace'] is False, 'production VFS unhealthy or busy')
    return dict(process=ident, container=container, mount_process=mount_process, queue=0, **counters)


def pinned_objects(cert):
    client = rehearsal.s3_client(*clone.p.source_credentials())
    try:
        for name, pin in cert['remote_metadata'].items():
            value = client.head_object(Bucket=clone.BUCKET, Key=clone.PREFIX + name)
            clone.p.response_ok(value)
            require((value['VersionId'], value['ETag'], value['ContentLength']) ==
                    (pin['version_id'], pin['etag'], pin['size']), 'Wasabi metadata head changed: ' + name)
    finally:
        client.close()
    return len(cert['remote_metadata'])


def observation():
    cert = clone.anchored_checkpoint()
    require(main_pid(WRITER) == 0 and not mount_row(DB)
            and not mount_row(preflight.WRITER_MOUNT), 'lab writer already present')
    require(admission.sha(clone.read_path(clone.TRIAL / 'prepared-writer-request.json')) == PREPARED,
            'prepared request changed')
    before = reader(False)
    require(preflight._open_users(before['process']['pid']) == [], 'clone mount has open users')
    return dict(scope=SCOPE, release_sha256=verify_release(), certificate_sha256=clone.CHECKPOINT_SHA,
                prepared_sha256=PREPARED, reader=before, production=production(), metadata_heads=pinned_objects(cert),
                reader_config_sha256=admission.sha(clone.read_path(Path(COMMON[2]))),
                clean_cache_files=clean_reader_cache(), target=clone.BUCKET + '/' + clone.PREFIX,
                worker_request=None, restored_cache_mode='off', restored_read_only=True)


def wait_for(get, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        val = get()
        if val:
            return val
        time.sleep(.2)
    raise RuntimeError('service or mount did not reach the required state')


def private_writer_ready():
    pid = main_pid(WRITER)
    if not pid:
        return None
    proc = Path('/proc') / str(pid)
    row = mount_row(DB, proc)
    if not row:
        return None
    process(pid)
    require(os.readlink(proc / 'ns/mnt') != os.readlink('/proc/1/ns/mnt') and not mount_row(DB)
            and not mount_row(reopen.MOUNT) and 'rw' in row.split()[5].split(',')
            and 'default_permissions' in row and re.fullmatch(
                r'iam_writer(?:\{[A-Za-z0-9_-]+\})?:' + re.escape(clone.BUCKET + '/' + clone.PREFIX.rstrip('/')),
                row.split(' - ')[1].split()[1]), 'writer mount provenance differs')
    root = proc / 'root' / DB.lstrip('/')
    for path, mode in ((root, 0o555), (root / 'CURRENT', 0o444)):
        st = path.stat()
        require(st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == mode, 'writer DAC differs')
    return pid


def denied_worker(pid):
    proc = Path('/proc') / str(pid)
    with open(INSTALL / 'worker', 'rb') as exe, open(proc / 'ns/mnt', 'rb', buffering=0) as ns:
        parent, child = socket.socketpair()
        with parent, child:
            flags = ['/usr/bin/nsenter', '--mount=/proc/self/fd/' + str(ns.fileno()), '/usr/bin/unshare',
                     '--net', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
                     '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs']
            with subprocess.Popen(flags + ['/proc/self/fd/' + str(exe.fileno()), 'worker'], stdin=child,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(exe.fileno(), ns.fileno()),
                                  env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, cwd='/') as process_:
                child.close()
                parent.settimeout(12)
                try:
                    with parent.makefile('rb') as pipe:
                        hello = pipe.readline(2048)
                        require(json.loads(hello) == {'seq': 1, 'kind': 'ready'}, 'missing worker handshake')
                        require(private_writer_ready() == pid, 'writer changed before denial')
                        parent.sendall(b'{"seq":1,"allow":false}\n')
                        stdout, stderr = process_.communicate(timeout=12)
                        require(process_.returncode == 2 and not stdout and stderr.strip() == b'controller revoked batch'
                                and not pipe.read(1), 'worker did not stop before DB open')
                finally:
                    if process_.poll() is None:
                        process_.kill()
                        process_.wait(timeout=10)
    return dict(ready=True, allow=False, request_sent=False, worker_uid=65534, exit_code=2, writer_pid=pid)


def run_writer(cert):
    iam, sts = clone.p.clients(*clone.p.source_credentials())
    try:
        account = clone.p.identity(sts)['account']
        with clone.Journal('writer') as journal:
            bound = clone.binding(account, 'writer', cert)
            clone.verify_role(iam, journal, bound)
            cfg = rehearsal.writer_config(clone.policies.parse(journal.raw('credential.json')),
                                         rehearsal.RemoteBinding(clone.BUCKET, clone.PREFIX))
    finally:
        iam.close()
        sts.close()
    short = WRITER.removesuffix('.service')
    with tempfile.TemporaryDirectory(dir='/run', prefix='rhea-denied-') as tmp:
        config = Path(tmp) / 'writer.conf'
        config.write_bytes(cfg)
        del cfg
        props = ['PrivateMounts=yes', 'PrivateTmp=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
                 'NoNewPrivileges=yes', 'RuntimeMaxSec=90', 'RuntimeDirectory=' + short,
                 'TemporaryFileSystem=/mnt:ro', 'BindPaths=/run/' + short + ':' + DB,
                 'LoadCredential=writer.conf:' + str(config)]
        args = ['/usr/bin/systemd-run', '--quiet', '--collect', '--service-type=exec', '--unit=' + WRITER]
        for prop in props:
            args.extend(['-p', prop])
        args += ['/usr/bin/rclone', '--config', '/run/credentials/' + WRITER + '/writer.conf',
                 '--s3-no-check-bucket', '--s3-no-head-object', 'mount',
                 'iam_writer:' + clone.BUCKET + '/' + clone.PREFIX.rstrip('/'), DB, '--allow-non-empty',
                 '--allow-other', '--default-permissions', '--uid', '0', '--gid', '0', '--dir-perms', '0555',
                 '--file-perms', '0444', '--cache-dir', '/tmp/denied-worker-cache', '--vfs-cache-mode', 'full',
                 '--vfs-write-back', '168h', '--poll-interval', '0', '--log-level', 'ERROR']
        output(args)
        config.unlink()
        return denied_worker(wait_for(private_writer_ready))


def entry(name, value):
    rehearsal.private_write(TRIAL / name, admission.canonical(value))


def restore():
    if main_pid(WRITER):
        output(['/usr/bin/systemctl', 'stop', WRITER], timeout=105)
    require(main_pid(WRITER) == 0 and not mount_row(DB), 'scoped writer still running')
    if main_pid(READER):
        row = mount_row(reopen.MOUNT)
        if row is None:
            wait_for(lambda: mount_row(reopen.MOUNT))
        if os.statvfs(reopen.MOUNT).f_flag & os.ST_RDONLY:
            return reader(True)
        # An interrupted handoff may have stopped before the original reader was taken down.
        original = admission.parse(clone.read_path(TRIAL / 'intent.json'))['binding']['reader']
        require(reader(False) == original, 'unexpected reader is active')
        return original
    require(not mount_row(reopen.MOUNT) and not any(Path(reopen.MOUNT).iterdir()), 'reader mountpoint occupied')
    wait_for(lambda: output(['/usr/bin/systemctl', 'show', '--value', '-p', 'LoadState', READER]) == 'not-found')
    output(['/usr/bin/systemd-run', '--quiet', '--unit=' + READER, '--description=Rhea parked read-only clone',
            '-p', 'Restart=on-failure', '-p', 'RestartSec=30s', '-p', 'MemoryMax=2G', '-p', 'Nice=10',
            '-p', 'RuntimeDirectory=' + Path(NEW_CACHE).name, '-p', 'RuntimeDirectoryMode=0700', *NEW_ARGS])
    wait_for(lambda: main_pid(READER) and mount_row(reopen.MOUNT))
    return reader(True)


def inspect_restored(cert):
    require(reader(True) and os.statvfs(reopen.MOUNT).f_flag & os.ST_RDONLY, 'restored mount must be read-only')
    db = Path(reopen.MOUNT) / 'pebbleds'
    reopen.certify_metadata(db, cert)
    try:
        fd = os.open(db / 'CURRENT', os.O_WRONLY | os.O_NOFOLLOW)
    except OSError as exc:
        require(exc.errno == errno.EROFS, 'restored mount did not enforce EROFS')
    else:
        os.close(fd)
        raise RuntimeError('restored clone accepted a writable open')
    # Retain the original root-only FUSE access. The inspector gets no capabilities or network.
    report = json.loads(output(['/usr/bin/systemd-run', '--quiet', '--collect', '--wait', '--pipe',
        '--service-type=exec', '-p', 'PrivateNetwork=yes', '-p', 'CapabilityBoundingSet=',
        '-p', 'NoNewPrivileges=yes', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=yes',
        '-p', 'BindReadOnlyPaths=' + str(INSTALL / 'inspector') + ':' + reopen.INSPECTOR,
        '-p', 'RuntimeMaxSec=150', reopen.INSPECTOR, '--db', str(db), '--require-read-only-mount'], timeout=170))
    fields = ('format_major_version', 'marked_files', 'sst_count', 'sst_bytes')
    require(report['mount_read_only'] is True and report['read_only'] is True and
            tuple(report[k] for k in fields) == tuple(cert[k] for k in ('after_format', 'marked_after', 'sst_count', 'sst_bytes')),
            'read-only Pebble reopen differs from certificate')
    reopen.certify_metadata(db, cert)
    return {k: report[k] for k in (*fields, 'elapsed_seconds', 'mount_read_only', 'read_only')}


def run():
    raw = admission.protected_read(INSTALL / 'handoff.json')
    verified = checked_claims(raw, admission.protected_read(INSTALL / 'handoff.sig'),
                              admission.protected_read(INSTALL / 'handoff.pub'), observation(), int(time.time()))
    claims = admission.parse(raw)
    cert = clone.anchored_checkpoint()
    before = claims['binding']['reader']
    with admission.protected_directory(INSTALL / 'consumed-nonces', private=True) as fd:
        admission._consume_at(fd, verified, lock_path=admission.WRITER_LOCK, uid=0)
    fd = clone.p.directory(TRIAL, create=True, private=True)
    os.close(fd)
    entry('intent.json', claims)
    try:
        require(reader(False) == before and not preflight._open_users(before['process']['pid'])
                and clean_reader_cache() == claims['binding']['clean_cache_files'] and
                production() == claims['binding']['production'] and time.time() < verified.expires,
                'handoff changed before stop')
        output(['/usr/bin/systemctl', 'stop', READER], timeout=105)
        require(not Path('/proc', str(before['process']['pid'])).exists() and main_pid(READER) == 0
                and not mount_row(reopen.MOUNT), 'old reader still present')
        entry('reader-stopped.json', dict(reader=before, stopped=True))
        require(time.time() < verified.expires, 'handoff expired before scoped mount')
        proof = run_writer(cert)
        entry('denied-worker.json', proof)
    finally:
        restore()
    return finish()


def finish():
    # Repeated recovery verifies only read-only evidence; it never launches a worker.
    claims = admission.parse(clone.read_path(TRIAL / 'intent.json'))
    raw = admission.protected_read(INSTALL / 'handoff.json')
    require(admission.canonical(claims) == raw, 'retained handoff intent changed')
    sig = admission.protected_read(INSTALL / 'handoff.sig')
    checked_claims(raw, sig, admission.protected_read(INSTALL / 'handoff.pub'), claims['binding'], claims['issued'])
    require(claims['binding']['release_sha256'] == verify_release(), 'release differs from signed handoff')
    nonce = admission.parse(clone.read_path(INSTALL / 'consumed-nonces' / (claims['nonce'] + '.json')))
    require(nonce == dict(schema=1, claims_sha256=admission.sha(raw), signature_sha256=admission.sha(sig),
                          nonce=claims['nonce']), 'consumed admission differs')
    before = claims['binding']['reader']
    require(admission.parse(clone.read_path(TRIAL / 'reader-stopped.json')) == dict(reader=before, stopped=True)
            and main_pid(WRITER) == 0, 'reader stop or writer shutdown unconfirmed')
    proof = admission.parse(clone.read_path(TRIAL / 'denied-worker.json'))
    require(proof == dict(ready=True, allow=False, request_sent=False, worker_uid=65534,
                          exit_code=2, writer_pid=proof['writer_pid']), 'worker denial evidence differs')
    cert = clone.anchored_checkpoint()
    restored = reader(True)
    require(restored['process'] != before['process'], 'reader was not freshly restored')
    report = inspect_restored(cert)
    after = production()
    require(after == claims['binding']['production'] and reader(True) == restored and
            clone.anchored_checkpoint() == cert, 'state changed after restore')
    result = dict(scope=SCOPE, result='PASS', completed_unix=int(time.time()), receipt_sha256=admission.sha(raw),
                  certificate_sha256=clone.CHECKPOINT_SHA, prepared_sha256=PREPARED, production=after,
                  stopped_reader=before, restored_reader=restored, clean_cache_files=claims['binding']['clean_cache_files'],
                  worker=proof, reopen=report, metadata_heads_verified_before_and_after=pinned_objects(cert),
                  metadata_bodies_verified_twice=len(cert['remote_metadata']), generation=13, certified_rewrites=9)
    entry('complete.json', result)
    return result


def main(mode):
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    verify_release()
    with admission.protected_directory(admission.WRITER_LOCK.parent, private=True) as parent:
        admission.read_at(parent, admission.WRITER_LOCK.name)
        fd = os.open(admission.WRITER_LOCK.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    with os.fdopen(fd, 'rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if mode == 'observe':
            return observation()
        if mode == 'run':
            return run()
        if mode == 'verify-restored':
            return finish()
        require(mode == 'restore-only', 'unknown mode')
        if (TRIAL / 'intent.json').exists() and not (TRIAL / 'complete.json').exists():
            return restore()
        return {'restore_required': False}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('expected observe, run or restore-only')
    print(admission.canonical(main(sys.argv[1])).decode(), end='')
