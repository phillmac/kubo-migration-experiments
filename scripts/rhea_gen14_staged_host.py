"""Private full-clone rclone lifecycle for locally staged metadata and deferred SSTs."""
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time

import rhea_gen14_clone_credentials as iam
import rhea_gen14_rclone_rehearsal as r
import rhea_gen14_signed_handoff as h
import rhea_gen14_writer_supervisor as supervisor

c = supervisor.c
require = c.require
INSTALL = Path('/root/.local/share/rhea-gen14-live-checkpoint-warm-20261127')
STATE = iam.TRIAL / 'checkpoint-000014-warm'
DATA = Path('/data/rhea-gen14-checkpoint-000014-warm-20261127')
BATCH_INSTALL = Path('/root/.local/share/rhea-clone-batch-runner-v1')
BATCH_DATA = Path('/data/rhea-pebble-clone-batches')
UNIT = 'rhea-gen14-full-clone-staged-writer-20261127.service'
PROBE = 'rhea-gen14-full-clone-staged-inspect-20261127.service'
DB = h.DB
LOCAL = '/run/rhea-gen14-two-sst-metadata'


def put(path, obj):
    r.private_write(path, c.canonical(obj))


def read(path):
    with path.open('rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600
                and st.st_nlink == 1 and st.st_size <= 32 << 20, 'invalid trial receipt')
        return c.parse(stream.read())


def mkdir(path):
    fd = iam.p.directory(path, create=True, private=True)
    os.close(fd)


def copy_closed(source, destination, expected_size):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as src, destination.open('xb') as dst:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_size == expected_size, 'closed payload size differs')
        digest, total = hashlib.sha256(), 0
        while block := src.read(1 << 20):
            total += len(block)
            require(total <= expected_size, 'closed payload grew')
            digest.update(block)
            dst.write(block)
        dst.flush()
        os.fsync(dst.fileno())
        last = os.fstat(fd)
        require(total == expected_size and (last.st_ino, last.st_size, last.st_mtime_ns) ==
                (first.st_ino, first.st_size, first.st_mtime_ns), 'closed payload changed while copying')
    with c_dir(destination.parent) as directory:
        os.fsync(directory)
    return dict(size=total, sha256=digest.hexdigest())


@contextlib.contextmanager
def c_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def start_reader():
    if h.main_pid(h.READER):
        return h.reader(True)
    require(not h.mount_row(h.reopen.MOUNT) and not any(Path(h.reopen.MOUNT).iterdir()), 'occupied reader mountpoint')
    h.wait_for(lambda: h.output(['/usr/bin/systemctl','show','--value','-p','LoadState',h.READER]) == 'not-found')
    h.output(['/usr/bin/systemd-run','--quiet','--unit='+h.READER,'--description=Rhea parked read-only clone',
              '-p','Restart=on-failure','-p','RestartSec=30s','-p','SuccessExitStatus=143',
              '-p','MemoryMax=2G','-p','Nice=10','-p','RuntimeDirectory='+Path(h.NEW_CACHE).name,
              '-p','RuntimeDirectoryMode=0700',*h.NEW_ARGS])
    h.wait_for(lambda: h.main_pid(h.READER) and h.mount_row(h.reopen.MOUNT))
    return h.reader(True)


def collect_reader(original):
    fields = ['LoadState','ActiveState','SubState','MainPID','Result','ExecMainPID','ExecMainCode',
              'ExecMainStatus','User','Group','DropInPaths','NeedDaemonReload','FragmentPath']
    unit = dict(line.split('=',1) for line in h.output(
        ['/usr/bin/systemctl','show','--property='+','.join(fields),h.READER]).splitlines())
    pid = original['process']['pid']
    choice = h.lifecycle.classify_reader_stop(unit, process_absent=not Path('/proc',str(pid)).exists(),
                                              mount_absent=not h.mount_row(h.reopen.MOUNT))
    if choice != 'collected':
        require(unit['ExecMainPID'] == str(pid) and unit['FragmentPath'] == '/run/systemd/transient/'+h.READER,
                'failed reader is not the admitted unit')
        h.output(['/usr/bin/systemctl','reset-failed',h.READER])
    return dict(original=original, endpoint=choice)


def role_credentials(role, cert):
    iam_client, sts = iam.p.clients(*iam.p.source_credentials())
    try:
        account = iam.p.identity(sts)['account']
        publication = iam.publisher_keys() if role == 'publisher' else None
        bound = iam.binding(account, role, cert, publication)
        with iam.Journal(role) as journal:
            iam.verify_role(iam_client, journal, bound)
            return iam.policies.parse(journal.raw('credential.json')), account
    finally:
        iam_client.close()
        sts.close()


def inspector(binary, mode):
    require(mode in ('plan','inspect') and binary in (INSTALL/'worker', BATCH_INSTALL/'worker'), 'invalid read-only inspection command')
    observed = h.reader(True)
    raw = h.output(['/usr/bin/systemd-run','--quiet','--collect','--wait','--pipe','--service-type=exec',
        '-p','PrivateNetwork=yes','-p','CapabilityBoundingSet=','-p','NoNewPrivileges=yes','-p','ProtectSystem=strict',
        '-p','ProtectHome=yes','-p','RuntimeMaxSec=240','-p','BindReadOnlyPaths='+str(binary)+':/run/rhea-gen14-ro-inspector',
        '/usr/bin/env','/run/rhea-gen14-ro-inspector',mode],timeout=260)
    require(h.reader(True) == observed, 'reader changed across cold inspection')
    return json.loads(raw)


class WriterMount:
    def __init__(self, work, unit):
        batch = (work.parent.parent == BATCH_DATA and re.fullmatch(r'[0-9]{6}', work.parent.name)
                 and work.name == 'writer' and unit == UNIT)
        require(unit in (UNIT,PROBE) and (work.parent == DATA or batch), 'unexpected mount identity')
        self.binary = (BATCH_INSTALL if batch else INSTALL) / 'worker'
        self.work, self.unit = work, unit
        self.cache, self.meta = work/'cache', work/'metadata'
        self.runtime, self.sock = work/'runtime', work/'runtime'/'rc.sock'
        self.pid = None
        self.fs = None
        self.proc = None
        self.executable = None
        self.start_ticks = None

    def prepare(self, metadata):
        require(not self.work.exists(), 'writer work directory already exists')
        mkdir(self.work)
        for path in (self.cache,self.runtime,self.work/'empty',self.meta):
            mkdir(path)
        for name, body in metadata.items():
            require(c.verifier.proof.base.META_NAME.fullmatch(name), 'unexpected metadata name')
            r.private_write(self.meta/name, body)
            os.chown(self.meta/name,65534,65534)
        os.chown(self.meta,65534,65534)
        require(not h.main_pid(self.unit) and not h.mount_row(DB), 'writer already mounted')

    def start(self, credential):
        remote = r.RemoteBinding(iam.BUCKET,iam.PREFIX)
        with tempfile.TemporaryDirectory(dir='/run', prefix='rhea-clone-writer-') as directory:
            cfg = Path(directory)/'writer.conf'
            r.private_write(cfg,r.writer_config(credential,remote))
            props = ['PrivateMounts=yes','PrivateTmp=yes','ProtectSystem=strict','ProtectHome=yes','NoNewPrivileges=yes',
                     'SuccessExitStatus=143','Restart=no','RuntimeMaxSec=7200','MemoryMax=4G','UMask=0077',
                     'TemporaryFileSystem=/mnt:ro','BindPaths='+str(self.work/'empty')+':'+DB,
                     'BindPaths='+str(self.meta)+':'+LOCAL,
                     'BindReadOnlyPaths='+str(r.RCLONE)+':/run/rhea-gen14-pilot-rclone',
                     'ReadWritePaths='+str(self.cache)+' '+str(self.runtime),
                     'LoadCredential=writer.conf:'+str(cfg)]
            argv = ['/usr/bin/systemd-run','--quiet','--collect','--service-type=exec','--unit='+self.unit]
            for item in props:
                argv += ['-p',item]
            argv += ['/usr/bin/env','/run/rhea-gen14-pilot-rclone','--config','/run/credentials/'+self.unit+'/writer.conf',
                     '--s3-no-check-bucket','--s3-no-head-object','--use-server-modtime','--fast-list',
                     'mount',remote.fs,DB,'--allow-non-empty','--allow-other','--default-permissions',
                     '--uid','65534','--gid','65534','--dir-perms','0700','--file-perms','0600',
                     '--vfs-cache-mode','full','--cache-dir',str(self.cache),'--vfs-cache-max-size','96Gi',
                     '--vfs-cache-max-age','168h','--vfs-write-back','168h','--poll-interval','0','--buffer-size','8Mi',
                     '--dir-cache-time','12h','--rc','--rc-addr','unix://'+str(self.sock),'--rc-no-auth','--log-level','ERROR']
            h.output(argv,timeout=35)
        def ready():
            self.pid = h.main_pid(self.unit)
            self.proc = Path('/proc')/str(self.pid)
            return self.pid and h.mount_row(DB,self.proc) and self.sock.exists()
        h.wait_for(ready,timeout=60)
        self.executable = (self.proc/'exe').stat()
        self.start_ticks = (self.proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        require(h.reopen.digest_file(self.proc/'exe') == r.RCLONE_SHA256 and
                os.readlink(self.proc/'ns/mnt') != os.readlink('/proc/1/ns/mnt') and not h.mount_row(DB),
                'incorrect rclone executable or mount namespace')
        vfses = self.rc('vfs/list')['vfses']
        require(len(vfses) == 1 and re.fullmatch(r'iam_writer(?:\{[A-Za-z0-9_-]+\})?:'
                + re.escape(iam.BUCKET+'/'+iam.PREFIX.rstrip('/'))+r'/?',vfses[0]), 'incorrect VFS backend')
        self.fs = vfses[0]
        row = h.mount_row(DB,self.proc)
        require(row.split(' - ')[1].split()[1].rstrip('/') == self.fs.rstrip('/') and
                'rw' in row.split()[5].split(',') and 'default_permissions' in row, 'wrong RW FUSE mount')
        actual_meta = self.proc/'root'/LOCAL.lstrip('/')
        require(os.path.samestat(actual_meta.stat(),self.meta.stat()) and self.meta.stat().st_uid == 65534
                and stat.S_IMODE(self.meta.stat().st_mode)==0o700, 'metadata staging bind differs')
        return dict(pid=self.pid,start_ticks=self.start_ticks,fs=self.fs,exe_sha256=r.RCLONE_SHA256,
                    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())

    def rc(self,method):
        require(method in ('vfs/list','vfs/queue','vfs/stats'), 'read-only RC route required')
        sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        with sock:
            sock.settimeout(12)
            sock.connect(str(self.sock))
            require(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)) == (self.pid,0,0),
                    'RC peer differs from scoped writer')
            connection = http.client.HTTPConnection('localhost',timeout=12)
            connection.sock = sock
            connection.request('POST','/'+method,body=json.dumps({'fs':self.fs} if self.fs else {}),
                         headers={'Content-Type':'application/json'})
            response = connection.getresponse()
            body = response.read(1<<20)
            require(response.status == 200 and len(body)<1<<20, 'RC response refused')
            return json.loads(body)

    def sample(self):
        require(self.pid and h.main_pid(self.unit)==self.pid and os.path.samestat((self.proc/'exe').stat(),self.executable)
                and (self.proc/'stat').read_text().rsplit(')',1)[1].split()[19]==self.start_ticks and not h.preflight.STOP.exists(),
                'writer identity changed or stop requested')
        stats = self.rc('vfs/stats')
        q = self.rc('vfs/queue')
        rows = q.get('queue',q.get('queued'))
        disk = stats['diskCache']
        require(type(rows) is list and len(rows)<=256 and disk['outOfSpace'] is False
                and disk['uploadsInProgress']==0 and disk['erroredFiles']==0
                and all(Path(disk[k]).is_relative_to(self.cache) for k in ('path','pathMeta')), 'unsafe writer cache')
        for row in rows:
            require(c.verifier.proof.base.SST_NAME.fullmatch(row['name']) and row['uploading'] is False
                    and row['tries']==0 and row['expiry']>3600 and type(row['size']) is int and row['size']>=0,
                    'early upload or unexpected deferred object')
        health = dict(cache_bytes=disk['bytesUsed'],free_bytes=shutil.disk_usage(self.work).free,
                      queue_bytes=sum(row['size'] for row in rows),queue_files=len(rows),errors=disk['erroredFiles'],
                      transferring=disk['uploadsInProgress'])
        c.health(health)
        return rows,health

    @contextlib.contextmanager
    def launch(self, mode):
        require(mode in ('worker','inspect-staged') and self.pid, 'unbound child launch')
        exe = self.binary
        with exe.open('rb') as binary, (self.proc/'ns/mnt').open('rb',buffering=0) as ns:
            flags=['/usr/bin/nsenter','--mount=/proc/self/fd/'+str(ns.fileno()),'/usr/bin/unshare','--net',
                   '/usr/bin/setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all',
                   '--inh-caps=-all','--ambient-caps=-all','--no-new-privs']
            parent,child = socket.socketpair()
            with parent,child, (self.work/(mode+'.stderr')).open('xb') as stderr:
                with subprocess.Popen(flags+['/proc/self/fd/'+str(binary.fileno()),mode],
                    stdin=child,stdout=subprocess.PIPE if mode=='inspect-staged' else subprocess.DEVNULL,stderr=stderr,
                    pass_fds=(binary.fileno(),ns.fileno()),cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}) as proc:
                    child.close()
                    try:
                        yield proc,parent
                    finally:
                        parent.close()
                        if proc.poll() is None:
                            proc.terminate()
                            try:
                                proc.wait(timeout=20)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait(timeout=10)

    @property
    def database(self):
        return self.proc/'root'/DB.lstrip('/')

    def quarantine(self):
        if h.main_pid(self.unit):
            h.output(['/usr/bin/systemctl','stop',self.unit],timeout=125)
        require(h.main_pid(self.unit)==0 and not h.mount_row(DB), 'writer still mounted')
        target = self.work/'quarantined-cache'
        if self.cache.is_dir() and not self.cache.is_symlink():
            require(not target.exists(), 'conflicting quarantine')
            self.cache.rename(target)
        if target.exists() and not self.cache.exists():
            r.private_write(self.cache,b'QUARANTINED - never reuse this cache\n')
        require(target.is_dir() and self.cache.is_file() and self.cache.read_bytes()==b'QUARANTINED - never reuse this cache\n'
                and not self.sock.exists(), 'incomplete cache quarantine')
        return dict(stopped=True,cache=str(target),no_rc_socket=True)
