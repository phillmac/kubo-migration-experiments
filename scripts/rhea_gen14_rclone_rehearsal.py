#!/usr/bin/env python3
"""Isolated writer-cache denial, quarantine, then conditional marker publication.

The public CLI has one fixed disposable scope. NativeHost exposes a lifecycle
primitive for separately reviewed controllers; it never receives publisher keys.
An interrupted run is never automatically replayed or its cache reused.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time

import rhea_gen14_create_iam_credentials as p
import rhea_gen14_recover_iam_policy as managed
import rhea_gen14_live_iam_acceptance as live

STATE = Path('/root/.local/share/rhea-gen14-rclone-rehearsal-20261125')
RCLONE = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101/rclone-v1.68.1')
RCLONE_SHA256 = '3afdc72c395651badd72426cc218b0420249ceb10960c03b539939e56e60bf2e'
FUSERMOUNT = '/usr/bin/fusermount3'
PORT = 5574
DATA = 'acceptance-rclone.sst'
DIRTY = 'CURRENT'
PAYLOAD = b'rhea isolated rclone data\n'
DIRTY_PAYLOAD = b'rhea denied dirty CURRENT; never publish\n'
PUBLISH_PAYLOAD = b'rhea publication after writer cache quarantine\n'
MAX_LOG = 1024 * 1024
WAIT_SECONDS = 90
REFUSAL = p.Refusal
BLOCKED_PATH = b'QUARANTINED - this rehearsal path must not be reused\n'
BLOCKED_MOUNT = b'QUARANTINED - mount disabled\n'


@dataclass(frozen=True)
class RemoteBinding:
    bucket: str
    prefix: str
    endpoint: str = p.S3_ENDPOINT
    region: str = 'ca-central-1'

    def validate(self):
        p.require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', self.bucket)
                  and self.prefix.endswith('/') and '..' not in self.prefix.split('/')
                  and re.fullmatch(r'[A-Za-z0-9_./-]+/', self.prefix)
                  and self.endpoint == p.S3_ENDPOINT and self.region == 'ca-central-1',
                  'invalid explicit writer remote binding')

    @property
    def fs(self):
        return 'iam_writer:' + self.bucket + '/' + self.prefix.rstrip('/')


REMOTE = RemoteBinding(p.admin.TEST_BUCKET, p.admin.PREFIX)


@dataclass(frozen=True)
class HostPaths:
    base: Path

    @property
    def cache(self): return self.base / 'cache'
    @property
    def mount(self): return self.base / 'mount'
    @property
    def config(self): return self.base / 'writer.conf'
    @property
    def auth(self): return self.base / 'rc-auth.json'
    @property
    def log(self): return self.base / 'rclone.jsonl'
    @property
    def stderr(self): return self.base / 'rclone.stderr'
    @property
    def quarantine(self): return self.base / 'quarantine-do-not-reuse'


def private_write(path, raw):
    """Append-only private artifact creation; no replacement or shell parsing."""
    parent = p.directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


class Journal(p.Journal):
    def __enter__(self):
        self.fd, self.lock = p.directory(STATE, create=True, private=True), None
        try:
            try:
                self.lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=self.fd)
                os.fsync(self.lock)
                os.fsync(self.fd)
            except FileExistsError:
                self.lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            p.checked_file(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise


def writer_config(writer, remote):
    remote.validate()
    p.require(writer.get('role') == 'writer' and writer.get('endpoint') == remote.endpoint
              and writer.get('region') == remote.region, 'writer-only credential required')
    key, secret = writer.get('AccessKeyId'), writer.get('SecretAccessKey')
    p.require(type(key) is str and re.fullmatch(r'[A-Za-z0-9]{16,128}', key)
              and type(secret) is str and re.fullmatch(r'[!-~]{16,256}', secret),
              'invalid writer credential format')
    return ('[iam_writer]\ntype = s3\nprovider = Wasabi\nenv_auth = false\n'
            'access_key_id = ' + key + '\nsecret_access_key = ' + secret + '\n'
            'endpoint = ' + remote.endpoint + '\nregion = ' + remote.region + '\n'
            'force_path_style = true\nno_check_bucket = true\nacl =\n').encode()


def mount_present(path):
    target = str(path)
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if len(fields) > 4:
            value = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
            if value == target:
                return True
    return False


def references(paths):
    """Bounded root scan of process arguments and FDs; no credential/env reads."""
    roots = tuple(str(path) for path in paths)
    matches = []
    def relevant(value):
        value = value.removesuffix(' (deleted)')
        return any(value == root or value.startswith(root + '/') for root in roots)
    processes = [x for x in Path('/proc').iterdir() if x.name.isdigit()]
    p.require(len(processes) <= 65536, 'process census exceeds bound')
    for process in processes:
        try:
            args = (process / 'cmdline').read_bytes()
            p.require(len(args) <= 1024 * 1024, 'oversized process arguments')
            if any(relevant(arg.decode(errors='replace').split('=', 1)[-1]) for arg in args.split(b'\0')):
                matches.append(dict(pid=int(process.name), kind='arguments'))
            for fd in (process / 'fd').iterdir():
                try:
                    if relevant(os.readlink(fd)):
                        matches.append(dict(pid=int(process.name), kind='descriptor'))
                except FileNotFoundError:
                    pass
        except (FileNotFoundError, ProcessLookupError):
            pass
    return matches


def listener_owned(pid, port):
    try:
        inodes = {os.readlink(fd).removeprefix('socket:[').removesuffix(']')
                  for fd in (Path('/proc') / str(pid) / 'fd').iterdir()
                  if os.readlink(fd).startswith('socket:[')}
        for row in (Path('/proc') / str(pid) / 'net/tcp').read_text().splitlines()[1:]:
            fields = row.split()
            if fields[1] == f'0100007F:{port:04X}' and fields[3] == '0A' and fields[9] in inodes:
                return True
    except (FileNotFoundError, ProcessLookupError):
        pass
    return False


class NativeHost:
    """Foreground writer lifecycle; callers must separately validate scope/IAM."""
    def __init__(self, paths, remote, port=PORT, expected_dirty=None):
        p.require(type(port) is int and 1024 <= port <= 65535, 'invalid private RC port')
        self.paths, self.remote, self.port = paths, remote, port
        self.process, self.stderr_file, self.password = None, None, None
        self.vfs_fs = None
        self.started, self.prepared, self.quarantined = False, False, False
        self.expected_dirty = expected_dirty or {}
        self.manifest_sha = None

    def prepare(self, writer):
        self.remote.validate()
        fd = p.directory(self.paths.base, create=True, private=True)
        os.close(fd)
        p.require(not mount_present(self.paths.mount), 'test mount already exists')
        p.require(not references((self.paths.cache, self.paths.mount, self.paths.config)),
                  'test paths already referenced')
        for path in (self.paths.cache, self.paths.mount):
            path.mkdir(mode=0o700)
        self.prepared = True
        private_write(self.paths.config, writer_config(writer, self.remote))
        self.password = secrets.token_urlsafe(32)
        private_write(self.paths.auth, p.canonical(dict(user='rhea-rehearsal', password=self.password)))
        private_write(self.paths.log, b'')
        private_write(self.paths.stderr, b'')

    def start(self):
        p.require(self.prepared and self.process is None, 'writer lifecycle already started')
        directory = p.directory(RCLONE.parent)
        fd = os.open(RCLONE.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                      and not stat.S_IMODE(info.st_mode) & 0o022 and info.st_size <= 128 * 1024 * 1024,
                      'unsafe rclone executable')
            digest = hashlib.sha256()
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''): digest.update(block)
            p.require(digest.hexdigest() == RCLONE_SHA256, 'rclone executable hash differs')
        finally:
            os.close(fd)
            os.close(directory)
        with socket.socket() as test:
            test.bind(('127.0.0.1', self.port))
        args, env = self.command()
        parent = os.getpid()
        def parent_death():
            if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
                os._exit(126)
        self.stderr_file = self.paths.stderr.open('ab', buffering=0)
        self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.stderr_file,
            stderr=self.stderr_file, env=env, cwd=self.paths.base, close_fds=True,
            start_new_session=True, preexec_fn=parent_death)
        self.started = True
        private_write(self.paths.base / 'writer-process.json', p.canonical(dict(
            pid=self.process.pid, executable_sha256=RCLONE_SHA256, remote=self.remote.fs,
            cache=str(self.paths.cache), mount=str(self.paths.mount), restart='none')))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            p.require(self.process.poll() is None, 'writer exited during startup')
            self.log_denials()
            if mount_present(self.paths.mount) and listener_owned(self.process.pid, self.port):
                p.require(self.rc('rc/noopauth', authenticated=False)[0] == 401,
                          'RC authentication was not enforced')
                p.require(self.rc('rc/noopauth')[0] == 200, 'authenticated RC unavailable')
                self.bind_vfs()
                return
            time.sleep(.25)
        raise REFUSAL('bounded writer startup timed out')

    def command(self):
        """Reviewable arguments; cloud credentials stay only in writer.conf."""
        args = [str(RCLONE), 'mount', self.remote.fs, str(self.paths.mount),
                '--config', str(self.paths.config), '--cache-dir', str(self.paths.cache),
                '--vfs-cache-mode', 'full', '--vfs-cache-max-size', '16M',
                '--vfs-cache-max-age', '24h', '--vfs-cache-poll-interval', '1s',
                '--vfs-write-back', '1s', '--vfs-read-ahead', '0', '--buffer-size', '0',
                '--transfers', '1', '--checkers', '1', '--retries', '1', '--low-level-retries', '1',
                '--contimeout', '5s', '--timeout', '10s', '--poll-interval', '0',
                '--dir-cache-time', '1s', '--no-modtime', '--umask', '077',
                '--s3-no-check-bucket', '--rc', '--rc-addr', f'127.0.0.1:{self.port}',
                '--use-json-log', '--log-level', 'INFO', '--log-file', str(self.paths.log)]
        env = dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LC_ALL='C',
                   RCLONE_RC_USER='rhea-rehearsal', RCLONE_RC_PASS=self.password)
        return args, env

    def rc(self, method, params=None, *, authenticated=True):
        p.require(method in ('rc/noopauth', 'vfs/list', 'vfs/queue', 'vfs/stats', 'vfs/queue-set-expiry'),
                  'unreviewed RC method')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            token = base64.b64encode(('rhea-rehearsal:' + self.password).encode()).decode()
            headers['Authorization'] = 'Basic ' + token
        try:
            connection.request('POST', '/' + method, json.dumps(params or {}), headers)
            response = connection.getresponse()
            body = response.read(MAX_LOG + 1)
            p.require(len(body) <= MAX_LOG, 'oversized RC response')
            if response.status != 200: return response.status, None
            value = json.loads(body)
            p.require(type(value) is dict, 'invalid RC response')
            return response.status, value
        finally:
            connection.close()

    def bind_vfs(self):
        code, value = self.rc('vfs/list')
        p.require(code == 200 and type(value.get('vfses')) is list and len(value['vfses']) == 1,
                  'isolated RC must own exactly one VFS')
        actual = value['vfses'][0]
        target = self.remote.bucket + '/' + self.remote.prefix.rstrip('/')
        p.require(type(actual) is str and re.fullmatch(
            r'iam_writer(?:\{[A-Za-z0-9_-]{1,64}\})?:' + re.escape(target) + r'/?', actual),
            'isolated VFS does not match writer scope')
        p.require(self.vfs_fs is None or self.vfs_fs == actual, 'isolated VFS identity changed')
        self.vfs_fs = actual
        private_write(self.paths.base / 'writer-vfs.json', p.canonical(dict(fs=actual)))

    def write(self, name, payload):
        p.require(name in (DATA, DIRTY) and type(payload) is bytes and len(payload) <= 1024,
                  'write outside fixed rehearsal fixture')
        p.require(self.process is not None and self.process.poll() is None
                  and mount_present(self.paths.mount), 'writer mount unavailable')
        script = ('import os,sys\n'
                  'raw=sys.stdin.buffer.read(1025)\n'
                  'assert len(raw)<=1024\n'
                  'fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)\n'
                  'try:\n'
                  ' with os.fdopen(fd,"wb",closefd=False) as stream:\n'
                  '  stream.write(raw);stream.flush();os.fsync(fd)\n'
                  'finally: os.close(fd)\n')
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(self.paths.mount / name)],
            input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LC_ALL='C'), timeout=20, check=False)
        p.require(result.returncode == 0, 'bounded FUSE write failed')

    def log_denials(self):
        for path in (self.paths.log, self.paths.stderr):
            p.require(path.stat().st_size <= MAX_LOG, 'rehearsal log exceeded bound')
        count = 0
        for line in self.paths.log.read_text(errors='replace').splitlines():
            try: row = json.loads(line)
            except json.JSONDecodeError: continue
            message = str(row.get('msg', '')) + ' ' + str(row.get('error', ''))
            if ('AccessDenied' in message and re.search(r'\b403\b', message)
                    and (row.get('object') == DIRTY or DIRTY in message)):
                count += 1
        return count

    def observe(self):
        p.require(self.process.poll() is None and listener_owned(self.process.pid, self.port),
                  'writer or authenticated RC listener changed')
        p.require(self.vfs_fs is not None, 'isolated VFS identity is unbound')
        code, queue = self.rc('vfs/queue', {'fs': self.vfs_fs})
        p.require(code == 200, 'VFS queue unavailable')
        names = [name for name in ('queued', 'queue') if name in queue]
        p.require(len(names) == 1 and type(queue[names[0]]) is list, 'unexpected VFS queue schema')
        rows = queue[names[0]]
        p.require(len(rows) <= 2 and all(row.get('name') in (DATA, DIRTY) for row in rows), 'unexpected queued file')
        code, stats = self.rc('vfs/stats', {'fs': self.vfs_fs})
        p.require(code == 200 and type(stats.get('diskCache')) is dict, 'VFS stats unavailable')
        disk = stats['diskCache']
        for field in ('path', 'pathMeta'):
            p.require(type(disk.get(field)) is str and '..' not in Path(disk[field]).parts
                      and Path(disk[field]).is_relative_to(self.paths.cache),
                      'VFS cache escaped isolated directory')
        p.require(disk.get('outOfSpace') is False and disk.get('bytesUsed', 0) <= 16 * 1024 * 1024,
                  'VFS cache bound exceeded')
        return dict(queue=rows, uploads_in_progress=disk.get('uploadsInProgress'),
                    uploads_queued=disk.get('uploadsQueued'), access_denials=self.log_denials())

    def defer_dirty(self, row):
        p.require(row.get('name') == DIRTY and type(row.get('id')) is int
                  and row.get('uploading') is False, 'dirty queue is not idle')
        p.require(self.vfs_fs is not None, 'isolated VFS identity is unbound')
        code, _ = self.rc('vfs/queue-set-expiry', dict(fs=self.vfs_fs, id=row['id'], expiry=3600))
        p.require(code == 200, 'dirty upload could not be deferred')

    def stop_and_quarantine(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.stderr_file is not None:
            self.stderr_file.close()
            self.stderr_file = None
        if mount_present(self.paths.mount):
            result = subprocess.run([FUSERMOUNT, '-u', str(self.paths.mount)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=8, check=False)
            p.require(result.returncode == 0, 'isolated mount could not be unmounted')
        p.require(not mount_present(self.paths.mount), 'isolated mount remains mounted')
        paths = (self.paths.cache, self.paths.mount, self.paths.config)
        p.require(not references(paths), 'isolated paths still have process references')
        if self.prepared and not self.quarantined:
            self.paths.quarantine.mkdir(mode=0o700)
            for path in (self.paths.cache, self.paths.config, self.paths.auth):
                if path.exists():
                    os.rename(path, self.paths.quarantine / path.name)
                private_write(path, BLOCKED_PATH)
            self.paths.mount.rmdir()
            private_write(self.paths.mount, BLOCKED_MOUNT)
            self.manifest_sha = self.cache_manifest()
            private_write(self.paths.base / 'quarantine-manifest.json', p.canonical(dict(
                sha256=self.manifest_sha, dirty_payload_preserved=True)))
            directory = p.directory(self.paths.base)
            os.fsync(directory)
            os.close(directory)
            self.quarantined = True
        return self.proof()

    def cache_manifest(self):
        root = self.paths.quarantine / 'cache'
        p.require(root.is_dir() and not root.is_symlink(), 'quarantined cache is missing')
        manifest, total, nodes = [], 0, 0
        found = {name: False for name in self.expected_dirty}
        for parent, dirs, files in os.walk(root, followlinks=False):
            nodes += len(dirs) + len(files)
            p.require(nodes <= 512, 'quarantine manifest exceeds bound')
            for name in dirs:
                p.require(not (Path(parent) / name).is_symlink(), 'symlink in quarantined cache')
            for name in files:
                path = Path(parent) / name
                info = path.lstat()
                p.require(stat.S_ISREG(info.st_mode) and info.st_uid == p.OWNER and info.st_nlink == 1
                          and not stat.S_IMODE(info.st_mode) & 0o022 and info.st_size <= 1024 * 1024,
                          'unexpected quarantined file')
                raw = path.read_bytes()
                total += len(raw)
                p.require(total <= 16 * 1024 * 1024, 'quarantine bytes exceed bound')
                if name in found and raw == self.expected_dirty[name]: found[name] = True
                manifest.append(dict(path=str(path.relative_to(root)), bytes=len(raw), sha256=p.sha(raw)))
        p.require(all(found.values()), 'denied dirty payload was not preserved in quarantine')
        return p.admin.iam.digest(sorted(manifest, key=lambda row: row['path']))

    def proof(self):
        stopped = self.process is None or self.process.poll() is not None
        p.require(stopped and not mount_present(self.paths.mount), 'writer is not stopped and unmounted')
        p.require(not references((self.paths.cache, self.paths.mount, self.paths.config, self.paths.quarantine)),
                  'quarantined paths still referenced')
        p.require(self.quarantined and self.paths.quarantine.is_dir()
                  and all(path.is_file() and not path.is_symlink() for path in
                          (self.paths.cache, self.paths.mount, self.paths.config, self.paths.auth)),
                  'cache/config/mount restart paths are not blocked')
        for path in (self.paths.cache, self.paths.mount, self.paths.config, self.paths.auth):
            info = path.lstat()
            expected = BLOCKED_MOUNT if path == self.paths.mount else BLOCKED_PATH
            p.require(info.st_uid == p.OWNER and info.st_nlink == 1
                      and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(expected)
                      and path.read_bytes() == expected, 'restart blocker changed')
        p.require(self.cache_manifest() == self.manifest_sha, 'quarantined cache changed')
        return dict(writer_stopped=True, unmounted=True, open_references=0, restart_paths_blocked=True,
                    quarantine=str(self.paths.quarantine), cache_quarantined=True,
                    cache_manifest_sha256=self.manifest_sha, dirty_payload_preserved=True)


def response_ok(value):
    p.response_ok(value)
    p.require('Error' not in value, 'embedded provider error')


class Cloud:
    """Read-only admin observations; publisher credential is loaded after proof."""
    def __init__(self, account, admin, publisher_factory):
        self.account, self.admin, self.publisher_factory = account, admin, publisher_factory

    def params(self, key=None, **extra):
        return dict(Bucket=REMOTE.bucket, ExpectedBucketOwner=self.account,
                    **({'Key': key} if key is not None else {}), **extra)

    def read(self, key, version=None):
        value = self.admin.get_object(**self.params(key, **({'VersionId': version} if version else {})))
        try:
            response_ok(value)
            body = value['Body'].read(1025)
            p.require(len(body) <= 1024 and live.opaque(value.get('VersionId'))
                      and (version is None or value['VersionId'] == version), 'invalid bounded version readback')
            return body, value['VersionId'], value.get('ETag')
        finally:
            if 'Body' in value: value['Body'].close()

    def no_uploads(self):
        for bucket in (p.admin.TEST_BUCKET, p.admin.CONTROL_BUCKET):
            value = self.admin.list_multipart_uploads(Bucket=bucket,
                ExpectedBucketOwner=self.account, MaxUploads=1000)
            response_ok(value)
            p.require(value.get('IsTruncated', False) is False and value.get('Uploads', []) == [],
                      'outstanding test multipart upload exists')

    def data_absent(self):
        try: self.read(REMOTE.prefix + DATA)
        except Exception as exc:
            detail = live.error_details(exc)
            p.require(detail['error_code'] == 'NoSuchKey' and detail['http_status'] == 404,
                      'fresh test data absence unconfirmed')
            return
        raise REFUSAL('rclone test data already exists; no replay')

    def data_uploaded(self):
        try: body, version, _ = self.read(REMOTE.prefix + DATA)
        except Exception as exc:
            detail = live.error_details(exc)
            if detail['error_code'] == 'NoSuchKey' and detail['http_status'] == 404: return None
            raise
        p.require(body == PAYLOAD, 'rclone data readback differs')
        return version

    def history(self):
        value = self.admin.list_object_versions(**self.params(Prefix=REMOTE.prefix, MaxKeys=1000))
        response_ok(value)
        p.require(value.get('IsTruncated', False) is False, 'protected history is truncated')
        def protected(key):
            tail = key.removeprefix(REMOTE.prefix)
            return key.startswith(REMOTE.prefix) and (tail == 'CURRENT' or any(
                tail == stem or tail.startswith(stem + '.') for stem in ('marker.manifest', 'marker.format-version')))
        rows = [row for row in value.get('Versions', []) if protected(row.get('Key', ''))]
        markers = [row for row in value.get('DeleteMarkers', []) if protected(row.get('Key', ''))]
        p.require(len(rows) <= 128 and not markers, 'unexpected protected history or delete marker')
        result = []
        for row in rows:
            p.require(live.opaque(row.get('VersionId')) and type(row.get('IsLatest')) is bool,
                      'incomplete protected version metadata')
            body, version, etag = self.read(row['Key'], row.get('VersionId'))
            p.require(live.opaque(etag), 'protected ETag missing')
            result.append(dict(key=row['Key'], version=version, latest=row.get('IsLatest') is True,
                               etag=etag, bytes=len(body), sha256=p.sha(body)))
        p.require(len({(row['key'], row['version']) for row in result}) == len(result),
                  'duplicate protected version metadata')
        for key in {row['key'] for row in result}:
            p.require(sum(row['key'] == key and row['latest'] for row in result) == 1,
                      'protected latest version is ambiguous')
        for key in (REMOTE.prefix + DIRTY, REMOTE.prefix + p.admin.MARKER):
            p.require(sum(row['key'] == key and row['latest'] for row in result) == 1,
                      'protected latest marker is missing or ambiguous')
        return sorted(result, key=lambda row: (row['key'], row['version']))

    def publish(self, baseline):
        key = REMOTE.prefix + p.admin.MARKER
        current = next(row for row in baseline if row['key'] == key and row['latest'])
        client = self.publisher_factory()
        try:
            value = live.ConditionalS3(client).put_object(**self.params(key, Body=PUBLISH_PAYLOAD, IfMatch=current['etag']))
            response_ok(value)
            version = value.get('VersionId')
            p.require(live.opaque(version), 'conditional publication has no version receipt')
        finally:
            client.close()
        body, observed, _ = self.read(key, version)
        p.require(observed == version and body == PUBLISH_PAYLOAD, 'conditional publication readback differs')
        after = self.history()
        old = {(row['key'], row['version']): {k: v for k, v in row.items() if k != 'latest'} for row in baseline}
        new = {(row['key'], row['version']): {k: v for k, v in row.items() if k != 'latest'} for row in after}
        p.require(set(new) - set(old) == {(key, version)} and all(new.get(k) == v for k, v in old.items()),
                  'publication changed unrelated protected versions')
        p.require({(row['key'], row['version']): row['latest'] for row in after if row['key'] != key}
                  == {(row['key'], row['version']): row['latest'] for row in baseline if row['key'] != key},
                  'publication changed another protected latest version')
        p.require(next(row for row in after if row['key'] == key and row['latest'])['version'] == version,
                  'publication is not current')
        return dict(version_id=version, history_sha256=p.admin.iam.digest(after), protected_versions=len(after))


def load_context():
    verified = managed.run('verify')
    with p.Journal() as old, managed.Journal() as credentials:
        binding, _ = managed.legacy_binding(old)
        receipts, pending = credentials.load_managed(binding)
        p.require(len(receipts) == 6 and pending is None and verified['plan_sha256'] == p.admin.iam.digest(binding),
                  'managed credential binding changed')
        raw = credentials.raw('writer.json')
        p.require(p.sha(raw) == receipts[4]['result']['credential_file_sha256'], 'writer credential changed')
        writer = p.admin.iam.parse(raw)
        publisher_sha = receipts[5]['result']['credential_file_sha256']
    import boto3
    from botocore.config import Config
    config = Config(retries={'total_max_attempts': 1, 'mode': 'standard'}, connect_timeout=5,
                    read_timeout=10, signature_version='v4', proxies={}, s3={'addressing_style': 'path'})
    def client(key, secret):
        return boto3.client('s3', endpoint_url=p.S3_ENDPOINT, region_name='ca-central-1',
                            aws_access_key_id=key, aws_secret_access_key=secret, config=config)
    admin = client(*p.source_credentials())
    def publisher_factory():
        with managed.Journal() as credentials:
            raw = credentials.raw('publisher.json')
            p.require(p.sha(raw) == publisher_sha, 'publisher credential changed')
            saved = p.admin.iam.parse(raw)
        return client(saved['AccessKeyId'], saved['SecretAccessKey'])
    return writer, Cloud(binding['identity']['account'], admin, publisher_factory), verified['plan_sha256']


def rehearse(host, cloud, journal, writer, *, now=time.monotonic, sleep=time.sleep):
    def event(name, fn):
        journal.write(name + '.intent.json', dict(operation=name))
        value = fn()
        journal.write(name + '.receipt.json', dict(operation=name, result=value))
        return value
    baseline = event('01-baseline-history', cloud.history)
    event('02-no-existing-uploads', cloud.no_uploads)
    event('03-data-absent', cloud.data_absent)
    failure, stopped = None, None
    observations, data_version = [], None
    try:
        event('04-prepare-writer', lambda: host.prepare(writer))
        event('05-start-writer', host.start)
        event('06-write-data', lambda: host.write(DATA, PAYLOAD))
        event('07-write-dirty-marker', lambda: host.write(DIRTY, DIRTY_PAYLOAD))
        deadline = now() + WAIT_SECONDS
        dirty = None
        while now() < deadline:
            sequence = len(observations)
            sample = event(f'08-observe-{sequence:04d}', host.observe)
            observations.append(sample)
            p.require(len(observations) <= 180, 'observation bound exceeded')
            data_version = event(f'08-data-readback-{sequence:04d}', cloud.data_uploaded)
            dirty = next((row for row in sample['queue'] if row.get('name') == DIRTY), None)
            if (data_version and dirty and type(dirty.get('tries')) is int and dirty['tries'] >= 2
                    and dirty.get('uploading') is False and sample['uploads_in_progress'] == 0
                    and sample['uploads_queued'] == 1 and len(sample['queue']) == 1
                    and sample['access_denials'] >= 2):
                break
            sleep(1)
        else:
            raise REFUSAL('bounded upload/denial retry evidence not obtained')
        journal.write('08-denial-observations.json', dict(samples=observations, data_version=data_version))
        event('09-defer-dirty-retry', lambda: host.defer_dirty(dirty))
    except Exception as exc:
        failure = exc
    finally:
        try: stopped = event('10-stop-and-quarantine', host.stop_and_quarantine)
        except Exception as exc:
            if failure is None: failure = exc
    if failure is not None: raise failure
    p.require(stopped == host.proof() and stopped.get('writer_stopped') is True
              and stopped.get('unmounted') is True and stopped.get('cache_quarantined') is True
              and stopped.get('open_references') == 0 and stopped.get('restart_paths_blocked') is True
              and stopped.get('dirty_payload_preserved') is True,
              'writer quiescence and quarantine unproven')
    event('11-no-outstanding-uploads', cloud.no_uploads)
    after = event('12-history-after-quarantine', cloud.history)
    p.require(after == baseline, 'dirty writer changed protected history')
    p.require(event('13-final-writer-proof', host.proof) == stopped, 'writer proof changed before publication')
    published = event('14-conditional-publisher', lambda: cloud.publish(after))
    event('15-no-final-uploads', cloud.no_uploads)
    p.require(event('16-final-writer-proof', host.proof) == stopped, 'writer proof changed after publication')
    return dict(result='PASS', scope='DISPOSABLE_BUCKET_ONLY', writer_data_version=data_version,
                actual_rehearsal_proven=True,
                denied_marker=DIRTY, denied_upload_attempts=dirty['tries'],
                writer_cache_quarantined=True, writer_stopped=True, writer_mount_removed=True,
                protected_history_preserved=True, conditional_publication=published,
                production_cutover_authorized=False, completed_at_utc=datetime.now(timezone.utc).isoformat())


def run(mode):
    p.require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', HOME='/nonexistent', LC_ALL='C', AWS_EC2_METADATA_DISABLED='true')
    if mode == 'status' and not STATE.exists(): return dict(result='NOT_STARTED', credentials='NOT_ACCESSED')
    with Journal() as journal:
        if journal.exists('result.json'): return journal.read('result.json')
        if mode == 'status': return dict(result='PENDING' if journal.exists('run.intent.json') else 'NOT_STARTED')
        p.require(not journal.exists('run.intent.json'), 'rehearsal already started; no cache restart or mutation replay')
        writer, cloud, plan_sha = load_context()
        try:
            journal.write('run.intent.json', dict(scope='DISPOSABLE_BUCKET_ONLY', bucket=REMOTE.bucket,
                prefix=REMOTE.prefix, data=DATA, dirty_marker=DIRTY, credential_plan_sha256=plan_sha,
                rclone_sha256=RCLONE_SHA256))
            host = NativeHost(HostPaths(STATE), REMOTE, expected_dirty={DIRTY: DIRTY_PAYLOAD})
            try: result = rehearse(host, cloud, journal, writer)
            except Exception as exc:
                result = dict(result='REFUSED', actual_rehearsal_proven=False, **live.error_details(exc))
                if type(exc) is REFUSAL: result['reason'] = str(exc)
            journal.write('result.json', result)
            return result
        finally:
            cloud.admin.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('status', 'run'))
    try:
        result = run(parser.parse_args(argv).mode)
    except Exception as exc:
        result = dict(result='REFUSED', actual_rehearsal_proven=False, **live.error_details(exc))
        if type(exc) is REFUSAL: result['reason'] = str(exc)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] != 'REFUSED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
