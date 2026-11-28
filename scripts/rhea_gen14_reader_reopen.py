"""Read-only qualification of Rhea's temporary generation-13 rclone service.

The candidate has a private /mnt, a clone-only credential, and the host writer
lock. This observer verifies the service, reads the pinned metadata and runs
the inspector as nobody inside that mount namespace with networking disabled.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

UNIT = 'rhea-gen14-reader-qualification-20261127.service'
MOUNT = '/mnt/rhea-pebble-lab-reader-20261102'
INSPECTOR = '/run/rhea-gen14-ro-inspector'
ROOT = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101/full-clone-steps')
CERT = ROOT / 'checkpoints/000013-step.json'
CERT_SHA = '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774'
STATE_SHA = 'c1563e322c496ca479c26501ef3f8ae2b71091565ee8fa227e24b4292f2cd90c'
INSPECTOR_SHA = '1e3e16624ebd61ed3cccf4cd680be467dc9faa5861a685961783fd80bf8a20a6'
RCLONE_SHA = 'dc1ec3109000e4d36c8d14efac6d4c4158d1b860853cb75c09dcc9f6dded420b'
REMOTE = 'rhea_pebble_lab_reader:rhea-pebble-lab-20261101-39037c6f01/rhea'
LOCK = '/run/rhea-wasabi-lab/writer.lock'


def require(condition, issue):
    if not condition:
        raise RuntimeError(issue)


def digest_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def mount_rows(proc):
    return [row for row in (proc / 'mountinfo').read_text().splitlines() if row.split()[4] == MOUNT]


def service_identity():
    pid = int(subprocess.check_output(['/usr/bin/systemctl', 'show', '--value', '-p', 'MainPID', UNIT],
                                      text=True, timeout=10))
    require(pid > 1, 'qualification reader is inactive')
    proc = Path('/proc') / str(pid)
    require(os.readlink(proc / 'exe') == '/usr/bin/rclone' and digest_file(proc / 'exe') == RCLONE_SHA
            and os.readlink(proc / 'ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'unexpected reader identity')
    args = (proc / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
    for name, value in (('mount', REMOTE), ('--config', '/run/credentials/' + UNIT + '/reader.conf'),
                        ('--vfs-cache-mode', 'off')):
        require(args.count(name) == 1 and args[args.index(name) + 1] == value, 'unexpected reader command')
    require(args[args.index('mount') + 2] == MOUNT and args.count('--read-only') == 1,
            'fresh clone reader command lacks read-only mount')
    rows = mount_rows(proc)
    fuse = [row for row in rows if row.split(' - ')[1].split()[0] == 'fuse.rclone']
    require(len(fuse) == 1 and 'ro' in fuse[0].split()[5].split(',') and
            re.fullmatch(r'rhea_pebble_lab_reader(?:\{[A-Za-z0-9_-]+\})?:rhea-pebble-lab-20261101-39037c6f01/rhea',
                         fuse[0].split(' - ')[1].split()[1]), 'expected a fresh read-only FUSE mount')
    lock = os.stat(LOCK)
    def held(line):
        fields = line.split()
        if len(fields) < 8 or fields[1:5] != ['FLOCK', 'ADVISORY', 'WRITE', str(pid)]:
            return False
        maj, minor, inode = fields[5].split(':')
        return (int(maj, 16), int(minor, 16), int(inode)) == (os.major(lock.st_dev), os.minor(lock.st_dev), lock.st_ino)
    require(any(held(line) for line in Path('/proc/locks').read_text().splitlines()),
            'candidate does not hold the existing host writer lock')
    return pid, (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19], tuple(rows)


def certify_metadata(db, cert):
    for name, pin in cert['remote_metadata'].items():
        require(Path(name).name == name, 'invalid metadata name in certificate')
        path = db / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == pin['size'] and
                digest_file(path) == pin['sha256'], 'clone metadata differs: ' + name)


def run():
    anchor = (digest_file(CERT), digest_file(ROOT / 'state.json'))
    require(anchor == (CERT_SHA, STATE_SHA), 'generation-13 anchor changed')
    cert = json.loads(CERT.read_bytes())
    require(len(cert['remote_metadata']) == 8 and cert['generation'] == 13, 'checkpoint schema differs')
    identity = service_identity()
    pid = identity[0]
    root = Path('/proc') / str(pid) / 'root'
    db = root / MOUNT.lstrip('/') / 'pebbleds'
    parked = mount_rows(Path('/proc/1'))
    require(len(parked) == 1 and ' - fuse.rclone ' in parked[0], 'parked reader absent or ambiguous')
    require(digest_file(root / INSPECTOR.lstrip('/')) == INSPECTOR_SHA and os.statvfs(db).f_flag & os.ST_RDONLY,
            'inspector digest or kernel mount differs')
    certify_metadata(db, cert)
    try:
        fd = os.open(db / 'CURRENT', os.O_WRONLY | os.O_NOFOLLOW)
    except OSError as exc:
        require(exc.errno == errno.EROFS, 'kernel failed to deny writable open with EROFS')
    else:
        os.close(fd)
        raise RuntimeError('kernel admitted a writable open of CURRENT')
    result = subprocess.run(['/usr/bin/nsenter', '--target', str(pid), '--mount',
        '/usr/bin/unshare', '--net', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
        '--clear-groups', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
        '--no-new-privs', INSPECTOR, '--db', MOUNT + '/pebbleds', '--require-read-only-mount'],
        stdout=subprocess.PIPE, timeout=150, check=True)
    report = json.loads(result.stdout)
    require(report['mount_read_only'] is True and report['read_only'] is True and
            (report['format_major_version'], report['marked_files'], report['sst_count'], report['sst_bytes'])
            == (cert['after_format'], cert['marked_after'], cert['sst_count'], cert['sst_bytes']),
            'Pebble reopen differs from the certificate')
    certify_metadata(db, cert)
    require(service_identity() == identity and mount_rows(Path('/proc/1')) == parked
            and (digest_file(CERT), digest_file(ROOT / 'state.json')) == anchor,
            'service, parked reader or anchor changed during inspection')
    summary = {k: report[k] for k in ('format_major_version', 'marked_files', 'sst_count',
                                      'sst_bytes', 'mount_read_only', 'elapsed_seconds')}
    return dict(result='PASS', generation=13, certificate_sha256=CERT_SHA, inspector_sha256=INSPECTOR_SHA,
                rclone_sha256=RCLONE_SHA, metadata_files_verified_before_and_after=len(cert['remote_metadata']),
                metadata_bytes_each_pass=sum(p['size'] for p in cert['remote_metadata'].values()),
                writable_open='EROFS', inspector_uid=65534, private_network_for_inspector=True,
                vfs_cache_mode='off', fresh_rclone_read_only=True, host_writer_lock_held=True,
                parked_reader_preserved=True, **summary)


if __name__ == '__main__':
    print(json.dumps(run(), sort_keys=True))
