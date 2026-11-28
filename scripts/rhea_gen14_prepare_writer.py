"""Prepare generation 14 under Rhea's writer lock using a read-only clone mount."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

BASE = Path('/root/.local/share')
LEGACY = BASE / 'rhea-wasabi-lab-admin-20261101/full-clone-steps'
TRIAL = BASE / 'rhea-gen14-two-sst-20261125'
CERT_SHA = '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774'
STATE_SHA = 'c1563e322c496ca479c26501ef3f8ae2b71091565ee8fa227e24b4292f2cd90c'
MOUNT = '/mnt/rhea-pebble-lab-reader-20261102'
LOCK = '/run/rhea-wasabi-lab/writer.lock'
RECORD = 'prepared-writer-request.json'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def anchor():
    cert = (LEGACY / 'checkpoints/000013-step.json').read_bytes()
    state = (LEGACY / 'state.json').read_bytes()
    require(hashlib.sha256(cert).hexdigest() == CERT_SHA and hashlib.sha256(state).hexdigest() == STATE_SHA,
            'parked clone state differs from the certified generation')
    return json.loads(cert)


def retain(record):
    raw = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    TRIAL.mkdir(mode=0o700, exist_ok=True)
    for p in (TRIAL, *TRIAL.parents):
        st = p.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'unsafe preparation directory')
    require(stat.S_IMODE(TRIAL.stat().st_mode) == 0o700, 'private trial directory required')
    with tempfile.NamedTemporaryFile(dir=TRIAL) as candidate:
        candidate.write(raw)
        candidate.flush()
        os.fsync(candidate.fileno())
        try:
            os.link(candidate.name, TRIAL / RECORD)
        except FileExistsError:
            fd = os.open(TRIAL / RECORD, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as old:
                st = os.fstat(fd)
                require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600
                        and old.read(len(raw)+1) == raw, 'conflicting prepared request; preserve for inspection')
    for path in (TRIAL, TRIAL.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def prepare(binary, expected_sha):
    require(os.geteuid() == 0 and re.fullmatch('[0-9a-f]{64}', expected_sha), 'root and reviewed binary SHA required')
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as lock, tempfile.TemporaryDirectory(dir='/tmp', prefix='rhea-gen14-plan-') as scratch:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cert = anchor()
        fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            require(stat.S_ISREG(os.fstat(fd).st_mode), 'invalid planner file')
            data = source.read(128 * 1024**2 + 1)
        require(len(data) <= 128 * 1024**2 and hashlib.sha256(data).hexdigest() == expected_sha,
                'planner executable SHA differs')
        exe = Path(scratch) / 'planner'
        exe.write_bytes(data)
        exe.chmod(0o555)
        run = subprocess.run(['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
            '-p', 'ProtectSystem=strict', '-p', 'PrivateNetwork=yes', '-p', 'NoNewPrivileges=yes',
            '-p', 'CapabilityBoundingSet=', '-p', 'InaccessiblePaths=/root', '-p', 'ProtectHome=yes',
            '-p', 'RuntimeMaxSec=150', '-p', 'BindReadOnlyPaths=' + MOUNT, '-p', 'RestrictSUIDSGID=yes',
            str(exe), 'plan'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, check=True, timeout=180)
        proposal = json.loads(run.stdout)
        before = dict(format=cert['after_format'], marked=cert['marked_after'], files=cert['sst_count'],
                      bytes=cert['sst_bytes'], inventory_sha256=cert['sst_inventory_sha256'])
        require(proposal['request']['maximum_units'] == 2 and proposal['request']['before'] == before and
                proposal['request']['initial_plan_sha256'] == proposal['first_picker_plan']['plan_sha256']
                and anchor() == cert, 'live plan differs from certificate')
        record = dict(schema=1, generation=14, phase='prepared', previous_checkpoint_sha256=CERT_SHA,
                      binary_sha256=expected_sha, proposal=proposal)
        return dict(phase='prepared', record_sha256=retain(record), proposal=proposal)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('expected_sha256')
    args = parser.parse_args()
    print(json.dumps(prepare(args.binary, args.expected_sha256), sort_keys=True))
