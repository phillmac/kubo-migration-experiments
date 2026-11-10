"""Reviewed one-shot installer/supervisor; fill only exact source payloads."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'integrated-verification-profile-20261105'
PAYLOADS = []  # Filled locally only after all five installed sources are frozen.
OUTER_SECONDS = 900
TERM_GRACE_SECONDS = 15
SPAWN_IN_PROGRESS = False
DEFERRED_SIGNAL = False


class SupervisorInterrupted(BaseException):
    pass


def interrupted(signum, frame):
    global DEFERRED_SIGNAL
    if SPAWN_IN_PROGRESS:
        DEFERRED_SIGNAL = True
        return
    raise SupervisorInterrupted()


def emit(value):
    try:
        print(json.dumps(value), flush=True)
    except OSError:
        pass


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def protected(path, *, directory=False):
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'unprotected launch path')
    if directory:
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, 'launch directory mode differs')
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'launch file type/mode differs')


def new_bytes(name, raw):
    path = OPS / name
    require(path.parent == OPS and path.name == name, 'launch write outside fixed namespace')
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(OPS, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def new_json(name, value):
    return new_bytes(name, (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode())


def main():
    global SPAWN_IN_PROGRESS, DEFERRED_SIGNAL
    require(os.geteuid() == 0, 'root supervisor required')
    protected(TRUST, directory=True)
    require({row['name'] for row in PAYLOADS} == {'compare.py', 'enumerate_rhea_versions.py', 'verify_rhea_full_clone_bounded.py',
                'profile_rhea_full_clone_verification.py', 'verify_rhea_lab_format3.py'}
            and len(PAYLOADS) == 5, 'exact reviewed payload set required')
    decoded = {}
    for row in PAYLOADS:
        raw = base64.b64decode(row['base64'], validate=True)
        require(len(raw) == row['bytes'] <= 128 * 1024 and sha(raw) == row['sha256'], 'source payload differs')
        compile(raw, str(OPS / row['name']), 'exec')
        decoded[row['name']] = raw
    require(b'_SHA_PENDING' not in decoded['compare.py'], 'candidate source pins not finalized')
    pins = {
        TRUST / 'verification-profile-20261105/health.py': '617108d7b87b9879c622fcf22bc4ddf47ae258f680625cd4119661338c47a3f8',
        TRUST / 'verification-profile-20261105/replay.py': '6660de99fce5982bfcb66975b0e3869b891825a5d07942ea4a29bf56a2e125a1',
        TRUST / 'verification-profile-20261105/profile_rhea_full_clone_verification.py': '282643a0f8a209681c984d236ddc594978951faad25e0bb7b80be33f2975e741',
    }
    for path, digest in pins.items():
        protected(path)
        require(sha(path.read_bytes()) == digest, 'retained guard source differs')
    require(not OPS.exists() and not OPS.is_symlink(), 'comparison namespace already exists')
    os.mkdir(OPS, 0o700)
    parent_fd = os.open(TRUST, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    protected(OPS, directory=True)
    for row in PAYLOADS:
        require(new_bytes(row['name'], decoded[row['name']]) == row['sha256'], 'installed source hash differs')
    source_pins = {row['name']: {'sha256': row['sha256'], 'bytes': row['bytes']} for row in PAYLOADS}
    intent_sha = new_json('launcher-intent.json', {
        'schema': 1, 'scope': 'fixed-read-only-integrated-verification-supervisor', 'created_unix': time.time(),
        'sources': source_pins, 'outer_timeout_seconds': OUTER_SECONDS, 'term_grace_seconds': TERM_GRACE_SECONDS,
        'database_writer_invoked': False, 'automatic_retry_permitted': False})
    out_path, err_path = OPS / 'invocation.stdout', OPS / 'invocation.stderr'
    out_fd = os.open(out_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    err_fd = os.open(err_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    started, tick = time.time(), time.perf_counter()
    timed_out, term_sent, kill_sent = False, False, False
    group_guard_failed, supervisor_error_type, child = False, None, None

    def signal_child(sig):
        nonlocal group_guard_failed
        if child.poll() is not None:
            return
        try:
            group_owned = os.getpgid(child.pid) == child.pid
        except ProcessLookupError:
            group_owned = False
        if group_owned:
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                child.send_signal(sig)
        else:
            # Popen retains ownership of this unreaped child PID; an unverified
            # process group is never signalled.
            group_guard_failed = True
            child.send_signal(sig)

    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    with os.fdopen(out_fd, 'wb') as stdout, os.fdopen(err_fd, 'wb') as stderr:
        try:
            SPAWN_IN_PROGRESS = True
            try:
                child = subprocess.Popen([sys.executable, '-B', '-u', str(OPS / 'compare.py'), '--compare-current'],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, close_fds=True)
            finally:
                SPAWN_IN_PROGRESS = False
            if DEFERRED_SIGNAL:
                raise SupervisorInterrupted()
            require(os.getpgid(child.pid) == child.pid, 'child process group differs')
            launch = {'schema': 1, 'pid': child.pid, 'process_group': child.pid, 'started_unix': started,
                      'launcher_intent_sha256': intent_sha, 'sources': source_pins}
            new_json('launch.json', launch)
            emit({'launched': True, 'pid': child.pid, 'namespace': str(OPS)})
            try:
                child.wait(timeout=OUTER_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                    signal.signal(sig, signal.SIG_IGN)
                signal_child(signal.SIGTERM)
                term_sent = True
                try:
                    child.wait(timeout=TERM_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    signal_child(signal.SIGKILL)
                    kill_sent = True
                    child.wait()
        except BaseException as exc:
            supervisor_error_type = type(exc).__name__
        finally:
            # Unexpected supervisor errors also terminate and reap only this
            # dedicated read-only child. Never leave it running without control.
            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, signal.SIG_IGN)
            if child is not None:
                if child.poll() is None:
                    signal_child(signal.SIGKILL)
                    kill_sent = True
                child.wait()
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
    completed = (OPS / 'completed.json').is_file()
    failure = (OPS / 'failure.json').is_file()
    returncode = None if child is None else child.returncode
    timing = {'schema': 1, 'scope': 'fixed-read-only-integrated-verification-invocation', 'started_unix': started,
              'finished_unix': time.time(), 'elapsed_seconds': time.perf_counter() - tick,
              'returncode': returncode, 'pid': None if child is None else child.pid,
              'child_reaped': child is not None and child.returncode is not None,
              'outer_timeout': timed_out, 'term_sent': term_sent, 'kill_sent': kill_sent,
              'process_group_guard_failed': group_guard_failed, 'supervisor_error_type': supervisor_error_type,
              'completed_receipt_present': completed, 'failure_receipt_present': failure,
              'stdout_sha256': sha(out_path.read_bytes()), 'stderr_sha256': sha(err_path.read_bytes()),
              'launcher_intent_sha256': intent_sha, 'sources': source_pins}
    timing_sha = new_json('invocation-timing.json', timing)
    emit({'timing': timing, 'timing_sha256': timing_sha})
    require(returncode == 0 and not timed_out and not group_guard_failed and supervisor_error_type is None
            and completed and not failure, 'read-only comparison failed; no automatic retry')


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Integrated verification supervisor did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
