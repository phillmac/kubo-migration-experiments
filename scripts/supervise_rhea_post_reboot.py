"""One explicit, read-only post-reboot proof; never replay a prior invocation."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import types


sys.dont_write_bytecode = True
OPS = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101/post-reboot-20261106')
INSTALL = OPS / 'supervise.py'
OUT = OPS / 'supervision'
HEALTH_SHA = '4ccc2010e92a7e5202ef76a6f104af887246fa1e828b480d6b3bfcbcb63cb36f'
VERIFY_SHA = 'f1395771c687e95fae241ed90fe633b9546a1d1bb9c4493f024306a4f3c06f63'
IDENTITY_SHA = '3821f719ebc3b31df7cb77b02e516e3da2f11db5044df040f6be1129a9a14e67'
BOOT_ID = '6fc54ca7-d64a-4125-98fa-d0a728485237'
LIMIT = 4 * 1024 * 1024
SPAWNING = False
DEFERRED_SIGNAL = None


class Interrupted(BaseException):
    pass


def interrupted(signum, frame):
    global DEFERRED_SIGNAL
    if SPAWNING:
        DEFERRED_SIGNAL = signum
    else:
        raise Interrupted(signum)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def emit(value):
    try:
        print(json.dumps(value), flush=True)
    except OSError:
        pass


def protected(path, *, directory=False, executable=False):
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'unprotected supervisor path')
        if part != path:
            require(stat.S_ISDIR(info.st_mode), 'non-directory supervisor ancestor')
    if directory:
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
                'supervisor directory mode differs')
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and (bool(info.st_mode & 0o111) if executable else stat.S_IMODE(info.st_mode) == 0o600),
                'supervisor file type/mode differs')


def read(path, *, executable=False):
    protected(path, executable=executable)
    limit = 128 * 1024 * 1024 if executable else LIMIT
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'supervisor input exceeds bound')
    return raw


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def output(name):
    require(name in ('intent.json', 'launch.json', 'timing.json', 'health-after.json', 'stdout', 'stderr'),
            'unexpected supervision output')
    fd = os.open(OUT / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, 'wb')


def write(name, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    require(len(raw) <= LIMIT, 'supervision receipt exceeds bound')
    with output(name) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(OUT)
    return sha(raw)


def process(pid):
    try:
        text = Path('/proc', str(pid), 'stat').read_text()
        fields = text[text.rfind(')') + 2:].split()
        return {'pid': pid, 'ppid': int(fields[1]), 'pgrp': int(fields[2]),
                'session': int(fields[3]), 'start_ticks': fields[19], 'state': fields[0]}
    except FileNotFoundError:
        return None


def members(group):
    result = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            row = process(int(entry.name))
            if row is not None and row['pgrp'] == group:
                result.append(row)
    return sorted(result, key=lambda row: row['pid'])


def group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def main():
    global SPAWNING, DEFERRED_SIGNAL
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL and sys.argv[1:] == [],
            'fixed root supervisor invocation required')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT_ID,
            'supervisor boot identity differs')
    supervisor = process(os.getpid())
    require(supervisor is not None, 'supervisor identity unavailable')
    os.umask(0o077)
    protected(OPS, directory=True)
    sources = {}
    for name, expected in (('health.py', HEALTH_SHA), ('verify.py', VERIFY_SHA), ('identity.json', IDENTITY_SHA)):
        raw = read(OPS / name)
        require(sha(raw) == expected, 'supervisor source or identity pin differs')
        sources[name] = {'sha256': sha(raw), 'bytes': len(raw)}
    own = read(INSTALL)
    sources['supervise.py'] = {'sha256': sha(own), 'bytes': len(own)}
    binaries = {}
    for path in (Path('/usr/bin/timeout'), Path('/usr/bin/python3').resolve(strict=True)):
        raw = read(path, executable=True)
        binaries[str(path)] = {'sha256': sha(raw), 'bytes': len(raw)}
    require(not (OPS / 'verification').exists() and not (OPS / 'verification').is_symlink(),
            'a verification attempt already exists; no replay permitted')
    OUT.mkdir(mode=0o700)  # Exclusive namespace is the one-shot admission gate.
    sync_dir(OPS)
    protected(OUT, directory=True)
    argv = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=15s', '600s',
            '/usr/bin/python3', '-B', '-u', str(OPS / 'verify.py'), '--identity-sha256', IDENTITY_SHA]
    intent_sha = write('intent.json', {
        'schema': 1, 'scope': 'rhea-post-reboot-proof-supervision-intent', 'created_unix': time.time(),
        'argv': argv, 'sources': sources, 'binaries': binaries, 'identity_sha256': IDENTITY_SHA,
        'boot_id': BOOT_ID, 'supervisor': supervisor,
        'timeout_seconds': 600, 'term_grace_seconds': 15, 'parent_backstop_seconds': 630,
        'post_proof_health_deadline_seconds': 60,
        'automatic_retry_permitted': False, 'database_writer_invoked': False,
        'journal_mutated': False, 'checkpoint_replaced': False})
    child = None
    child_start = None
    launch_members = []
    error = None
    parent_timeout = False
    cleanup_error = None
    term_sent = kill_sent = False
    started, tick = time.time(), time.perf_counter()

    def signal_group(sig):
        nonlocal term_sent, kill_sent
        rows = members(child.pid)
        require(all(row['session'] == child.pid and (child_start is None
                    or int(row['start_ticks']) >= int(child_start)) for row in rows),
                'owned process group identity differs')
        try:
            os.killpg(child.pid, sig)
            term_sent |= sig == signal.SIGTERM
            kill_sent |= sig == signal.SIGKILL
        except ProcessLookupError:
            pass

    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    with output('stdout') as stdout, output('stderr') as stderr:
        sync_dir(OUT)
        try:
            SPAWNING = True
            try:
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                         start_new_session=True, close_fds=True)
            finally:
                SPAWNING = False
            if DEFERRED_SIGNAL is not None:
                raise Interrupted(DEFERRED_SIGNAL)
            row = process(child.pid)
            require(row is not None and row['pgrp'] == child.pid and row['session'] == child.pid,
                    'timeout did not enter its own session')
            child_start = row['start_ticks']
            launch_members = members(child.pid)
            write('launch.json', {'schema': 1, 'started_unix': started, 'pid': child.pid,
                  'process_group': child.pid, 'session': child.pid, 'start_ticks': child_start,
                  'boot_id': BOOT_ID, 'supervisor': supervisor,
                  'observed_members': launch_members, 'intent_sha256': intent_sha, 'sources': sources})
            emit({'launched': True, 'timeout_pid': child.pid, 'namespace': str(OUT)})
            try:
                child.wait(timeout=630)
            except subprocess.TimeoutExpired:
                parent_timeout = True
                raise
        except BaseException as exc:
            error = type(exc).__name__
        finally:
            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, signal.SIG_IGN)
            if child is not None:
                try:
                    if child.poll() is None or group_exists(child.pid):
                        signal_group(signal.SIGTERM)
                        end = time.monotonic() + 15
                        while time.monotonic() < end:
                            child.poll()
                            if not group_exists(child.pid):
                                break
                            time.sleep(0.1)
                        if group_exists(child.pid):
                            signal_group(signal.SIGKILL)
                except BaseException as exc:
                    cleanup_error = type(exc).__name__
                    # Keep the independent timeout alive unless its still-owned
                    # session/group can be signalled together with the verifier.
                    # Killing only timeout would remove the verifier's backstop.
                    if child.poll() is None:
                        try:
                            require(os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid,
                                    'timeout no longer leads the owned session/group')
                            os.killpg(child.pid, signal.SIGKILL)
                            kill_sent = True
                        except ProcessLookupError:
                            pass
                        except BaseException as guard_exc:
                            cleanup_error = type(guard_exc).__name__
                finally:
                    child.wait()
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    absent = False
    remaining = []
    if child is not None:
        end = time.monotonic() + 5
        while group_exists(child.pid) and time.monotonic() < end:
            time.sleep(0.1)
        remaining = members(child.pid)
        absent = not group_exists(child.pid) and process(child.pid) is None and not remaining
    completion_sha = health_sha = None
    completion_error = None
    if (child is not None and child.returncode == 0 and error is None and cleanup_error is None
            and absent and not parent_timeout):
        try:
            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
                signal.signal(sig, interrupted)
            signal.alarm(60)
            require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT_ID,
                    'supervisor boot changed during proof')
            for name, pin in sources.items():
                raw = read(OPS / name)
                require(sha(raw) == pin['sha256'] and len(raw) == pin['bytes'], 'post-proof source changed')
            require(str(Path('/usr/bin/python3').resolve(strict=True)) in binaries, 'Python link changed')
            for path, pin in binaries.items():
                raw = read(Path(path), executable=True)
                require(sha(raw) == pin['sha256'] and len(raw) == pin['bytes'], 'supervisor binary changed')
            health = types.ModuleType('post_reboot_supervised_health')
            health.__file__ = str(OPS / 'health.py')
            sys.modules[health.__name__] = health
            exec(compile(read(OPS / 'health.py'), health.__file__, 'exec'), health.__dict__)
            ctx = health.load()  # Requires and validates the complete retained proof.
            require(ctx['identity_sha256'] == IDENTITY_SHA, 'completed proof changed identity')
            with ctx['rt'].lock():
                observed = health.observe(ctx, authenticated_rc=True)
            health_sha = write('health-after.json', observed)
            completion_sha = sha(read(OPS / 'verification/completed.json'))
        except BaseException as exc:
            completion_error = type(exc).__name__
        finally:
            signal.alarm(0)
            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, signal.SIG_IGN)
    timing = {'schema': 1, 'scope': 'rhea-post-reboot-proof-supervision-timing',
        'started_unix': started, 'finished_unix': time.time(), 'elapsed_seconds': time.perf_counter() - tick,
        'boot_id': BOOT_ID, 'supervisor': supervisor,
        'intent_sha256': intent_sha, 'identity_sha256': IDENTITY_SHA, 'sources': sources,
        'pid': None if child is None else child.pid, 'process_group': None if child is None else child.pid,
        'returncode': None if child is None else child.returncode,
        'child_reaped': child is not None and child.returncode is not None,
        'child_and_group_absent': absent, 'remaining_group_members': remaining,
        'gnu_timeout_or_kill_status': child is not None and child.returncode in (124, 137, -signal.SIGKILL),
        'parent_backstop_timeout': parent_timeout, 'parent_term_sent': term_sent, 'parent_kill_sent': kill_sent,
        'supervisor_error_type': error, 'cleanup_error_type': cleanup_error,
        'completion_error_type': completion_error,
        'completed_sha256': completion_sha, 'health_after_sha256': health_sha,
        'stdout_sha256': sha(read(OUT / 'stdout')), 'stderr_sha256': sha(read(OUT / 'stderr')),
        'automatic_retry_permitted': False, 'database_writer_invoked': False,
        'journal_mutated': False, 'checkpoint_replaced': False}
    timing_sha = write('timing.json', timing)
    emit({'timing_sha256': timing_sha, 'returncode': timing['returncode'],
          'child_and_group_absent': absent, 'completed_sha256': completion_sha})
    require(child is not None and child.returncode == 0 and absent and error is None
            and cleanup_error is None and not parent_timeout
            and completion_error is None and completion_sha is not None,
            'post-reboot verification supervision failed; inspect receipts before any further action')


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        emit({'completed': False, 'error_type': type(exc).__name__, 'automatic_retry_permitted': False})
        raise SystemExit(1) from None
