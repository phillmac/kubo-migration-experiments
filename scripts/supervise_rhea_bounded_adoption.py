"""Stage reviewed adoption inputs and supervise one explicit apply or resume.

Only the child transaction installs operational code or changes state. This
supervisor writes within the separate adoption namespace, never overwrites a
payload, and never retries a child. Fill PAYLOADS with exact reviewed bytes.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'bounded-adoption-20261106'
PAYLOADS = []  # Filled locally only after every source and JSON input is frozen.
PAYLOAD_NAMES = frozenset({
    'run.py', 'health.py', 'transaction.py', 'controller-candidate.py',
    'verifier-candidate.py', 'scanner-candidate.py', 'expected-state-before.json',
    'expected-pins-before.json', 'deployment.json',
})
OUTER_SECONDS = 600
TERM_GRACE_SECONDS = 15
MAX_PAYLOAD_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
INTENT_SCOPE = 'fixed-bounded-verifier-adoption-supervisor'
TIMING_SCOPE = 'fixed-bounded-verifier-adoption-invocation'
COMPLETION_SCOPE = 'fixed-generation-nine-bounded-verifier-adoption-completed'
ATTEMPT = re.compile(r'(apply|resume-([0-9]{6}))-launcher-intent\.json')
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


def json_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(value):
        raise RuntimeError('nonfinite JSON number')

    def finite(value):
        if isinstance(value, dict):
            return all(finite(item) for item in value.values())
        if isinstance(value, list):
            return all(finite(item) for item in value)
        return not isinstance(value, float) or math.isfinite(value)

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(type(value) is dict and finite(value), 'JSON object with finite numbers required')
    return value


def protected(path, *, directory=False):
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'unprotected launch path')
        if part != path:
            require(stat.S_ISDIR(info.st_mode), 'launch ancestor is not a directory')
    if directory:
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
                'launch directory mode differs')
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'launch file type/mode differs')


def read_protected(path, limit=MAX_RECEIPT_BYTES):
    protected(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'protected input exceeds bound')
    return raw


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_output(name):
    path = OPS / name
    require(path.parent == OPS and path.name == name, 'launch write outside fixed namespace')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, 'wb')


def new_bytes(name, raw):
    with new_output(name) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(OPS)
    return sha(raw)


def new_json(name, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    require(len(raw) <= MAX_RECEIPT_BYTES, 'launch receipt exceeds bound')
    return new_bytes(name, raw)


def payloads():
    require(type(PAYLOADS) is list and len(PAYLOADS) == len(PAYLOAD_NAMES), 'exact reviewed payload set required')
    decoded, source_pins = {}, {}
    for row in PAYLOADS:
        require(type(row) is dict and set(row) == {'name', 'base64', 'bytes', 'sha256'}, 'invalid source payload')
        name = row['name']
        require(type(name) is str and name in PAYLOAD_NAMES and name not in decoded, 'invalid payload name')
        require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_PAYLOAD_BYTES
                and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
                and type(row['base64']) is str, 'invalid payload metadata')
        require(len(row['base64']) <= 4 * ((MAX_PAYLOAD_BYTES + 2) // 3), 'encoded payload exceeds bound')
        raw = base64.b64decode(row['base64'], validate=True)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'source payload differs')
        if name.endswith('.py'):
            require(b'_SHA_PENDING' not in raw, 'source pins not finalized')
            compile(raw, str(OPS / name), 'exec')
        else:
            json_object(raw)
        decoded[name] = raw
        source_pins[name] = {'sha256': row['sha256'], 'bytes': row['bytes']}
    require(set(decoded) == PAYLOAD_NAMES, 'exact reviewed payload set required')
    return decoded, source_pins


def previous_attempts(source_pins):
    """Never infer an old child's exit, or signal a process we did not launch."""
    references, last_resume = [], 0
    for path in sorted(OPS.iterdir()):
        match = ATTEMPT.fullmatch(path.name)
        if match is None:
            continue
        prefix = match.group(1)
        if match.group(2) is not None:
            number = int(match.group(2))
            require(number > 0, 'invalid resume attempt number')
            last_resume = max(last_resume, number)
        intent_raw = read_protected(path)
        intent = json_object(intent_raw)
        require(intent.get('schema') == 1 and type(intent.get('schema')) is int
                and intent.get('scope') == INTENT_SCOPE and intent.get('sources') == source_pins
                and intent.get('attempt') == prefix, 'prior supervisor intent differs')
        timing_path = OPS / (prefix + '-invocation-timing.json')
        require(timing_path.exists() and not timing_path.is_symlink(),
                'prior supervisor lacks a reaped receipt; independent reconciliation required')
        timing_raw = read_protected(timing_path)
        timing = json_object(timing_raw)
        require(timing.get('schema') == 1 and type(timing.get('schema')) is int
                and timing.get('scope') == TIMING_SCOPE and timing.get('sources') == source_pins
                and timing.get('attempt') == prefix and timing.get('launcher_intent_sha256') == sha(intent_raw)
                and timing.get('child_reaped') is True and type(timing.get('pid')) is int and timing['pid'] > 0
                and type(timing.get('returncode')) is int,
                'prior supervisor lacks a matching reaped receipt; independent reconciliation required')
        references.append({'attempt': prefix, 'intent_sha256': sha(intent_raw), 'timing_sha256': sha(timing_raw)})
    require(last_resume < 999_999, 'resume attempt namespace exhausted')
    return references, 'resume-' + format(last_resume + 1, '06d')


def completion():
    path = OPS / 'completed.json'
    if not path.exists() and not path.is_symlink():
        return False, None, None
    raw = read_protected(path)
    value = json_object(raw)
    require(type(value.get('schema')) is int and value['schema'] == 1
            and value.get('scope') == COMPLETION_SCOPE
            and type(value.get('generation')) is int and value['generation'] == 9
            and type(value.get('rewrites')) is int and value['rewrites'] == 5
            and value.get('database_writer_invoked') is False and value.get('pebble_open_performed') is False,
            'adoption completion scope differs')
    return True, sha(raw), value


def supervise(action, attempt, source_pins, prior_attempts):
    global SPAWN_IN_PROGRESS, DEFERRED_SIGNAL
    SPAWN_IN_PROGRESS, DEFERRED_SIGNAL = False, False
    intent_sha = new_json(attempt + '-launcher-intent.json', {
        'schema': 1, 'scope': INTENT_SCOPE, 'action': action, 'attempt': attempt, 'created_unix': time.time(),
        'sources': source_pins, 'outer_timeout_seconds': OUTER_SECONDS, 'term_grace_seconds': TERM_GRACE_SECONDS,
        'prior_attempts': prior_attempts, 'database_writer_invoked': False,
        'operational_targets_installed_by_supervisor': False, 'automatic_retry_permitted': False})
    out_name, err_name = attempt + '-invocation.stdout', attempt + '-invocation.stderr'
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
            group_guard_failed = True
            child.send_signal(sig)

    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    with new_output(out_name) as stdout, new_output(err_name) as stderr:
        try:
            SPAWN_IN_PROGRESS = True
            try:
                child = subprocess.Popen([sys.executable, '-B', '-u', str(OPS / 'run.py'), '--' + action],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, close_fds=True)
            finally:
                SPAWN_IN_PROGRESS = False
            if DEFERRED_SIGNAL:
                raise SupervisorInterrupted()
            require(os.getpgid(child.pid) == child.pid, 'child process group differs')
            new_json(attempt + '-launch.json', {
                'schema': 1, 'action': action, 'attempt': attempt, 'pid': child.pid, 'process_group': child.pid,
                'started_unix': started, 'launcher_intent_sha256': intent_sha, 'sources': source_pins})
            emit({'launched': True, 'action': action, 'attempt': attempt, 'pid': child.pid, 'namespace': str(OPS)})
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
    completed, completed_sha, completion_error_type = False, None, None
    try:
        completed, completed_sha, _ = completion()
    except Exception as exc:
        completion_error_type = type(exc).__name__
    returncode = None if child is None else child.returncode
    timing = {
        'schema': 1, 'scope': TIMING_SCOPE, 'action': action, 'attempt': attempt, 'started_unix': started,
        'finished_unix': time.time(), 'elapsed_seconds': time.perf_counter() - tick,
        'returncode': returncode, 'pid': None if child is None else child.pid,
        'child_reaped': child is not None and child.returncode is not None,
        'outer_timeout': timed_out, 'term_sent': term_sent, 'kill_sent': kill_sent,
        'process_group_guard_failed': group_guard_failed, 'supervisor_error_type': supervisor_error_type,
        'completed_receipt_valid': completed, 'completed_receipt_sha256': completed_sha,
        'completion_error_type': completion_error_type,
        'stdout_sha256': sha(read_protected(OPS / out_name)),
        'stderr_sha256': sha(read_protected(OPS / err_name)),
        'launcher_intent_sha256': intent_sha, 'sources': source_pins,
    }
    timing_sha = new_json(attempt + '-invocation-timing.json', timing)
    emit({'timing': timing, 'timing_sha256': timing_sha})
    require(returncode == 0 and not timed_out and not group_guard_failed and supervisor_error_type is None
            and completed and completion_error_type is None, 'adoption invocation failed; no automatic retry')
    return timing


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--resume', action='store_true')
    args = parser.parse_args(argv)
    action = 'apply' if args.apply else 'resume'
    require(os.geteuid() == 0, 'root supervisor required')
    protected(TRUST, directory=True)
    decoded, source_pins = payloads()
    if action == 'apply':
        require(not OPS.exists() and not OPS.is_symlink(), 'adoption namespace already exists; explicit resume required')
        os.mkdir(OPS, 0o700)
        sync_dir(TRUST)
    protected(OPS, directory=True)
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if action == 'apply':
        flags |= os.O_CREAT | os.O_EXCL
    lock_path = OPS / 'supervisor.lock'
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        protected(lock_path)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'apply':
            os.fsync(lock_fd)
            sync_dir(OPS)
            for name, raw in decoded.items():
                require(new_bytes(name, raw) == source_pins[name]['sha256'], 'staged payload hash differs')
            prior, attempt = [], 'apply'
        else:
            for name, raw in decoded.items():
                require(read_protected(OPS / name, MAX_PAYLOAD_BYTES) == raw, 'staged resume payload differs')
            prior, attempt = previous_attempts(source_pins)
        return supervise(action, attempt, source_pins, prior)
    finally:
        os.close(lock_fd)


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        print('Bounded adoption supervisor did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        raise SystemExit(1) from None
