"""Owned local child-process exercises; no host, credentials, cloud, or services."""
import base64
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(tempfile.gettempdir())
TEMPLATE = Path(__file__).resolve().with_name('supervise_rhea_bounded_adoption.py')
TEMPLATE_SHA = '5344def7b7c62603ae04174a7f6632421763cf75bc86bccab370c086cb1ebc68'
COMPLETION_SCOPE = 'fixed-generation-nine-bounded-verifier-adoption-completed'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def load():
    assert sha(TEMPLATE.read_bytes()) == TEMPLATE_SHA
    spec = importlib.util.spec_from_file_location('controlled_adoption_supervisor', TEMPLATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dummy(mode):
    source = '''import json, os, signal, sys, time
from pathlib import Path
base = Path(__file__).parent
assert sys.argv[1:] in (['--apply'], ['--resume'])
action = sys.argv[1][2:]
signal.signal(signal.SIGTERM, signal.SIG_IGN)
signal.signal(signal.SIGHUP, signal.SIG_IGN)
def save(name, value):
    with os.fdopen(os.open(base / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
save('dummy-ready-' + str(os.getpid()) + '.json', {'pid': os.getpid(), 'ppid': os.getppid(), 'group': os.getpgrp()})
mode = MODE
if mode in ('timeout', 'parent-hup', 'constructor-hup'):
    while True:
        time.sleep(60)
if mode == 'resume-success' and action == 'apply':
    save('failure.json', {'fixture_failure': True})
    raise SystemExit(7)
if not (base / 'completed.json').exists():
    time.sleep(0.02)
    save('dummy-proof.json', {'proof_performed_once': True})
    save('completed.json', {'schema': 1, 'scope': SCOPE, 'generation': 9, 'rewrites': 5,
                           'database_writer_invoked': False, 'pebble_open_performed': False})
print(json.dumps({'completed': True, 'action': action}))
'''
    return source.replace('MODE', repr(mode)).replace('SCOPE', repr(COMPLETION_SCOPE)).encode()


def prepare_payloads(module, mode):
    values = {name: (b'{"fixture":true,"pending":null}\n' if name.endswith('.json') else b'# inert local helper\n')
              for name in module.PAYLOAD_NAMES}
    values['run.py'] = dummy(mode)
    module.PAYLOADS = [{'name': name, 'base64': base64.b64encode(raw).decode(),
                        'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(values.items())]


def child_main(case, mode, action):
    module = load()
    module.TRUST = case / 'trust'
    module.OPS = module.TRUST / 'ops'
    module.OUTER_SECONDS = module.TERM_GRACE_SECONDS = 0.2
    prepare_payloads(module, mode)

    # Only path/root authorization is adapted to this ordinary local account.
    # Real Popen, process groups, signals, flock, fsync, wait/reap and receipts run.
    class AuthorizedLocalOS:
        @staticmethod
        def geteuid():
            return 0

        def __getattr__(self, name):
            return getattr(os, name)

    def local_protected(path, *, directory=False):
        relative = path.relative_to(case)
        current = case
        for component in (None, *relative.parts):
            if component is not None:
                current = current / component
            info = current.lstat()
            assert info.st_uid == os.getuid() and info.st_gid == os.getgid()
            assert not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o022
            if current != path:
                assert stat.S_ISDIR(info.st_mode)
        if directory:
            assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
        else:
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600

    module.os, module.protected = AuthorizedLocalOS(), local_protected
    if mode == 'constructor-hup':
        class InjectAfterRealSpawn:
            @staticmethod
            def Popen(*args, **kwargs):
                child = subprocess.Popen(*args, **kwargs)
                write(case / 'constructor-spawn.json', json_bytes({'pid': child.pid}))
                assert module.SPAWN_IN_PROGRESS is True
                os.kill(os.getpid(), signal.SIGHUP)
                assert module.DEFERRED_SIGNAL is True
                return child

            def __getattr__(self, name):
                return getattr(subprocess, name)

        module.subprocess = InjectAfterRealSpawn()
    try:
        module.main(['--' + action])
    except BaseException as error:
        print('Controlled supervisor exit (' + type(error).__name__ + ').', file=sys.stderr)
        return 1
    return 0


def absent(pid, *, group=False):
    try:
        (os.killpg if group else os.kill)(pid, 0)
    except ProcessLookupError:
        return True
    return False


def prepare(case):
    case.mkdir(mode=0o700)
    (case / 'trust').mkdir(mode=0o700)


def inventory(ops):
    return {path.name: {'sha256': sha(path.read_bytes()), 'bytes': path.stat().st_size,
                       'inode': path.stat().st_ino, 'mtime_ns': path.stat().st_mtime_ns}
            for path in sorted(ops.iterdir()) if path.is_file()}


def invoke(case, mode, action, label, *, expect_launch=True):
    ops = case / 'trust/ops'
    before_names = set() if not ops.exists() else {path.name for path in ops.iterdir()}
    started = time.perf_counter()
    process = subprocess.Popen([sys.executable, '-B', str(Path(__file__)), '--case', str(case), mode, action],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    child_pid, fallback = None, False
    try:
        if mode == 'parent-hup':
            deadline = time.monotonic() + 3
            while not ((ops / 'apply-launch.json').exists() and list(ops.glob('dummy-ready-*.json'))):
                assert process.poll() is None, 'supervisor exited before SIGHUP injection'
                assert time.monotonic() < deadline, 'launch/readiness deadline exceeded'
                time.sleep(0.002)
            child_pid = json.loads((ops / 'apply-launch.json').read_text())['pid']
            os.kill(process.pid, signal.SIGHUP)
        stdout, stderr = process.communicate(timeout=6)
        elapsed = time.perf_counter() - started
        write(case / (label + '.stdout'), stdout)
        write(case / (label + '.stderr'), stderr)
        assert elapsed < 3, 'controlled exercise exceeded its bound'
        new_timings = sorted(path for path in ops.glob('*-invocation-timing.json') if path.name not in before_names)
        if not expect_launch:
            assert process.returncode == 1 and not new_timings
            assert not any(path.name not in before_names and path.name.endswith('-launcher-intent.json')
                           for path in ops.iterdir())
            return {'supervisor_returncode': process.returncode, 'elapsed_seconds': elapsed,
                    'new_child_launched': False, 'new_attempt_receipts': False}
        assert len(new_timings) == 1
        timing = json.loads(new_timings[0].read_text())
        child_pid = timing['pid']
        assert timing['child_reaped'] is True
        assert absent(child_pid) and absent(child_pid, group=True), 'controlled child/group remains'
        assert timing['process_group_guard_failed'] is False
        assert timing['supervisor_error_type'] is None or mode in ('parent-hup', 'constructor-hup')
        if mode == 'timeout':
            assert process.returncode == 1 and timing['returncode'] == -signal.SIGKILL
            assert timing['outer_timeout'] and timing['term_sent'] and timing['kill_sent']
            assert 0.39 <= timing['elapsed_seconds'] < 2
        elif mode in ('parent-hup', 'constructor-hup'):
            assert process.returncode == 1 and timing['returncode'] == -signal.SIGKILL
            assert not timing['outer_timeout'] and not timing['term_sent'] and timing['kill_sent']
            assert timing['supervisor_error_type'] == 'SupervisorInterrupted'
            if mode == 'constructor-hup':
                assert not (ops / 'apply-launch.json').exists()
                assert json.loads((case / 'constructor-spawn.json').read_text())['pid'] == child_pid
        elif mode == 'resume-success' and action == 'apply':
            assert process.returncode == 1 and timing['returncode'] == 7
            assert not timing['completed_receipt_valid']
        else:
            assert process.returncode == timing['returncode'] == 0
            assert timing['completed_receipt_valid'] and timing['completion_error_type'] is None
            assert not timing['outer_timeout'] and not timing['term_sent'] and not timing['kill_sent']
        return {'supervisor_returncode': process.returncode, 'elapsed_seconds': elapsed, 'timing': timing,
                'pid_absent': True, 'process_group_absent': True, 'fallback_cleanup_used': False}
    finally:
        if child_pid is None:
            for path in (ops / 'apply-launch.json', case / 'constructor-spawn.json'):
                if path.exists():
                    child_pid = json.loads(path.read_text())['pid']
                    break
        if child_pid is not None and not absent(child_pid):
            fields = (Path('/proc') / str(child_pid) / 'stat').read_text().rpartition(') ')[2].split()
            assert int(fields[1]) in (process.pid, os.getpid()), 'refusing unrelated PID cleanup'
            assert os.getpgid(child_pid) == child_pid
            os.killpg(child_pid, signal.SIGKILL)
            fallback = True
        if process.poll() is None:
            process.kill()
            fallback = True
        process.wait(timeout=3)
        if child_pid is not None:
            try:
                os.waitpid(child_pid, os.WNOHANG)
            except ChildProcessError:
                pass
        assert not fallback, 'supervisor failed; controlled fallback cleanup was required'


def main():
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    workspace = Path(tempfile.mkdtemp(prefix='bounded-adoption-supervisor-local-', dir=ROOT))
    results = []
    for name in ('success', 'timeout', 'parent-hup', 'constructor-hup'):
        case = workspace / name
        prepare(case)
        results.append({'case': name, **invoke(case, name, 'apply', 'first')})

    case = workspace / 'fresh-apply-refusal'
    prepare(case)
    first = invoke(case, 'success', 'apply', 'first')
    before = inventory(case / 'trust/ops')
    refused = invoke(case, 'success', 'apply', 'refused', expect_launch=False)
    assert inventory(case / 'trust/ops') == before
    results.append({'case': case.name, 'first': first, 'refusal': refused, 'existing_files_unchanged': True})

    case = workspace / 'explicit-resume'
    prepare(case)
    failed = invoke(case, 'resume-success', 'apply', 'failed')
    ops = case / 'trust/ops'
    before = inventory(ops)
    resumed = invoke(case, 'resume-success', 'resume', 'resumed')
    after = inventory(ops)
    assert all(after[name] == value for name, value in before.items())
    assert resumed['timing']['attempt'] == 'resume-000001'
    assert (ops / 'failure.json').exists()
    proof = (ops / 'dummy-proof.json').stat()
    complete = (ops / 'completed.json').read_bytes()
    completed_resume = invoke(case, 'resume-success', 'resume', 'completed-resume')
    assert completed_resume['timing']['attempt'] == 'resume-000002'
    assert (ops / 'dummy-proof.json').stat().st_mtime_ns == proof.st_mtime_ns
    assert (ops / 'completed.json').read_bytes() == complete
    results.append({'case': case.name, 'failed': failed, 'resumed': resumed,
                    'completed_resume': completed_resume, 'prior_evidence_and_payloads_unchanged': True,
                    'completed_resume_no_new_proof': True})

    for reason in ('payload-mismatch', 'missing-reaped-receipt', 'unreaped-receipt', 'supervisor-lock-held'):
        case = workspace / reason
        prepare(case)
        invoke(case, 'success', 'apply', 'first')
        ops = case / 'trust/ops'
        lock_fd = None
        if reason == 'payload-mismatch':
            path = ops / 'scanner-candidate.py'
            with path.open('ab') as stream:
                stream.write(b'# altered local fixture\n')
        elif reason == 'missing-reaped-receipt':
            path = ops / 'apply-invocation-timing.json'
            write(case / 'removed-timing.json', path.read_bytes())
            path.unlink()
        elif reason == 'unreaped-receipt':
            path = ops / 'apply-invocation-timing.json'
            value = json.loads(path.read_bytes())
            value['child_reaped'] = False
            path.write_bytes(json_bytes(value))
        else:
            lock_fd = os.open(ops / 'supervisor.lock', os.O_RDWR)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = inventory(ops)
        try:
            refused = invoke(case, 'success', 'resume', 'refused', expect_launch=False)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
        assert inventory(ops) == before
        results.append({'case': reason, **refused, 'existing_files_unchanged': True})

    module = load()
    prepare_payloads(module, 'success')
    module.payloads()  # JSON literals true/null must be parsed, not compiled.
    rejected_json = []
    for raw in (b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'not JSON'):
        try:
            module.json_object(raw)
        except Exception:
            rejected_json.append(sha(raw))
        else:
            raise AssertionError('malformed JSON accepted')
    results.append({'case': 'strict-json-payload-validation', 'valid_payload_set_accepted': True,
                    'malformed_values_rejected': len(rejected_json)})

    assert sha(TEMPLATE.read_bytes()) == TEMPLATE_SHA
    report = {'schema': 1, 'supervisor_sha256': TEMPLATE_SHA, 'supervisor_unchanged': True,
              'local_uid': os.getuid(), 'authorization_only_adapted_for_owned_scratch': True,
              'no_hosts_cloud_or_credentials': True, 'outer_seconds': 0.2, 'grace_seconds': 0.2,
              'all_passed': True, 'cases': results}
    path = workspace / 'report.json'
    write(path, (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'report': str(path), 'report_sha256': sha(path.read_bytes()),
                      'supervisor_sha256': TEMPLATE_SHA, 'case_count': len(results), 'all_passed': True}))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--case':
        raise SystemExit(child_main(Path(sys.argv[2]), sys.argv[3], sys.argv[4]))
    main()
