"""One explicit reader/writer handoff or closed-batch reader restoration.

This recipe never invokes a database writer or changes the migration journal.
It uses the original paired runtime/wrapper for service and read-only work.
All service actions have exclusive intent receipts; no action is replayed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'pacing-batch2-20261107'
INSTALL = OPS / 'mounts.py'
HEALTH = OPS / 'health.py'
HEALTH_SHA = '2781718c06389a0753cc23b6ff39d97bac388f492399dbb1bb637d57dbf4db1e'
STATE_AFTER_SHA = '0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9'
CERT9_SHA = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
UNIT_SHA = '193fd66756a7c3b2c340dc8f7e0868d54767a2877f83dfcd18160564ebff1dfe'
INSPECTOR_SHA = '6c0f7cb23cb4f5dcf42898334c70df65574ab21769024091c5036123bbbb3bc8'
MAX_JSON = 16 * 1024**2
STOP_REQUESTED = False
START_NAMES = (
    'reader-stop-intent.json', 'reader-stop-observed.json', 'reader-stopped.json',
    'reader-reset-intent.json', 'reader-reset-completed.json',
    'writer-stage-intent.json', 'writer-staged.json', 'writer-start-intent.json',
    'writer-started.json', 'writer-generation-before-open.json',
    'writer-generation-after-open.json', 'writer-read-only-reopen.json',
    'start-completed.json', 'start-failure.json',
)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def interrupted(signum, frame):
    # Do not raise in a service call or while the existing runtime owns a Go child.
    global STOP_REQUESTED
    STOP_REQUESTED = True


def cancellation_point():
    require(not STOP_REQUESTED, 'mount lifecycle interrupted; inspect retained state before further actions')


def classify_reader_stop(service, *, process_absent, mount_absent):
    """Only an absent reader can be collected; the known intentional exit143 is explicit."""
    require(process_absent and mount_absent and service.get('MainPID') == '0',
            'reader process or mount remains')
    if (service.get('LoadState') == 'not-found' and service.get('ActiveState') == 'inactive'
            and service.get('SubState') == 'dead'):
        return 'collected'
    expected = {'LoadState': 'loaded', 'ActiveState': 'failed', 'SubState': 'failed',
                'Result': 'exit-code', 'ExecMainCode': '1', 'ExecMainStatus': '143',
                'User': '', 'Group': '', 'DropInPaths': '', 'NeedDaemonReload': 'no'}
    require(all(service.get(key) == value for key, value in expected.items()),
            'reader stop is not the known intentional exit143 endpoint')
    return 'reset-known-exit143'


def validate_final_generation(state, generation):
    require(type(generation) is int and 10 <= generation <= 13,
            'explicit completed generation10 through13 required')
    require(state.get('generation') == generation and state.get('rewrites') == generation - 4
            and state.get('pending') is None and state.get('checkpoint', {}).get('generation') == generation,
            'finalization target is not the exact completed generation')


def validate_reader_inspection(report, expected):
    require(report.get('scope') == 'lab-reader-only' and report.get('read_only') is True
            and report.get('format_major_version') == expected['format']
            and report.get('marked_files') == expected['marked']
            and report.get('sst_count') == expected['count']
            and report.get('sst_bytes') == expected['bytes'],
            'fresh reader inspection differs from the certified generation')


def stop_read_only_child(child, *, grace_seconds=15):
    """Only signal our still-owned read-only child/session, and always reap it."""
    term_sent = kill_sent = False

    def send(sig):
        if child.poll() is not None:
            return False
        try:
            owned = os.getpgid(child.pid) == child.pid and os.getsid(child.pid) == child.pid
        except ProcessLookupError:
            return False
        require(owned, 'read-only inspector process group changed')
        try:
            os.killpg(child.pid, sig)
            return True
        except ProcessLookupError:
            return False

    try:
        if child.poll() is None:
            term_sent = send(signal.SIGTERM)
            try:
                child.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                kill_sent = send(signal.SIGKILL)
    finally:
        # This fixed inspector is read-only. A failed group observation may not
        # abandon its Popen-owned PID; that PID cannot be reused before reap.
        if child.poll() is None:
            child.kill()
            kill_sent = True
        child.wait(timeout=grace_seconds)
    return {'term_sent': term_sent, 'kill_sent': kill_sent}


class Operations:
    def __init__(self, health, ctx):
        self.health, self.ctx = health, ctx
        self.rt, self.w, self.c, self.old = (ctx[key] for key in ('rt', 'w', 'c', 'old'))
        self.phase = 'preflight'

    def read(self, path, maximum=MAX_JSON):
        return self.w.read_protected(path, mode=0o600, max_bytes=maximum)

    def write(self, directory, name, value, *, raw=None):
        require(self.rt.host.locked and Path(name).name == name and name not in ('.', '..'),
                'unlocked or unscoped lifecycle receipt')
        require(directory in (OPS, OPS / 'finalization'), 'unknown lifecycle evidence directory')
        self.w.secure_path(directory, leaf_mode=0o700)
        data = canonical(value) if raw is None else raw
        require(type(data) is bytes and len(data) <= MAX_JSON, 'lifecycle receipt exceeds bound')
        path = directory / name
        self.w.secure_path(path, leaf_mode=0o600, missing=True)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.rt._sync_dir(directory)
        require(self.read(path) == data, 'lifecycle receipt readback differs')
        return sha(data)

    def state(self):
        raw = self.read(self.c.STATE_ROOT / 'state.json')
        value = self.c.json_object(raw)
        require(canonical(value) == raw, 'journal is not canonical')
        return raw, value

    def preserved(self, raw, cert):
        require(self.read(self.c.STATE_ROOT / 'state.json') == raw, 'journal changed during mount handoff')
        name = f"{cert['generation']:06d}-step.json"
        require(self.read(self.c.STATE_ROOT / 'checkpoints' / name) == canonical(cert),
                'certificate changed during mount handoff')
        require(not self.rt.stop_present(), 'budget stop requires separate reconciliation')
        self.health.production_observation(self.ctx)

    def reader_gone(self, pid):
        require(not (Path('/proc') / str(pid)).exists(), 'stopped reader PID remains')
        rows = self.w.mount_rows(Path('/proc/self/mountinfo').read_text())
        require(not any(row['target'] == str(self.old.READER_MOUNT) for row in rows), 'reader mount remains')
        require(self.old.READER_MOUNT.is_dir() and not any(self.old.READER_MOUNT.iterdir()),
                'unmounted reader path is not empty')
        require(self.old.READER_CACHE.is_dir(), 'reader cache missing')
        self.old.no_other_lab_users(self.rt, 0)
        self.health.writer_absent(self.ctx)

    def stop_reader(self, reader, raw, cert):
        self.phase = 'reader-stop'
        pid = reader['process']['pid']
        intent_sha = self.write(OPS, 'reader-stop-intent.json', {
            'schema': 1, 'started_unix': time.time(), 'argv': self.old.READER_ARGV,
            'reader': reader, 'state_sha256': sha(raw), 'checkpoint_sha256': sha(canonical(cert)),
        })
        cancellation_point()
        require(self.old.reader_observation(self.rt, pid) == reader, 'reader changed before requested stop')
        self.rt.host.run([self.rt.host.systemctl, 'stop', self.old.READER_UNIT])
        end = time.monotonic() + 120
        while True:
            service = self.rt.host.service(self.old.READER_UNIT)
            rows = self.w.mount_rows(Path('/proc/self/mountinfo').read_text())
            mount_absent = not any(row['target'] == str(self.old.READER_MOUNT) for row in rows)
            process_absent = not (Path('/proc') / str(pid)).exists()
            if service.get('MainPID') == '0' and process_absent and mount_absent:
                choice = classify_reader_stop(service, process_absent=True, mount_absent=True)
                break
            require(service.get('ActiveState') in ('active', 'deactivating', 'inactive', 'failed')
                    and time.monotonic() < end, 'reader stop did not settle; no repeated stop')
            time.sleep(0.2)
        self.reader_gone(pid)
        self.preserved(raw, cert)
        observed_sha = self.write(OPS, 'reader-stop-observed.json', {
            'observed_unix': time.time(), 'reader': reader, 'service': service,
            'process_absent': True, 'mount_absent': True, 'classification': choice,
            'stop_intent_sha256': intent_sha,
        })
        reset_sha = None
        if choice == 'reset-known-exit143':
            require(service.get('Id') == self.old.READER_UNIT
                    and service.get('FragmentPath') == '/run/systemd/transient/' + self.old.READER_UNIT
                    and service.get('ControlGroup') in ('', '/system.slice/' + self.old.READER_UNIT),
                    'failed reader unit identity differs')
            self.phase = 'reader-reset-failed'
            cancellation_point()
            reset_intent = self.write(OPS, 'reader-reset-intent.json', {
                'started_unix': time.time(), 'observed_sha256': observed_sha,
                'stop_intent_sha256': intent_sha, 'service_before': service,
                'reset_failed_only': True, 'reader_process_absent': True, 'reader_mount_absent': True,
            })
            self.rt.host.run([self.rt.host.systemctl, 'reset-failed', self.old.READER_UNIT])
            end = time.monotonic() + 30
            while True:
                service = self.rt.host.service(self.old.READER_UNIT)
                if (service.get('LoadState') == 'not-found' and service.get('ActiveState') == 'inactive'
                        and service.get('SubState') == 'dead' and service.get('MainPID') == '0'):
                    break
                require(service.get('MainPID') == '0' and service.get('ActiveState') in ('inactive', 'failed')
                        and time.monotonic() < end, 'reader collection did not settle; no repeated reset')
                time.sleep(0.1)
            self.reader_gone(pid)
            self.preserved(raw, cert)
            reset_sha = self.write(OPS, 'reader-reset-completed.json', {
                'completed_unix': time.time(), 'intent_sha256': reset_intent,
                'service_after': service, 'reader_process_absent': True, 'reader_mount_absent': True,
            })
        stopped_sha = self.write(OPS, 'reader-stopped.json', {
            'completed_unix': time.time(), 'service': service, 'reader': reader,
            'mount_absent': True, 'process_absent': True, 'reader_cache_retained': True,
            'stop_intent_sha256': intent_sha, 'observed_sha256': observed_sha,
            'reset_completed_sha256': reset_sha, 'state_sha256': sha(raw),
            'checkpoint_sha256': sha(canonical(cert)),
        })
        self.health.observe(self.ctx, phase='reader-stopped')
        return intent_sha, stopped_sha

    def start(self):
        with self.rt.lock():
            require(all(not (OPS / name).exists() and not (OPS / name).is_symlink() for name in START_NAMES),
                    'startup was already attempted; preserve evidence and reconcile')
            require(not (OPS / 'finalization').exists(), 'finalization already exists')
            before = self.health.observe(self.ctx, phase='policy-after')
            raw, state = self.state()
            cert = state['checkpoint']
            require(sha(raw) == STATE_AFTER_SHA and sha(canonical(cert)) == CERT9_SHA
                    and state['generation'] == 9 and state['rewrites'] == 5 and state['pending'] is None,
                    'startup requires the exact adopted generation-nine endpoint')
            reader = self.old.reader_observation(self.rt, before['reader_process']['pid'])
            require(self.rt.profile.cache.is_dir() and self.old.READER_CACHE.is_dir(), 'retained caches missing')
            require(self.rt.free_bytes() >= self.c.MIN_FREE + self.c.RESERVATION,
                    'writer admission reserve unavailable')
            unit = self.w.render_unit(self.rt.profile).encode()
            require(sha(unit) == UNIT_SHA, 'rendered writer unit changed')
            require(self.rt.host.read_admission(self.rt.profile) == self.ctx['admission'],
                    'retained cache admission changed')
            first_reader = self.old.metadata(self.rt, self.c, self.old.READER_DB, cert)
            self.preserved(raw, cert)
            cancellation_point()
            try:
                stop_sha, stopped_sha = self.stop_reader(reader, raw, cert)
                cancellation_point()
                self.phase = 'writer-stage'
                self.rt.host.guard(self.rt.profile, running=False)
                stage_intent = self.write(OPS, 'writer-stage-intent.json', {
                    'started_unix': time.time(), 'unit': self.rt.profile.unit,
                    'unit_sha256': UNIT_SHA, 'reader_stopped_sha256': stopped_sha,
                })
                self.rt.host.stage(self.rt.profile)
                require(self.read(self.w.UNIT_DIR / self.rt.profile.unit) == unit,
                        'staged writer unit differs')
                self.rt._sync_dir(self.w.UNIT_DIR)
                self.write(OPS, 'writer-staged.json', {
                    'completed_unix': time.time(), 'intent_sha256': stage_intent, 'unit_sha256': UNIT_SHA,
                })
                self.rt.host.guard(self.rt.profile, running=False)
                self.rt.host.admit(self.rt.profile)  # Existing admission is required and remains unchanged.
                self.preserved(raw, cert)
                cancellation_point()
                self.phase = 'writer-start'
                start_sha = self.write(OPS, 'writer-start-intent.json', {
                    'started_unix': time.time(), 'unit': self.rt.profile.unit, 'unit_sha256': UNIT_SHA,
                    'state_sha256': sha(raw), 'checkpoint_sha256': CERT9_SHA,
                    'reader_stopped_sha256': stopped_sha,
                })
                self.rt.host.launch(self.rt.profile)
                self.rt.host.guard(self.rt.profile, running=True, admission=False)
                observed = self.rt.host.observe(self.rt.profile)
                self.w.validate_stats(self.rt.profile, observed)
                self.w.clean_queue(observed['stats'], observed['queue'])
                self.rt.pid = observed['pid']
                process = self.rt._process_identity(self.rt.pid)
                writer_sha = self.write(OPS, 'writer-started.json', {
                    'completed_unix': time.time(), 'intent_sha256': start_sha, 'observation': observed,
                    'process': process, 'state_sha256': sha(raw), 'checkpoint_sha256': CERT9_SHA,
                })
                self.health.observe(self.ctx, phase='writer-active', writer_sha256=writer_sha)
                cancellation_point()
                self.phase = 'writer-metadata'
                # Populate the new FUSE directory before the monitored Go open.
                first = self.old.metadata(self.rt, self.c, self.c.DB, cert)
                self.write(OPS, 'writer-generation-before-open.json', first)
                require(first['metadata'] == first_reader['metadata'] and first['state'] == first_reader['state'],
                        'writer mount exposes another closed generation')
                self.phase = 'writer-read-only-open'
                self.rt.guard(new_work=True, clean=True)
                report = self.rt.run_tool('inspect')
                self.c.validate_inspection(report, self.c.checkpoint_state(cert))
                self.write(OPS, 'writer-read-only-reopen.json', report)
                second = self.old.metadata(self.rt, self.c, self.c.DB, cert)
                self.write(OPS, 'writer-generation-after-open.json', second)
                require(first['metadata'] == second['metadata'] and first['state'] == second['state'],
                        'writer metadata changed during read-only inspection')
                self.preserved(raw, cert)
                after = self.health.observe(self.ctx, phase='writer-active', writer_sha256=writer_sha)
                cancellation_point()
                done = {'schema': 1, 'scope': 'rhea-batch2-reader-to-writer-completed',
                    'completed_unix': time.time(), 'verified': True, 'state_sha256': sha(raw),
                    'checkpoint_sha256': CERT9_SHA, 'writer_started_sha256': writer_sha,
                    'writer_process': process, 'reader_stop_intent_sha256': stop_sha,
                    'reader_stopped_sha256': stopped_sha, 'reader_before': reader,
                    'reader_inactive': True, 'reader_cache_retained': True,
                    'metadata_before': first, 'metadata_after': second, 'read_only_reopen': report,
                    'host_before': before, 'host_after': after, 'database_writer_invoked': False,
                    'journal_mutated': False, 'recipe_sha256': sha(self.read(INSTALL))}
                done_sha = self.write(OPS, 'start-completed.json', done)
                return {'verified': True, 'completion_sha256': done_sha, 'writer_process': process,
                        'state_sha256': sha(raw), 'checkpoint_sha256': CERT9_SHA}
            except BaseException as exc:
                self.write(OPS, 'start-failure.json', {'failed_unix': time.time(), 'phase': self.phase,
                    'error_type': type(exc).__name__, 'automatic_retry_permitted': False,
                    'instruction': 'Preserve services, caches and evidence; reconcile before another action.'})
                raise

    def inspect_reader(self, directory):
        """Supervise only the fixed read-only inspector after writer shutdown."""
        self.health.writer_absent(self.ctx)
        require(sha(self.w.read_protected(self.old.INSPECTOR)) == INSPECTOR_SHA,
                'reader inspector changed')
        paths = [directory / name for name in ('reader-inspect.stdout', 'reader-inspect.stderr')]
        for path in paths:
            self.w.secure_path(path, leaf_mode=0o600, missing=True)
            require(not path.exists() and not path.is_symlink(), 'reader inspection already attempted')
        started, tick = time.time(), time.monotonic()
        child = None
        interrupted_child = False
        cleanup = {'term_sent': False, 'kill_sent': False}
        cleanup_error = None
        execution_error = None
        fds = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
               for path in paths]
        with os.fdopen(fds[0], 'wb') as out, os.fdopen(fds[1], 'wb') as err:
            try:
                child = subprocess.Popen([str(self.old.INSPECTOR), '--db', str(self.old.READER_DB)],
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=self.w.CLEAN_ENV,
                    start_new_session=True, close_fds=True)
                self.write(directory, 'reader-inspect-process.json', {
                    'started_unix': started, 'process': self.rt._process_identity(child.pid),
                    'process_group': child.pid, 'inspector_sha256': INSPECTOR_SHA, 'read_only': True,
                })
                end = time.monotonic() + 120
                while child.poll() is None:
                    if STOP_REQUESTED or time.monotonic() >= end:
                        interrupted_child = True
                        break
                    time.sleep(0.1)
            except BaseException as exc:
                execution_error = type(exc).__name__
            finally:
                try:
                    if child is not None:
                        cleanup = stop_read_only_child(child)
                except BaseException as exc:
                    cleanup_error = type(exc).__name__
                finally:
                    for stream in (out, err):
                        stream.flush()
                        os.fsync(stream.fileno())
                    self.rt._sync_dir(directory)
        raw, errors = (self.read(path) for path in paths)
        group_absent = False
        if child is not None and child.returncode is not None:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                group_absent = True
        timing = {'started_unix': started, 'finished_unix': time.time(),
            'seconds': time.monotonic() - tick, 'returncode': None if child is None else child.returncode,
            'interrupted_or_timed_out': interrupted_child,
            'child_reaped': child is not None and child.returncode is not None,
            'child_and_group_absent': group_absent, 'cleanup_error_type': cleanup_error,
            'execution_error_type': execution_error,
            **cleanup,
            'stdout_sha256': sha(raw), 'stderr_sha256': sha(errors)}
        self.write(directory, 'reader-inspect-timing.json', timing)
        require(child is not None and child.returncode == 0 and group_absent
                and not interrupted_child and cleanup_error is None and execution_error is None,
                'read-only inspector did not complete cleanly; no retry')
        return self.c.json_object(raw), timing

    def finish(self, generation):
        directory = OPS / 'finalization'
        with self.rt.lock():
            require(not directory.exists() and not directory.is_symlink(),
                    'finalization was already attempted; reconcile preserved evidence')
            before = self.health.observe(self.ctx, phase='writer-active')
            raw, state = self.state()
            validate_final_generation(state, generation)
            cert = state['checkpoint']
            cert_sha = sha(canonical(cert))
            expected = self.c.checkpoint_state(cert)
            self.rt.pid = before['writer_process']['pid']
            self.rt.guard(new_work=False, clean=True)
            metadata = self.old.metadata(self.rt, self.c, self.c.DB, cert)
            self.preserved(raw, cert)
            cancellation_point()
            directory.mkdir(mode=0o700)
            self.rt._sync_dir(OPS)
            try:
                self.phase = 'writer-stop'
                self.write(directory, 'state-preserved.json', None, raw=raw)
                self.write(directory, 'certificate-preserved.json', cert)
                stop_sha = self.write(directory, 'writer-stop-intent.json', {
                    'started_unix': time.time(), 'generation': generation, 'state_sha256': sha(raw),
                    'checkpoint_sha256': cert_sha, 'writer_process': before['writer_process'],
                    'writer_metadata': metadata, 'host_before': before,
                })
                self.rt.host.halt(self.rt.profile)
                self.rt.host.guard(self.rt.profile, running=False, admission=False)
                stopped = self.health.writer_absent(self.ctx)
                stopped_sha = self.write(directory, 'writer-stopped.json', {
                    'completed_unix': time.time(), 'stop_intent_sha256': stop_sha, 'service': stopped,
                    'state_sha256': sha(raw), 'checkpoint_sha256': cert_sha,
                    'mount_absent': True, 'socket_absent': True, 'cache_retained': True,
                })
                self.health.observe(self.ctx, phase='writer-stopped')
                self.preserved(raw, cert)
                cancellation_point()
                self.phase = 'reader-start'
                require(self.old.READER_MOUNT.is_dir() and not any(self.old.READER_MOUNT.iterdir()),
                        'unmounted reader path is not empty')
                command = [str(self.old.SYSTEMD_RUN), '--unit=' + self.old.READER_UNIT]
                command += ['--property=' + key + '=' + value for key, value in self.old.READER_PROPERTIES.items()]
                command += ['--', *self.old.READER_ARGV]
                self.write(directory, 'reader-start-intent.json', {
                    'started_unix': time.time(), 'argv': command, 'state_sha256': sha(raw),
                    'checkpoint_sha256': cert_sha, 'writer_stopped_sha256': stopped_sha,
                })
                self.rt.host.run(command)
                end = time.monotonic() + 120
                while True:
                    service = self.rt.host.service(self.old.READER_UNIT)
                    require(service.get('ActiveState') in ('active', 'activating'), 'reader mount start failed')
                    rows = self.w.mount_rows(Path('/proc/self/mountinfo').read_text())
                    if service.get('ActiveState') == 'active' and any(row['target'] == str(self.old.READER_MOUNT) for row in rows):
                        break
                    require(time.monotonic() < end, 'reader mount start deadline exceeded; no second start')
                    time.sleep(0.2)
                reader = self.old.reader_observation(self.rt)
                reader_sha = self.write(directory, 'reader-restored.json', reader)
                self.health.observe(self.ctx, phase='reader-restored', reader_sha256=reader_sha)
                cancellation_point()
                self.phase = 'reader-metadata-and-reopen'
                first = self.old.metadata(self.rt, self.c, self.old.READER_DB, cert)
                self.write(directory, 'reader-generation-before-open.json', first)
                require(first['metadata'] == metadata['metadata'] and first['state'] == metadata['state'],
                        'reader restoration exposes another generation')
                report, execution = self.inspect_reader(directory)
                validate_reader_inspection(report, expected)
                self.write(directory, 'fresh-reader-reopen.json', {'report': report, 'execution': execution})
                second = self.old.metadata(self.rt, self.c, self.old.READER_DB, cert)
                self.write(directory, 'reader-generation-after-open.json', second)
                require(first['metadata'] == second['metadata'] and first['state'] == second['state'],
                        'reader metadata changed during read-only inspection')
                self.preserved(raw, cert)
                after = self.health.observe(self.ctx, phase='reader-restored', reader_sha256=reader_sha)
                cancellation_point()
                done = {'schema': 1, 'scope': 'rhea-batch2-reader-restoration-completed',
                    'verified': True,
                    'completed_unix': time.time(), 'generation': generation, 'rewrites': generation - 4,
                    'state_sha256': sha(raw), 'checkpoint_sha256': cert_sha, 'state': expected,
                    'reader_restored_sha256': reader_sha, 'reader': reader, 'host_after': after,
                    'writer_stopped_sha256': stopped_sha, 'writer_mount_and_socket_absent': True,
                    'writer_cache_retained': True, 'fresh_reader_reopen_verified': True,
                    'database_writer_invoked': False, 'journal_mutated': False,
                    'recipe_sha256': sha(self.read(INSTALL)), 'production_cutover': False}
                completion_sha = self.write(directory, 'completed.json', done)
                return {'verified': True, 'completion_sha256': completion_sha,
                    'generation': generation, 'rewrites': generation - 4, 'reader_process': reader['process'],
                    'state_sha256': sha(raw), 'checkpoint_sha256': cert_sha}
            except BaseException as exc:
                self.write(directory, 'failure.json', {'failed_unix': time.time(), 'phase': self.phase,
                    'error_type': type(exc).__name__, 'automatic_retry_permitted': False,
                    'instruction': 'Preserve services, caches and evidence; reconcile before another action.'})
                raise


def main():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL,
            'fixed root mount-lifecycle installation required')
    require(sys.argv[1:] == ['start', '--apply'] or
            (len(sys.argv) == 4 and sys.argv[1] == 'finish' and sys.argv[2] in ('10', '11', '12', '13')
             and sys.argv[3] == '--apply'), 'explicit start or one completed-generation finish required')
    raw = HEALTH.read_bytes()
    require(sha(raw) == HEALTH_SHA, 'batch2 health source differs')
    h = types.ModuleType('rhea_batch2_mount_health')
    h.__file__ = str(HEALTH)
    sys.modules[h.__name__] = h
    exec(compile(raw, str(HEALTH), 'exec'), h.__dict__)
    ctx = h.load()
    ctx['w'].secure_path(INSTALL, leaf_mode=0o600)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    operations = Operations(h, ctx)
    result = operations.start() if sys.argv[1] == 'start' else operations.finish(int(sys.argv[2]))
    try:
        print(json.dumps(result), flush=True)
    except OSError:
        pass


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        try:
            print('Batch2 mount lifecycle did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        except OSError:
            pass
        raise SystemExit(1) from None
