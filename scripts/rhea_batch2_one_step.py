#!/usr/bin/env python3
"""Admit one explicitly requested batch2 unit under its controller's own lock.

This fixed installation has no retry, recovery, batch loop or child-controller
process. It calls the unchanged pinned Controller in process. HUP/TERM/INT only
latch a cooperative stop request: the controller's existing Go-child monitor
writes the protected stop sentinel and waits for that same child. No signal is
sent to the writer, mount, or supervising controller.

Every attempt owns exclusive intent/stdout/stderr/timing files. Apply requires a
successful dry-run from exactly the requested raw journal and sealed writer; a
later unit also requires a separately written operator review of the prior unit.
The operator, never this program, writes reviews/000010.json through 000012.json.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'pacing-batch2-20261107'
INSTALL = OPS / 'one-step.py'
HEALTH = OPS / 'health.py'
STATE = TRUST / 'full-clone-steps/state.json'
HEALTH_SHA256 = '2781718c06389a0753cc23b6ff39d97bac388f492399dbb1bb637d57dbf4db1e'
CONTROLLER_SHA256 = 'b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828'
INITIAL_STATE_SHA256 = '0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9'
INITIAL_CHECKPOINT_SHA256 = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
BOOT_ID = '6fc54ca7-d64a-4125-98fa-d0a728485237'
SCOPE = 'rhea-batch2-one-step'
REVIEW_SCOPE = 'rhea-batch2-prior-unit-review'
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILE = 16 * 1024**2
PHASES = ('plan', 'writer', 'snapshot', 'defer_markers', 'drain_data',
          'verify_before_markers', 'publish_markers', 'verify_final', 'reopen')


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def json_object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    require(type(value) is dict and canonical(value) == raw, 'canonical JSON object required')
    return value


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def process_identity(value):
    require(type(value) is dict and set(value) == {'pid', 'start_ticks', 'boot_id'}
            and type(value['pid']) is int and value['pid'] > 1
            and type(value['start_ticks']) is str and value['start_ticks'].isdigit()
            and value['boot_id'] == BOOT_ID, 'invalid sealed writer process')
    return value


def request(generation, apply, expected_state_sha256):
    require(type(generation) is int and 10 <= generation <= 13, 'generation must be 10 through 13')
    require(type(apply) is bool, 'explicit dry-run or apply required')
    require(type(expected_state_sha256) is str and HEX.fullmatch(expected_state_sha256),
            'expected raw state SHA256 required')
    return {'generation': generation, 'mode': 'apply' if apply else 'dry-run',
            'state_sha256': expected_state_sha256}


def paths(generation, mode):
    require(type(generation) is int and 10 <= generation <= 13 and mode in ('dry-run', 'apply'),
            'invalid receipt identity')
    stem = f"step-{generation:06d}-" + ('operation' if mode == 'apply' else 'dry-run')
    return {'intent': OPS / (stem + '-intent.json'), 'stdout': OPS / (stem + '.stdout'),
            'stderr': OPS / (stem + '.stderr'), 'timing': OPS / (stem + '-timing.json')}


def load_health():
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL,
            'fixed root one-step installation required')
    for part in (*reversed(HEALTH.parents), HEALTH):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'untrusted health path')
        require(stat.S_ISDIR(info.st_mode) if part != HEALTH else
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'untrusted health path type')
    with os.fdopen(os.open(HEALTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        source = stream.read(MAX_FILE + 1)
    require(len(source) <= MAX_FILE and sha(source) == HEALTH_SHA256, 'health source digest differs')
    module = types.ModuleType('batch2_one_step_health')
    module.__file__ = str(HEALTH)
    sys.modules[module.__name__] = module
    exec(compile(source, str(HEALTH), 'exec'), module.__dict__)
    return module


class Files:
    """Small protected receipt store; existing attempts are never overwritten."""
    def __init__(self, rt):
        self.rt = rt

    def read(self, path):
        return self.rt.wrapper.read_protected(path, mode=0o600, max_bytes=MAX_FILE)

    def absent(self, path):
        self.rt.wrapper.secure_path(path, leaf_mode=0o600, missing=True)
        return not path.exists() and not path.is_symlink()

    def open_new(self, path, *, text=False):
        require(self.absent(path), 'attempt receipt already exists; preserve it without retry')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.rt._sync_dir(path.parent)
        return os.fdopen(fd, 'w' if text else 'wb', **({'encoding': 'utf-8'} if text else {}))

    def write_new(self, path, raw):
        require(type(raw) is bytes and len(raw) <= MAX_FILE, 'receipt exceeds bound')
        with self.open_new(path) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self.rt._sync_dir(path.parent)
        require(self.read(path) == raw, 'receipt write readback differs')


class StopLatch:
    def __init__(self):
        self.signal = None
        self.sentinel_requested = False

    def handle(self, number, unused_frame):
        # Deliberately do not raise or perform IO, including during Go Popen.
        if self.signal is None:
            self.signal = number

    def check(self, rt, controller):
        if self.signal is None:
            return
        if rt.host.locked and not self.sentinel_requested:
            try:
                rt.signal_budget_stop('batch2 one-step interruption requested')
                self.sentinel_requested = True
            except Exception:
                pass  # The live child's ordinary monitor also attempts the sentinel.
        raise controller.Refusal('batch2 one-step interruption requested; preserve state and evidence')

    @contextmanager
    def installed(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)}
        try:
            for number in previous:
                signal.signal(number, self.handle)
            yield self
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)


def validate_state(controller, state, raw, requested, *, after=False):
    generation = requested['generation'] - int(not after)
    require(type(state.get('generation')) is int and state['generation'] == generation
            and type(state.get('rewrites')) is int and state['rewrites'] == generation - 4
            and state.get('pending') is None, 'journal is not the explicitly requested idle generation')
    require(canonical(state) == raw and state['binding']['controller_sha256'] == CONTROLLER_SHA256
            and state['binding']['limits']['maximum_rewrites'] == 9, 'journal bytes or policy differ')
    require(controller.checkpoint_state(state['checkpoint'])['format'] == '013', 'checkpoint is not format013')
    if not after:
        require(sha(raw) == requested['state_sha256'], 'raw journal changed from explicit admission')
    if generation == 9:
        require(sha(raw) == INITIAL_STATE_SHA256
                and sha(canonical(state['checkpoint'])) == INITIAL_CHECKPOINT_SHA256, 'batch2 anchor differs')


def validate_result(controller, result, state, *, apply):
    require(type(result) is dict and result.get('action') == 'step' and result.get('applied') is apply,
            'controller result action differs')
    expected_keys = {'action', 'applied', 'phase_timings'} | (
        {'checkpoint', 'rewrites_completed', 'production_cutover'} if apply else {'before', 'picker_plan', 'limits'})
    require(set(result) == expected_keys, 'controller result fields differ')
    timing = result['phase_timings']
    require(type(timing) is dict and timing.get('schema') == 1
            and timing.get('scope') == 'full-clone-batch2-invocation'
            and all(finite(timing.get(key)) for key in ('started_unix', 'finished_unix', 'elapsed_seconds'))
            and timing['elapsed_seconds'] >= 0, 'controller timing is invalid')
    phases = timing.get('phases')
    require(type(phases) is list and [row.get('phase') for row in phases] == list(PHASES if apply else ('plan',))
            and all(set(row) == {'phase', 'seconds'} and finite(row['seconds']) and row['seconds'] >= 0
                    for row in phases), 'controller proof phases differ')
    if apply:
        require(result['checkpoint'] == state['checkpoint'] and result['rewrites_completed'] == state['rewrites']
                and result['production_cutover'] is False, 'applied result differs from the committed checkpoint')
    else:
        require(result['before'] == controller.checkpoint_state(state['checkpoint'])
                and result['limits'] == controller.LIMITS and type(result['picker_plan']) is dict,
                'dry-run result differs from its checkpoint or limits')


class Admission:
    def __init__(self, ctx, health, rt, requested, files):
        self.ctx, self.health, self.rt = ctx, health, rt
        self.c, self.request, self.files = ctx['batch'], requested, files
        self.sealed = {}
        self.before_health = None
        self.checked = False
        self.in_progress = False
        self.dry_plan = None
        self.raw_state = files.read(STATE)
        self.state = json_object(self.raw_state)
        self.c.Runtime.validate_state(rt, self.state)
        validate_state(self.c, self.state, self.raw_state, requested)
        self.checkpoint_sha256 = sha(canonical(self.state['checkpoint']))
        for path in (INSTALL, HEALTH, TRUST / 'run_rhea_full_clone_steps_batch2.py',
                     OPS / 'start-completed.json', OPS / 'writer-started.json'):
            self.capture(path)
        require(sha(self.sealed[HEALTH]) == HEALTH_SHA256
                and sha(self.sealed[TRUST / 'run_rhea_full_clone_steps_batch2.py']) == CONTROLLER_SHA256,
                'one-step dependency source differs')
        started = json_object(self.sealed[OPS / 'writer-started.json'])
        done = json_object(self.sealed[OPS / 'start-completed.json'])
        self.writer = process_identity(started.get('process'))
        require(done.get('verified') is True and done.get('writer_process') == self.writer
                and done.get('writer_started_sha256') == sha(self.sealed[OPS / 'writer-started.json'])
                and all(value.get('state_sha256') == INITIAL_STATE_SHA256
                        and value.get('checkpoint_sha256') == INITIAL_CHECKPOINT_SHA256 for value in (started, done))
                and started.get('observation', {}).get('pid') == self.writer['pid'],
                'writer startup does not bind the policy anchor and sealed process')
        self.code = {'recipe': sha(self.sealed[INSTALL]), 'health': HEALTH_SHA256, 'controller': CONTROLLER_SHA256}
        if requested['mode'] == 'apply':
            dry = self.retained_attempt(requested['generation'], 'dry-run', self.state, self.raw_state)
            self.dry_plan = dry['picker_plan']
            if requested['generation'] > 10:
                self.validate_review()

    def capture(self, path):
        raw = self.files.read(path)
        require(path not in self.sealed or self.sealed[path] == raw, 'retained input changed')
        self.sealed[path] = raw
        return raw

    def references(self):
        return {str(path.relative_to(OPS)) if path.is_relative_to(OPS) else str(path):
                {'sha256': sha(raw), 'bytes': len(raw)} for path, raw in self.sealed.items()}

    def unchanged(self):
        for path, raw in self.sealed.items():
            require(self.files.read(path) == raw, 'sealed admission input changed')

    def retained_attempt(self, generation, mode, state, raw_state):
        names = paths(generation, mode)
        blobs = {key: self.capture(path) for key, path in names.items()}
        intent, timing, result = (json_object(blobs[key]) for key in ('intent', 'timing', 'stdout'))
        require(intent.get('schema') == 1 and intent.get('scope') == SCOPE + '-intent'
                and intent.get('generation') == generation and intent.get('mode') == mode
                and intent.get('code_sha256') == self.code and intent.get('writer_process') == self.writer,
                'retained attempt intent differs')
        require(timing.get('schema') == 1 and timing.get('scope') == SCOPE + '-timing'
                and timing.get('generation') == generation and timing.get('mode') == mode
                and type(timing.get('returncode')) is int and timing['returncode'] == 0
                and timing.get('interrupted') is False and timing.get('error_type') is None
                and timing.get('code_sha256') == self.code and timing.get('writer_process') == self.writer
                and timing.get('state_after_sha256') == sha(raw_state)
                and timing.get('checkpoint_sha256') == sha(canonical(state['checkpoint']))
                and timing.get('intent_sha256') == sha(blobs['intent'])
                and timing.get('stdout_sha256') == sha(blobs['stdout'])
                and timing.get('stderr_sha256') == sha(blobs['stderr']), 'retained attempt did not complete at this state')
        require(all(finite(timing.get(key)) for key in ('started_unix', 'finished_unix', 'elapsed_seconds'))
                and timing['finished_unix'] >= timing['started_unix'] and timing['elapsed_seconds'] >= 0,
                'retained attempt timing is invalid')
        require(timing.get('state_before_sha256') == intent.get('state_sha256')
                and timing.get('after_health', {}).get('state_sha256') == sha(raw_state)
                and timing['after_health'].get('writer_process') == self.writer
                and timing['after_health'].get('pending') is None, 'retained health or admission link differs')
        if mode == 'dry-run':
            require(intent.get('state_sha256') == sha(raw_state)
                    and intent.get('checkpoint_sha256') == sha(canonical(state['checkpoint'])),
                    'dry-run is from another raw state')
        validate_result(self.c, result, state, apply=mode == 'apply')
        return result

    def validate_review(self):
        generation = self.request['generation'] - 1
        self.retained_attempt(generation, 'apply', self.state, self.raw_state)
        prior = paths(generation, 'apply')
        review = json_object(self.capture(OPS / 'reviews' / f'{generation:06d}.json'))
        require(set(review) == {'schema', 'scope', 'generation', 'next_generation', 'verdict', 'observed_unix',
                'boot_id', 'controller_sha256', 'state_sha256', 'checkpoint_sha256',
                'operation_intent_sha256', 'operation_stdout_sha256', 'operation_timing_sha256'}
                and type(review['schema']) is int and review['schema'] == 1
                and review['scope'] == REVIEW_SCOPE and type(review['generation']) is int
                and review['generation'] == generation and type(review['next_generation']) is int
                and review['next_generation'] == self.request['generation']
                and review['verdict'] == 'admit-next-unit' and review['boot_id'] == BOOT_ID
                and review['controller_sha256'] == CONTROLLER_SHA256
                and review['state_sha256'] == sha(self.raw_state)
                and review['checkpoint_sha256'] == self.checkpoint_sha256
                and finite(review['observed_unix'])
                and review['observed_unix'] >= json_object(self.sealed[prior['timing']])['finished_unix']
                and all(review['operation_' + key + '_sha256'] == sha(self.sealed[prior[key]])
                        for key in ('intent', 'stdout', 'timing')), 'prior-unit operator review differs')

    def check_writer(self):
        require(self.rt.host.locked, 'one-step identity admission requires controller lock')
        require(self.rt._process_identity(self.writer['pid']) == self.writer,
                'writer differs from sealed startup identity')
        self.rt.pid = self.writer['pid']

    def initial(self, state):
        require(self.rt.host.locked and not self.checked and not self.in_progress,
                'initial admission requires controller lock exactly once')
        self.in_progress = True
        try:
            raw = self.files.read(STATE)
            require(raw == self.raw_state and state == self.state, 'journal raced before controller admission')
            validate_state(self.c, state, raw, self.request)
            self.unchanged()
            self.check_writer()
            self.before_health = self.health.observe(self.ctx, phase='writer-active')
            require(self.before_health.get('state_sha256') == sha(raw)
                    and self.before_health.get('writer_process') == self.writer,
                    'admission health binds a different state or writer')
            require(self.files.read(STATE) == raw, 'journal changed during admission health')
            self.unchanged()
            self.checked = True
        finally:
            self.in_progress = False


def runtime_class(controller):
    class AdmittedRuntime(controller.Runtime):
        admission = None
        stop_latch = None

        def _admission_check(self):
            require(self.admission is not None and self.stop_latch is not None, 'missing explicit one-step admission')
            self.stop_latch.check(self, controller)
            self.admission.check_writer()

        def load_state(self):
            state = super().load_state()
            if self.admission is not None and not self.admission.checked and not self.admission.in_progress:
                self._admission_check()
                self.admission.initial(state)
            return state

        def guard(self, **kwargs):
            self._admission_check()
            result = super().guard(**kwargs)
            self._admission_check()
            return result

        def observe(self):
            self._admission_check()
            result = super().observe()
            require(result['pid'] == self.admission.writer['pid'], 'authenticated mount peer differs')
            self._admission_check()
            return result

        def run_tool(self, action, **kwargs):
            self._admission_check()
            require(self.admission.checked, 'Go call before completed explicit admission')
            self.admission.unchanged()
            if action == 'step':
                pending = kwargs.get('pending', {})
                require(self.admission.request['mode'] == 'apply'
                        and pending.get('index') == self.admission.request['generation']
                        and pending.get('previous_checkpoint_sha256') == self.admission.checkpoint_sha256
                        and kwargs.get('plan') == self.admission.dry_plan, 'writer admission or dry-run plan differs')
            result = super().run_tool(action, **kwargs)
            self._admission_check()  # Handles an interrupt just as a child exited.
            if action == 'plan' and self.admission.dry_plan is not None:
                require(result.get('picker_plan') == self.admission.dry_plan, 'fresh picker differs from saved dry-run')
            return result

    return AdmittedRuntime


def execute(ctx, health, rt, requested, *, stop=None):
    """Execute once; all writer admission occurs in Controller.run's own lock."""
    c, files = ctx['batch'], Files(rt)
    stop = stop or StopLatch()
    admission = Admission(ctx, health, rt, requested, files)
    rt.admission, rt.stop_latch = admission, stop
    names = paths(requested['generation'], requested['mode'])
    require(all(files.absent(path) for path in names.values()), 'attempt already exists; no automatic replay')
    started_unix, started = time.time(), time.monotonic()
    intent = dict(schema=1, scope=SCOPE + '-intent', action='step', **requested,
        checkpoint_sha256=admission.checkpoint_sha256, writer_process=admission.writer,
        code_sha256=admission.code, inputs=admission.references(), started_unix=started_unix)
    intent_raw = canonical(intent)
    files.write_new(names['intent'], intent_raw)
    code, error_type, result, after_health = 1, None, None, None
    after_sha = checkpoint_sha = None
    # The signal context encloses both Go Popen construction and every child wait.
    with stop.installed(), files.open_new(names['stdout']) as out, files.open_new(names['stderr'], text=True) as err:
        try:
            with redirect_stderr(err):
                result = c.Controller(rt).run('step', apply=requested['mode'] == 'apply')
                result_raw = canonical(result)
                require(len(result_raw) <= MAX_FILE, 'controller output exceeds bound')
                out.write(result_raw)
                out.flush()
                os.fsync(out.fileno())
                with rt.lock():
                    stop.check(rt, c)
                    state = c.Runtime.load_state(rt)
                    raw = files.read(STATE)
                    validate_state(c, state, raw, requested, after=requested['mode'] == 'apply')
                    validate_result(c, result, state, apply=requested['mode'] == 'apply')
                    admission.unchanged()
                    after_health = health.observe(ctx, phase='writer-active')
                    require(after_health.get('state_sha256') == sha(raw)
                            and after_health.get('writer_process') == admission.writer,
                            'final health binds a different state or writer')
                    require(files.read(STATE) == raw, 'journal changed during final health')
                    admission.unchanged()
                    stop.check(rt, c)
                    after_sha, checkpoint_sha = sha(raw), sha(canonical(state['checkpoint']))
                    code = 0
        except BaseException as exc:
            error_type = type(exc).__name__
            err.write('One-step refused (' + error_type + '); preserve all receipts and journal; no retry.\n')
        finally:
            # All Go calls above retain their frozen monitor/wait path. These
            # reads record an error endpoint without claiming it was certified.
            if code:
                try:
                    raw = files.read(STATE)
                    after_sha = sha(raw)
                    checkpoint_sha = sha(canonical(json_object(raw)['checkpoint']))
                except Exception:
                    pass
            for stream in (out, err):
                stream.flush()
                os.fsync(stream.fileno())
            rt._sync_dir(OPS)
        if stop.signal is not None:
            code = 1
            error_type = error_type or 'Interrupted'
        timing = {'schema': 1, 'scope': SCOPE + '-timing', 'action': 'step',
            'generation': requested['generation'], 'mode': requested['mode'],
            'started_unix': started_unix, 'finished_unix': time.time(), 'elapsed_seconds': time.monotonic() - started,
            'returncode': code, 'error_type': error_type, 'interrupted': stop.signal is not None,
            'signal': stop.signal, 'sentinel_requested': stop.sentinel_requested,
            'intent_sha256': sha(intent_raw), 'stdout_sha256': sha(files.read(names['stdout'])),
            'stderr_sha256': sha(files.read(names['stderr'])),
            'state_before_sha256': requested['state_sha256'], 'state_after_sha256': after_sha,
            'checkpoint_sha256': checkpoint_sha, 'writer_process': admission.writer, 'code_sha256': admission.code,
            'before_health': admission.before_health, 'after_health': after_health}
        files.write_new(names['timing'], canonical(timing))
    return timing


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generation', required=True, type=int, choices=range(10, 14))
    parser.add_argument('--expected-state-sha256', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    requested = request(args.generation, args.apply, args.expected_state_sha256)
    health = load_health()
    ctx = health.load()
    require(ctx['batch'] is not None, 'batch2 policy must be activated first')
    rt = runtime_class(ctx['batch'])()
    ctx = health.bind_runtime(ctx, rt)
    timing = execute(ctx, health, rt, requested)
    try:
        print(json.dumps({'completed': timing['returncode'] == 0, 'generation': args.generation,
              'mode': requested['mode'], 'timing_sha256': sha(canonical(timing)),
              'state_sha256': timing['state_after_sha256']}), flush=True)
    except OSError:
        pass  # Durable files, rather than a delivery channel, record the outcome.
    return timing['returncode']


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        try:
            print('One-step admission refused (' + type(exc).__name__ + '); preserve evidence.', file=sys.stderr)
        except OSError:
            pass
        raise SystemExit(1) from None
