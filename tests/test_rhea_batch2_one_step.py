"""Local-only single-unit admission, retained review, and child-wait checks."""
import copy
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('batch2_single_unit_tests', ROOT / 'scripts/rhea_batch2_one_step.py')
fixtures = load('batch2_single_unit_controller_fixtures', Path(__file__).with_name('test_run_rhea_full_clone_steps_batch2.py'))
c = fixtures.m
WRITER = {'pid': 999, 'start_ticks': '12345', 'boot_id': m.BOOT_ID}


def put(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)


class Environment:
    def __init__(self, root):
        self.root, self.ops = root, root / 'pacing-batch2-20261107'
        self.ops.mkdir(mode=0o700)
        self.state_path = root / 'full-clone-steps/state.json'
        put(self.state_path, m.canonical(fixtures.candidate_state()))
        for name, target in (('rhea_batch2_one_step.py', self.ops / 'one-step.py'),
                             ('rhea_batch2_health.py', self.ops / 'health.py'),
                             ('run_rhea_full_clone_steps_batch2.py', root / 'run_rhea_full_clone_steps_batch2.py')):
            put(target, (ROOT / 'scripts' / name).read_bytes())
        started = {'process': WRITER, 'observation': {'pid': WRITER['pid']},
                   'state_sha256': m.INITIAL_STATE_SHA256, 'checkpoint_sha256': m.INITIAL_CHECKPOINT_SHA256}
        put(self.ops / 'writer-started.json', m.canonical(started))
        done = {'verified': True, 'writer_process': WRITER,
                'writer_started_sha256': m.sha(m.canonical(started)),
                'state_sha256': m.INITIAL_STATE_SHA256, 'checkpoint_sha256': m.INITIAL_CHECKPOINT_SHA256}
        put(self.ops / 'start-completed.json', m.canonical(done))
        self.lock_hook = None
        self.tool_hook = None
        self.current_writer = copy.deepcopy(WRITER)
        self.stop = False
        self.health_calls = []
        env = self

        class Base(fixtures.fixtures.FakeRuntime):
            def __init__(self):
                super().__init__()
                self.state = fixtures.candidate_state()
                self.binding = copy.deepcopy(self.state['binding'])
                self.db = c.checkpoint_state(self.state['checkpoint'])
                self.certificates = {9: copy.deepcopy(self.state['checkpoint'])}
                self.host = SimpleNamespace(locked=False)
                self.wrapper = SimpleNamespace(read_protected=self.read, secure_path=lambda *a, **k: None)
                self.pid = None

            @staticmethod
            def read(path, *, mode=0o600, max_bytes=m.MAX_FILE):
                assert path.stat().st_mode & 0o777 == mode
                raw = path.read_bytes()
                assert len(raw) <= max_bytes
                return raw

            @contextmanager
            def lock(self):
                assert not self.host.locked
                self.host.locked = True
                self.events.append(('lock',))
                try:
                    if env.lock_hook is not None:
                        callback, env.lock_hook = env.lock_hook, None
                        callback(self)
                    yield
                finally:
                    self.host.locked = False

            validate_state = c.Runtime.validate_state

            def load_state(self):
                state = m.json_object(env.state_path.read_bytes())
                self.validate_state(state)
                return state

            def write_state(self, state):
                assert self.host.locked
                super().write_state(state)
                put(env.state_path, m.canonical(state))

            def guard(self, **kwargs):
                assert self.host.locked
                super().guard(**kwargs)
                return self.observe()

            def observe(self):
                assert self.host.locked
                value = fixtures.fixtures.observation()
                value['pid'] = env.current_writer['pid']
                return value

            def _process_identity(self, pid):
                assert pid == WRITER['pid']
                return copy.deepcopy(env.current_writer)

            def signal_budget_stop(self, reason):
                assert self.host.locked
                env.stop = True
                self.events.append(('sentinel',))

            def stop_present(self):
                return env.stop

            def run_tool(self, action, **kwargs):
                assert self.host.locked
                result = super().run_tool(action, **kwargs)
                return result if env.tool_hook is None else env.tool_hook(self, action, result)

            @staticmethod
            def _sync_dir(path):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)

        self.controller = SimpleNamespace(**vars(c))
        self.controller.Runtime = Base
        self.rt = m.runtime_class(self.controller)()
        self.ctx = {'batch': self.controller}

        def observe(ctx, *, phase):
            assert ctx is self.ctx and phase == 'writer-active' and self.rt.host.locked
            self.rt.guard(new_work=False, clean=True)
            state = m.json_object(self.state_path.read_bytes())
            self.health_calls.append(state['generation'])
            return {'state_sha256': m.sha(self.state_path.read_bytes()), 'pending': state['pending'],
                    'generation': state['generation'], 'writer_process': copy.deepcopy(env.current_writer)}
        self.health = SimpleNamespace(observe=observe)

    def invoke(self, generation=10, *, apply=False, expected=None, stop=None):
        requested = m.request(generation, apply, expected or m.sha(self.state_path.read_bytes()))
        return m.execute(self.ctx, self.health, self.rt, requested, stop=stop)

    def write_review(self, generation):
        previous = m.paths(generation, 'apply')
        timing = m.json_object(previous['timing'].read_bytes())
        state = m.json_object(self.state_path.read_bytes())
        review = {'schema': 1, 'scope': m.REVIEW_SCOPE, 'generation': generation,
                  'next_generation': generation + 1, 'verdict': 'admit-next-unit',
                  'observed_unix': timing['finished_unix'], 'boot_id': m.BOOT_ID,
                  'controller_sha256': m.CONTROLLER_SHA256, 'state_sha256': m.sha(self.state_path.read_bytes()),
                  'checkpoint_sha256': m.sha(m.canonical(state['checkpoint']))}
        review.update({'operation_' + key + '_sha256': m.sha(previous[key].read_bytes())
                       for key in ('intent', 'stdout', 'timing')})
        path = self.ops / 'reviews' / f'{generation:06d}.json'
        put(path, m.canonical(review))
        return path


class AdmissionTests(unittest.TestCase):
    @contextmanager
    def environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ops = root / 'pacing-batch2-20261107'
            with patch.multiple(m, TRUST=root, OPS=ops, STATE=root / 'full-clone-steps/state.json',
                                INSTALL=ops / 'one-step.py', HEALTH=ops / 'health.py'):
                yield Environment(root)

    def test_explicit_generation_mode_digest_and_frozen_source_pins(self):
        for args in ((9, False, 'a' * 64), (14, False, 'a' * 64), (True, False, 'a' * 64),
                     (10, 1, 'a' * 64), (10, False, None), (10, False, 'short')):
            with self.subTest(args=args), self.assertRaises(m.Refusal):
                m.request(*args)
        for path, expected in (('rhea_batch2_health.py', m.HEALTH_SHA256),
                               ('run_rhea_full_clone_steps_batch2.py', m.CONTROLLER_SHA256)):
            self.assertEqual(m.sha((ROOT / 'scripts' / path).read_bytes()), expected)

    def test_dry_then_exact_one_apply_preserves_all_controller_proof_phases(self):
        with self.environment() as env:
            before = env.state_path.read_bytes()
            dry = env.invoke()
            self.assertEqual(dry['returncode'], 0)
            self.assertEqual(env.state_path.read_bytes(), before)
            self.assertFalse(any(event[0] in ('journal', 'create', 'certificate') for event in env.rt.events))
            applied = env.invoke(apply=True)
            self.assertEqual(applied['returncode'], 0)
            state = m.json_object(env.state_path.read_bytes())
            self.assertEqual((state['generation'], state['rewrites'], state['pending']), (10, 6, None))
            result = m.json_object(m.paths(10, 'apply')['stdout'].read_bytes())
            self.assertEqual([row['phase'] for row in result['phase_timings']['phases']], list(m.PHASES))
            self.assertEqual(result['checkpoint'], state['checkpoint'])
            self.assertEqual([event for event in env.rt.events if event[0] == 'verify'],
                             [('verify', 'before-markers'), ('verify', 'final')])
            self.assertEqual(sum(event == ('tool', 'step') for event in env.rt.events), 1)
            self.assertEqual(env.health_calls, [9, 9, 9, 10])
            self.assertFalse((env.ops / 'reviews').exists())

    def test_four_independent_units_require_manual_reviews_and_never_run_a_fifth(self):
        with self.environment() as env:
            for generation in range(10, 14):
                self.assertEqual(env.invoke(generation)['returncode'], 0)
                if generation > 10:
                    with self.assertRaises(FileNotFoundError):
                        env.invoke(generation, apply=True)
                    self.assertFalse(m.paths(generation, 'apply')['intent'].exists())
                    env.write_review(generation - 1)
                self.assertEqual(env.invoke(generation, apply=True)['returncode'], 0)
                state = m.json_object(env.state_path.read_bytes())
                self.assertEqual((state['generation'], state['rewrites']), (generation, generation - 4))
                self.assertEqual(sum(event == ('tool', 'step') for event in env.rt.events), generation - 9)
            with self.assertRaises(m.Refusal):
                env.invoke(14, apply=True)
            self.assertEqual(len(list((env.ops / 'reviews').iterdir())), 3)

    def test_raw_state_race_is_rejected_inside_controller_lock_before_any_go_call(self):
        with self.environment() as env:
            def race(rt):
                state = m.json_object(env.state_path.read_bytes())
                state['checkpoint']['concurrent_change'] = True
                put(env.state_path, m.canonical(state))
            env.lock_hook = race
            result = env.invoke()
            self.assertEqual(result['returncode'], 1)
            self.assertFalse(any(event[0] == 'tool' for event in env.rt.events))
            self.assertIsNone(result['before_health'])
            self.assertNotEqual(result['state_before_sha256'], result['state_after_sha256'])

    def test_retained_startup_mutation_and_restarted_writer_are_refused_before_go(self):
        for mutation in ('startup', 'process'):
            with self.subTest(mutation=mutation), self.environment() as env:
                def race(rt):
                    if mutation == 'startup':
                        path = env.ops / 'start-completed.json'
                        value = m.json_object(path.read_bytes())
                        value['extra'] = True
                        put(path, m.canonical(value))
                    else:
                        env.current_writer['start_ticks'] = '999999'
                env.lock_hook = race
                self.assertEqual(env.invoke()['returncode'], 1)
                self.assertFalse(any(event[0] == 'tool' for event in env.rt.events))

    def test_apply_requires_successful_same_state_dry_run(self):
        with self.environment() as env:
            with self.assertRaises(FileNotFoundError):
                env.invoke(apply=True)
            self.assertFalse(m.paths(10, 'apply')['intent'].exists())
            self.assertEqual(env.invoke()['returncode'], 0)
            path = m.paths(10, 'dry-run')['timing']
            timing = m.json_object(path.read_bytes())
            timing['returncode'] = 1
            put(path, m.canonical(timing))
            with self.assertRaises(m.Refusal):
                env.invoke(apply=True)
            self.assertFalse(any(event == ('tool', 'step') for event in env.rt.events))

    def test_fresh_plan_mismatch_refuses_before_pending_or_writer_stage(self):
        with self.environment() as env:
            self.assertEqual(env.invoke()['returncode'], 0)
            before = env.state_path.read_bytes()
            def change(rt, action, result):
                if action == 'plan':
                    result['picker_plan']['plan_sha256'] = 'd' * 64
                return result
            env.tool_hook = change
            self.assertEqual(env.invoke(apply=True)['returncode'], 1)
            self.assertEqual(env.state_path.read_bytes(), before)
            self.assertFalse(any(event[0] == 'create' or event == ('tool', 'step') for event in env.rt.events))

    def test_review_must_bind_exact_prior_outputs_state_and_next_generation(self):
        for key, value in (('verdict', 'observe-only'), ('next_generation', 12),
                           ('operation_stdout_sha256', '0' * 64), ('state_sha256', '0' * 64)):
            with self.subTest(key=key), self.environment() as env:
                env.invoke(); env.invoke(apply=True); env.invoke(11)
                path = env.write_review(10)
                review = m.json_object(path.read_bytes())
                review[key] = value
                put(path, m.canonical(review))
                with self.assertRaises(m.Refusal):
                    env.invoke(11, apply=True)
                self.assertEqual(sum(event == ('tool', 'step') for event in env.rt.events), 1)
                self.assertFalse(m.paths(11, 'apply')['intent'].exists())

    def test_repeated_attempt_preserves_original_receipts_and_never_replays(self):
        with self.environment() as env:
            env.invoke()
            names = m.paths(10, 'dry-run')
            before = {key: path.read_bytes() for key, path in names.items()}
            events = copy.deepcopy(env.rt.events)
            with self.assertRaises(m.Refusal):
                env.invoke()
            self.assertEqual(env.rt.events, events)
            self.assertEqual({key: path.read_bytes() for key, path in names.items()}, before)

    def test_closed_writer_failure_is_retained_without_retry_or_certificate(self):
        with self.environment() as env:
            env.invoke()
            env.rt.failure = c.Refusal('injected closed writer error')
            timing = env.invoke(apply=True)
            self.assertEqual(timing['returncode'], 1)
            state = m.json_object(env.state_path.read_bytes())
            self.assertEqual((state['generation'], state['pending']['phase']), (9, 'executing'))
            self.assertEqual(sum(event == ('tool', 'step') for event in env.rt.events), 1)
            self.assertFalse(any(event[0] in ('verify', 'certificate') for event in env.rt.events))
            self.assertEqual(m.paths(10, 'apply')['stdout'].read_bytes(), b'')
            self.assertTrue(m.paths(10, 'apply')['timing'].exists())

    def test_interrupt_before_controller_go_requests_sentinel_and_restores_handlers(self):
        with self.environment() as env:
            stop = m.StopLatch()
            stop.handle(signal.SIGTERM, None)
            previous = {number: signal.getsignal(number) for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)}
            timing = env.invoke(stop=stop)
            self.assertEqual(timing['returncode'], 1)
            self.assertTrue(timing['interrupted'] and timing['sentinel_requested'] and env.stop)
            self.assertFalse(any(event[0] == 'tool' for event in env.rt.events))
            self.assertEqual({number: signal.getsignal(number) for number in previous}, previous)

    def test_new_runtime_context_cannot_accidentally_use_foreign_health_lock(self):
        with self.environment() as env:
            def wrong_health(ctx, *, phase):
                self.assertTrue(env.rt.host.locked)
                return {'state_sha256': '0' * 64, 'writer_process': WRITER}
            env.health.observe = wrong_health
            self.assertEqual(env.invoke()['returncode'], 1)
            self.assertFalse(any(event[0] == 'tool' for event in env.rt.events))


class LiveChildMonitorTests(unittest.TestCase):
    def test_real_runtime_constructor_signal_window_keeps_one_child_until_wait(self):
        # Exercise the unchanged real Runtime.run_tool/_wait_tool, with a
        # controlled Popen handle and a real signal delivered in its constructor.
        for action in ('plan', 'step'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                klass = m.runtime_class(c)
                rt = klass.__new__(klass)
                rt.host = SimpleNamespace(locked=True)
                rt.pid = WRITER['pid']
                rt.wrapper = SimpleNamespace(CLEAN_ENV={}, Refusal=RuntimeError,
                    secure_path=lambda *a, **k: None)
                rt.check_tool = Mock()
                rt._sync_dir = Mock()
                rt.stage_dir = Mock(return_value=root)
                rt._process_identity = Mock(return_value={'pid': 777, 'start_ticks': '888', 'boot_id': m.BOOT_ID})
                rt.signal_budget_stop = Mock()
                rt.stop_present = Mock(return_value=True)
                rt.atomic_json = Mock()
                rt.free_bytes = Mock(return_value=c.MIN_FREE * 2)
                stop = m.StopLatch()
                rt.stop_latch = stop
                rt.admission = SimpleNamespace(checked=True, unchanged=Mock(), check_writer=Mock(),
                    request={'mode': 'apply', 'generation': 10}, checkpoint_sha256='c' * 64,
                    dry_plan=fixtures.fixtures.plan(), writer=WRITER)
                child = Mock(pid=777)
                child.poll.side_effect = [None, None, 0]
                child.wait.return_value = 0
                def construct(*args, **kwargs):
                    os.kill(os.getpid(), signal.SIGHUP)
                    self.assertEqual(stop.signal, signal.SIGHUP)
                    return child
                monitor_failed = Mock()
                kwargs = {} if action == 'plan' else {
                    'expected': {'format': '013', 'marked': 2, 'inventory': 'e' * 64},
                    'plan': rt.admission.dry_plan,
                    'pending': {'index': 10, 'previous_checkpoint_sha256': 'c' * 64},
                    'launched': Mock(), 'monitor_failed': monitor_failed}
                with stop.installed(), patch.object(c, 'TRUST', root), \
                        patch.object(c.subprocess, 'Popen', side_effect=construct) as popen, \
                        patch.object(c.time, 'sleep'), self.assertRaises(c.Refusal):
                    rt.run_tool(action, **kwargs)
                popen.assert_called_once()
                child.wait.assert_called_once_with()
                child.terminate.assert_not_called()
                child.kill.assert_not_called()
                child.send_signal.assert_not_called()
                self.assertTrue(rt.signal_budget_stop.called and stop.sentinel_requested)
                if action == 'step':
                    monitor_failed.assert_called_once()
                    rt.atomic_json.assert_called_once()
                    self.assertEqual(rt.atomic_json.call_args.args[1]['returncode'], 0)
                    self.assertIsNotNone(rt.atomic_json.call_args.args[1]['monitor_failure'])


if __name__ == '__main__':
    unittest.main()
