"""Fixed adapter, real temporary-file durability and pure engine wiring checks."""
from contextlib import contextmanager, ExitStack
import importlib.util
import json
import os
from pathlib import Path
import stat
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


m = load('batch2_policy_adapter_tests', ROOT / 'scripts/run_rhea_batch2_policy.py')
engine = load('batch2_policy_adapter_engine_fixture', ROOT / 'scripts/rhea_batch2_policy_transition.py')
BEFORE = (ROOT / 'docs/evidence/rhea-bounded-adoption-state-after-20261106.json').read_bytes()
PINS_BEFORE = (ROOT / 'docs/evidence/rhea-bounded-adoption-pins-after-20261106.json').read_bytes()
AFTER, PINS_AFTER = engine.expected_transition(BEFORE, PINS_BEFORE)


def write(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)


@contextmanager
def local_files():
    """All file calls are confined to this fixture; real /root is unreachable."""
    with tempfile.TemporaryDirectory() as name, ExitStack() as patches:
        root = Path(name)
        trust, ops = root / 'trust', root / 'trust/pacing-batch2-20261107'
        trust.mkdir(mode=0o700)
        ops.mkdir(mode=0o700)
        state = trust / 'full-clone-steps/state.json'
        state.parent.mkdir(mode=0o700)

        def protected(path, *, mode=0o600, missing=False):
            relative = path.relative_to(root)  # Any real fixed-host fallback fails.
            current = root
            for part in (None, *relative.parts):
                if part is not None:
                    current = current / part
                try:
                    info = current.lstat()
                except FileNotFoundError:
                    m.require(missing and current == path, 'protected ancestor is missing')
                    return None
                m.require(info.st_uid == os.getuid() and info.st_gid == os.getgid()
                          and not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o022,
                          'local path protection differs')
                if current != path:
                    m.require(stat.S_ISDIR(info.st_mode), 'local ancestor is not a directory')
            m.require(stat.S_IMODE(info.st_mode) == mode, 'protected leaf mode differs')
            m.require(stat.S_ISDIR(info.st_mode) if mode == 0o700 else
                      stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'protected leaf type differs')
            return info

        targets = {role: trust / path.name for role, path in m.TARGETS.items()}
        for key, value in {'TRUST': trust, 'OPS': ops, 'STATE': state, 'INSTALL': ops / 'run.py',
                           '__file__': str(ops / 'run.py'), 'TARGETS': targets, 'protected': protected}.items():
            patches.enter_context(patch.object(m, key, value))
        rt = SimpleNamespace(host=SimpleNamespace(locked=False))

        @contextmanager
        def lock():
            assert not rt.host.locked
            rt.host.locked = True
            try:
                yield
            finally:
                rt.host.locked = False

        rt.lock = lock
        ctx = {'rt': rt, 'w': object()}
        adapter = m.Adapter(SimpleNamespace(), ctx, b'', {}, {})
        adapter.unchanged = Mock()
        yield SimpleNamespace(root=root, trust=trust, ops=ops, state=state, adapter=adapter,
                              patches=patches, rt=rt, ctx=ctx)


def stage(env):
    payloads = {name: b'# fixed fixture module\n' for name in m.PAYLOAD_NAMES}
    payloads.update({
        'run.py': (ROOT / 'scripts/run_rhea_batch2_policy.py').read_bytes(),
        'transaction.py': (ROOT / 'scripts/rhea_batch2_policy_transition.py').read_bytes(),
        'controller-candidate.py': (ROOT / 'scripts/run_rhea_full_clone_steps_batch2.py').read_bytes(),
        'expected-state-before.json': BEFORE,
        'expected-pins-before.json': PINS_BEFORE,
    })
    deployment = {'schema': 1, 'scope': m.DEPLOYMENT_SCOPE, 'source_commit': '1' * 40,
                  'parent_commit': m.PARENT_COMMIT,
                  'payloads': {name: {'sha256': m.sha(raw), 'bytes': len(raw)}
                               for name, raw in payloads.items()}}
    for name, raw in payloads.items():
        write(env.ops / name, raw)
    raw = m.canonical(deployment)
    write(env.ops / 'deployment.json', raw)
    # The health fixture is deliberately inert. Its production hash stays fixed
    # in source; only this one fixture pin is redirected, not the path policy.
    env.patches.enter_context(patch.object(m, 'FIXED_PAYLOAD_HASHES',
        dict(m.FIXED_PAYLOAD_HASHES, **{'health.py': m.sha(payloads['health.py'])})))
    env.patches.enter_context(patch.object(m.os, 'geteuid', return_value=0))
    return raw, deployment, payloads


class AdapterTests(unittest.TestCase):
    def test_protected_read_refuses_mode_symlink_hardlink_and_replaced_open(self):
        with local_files() as env:
            path = env.ops / 'input.json'
            write(path, b'original')
            self.assertEqual(m.read_protected(path), b'original')
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'mode differs'):
                m.read_protected(path)
            path.chmod(0o600)
            link = env.ops / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                m.read_protected(link)
            hard = env.ops / 'hard.json'
            os.link(path, hard)
            with self.assertRaisesRegex(RuntimeError, 'type differs'):
                m.read_protected(path)
            hard.unlink()
            replacement = env.ops / 'replacement.json'
            write(replacement, b'replaced')
            original_open = os.open

            def changed_open(target, *args, **kwargs):
                if target == path:
                    os.replace(replacement, path)
                return original_open(target, *args, **kwargs)

            with patch.object(m.os, 'open', side_effect=changed_open), \
                    self.assertRaisesRegex(RuntimeError, 'changed before open'):
                m.read_protected(path)

    def test_immutable_create_and_reseal_sync_file_and_directory_without_replacement(self):
        with local_files() as env:
            path, raw = env.ops / 'intent.json', b'{"fixture":true}\n'
            m.immutable_write(path, raw)
            before = path.stat()
            seen, fsync = [], os.fsync

            def sync(fd):
                seen.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                fsync(fd)

            with patch.object(m.os, 'fsync', side_effect=sync), patch.object(m.os, 'replace') as replace:
                self.assertEqual(m.immutable_write(path, raw), m.sha(raw))
            self.assertEqual(seen, ['file', 'directory'])
            self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns),
                             (before.st_ino, before.st_mtime_ns))
            replace.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'already differs'):
                m.immutable_write(path, b'changed')
            self.assertEqual(path.read_bytes(), raw)

    def test_fixed_targets_and_original_lock_are_required(self):
        with local_files() as env, patch.object(m, 'immutable_write') as writer:
            for method, name in ((env.adapter.install_new, '../original.py'),
                                 (env.adapter.write_new, '../state.json'),
                                 (env.adapter.install_new, 'controller'),
                                 (env.adapter.write_new, 'intent.json')):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    method(name, b'x')
            with env.rt.lock():
                with self.assertRaisesRegex(RuntimeError, 'fixed install bytes'):
                    env.adapter.install_new('controller', b'arbitrary replacement')
                writer.assert_not_called()
                env.adapter.install_new('pins', PINS_AFTER)
                writer.assert_called_once_with(m.TARGETS['pins'], PINS_AFTER)
                writer.reset_mock()
                env.adapter.write_new('intent.json', b'fixed receipt')
                writer.assert_called_once_with(env.ops / 'intent.json', b'fixed receipt')

    def test_atomic_state_activation_syncs_before_and_after_exact_two_leaf_replacement(self):
        with local_files() as env:
            write(env.state, BEFORE)
            old_inode = env.state.stat().st_ino
            seen, fsync, replace = [], os.fsync, os.replace

            def sync(fd):
                seen.append('directory-sync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file-sync')
                fsync(fd)

            def activate(source, destination):
                self.assertEqual(destination, env.state)
                seen.append('replace')
                return replace(source, destination)

            with env.rt.lock(), patch.object(m.os, 'fsync', side_effect=sync), \
                    patch.object(m.os, 'replace', side_effect=activate):
                env.adapter.replace_state(BEFORE, AFTER)
            self.assertEqual(seen, ['file-sync', 'replace', 'directory-sync'])
            self.assertEqual(env.state.read_bytes(), AFTER)
            self.assertNotEqual(env.state.stat().st_ino, old_inode)
            self.assertEqual(list(env.state.parent.glob('.batch2-policy-*')), [])
            with env.rt.lock():
                with self.assertRaisesRegex(RuntimeError, 'preimage differs'):
                    env.adapter.replace_state(BEFORE, AFTER)
                with self.assertRaisesRegex(RuntimeError, 'fixed state transition bytes'):
                    env.adapter.replace_state(AFTER, BEFORE)

    def test_after_rename_interruption_is_resealed_without_new_state_replace(self):
        with local_files() as env, env.rt.lock():
            write(env.state, BEFORE)
            with patch.object(m, 'sync_dir', side_effect=OSError('before directory fsync')), \
                    self.assertRaises(OSError):
                env.adapter.replace_state(BEFORE, AFTER)
            self.assertEqual(env.state.read_bytes(), AFTER)
            before, seen, fsync = env.state.stat(), [], os.fsync

            def sync(fd):
                seen.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                fsync(fd)

            with patch.object(m.os, 'fsync', side_effect=sync), patch.object(m.os, 'replace') as replace:
                env.adapter.seal_state(AFTER)
            self.assertEqual(seen, ['file', 'directory'])
            replace.assert_not_called()
            self.assertEqual((env.state.stat().st_ino, env.state.stat().st_mtime_ns),
                             (before.st_ino, before.st_mtime_ns))
            with self.assertRaisesRegex(RuntimeError, 'fixed state reseal'):
                env.adapter.seal_state(BEFORE)

    def test_observation_keeps_original_context_and_has_no_cloud_or_writer_callback(self):
        with local_files() as env:
            env.adapter.health = SimpleNamespace(observe=Mock(return_value={'observed': True}))
            with env.rt.lock():
                self.assertEqual(env.adapter.observe('policy-after', 'pinned'), {'observed': True})
                env.adapter.health.observe.assert_called_once_with(env.ctx, phase='policy-after',
                    authenticated_rc=True, intent_sha256='pinned')
                with self.assertRaisesRegex(RuntimeError, 'unknown fixed policy phase'):
                    env.adapter.observe('writer-active', 'pinned')
            self.assertFalse(hasattr(env.adapter, 'verify'))
            self.assertFalse(hasattr(env.rt, 'cloud'))


class DeploymentAndWiringTests(unittest.TestCase):
    def test_exact_eight_payload_manifest_and_source_pins_are_checked(self):
        with local_files() as env:
            raw, deployment, payloads = stage(env)
            self.assertEqual(m.load_deployment(), (raw, deployment, payloads))
            changes = [dict(schema=True), dict(scope='other'), dict(parent_commit='0' * 40),
                       dict(source_commit=m.PARENT_COMMIT), dict(source_commit='not a commit'),
                       dict(payloads=dict(deployment['payloads'], extra={'sha256': '0' * 64, 'bytes': 1}))]
            for change in changes:
                bad = dict(deployment, **change)
                write(env.ops / 'deployment.json', m.canonical(bad))
                with self.subTest(change=list(change)), self.assertRaises(RuntimeError):
                    m.load_deployment()
            write(env.ops / 'deployment.json', raw)
            write(env.ops / 'one-step.py', b'changed even though not executed by this runner')
            with self.assertRaisesRegex(RuntimeError, 'staged payload differs'):
                m.load_deployment()

    def test_deployment_bytes_are_rechecked_before_every_write(self):
        with local_files() as env:
            raw, deployment, payloads = stage(env)
            adapter = m.Adapter(SimpleNamespace(), env.ctx, raw, deployment, payloads)
            write(env.state, BEFORE)
            write(env.ops / 'mounts.py', b'changed')
            with env.rt.lock(), patch.object(m, 'immutable_write') as writer:
                for method, args in ((adapter.install_new, ('pins', PINS_AFTER)),
                                     (adapter.write_new, ('intent.json', b'{}\n')),
                                     (adapter.replace_state, (BEFORE, AFTER))):
                    with self.assertRaisesRegex(RuntimeError, 'deployment payload changed'):
                        method(*args)
                writer.assert_not_called()
            self.assertEqual(env.state.read_bytes(), BEFORE)

    def test_main_wires_real_engine_apply_check_resume_and_preserves_context(self):
        with local_files() as env:
            stage(env)
            write(env.state, BEFORE)
            observed = []

            def observe(ctx, *, phase, intent_sha256, authenticated_rc):
                self.assertIs(ctx, env.ctx)
                self.assertTrue(env.rt.host.locked)
                self.assertTrue(authenticated_rc)
                state = env.state.read_bytes()
                self.assertEqual(state, BEFORE if phase == 'policy-before' else AFTER)
                if intent_sha256 is not None:
                    self.assertEqual(m.sha((env.ops / 'intent.json').read_bytes()), intent_sha256)
                observed.append(phase)
                return {'phase': phase, 'generation': 9, 'rewrites': 5,
                        'baseline_state_sha256': engine.OLD_STATE_SHA256,
                        'checkpoint_sha256': engine.CHECKPOINT_SHA256, 'state_sha256': m.sha(state),
                        'pins_sha256': engine.OLD_PINS_SHA256 if phase == 'policy-before' else engine.NEW_PINS_SHA256}

            health = SimpleNamespace(load=Mock(return_value=env.ctx), observe=observe)

            def module(path, digest, name):
                self.assertEqual(m.sha(m.read_protected(path)), digest)
                return health if path.name == 'health.py' else engine

            summaries = []
            with patch.object(m, 'exact_module', side_effect=module), patch('builtins.print') as output:
                for action in ('--apply', '--check', '--resume'):
                    with patch.object(m.sys, 'argv', [str(m.INSTALL), action]):
                        m.main()
                    summaries.append(json.loads(output.call_args.args[0]))
                    self.assertFalse(env.rt.host.locked)
                    self.assertEqual(env.state.read_bytes(), AFTER)
            self.assertEqual(observed, ['policy-before', 'policy-before', 'policy-after',
                                        'policy-after', 'policy-after'])
            completion = (env.ops / 'completed.json').read_bytes()
            self.assertTrue(all(row['completed'] and row['completed_sha256'] == m.sha(completion)
                                for row in summaries))
            self.assertTrue(all(row['database_writer_invoked'] is False
                                and row['pebble_open_performed'] is False
                                and row['service_action_performed'] is False for row in summaries))
            self.assertEqual(set(path.name for path in env.state.parent.iterdir()), {'state.json'})
            self.assertEqual((env.ops / 'state-before.json').read_bytes(), BEFORE)
            self.assertEqual((env.ops / 'pins-before.json').read_bytes(), PINS_BEFORE)
            self.assertEqual(m.TARGETS['pins'].read_bytes(), PINS_AFTER)


if __name__ == '__main__':
    unittest.main()
