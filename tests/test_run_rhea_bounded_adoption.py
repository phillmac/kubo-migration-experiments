"""Local filesystem and injected acceptance adapter checks; no host or SDK calls."""
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/run_rhea_bounded_adoption.py'
SPEC = importlib.util.spec_from_file_location('bounded_adoption_runner_tests', SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def write(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)


@contextmanager
def local_files():
    with tempfile.TemporaryDirectory() as name, ExitStack() as patches:
        root = Path(name)
        trust, ops = root / 'trust', root / 'trust/ops'
        ops.mkdir(mode=0o700, parents=True)
        state = trust / 'state/state.json'
        state.parent.mkdir(mode=0o700)

        def protected(path, *, mode=0o600, missing=False):
            relative = path.relative_to(root)
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
                           'TARGETS': targets, 'protected': protected}.items():
            patches.enter_context(patch.object(m, key, value))
        rt = SimpleNamespace(host=SimpleNamespace(locked=True), lock=Mock())
        adapter = m.Adapter(SimpleNamespace(), {'rt': rt}, b'', {}, {})
        adapter.unchanged = Mock()
        yield SimpleNamespace(root=root, trust=trust, ops=ops, state=state, adapter=adapter,
                              patches=patches, rt=rt)


class FilesystemAdapterTests(unittest.TestCase):
    def test_protected_read_refuses_link_mode_and_open_identity_changes(self):
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

    def test_immutable_create_and_exact_reseal_sync_without_replacement(self):
        with local_files() as env:
            path = env.ops / 'intent.json'
            raw = b'{"fixture":true}\n'
            m.immutable_write(path, raw)
            before = path.stat()
            seen, fsync = [], os.fsync

            def sync(fd):
                seen.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                fsync(fd)

            with patch.object(m.os, 'fsync', side_effect=sync), patch.object(m.os, 'replace') as replace:
                self.assertEqual(m.immutable_write(path, raw), m.sha(raw))
            self.assertEqual(seen, ['file', 'directory'])
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            replace.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'already differs'):
                m.immutable_write(path, b'changed')
            self.assertEqual(path.read_bytes(), raw)

    def test_fixed_install_receipt_destinations_and_lock_are_enforced(self):
        with local_files() as env, patch.object(m, 'immutable_write') as writer:
            for method, name in ((env.adapter.install_new, '../original.py'),
                                 (env.adapter.write_new, '../state.json')):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    method(name, b'x')
            env.rt.host.locked = False
            for method, name in ((env.adapter.install_new, 'controller'),
                                 (env.adapter.write_new, 'intent.json')):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    method(name, b'x')
            writer.assert_not_called()
            env.rt.host.locked = True
            env.adapter.install_new('controller', b'fixed source')
            writer.assert_called_once_with(m.TARGETS['controller'], b'fixed source')
            writer.reset_mock()
            env.adapter.write_new('intent.json', b'fixed receipt')
            writer.assert_called_once_with(env.ops / 'intent.json', b'fixed receipt')

    def test_state_activation_syncs_file_before_replace_and_directory_after(self):
        with local_files() as env:
            write(env.state, b'before')
            before_inode = env.state.stat().st_ino
            seen, fsync, replace = [], os.fsync, os.replace

            def sync(fd):
                seen.append('directory-sync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file-sync')
                fsync(fd)

            def activate(source, destination):
                self.assertEqual(destination, env.state)
                seen.append('replace')
                return replace(source, destination)

            with patch.object(m.os, 'fsync', side_effect=sync), patch.object(m.os, 'replace', side_effect=activate):
                env.adapter.replace_state(b'before', b'after')
            self.assertEqual(seen, ['file-sync', 'replace', 'directory-sync'])
            self.assertEqual(env.state.read_bytes(), b'after')
            self.assertNotEqual(env.state.stat().st_ino, before_inode)
            self.assertEqual(list(env.state.parent.glob('.bounded-adoption-*')), [])
            with self.assertRaisesRegex(RuntimeError, 'preimage differs'):
                env.adapter.replace_state(b'before', b'unexpected')
            self.assertEqual(env.state.read_bytes(), b'after')

    def test_visible_activation_reseal_syncs_without_second_replace(self):
        with local_files() as env:
            write(env.state, b'before')
            with patch.object(m, 'sync_dir', side_effect=OSError('fixture interruption before directory fsync')), \
                    self.assertRaises(OSError):
                env.adapter.replace_state(b'before', b'after')
            self.assertEqual(env.state.read_bytes(), b'after')
            before = env.state.stat()
            seen, fsync = [], os.fsync

            def sync(fd):
                seen.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                fsync(fd)

            with patch.object(m.os, 'fsync', side_effect=sync), patch.object(m.os, 'replace') as replace:
                env.adapter.seal_state(b'after')
            self.assertEqual(seen, ['file', 'directory'])
            replace.assert_not_called()
            self.assertEqual(env.state.stat().st_ino, before.st_ino)
            self.assertEqual(env.state.stat().st_mtime_ns, before.st_mtime_ns)
            with self.assertRaisesRegex(RuntimeError, 'endpoint differs'):
                env.adapter.seal_state(b'wrong')
            env.rt.host.locked = False
            with self.assertRaisesRegex(RuntimeError, 'original host lock'):
                env.adapter.seal_state(b'after')

    def test_completed_observation_routes_to_full_retained_proof_check(self):
        with local_files() as env:
            health = SimpleNamespace(observe=Mock(return_value={'fresh': True}),
                                     check_completed=Mock(return_value={'intent_sha256': 'pinned'}))
            env.adapter.health = health
            env.adapter.receipt_bytes = Mock(return_value=None)
            self.assertEqual(env.adapter.observe('after', 'pinned'), {'fresh': True})
            health.observe.assert_called_once_with(env.adapter.ctx, phase='after', authenticated_rc=True,
                                                   intent_sha256='pinned')
            env.adapter.receipt_bytes.return_value = b'completed'
            self.assertEqual(env.adapter.observe('after', 'pinned'), {'intent_sha256': 'pinned'})
            health.check_completed.assert_called_once_with(env.adapter.ctx)
            self.assertEqual(health.observe.call_count, 1)
            with self.assertRaisesRegex(RuntimeError, 'intent differs'):
                env.adapter.observe('after', 'wrong')

    def test_acceptance_attempts_are_exclusive_sequential_and_reject_unknown_entries(self):
        with local_files() as env:
            first, path = env.adapter._attempt()
            self.assertEqual((first, path.name), (1, '000001'))
            write(path / 'failure.json', b'prior failure')
            second, other = env.adapter._attempt()
            self.assertEqual((second, other.name), (2, '000002'))
            self.assertEqual((path / 'failure.json').read_bytes(), b'prior failure')
            (other.parent / 'unknown').mkdir(mode=0o700)
            with self.assertRaisesRegex(RuntimeError, 'unknown acceptance'):
                env.adapter._attempt()


class AcceptanceWiringTests(unittest.TestCase):
    @contextmanager
    def acceptance(self, *, cancellation=False, failure=None):
        with local_files() as env:
            events = []
            state = {'binding': 'adopted fixture', 'generation': 9}
            write(env.state, m.canonical(state))
            stage_root = env.trust / 'full-clone-steps'
            stage = stage_root / 'stages/000009-step'
            snapshot = stage / 'snapshot'
            snapshot.mkdir(mode=0o700, parents=True)
            metadata = {'LOCK': b'', 'CURRENT': b'MANIFEST-000000\n', '000010.log': b'W' * 11,
                        'OPTIONS-000011': b'O' * 1170, 'marker.manifest.000007.MANIFEST-000012': b'',
                        'marker.format-version.000012.013': b'', 'MANIFEST-000009': b'A' * 15_779_601}
            metadata['MANIFEST-000012'] = b'B' * (31_560_396 - sum(map(len, metadata.values())))
            for name in metadata:
                write(snapshot / name, b'fixture filename only')
            previous, writer, created = {'generation': 8}, {'action': 'step'}, {'fixture.sst': {'size': 1}}
            expected = {'previous_checkpoint_sha256': m.sha(m.canonical(previous)),
                        'go_report_sha256': m.sha(m.canonical(writer)),
                        'closed_output_hashes_sha256': m.sha(m.canonical(created)),
                        'remote_metadata': {name: {'size': len(raw), 'sha256': m.sha(raw)}
                                            for name, raw in metadata.items()}}
            inputs = {
                stage_root / 'checkpoints/000008-step.json': m.canonical(previous),
                stage_root / 'checkpoints/000009-step.json': m.canonical(expected),
                stage / 'writer.json': m.canonical(writer), stage / 'created-sst-hashes.json': m.canonical(created),
                **{snapshot / name: raw for name, raw in metadata.items()},
            }
            refs = {}
            for role, path in [('000008-step-certificate', stage_root / 'checkpoints/000008-step.json'),
                               ('000009-step-certificate', stage_root / 'checkpoints/000009-step.json'),
                               ('000009-step-writer', stage / 'writer.json'),
                               ('000009-step-created-sst-hashes', stage / 'created-sst-hashes.json'),
                               *[('000009-snapshot-' + name, snapshot / name) for name in metadata]]:
                refs[role] = {'path': str(path.relative_to(env.trust)), 'sha256': m.sha(inputs[path]),
                              'bytes': len(inputs[path])}
            ledger_blob = b'L' * 4_574_902
            ledger_path = env.trust / 'fixture-ledger'
            inputs[ledger_path] = ledger_blob
            reads = SimpleNamespace(references={}, unchanged=Mock(side_effect=lambda: events.append('inputs-unchanged')))

            def read_input(role, path, expected):
                raw = inputs[path]
                self.assertEqual(m.sha(raw), expected)
                reads.references[role] = {'sha256': expected}
                return raw

            reads.raw = read_input
            ledger = object()
            wrapper = SimpleNamespace(secure_path=Mock(), LEDGER=ledger_path, load_ledger=Mock(return_value=ledger))
            original = SimpleNamespace(BUCKET='fixture-bucket', PREFIX='rhea/pebbleds/', LEDGER_SHA256=m.sha(ledger_blob))
            candidate = SimpleNamespace(__file__=str(m.TARGETS['verifier']), **vars(original))
            installed_runtime = SimpleNamespace(verifier=candidate, load_state=Mock(return_value=state),
                                                cloud=Mock(side_effect=AssertionError('new cloud forbidden')),
                                                guard=Mock(side_effect=AssertionError('writer guard forbidden')))
            installed = SimpleNamespace(Runtime=Mock(return_value=installed_runtime))
            config = SimpleNamespace(connect_timeout=10, read_timeout=30, max_pool_connections=10,
                                     retries={'mode': 'standard', 'total_max_attempts': 3})
            client = SimpleNamespace(meta=SimpleNamespace(config=config))

            @contextmanager
            def cloud():
                events.append('old-cloud-enter')
                try:
                    yield client
                finally:
                    events.append('old-cloud-close')

            env.rt.cloud = cloud
            c = SimpleNamespace(STATE_ROOT=stage_root, canonical=m.canonical, json_object=m.json_object,
                                digest=lambda value: m.sha(m.canonical(value)))
            observation = {'state_sha256': m.sha(m.canonical(state)), 'state': state,
                           'reader_process': {'pid': 1}, 'production_service_process': {'pid': 2},
                           'production_rc_process': {'pid': 3}}
            ctx = {'f': SimpleNamespace(ReadSet=lambda c, w: reads), 'c': c, 'rt': env.rt, 'w': wrapper,
                   'v': original, 'bundle': {'evidence': refs}, 'cert': expected, 'ledger_blob': ledger_blob}
            health = SimpleNamespace(PROJECTION_SHA='a' * 64, CERT_SHA='b' * 64)
            adapter = m.Adapter(health, ctx, b'', {'source_commit': 'c' * 40}, {})
            adapter.unchanged = Mock(side_effect=lambda: events.append('deployment-unchanged'))
            adapter.observe = Mock(side_effect=lambda *args: (events.append('health'), observation)[1])
            adapter.target_bytes = Mock(return_value=b'installed artifact')

            class Cancellation:
                def __init__(self): self.value = False
                def set(self): self.value = True
                def is_set(self): return self.value

            def cancelled(token):
                if token.is_set():
                    raise RuntimeError('fixture cancellation')

            guard = SimpleNamespace(audit=Mock(return_value={'guarded': True}))
            comparison = SimpleNamespace(Cancellation=Cancellation, cancelled=cancelled,
                GuardedClient=Mock(return_value=guard), validate_pass=Mock())
            replay = SimpleNamespace(PROJECTION_SHA=health.PROJECTION_SHA,
                                     equivalent=Mock(side_effect=lambda *args: events.append('equivalent')))
            returned = {'verified_unix': 1.0, 'pebble_reopen_verified': False}

            def profile(verifier, guarded, loaded_ledger, before, report, snapshot_bytes, hashes, mode, previous_hash, **kwargs):
                events.append('installed-verify')
                self.assertIs(verifier, candidate)
                self.assertIs(guarded, guard)
                self.assertIs(loaded_ledger, ledger)
                self.assertEqual((before, report, snapshot_bytes, hashes, mode),
                                 (previous, writer, metadata, created, 'final'))
                self.assertEqual(previous_hash, c.digest(previous))
                self.assertEqual(set(kwargs), {'metrics', 'enumeration_workers', 'enumeration_stop', 'enumeration_metrics'})
                self.assertEqual(kwargs['enumeration_workers'], 4)
                kwargs['metrics']['wall_seconds'] = 0.25
                kwargs['enumeration_metrics']['pages'] = 4
                if failure is not None:
                    raise failure
                if cancellation:
                    kwargs['enumeration_stop'].set()
                return returned, kwargs['metrics']

            profiler = SimpleNamespace(profile_verify_generation=Mock(side_effect=profile))
            helpers = {'comparison': comparison, 'profiler': profiler, 'equivalence': replay}
            helper_paths = {}
            for role in helpers:
                path = env.ops / (role + '.py')
                raw = ('# ' + role + '\n').encode()
                write(path, raw)
                helper_paths[role] = (path, m.sha(raw))

            def load_module(path, digest, name):
                if path == m.TARGETS['controller']:
                    self.assertEqual(digest, m.FIXED_PAYLOAD_HASHES['controller-candidate.py'])
                    return installed
                for role, (expected_path, expected_sha) in helper_paths.items():
                    if path == expected_path:
                        self.assertEqual(digest, expected_sha)
                        return helpers[role]
                raise AssertionError('unexpected module source')

            sdk_path = env.ops / 'sdk-handlers.py'
            write(sdk_path, b'# pinned SDK fixture\n')
            boto3, botocore, handlers = (ModuleType(name) for name in ('boto3', 'botocore', 'botocore.handlers'))
            boto3.__version__ = botocore.__version__ = m.SDK_VERSION
            botocore.__path__ = []
            botocore.handlers = handlers
            handlers.__file__ = str(sdk_path)
            for name, value in {'HELPERS': helper_paths, 'exact_module': load_module,
                                'SDK_HANDLERS_SHA': m.sha(sdk_path.read_bytes())}.items():
                env.patches.enter_context(patch.object(m, name, value))
            env.patches.enter_context(patch.dict(sys.modules, {'boto3': boto3, 'botocore': botocore,
                                                             'botocore.handlers': handlers}))
            env.patches.enter_context(patch.object(m.signal, 'signal', return_value=signal.SIG_DFL))
            alarm = env.patches.enter_context(patch.object(m.signal, 'alarm'))
            env.patches.enter_context(patch.object(m.resource, 'setrlimit'))
            yield SimpleNamespace(adapter=adapter, env=env, events=events, profiler=profiler,
                                  installed_runtime=installed_runtime, candidate=candidate, alarm=alarm,
                                  returned=returned, comparison=comparison, replay=replay)

    def test_acceptance_uses_installed_candidate_explicit_four_and_original_cloud(self):
        with self.acceptance() as fixture:
            result = fixture.adapter.verify('d' * 64)
            self.assertTrue(result['verified'])
            self.assertEqual((result['attempt'], result['path']), (1, 'acceptance/000001'))
            self.assertEqual(fixture.profiler.profile_verify_generation.call_count, 1)
            fixture.installed_runtime.cloud.assert_not_called()
            fixture.installed_runtime.guard.assert_not_called()
            fixture.comparison.validate_pass.assert_called_once()
            self.assertLess(fixture.events.index('installed-verify'), fixture.events.index('old-cloud-close'))
            self.assertLess(fixture.events.index('old-cloud-close'), len(fixture.events) - 1)
            path = fixture.env.ops / result['path']
            self.assertEqual(m.json_object((path / 'result.json').read_bytes()), fixture.returned)
            done = m.json_object((path / 'completed.json').read_bytes())
            self.assertTrue(done['workers_drained'] and done['sdk_clients_closed'])
            self.assertFalse(done['checkpoint_replaced'] or done['database_writer_invoked'] or done['pebble_open_performed'])
            self.assertEqual(fixture.alarm.call_args_list[-1].args, (0,))

    def test_cancelled_or_failed_verification_closes_cloud_and_cannot_complete(self):
        failure = OSError('fixture SDK failure')
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled), self.acceptance(
                    cancellation=cancelled, failure=None if cancelled else failure) as fixture:
                with self.assertRaises(RuntimeError if cancelled else OSError) as raised:
                    fixture.adapter.verify('d' * 64)
                if not cancelled:
                    self.assertIs(raised.exception, failure)
                self.assertEqual(fixture.profiler.profile_verify_generation.call_count, 1)
                self.assertIn('old-cloud-close', fixture.events)
                path = fixture.env.ops / 'acceptance/000001'
                self.assertFalse((path / 'completed.json').exists())
                self.assertFalse((path / 'result.json').exists())
                receipt = m.json_object((path / 'failure.json').read_bytes())
                self.assertEqual(receipt['cancellation_latched'], cancelled)
                self.assertNotIn('fixture SDK failure', (path / 'failure.json').read_text())
                self.assertEqual(fixture.alarm.call_args_list[-1].args, (0,))


if __name__ == '__main__':
    unittest.main()
