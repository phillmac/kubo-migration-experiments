"""Offline only: injected filesystem/host observations never enter shipping code."""
from contextlib import ExitStack, contextmanager
import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_signed_admission as a
import rhea_multi_sst_root_host_adapter as r
import test_rhea_multi_sst_signed_admission as fixture


class InstallationTests(unittest.TestCase):
    command = staticmethod(fixture.AdmissionTests.command)
    sign = fixture.AdmissionTests.sign
    setUpClass = classmethod(fixture.AdmissionTests.setUpClass.__func__)
    tearDownClass = classmethod(fixture.AdmissionTests.tearDownClass.__func__)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.path)
        self.addCleanup(self.temp.cleanup)
        self.install = Path(self.temp.name) / 'installed'
        self.install.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.root_uid = os.stat('/').st_uid
        self.now = int(__import__('time').time())
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.wrapper = self.install / 'historical-wrapper.py'
        self.wrapper.write_bytes((ROOT / 'scripts/rhea_wasabi_lab_mount.py').read_bytes())
        self.wrapper.chmod(0o600)
        # A second independent ephemeral key is used for admission.
        admission_private = Path(self.temp.name) / 'admission-private.pem'
        admission_public = Path(self.temp.name) / 'admission-public.pem'
        self.command('genpkey', '-algorithm', 'Ed25519', '-out', str(admission_private))
        self.command('pkey', '-in', str(admission_private), '-pubout', '-out', str(admission_public))
        self.admission_pem = admission_public.read_bytes()
        self.artifacts = {}
        for role, (name, mode) in r.ARTIFACTS.items():
            raw = (self.admission_pem if role == 'admission_key' else b'offline disabled writer' if role == 'writer'
                   else (ROOT / 'scripts' / name).read_bytes())
            path = self.install / name
            path.write_bytes(raw)
            path.chmod(mode)
            self.artifacts[role] = a.sha(raw)
        pins = r._pins_from_controller((self.install / r.ARTIFACTS['controller'][0]).read_bytes())
        for name in pins:
            path = self.install / 'sources' / name
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
            path.chmod(0o600)
        self.deployment = dict(schema=1, scope='rhea-root-deployment-v1', issued=self.now - 1,
            expires=self.now + 120, host='rhea', boot_id=self.boot, install=str(self.install),
            base_commit=r.BASE_COMMIT, artifacts=self.artifacts, source_pins_sha256=a.sha(a.canonical(pins)),
            legacy_journal_sha256=a.sha(b'offline exact idle journal'))
        self.installation = dict(self.deployment, scope='rhea-root-installation-v1')
        self.write_manifests()
        (self.install / 'deployment.pub').write_bytes(self.pem)
        (self.install / 'deployment.pub').chmod(0o600)

    def write_manifests(self):
        self.installation['deployment_sha256'] = a.sha(a.canonical(self.deployment))
        for name, value in (('deployment', self.deployment), ('installation', self.installation)):
            raw = a.canonical(value)
            for suffix, data in (('json', raw), ('sig', self.sign(raw, domain=a.DEPLOYMENT_DOMAIN))):
                path = self.install / (name + '.' + suffix)
                path.write_bytes(data)
                path.chmod(0o600)

    @contextmanager
    def offline_installation(self):
        original_directory = a.protected_directory
        original_verify = a.verify_detached
        def directory(path, **kwargs):
            if Path(path).is_relative_to(self.install):
                kwargs.update(uid=self.uid, ancestor_uid=self.root_uid)
            return original_directory(path, **kwargs)
        def read(path, *, mode=0o600, limit=a.MAX_BYTES):
            path = Path(path)
            with original_directory(path.parent, uid=self.uid, ancestor_uid=self.root_uid) as fd:
                return a.read_at(fd, path.name, uid=self.uid, mode=mode, limit=limit)
        def verify(*args, **kwargs):
            return original_verify(*args, **dict(kwargs, openssl_uid=os.stat('/usr/bin/openssl').st_uid))
        with ExitStack() as stack:
            for owner, name, value in (
                (r, 'INSTALL', self.install), (r, 'WRAPPER', self.wrapper),
                (r, '__file__', str(self.install / r.ARTIFACTS['adapter'][0])),
                (a, '__file__', str(self.install / r.ARTIFACTS['signed_admission'][0])),
                (r, 'PROVISION_PUBLIC_KEY', self.install / 'deployment.pub'),
                (r, 'PROVISION_PUBLIC_KEY_SHA256', self.pin),
                (r, 'PROVISION_KEY_NOT_BEFORE', self.now - 100), (r, 'PROVISION_KEY_NOT_AFTER', self.now + 1000),
                (a, 'PUBLIC_KEY_SHA256', a.sha(self.admission_pem)),
                (a, 'KEY_NOT_BEFORE', self.now - 100), (a, 'KEY_NOT_AFTER', self.now + 1000),
                (a, 'protected_directory', directory), (a, 'protected_read', read), (a, 'verify_detached', verify)):
                stack.enter_context(patch.object(owner, name, value))
            stack.enter_context(patch.object(os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(r.socket, 'gethostname', return_value='rhea'))
            yield

    def test_independent_signed_installation_and_all_bytes(self):
        with self.offline_installation():
            validated = r.validate_installation()
        self.assertEqual(validated['_deployment_sha256'], a.sha(a.canonical(self.deployment)))
        self.assertEqual(validated['_installation_sha256'], a.sha(a.canonical(self.installation)))

    def test_unsigned_or_tampered_deployment_refused(self):
        signature = self.install / 'deployment.sig'
        signature.write_bytes(bytes(64))
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_installation_expired_even_with_valid_signature(self):
        self.installation['expires'] = self.now
        self.write_manifests()
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_wrong_boot_with_valid_signatures(self):
        self.deployment['boot_id'] = self.installation['boot_id'] = '12345678-1234-1234-1234-123456789abc'
        self.write_manifests()
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_installed_artifact_tampering(self):
        (self.install / r.ARTIFACTS['writer'][0]).write_bytes(b'tampered writer never invoked')
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_baseline_source_tampering(self):
        (self.install / 'sources/cmd/pebble-format-v1/go.mod').write_bytes(b'tampered')
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_key_permissions_refused(self):
        (self.install / 'deployment.pub').chmod(0o644)
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_signed_manifest_extra_fields_refused(self):
        self.deployment['test_bypass'] = self.installation['test_bypass'] = True
        self.write_manifests()
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_wrapper_tamper_not_executed(self):
        self.wrapper.write_bytes(b'raise AssertionError("must never execute")')
        with self.offline_installation(), self.assertRaises(a.Refusal):
            r.validate_installation()

    def test_wrong_provisioning_key(self):
        with self.offline_installation(), patch.object(r, 'PROVISION_PUBLIC_KEY_SHA256', '0' * 64), self.assertRaises(a.Refusal):
            r.validate_installation()


class BoundaryTests(unittest.TestCase):
    def test_all_mutations_and_unproven_reads_explicitly_refuse(self):
        adapter = object.__new__(r.RootHostAdapter)
        with patch.object(subprocess, 'run', side_effect=AssertionError('no writer/command allowed')):
            for name in ('handoff', 'run_go_monitored', 'drain_stop', 'publish_markers', 'reopen_readonly',
                         'snapshot_closed', 'cloud_read', 'baseline_ledger'):
                with self.subTest(name=name), self.assertRaises(a.Refusal):
                    getattr(adapter, name)({})

    def test_default_production_constructor_refuses(self):
        with self.assertRaises(a.Refusal):
            r.RootHostAdapter()

    def test_preflight_and_guards_never_claim_complete_success(self):
        adapter = object.__new__(r.RootHostAdapter)
        calls = []
        adapter.observe_host = lambda: calls.append('real-read-path-replaced-only-in-test') or {'controller_ready': False}
        for action in (lambda: adapter.preflight({}), adapter.protected_guards):
            with self.assertRaises(a.Refusal):
                action()
        self.assertEqual(len(calls), 2)

    def test_queue_exact_counters_and_resource_bounds(self):
        observation = dict(stats=dict(diskCache=dict(bytesUsed=1, uploadsQueued=0, uploadsInProgress=0,
                                                    erroredFiles=0, outOfSpace=False)), queue={'queue': []})
        space = types.SimpleNamespace(f_bavail=2 * 1024**4, f_frsize=1)
        self.assertEqual(r.queue_health_from_observation(observation, space)['queue_bytes'], 0)
        for key, value in (('bytesUsed', None), ('uploadsQueued', True), ('uploadsInProgress', 1),
                           ('erroredFiles', 1), ('outOfSpace', True), ('bytesUsed', 96 * 1024**3 + 1)):
            changed = copy.deepcopy(observation)
            changed['stats']['diskCache'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(a.Refusal):
                r.queue_health_from_observation(changed, space)
        with self.assertRaises(a.Refusal):
            r.queue_health_from_observation(observation, types.SimpleNamespace(f_bavail=1, f_frsize=1))
        observation['queue']['queue'] = [{'size': 1}]
        with self.assertRaises(a.Refusal):
            r.queue_health_from_observation(observation, space)

    def test_shared_realhost_lock_is_used_and_released(self):
        events = []
        class FakeHostOnlyInTests:
            locked = False
            @contextmanager
            def lock(self):
                events.append('shared-writer-lock-enter')
                self.locked = True
                try:
                    yield
                finally:
                    self.locked = False
                    events.append('shared-writer-lock-exit')
        adapter = object.__new__(r.RootHostAdapter)
        adapter.host = FakeHostOnlyInTests()
        adapter._locked = False
        adapter._admission = None
        with adapter.exclusive():
            adapter._require_lock()
            with self.assertRaises(a.Refusal):
                with adapter.exclusive():
                    pass
        self.assertEqual(events, ['shared-writer-lock-enter', 'shared-writer-lock-exit'])
        with self.assertRaises(a.Refusal):
            adapter._require_lock()

    def test_recovery_observer_never_claims_certifiability(self):
        observer = object.__new__(r.ReadOnlyRecoveryObserver)
        observer._adapter = types.SimpleNamespace(observe_host=lambda: {'controller_ready': False})
        finding = observer.observe({})
        self.assertEqual(finding['decision'], 'preserve/manual-inspection')
        self.assertFalse(finding['mutations_performed'])
        for name in ('independent_snapshot', 'cloud_read', 'baseline_ledger', 'reopen_observation'):
            with self.subTest(name=name), self.assertRaises(a.Refusal):
                getattr(observer, name)()

    def test_new_clis_refuse_without_constructing_live_host(self):
        with patch.object(r, 'RootHostAdapter', side_effect=AssertionError('no host access')), \
             patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(r.main(), 2)
            self.assertEqual(a.main(), 2)


if __name__ == '__main__':
    unittest.main()
