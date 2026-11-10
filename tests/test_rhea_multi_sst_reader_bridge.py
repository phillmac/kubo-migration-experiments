"""Offline only. All host/cloud substitutions live in this test file."""
from contextlib import contextmanager, ExitStack
import copy
import fcntl
import io
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_reader_bridge as b
import rhea_multi_sst_signed_admission as a
import test_rhea_multi_sst_reader_preflight as reader
import test_rhea_multi_sst_root_host_adapter as installation
import test_rhea_multi_sst_signed_admission as crypto


def evidence():
    value = reader.fixture()
    value['witness']['reader_exe_sha256'] = b.READER_EXE_SHA256
    return value


def proposal(deployment, observed):
    state = b.p.IMMUTABLE_REPORT['state']
    return dict(schema=1, scope='rhea-gen14-two-unit-proposal-v1', generation=14, unit_count=2,
        physical_rewrite_base=9, previous_checkpoint_sha256=a.ANCHOR,
        go_binary_sha256=deployment['artifacts']['writer'], deployment_sha256=deployment['_deployment_sha256'],
        installation_sha256=deployment['_installation_sha256'],
        bridge_manifest_sha256=observed['bridge_manifest_sha256'], reader=observed['reader'],
        request=dict(maximum_units=2, before=dict(format=state['format'], marked=state['marked'], files=state['count'],
            bytes=state['bytes'], inventory_sha256=state['inventory']), initial_plan_sha256='c' * 64))


class ReaderComparisonTests(unittest.TestCase):
    def setUp(self):
        self.before = evidence()
        self.report = b.p.object_json(self.before['raw'])
        self.now = self.report['observed_unix'] + 2
        self.report['observed_unix'] += 1

    def compare(self, witness=None):
        return b.reconcile_reader(self.before, a.canonical(self.report),
            self.before['witness'] if witness is None else witness, now=self.now)

    def test_fresh_locked_observation_against_real_archived_chain(self):
        result = self.compare()
        self.assertEqual(result['reader']['pid'], 78502)
        self.assertNotEqual(result['outside_sha256'], result['locked_sha256'])

    def test_every_independent_witness_field_changes_refuse(self):
        for key in self.before['witness']:
            changed = copy.deepcopy(self.before['witness'])
            changed[key] = 'substituted'
            with self.subTest(key=key), self.assertRaises((a.Refusal, TypeError, AttributeError)):
                self.compare(changed)

    def test_all_historical_report_fields_revalidated_under_lock(self):
        for key in b.p.IMMUTABLE_REPORT:
            report = dict(self.report, **{key: 'changed'})
            with self.subTest(key=key), self.assertRaises(a.Refusal):
                b.reconcile_reader(self.before, a.canonical(report), self.before['witness'], now=self.now)

    def test_unchanged_but_unpinned_reader_executable_refuses(self):
        self.before['witness']['reader_exe_sha256'] = '0' * 64
        with self.assertRaises(a.Refusal):
            self.compare()

    def test_lock_gap_process_cache_mount_inode_and_file_replacement(self):
        for key in ('cache_identities', 'file_identities', 'processes', 'mountinfo'):
            changed = copy.deepcopy(self.before['witness'])
            if key == 'mountinfo':
                changed[key][0] = changed[key][0].replace('87 29', '88 29')
            elif key == 'processes':
                changed[key]['reader_process']['start_ticks'] = '5054052'
            else:
                next(iter(changed[key].values()))['inode'] += 1
            with self.subTest(key=key), self.assertRaises(a.Refusal):
                self.compare(changed)

    def test_replay_regression_future_stale_refuse(self):
        for timestamp in (self.now - 2, self.now - 3, self.now + 1, self.now - 121):
            self.report['observed_unix'] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaises(a.Refusal):
                self.compare()


class BridgeInstallationTests(unittest.TestCase):
    command = staticmethod(crypto.AdmissionTests.command)
    sign = crypto.AdmissionTests.sign
    setUpClass = classmethod(crypto.AdmissionTests.setUpClass.__func__)
    tearDownClass = classmethod(crypto.AdmissionTests.tearDownClass.__func__)
    write_manifests = installation.InstallationTests.write_manifests
    offline_installation = installation.InstallationTests.offline_installation

    def setUp(self):
        installation.InstallationTests.setUp(self)
        # Historical source_root deliberately recognizes ONLY its real installed
        # path. A relocated test import therefore uses parents[1] as source root.
        for name in installation.r._pins_from_controller(
                (self.install / installation.r.ARTIFACTS['controller'][0]).read_bytes()):
            path = self.install.parent / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        for name in b.TRANSITIVE_SOURCE_PINS:
            for base in (self.install / 'sources', self.install.parent):
                path = base / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, path)
                path.chmod(0o600)
        self.bridge = self.install / 'rhea_multi_sst_reader_bridge.py'
        self.bridge.write_bytes((ROOT / 'scripts' / self.bridge.name).read_bytes())
        self.bridge.chmod(0o600)
        self.health = self.install / 'historical-health.py'
        self.health.write_bytes((ROOT / 'scripts/rhea_batch2_health.py').read_bytes())
        self.health.chmod(0o600)
        self.manifest = dict(schema=1, scope=b.SCOPE, issued=self.now - 1, expires=self.now + 120,
            host='rhea', boot_id=self.boot, base_commit=b.BASE_COMMIT, bridge_sha256=a.sha(self.bridge.read_bytes()),
            deployment_sha256=a.sha(a.canonical(self.deployment)),
            installation_sha256=a.sha(a.canonical(self.installation)),
            protected_files={str(self.health): dict(bytes=self.health.stat().st_size, sha256=b.p.HEALTH_SHA256)})
        self.write_bridge_manifest()

    def write_bridge_manifest(self):
        raw = a.canonical(self.manifest)
        for name, data in [('bridge.json', raw), ('bridge.sig', self.sign(raw, domain=a.DEPLOYMENT_DOMAIN))]:
            path = self.install / name
            path.write_bytes(data)
            path.chmod(0o600)

    @contextmanager
    def installed(self):
        with self.offline_installation(), patch.object(b, '__file__', str(self.bridge)), \
             patch.object(b, 'SELF', self.bridge), patch.object(b, 'INSTALL', self.install), \
             patch.object(b, 'MANIFEST', self.install / 'bridge.json'), patch.object(b.p, 'HEALTH', self.health), \
             patch.object(b.p, '__file__', str(self.install / installation.r.ARTIFACTS['reader_preflight'][0])):
            yield

    def test_three_real_signed_manifests_before_loading_health(self):
        with self.installed():
            bridge = b.ReaderBridge()
        self.assertFalse(bridge._active)
        self.assertEqual(bridge.health.__file__, str(self.health))

    def test_every_manifest_binding_field_enforced(self):
        for key in ('schema', 'scope', 'host', 'boot_id', 'base_commit', 'deployment_sha256',
                    'installation_sha256', 'bridge_sha256', 'protected_files'):
            original = copy.deepcopy(self.manifest)
            self.manifest[key] = 'changed'
            self.write_bridge_manifest()
            with self.subTest(key=key), self.installed(), self.assertRaises(a.Refusal):
                b.ReaderBridge()
            self.manifest = original

    def test_unsigned_bridge_and_source_tamper_never_loaded(self):
        with self.installed():
            (self.install / 'bridge.sig').write_bytes(bytes(64))
            with self.assertRaises(a.Refusal):
                b.ReaderBridge()
            self.write_bridge_manifest()
            self.bridge.write_bytes(b'changed')
            with self.assertRaises(a.Refusal):
                b.ReaderBridge()

    def test_manifest_validity_and_unknown_fields(self):
        for change in ({'issued': self.now + 1}, {'expires': self.now}, {'schema': True}, {'unsafe': True}):
            value = dict(self.manifest, **change)
            with self.subTest(change=change), self.installed(), self.assertRaises(a.Refusal):
                b.validate_manifest(value, dict(_deployment_sha256=self.manifest['deployment_sha256'],
                    _installation_sha256=self.manifest['installation_sha256']), now=self.now, boot=self.boot)

    def test_wrong_signature_domain(self):
        (self.install / 'bridge.sig').write_bytes(self.sign(a.canonical(self.manifest), domain=a.DOMAIN))
        with self.installed(), self.assertRaises(a.Refusal):
            b.ReaderBridge()

    def test_transitive_decoder_and_scanner_protected_before_controller_import(self):
        for name in b.TRANSITIVE_SOURCE_PINS:
            path = self.install / 'sources' / name
            raw = path.read_bytes()
            path.write_bytes(b'changed transitive source')
            with self.subTest(name=name), self.installed(), self.assertRaises(a.Refusal):
                b.ReaderBridge()
            path.write_bytes(raw)

    def test_revalidation_rejects_manifest_or_source_change_after_constructor(self):
        with self.installed():
            bridge = b.ReaderBridge()
            self.bridge.write_bytes(b'changed')
            with self.assertRaises(a.Refusal):
                bridge._installation()


class ClaimTests(unittest.TestCase):
    command = staticmethod(crypto.AdmissionTests.command)
    sign = crypto.AdmissionTests.sign
    setUpClass = classmethod(crypto.AdmissionTests.setUpClass.__func__)
    tearDownClass = classmethod(crypto.AdmissionTests.tearDownClass.__func__)

    def setUp(self):
        self.now = int(time.time())
        self.binding = dict(schema=1, scope=b.SCOPE, reader={'pid': 78502, 'start_ticks': '5054051'},
            intent_sha256='c' * 64, protected_files_sha256='d' * 64, units=2,
            target=dict(bucket=a.BUCKET, prefix='rhea/'))
        self.claims = dict(self.binding, issued=self.now - 1, expires=self.now + 120, nonce=secrets.token_hex(32))

    def verify(self, claims=None, signature=None, domain=a.DOMAIN):
        raw = a.canonical(self.claims if claims is None else claims)
        original = a.verify_detached
        def verify(*args, **kwargs):
            return original(*args, **dict(kwargs, openssl_uid=os.stat('/usr/bin/openssl').st_uid))
        with patch.object(a, 'PUBLIC_KEY_SHA256', self.pin), patch.object(a, 'KEY_NOT_BEFORE', self.now - 100), \
             patch.object(a, 'KEY_NOT_AFTER', self.now + 1000), patch.object(a, 'verify_detached', verify):
            return b.verify_claims(raw, self.sign(raw, domain=domain) if signature is None else signature,
                                  self.pem, binding=self.binding, now=self.now)

    def test_real_detached_ed25519_signature(self):
        self.assertEqual(self.verify().nonce, self.claims['nonce'])

    def test_each_exact_signed_binding_field_refuses_change(self):
        for key in self.binding:
            claims = dict(self.claims, **{key: 'changed'})
            with self.subTest(key=key), self.assertRaises(a.Refusal):
                self.verify(claims)

    def test_signature_domain_and_signature_corruption_refuse(self):
        for kwargs in ({'domain': a.DEPLOYMENT_DOMAIN}, {'signature': bytes(64)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(a.Refusal):
                self.verify(**kwargs)

    def test_time_nonce_boolean_and_extra_fields_refuse(self):
        for change in ({'issued': self.now + 1}, {'expires': self.now}, {'issued': True},
                       {'expires': self.now + 901}, {'nonce': 'a' * 64}, {'extra': True}):
            with self.subTest(change=change), self.assertRaises(a.Refusal):
                self.verify(dict(self.claims, **change))


class FlowTests(unittest.TestCase):
    def test_real_locked_observe_flow_checks_before_and_after_and_closes_clients(self):
        bridge = object.__new__(b.ReaderBridge)
        bridge._active = True
        bridge.outside = evidence()
        report = b.p.object_json(bridge.outside['raw'])
        now = report['observed_unix'] + 2
        report['observed_unix'] += 1
        witness = bridge.outside['witness']
        bridge.lock_identity = dict(device=1, inode=2)
        bridge.manifest, bridge.raw = {}, b'offline signed manifest bytes'
        calls = []
        s3 = types.SimpleNamespace(close=lambda: calls.append('s3-close'))
        sts = types.SimpleNamespace(close=lambda: calls.append('sts-close'))
        cloud = {'Account': 'fixed-test-identity'}
        host = types.SimpleNamespace(cloud=lambda _: (s3, sts))
        w = types.SimpleNamespace(CONFIG=Path('/fixed/config'), parse_config=lambda _: ('key', 'secret'),
            read_protected=lambda *args, **kwargs: b'offline configuration', verify_cloud_identity=lambda *_: cloud)
        bridge.ctx = {'rt': types.SimpleNamespace(host=host), 'w': w, 'admission': {'identity': cloud}}
        bridge.health = types.SimpleNamespace(observe=lambda *args, **kwargs: copy.deepcopy(report))
        bridge._installation = lambda: calls.append('installation')
        with patch.object(b, 'owned_lock') as lock, patch.object(b, 'protected_inventory', return_value='e' * 64) as inventory, \
             patch.object(b, 'locked_witness', return_value=copy.deepcopy(witness)) as snapshot, \
             patch.object(b.time, 'time', return_value=now):
            first = bridge.observe()
            report['observed_unix'] += .25
            second = bridge.observe()
            self.assertEqual(first, second)  # signed identities stable; live timestamps are revalidated, not signed anew
        self.assertEqual(lock.call_count, 4)
        self.assertEqual(inventory.call_count, 4)
        self.assertEqual(snapshot.call_count, 6)
        self.assertEqual(calls.count('s3-close'), 2)
        self.assertEqual(calls.count('sts-close'), 2)
        self.assertFalse(first['execution_allowed'])
        self.assertFalse(first['controller_ready'])
        bridge._active = False
        with self.assertRaises(a.Refusal):
            bridge.observe()

    def test_full_protected_inventory_no_omissions_and_full_byte_verification(self):
        public = Path('/production/public-source')
        private = Path('/private/source')
        bodies = {name: ('exact full protected source ' + name).encode() for name in
                  set(b.p.PROTECTED_PINS) | {str(private), '/rclone', '/config', '/ledger',
                  str(b.h.TRUST / 'run_rhea_full_clone_steps_batch2.py')}}
        pins = {name: dict(bytes=len(raw), sha256=a.sha(raw)) for name, raw in bodies.items()}
        public_pin = dict(bytes=3, sha256=a.sha(b'pub'))
        pins[str(public)] = public_pin
        read_public = []
        ctx = dict(w=types.SimpleNamespace(RCLONE=Path('/rclone'), CONFIG=Path('/config'), LEDGER=Path('/ledger'),
                       read_protected=lambda path, **kwargs: bodies[str(path)]),
                   reboot=types.SimpleNamespace(INPUTS={public}, read_input=lambda *args: read_public.append(args)),
                   protected_sources={private: a.sha(bodies[str(private)])}, protected_configs={},
                   identity={'protected_inputs': {str(public): public_pin}})
        historical = {name: pin['sha256'] for name, pin in pins.items() if name in b.p.PROTECTED_PINS}
        with patch.dict(b.p.PROTECTED_PINS, historical, clear=True):
            b.protected_inventory(ctx, {'protected_files': pins})
            self.assertEqual(read_public, [(public, public_pin)])
            for name in pins:
                omitted = dict(pins)
                omitted.pop(name)
                with self.subTest(name=name), self.assertRaises(a.Refusal):
                    b.protected_inventory(ctx, {'protected_files': omitted})
            bodies[str(private)] += b' changed tail'
            with self.assertRaises(a.Refusal):
                b.protected_inventory(ctx, {'protected_files': pins})

    def test_durable_signed_proposal_order_no_service_action_and_no_retry(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            directory = Path(tmp)
            bridge = object.__new__(b.ReaderBridge)
            observed = dict(bridge_manifest_sha256='d' * 64, reader={'reader': {'pid': 78502}, 'witness_sha256': 'e' * 64})
            bridge.deployment = dict(artifacts={'writer': 'a' * 64}, _deployment_sha256='b' * 64,
                                     _installation_sha256='c' * 64)
            bridge.observe = lambda: copy.deepcopy(observed)
            host = object()
            bridge.ctx = {'rt': types.SimpleNamespace(host=host)}
            intent = proposal(bridge.deployment, observed)
            original = a.protected_directory
            @contextmanager
            def protected(path, **kwargs):
                with original(path, uid=os.geteuid(), ancestor_uid=os.stat('/').st_uid, **kwargs) as fd:
                    yield fd
            original_read = a.read_at
            def read(*args, **kwargs):
                return original_read(*args, uid=os.geteuid(), **kwargs)
            verified = a.VerifiedAdmission(b'claims', bytes(64), secrets.token_hex(32), int(time.time()) + 120)
            events = []
            fsync = os.fsync
            def sync(fd):
                events.append('fsync')
                return fsync(fd)
            def consume(admission, actual_host):
                self.assertIs(admission, verified)
                self.assertIs(actual_host, host)
                self.assertEqual(os.listdir(directory), [])
                events.append('nonce')
            with patch.object(b, 'EVIDENCE', directory), patch.object(a, 'protected_directory', protected), \
                 patch.object(a, 'read_at', read), patch.object(a, 'protected_read', return_value=b'claims'), \
                 patch.object(b, 'verify_claims', return_value=verified), \
                 patch.object(a, 'consume_production_nonce', side_effect=consume) as nonce, \
                 patch.object(b.os, 'fsync', side_effect=sync):
                result = bridge.retain_stop_proposal(intent)
                self.assertEqual(events, ['nonce'] + ['fsync'] * 10)  # file and directory for each record
                self.assertEqual((directory / 'intent.json').read_bytes(), a.canonical(intent))
                stop = a.parse((directory / 'reader-stop-intent.json').read_bytes())
                self.assertFalse(stop['executable'])
                self.assertFalse(stop['automatic_retry'])
                self.assertEqual(stop['intent_sha256'], a.sha(a.canonical(intent)))
                self.assertEqual(result['service_actions'], 0)
                with self.assertRaises(a.Refusal):
                    bridge.retain_stop_proposal(intent)
                self.assertEqual(nonce.call_count, 1)
                partial = directory / 'partial-attempt'
                partial.mkdir(mode=0o700)
                def crash(fd):
                    fsync(fd)
                    raise OSError('simulated intent file fsync boundary, before directory fsync')
                with patch.object(b, 'EVIDENCE', partial), \
                     patch.object(a, 'consume_production_nonce') as partial_nonce:
                    with patch.object(b.os, 'fsync', side_effect=crash), self.assertRaises(OSError):
                        bridge.retain_stop_proposal(intent)
                    self.assertEqual((partial / 'intent.json').read_bytes(), a.canonical(intent))
                    self.assertFalse((partial / 'reader-stop-intent.json').exists())
                    with self.assertRaises(a.Refusal):
                        bridge.retain_stop_proposal(intent)
                    self.assertEqual(partial_nonce.call_count, 1)
            for path in directory.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_lock_order_outside_child_then_locked_independent_observation(self):
        bridge = object.__new__(b.ReaderBridge)
        bridge._active = False
        events = []
        bridge._installation = lambda: events.append('installation')
        bridge.adapter = types.SimpleNamespace(observe_reader_restored=lambda:
            events.append('child-takes-own-lock') or {'evidence': evidence()})
        @contextmanager
        def lock():
            events.append('exclusive-enter')
            try:
                yield
            finally:
                events.append('exclusive-exit')
        bridge.health = types.SimpleNamespace(load=lambda: {'rt': types.SimpleNamespace(lock=lock)})
        bridge.observe = lambda: events.append('independent-locked-observation') or {'controller_ready': False}
        with patch.object(b.p, '_unlocked_identity', return_value={'device': 1, 'inode': 2}):
            with bridge.locked():
                self.assertTrue(bridge._active)
                with self.assertRaises(a.Refusal):
                    with bridge.locked():
                        pass
        self.assertEqual(events, ['installation', 'child-takes-own-lock', 'exclusive-enter',
                                  'independent-locked-observation', 'exclusive-exit'])
        self.assertFalse(bridge._active)
        self.assertIsNone(bridge.ctx)

    def test_owned_lock_real_kernel_inode_and_pid(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            directory = Path(tmp)
            lock = directory / 'writer.lock'
            lock.write_bytes(b'')
            lock.chmod(0o600)
            info = lock.stat()
            identity = dict(device=info.st_dev, inode=info.st_ino)
            original = a.protected_directory
            @contextmanager
            def protected(path, **kwargs):
                with original(path, uid=os.geteuid(), ancestor_uid=os.stat('/').st_uid, **kwargs) as fd:
                    yield fd
            original_read = a.read_at
            def read(*args, **kwargs):
                return original_read(*args, uid=os.geteuid(), **kwargs)
            host = types.SimpleNamespace(locked=True)
            with patch.object(b.p, 'LOCK', lock), patch.object(a, 'protected_directory', protected), \
                 patch.object(a, 'read_at', read), lock.open('r') as held:
                with self.assertRaises(a.Refusal):
                    b.owned_lock(host, identity)
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                b.owned_lock(host, identity)
                with self.assertRaises(a.Refusal):
                    b.owned_lock(host, dict(identity, inode=identity['inode'] + 1))
                host.locked = False
                with self.assertRaises(a.Refusal):
                    b.owned_lock(host, identity)

    def test_proposal_pins_full_request_reader_writer_and_physical_lineage(self):
        deployment = dict(artifacts={'writer': 'a' * 64}, _deployment_sha256='b' * 64,
                          _installation_sha256='c' * 64)
        observed = dict(bridge_manifest_sha256='d' * 64, reader={'pid': 78502})
        intent = proposal(deployment, observed)
        b.validate_proposal(intent, deployment, observed)
        for key in intent:
            changed = copy.deepcopy(intent)
            changed[key] = 'changed'
            with self.subTest(key=key), self.assertRaises(a.Refusal):
                b.validate_proposal(changed, deployment, observed)
        for key, value in [('maximum_units', True), ('maximum_units', 1), ('before', {}),
                           ('initial_plan_sha256', 'x')]:
            changed = copy.deepcopy(intent)
            changed['request'][key] = value
            with self.subTest(key=key), self.assertRaises(a.Refusal):
                b.validate_proposal(changed, deployment, observed)

    def test_no_mutation_interface_and_no_live_cli(self):
        for name in ('handoff', 'run_go_monitored', 'publish_markers', 'drain_stop', 'reopen_readonly', 'stop_reader'):
            self.assertFalse(hasattr(b.ReaderBridge, name))
        with patch.object(b, 'ReaderBridge', side_effect=AssertionError('no host construction')), \
             patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(b.main(), 2)

    def test_pure_handoff_controls_preserve_exact_identities_and_stay_blocked(self):
        deployment = dict(artifacts={'writer': 'a' * 64}, _deployment_sha256='b' * 64,
                          _installation_sha256='c' * 64)
        observed = dict(bridge_manifest_sha256='d' * 64,
                        reader={'reader': copy.deepcopy(b.p.IMMUTABLE_REPORT['reader_process'])})
        intent = proposal(deployment, observed)
        plan = b.handoff_plan(intent, deployment, observed)
        self.assertEqual(plan['state'], 'proposal-only')
        self.assertFalse(plan['execution_allowed'])
        self.assertFalse(plan['automatic_retry'])
        stop, writer = plan['controls']
        self.assertEqual(stop['process']['pid'], 78502)
        self.assertEqual(stop['unit'], b.p.READER_UNIT)
        self.assertEqual(writer['mount'], b.p.WRITER_MOUNT)
        self.assertEqual(writer['cache'], b.p.CACHES[1])
        self.assertEqual(writer['rc_socket'], str(b.p.WRITER_SOCKET))
        self.assertFalse(stop['executable'])
        self.assertFalse(writer['executable'])
        changed = copy.deepcopy(intent)
        changed['unit_count'] = 1
        with self.assertRaises(a.Refusal):
            b.handoff_plan(changed, deployment, observed)


if __name__ == '__main__':
    unittest.main()
