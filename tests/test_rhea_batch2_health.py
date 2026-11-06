"""Offline policy, retained-chain and mount-identity boundaries; no host actions."""
import copy
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


m = module('batch2_health_tests', ROOT / 'scripts/rhea_batch2_health.py')
c = module('batch2_health_original_controller', ROOT / 'scripts/run_rhea_full_clone_steps.py')
b = module('batch2_health_candidate_controller', ROOT / 'scripts/run_rhea_full_clone_steps_batch2.py')
e = module('batch2_health_policy_engine', ROOT / 'scripts/rhea_batch2_policy_transition.py')
w = module('batch2_health_wrapper', ROOT / 'scripts/rhea_wasabi_lab_mount.py')
r = module('batch2_health_reboot', ROOT / 'scripts/rhea_post_reboot_health.py')
fixtures = module('batch2_health_verifier_fixtures', Path(__file__).with_name('test_verify_rhea_full_clone.py'))
v = fixtures.m


def exported(name):
    return (ROOT / 'docs/evidence' / name).read_bytes()


class ReadSet:
    def __init__(self, stored):
        self.stored, self.reads = stored, []
        self.unchanged = Mock()

    def raw(self, role, path, *, expected=None, **kwargs):
        raw = self.stored[path]
        m.require(expected is None or m.sha(raw) == expected, 'retained digest differs: ' + role)
        self.reads.append((role, path))
        return raw

    def json(self, role, path, **kwargs):
        return c.json_object(self.raw(role, path, **kwargs))


def policy_fixture():
    old = exported('rhea-bounded-adoption-state-after-20261106.json')
    pins = exported('rhea-bounded-adoption-pins-after-20261106.json')
    after, new_pins = e.expected_transition(old, pins)
    sources = {
        'controller-candidate.py': (ROOT / 'scripts/run_rhea_full_clone_steps_batch2.py').read_bytes(),
        'transaction.py': (ROOT / 'scripts/rhea_batch2_policy_transition.py').read_bytes(),
        'health.py': (ROOT / 'scripts/rhea_batch2_health.py').read_bytes(),
        'expected-state-before.json': old, 'expected-pins-before.json': pins,
        'run.py': b'fixed reviewed runner', 'mounts.py': b'fixed reviewed mount lifecycle',
        'one-step.py': b'fixed reviewed one-step runner',
    }
    deployment = {'schema': 1, 'scope': 'fixed-generation-nine-batch2-policy-deployment',
        'source_commit': '1' * 40, 'parent_commit': '10a088d5f3de8e3c1e555e6b1848f224dbd79451',
        'payloads': {name: {'sha256': m.sha(raw), 'bytes': len(raw)} for name, raw in sources.items()}}
    deployment_raw = m.canonical(deployment)
    provenance = {'schema': 1, 'source_commit': deployment['source_commit'],
        'deployment_sha256': m.sha(deployment_raw), 'recipe_sha256': m.sha(sources['run.py']),
        'engine_sha256': m.sha(sources['transaction.py']), 'health_sha256': m.sha(sources['health.py'])}
    plan = e.build_plan(old, pins, {'controller': sources['controller-candidate.py']}, provenance)

    def observation(phase):
        before = phase == 'policy-before'
        return {'phase': phase, 'generation': 9, 'rewrites': 5, 'baseline_state_sha256': m.OLD_STATE_SHA,
            'checkpoint_sha256': m.CERT_SHA, 'state_sha256': m.OLD_STATE_SHA if before else m.NEW_STATE_SHA,
            'pins_sha256': m.OLD_PINS_SHA if before else m.NEW_PINS_SHA}

    intent = dict(plan.intent_fields(), started_unix=1000, before=observation('policy-before'))
    intent_raw = m.canonical(intent)
    done = {'schema': 1, 'scope': e.COMPLETED_SCOPE, 'completed_unix': 1001,
        'intent_sha256': m.sha(intent_raw), 'generation': 9, 'rewrites': 5, 'checkpoint_sha256': m.CERT_SHA,
        'state_sha256': m.NEW_STATE_SHA, 'pins_sha256': m.NEW_PINS_SHA, 'artifacts': plan.artifacts(),
        'after': observation('policy-after'), 'resumed': False, 'state_replaced_this_run': True,
        'database_writer_invoked': False, 'pebble_open_performed': False, 'service_action_performed': False}
    stored = {m.OPS / name: raw for name, raw in sources.items()}
    stored.update({m.OPS / 'deployment.json': deployment_raw, m.OPS / 'state-before.json': old,
        m.OPS / 'pins-before.json': pins, m.OPS / 'intent.json': intent_raw,
        m.OPS / 'completed.json': m.canonical(done), m.STATE: after,
        m.CONTROLLER: sources['controller-candidate.py'], m.PINS: new_pins})
    ctx = {'c': c, 'engine': e, 'batch': b, 'w': w, 'reboot': r, 'v': v,
        'f': SimpleNamespace(),
        'adopted_state': c.json_object(old), 'adopted_pins': c.json_object(pins),
        'admitted_state': c.json_object(after), 'batch2_pins': c.json_object(new_pins),
        'cert': c.json_object(old)['checkpoint']}
    return ctx, stored, plan


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.ctx, self.stored, self.plan = policy_fixture()
        self.absence = patch.object(m, 'absent', side_effect=lambda path: path not in self.stored)
        self.absence.start()
        self.addCleanup(self.absence.stop)
        self.new_rt = SimpleNamespace(binding=self.ctx['admitted_state']['binding'], pins=self.ctx['batch2_pins'],
            load_state=Mock(return_value=self.ctx['admitted_state']),
            host=Mock(), profile=object())
        self.candidate = SimpleNamespace(Runtime=Mock(return_value=self.new_rt))
        self.importer = patch.object(m, 'exact_module', return_value=self.candidate)
        self.import_mock = self.importer.start()
        self.addCleanup(self.importer.stop)

    def test_before_accepts_only_absent_or_exact_successor_files_and_keeps_old_state(self):
        self.stored[m.STATE] = self.plan.state_before
        for name in ('intent.json', 'completed.json'):
            del self.stored[m.OPS / name]
        del self.stored[m.CONTROLLER]
        del self.stored[m.PINS]
        state, pins, done = m._policy(self.ctx, ReadSet(self.stored), 'policy-before', None)
        self.assertEqual(state, self.ctx['adopted_state'])
        self.assertEqual(pins, m.OLD_PINS_SHA)
        self.assertIsNone(done)
        self.stored[m.CONTROLLER] = b'partial controller'
        with self.assertRaisesRegex(RuntimeError, 'digest differs'):
            m._policy(self.ctx, ReadSet(self.stored), 'policy-before', None)

    def test_exact_after_accepts_durable_intent_before_completion_and_later_completion(self):
        intent_sha = m.sha(self.stored[m.OPS / 'intent.json'])
        completion = self.stored.pop(m.OPS / 'completed.json')
        state, pins, done = m._policy(self.ctx, ReadSet(self.stored), 'policy-after', intent_sha)
        self.assertEqual(m.sha(m.canonical(state)), m.NEW_STATE_SHA)
        self.assertEqual(pins, m.NEW_PINS_SHA)
        self.assertIsNone(done)
        self.stored[m.OPS / 'completed.json'] = completion
        _, _, done = m._policy(self.ctx, ReadSet(self.stored), 'writer-stopped', None)
        self.assertEqual(done['checkpoint_sha256'], m.CERT_SHA)

    def test_resealed_extra_policy_leaf_or_wrong_intent_is_refused(self):
        changed = copy.deepcopy(self.ctx['admitted_state'])
        changed['binding']['limits']['cache_bytes'] += 1
        self.stored[m.STATE] = m.canonical(changed)
        with self.assertRaisesRegex(RuntimeError, 'two-leaf'):
            m._policy(self.ctx, ReadSet(self.stored), 'policy-after', m.sha(self.stored[m.OPS / 'intent.json']))
        self.stored[m.STATE] = self.plan.state_after
        with self.assertRaisesRegex(RuntimeError, 'intent digest'):
            m._policy(self.ctx, ReadSet(self.stored), 'policy-after', '0' * 64)

    def test_after_same_before_context_validates_new_runtime_without_transferring_its_host(self):
        original_rt, original_wrapper = object(), self.ctx['w']
        self.ctx.update(batch=None, rt=original_rt)
        self.stored[m.STATE] = self.plan.state_before
        intent_sha = m.sha(self.stored[m.OPS / 'intent.json'])
        m._policy(self.ctx, ReadSet(self.stored), 'policy-before', intent_sha)
        self.candidate.Runtime.assert_not_called()
        self.stored[m.STATE] = self.plan.state_after
        m._policy(self.ctx, ReadSet(self.stored), 'policy-after', intent_sha)
        self.import_mock.assert_called_once_with(m.CONTROLLER, m.CONTROLLER_SHA, 'batch2_policy_runtime_validation')
        self.candidate.Runtime.assert_called_once_with()
        self.new_rt.load_state.assert_called_once_with()
        self.new_rt.host.assert_not_called()
        self.assertIs(self.ctx['rt'], original_rt)
        self.assertIs(self.ctx['w'], original_wrapper)
        self.assertIsNone(self.ctx['batch'])
        self.new_rt.load_state.return_value = self.ctx['adopted_state']
        with self.assertRaisesRegex(RuntimeError, 'does not accept'):
            m._policy(self.ctx, ReadSet(self.stored), 'policy-after', intent_sha)

    def test_deployment_source_change_is_not_accepted_by_an_unchanged_intent(self):
        self.stored[m.OPS / 'mounts.py'] += b'changed'
        with self.assertRaisesRegex(RuntimeError, 'digest differs'):
            m._policy(self.ctx, ReadSet(self.stored), 'policy-after', m.sha(self.stored[m.OPS / 'intent.json']))

    def test_pending_wrong_counter_and_generation14_are_not_closed_health(self):
        for change in ({'pending': {}}, {'rewrites': 6}, {'generation': 14, 'rewrites': 10}, {'schema': True}):
            state = copy.deepcopy(self.ctx['admitted_state'])
            state.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'closed bounded'):
                m.validate_progress(self.ctx, ReadSet({}), state)
        self.assertEqual(m.validate_progress(self.ctx, ReadSet({}), self.ctx['admitted_state']), [])


class RuntimeBindingTests(unittest.TestCase):
    def setUp(self):
        self.ctx, self.stored, _ = policy_fixture()
        self.rt = object.__new__(b.Runtime)
        self.rt.wrapper, self.rt.host = w, w.RealHost()
        self.rt.profile, self.rt.verifier = w.PROFILES['full-clone'], v
        self.rt.binding, self.rt.pins = self.ctx['admitted_state']['binding'], self.ctx['batch2_pins']
        self.stored[b.WRAPPER] = (ROOT / 'scripts/rhea_wasabi_lab_mount.py').read_bytes()
        self.reader = patch.object(w, 'read_protected', side_effect=lambda path, **kw: self.stored[path])
        self.reader.start()
        self.addCleanup(self.reader.stop)

    def test_complete_runtime_tuple_is_rebound_without_mutating_original_context(self):
        original = dict(self.ctx)
        bound = m.bind_runtime(self.ctx, self.rt)
        self.assertEqual(self.ctx, original)
        self.assertIsNot(bound, self.ctx)
        for key, expected in (('rt', self.rt), ('w', w), ('c', b), ('v', v)):
            self.assertIs(bound[key], expected)

    def test_profile_from_another_identical_import_or_nonreal_host_is_refused(self):
        other = module('batch2_health_distinct_wrapper', ROOT / 'scripts/rhea_wasabi_lab_mount.py')
        self.rt.profile = other.PROFILES['full-clone']
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            m.bind_runtime(self.ctx, self.rt)
        self.rt.profile = w.PROFILES['full-clone']
        self.rt.host = SimpleNamespace(locked=True)
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            m.bind_runtime(self.ctx, self.rt)

    def test_unapproved_binding_or_installed_source_is_refused(self):
        self.rt.binding = copy.deepcopy(self.rt.binding)
        self.rt.binding['limits']['maximum_rewrites'] = 10
        with self.assertRaisesRegex(RuntimeError, 'binding'):
            m.bind_runtime(self.ctx, self.rt)
        self.rt.binding = self.ctx['admitted_state']['binding']
        self.stored[m.CONTROLLER] = b'not the reviewed controller'
        with self.assertRaisesRegex(RuntimeError, 'source'):
            m.bind_runtime(self.ctx, self.rt)


class RetainedHistoryTests(unittest.TestCase):
    def test_real_adoption_acceptance_uses_saved_preimage_and_never_old_live_guard(self):
        h = module('batch2_saved_adoption_health', ROOT / 'scripts/rhea_bounded_adoption_health.py')
        comparison = module('batch2_saved_acceptance_metrics', ROOT / 'scripts/run_rhea_integrated_verification_profile.py')
        directory = r.ADOPTION
        stored = {}

        def adoption(name):
            return exported('rhea-bounded-adoption-' + name + '-20261106.json')

        for name in ('state-before', 'pins-before', 'intent', 'completed', 'deployment'):
            stored[directory / (name + '.json')] = adoption(name)
        sources = {'controller-candidate.py': 'run_rhea_full_clone_steps_bounded.py',
            'verifier-candidate.py': 'verify_rhea_full_clone_bounded.py',
            'scanner-candidate.py': 'enumerate_rhea_versions.py', 'health.py': 'rhea_bounded_adoption_health.py',
            'transaction.py': 'adopt_rhea_bounded_verification.py', 'run.py': 'run_rhea_bounded_adoption.py'}
        for name, source in sources.items():
            stored[directory / name] = (ROOT / 'scripts' / source).read_bytes()
        stored[directory / 'expected-state-before.json'] = adoption('state-before')
        stored[directory / 'expected-pins-before.json'] = adoption('pins-before')
        stored[h.NEW_CONTROLLER] = stored[directory / 'controller-candidate.py']
        stored[h.NEW_VERIFIER] = stored[directory / 'verifier-candidate.py']
        stored[h.SCANNER] = stored[directory / 'scanner-candidate.py']
        stored[h.NEW_PINS] = adoption('pins-after')
        accepted = directory / 'acceptance/000001'
        for name in ('intent', 'result', 'metrics', 'completed'):
            stored[accepted / (name + '.json')] = adoption('acceptance-' + name)
        state = c.json_object(adoption('state-after'))
        ctx = {'h': h, 'reboot': r, 'c': c, 'cert': state['checkpoint'],
            'bundle': c.json_object(exported('rhea-full-clone-pacing-certified-20261104.json'))}
        reads = ReadSet(stored)
        with patch.object(m, 'exact_module', return_value=comparison), \
                patch.object(m, 'absent', side_effect=lambda path: path not in stored), \
                patch.object(h, '_phase_files', side_effect=AssertionError('old current-state guard forbidden')), \
                patch.object(h, 'observe', side_effect=AssertionError('old PID observer forbidden')):
            adopted, pins, _ = m._retained_adoption(ctx, reads)
            self.assertEqual(m.sha(m.canonical(adopted)), m.OLD_STATE_SHA)
            self.assertEqual(m.sha(m.canonical(pins)), m.OLD_PINS_SHA)
            self.assertNotIn(m.STATE, [path for unused_role, path in reads.reads])
            self.assertEqual(adopted, state)
            stored[accepted / 'result.json'] += b' '
            with self.assertRaisesRegex(RuntimeError, 'acceptance differs'):
                m._retained_adoption(ctx, ReadSet(stored))


def link_fixture(generation=10):
    fx = fixtures.RepeatedStepFixture()
    fx.previous['generation'] = generation - 1
    fx.previous['sst_lineage']['rewrite_operations'] = generation - 5
    for key in ('created', 'retired'):
        fx.report['sst_diff'][key + '_bytes'] = sum(row['size'] for row in fx.report['sst_diff'][key])
    current = fx.verify()
    current.update(generation=generation, action='step', bucket=c.BUCKET, prefix=c.PREFIX,
                   pebble_reopen_verified=True)
    current['reopen'] = {'action': 'inspect', 'compactions': []}
    for side in ('before', 'after'):
        current['reopen'][side + '_format'] = fx.report['after_format']
        for field in ('marked', 'sst_files', 'sst_bytes', 'sst_inventory_sha256'):
            current['reopen'][field + '_' + side] = fx.report[field + '_after']
    before, before_stats = v._decode_tables(fx.metadata[fx.old_manifest])
    after, after_stats = v._decode_tables(fx.metadata[fx.new_manifest])
    exit_report = {'returncode': 0, 'monitor_failure': None, 'budget_stop_present': False}
    with patch.object(v.base, 'EXPECTED_SSTS', 2), patch.object(v.base, 'EXPECTED_SST_BYTES', 300), \
            patch.object(v.base, 'EXPECTED_INVENTORY', v.base.inventory_digest({1: 100, 2: 200})):
        baseline = v._baseline_pins(fx.ledger)
    return [c, v, fx.previous, current, fx.report, exit_report, fx.hashes,
            before, after, before_stats, after_stats, baseline]


class LinkTests(unittest.TestCase):
    def test_each_new_generation_preserves_actual_verifier_lineage_and_hash_equations(self):
        for generation in range(10, 14):
            with self.subTest(generation=generation):
                args = link_fixture(generation)
                before = copy.deepcopy(args[2:])
                created, retired = m.validate_link(*args)
                self.assertEqual(set(created), {'000026.sst'})
                self.assertEqual(set(retired), {'000002.sst'})
                self.assertEqual(args[2:], before)

    def test_old_or_beyond_window_generation_and_changed_parent_are_refused(self):
        for generation in (9, 14):
            with self.subTest(generation=generation), self.assertRaisesRegex(RuntimeError, 'not final'):
                m.validate_link(*link_fixture(generation))
        args = link_fixture()
        args[3]['previous_checkpoint_sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'chain hashes'):
            m.validate_link(*args)

    def test_failed_or_unmonitored_close_is_never_made_a_success(self):
        for change in ({'returncode': 1}, {'returncode': True}, {'monitor_failure': 'RC timeout'},
                       {'budget_stop_present': True}):
            args = link_fixture()
            args[5].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'close successfully'):
                m.validate_link(*args)

    def test_resealed_picker_substitution_does_not_bypass_canonical_binding(self):
        args = link_fixture()
        args[4]['picker_plan']['candidate_sha256'] = '0' * 64
        args[3]['go_report_sha256'] = c.digest(args[4])
        with self.assertRaisesRegex(RuntimeError, 'picker binding'):
            m.validate_link(*args)

    def test_changed_prior_output_mark_or_payload_pin_is_refused(self):
        for field, value in (('size', 118), ('sha256', '0' * 64)):
            args = link_fixture()
            args[3]['sst_lineage']['created']['000020.sst'][field] = value
            with self.subTest(field=field), self.assertRaises((RuntimeError, v.VerificationError)):
                m.validate_link(*args)
        args = link_fixture()
        args[8]['000020.sst']['marked'] = True
        with self.assertRaises((RuntimeError, v.VerificationError)):
            m.validate_link(*args)


def pid(number, ticks):
    return {'pid': number, 'start_ticks': str(ticks), 'boot_id': m.BOOT_ID}


def unit(active=False, number=0):
    return {'LoadState': 'loaded' if active else 'not-found',
        'ActiveState': 'active' if active else 'inactive', 'SubState': 'running' if active else 'dead',
        'MainPID': str(number), 'Result': 'success', 'ExecMainStatus': '0'}


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.ctx, self.stored, self.plan = policy_fixture()
        self.reader = {'process': pid(4415, 109203), 'service': unit(True, 4415), 'properties': {}, 'mount': {}}
        self.production = {'production_process': pid(3786, 93876), 'rc_server': {'process': pid(3905, 94049)}}
        self.identity = {'reader': self.reader, 'production': self.production}
        self.clean = {'bytesUsed': 0, 'uploadsQueued': 0, 'uploadsInProgress': 0, 'erroredFiles': 0, 'outOfSpace': False}
        self.writer = pid(5000, 120000)
        self.lab = {'pid': 5000, 'stats': {'fs': w.PROFILES['full-clone'].remote,
            'diskCache': dict(self.clean)}, 'queue': {'queue': []}}
        self.old = SimpleNamespace(READER_UNIT='reader.service', READER_MOUNT=Path('/reader'),
            READER_CACHE=Path('/reader-cache'), no_other_lab_users=Mock(),
            reader_observation=Mock(return_value=self.reader), writer_absent=Mock(return_value=unit()))
        host = SimpleNamespace(locked=True, service=Mock(side_effect=lambda name: unit() if name == self.old.READER_UNIT else unit(True, 5000)),
            unit_identity=Mock(return_value=5000))

        def current_process(number):
            if number == 5000:
                return self.writer
            raise FileNotFoundError()

        self.rt = SimpleNamespace(host=host, profile=w.PROFILES['full-clone'],
            stop_present=Mock(return_value=False), _process_identity=Mock(side_effect=current_process),
            guard=Mock(return_value=self.lab), free_bytes=Mock(return_value=7 * 1024**4))
        self.ctx.update(rt=self.rt, identity=self.identity, old=self.old,
            f=SimpleNamespace(ReadSet=lambda *unused: ReadSet(self.stored)))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(m, 'absent', side_effect=lambda path: path not in self.stored))
        self.unchanged = self.stack.enter_context(patch.object(m, '_unchanged'))
        self.prod = self.stack.enter_context(patch.object(m, 'production_observation', return_value=self.production))
        self.rc = self.stack.enter_context(patch.object(m, '_production_rc', return_value=self.clean))
        self.stack.enter_context(patch.object(m.Path, 'read_text', lambda path, **kw: m.BOOT_ID if path.name == 'boot_id' else ''))
        self.stack.enter_context(patch.object(m.Path, 'is_dir', return_value=True))
        self.stack.enter_context(patch.object(m.os, 'uname', return_value=SimpleNamespace(release=m.KERNEL)))
        validation_rt = SimpleNamespace(binding=self.ctx['admitted_state']['binding'], pins=self.ctx['batch2_pins'],
            load_state=Mock(return_value=self.ctx['admitted_state']))
        self.stack.enter_context(patch.object(m, 'exact_module',
            return_value=SimpleNamespace(Runtime=Mock(return_value=validation_rt))))

    def seal_writer(self):
        started = {'process': self.writer, 'observation': self.lab,
            'state_sha256': m.NEW_STATE_SHA, 'checkpoint_sha256': m.CERT_SHA}
        raw = m.canonical(started)
        self.stored[m.OPS / 'writer-started.json'] = raw
        self.stored[m.OPS / 'start-completed.json'] = m.canonical({'verified': True,
            'writer_started_sha256': m.sha(raw), 'writer_process': self.writer,
            'state_sha256': m.NEW_STATE_SHA, 'checkpoint_sha256': m.CERT_SHA})
        return m.sha(raw)

    def test_policy_after_observes_exact_original_reader_and_stopped_writer(self):
        value = m.observe(self.ctx, phase='policy-after', intent_sha256=m.sha(self.stored[m.OPS / 'intent.json']))
        self.assertEqual(value['state_sha256'], m.NEW_STATE_SHA)
        self.assertEqual(value['reader_process'], self.reader['process'])
        self.assertTrue(value['writer_mount_and_socket_absent'])
        self.assertEqual(value['production_rc_process']['pid'], 3905)
        self.unchanged.assert_called()
        self.rt.guard.assert_not_called()

    def test_unlocked_or_pending_refuses_before_host_or_network_observation(self):
        self.rt.host.locked = False
        with self.assertRaisesRegex(RuntimeError, 'idle lock'):
            m.observe(self.ctx, phase='policy-after')
        self.prod.assert_not_called()
        self.rt.host.locked = True
        state = copy.deepcopy(self.ctx['admitted_state'])
        state['pending'] = {'phase': 'executing'}
        self.stored[m.STATE] = m.canonical(state)
        with self.assertRaisesRegex(RuntimeError, 'closed bounded'):
            m.observe(self.ctx, phase='writer-active')
        self.prod.assert_not_called()

    def test_writer_active_uses_sealed_new_identity_and_never_old_reader_observer(self):
        self.seal_writer()
        value = m.observe(self.ctx, phase='writer-active')
        self.assertEqual(value['writer_process'], self.writer)
        self.assertIsNone(value['reader_process'])
        self.assertFalse(value['writer_mount_and_socket_absent'])
        self.old.reader_observation.assert_not_called()
        self.rt.guard.assert_called_once_with(new_work=False, clean=True)
        self.assertEqual(self.rt.pid, 5000)

    def test_writer_restart_wrong_peer_or_start_failure_is_refused(self):
        self.seal_writer()
        self.rt._process_identity.side_effect = lambda unused: pid(5000, 999999)
        with self.assertRaisesRegex(RuntimeError, 'sealed startup'):
            m.observe(self.ctx, phase='writer-active')
        self.rt.guard.assert_not_called()
        self.stored[m.OPS / 'start-failure.json'] = b'preserved failure'
        with self.assertRaisesRegex(RuntimeError, 'failure reconciliation'):
            m.observe(self.ctx, phase='writer-active')

    def test_new_reader_requires_explicit_raw_pin_or_matching_completed_generation(self):
        restored = copy.deepcopy(self.reader)
        restored['process'] = pid(6000, 130000)
        raw = m.canonical(restored)
        directory = m.OPS / 'finalization'
        self.stored[directory / 'reader-restored.json'] = raw
        self.old.reader_observation.return_value = restored
        value = m.observe(self.ctx, phase='reader-restored', reader_sha256=m.sha(raw))
        self.assertEqual(value['reader_process']['pid'], 6000)
        self.stored[directory / 'completed.json'] = m.canonical({'verified': True,
            'reader_restored_sha256': m.sha(raw), 'state_sha256': m.NEW_STATE_SHA, 'checkpoint_sha256': m.CERT_SHA})
        m.observe(self.ctx, phase='reader-restored')
        self.stored[directory / 'reader-restored.json'] += b' '
        with self.assertRaisesRegex(RuntimeError, 'digest differs'):
            m.observe(self.ctx, phase='reader-restored')

    def test_during_observation_production_change_fails_before_success(self):
        changed = copy.deepcopy(self.production)
        changed['rc_server']['process']['start_ticks'] = '123456'
        self.prod.side_effect = [self.production, changed]
        with self.assertRaisesRegex(RuntimeError, 'production identity changed'):
            m.observe(self.ctx, phase='policy-after', intent_sha256=m.sha(self.stored[m.OPS / 'intent.json']))


if __name__ == '__main__':
    unittest.main()
