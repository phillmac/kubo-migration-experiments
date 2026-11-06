"""Focused offline health contract tests using the exact public gen9 anchor."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('bounded_adoption_health_tests', ROOT / 'scripts/rhea_bounded_adoption_health.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.cert = json.loads((ROOT / 'docs/evidence/rhea-full-clone-000009-step-20261104.json').read_bytes())
        binding = dict(m.old_pins(), wrapper_sha256=m.WRAPPER_SHA, seed_sha256=m.SEED_SHA,
                       bucket='rhea-pebble-lab-20261101-39037c6f01', prefix='rhea/', limits=m.LIMITS)
        self.before = {'schema': 1, 'binding': binding, 'checkpoint': self.cert,
                       'generation': 9, 'rewrites': 5, 'pending': None}
        self.before_raw = m.canonical(self.before)
        self.pins_before_raw = m.canonical(m.old_pins())
        self.assertEqual(m.sha(self.before_raw), m.BASELINE_STATE_SHA)
        self.assertEqual(m.sha(self.pins_before_raw), m.OLD_PINS_SHA)
        unused, self.after, self.new_pins = m.expected_transition(self.before_raw)
        self.profile = json.loads((ROOT / 'docs/evidence/rhea-integrated-verification-profile-20261105.json').read_bytes())
        self.before_guard = dict(copy.deepcopy(self.profile['host_after']), scope=m.HEALTH_SCOPE,
                                 phase='before', pins_sha256=m.OLD_PINS_SHA,
                                 baseline_state_sha256=m.BASELINE_STATE_SHA, intent_sha256=None)
        self.payloads = {
            'expected-state-before.json': self.before_raw, 'expected-pins-before.json': self.pins_before_raw,
            'controller-candidate.py': (ROOT / 'scripts/run_rhea_full_clone_steps_bounded.py').read_bytes(),
            'verifier-candidate.py': (ROOT / 'scripts' / m.NEW_VERIFIER.name).read_bytes(),
            'scanner-candidate.py': (ROOT / 'scripts' / m.SCANNER.name).read_bytes(),
            'health.py': (ROOT / 'scripts/rhea_bounded_adoption_health.py').read_bytes(),
            'transaction.py': b'# pure offline transaction fixture\n', 'run.py': b'# fixed offline runner fixture\n',
        }
        self.deployment = {'schema': 1, 'scope': 'fixed-generation-nine-bounded-verifier-deployment',
                           'source_commit': 'a' * 40, 'parent_commit': m.PARENT_COMMIT,
                           'payloads': {name: {'sha256': m.sha(raw), 'bytes': len(raw)}
                                        for name, raw in self.payloads.items()}}
        self.intent = {'schema': 1, 'scope': m.INTENT_SCOPE, 'started_unix': 1794000000.0,
                       'provenance': {'schema': 1, 'source_commit': 'a' * 40,
                                      'deployment_sha256': m.sha(m.canonical(self.deployment)),
                                      'recipe_sha256': m.sha(self.payloads['run.py']),
                                      'engine_sha256': m.sha(self.payloads['transaction.py']),
                                      'health_sha256': m.sha(self.payloads['health.py'])},
                       'generation': 9, 'rewrites': 5, 'checkpoint_sha256': m.CERT_SHA,
                       'old_state_sha256': m.BASELINE_STATE_SHA, 'new_state_sha256': m.sha(m.canonical(self.after)),
                       'old_pins_sha256': m.OLD_PINS_SHA, 'new_pins_sha256': m.sha(m.canonical(self.new_pins)),
                       'old_binding': self.before['binding'], 'new_binding': self.after['binding'],
                       'artifacts': m.artifact_manifest(self.new_pins), 'before': self.before_guard}
        self.intent_raw = m.canonical(self.intent)
        self.intent_sha = m.sha(self.intent_raw)
        self.after_guard = dict(copy.deepcopy(self.before_guard), phase='after',
                                state_sha256=self.intent['new_state_sha256'], pins_sha256=self.intent['new_pins_sha256'],
                                intent_sha256=self.intent_sha)
        self.files = {m.STATE: m.canonical(self.after), m.OPS / 'state-before.json': self.before_raw,
                      m.OPS / 'pins-before.json': self.pins_before_raw,
                      m.OPS / 'intent.json': self.intent_raw,
                      m.OPS / 'deployment.json': m.canonical(self.deployment),
                      m.NEW_CONTROLLER: self.payloads['controller-candidate.py'],
                      m.NEW_VERIFIER: self.payloads['verifier-candidate.py'], m.SCANNER: self.payloads['scanner-candidate.py'],
                      m.NEW_PINS: m.canonical(self.new_pins)}
        self.files.update({m.OPS / name: raw for name, raw in self.payloads.items()})
        self.old_rt = SimpleNamespace(validate_state=Mock(), host=SimpleNamespace(locked=True))

        def read(path, **kwargs):
            if path not in self.files:
                raise FileNotFoundError(str(path))
            return self.files[path]

        self.ctx = {'c': SimpleNamespace(MAX_JSON=m.MAX_JSON, json_object=json.loads,
                                        STATE_ROOT=m.STATE.parent, LIMITS=m.LIMITS),
                    'rt': self.old_rt, 'w': SimpleNamespace(read_protected=Mock(side_effect=read)),
                    'cert': self.cert, 'bundle': {'evidence': self.profile['retained_inputs']},
                    'paths': {}, 'retained': {},
                    'protected_configs': {}, 'protected_sources': {}}
        self.new_rt = SimpleNamespace(load_state=Mock(return_value=self.after),
                                      binding=self.after['binding'], pins=self.new_pins,
                                      host=Mock(), profile=object())
        self.new_module = SimpleNamespace(PINS=m.NEW_PINS, VERIFIER=m.NEW_VERIFIER, STATE_ROOT=m.STATE.parent,
                                          LIMITS=m.LIMITS, MAX_REWRITES=5, MAX_GENERATION=9,
                                          Runtime=Mock(return_value=self.new_rt))
        self.symlinks = set()

    @contextmanager
    def fixture_status(self):
        """No status query in the retained-proof fixture may reach /root."""
        failure = m.OPS / 'acceptance/000001/failure.json'
        calls = []

        def exists(path):
            self.assertEqual(path, failure, 'unexpected filesystem status query')
            calls.append(('exists', path))
            return path in self.files

        def is_symlink(path):
            self.assertEqual(path, failure, 'unexpected filesystem status query')
            calls.append(('is_symlink', path))
            return path in self.symlinks

        with patch.object(m.Path, 'exists', exists), patch.object(m.Path, 'is_symlink', is_symlink):
            yield calls

    def completion(self):
        result_value = json.loads((ROOT / 'docs/evidence/rhea-integrated-verification-bounded-candidate-20261105.json').read_bytes())
        result_value['verified_unix'] = 1794000058.0
        result = m.canonical(result_value)
        acceptance_intent = {'schema': 1, 'scope': m.ACCEPTANCE_SCOPE + '-intent', 'attempt': 1,
            'started_unix': 1794000001.0, 'adoption_intent_sha256': self.intent_sha,
            'source_commit': self.intent['provenance']['source_commit'], 'state_sha256': self.intent['new_state_sha256'],
            'checkpoint_sha256': m.CERT_SHA, 'parent_checkpoint_sha256': self.cert['previous_checkpoint_sha256'],
            'code_sha256': {role: pin[1] for role, pin in m.HELPERS.items()},
            'installed_sources': {role: pin['sha256'] for role, pin in self.intent['artifacts'].items()},
            'retained_inputs': self.profile['retained_inputs'], 'host_before': self.after_guard,
            'mode': 'final', 'workers': 4, 'max_pages': 512, 'max_received_rows': 500000,
            'soft_deadline_seconds': 420, 'address_space_limit_bytes': 2 * 1024**3,
            'database_writer_invoked': False, 'pebble_open_performed': False, 'checkpoint_replacement_permitted': False}
        intent_raw = m.canonical(acceptance_intent)
        metrics_value = {'schema': 1, 'scope': m.ACCEPTANCE_SCOPE + '-metrics', 'attempt': 1,
            'adoption_intent_sha256': self.intent_sha, 'metrics': self.profile['metrics']['bounded_candidate'],
            'enumeration': self.profile['candidate_enumeration'], 'listing_guard': self.profile['listing_guards']['bounded_candidate'],
            'sdk': self.profile['sdk'], 'invocation': {'started_unix': 1794000002.0, 'finished_unix': 1794000060.0},
            'process_peak_rss_kib': self.profile['process_peak_rss_kib']}
        metrics = m.canonical(metrics_value)
        receipt = m.canonical(dict(acceptance_intent, scope=m.ACCEPTANCE_SCOPE + '-completed',
            completed_unix=1794000061.0, intent_sha256=m.sha(intent_raw), result_sha256=m.sha(result),
            metrics_sha256=m.sha(metrics), verified=True, semantic_projection_sha256=m.PROJECTION_SHA,
            host_after=self.after_guard, wall_seconds=metrics_value['metrics']['wall_seconds'], overall_seconds=60.0,
            checkpoint_replaced=False, workers_drained=True, sdk_clients_closed=True))
        directory = m.OPS / 'acceptance/000001'
        self.files.update({directory / 'result.json': result, directory / 'metrics.json': metrics,
                           directory / 'completed.json': receipt, directory / 'intent.json': intent_raw})
        verification = {'schema': 1, 'verified': True, 'attempt': 1, 'path': 'acceptance/000001',
                        'checkpoint_sha256': m.CERT_SHA, 'semantic_projection_sha256': m.PROJECTION_SHA,
                        'result_sha256': m.sha(result), 'metrics_sha256': m.sha(metrics), 'receipt_sha256': m.sha(receipt)}
        done = {'schema': 1, 'scope': m.COMPLETED_SCOPE, 'completed_unix': 1794000062.0,
                'intent_sha256': self.intent_sha, 'generation': 9, 'rewrites': 5, 'checkpoint_sha256': m.CERT_SHA,
                'state_sha256': self.intent['new_state_sha256'], 'pins_sha256': self.intent['new_pins_sha256'],
                'artifacts': self.intent['artifacts'], 'after': self.after_guard, 'verification': verification,
                'resumed': False, 'state_replaced_this_run': True, 'database_writer_invoked': False,
                'pebble_open_performed': False}
        self.files[m.OPS / 'completed.json'] = m.canonical(done)
        return done

    def imports(self, path, digest, name):
        if path == m.NEW_CONTROLLER:
            return self.new_module
        self.assertEqual((path, digest), m.HELPERS['comparison'])
        spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/run_rhea_integrated_verification_profile.py')
        comparison = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(comparison)
        return comparison

    def test_exact_historical_sources_and_new_artifact_manifest(self):
        for name, digest in (('run_rhea_full_clone_steps.py', m.OLD_CONTROLLER_SHA),
                             ('verify_rhea_full_clone.py', m.OLD_VERIFIER_SHA),
                             ('rhea_full_clone_profile_health.py', m.OLD_HEALTH_SHA)):
            self.assertEqual(m.sha((ROOT / 'scripts' / name).read_bytes()), digest)
        for role, pin in m.artifact_manifest(self.new_pins).items():
            raw = self.files[m.TRUST / pin['path']]
            self.assertEqual({'sha256': m.sha(raw), 'bytes': len(raw)},
                             {key: pin[key] for key in ('sha256', 'bytes')}, role)

    def test_exact_certified_preimage_changes_only_two_binding_hashes(self):
        self.assertEqual({key for key in self.before if self.before[key] != self.after[key]}, {'binding'})
        self.assertEqual({key for key in self.before['binding'] if self.before['binding'][key] != self.after['binding'][key]},
                         {'controller_sha256', 'verifier_sha256'})
        self.assertEqual(self.after['binding']['limits']['maximum_rewrites'], 5)
        self.assertEqual((self.after['generation'], self.after['rewrites'], self.after['pending']), (9, 5, None))
        self.assertEqual(self.after['checkpoint'], self.cert)

    def test_altered_or_noncanonical_preimage_is_refused(self):
        for raw in (self.before_raw + b' ', self.before_raw.replace(b'"rewrites":5', b'"rewrites":6')):
            with self.subTest(raw=raw[-30:]), self.assertRaisesRegex(RuntimeError, 'preimage'):
                m.expected_transition(raw)

    def test_before_needs_no_new_installation_or_runtime(self):
        self.files = {m.STATE: self.before_raw}
        with patch.object(m, 'exact_module', side_effect=AssertionError('new runtime must not load')):
            files, state, pins = m._phase_files(self.ctx, 'before', None)
        self.assertEqual(files, {m.STATE: self.before_raw})
        self.assertEqual(state, self.before)
        self.assertEqual(pins, m.OLD_PINS_SHA)
        self.old_rt.validate_state.assert_called_once_with(self.before)

    def test_before_resume_validates_intent_without_requiring_all_targets(self):
        self.files[m.STATE] = self.before_raw
        for path in (m.NEW_CONTROLLER, m.NEW_VERIFIER, m.NEW_PINS):
            del self.files[path]
        with patch.object(m, 'exact_module', side_effect=AssertionError('new runtime must not load')):
            unused, state, pins = m._phase_files(self.ctx, 'before', self.intent_sha)
        self.assertEqual(state, self.before)
        self.assertEqual(pins, m.OLD_PINS_SHA)

    def test_after_validates_new_runtime_without_replacing_original_host(self):
        original = (self.ctx['rt'], self.ctx['w'], self.old_rt.host)
        with patch.object(m, 'exact_module', return_value=self.new_module):
            unused, state, pins = m._phase_files(self.ctx, 'after', self.intent_sha)
        self.assertEqual(state, self.after)
        self.assertEqual(pins, self.intent['new_pins_sha256'])
        self.assertEqual((self.ctx['rt'], self.ctx['w'], self.old_rt.host), original)
        self.new_module.Runtime.assert_called_once_with()
        self.new_rt.load_state.assert_called_once_with()
        self.assertEqual(self.new_rt.host.mock_calls, [])
        self.old_rt.validate_state.assert_not_called()

    def test_after_requires_exact_intent_and_all_installed_targets(self):
        for intent_sha in (None, '0' * 64):
            with self.subTest(intent_sha=intent_sha), self.assertRaises(RuntimeError):
                m._phase_files(self.ctx, 'after', intent_sha)
        for path in (m.NEW_CONTROLLER, m.NEW_VERIFIER, m.SCANNER, m.NEW_PINS):
            raw = self.files.pop(path)
            with self.subTest(path=path), self.assertRaises(FileNotFoundError):
                m._phase_files(self.ctx, 'after', self.intent_sha)
            self.files[path] = raw

    def test_after_refuses_progress_cap_or_checkpoint_changes(self):
        changes = [lambda s: s.update(generation=10), lambda s: s.update(pending={'phase': 'executing'}),
                   lambda s: s['binding']['limits'].update(maximum_rewrites=6),
                   lambda s: s['checkpoint'].update(marked_after=93689)]
        for change in changes:
            changed = copy.deepcopy(self.after)
            change(changed)
            self.files[m.STATE] = m.canonical(changed)
            with self.subTest(change=change), patch.object(m, 'exact_module') as importer, self.assertRaises(RuntimeError):
                m._phase_files(self.ctx, 'after', self.intent_sha)
            importer.assert_not_called()

    def test_intent_refuses_policy_identity_or_clean_health_tampering(self):
        changes = [lambda x: x.update(extra=True), lambda x: x.update(new_state_sha256='0' * 64),
                   lambda x: x['new_binding']['limits'].update(maximum_rewrites=6),
                   lambda x: x['artifacts']['scanner'].update(path='../enumerate_rhea_versions.py'),
                   lambda x: x['before'].update(production_rc_checked=False),
                   lambda x: x['before'].update(generation=True), lambda x: x.update(started_unix=float('nan'))]
        for change in changes:
            intent = copy.deepcopy(self.intent)
            change(intent)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                m.validate_intent(intent, self.before_raw, self.pins_before_raw, m.artifact_manifest(self.new_pins))

    def test_manifest_requires_exact_eight_payloads_and_actual_bytes(self):
        m.validate_deployment(self.deployment, self.intent, self.payloads)
        for name in self.payloads:
            changed = dict(self.payloads)
            changed[name] += b'changed'
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                m.validate_deployment(self.deployment, self.intent, changed)
        changed = copy.deepcopy(self.deployment)
        changed['payloads']['unapproved.py'] = {'sha256': 'a' * 64, 'bytes': 1}
        with self.assertRaises(RuntimeError):
            m.validate_deployment(changed, self.intent, self.payloads)

    def test_completion_requires_matching_intent_proof_and_unchanged_identities(self):
        done = self.completion()
        self.assertEqual(m.validate_completed(done, self.intent, self.intent_sha), done['verification'])
        changes = [lambda x: x.update(intent_sha256='0' * 64), lambda x: x.update(pebble_open_performed=True),
                   lambda x: x['verification'].update(path='acceptance/../other'),
                   lambda x: x['verification'].update(semantic_projection_sha256='0' * 64),
                   lambda x: x['after']['reader_process'].update(pid=1),
                   lambda x: x.update(state_replaced_this_run=1)]
        for change in changes:
            changed = copy.deepcopy(done)
            change(changed)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                m.validate_completed(changed, self.intent, self.intent_sha)

    def test_permanent_check_refuses_missing_completion_before_observing(self):
        with patch.object(m, 'observe') as observe, self.assertRaises(FileNotFoundError):
            m.check_completed(self.ctx)
        observe.assert_not_called()

    def test_permanent_check_reconciles_exact_semantics_and_rejects_changed_proof(self):
        done = self.completion()
        with self.fixture_status() as calls, patch.object(m, 'observe', return_value=self.after_guard), \
                patch.object(m, 'exact_module', side_effect=self.imports):
            checked = m.check_completed(self.ctx)
        failure = m.OPS / 'acceptance/000001/failure.json'
        self.assertEqual(calls, [('exists', failure), ('is_symlink', failure)])
        self.assertEqual(checked['completed_sha256'], m.sha(m.canonical(done)))
        path = m.OPS / 'acceptance/000001/result.json'
        result = json.loads(self.files[path])
        result['sst_lineage']['created']['47475312.sst']['version_id'] = 'changed-history'
        self.files[path] = m.canonical(result)
        done['verification']['result_sha256'] = m.sha(self.files[path])
        receipt_path = m.OPS / 'acceptance/000001/completed.json'
        receipt = json.loads(self.files[receipt_path])
        receipt['result_sha256'] = done['verification']['result_sha256']
        self.files[receipt_path] = m.canonical(receipt)
        done['verification']['receipt_sha256'] = m.sha(self.files[receipt_path])
        self.files[m.OPS / 'completed.json'] = m.canonical(done)
        with self.fixture_status() as calls, patch.object(m, 'observe', return_value=self.after_guard), \
                self.assertRaisesRegex(RuntimeError, 'semantic projection'):
            m.check_completed(self.ctx)
        self.assertEqual(calls, [('exists', failure), ('is_symlink', failure)])

    def test_permanent_check_refuses_failure_receipt_or_broken_symlink(self):
        self.completion()
        failure = m.OPS / 'acceptance/000001/failure.json'
        for broken_symlink in (False, True):
            if broken_symlink:
                self.symlinks.add(failure)
            else:
                self.files[failure] = b'{"failed":true}\n'
            with self.subTest(broken_symlink=broken_symlink), self.fixture_status() as calls, \
                    patch.object(m, 'observe', return_value=self.after_guard), \
                    patch.object(m, 'exact_module') as importer, \
                    self.assertRaisesRegex(RuntimeError, 'also has a failure receipt'):
                m.check_completed(self.ctx)
            importer.assert_not_called()
            expected = [('exists', failure)] + ([('is_symlink', failure)] if broken_symlink else [])
            self.assertEqual(calls, expected)
            self.files.pop(failure, None)
            self.symlinks.discard(failure)

    def test_acceptance_receipt_links_lifecycle_sources_and_invocation(self):
        done = self.completion()
        names = ('intent.json', 'completed.json', 'metrics.json', 'result.json')
        blobs = {name: self.files[m.OPS / 'acceptance/000001' / name] for name in names}
        m.validate_acceptance(self.ctx, blobs, self.intent, done, done['verification'])
        mutations = [('completed.json', lambda x: x.update(workers_drained=False)),
                     ('completed.json', lambda x: x.update(sdk_clients_closed=False)),
                     ('completed.json', lambda x: x.update(intent_sha256='0' * 64)),
                     ('intent.json', lambda x: x.update(source_commit='c' * 40)),
                     ('intent.json', lambda x: x.update(state_sha256='0' * 64)),
                     ('metrics.json', lambda x: x.update(attempt=2)),
                     ('result.json', lambda x: x.update(verified_unix=1794000099.0))]
        for name, mutate in mutations:
            changed = dict(blobs)
            value = json.loads(changed[name])
            mutate(value)
            changed[name] = m.canonical(value)
            with self.subTest(name=name, mutate=mutate), self.assertRaises(RuntimeError):
                m.validate_acceptance(self.ctx, changed, self.intent, done, done['verification'])


if __name__ == '__main__':
    unittest.main()
