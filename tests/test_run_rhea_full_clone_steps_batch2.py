"""Offline second-window policy, proof ordering, and diagnostic timing checks."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/run_rhea_full_clone_steps_batch2.py"
PREVIOUS_SOURCE = SOURCE.with_name("run_rhea_full_clone_steps_bounded.py")
PREVIOUS_SHA = "56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a"
STATE_SHA = "22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2"
CERT_SHA = "220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# All fixture modules are private copies; original discovery keeps its globals.
fixtures = load("batch2_legacy_fixtures", Path(__file__).with_name("test_run_rhea_full_clone_steps.py"))
wiring = load("batch2_bounded_fixtures", Path(__file__).with_name("test_run_rhea_full_clone_steps_bounded.py"))
old_fixtures = load("batch2_predecessor_fixtures", Path(__file__).with_name("test_run_rhea_full_clone_steps.py"))
previous = load("batch2_predecessor", PREVIOUS_SOURCE)
m = load("batch2_controller", SOURCE)
fixtures.m, fixtures.SOURCE = m, SOURCE
wiring.m, wiring.SOURCE = m, SOURCE
old_fixtures.m, old_fixtures.SOURCE = previous, PREVIOUS_SOURCE


def original_state():
    raw = (ROOT / "docs/evidence/rhea-bounded-adoption-state-after-20261106.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == STATE_SHA
    return m.json_object(raw)


def candidate_state():
    state = original_state()
    state["binding"]["controller_sha256"] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    state["binding"]["limits"]["maximum_rewrites"] = m.MAX_REWRITES
    return state


def runtime_at_anchor():
    runtime = fixtures.FakeRuntime()
    runtime.state = candidate_state()
    runtime.binding = copy.deepcopy(runtime.state["binding"])
    runtime.db = m.checkpoint_state(runtime.state["checkpoint"])
    runtime.certificates[9] = copy.deepcopy(runtime.state["checkpoint"])
    return runtime


def changed_paths(left, right, path=()):
    if isinstance(left, dict) and isinstance(right, dict) and left.keys() == right.keys():
        return set().union(*(changed_paths(left[k], right[k], path + (k,)) for k in left))
    return set() if left == right and type(left) is type(right) else {path}


class ValidationTests(fixtures.ValidationTests):
    pass


class BudgetTests(fixtures.BudgetTests):
    pass


class ControllerSafetyTests(unittest.TestCase):
    test_dry_run_performs_readonly_plan_without_journal_or_writer = fixtures.ControllerTests.test_dry_run_performs_readonly_plan_without_journal_or_writer
    test_intent_and_prepublication_proof_are_durable_before_mutations = fixtures.ControllerTests.test_intent_and_prepublication_proof_are_durable_before_mutations
    test_dirty_admission_and_out_of_order_stages_never_launch_writer = fixtures.ControllerTests.test_dirty_admission_and_out_of_order_stages_never_launch_writer
    test_running_writer_or_unmatching_reopen_prevents_recovery = fixtures.ControllerTests.test_running_writer_or_unmatching_reopen_prevents_recovery


class RuntimeSafetyTests(unittest.TestCase):
    runtime = fixtures.RuntimeTests.runtime
    test_real_historical_certificates_and_failed_close_bridge_remain_valid = fixtures.RuntimeTests.test_real_historical_certificates_and_failed_close_bridge_remain_valid
    test_progress_lineage_checkpoint_and_expected_binding_mismatches_fail = fixtures.RuntimeTests.test_progress_lineage_checkpoint_and_expected_binding_mismatches_fail
    test_atomic_evidence_is_private_and_syncs_directories = fixtures.RuntimeTests.test_atomic_evidence_is_private_and_syncs_directories
    test_monitor_requests_cooperative_stop_and_waits_without_kill_or_retry = fixtures.RuntimeTests.test_monitor_requests_cooperative_stop_and_waits_without_kill_or_retry
    test_readonly_open_is_monitored_without_creating_progress_or_repeating_child = fixtures.RuntimeTests.test_readonly_open_is_monitored_without_creating_progress_or_repeating_child
    test_post_spawn_identity_or_journal_failure_stops_and_waits_for_existing_child = fixtures.RuntimeTests.test_post_spawn_identity_or_journal_failure_stops_and_waits_for_existing_child


class BoundedWiringTests(wiring.BoundedWiringTests):
    def test_fixed_sources_paths_and_limits_preserve_historical_controller(self):
        self.assertEqual(hashlib.sha256(PREVIOUS_SOURCE.read_bytes()).hexdigest(), PREVIOUS_SHA)
        self.assertEqual(m.PINS, m.TRUST / "full-clone-batch2-step-pins.json")
        self.assertNotEqual(m.PINS, previous.PINS)
        self.assertEqual((m.MAX_REWRITES, m.MAX_GENERATION), (9, 13))
        for name in ("STAGES", "PHASES", "STATE_ROOT", "SEED", "SEED_SHA256", "TOOL", "STOP_FILE", "DB",
                     "BUCKET", "PREFIX", "WRAPPER", "WRAPPER_SHA256", "VERIFIER", "VERIFIER_SHA256",
                     "SCANNER", "SCANNER_SHA256", "DECODER", "DECODER_SHA256", "RESERVATION"):
            with self.subTest(name=name):
                self.assertEqual(getattr(m, name), getattr(previous, name))
        self.assertEqual(changed_paths(previous.LIMITS, m.LIMITS), {("maximum_rewrites",)})
        for path, expected in ((m.VERIFIER, m.VERIFIER_SHA256), (m.SCANNER, m.SCANNER_SHA256),
                               (m.DECODER, m.DECODER_SHA256), (m.WRAPPER, m.WRAPPER_SHA256)):
            self.assertEqual(hashlib.sha256(SOURCE.with_name(path.name).read_bytes()).hexdigest(), expected)

    def test_adopted_state_changes_only_two_bindings_and_old_load_refuses_it(self):
        before, after = original_state(), candidate_state()
        with self.installation() as env:
            runtime = m.Runtime()
            self.assertEqual(runtime.binding, after["binding"])
            runtime.validate_state(after)
            old_runtime = previous.Runtime.__new__(previous.Runtime)
            old_runtime.binding = before["binding"]
            old_runtime.validate_state(before)
            self.assertEqual(changed_paths(before, after), {
                ("binding", "controller_sha256"), ("binding", "limits", "maximum_rewrites")})
            self.assertEqual(m.digest(before["checkpoint"]), CERT_SHA)
            self.assertEqual(m.canonical(before["checkpoint"]), m.canonical(after["checkpoint"]))
            old_pins = m.json_object((ROOT / "docs/evidence/rhea-bounded-adoption-pins-after-20261106.json").read_bytes())
            self.assertEqual(changed_paths(old_pins, env.pins), {("controller_sha256",)})
            with self.assertRaisesRegex(m.Refusal, "journal binding mismatch"):
                runtime.validate_state(before)
            with self.assertRaisesRegex(previous.Refusal, "journal binding mismatch"):
                old_runtime.validate_state(after)
            for change in (lambda s: s["binding"]["limits"].update(input_bytes=m.MAX_INPUT + 1),
                           lambda s: s["binding"].update(verifier_sha256="0" * 64),
                           lambda s: s.update(generation=10),
                           lambda s: s["checkpoint"]["sst_lineage"].update(rewrite_operations=6)):
                changed = copy.deepcopy(after)
                change(changed)
                with self.subTest(state=changed), self.assertRaises(m.Refusal):
                    runtime.validate_state(changed)


class BatchPolicyTests(unittest.TestCase):
    def test_four_separate_units_preserve_anchor_and_stop_after_each_certificate(self):
        runtime = runtime_at_anchor()
        anchor = copy.deepcopy(runtime.state["checkpoint"])
        controller = m.Controller(runtime)
        for generation in range(10, 14):
            parent = copy.deepcopy(runtime.state["checkpoint"])
            result = controller.run("step", apply=True)
            completed = generation - 9
            self.assertEqual(runtime.state["generation"], generation)
            self.assertEqual(runtime.state["rewrites"], generation - 4)
            self.assertIsNone(runtime.state["pending"])
            self.assertEqual(result["checkpoint"]["previous_checkpoint_sha256"], m.digest(parent))
            self.assertEqual(result["checkpoint"]["sst_lineage"]["rewrite_operations"], generation - 4)
            self.assertEqual(set(runtime.certificates), set(range(9, generation + 1)))
            self.assertEqual(sum(event == ("tool", "step") for event in runtime.events), completed)
            self.assertEqual(sum(event == ("verify", "before-markers") for event in runtime.events), completed)
            self.assertEqual(sum(event == ("verify", "final") for event in runtime.events), completed)
            self.assertEqual(runtime.certificates[9], anchor)
            # Generation 10 has returned without creating/admitting generation 11.
            if generation == 10:
                self.assertEqual(set(runtime.certificates), {9, 10})
                self.assertEqual(result["rewrites_completed"], 6)
        events = copy.deepcopy(runtime.events)
        for apply in (False, True):
            with self.subTest(apply=apply), self.assertRaisesRegex(m.Refusal, "limit has already been reached"):
                controller.run("step", apply=apply)
        for forbidden in ("finish", "ratchet14"):
            with self.subTest(action=forbidden), self.assertRaises(m.Refusal):
                controller.run(forbidden, apply=True)
        self.assertEqual(runtime.events, events)

    def test_stage_directories_extend_only_through_thirteen_without_writer_replay(self):
        fixture = RuntimeSafetyTests()
        with fixture.runtime() as runtime:
            old_path = m.STATE_ROOT / "checkpoints/000009-step.json"
            old_path.parent.mkdir(mode=0o700, parents=True)
            raw = m.canonical(original_state()["checkpoint"])
            old_path.write_bytes(raw)
            for generation in range(10, 14):
                pending = {"index": generation, "action": "step"}
                self.assertEqual(runtime.stage_dir(pending).name, f"{generation:06d}-step")
                runtime.create_stage(pending)
                with self.assertRaisesRegex(m.Refusal, "refuse writer replay"):
                    runtime.create_stage(pending)
            for pending in ({"index": 14, "action": "step"}, {"index": 10, "action": "ratchet13"},
                            {"index": True, "action": "step"}):
                with self.subTest(pending=pending), self.assertRaises(m.Refusal):
                    runtime.stage_dir(pending)
            self.assertEqual(old_path.read_bytes(), raw)

    def test_failed_first_new_writer_blocks_new_work_and_recovery_does_not_repeat_it(self):
        runtime = runtime_at_anchor()
        controller = m.Controller(runtime)
        failure = m.Refusal("fixture interruption after a closed writer")
        runtime.failure = failure
        with self.assertRaises(m.Refusal) as raised:
            controller.run("step", apply=True)
        self.assertIs(raised.exception, failure)
        self.assertEqual((runtime.state["generation"], runtime.state["rewrites"]), (9, 5))
        self.assertEqual(runtime.state["pending"]["index"], 10)
        with self.assertRaisesRegex(m.Refusal, "unfinished stage"):
            controller.run("step", apply=True)
        runtime.failure = None
        check = controller.recover()
        self.assertFalse(check["writer_will_be_repeated"])
        self.assertEqual([row["phase"] for row in check["phase_timings"]["phases"]], ["recovery_reopen"])
        result = controller.recover(apply=True)
        self.assertEqual((runtime.state["generation"], result["rewrites_completed"]), (10, 6))
        self.assertEqual(sum(event == ("tool", "step") for event in runtime.events), 1)
        self.assertNotIn("writer", [row["phase"] for row in result["phase_timings"]["phases"]])


class TimingTests(unittest.TestCase):
    def test_timing_addition_preserves_exact_result_checkpoint_journal_and_call_order(self):
        old_runtime = old_fixtures.FakeRuntime("013", 2)
        new_runtime = fixtures.FakeRuntime("013", 2)
        old_result = previous.Controller(old_runtime).run("step", apply=True)
        result = m.Controller(new_runtime).run("step", apply=True)
        timing = result.pop("phase_timings")
        self.assertEqual(result, old_result)
        self.assertEqual(new_runtime.state, old_runtime.state)
        self.assertEqual(new_runtime.certificates, old_runtime.certificates)
        self.assertEqual(new_runtime.events, old_runtime.events)
        self.assertEqual([row["phase"] for row in timing["phases"]], [
            "plan", "writer", "snapshot", "defer_markers", "drain_data",
            "verify_before_markers", "publish_markers", "verify_final", "reopen"])
        self.assertEqual(timing["schema"], 1)
        self.assertEqual(timing["scope"], "full-clone-batch2-invocation")
        self.assertTrue(all(row["seconds"] >= 0 for row in timing["phases"]))
        self.assertGreaterEqual(timing["elapsed_seconds"], sum(row["seconds"] for row in timing["phases"]))
        self.assertGreaterEqual(timing["finished_unix"], timing["started_unix"])

    def test_dry_run_has_only_planning_timing_and_no_state_or_stage_write(self):
        runtime = runtime_at_anchor()
        before = copy.deepcopy(runtime.state)
        result = m.Controller(runtime).run("step")
        self.assertFalse(result["applied"])
        self.assertEqual([row["phase"] for row in result["phase_timings"]["phases"]], ["plan"])
        self.assertEqual(runtime.state, before)
        self.assertFalse(any(event[0] in ("journal", "create", "publish", "certificate") for event in runtime.events))

    def test_partial_publication_recovery_times_only_new_work_not_retained_preproof(self):
        runtime = runtime_at_anchor()
        controller = m.Controller(runtime)
        publish = runtime.publish_markers
        runtime.publish_markers = Mock(side_effect=m.Refusal("fixture publication interruption"))
        with self.assertRaises(m.Refusal):
            controller.run("step", apply=True)
        before = copy.deepcopy(runtime.state["pending"]["before_markers"])
        runtime.publish_markers = publish
        result = controller.recover(apply=True)
        self.assertEqual([row["phase"] for row in result["phase_timings"]["phases"]],
                         ["recovery_reopen", "snapshot", "publish_markers", "verify_final", "reopen"])
        self.assertEqual(sum(event == ("tool", "step") for event in runtime.events), 1)
        self.assertEqual(sum(event == ("verify", "before-markers") for event in runtime.events), 1)
        self.assertEqual(result["checkpoint"]["previous_checkpoint_sha256"], CERT_SHA)
        self.assertEqual(before["sst_lineage"]["rewrite_operations"], 6)

    def test_monotonic_durations_and_original_exception_propagation(self):
        failure = RuntimeError("fixture error")
        function = Mock(side_effect=failure)
        with patch.object(m.time, "time", side_effect=[100.0, 90.0]), \
                patch.object(m.time, "monotonic", side_effect=[1.0, 2.0, 5.0, 7.0]):
            timing = m.PhaseTimings()
            with self.assertRaises(RuntimeError) as raised:
                timing.call("verify_final", function)
            self.assertIs(raised.exception, failure)
            recorded = timing.attach({})["phase_timings"]
        function.assert_called_once_with()
        self.assertEqual(recorded["elapsed_seconds"], 6.0)
        self.assertEqual(recorded["phases"], [{"phase": "verify_final", "seconds": 3.0}])
        self.assertEqual(recorded["finished_unix"], 90.0)


if __name__ == "__main__":
    unittest.main()
