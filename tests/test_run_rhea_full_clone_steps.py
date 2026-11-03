"""Offline controller, budget, and durable-progress regressions; no live services."""
import copy
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/run_rhea_full_clone_steps.py"
SPEC = importlib.util.spec_from_file_location("full_clone_controller_tests", SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def checkpoint(fmt="003", marks=0):
    return {"bucket": m.BUCKET, "prefix": m.PREFIX, "format_major_version": fmt,
            "marked_files": marks, "sst_count": 93_697, "sst_bytes": 7_786_594_080_785,
            "sst_inventory_sha256": m.BASELINE_DIGEST, "remote_metadata": {},
            "remote_format3_closure_verified": True, "pebble_reopen_verified": True}


def plan():
    return {"input_files": ["000001.sst"], "input_bytes": 100, "input_level": 6, "output_level": 6,
            "plan_sha256": "a" * 64, "candidate_sha256": "c" * 64}


def report(action, before, picked=None):
    after = dict(before)
    if action in m.STAGES:
        after["format"] = m.STAGES[action][1]
    if action == "ratchet10":
        after["marked"] = 1
    result = {"action": action, "compactions": [], "error": "",
              "io": {"sst_write_bytes": 0, "metadata_write_bytes": 32,
                     "max_sst_write_bytes": m.MAX_OUTPUT, "max_metadata_write_bytes": m.MAX_METADATA_WRITES},
              "sst_diff": {"created": [], "retired": [], "created_bytes": 0, "retired_bytes": 0}}
    if action in ("plan", "step"):
        result["picker_plan"] = copy.deepcopy(picked or plan())
    if action == "step":
        after.update(marked=before["marked"] - 1, inventory="b" * 64)
        retired = {"name": "000001.sst", "number": 1, "size": 100, "level": 6}
        created = {"name": "100000000.sst", "number": 100000000, "size": 100, "level": 6}
        result["sst_diff"].update(created=[created], retired=[retired], created_bytes=100, retired_bytes=100)
        result["io"]["sst_write_bytes"] = 100
        result["compactions"] = [{"type": "begin", "reason": "rewrite", "job": 1},
                                 {"type": "end", "reason": "rewrite", "job": 1, "error": "",
                                  "input": [retired], "output": [created]}]
    for side, state in (("before", before), ("after", after)):
        result.update({f"{side}_format": state["format"], f"marked_{side}": state["marked"],
                       f"sst_files_{side}": state["count"], f"sst_bytes_{side}": state["bytes"],
                       f"sst_inventory_sha256_{side}": state["inventory"]})
    return result


def observation():
    return {"pid": 999, "stats": {"diskCache": {"bytesUsed": 0, "uploadsQueued": 0,
             "uploadsInProgress": 0, "erroredFiles": 0, "outOfSpace": False}}, "queue": {"queue": []}}


class ValidationTests(unittest.TestCase):
    def test_wrapper_source_pin_matches_the_reviewed_dependency(self):
        source = SOURCE.with_name("rhea_wasabi_lab_mount.py").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), m.WRAPPER_SHA256)

    def test_metadata_stage_and_single_rewrite_reports(self):
        before = m.checkpoint_state(checkpoint())
        m.validate_result(report("ratchet6", before), "ratchet6", before, None)
        before = m.checkpoint_state(checkpoint("013", 1))
        candidate = m.validate_plan(report("plan", before), before)
        m.validate_result(report("step", before, candidate), "step", before, candidate)

    def test_same_count_size_substitution_in_readonly_plan_is_rejected(self):
        before = m.checkpoint_state(checkpoint("013", 1))
        changed = report("plan", before)
        changed["sst_inventory_sha256_after"] = "d" * 64
        with self.assertRaisesRegex(m.Refusal, "certified checkpoint"):
            m.validate_plan(changed, before)

    def test_oversized_or_ambiguous_picker_units_are_rejected_before_writer(self):
        before = m.checkpoint_state(checkpoint("013", 1))
        for change in ({"input_bytes": m.MAX_INPUT + 1}, {"input_bytes": 0},
                       {"input_files": ["000001.sst", "000001.sst"]},
                       {"input_files": ["../production/000001.sst"]}, {"plan_sha256": "untrusted"}):
            value = report("plan", before)
            value["picker_plan"].update(change)
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                m.validate_plan(value, before)

    def test_writer_changed_plan_extra_compaction_and_output_overflow_are_rejected(self):
        before = m.checkpoint_state(checkpoint("013", 1))
        original = report("step", before)
        variants = []
        value = copy.deepcopy(original); value["picker_plan"]["plan_sha256"] = "d" * 64; variants.append(value)
        value = copy.deepcopy(original); value["compactions"] *= 2; variants.append(value)
        value = copy.deepcopy(original); value["compactions"][-1]["error"] = "write failure"; variants.append(value)
        value = copy.deepcopy(original); value["io"]["sst_write_bytes"] = m.MAX_OUTPUT + 1; variants.append(value)
        value = copy.deepcopy(original); value["io"]["metadata_write_bytes"] = m.MAX_METADATA_WRITES + 1; variants.append(value)
        value = copy.deepcopy(original); value["marked_after"] = value["marked_before"]; variants.append(value)
        value = copy.deepcopy(original); value["blocked_budget_error"] = "free space"; variants.append(value)
        value = copy.deepcopy(original); value["io"]["blocked_budget_error"] = "free space"; variants.append(value)
        value = copy.deepcopy(original); value["sst_diff"]["retired"][0].update(name="000002.sst", number=2); variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(m.Refusal):
                m.validate_result(value, "step", before, plan())

    def test_metadata_stage_must_not_write_ssts_or_compact(self):
        before = m.checkpoint_state(checkpoint())
        for mutate in (lambda value: value["io"].update(sst_write_bytes=1),
                       lambda value: value["compactions"].append({"type": "end", "reason": "rewrite"}),
                       lambda value: value.update(sst_inventory_sha256_after="d" * 64)):
            value = report("ratchet6", before)
            mutate(value)
            with self.assertRaises(m.Refusal):
                m.validate_result(value, "ratchet6", before, None)

    def test_boolean_counts_bad_scope_and_duplicate_json_are_rejected(self):
        for change in ({"marked_files": False}, {"bucket": "ipfs-remote-mount"}, {"prefix": "production/"}):
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                m.checkpoint_state(dict(checkpoint(), **change))
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[]'):
            with self.assertRaises(m.Refusal):
                m.json_object(raw)

    def test_upload_order_is_data_then_manifest_then_format(self):
        names = ["pebbleds/marker.format-version.000003.013", "pebbleds/MANIFEST-000012",
                 "pebbleds/000001.sst", "pebbleds/CURRENT", "pebbleds/000010.log",
                 "pebbleds/OPTIONS-000011", "pebbleds/marker.manifest.000002.MANIFEST-000012"]
        self.assertEqual([m.upload_priority(name) for name in sorted(names, key=m.upload_priority)], list(range(7)))
        for name in ("production/CURRENT", "pebbleds/../CURRENT", "pebbleds/LOCK", "pebbleds/unrecognized"):
            with self.assertRaises(m.Refusal): m.upload_priority(name)


class BudgetTests(unittest.TestCase):
    def test_admission_reserves_input_output_and_metadata_separately(self):
        value = observation()
        m.health(value, m.MIN_FREE + m.RESERVATION, new_work=True)
        with self.assertRaises(m.Refusal): m.health(value, m.MIN_FREE + m.RESERVATION - 1, new_work=True)
        value["stats"]["diskCache"]["bytesUsed"] = m.MAX_CACHE - m.RESERVATION + 1
        with self.assertRaises(m.Refusal): m.health(value, m.MIN_FREE + m.RESERVATION, new_work=True)
        m.health(value, m.MIN_FREE, new_work=False)

    def test_dirty_queue_never_admits_new_work(self):
        value = observation()
        value["stats"]["diskCache"]["uploadsQueued"] = 1
        value["queue"]["queue"] = [{"id": 1, "name": "pebbleds/000001.sst", "size": 100, "uploading": False}]
        with self.assertRaises(m.Refusal): m.health(value, m.MIN_FREE + m.RESERVATION, new_work=True)
        m.health(value, m.MIN_FREE)

    def test_upload_errors_cache_backlog_and_out_of_space_are_hard_gates(self):
        for key, changed in (("erroredFiles", 1), ("outOfSpace", True), ("bytesUsed", m.MAX_CACHE + 1),
                             ("uploadsQueued", m.MAX_BACKLOG_FILES + 1), ("bytesUsed", None)):
            value = observation(); value["stats"]["diskCache"][key] = changed
            with self.subTest(key=key), self.assertRaises(m.Refusal): m.health(value, m.MIN_FREE)
        value = observation()
        value["queue"]["queue"] = [{"id": 1, "name": "pebbleds/000001.sst", "size": m.MAX_BACKLOG_BYTES + 1, "uploading": False}]
        with self.assertRaises(m.Refusal): m.health(value, m.MIN_FREE)


class FakeRuntime:
    def __init__(self, fmt="003", marks=0):
        self.state = {"schema": 1, "binding": {}, "checkpoint": checkpoint(fmt, marks),
                      "generation": 4 if fmt == "013" else 0, "rewrites": 0, "pending": None}
        self.db = m.checkpoint_state(self.state["checkpoint"])
        self.events = []
        self.failure = None
        self.guard_error = None
        self.alive = False
        self.output = None
        self.closed_snapshot = {"CURRENT": b"MANIFEST-000000\n", "marker.format-version.000002.003": b""}

    def lock(self): return nullcontext()
    def load_state(self): return copy.deepcopy(self.state)
    def write_state(self, state):
        self.state = copy.deepcopy(state)
        self.events.append(("journal", None if state["pending"] is None else state["pending"]["phase"]))
    def create_stage(self, pending): self.events.append(("create", pending["action"]))
    def guard(self, **kwargs):
        self.events.append(("guard", kwargs))
        if self.guard_error: raise self.guard_error
    def run_tool(self, action, **kwargs):
        self.events.append(("tool", action))
        if action in m.STAGES:
            assert self.state["pending"]["phase"] == "executing"
            kwargs["launched"]({"pid": 999, "start_ticks": "123", "boot_id": "offline"})
            self.output = report(action, kwargs["expected"], kwargs.get("plan"))
            self.db = m.report_state(self.output, "after")
            if self.failure: raise self.failure
            return copy.deepcopy(self.output)
        return report(action, self.db)
    def writer_alive(self, pending): return self.alive
    def closed_report(self, pending): return copy.deepcopy(self.output)
    def snapshot(self, pending, result): return copy.deepcopy(self.closed_snapshot), {}
    def check_snapshot(self, snapshot): assert snapshot == self.closed_snapshot
    def defer_markers(self, *args): self.events.append(("defer",))
    def drain_data(self, *args): self.events.append(("drain-data",))
    def verify(self, previous, result, snapshot, created, mode):
        self.events.append(("verify", mode))
        state = m.report_state(result, "after")
        return {"bucket": m.BUCKET, "prefix": m.PREFIX, "after_format": state["format"], "marked_after": state["marked"],
                "sst_count": state["count"], "sst_bytes": state["bytes"], "sst_inventory_sha256": state["inventory"],
                "remote_generation_verified": mode == "final", "remote_metadata": {}, "changed_markers": []}
    def publish_markers(self, *args):
        assert self.state["pending"]["before_markers_sha256"] == m.digest(self.state["pending"]["before_markers"])
        self.events.append(("publish",))
    def save_certificate(self, pending, value): self.events.append(("certificate",)); return value


class ControllerTests(unittest.TestCase):
    def test_dry_run_performs_readonly_plan_without_journal_or_writer(self):
        runtime = FakeRuntime()
        result = m.Controller(runtime).run("ratchet6")
        self.assertFalse(result["applied"])
        self.assertEqual([event for event in runtime.events if event[0] == "tool"], [("tool", "inspect")])
        self.assertFalse(any(event[0] in ("journal", "create", "publish") for event in runtime.events))

    def test_intent_and_prepublication_proof_are_durable_before_mutations(self):
        runtime = FakeRuntime()
        result = m.Controller(runtime).run("ratchet6", apply=True)
        self.assertTrue(result["applied"])
        self.assertLess(runtime.events.index(("journal", "executing")), runtime.events.index(("tool", "ratchet6")))
        self.assertLess(runtime.events.index(("journal", "preverified")), runtime.events.index(("publish",)))
        self.assertLess(runtime.events.index(("drain-data",)), runtime.events.index(("verify", "before-markers")))
        self.assertLess(runtime.events.index(("verify", "final")), runtime.events.index(("certificate",)))
        self.assertIsNone(runtime.state["pending"])
        self.assertEqual(runtime.state["generation"], 1)

    def test_exactly_one_step_and_no_format14_action(self):
        runtime = FakeRuntime("013", 1)
        controller = m.Controller(runtime)
        self.assertEqual(controller.run("step", apply=True)["rewrites_completed"], 1)
        for action in ("step", "finish", "ratchet14"):
            with self.subTest(action=action), self.assertRaises(m.Refusal): controller.run(action, apply=True)
        self.assertEqual(sum(event == ("tool", "step") for event in runtime.events), 1)

    def test_dirty_admission_and_out_of_order_stages_never_launch_writer(self):
        runtime = FakeRuntime()
        with self.assertRaises(m.Refusal): m.Controller(runtime).run("ratchet13", apply=True)
        runtime.guard_error = m.Refusal("pending queue")
        with self.assertRaises(m.Refusal): m.Controller(runtime).run("ratchet6", apply=True)
        self.assertFalse(any(event[0] == "tool" for event in runtime.events))
        runtime = FakeRuntime("006", 1)
        with self.assertRaisesRegex(m.Refusal, "unfinished marked-file"):
            m.Controller(runtime).run("ratchet7", apply=True)
        self.assertFalse(any(event[0] == "tool" for event in runtime.events))

    def test_interrupted_closed_writer_recovers_without_repeating_it(self):
        runtime = FakeRuntime()
        runtime.failure = m.Refusal("interrupted parent after closed writer report")
        controller = m.Controller(runtime)
        with self.assertRaises(m.Refusal): controller.run("ratchet6", apply=True)
        self.assertEqual(runtime.state["pending"]["phase"], "executing")
        with self.assertRaisesRegex(m.Refusal, "unfinished stage"): controller.run("ratchet6", apply=True)
        runtime.failure = None
        self.assertTrue(controller.recover(apply=True)["applied"])
        self.assertEqual(sum(event == ("tool", "ratchet6") for event in runtime.events), 1)

    def test_running_writer_or_unmatching_reopen_prevents_recovery(self):
        runtime = FakeRuntime()
        runtime.failure = m.Refusal("interruption")
        controller = m.Controller(runtime)
        with self.assertRaises(m.Refusal): controller.run("ratchet6", apply=True)
        runtime.alive = True
        with self.assertRaisesRegex(m.Refusal, "still running"): controller.recover(apply=True)
        runtime.alive = False
        runtime.db["inventory"] = "d" * 64
        with self.assertRaisesRegex(m.Refusal, "certified checkpoint"): controller.recover(apply=True)
        self.assertFalse(any(event[0] == "publish" for event in runtime.events))

    def test_partial_publication_resumes_durable_proof_not_writer_or_prepass(self):
        runtime = FakeRuntime()
        original = runtime.publish_markers
        runtime.publish_markers = Mock(side_effect=m.Refusal("interrupted marker publication"))
        controller = m.Controller(runtime)
        with self.assertRaises(m.Refusal): controller.run("ratchet6", apply=True)
        self.assertEqual(runtime.state["pending"]["phase"], "publishing")
        runtime.publish_markers = original
        controller.recover(apply=True)
        self.assertEqual(sum(event == ("tool", "ratchet6") for event in runtime.events), 1)
        self.assertEqual(sum(event == ("verify", "before-markers") for event in runtime.events), 1)


class RuntimeTests(unittest.TestCase):
    @contextmanager
    def runtime(self):
        with tempfile.TemporaryDirectory() as location:
            runtime = m.Runtime.__new__(m.Runtime)
            runtime.wrapper = SimpleNamespace(secure_path=Mock(), CLEAN_ENV={"PATH": "/usr/bin"}, Refusal=RuntimeError)
            runtime.host = SimpleNamespace(mkdir_private=lambda path: path.mkdir(mode=0o700, parents=True, exist_ok=True), locked=True)
            runtime.check_tool = Mock()
            runtime._process_identity = Mock(return_value={"pid": 999, "start_ticks": "1", "boot_id": "offline"})
            runtime.observe = Mock(return_value=observation())
            runtime.free_bytes = Mock(return_value=m.MIN_FREE + m.RESERVATION)
            runtime.stop_present = Mock(return_value=False)
            runtime.signal_budget_stop = Mock()
            with patch.object(m, "STATE_ROOT", Path(location) / "state"), patch.object(m, "TRUST", Path(location)):
                yield runtime

    def test_atomic_evidence_is_private_and_syncs_directories(self):
        with self.runtime() as runtime:
            path = m.STATE_ROOT / "state.json"
            with patch.object(runtime, "_sync_dir", wraps=runtime._sync_dir) as sync:
                runtime.atomic_json(path, {"phase": "executing"})
            self.assertEqual(json.loads(path.read_bytes()), {"phase": "executing"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sync.call_count, 2)

    def test_monitor_requests_cooperative_stop_and_waits_without_kill_or_retry(self):
        with self.runtime() as runtime:
            pending = {"index": 1, "action": "ratchet6"}
            runtime.create_stage(pending)
            runtime.observe.return_value["stats"]["diskCache"]["bytesUsed"] = m.MAX_CACHE + 1
            child = Mock(pid=999)
            child.poll.side_effect = [None, None, 0]
            child.wait.return_value = 0
            launched, failed = Mock(), Mock()
            with patch.object(m.subprocess, "Popen", return_value=child) as popen, \
                    patch.object(m.time, "sleep"), patch.object(m.sys, "stderr", Mock()):
                with self.assertRaisesRegex(m.Refusal, "no automatic retry"):
                    runtime.run_tool("ratchet6", expected=m.checkpoint_state(checkpoint()), pending=pending,
                                     launched=launched, monitor_failed=failed)
            popen.assert_called_once()
            child.kill.assert_not_called(); child.terminate.assert_not_called(); child.send_signal.assert_not_called()
            child.wait.assert_called_once()
            runtime.signal_budget_stop.assert_called_once()
            launched.assert_called_once(); failed.assert_called_once()
            receipt = json.loads((runtime.stage_dir(pending) / "process-exit.json").read_bytes())
            self.assertTrue(receipt["monitor_failure"]["sentinel_written"])
            self.assertEqual(receipt["returncode"], 0)

    def test_readonly_open_is_monitored_without_creating_progress_or_repeating_child(self):
        for over_budget in (False, True):
            with self.subTest(over_budget=over_budget), self.runtime() as runtime:
                if over_budget:
                    runtime.observe.return_value["stats"]["diskCache"]["bytesUsed"] = m.MAX_CACHE + 1
                value = report("inspect", m.checkpoint_state(checkpoint()))
                child = Mock(pid=999)
                child.poll.side_effect = [None, 0]
                child.wait.return_value = 0

                def launch(command, **kwargs):
                    self.assertEqual(command, [str(m.TOOL), "inspect"])
                    kwargs["stdout"].write(m.canonical(value))
                    return child

                with patch.object(m.subprocess, "Popen", side_effect=launch) as popen, \
                        patch.object(m.time, "sleep"), patch.object(m.sys, "stderr", Mock()):
                    if over_budget:
                        with self.assertRaisesRegex(m.Refusal, "monitored bounds"):
                            runtime.run_tool("inspect")
                    else:
                        self.assertEqual(runtime.run_tool("inspect"), value)
                popen.assert_called_once()
                child.kill.assert_not_called(); child.terminate.assert_not_called(); child.send_signal.assert_not_called()
                child.wait.assert_called_once()
                self.assertEqual(runtime.signal_budget_stop.call_count, int(over_budget))
                self.assertFalse(m.STATE_ROOT.exists())

    def test_post_spawn_identity_or_journal_failure_stops_and_waits_for_existing_child(self):
        for source in ("identity", "journal"):
            with self.subTest(source=source), self.runtime() as runtime:
                pending = {"index": 1, "action": "ratchet6"}
                runtime.create_stage(pending)
                child = Mock(pid=999)
                child.poll.side_effect = [None, 0]
                child.wait.return_value = 0
                launched = Mock()
                if source == "identity":
                    runtime._process_identity.side_effect = OSError("identity read failed")
                else:
                    launched.side_effect = OSError("journal fsync failed")
                failed = Mock(side_effect=OSError("failure receipt fsync failed"))
                broken_stderr = Mock(write=Mock(side_effect=OSError("stderr unavailable")))
                with patch.object(m.subprocess, "Popen", return_value=child) as popen, \
                        patch.object(m.time, "sleep"), patch.object(m.sys, "stderr", broken_stderr):
                    with self.assertRaisesRegex(m.Refusal, "no automatic retry"):
                        runtime.run_tool("ratchet6", expected=m.checkpoint_state(checkpoint()), pending=pending,
                                         launched=launched, monitor_failed=failed)
                popen.assert_called_once()
                child.kill.assert_not_called(); child.terminate.assert_not_called(); child.send_signal.assert_not_called()
                child.wait.assert_called_once()
                runtime.signal_budget_stop.assert_called_once()
                receipt = json.loads((runtime.stage_dir(pending) / "process-exit.json").read_bytes())
                self.assertTrue(receipt["monitor_failure"]["sentinel_written"])
                self.assertTrue(receipt["monitor_failure"]["monitor_journal_error"])
                self.assertTrue(receipt["monitor_failure"]["diagnostic_error"])
                self.assertEqual(receipt["process"]["pid"], 999)


if __name__ == "__main__":
    unittest.main()
