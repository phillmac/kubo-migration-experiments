import copy
import importlib.util
from pathlib import Path
import unittest


def module(name, filename):
    path = Path(__file__).resolve().parents[1] / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


controller = module("failed_recovery_controller_test", "run_rhea_full_clone_steps.py")
recovery = module("failed_recovery_driver_test", "reconcile_rhea_failed_step.py")


class FailedCloseJournalTests(unittest.TestCase):
    def setUp(self):
        expected = recovery.EXPECTED_STATE
        self.previous = {"after_format": expected["format"], "marked_after": expected["marked"],
            "sst_count": expected["count"], "sst_bytes": expected["bytes"],
            "sst_inventory_sha256": expected["inventory"], "generation": 4}
        self.report = {"action": "step", "error": recovery.EXPECTED_ERROR, "picker_plan": {"input_files": ["46893047.sst"]},
            "io": {"sst_write_bytes": 0}, "sst_diff": {"created": [], "retired": [], "created_bytes": 0,
                "retired_bytes": 0, "created_count": 0, "retired_count": 0}}
        for side in ("before", "after"):
            self.report.update({side + "_format": expected["format"], "marked_" + side: expected["marked"],
                "sst_files_" + side: expected["count"], "sst_bytes_" + side: expected["bytes"],
                "sst_inventory_sha256_" + side: expected["inventory"]})
        self.exit = {"returncode": 1, "monitor_failure": None, "budget_stop_present": False,
            "process": {"pid": 2741005, "start_ticks": "6366522138", "boot_id": "test-boot"}}
        self.state = {"schema": 1, "binding": {"go_sha256": recovery.OLD_GO_SHA256},
            "generation": 4, "rewrites": 0, "checkpoint": self.previous,
            "pending": {"index": 5, "action": "step", "phase": "executing",
                "previous_checkpoint_sha256": controller.digest(self.previous),
                "picker_plan": self.report["picker_plan"], "process": self.exit["process"]}}
        self.capture = {"pending": copy.deepcopy(self.state["pending"])}
        inspection = copy.deepcopy(self.report)
        inspection.update(action="inspect", compactions=[])
        inspection.pop("error")
        self.bridge = dict(self.previous, action="reconcile-failed-step-close",
            scope="fixed-disposable-full-clone-failed-step-close", recovery_index=1, failed_attempts=1,
            remote_generation_verified=True, pebble_reopen_verified=True, reopen=inspection,
            previous_checkpoint_sha256=controller.digest(self.previous), sst_lineage={"rewrite_operations": 0},
            failed_attempt={"writer_sha256": recovery.PINS["writer.json"], "state_sha256": recovery.PINS["state.json"],
                "process_exit_sha256": recovery.PINS["process-exit.json"], "capture_sha256": recovery.PINS["capture.json"],
                "archive_path": str(recovery.ARCHIVE.relative_to(recovery.TRUST))})

    def validate(self):
        recovery.validate_captured(controller, self.state, self.previous, self.report, self.exit, self.capture)

    def test_preserves_actual_failed_report_and_pending_capture(self):
        original = copy.deepcopy((self.state, self.report, self.exit, self.capture))
        self.validate()
        self.assertEqual((self.state, self.report, self.exit, self.capture), original)
        self.assertEqual(self.report["error"], recovery.EXPECTED_ERROR)
        self.assertEqual(self.exit["returncode"], 1)

    def test_refuses_success_or_different_failure_and_any_sst_write(self):
        for field, value in (("error", ""), ("error", "another error")):
            with self.subTest(value=value):
                original = self.report[field]
                self.report[field] = value
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.report[field] = original
        self.report["io"]["sst_write_bytes"] = 1
        with self.assertRaises(RuntimeError):
            self.validate()

    def test_refuses_changed_inventory_or_changed_pending_process(self):
        self.report["sst_inventory_sha256_after"] = "0" * 64
        with self.assertRaises(RuntimeError):
            self.validate()
        self.report["sst_inventory_sha256_after"] = recovery.EXPECTED_STATE["inventory"]
        self.capture["pending"]["process"]["pid"] += 1
        with self.assertRaises(RuntimeError):
            self.validate()

    def test_commit_changes_only_checkpoint_and_pending_with_failure_provenance(self):
        original = copy.deepcopy(self.state)
        updated = recovery.reconciled_state(controller, self.state, self.bridge)
        self.assertEqual(self.state, original)
        self.assertEqual({key for key in updated if updated[key] != original[key]}, {"checkpoint", "pending"})
        self.assertEqual(updated["generation"], 4)
        self.assertEqual(updated["rewrites"], 0)
        self.assertIsNone(updated["pending"])
        self.assertEqual(updated["checkpoint"]["failed_attempt"]["writer_sha256"], recovery.PINS["writer.json"])

    def test_no_commit_without_final_remote_reopen_and_exact_failed_attempt_hashes(self):
        for key in ("remote_generation_verified", "pebble_reopen_verified"):
            bad = copy.deepcopy(self.bridge)
            bad[key] = False
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                recovery.reconciled_state(controller, self.state, bad)
        for key in ("writer_sha256", "state_sha256", "process_exit_sha256", "capture_sha256"):
            bad = copy.deepcopy(self.bridge)
            bad["failed_attempt"][key] = "0" * 64
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                recovery.reconciled_state(controller, self.state, bad)

    def test_no_commit_if_reopen_differs_or_bridge_claims_successful_rewrite(self):
        bad = copy.deepcopy(self.bridge)
        bad["reopen"]["marked_after"] -= 1
        with self.assertRaises(controller.Refusal):
            recovery.reconciled_state(controller, self.state, bad)
        bad = copy.deepcopy(self.bridge)
        bad["sst_lineage"]["rewrite_operations"] = 1
        with self.assertRaises(RuntimeError):
            recovery.reconciled_state(controller, self.state, bad)


if __name__ == "__main__":
    unittest.main()
