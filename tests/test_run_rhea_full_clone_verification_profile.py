"""Pure replay-certificate comparison regressions; no host or cloud calls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/run_rhea_full_clone_verification_profile.py"
SPEC = importlib.util.spec_from_file_location("full_clone_replay_tests", SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
CERTIFICATE = ROOT / "docs/evidence/rhea-full-clone-000009-step-20261104.json"
CERTIFICATE_SHA = "220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


CODEC = SimpleNamespace(
    canonical=canonical,
    digest=lambda value: hashlib.sha256(canonical(value)).hexdigest(),
)


class ReplayEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = CERTIFICATE.read_bytes()
        if hashlib.sha256(raw).hexdigest() != CERTIFICATE_SHA:
            raise AssertionError("published generation-nine fixture changed")
        cls.certificate = json.loads(raw)

    def setUp(self):
        self.expected = copy.deepcopy(self.certificate)
        self.result = copy.deepcopy(self.expected)
        for name in ("generation", "reopen", "reopen_scope"):
            self.result.pop(name)
        self.result["pebble_reopen_verified"] = False
        self.started, self.finished = 1000.0, 1001.0
        self.result["verified_unix"] = 1000.5

    def compare(self, result=None):
        return m.equivalent(
            CODEC, self.expected, self.result if result is None else result,
            self.started, self.finished,
        )

    def test_accepts_exact_replay_projection_without_mutating_inputs(self):
        before = copy.deepcopy(self.result)
        self.assertIsNone(self.compare())
        self.assertEqual(self.expected, self.certificate)
        self.assertEqual(self.result, before)

    def test_rejects_invalid_verification_time(self):
        for value in (999.0, 1002.0, True, float("nan"), float("inf"), "1000.5"):
            with self.subTest(value=value):
                result = copy.deepcopy(self.result)
                result["verified_unix"] = value
                with self.assertRaises(RuntimeError):
                    self.compare(result)

    def test_rejects_reopen_claim_or_non_boolean_false(self):
        for value in (True, 0, None):
            with self.subTest(value=value):
                result = copy.deepcopy(self.result)
                result["pebble_reopen_verified"] = value
                with self.assertRaises(RuntimeError):
                    self.compare(result)

    def test_rejects_extra_fields_including_controller_only_fields(self):
        for name, value in (("extra", True), ("generation", 9),
                            ("reopen", {}), ("reopen_scope", "historical")):
            with self.subTest(field=name):
                result = copy.deepcopy(self.result)
                result[name] = value
                with self.assertRaises(RuntimeError):
                    self.compare(result)

    def test_rejects_missing_fields(self):
        for name in ("verified_unix", "latest_delete_markers"):
            with self.subTest(field=name):
                result = copy.deepcopy(self.result)
                result.pop(name)
                with self.assertRaises(RuntimeError):
                    self.compare(result)

    def test_rejects_changed_latest_delete_count(self):
        self.result["latest_delete_markers"] += 1
        with self.assertRaises(RuntimeError):
            self.compare()

    def test_rejects_changed_surviving_earlier_output_pin(self):
        changes = {"version_id": "substituted-version", "etag": '"substituted-etag"',
                   "size": 67_057_186, "sha256": "0" * 64}
        for field, value in changes.items():
            with self.subTest(field=field):
                result = copy.deepcopy(self.result)
                result["sst_lineage"]["created"]["47475312.sst"][field] = value
                with self.assertRaises(RuntimeError):
                    self.compare(result)

    def test_private_deadline_bypasses_exception_catch_and_runs_cleanup(self):
        observed = []
        with self.assertRaises(m.ProbeDeadline):
            try:
                try:
                    raise m.ProbeDeadline("expired")
                except Exception:
                    observed.append("ordinary-exception-handler")
            finally:
                observed.append("cleanup")
        self.assertEqual(observed, ["cleanup"])


if __name__ == "__main__":
    unittest.main()
