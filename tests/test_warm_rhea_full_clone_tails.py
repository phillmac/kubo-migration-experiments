"""Offline scheduling regressions; no host, FUSE, RC, or cloud operations."""
import copy
from concurrent.futures import Future
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = load("warm_tail_test_subject", "scripts/warm_rhea_full_clone_tails.py")
controller = load("warm_tail_test_controller", "scripts/run_rhea_full_clone_steps.py")


def rows(count):
    return [{"name": f"{number:06d}.sst", "number": number, "size": w.TAIL_BYTES + number,
             "level": number % 7, "requested_bytes": w.TAIL_BYTES} for number in range(1, count + 1)]


class ReadFuture(Future):
    def __init__(self):
        super().__init__()
        self.cancellations = 0

    def cancel(self):
        self.cancellations += 1
        return super().cancel()


class Harness:
    """Complete actual Future objects on a virtual clock, retaining pending I/O."""
    def __init__(self, *, delay=0.01, free_fails_at=None, read_failure=None, slow_rc_at=None):
        self.now = 0.0
        self.delay = delay
        self.free_fails_at = free_fails_at
        self.read_failure = read_failure
        self.slow_rc_at = slow_rc_at
        self.active = {}
        self.futures = []
        self.submissions = []
        self.observations = []
        self.free_checks = []
        self.rc_while_active = False
        self.maximum_active = 0
        self.closed = False
        self.receipt = {
            "mode": "full", "monitor": {"samples": 0}, "pilot_results": [], "read_failures": [],
            "progress": {"scheduled_files": 0, "scheduled_bytes": 0, "completed_files": 0, "read_bytes": 0,
                         "failed_files": 0, "sum_read_seconds": 0, "maximum_read_seconds": 0,
                         "stopped_scheduling": False},
        }
        self.runtime = SimpleNamespace(observe=self.observe, free_bytes=self.free_bytes, atomic_json=Mock(),
                                       wrapper=SimpleNamespace(Refusal=RuntimeError, clean_queue=Mock()),
                                       verifier=SimpleNamespace(VerificationError=RuntimeError))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        assert not self.active, "existing read futures were not drained"
        self.closed = True

    def submit(self, function, directory_fd, row):
        assert function is w.read_tail and directory_fd == -1
        future = ReadFuture()
        delay = self.delay(row) if callable(self.delay) else self.delay
        self.active[future] = (self.now + delay, row, delay)
        self.futures.append(future)
        self.submissions.append((self.now, row["name"], row["requested_bytes"]))
        self.maximum_active = max(self.maximum_active, len(self.active))
        return future

    def wait(self, pending, *, timeout, return_when):
        assert pending and timeout <= 0.5 and set(pending) == set(self.active)
        earliest = min(self.active[future][0] for future in pending)
        self.now = min(self.now + timeout, earliest)
        done = {future for future in pending if self.active[future][0] <= self.now}
        for future in done:
            _, row, delay = self.active.pop(future)
            if row["number"] == self.read_failure:
                future.set_exception(w.Refusal("injected tail read failure"))
            else:
                future.set_result({"name": row["name"], "level": row["level"], "seconds": delay,
                                   "requested_bytes": row["requested_bytes"], "read_bytes": row["requested_bytes"]})
        return done, set(pending) - done

    def observe(self):
        if self.active:
            self.rc_while_active = True
            raise AssertionError("RC was requested with FUSE reads outstanding")
        if self.slow_rc_at == len(self.observations):
            self.now += w.MAX_UNOBSERVED_SECONDS + 1
        self.observations.append((self.now, self.receipt["progress"]["scheduled_files"],
                                  self.receipt["progress"]["scheduled_bytes"]))
        return {"pid": 999, "stats": {"diskCache": {"bytesUsed": 0, "erroredFiles": 0, "outOfSpace": False,
                                                    "uploadsQueued": 0, "uploadsInProgress": 0}},
                "queue": {"queue": []}}

    def free_bytes(self):
        self.free_checks.append(self.now)
        return controller.MIN_FREE + w.HEADROOM + (
            -1 if self.free_fails_at is not None and self.now >= self.free_fails_at else 1024**3)

    def run(self, count):
        with patch.object(w, "ThreadPoolExecutor", return_value=self) as executor, \
                patch.object(w, "wait", side_effect=self.wait), \
                patch.object(w.time, "monotonic", side_effect=lambda: self.now), \
                patch.object(w.time, "time", side_effect=lambda: 1_800_000_000 + self.now):
            failure = w.warm_selected(controller, self.runtime, rows(count), self.receipt, Path("/unused"), -1)
        executor.assert_called_once_with(max_workers=8, thread_name_prefix="rhea-tail")
        assert self.closed and not self.active
        assert not any(future.cancellations for future in self.futures), "read cancellation was attempted"
        return failure


class WarmupWindowTests(unittest.TestCase):
    def test_controller_source_pin_matches_the_reviewed_dependency(self):
        source = (ROOT / "scripts/run_rhea_full_clone_steps.py").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), w.CONTROLLER_SHA256)

    def test_fast_reads_are_bounded_to_128_files_and_eight_mib_per_observation(self):
        harness = Harness()
        self.assertIsNone(harness.run(300))
        self.assertEqual([sample[1] for sample in harness.observations], [0, 128, 256, 300])
        for before, after in zip(harness.observations, harness.observations[1:]):
            self.assertLessEqual(after[1] - before[1], 128)
            self.assertLessEqual(after[2] - before[2], 8 * 1024**2)
        self.assertEqual(harness.maximum_active, 8)
        self.assertFalse(harness.rc_while_active)
        self.assertEqual(harness.receipt["progress"]["read_bytes"], 300 * w.TAIL_BYTES)

    def test_five_second_submission_window_drains_before_authenticated_rc(self):
        harness = Harness(delay=6)
        self.assertIsNone(harness.run(24))
        self.assertEqual([sample[:2] for sample in harness.observations], [(0, 0), (6, 8), (12, 16), (18, 24)])
        self.assertEqual({submission[0] for submission in harness.submissions}, {0, 6, 12})
        self.assertFalse(harness.rc_while_active)
        self.assertGreaterEqual(harness.receipt["monitor"]["maximum_drain_seconds"], 1)
        self.assertTrue(all(any(abs(t - check) < 0.001 for check in harness.free_checks) for t in range(1, 18)))

    def test_slow_directory_drain_retains_independent_free_checks_and_latches_failure(self):
        harness = Harness(delay=55, free_fails_at=7)
        self.assertIn("8 GiB beyond", harness.run(300))
        self.assertEqual(len(harness.submissions), 8)
        self.assertEqual(harness.observations, [(0, 0, 0)])
        self.assertEqual(harness.now, 55)
        self.assertEqual(harness.receipt["progress"]["completed_files"], 8)
        self.assertTrue(harness.receipt["progress"]["stopped_scheduling"])
        self.assertTrue(all(any(abs(t - check) < 0.001 for check in harness.free_checks) for t in range(1, 55)))
        self.assertFalse(harness.rc_while_active)

    def test_stale_health_stops_admission_but_waits_for_uncancellable_read_completion(self):
        harness = Harness(delay=130)
        self.assertIn("120 seconds", harness.run(300))
        self.assertEqual(len(harness.submissions), 8)
        self.assertEqual(harness.now, 130)
        self.assertEqual(len(harness.observations), 1)
        self.assertEqual(harness.receipt["monitor"]["maximum_observation_gap_seconds"], 130)
        self.assertTrue(harness.receipt["progress"]["stopped_scheduling"])

    def test_read_error_never_admits_another_window_or_retries_the_read(self):
        harness = Harness(delay=lambda row: 0 if row["number"] == 1 else 2, read_failure=1)
        self.assertEqual(harness.run(300), "injected tail read failure")
        self.assertEqual(len(harness.submissions), 8)
        self.assertEqual(len({row[1] for row in harness.submissions}), 8)
        self.assertEqual(harness.receipt["progress"]["failed_files"], 1)
        self.assertEqual(harness.receipt["progress"]["completed_files"], 7)
        self.assertEqual(len(harness.observations), 1)
        self.assertFalse(harness.rc_while_active)

    def test_late_rc_success_cannot_clear_the_observation_age_failure(self):
        harness = Harness(slow_rc_at=1)
        self.assertIn("120 seconds", harness.run(300))
        self.assertEqual(len(harness.submissions), 128)
        self.assertEqual(len(harness.observations), 2)
        self.assertFalse(harness.rc_while_active)
        self.assertTrue(harness.receipt["progress"]["stopped_scheduling"])

    def test_sample_remains_deterministic_and_clips_small_files(self):
        tables = {row["name"]: {key: value for key, value in dict(row, marked=False).items()
                               if key not in ("name", "requested_bytes")} for row in rows(1000)}
        selected = w.select_tables(tables)
        self.assertEqual(len(selected), 128)
        self.assertEqual({row["level"] for row in selected}, set(range(7)))
        self.assertEqual(selected, w.select_tables(dict(reversed(list(tables.items())))))
        small = {"000001.sst": {"number": 1, "size": 17, "level": 0, "marked": False}}
        self.assertEqual(w.select_tables(small)[0]["requested_bytes"], 17)
        marked = copy.deepcopy(small)
        marked["000001.sst"]["marked"] = True
        with self.assertRaises(w.Refusal):
            w.select_tables(marked)


if __name__ == "__main__":
    unittest.main()
