"""Full-proof parity and failure tests for the opt-in bounded candidate."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
from pathlib import Path
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("bounded_full_clone_candidate_tests", ROOT / "scripts/verify_rhea_full_clone_bounded.py")
fixtures = load("bounded_full_clone_isolated_fixtures", ROOT / "tests/test_verify_rhea_full_clone.py")
legacy = fixtures.m
fixtures.m = m


class CompleteHistoryS3(fixtures.S3):
    """Independent cursor model over complete versions and delete histories."""
    def __init__(self):
        super().__init__()
        self.delete_history = {}
        self.list_calls = []
        self.paginator_calls = 0
        self.page_size = 3
        self.list_lock = threading.Lock()

    def delete(self, key):
        super().delete(key)
        marker = self.deleted[key]
        marker["VersionId"] = "delete-" + str(len(self.delete_history)) + "-" + key
        self.delete_history[key, marker["VersionId"]] = dict(marker)

    def records(self):
        versions = {(key, identifier): dict(row, IsLatest=False)
                    for (key, identifier), (row, _) in self.history.items()}
        # Direct mutations in inherited negative tests model malformed/latest
        # responses; expose them as returned, instead of hiding them in history.
        for key, row in self.latest.items():
            versions[key, row["VersionId"]] = dict(row, IsLatest=True)
        deletes = {identity: dict(row, IsLatest=False)
                   for identity, row in self.delete_history.items()}
        for key, row in self.deleted.items():
            deletes[key, row["VersionId"]] = dict(row, IsLatest=True)
        rows = [(field, copy.deepcopy(row)) for field, values in
                (("Versions", versions), ("DeleteMarkers", deletes)) for row in values.values()]
        for _, row in rows:
            row.setdefault("LastModified", datetime(2026, 11, 5, tzinfo=timezone.utc))
            row.setdefault("Owner", {"ID": "fixture-owner", "DisplayName": "private fixture"})
        return sorted(rows, key=lambda item: (item[1]["Key"].encode("utf-8"),
                                             not item[1]["IsLatest"], item[1]["VersionId"]))

    def get_paginator(self, name):
        self.paginator_calls += 1
        return super().get_paginator(name)

    def paginate(self, **request):
        if request != {"Bucket": m.BUCKET, "Prefix": "rhea/"}:
            raise AssertionError("legacy paginator scope differs")
        rows = self.records()
        yield {field: [row for kind, row in rows if kind == field]
               for field in ("Versions", "DeleteMarkers")}

    def list_object_versions(self, **request):
        if not set(request) <= {"Bucket", "Prefix", "MaxKeys", "KeyMarker", "VersionIdMarker"}:
            raise AssertionError("unexpected listing parameter")
        if (request["Bucket"], request["Prefix"], request["MaxKeys"]) != (m.BUCKET, "rhea/", 1000):
            raise AssertionError("bounded listing scope differs")
        with self.list_lock:
            self.list_calls.append(dict(request))
            rows = self.records()
        key, identifier = request.get("KeyMarker"), request.get("VersionIdMarker")
        start = 0
        if identifier is not None:
            positions = [i for i, (_, row) in enumerate(rows)
                         if (row["Key"], row["VersionId"]) == (key, identifier)]
            if len(positions) != 1:
                raise AssertionError("cursor is not an exact returned identity")
            start = positions[0] + 1
        elif key is not None:
            start = next((i for i, (_, row) in enumerate(rows)
                          if row["Key"].encode("utf-8") > key.encode("utf-8")), len(rows))
        selected = rows[start:start + self.page_size]
        truncated = start + len(selected) < len(rows)
        result = {field: [row for kind, row in selected if kind == field]
                  for field in ("Versions", "DeleteMarkers")}
        result.update(Name=m.BUCKET, Prefix="rhea/", KeyMarker=key or "",
                      VersionIdMarker=identifier or "", MaxKeys=1000,
                      IsTruncated=truncated, EncodingType="url", ResponseMetadata={"RetryAttempts": 0})
        if truncated:
            result["NextKeyMarker"], result["NextVersionIdMarker"] = (
                selected[-1][1]["Key"], selected[-1][1]["VersionId"])
        return result


# This fixture module is a separate import, so the historical tests and their
# original verifier reference remain unchanged in other test modules.
fixtures.S3 = CompleteHistoryS3
fixture_verify = fixtures.StageFixture.verify


def bounded_fixture_verify(self, **kwargs):
    kwargs.setdefault("enumeration_workers", 4)
    return fixture_verify(self, **kwargs)


fixtures.StageFixture.verify = bounded_fixture_verify


class InheritedBoundedProofTests(fixtures.VerificationTests):
    """Run every existing proof regression through the fresh bounded branch."""


def positional_args(fixture):
    return (fixture.s3, fixture.ledger, fixture.previous, fixture.report,
            fixture.metadata, fixture.hashes, fixture.mode, m.canonical_sha256(fixture.previous))


def legacy_verify(fixture):
    with patch.object(legacy.base, "EXPECTED_SSTS", 2), patch.object(legacy.base, "EXPECTED_SST_BYTES", 300), patch.object(
        legacy.base, "EXPECTED_INVENTORY", legacy.base.inventory_digest({1: 100, 2: 200})
    ):
        return legacy.verify_generation(*positional_args(fixture))


class BoundedIntegrationTests(unittest.TestCase):
    def test_exact_historical_certificate_and_live_reads_in_every_mode_and_stage(self):
        for action in m.TRANSITIONS:
            for mode in ("before-markers", "final"):
                with self.subTest(action=action, mode=mode):
                    fixture = fixtures.StageFixture(action, mode)
                    original_collector = legacy._collect_latest
                    with patch.object(m.time, "time", return_value=123456.0):
                        expected = legacy_verify(fixture)
                        gets, heads = list(fixture.s3.gets), list(fixture.s3.heads)
                        for workers in (1, 4):
                            fixture.s3.gets.clear()
                            fixture.s3.heads.clear()
                            metrics = {}
                            result = fixture.verify(enumeration_workers=workers, enumeration_metrics=metrics)
                            self.assertEqual(expected, result)
                            self.assertEqual(gets, fixture.s3.gets)
                            self.assertEqual(heads, fixture.s3.heads)
                            self.assertTrue(metrics["complete"])
                            self.assertGreater(metrics["pages"], 1)
                            self.assertEqual(metrics["range_count"], 1 if workers == 1 else 3)
                            self.assertFalse(set(result) & {"enumeration_metrics", "enumeration_workers", "scanner_sha256"})
                        self.assertEqual(expected, legacy_verify(fixture))
                    self.assertIs(legacy._collect_latest, original_collector)
                    self.assertEqual(2, fixture.s3.paginator_calls)

    def test_default_positional_api_remains_the_original_sdk_path(self):
        fixture = fixtures.StageFixture()
        with patch.object(m.time, "time", return_value=123456.0):
            expected = legacy_verify(fixture)
            actual = fixture.verify(enumeration_workers=None)
        self.assertEqual(expected, actual)
        self.assertEqual([], fixture.s3.list_calls)
        self.assertEqual(2, fixture.s3.paginator_calls)
        with patch.object(m.base, "EXPECTED_SSTS", 2), patch.object(m.base, "EXPECTED_SST_BYTES", 300), patch.object(
            m.base, "EXPECTED_INVENTORY", m.base.inventory_digest({1: 100, 2: 200})
        ):
            self.assertTrue(m.verify_generation(*positional_args(fixture))["remote_generation_verified"])
        self.assertEqual([], fixture.s3.list_calls)

    def test_quartile_keys_are_from_validated_baseline_and_full_prefix_scope(self):
        baseline = {f"{number:06d}.sst": {} for number in (8, 2, 1, 6, 4, 7, 3, 5)}
        self.assertEqual((m.PREFIX + "000003.sst", m.PREFIX + "000005.sst", m.PREFIX + "000007.sst"),
                         m._enumeration_boundaries(baseline, 4))
        self.assertEqual((), m._enumeration_boundaries(baseline, 1))
        fixture = fixtures.StageFixture()
        original = m.enumerator.scan_versions
        with patch.object(m.enumerator, "scan_versions", wraps=original) as observed:
            fixture.verify()
        self.assertEqual(1, observed.call_count)
        arguments = observed.call_args.kwargs
        self.assertEqual(arguments["prefix"], "rhea/")
        self.assertEqual(arguments["boundaries"], (m.PREFIX + "000001.sst", m.PREFIX + "000002.sst"))
        self.assertEqual((arguments["max_pages"], arguments["max_rows"]), (512, 500_000))
        fixture = fixtures.StageFixture()
        fixture.ledger[m.PREFIX + "000001.sst"].size += 1
        with self.assertRaises(m.VerificationError):
            fixture.verify()
        self.assertEqual([], fixture.s3.list_calls)
        self.assertEqual([], fixture.s3.gets)

    def test_both_proof_passes_rescan_and_later_changes_are_not_hidden(self):
        fixture = fixtures.StageFixture(mode="before-markers")
        before_metrics = {}
        before = fixture.verify(enumeration_metrics=before_metrics)
        first_calls = len(fixture.s3.list_calls)
        self.assertEqual(first_calls, before_metrics["requests"])
        self.assertFalse(before["remote_generation_verified"])
        for name in fixture.changed:
            fixture.s3.add(m.PREFIX + name, b"", "published-" + name)
        final_metrics = {}
        final = fixture.verify(mode="final", enumeration_metrics=final_metrics)
        second_calls = len(fixture.s3.list_calls)
        self.assertEqual(second_calls - first_calls, final_metrics["requests"])
        self.assertTrue(final["remote_generation_verified"])
        self.assertIn(fixture.new_manifest_marker, final["remote_metadata"])
        fixture.s3.add(m.PREFIX + "000002.sst", b"b" * 200, "later-untouched-overwrite")
        with self.assertRaisesRegex(m.VerificationError, "untouched SST version changed"):
            fixture.verify(mode="final")
        self.assertGreater(len(fixture.s3.list_calls), second_calls)

    def test_nonlatest_null_and_unknown_history_are_scanned_but_latest_null_is_refused(self):
        fixture = fixtures.StageFixture()
        key = m.PREFIX + "000002.sst"
        row, payload = fixture.s3.history[key, "base-pebbleds/000002.sst"]
        fixture.s3.history[key, "null"] = (dict(row, VersionId="null"), payload)
        obsolete = m.PREFIX + "arbitrary-obsolete-metadata"
        fixture.s3.add(obsolete, b"old", "opaque%2F-history")
        fixture.s3.delete(obsolete)
        metrics = {}
        with patch.object(m.time, "time", return_value=123456.0):
            self.assertEqual(legacy_verify(fixture), fixture.verify(enumeration_metrics=metrics))
        records = fixture.s3.records()
        self.assertEqual(metrics["retained_versions"], sum(field == "Versions" for field, _ in records))
        self.assertEqual(metrics["retained_delete_markers"], sum(field == "DeleteMarkers" for field, _ in records))
        for delete in (False, True):
            fixture = fixtures.StageFixture()
            if delete:
                fixture.s3.deleted[m.PREFIX + "000001.sst"]["VersionId"] = "null"
            else:
                fixture.s3.latest[key] = dict(fixture.s3.latest[key], VersionId="null")
            with self.subTest(delete=delete), self.assertRaisesRegex(m.VerificationError, "missing latest VersionId"):
                fixture.verify()

    def test_malformed_history_and_unknown_latest_keys_produce_no_certificate(self):
        for change in ("history-size", "unknown-array", "unknown-latest"):
            fixture = fixtures.StageFixture()
            metrics = {}
            if change == "history-size":
                key = m.PREFIX + "000002.sst"
                row, payload = fixture.s3.history[key, "base-pebbleds/000002.sst"]
                fixture.s3.history[key, "malformed-old"] = (dict(row, VersionId="malformed-old", Size=True), payload)
            elif change == "unknown-array":
                original = fixture.s3.list_object_versions
                fixture.s3.list_object_versions = lambda **kwargs: dict(original(**kwargs), FutureVersions=[])
            else:
                fixture.s3.add(m.PREFIX + "unknown-latest-object", b"extra", "unknown-v1")
            with self.subTest(change=change), self.assertRaises((m.VerificationError, m.enumerator.ScanRefusal)):
                fixture.verify(enumeration_metrics=metrics)
            if change != "unknown-latest":
                self.assertEqual({}, metrics)

    def test_invalid_controls_and_pre_cancel_refuse_before_any_read(self):
        options = [{"enumeration_workers": value} for value in (True, False, 0, 2, 3, 5, "4")]
        options += [{"enumeration_metrics": {"used": True}}, {"enumeration_metrics": []},
                    {"enumeration_workers": None, "enumeration_metrics": {}},
                    {"enumeration_stop": object()}]
        stop = threading.Event()
        stop.set()
        options.append({"enumeration_stop": stop})
        for controls in options:
            fixture = fixtures.StageFixture()
            with self.subTest(controls=controls), self.assertRaises(m.VerificationError):
                fixture.verify(**controls)
            self.assertEqual([], fixture.s3.gets)
            self.assertEqual([], fixture.s3.heads)
            self.assertEqual([], fixture.s3.list_calls)
            self.assertEqual(0, fixture.s3.paginator_calls)

    def test_scanner_pin_checks_exact_bytes_before_execution(self):
        with patch.object(m.Path, "open", return_value=io.BytesIO(b"raise AssertionError('must not execute')\n")):
            with self.assertRaisesRegex(m.VerificationError, "source hash mismatch"):
                m._load_enumerator()
        raw = (ROOT / "scripts/enumerate_rhea_versions.py").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), m.SCANNER_SHA256)
        self.assertEqual(hashlib.sha256((ROOT / "scripts/verify_rhea_full_clone.py").read_bytes()).hexdigest(),
                         "e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849")

    def test_worker_exception_drains_sibling_before_failure_without_downstream_proof(self):
        fixture = fixtures.StageFixture()
        sibling_started, failure_started = threading.Event(), threading.Event()
        release, finished = threading.Event(), threading.Event()
        failure = RuntimeError("controlled worker failure")
        errors, outcomes, metrics = [], [], {}
        original = fixture.s3.list_object_versions

        def listing(**request):
            if "KeyMarker" not in request:
                if not sibling_started.wait(3):
                    raise AssertionError("sibling was not started")
                failure_started.set()
                raise failure
            if request.get("KeyMarker") == m.PREFIX + "000001.sst" and "VersionIdMarker" not in request:
                sibling_started.set()
                if not release.wait(3):
                    raise AssertionError("controlled sibling not released")
            return original(**request)

        fixture.s3.list_object_versions = listing

        def invoke():
            try:
                outcomes.append(fixture.verify(enumeration_metrics=metrics))
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=invoke)
        thread.start()
        try:
            self.assertTrue(failure_started.wait(2))
            self.assertFalse(finished.wait(0.03))
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([failure], errors)
        self.assertEqual([], outcomes)
        self.assertEqual({}, metrics)
        self.assertEqual([], fixture.s3.heads)
        self.assertEqual([(m.PREFIX + fixture.old_manifest, "old-" + fixture.old_manifest)], fixture.s3.gets)

    def test_cancellation_during_scan_joins_and_never_returns_a_certificate(self):
        fixture = fixtures.StageFixture()
        entered, release, stop, finished = (threading.Event() for _ in range(4))
        errors, outcomes = [], []
        original = fixture.s3.list_object_versions

        def listing(**request):
            entered.set()
            if not release.wait(3):
                raise AssertionError("controlled call not released")
            return original(**request)

        fixture.s3.list_object_versions = listing

        def invoke():
            try:
                outcomes.append(fixture.verify(enumeration_workers=1, enumeration_stop=stop))
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=invoke)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            stop.set()
            self.assertFalse(finished.wait(0.03))
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], outcomes)
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], m.enumerator.ScanCancelled)
        self.assertEqual([], fixture.s3.heads)


if __name__ == "__main__":
    unittest.main()
