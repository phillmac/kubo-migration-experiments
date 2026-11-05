"""Pure serial-reference and captured-list replay checks; no host/cloud calls."""
import copy
import datetime
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("version_enumeration_runner_tests", ROOT / "scripts/run_rhea_version_enumeration_profile.py")
BUCKET = "fixed-test-bucket"
PREFIX = "rhea/"
WHEN = datetime.datetime(2026, 11, 5, 1, 2, 3, 456789, tzinfo=datetime.timezone.utc)


def version(key="rhea/a%2Fb.sst", identifier="opaque+/%version", *, latest=True):
    return {"Key": key, "VersionId": identifier, "IsLatest": latest, "Size": 17,
            "ETag": '"etag"', "LastModified": WHEN, "StorageClass": "STANDARD",
            "Owner": {"ID": "test-owner", "DisplayName": "test display"}}


def deleted(key="rhea/retired.sst", identifier="delete-version", *, latest=True):
    return {"Key": key, "VersionId": identifier, "IsLatest": latest, "LastModified": WHEN}


def page(versions=(), deletes=(), *, truncated=False, retries=0, **extra):
    result = {"Name": BUCKET, "Prefix": PREFIX, "IsTruncated": truncated,
              "Versions": list(versions), "DeleteMarkers": list(deletes)}
    if retries is not None:
        result["ResponseMetadata"] = {"RetryAttempts": retries}
    result.update(extra)
    return result


def snapshot(versions=(), deletes=()):
    return {kind: {(row["Key"], row["VersionId"]): copy.deepcopy(row) for row in rows}
            for kind, rows in (("Versions", versions), ("DeleteMarkers", deletes))}


class ReferenceS3:
    """An independent paginator; direct low-level listing is intentionally absent."""
    def __init__(self, pages, on_response=None):
        self.pages = list(pages)
        self.on_response = on_response
        self.operations = []
        self.scopes = []
        self.responses = 0
        self.advances = 0

    def get_paginator(self, operation):
        self.operations.append(operation)
        return self

    def paginate(self, **kwargs):
        self.scopes.append(kwargs)
        return self

    def __iter__(self):
        return self

    def __next__(self):
        self.advances += 1
        if not self.pages:
            raise StopIteration
        value = self.pages.pop(0)
        if isinstance(value, BaseException):
            raise value
        self.responses += 1
        if self.on_response is not None:
            self.on_response()
        return value


class SerialReferenceTests(unittest.TestCase):
    def scan(self, s3, stop=None, metrics=None):
        return m.serial_snapshot(s3, bucket=BUCKET, prefix=PREFIX,
                                 stop=stop if stop is not None else m.Cancellation(),
                                 metrics=metrics if metrics is not None else {})

    def test_sdk_oracle_preserves_all_rows_and_fields_across_empty_and_history_pages(self):
        current = version()
        historical = version(identifier="null", latest=False)
        unicode_row = version("rhea/é雪.sst", "unicode-version")
        marker = deleted()
        old_marker = deleted(identifier="older-delete", latest=False)
        source = [page([current, historical], truncated=True, retries=2),
                  page(truncated=True, retries=None),
                  page([unicode_row], [marker, old_marker])]
        unchanged = copy.deepcopy(source)
        s3, metrics = ReferenceS3(source), {}
        result = self.scan(s3, metrics=metrics)
        self.assertEqual(result, snapshot([current, historical, unicode_row], [marker, old_marker]))
        self.assertEqual(source, unchanged)
        self.assertEqual(s3.operations, ["list_object_versions"])
        self.assertEqual(s3.scopes, [{"Bucket": BUCKET, "Prefix": PREFIX}])
        self.assertEqual((s3.responses, s3.advances), (3, 4))
        self.assertEqual((metrics["pages"], metrics["rows_received"], metrics["version_rows"],
                          metrics["delete_rows"]), (3, 5, 3, 2))
        self.assertEqual((metrics["retry_metadata_present"], metrics["retry_metadata_missing"],
                          metrics["sdk_retries"], metrics["max_sdk_retries"]), (2, 1, 2, 2))
        self.assertTrue(metrics["exhausted"])
        self.assertIn(("rhea/a%2Fb.sst", "null"), result["Versions"])
        self.assertEqual(m.snapshot_counts(result), {"versions": 3, "delete_markers": 2,
                         "latest_versions": 2, "latest_delete_markers": 1})

    def test_empty_terminal_page_is_a_complete_reference(self):
        metrics = {}
        self.assertEqual(self.scan(ReferenceS3([page()]), metrics=metrics), snapshot())
        self.assertTrue(metrics["exhausted"])

    def test_page_limit_refuses_before_another_remote_response(self):
        s3, metrics = ReferenceS3([page(truncated=True), page()]), {}
        with patch.object(m, "MAX_PAGES", 1), self.assertRaisesRegex(RuntimeError, "page budget"):
            self.scan(s3, metrics=metrics)
        self.assertEqual((s3.responses, s3.advances, metrics["pages"]), (1, 1, 1))
        self.assertFalse(metrics["exhausted"])

    def test_terminal_page_at_the_page_limit_still_exhausts(self):
        s3, metrics = ReferenceS3([page()]), {}
        with patch.object(m, "MAX_PAGES", 1):
            self.assertEqual(self.scan(s3, metrics=metrics), snapshot())
        self.assertEqual((s3.responses, s3.advances), (1, 2))
        self.assertTrue(metrics["exhausted"])

    def test_row_limit_aborts_without_following_another_page(self):
        s3 = ReferenceS3([page([version(), version(identifier="old", latest=False)], truncated=True), page()])
        with patch.object(m, "MAX_ROWS", 1), self.assertRaisesRegex(RuntimeError, "row budget"):
            self.scan(s3)
        self.assertEqual(s3.responses, 1)

    def test_rejects_scope_grouping_and_malformed_page_types(self):
        cases = [dict(Name="another-bucket"), dict(Prefix="elsewhere/"),
                 dict(IsTruncated=1), dict(IsTruncated=None), dict(Delimiter="/"),
                 dict(CommonPrefixes=[{"Prefix": "rhea/group/"}]),
                 dict(Versions=()), dict(DeleteMarkers=None)]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.scan(ReferenceS3([page(**change)]))

    def test_rejects_missing_early_or_extra_terminal_pages(self):
        for pages in ([], [page(truncated=True)], [page(), page()]):
            with self.subTest(pages=pages), self.assertRaises(RuntimeError):
                self.scan(ReferenceS3(pages))

    def test_rejects_invalid_record_identity_types(self):
        changes = [{"Key": "outside/a"}, {"Key": None}, {"VersionId": ""},
                   {"VersionId": 1}, {"IsLatest": 1}, {"IsLatest": None}]
        for change in changes:
            row = dict(version(), **change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.scan(ReferenceS3([page([row])]))

    def test_duplicate_identity_is_rejected_across_pages_and_record_kinds(self):
        row = version()
        cases = [[page([row], truncated=True), page([dict(row)])],
                 [page([row], [deleted(row["Key"], row["VersionId"])])]]
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaisesRegex(RuntimeError, "duplicate"):
                self.scan(ReferenceS3(pages))

    def test_late_sdk_failure_is_propagated_with_partial_metrics(self):
        error = OSError("synthetic SDK failure")
        s3, metrics = ReferenceS3([page([version()], truncated=True), error]), {}
        with self.assertRaises(OSError) as raised:
            self.scan(s3, metrics=metrics)
        self.assertIs(raised.exception, error)
        self.assertEqual((metrics["pages"], metrics["rows_received"]), (1, 1))
        self.assertFalse(metrics["exhausted"])
        self.assertGreaterEqual(metrics["wall_seconds"], metrics["iterator_seconds"])

    def test_missing_or_malformed_retry_metadata_is_not_reported_as_zero_observed_retries(self):
        for value in (None, True, -1, "0"):
            metrics = {}
            with self.subTest(value=value):
                self.scan(ReferenceS3([page(retries=value)]), metrics=metrics)
                self.assertEqual(metrics["retry_metadata_present"], 0)
                self.assertEqual(metrics["retry_metadata_missing"], 1)

    def test_cancellation_before_setup_makes_no_sdk_call(self):
        stop, s3 = m.Cancellation(), ReferenceS3([page()])
        stop.set()
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.scan(s3, stop=stop)
        self.assertEqual(s3.operations, [])
        self.assertEqual(s3.advances, 0)

    def test_cancellation_during_response_stops_before_processing_or_next_call(self):
        stop, metrics = m.Cancellation(), {}
        s3 = ReferenceS3([page([version()], truncated=True), page()], on_response=stop.set)
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.scan(s3, stop=stop, metrics=metrics)
        self.assertEqual((s3.responses, s3.advances), (1, 1))
        self.assertEqual(metrics["rows_received"], 0)
        self.assertFalse(metrics["exhausted"])


class SnapshotDigestTests(unittest.TestCase):
    def test_order_independence_and_equivalent_aware_timezones(self):
        source = snapshot([version(), version("rhea/z", "second")], [deleted()])
        changed = copy.deepcopy(source)
        changed["Versions"] = dict(reversed(list(changed["Versions"].items())))
        for rows in changed.values():
            for identity, row in list(rows.items()):
                row = dict(reversed(list(row.items())))
                row["LastModified"] = row["LastModified"].astimezone(
                    datetime.timezone(datetime.timedelta(hours=11)))
                rows[identity] = row
        self.assertEqual(m.snapshot_digest(source), m.snapshot_digest(changed))

    def test_full_record_fields_and_json_types_change_the_digest(self):
        original = version()
        original["Extra"] = {"nested": [None, True, 1, "1"]}
        source = snapshot([original], [deleted()])
        baseline = m.snapshot_digest(source)
        changes = [("Owner", {"ID": "other-owner", "DisplayName": "test display"}),
                   ("StorageClass", "GLACIER"), ("ETag", '"other"'),
                   ("LastModified", WHEN + datetime.timedelta(microseconds=1)),
                   ("IsLatest", 1), ("Size", True), ("Extra", {"nested": [None, True, "1", "1"]})]
        for name, value in changes:
            changed = copy.deepcopy(source)
            changed["Versions"][(original["Key"], original["VersionId"])][name] = value
            with self.subTest(field=name):
                self.assertNotEqual(m.snapshot_digest(changed), baseline)
        changed = copy.deepcopy(source)
        next(iter(changed["DeleteMarkers"].values()))["IsLatest"] = False
        self.assertNotEqual(m.snapshot_digest(changed), baseline)

    def test_rejects_unsupported_types_naive_timestamps_and_identity_disagreement(self):
        row = version()
        for value in (WHEN.replace(tzinfo=None), 1.5, b"bytes", (1,), {1: "nonstring-key"}):
            changed = snapshot([dict(row, Extra=value)])
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                m.snapshot_digest(changed)
        invalid = snapshot([row])
        invalid["Versions"][(row["Key"], row["VersionId"])]["VersionId"] = "substituted"
        with self.assertRaisesRegex(RuntimeError, "identity"):
            m.snapshot_digest(invalid)
        for invalid in ({}, {"Versions": [], "DeleteMarkers": {}}, dict(snapshot(), extra={})):
            with self.subTest(snapshot=invalid), self.assertRaises(RuntimeError):
                m.snapshot_digest(invalid)


class ReadBackend:
    def __init__(self):
        self.calls = []
        self.response = {"opaque-response": object()}

    def get_object(self, **kwargs):
        self.calls.append(("get_object", kwargs))
        return self.response

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        return self.response


class SnapshotAdapterTests(unittest.TestCase):
    def setUp(self):
        self.backend, self.stop = ReadBackend(), m.Cancellation()
        self.snapshot = snapshot([version(), version(identifier="null", latest=False)], [deleted()])
        self.client = m.SnapshotClient(self.backend, self.snapshot, BUCKET, PREFIX, self.stop)

    def test_one_captured_listing_preserves_history_without_sdk_metadata_or_remote_calls(self):
        original = copy.deepcopy(self.snapshot)
        paginator = self.client.get_paginator("list_object_versions")
        pages = list(paginator.paginate(Bucket=BUCKET, Prefix=PREFIX))
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0], {"Versions": list(original["Versions"].values()),
                                   "DeleteMarkers": list(original["DeleteMarkers"].values())})
        self.assertNotIn("ResponseMetadata", pages[0])
        self.assertEqual(self.snapshot, original)
        self.assertEqual(self.backend.calls, [])
        with self.assertRaises(RuntimeError):
            self.client.get_paginator("list_object_versions")
        with self.assertRaises(RuntimeError):
            list(paginator.paginate(Bucket=BUCKET, Prefix=PREFIX))

    def test_only_exact_snapshot_paginator_scope_is_accepted(self):
        for name in ("list_objects_v2", "delete_objects", None):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.client.get_paginator(name)
        for kwargs in ({"Bucket": "other", "Prefix": PREFIX}, {"Bucket": BUCKET, "Prefix": "other/"},
                       {"Bucket": BUCKET}, {"Bucket": BUCKET, "Prefix": PREFIX, "MaxKeys": 1}):
            paginator = m.SnapshotPaginator(self.snapshot, BUCKET, PREFIX)
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                list(paginator.paginate(**kwargs))

    def test_get_head_preserve_exact_arguments_and_original_return_value(self):
        get = {"Bucket": BUCKET, "Key": "rhea/a%2Fb.sst", "VersionId": "null"}
        head = {"Bucket": BUCKET, "Key": "rhea/a%2Fb.sst"}
        self.assertIs(self.client.get_object(**get), self.backend.response)
        self.assertIs(self.client.head_object(**head), self.backend.response)
        self.assertEqual(self.backend.calls, [("get_object", get), ("head_object", head)])

    def test_rejects_remote_scope_type_and_parameter_changes_before_dispatch(self):
        valid = {"Bucket": BUCKET, "Key": "rhea/key", "VersionId": "version"}
        variants = [dict(valid, Bucket="other"), dict(valid, Key="other/key"), dict(valid, Key=None),
                    dict(valid, Range="bytes=0-1"), dict(valid, RequestPayer="requester")]
        variants.extend(dict(valid, VersionId=value) for value in (None, "", 1, True, [], b"version"))
        for method in (self.client.get_object, self.client.head_object):
            for kwargs in variants:
                with self.subTest(method=method.__name__, kwargs=kwargs), self.assertRaises(RuntimeError):
                    method(**kwargs)
        self.assertEqual(self.backend.calls, [])

    def test_unknown_mutating_and_client_lifecycle_apis_are_denied(self):
        for name in ("put_object", "delete_object", "delete_objects", "create_multipart_upload",
                     "copy_object", "list_object_versions", "close"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                getattr(self.client, name)
        self.assertEqual(self.backend.calls, [])

    def test_latched_cancel_prevents_each_subsequent_remote_read(self):
        kwargs = {"Bucket": BUCKET, "Key": "rhea/key"}
        self.client.head_object(**kwargs)
        self.stop.set()
        self.stop.set()
        self.assertTrue(self.stop.is_set())
        for method in (self.client.get_object, self.client.head_object):
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                method(**kwargs)
        self.assertEqual(self.backend.calls, [("head_object", kwargs)])

    def test_actual_verifier_keeps_exact_result_and_live_get_head_sequence(self):
        fixtures = load("enumeration_snapshot_verifier_fixture", ROOT / "tests/test_verify_rhea_full_clone.py")
        fixture, verifier = fixtures.StageFixture(), fixtures.m
        with patch.object(verifier.time, "time", return_value=123456.0):
            expected = fixture.verify()
            gets, heads = list(fixture.s3.gets), list(fixture.s3.heads)
            fixture.s3.gets.clear()
            fixture.s3.heads.clear()
            rows = []
            for (key, identifier), (row, unused_payload) in fixture.s3.history.items():
                latest = fixture.s3.latest.get(key, {}).get("VersionId") == identifier
                rows.append(dict(row, IsLatest=latest))
            captured = snapshot(rows, fixture.s3.deleted.values())
            before = m.snapshot_digest(captured)
            adapter = m.SnapshotClient(fixture.s3, captured, verifier.BUCKET, PREFIX)
            with patch.object(fixture.s3, "get_paginator", side_effect=AssertionError("unexpected remote enumeration")):
                actual = fixture.verify(s3=adapter)
        self.assertEqual(actual, expected)
        self.assertEqual(fixture.s3.gets, gets)
        self.assertEqual(fixture.s3.heads, heads)
        self.assertEqual(m.snapshot_digest(captured), before)

    def test_closed_diagnostic_output_does_not_raise(self):
        with patch("builtins.print", side_effect=BrokenPipeError("closed diagnostic pipe")):
            self.assertIsNone(m.emit({"phase_completed": "fixture"}))


if __name__ == "__main__":
    unittest.main()
