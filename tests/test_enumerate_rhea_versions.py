"""Pure, independently paginated fixtures for bounded version enumeration."""
import copy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import threading
import unittest


SPEC = importlib.util.spec_from_file_location(
    "enumerate_rhea_versions", Path(__file__).resolve().parents[1] / "scripts" / "enumerate_rhea_versions.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


def version(key, identifier="v1", *, latest=True, delete=False):
    row = {"Key": key, "VersionId": identifier, "IsLatest": latest,
           "LastModified": datetime(2026, 11, 5, tzinfo=timezone.utc),
           "Owner": {"ID": "opaque-owner", "DisplayName": "private-owner"}}
    if not delete:
        row.update(Size=17, ETag='"opaque-etag"', StorageClass="STANDARD",
                   ChecksumAlgorithm=["CRC32C"])
    return ("DeleteMarkers" if delete else "Versions"), row


def expected(records):
    result = {"Versions": {}, "DeleteMarkers": {}}
    for field, row in records:
        result[field][(row["Key"], row["VersionId"])] = copy.deepcopy(row)
    return result


class ListingClient:
    """Independent resume-after model; version order is supplied, never sorted."""
    def __init__(self, records, page_size=3, retries=0):
        self.records = sorted(copy.deepcopy(records), key=lambda item: item[1]["Key"].encode("utf-8"))
        self.page_size, self.retries = page_size, retries
        self.calls, self.lock = [], threading.Lock()

    def list_object_versions(self, **request):
        with self.lock:
            self.calls.append(copy.deepcopy(request))
        if not set(request).issubset({"Bucket", "Prefix", "MaxKeys", "KeyMarker", "VersionIdMarker"}):
            raise AssertionError("unexpected request option")
        if request["MaxKeys"] != 1000:
            raise AssertionError("unexpected requested page size")
        records = [item for item in self.records if item[1]["Key"].startswith(request["Prefix"])]
        key, identifier = request.get("KeyMarker"), request.get("VersionIdMarker")
        start = 0
        if identifier is not None:
            matches = [index for index, (_, row) in enumerate(records)
                       if row["Key"] == key and row["VersionId"] == identifier]
            if len(matches) != 1:
                raise AssertionError("unknown paired cursor")
            start = matches[0] + 1
        elif key is not None:
            start = next((index for index, (_, row) in enumerate(records)
                          if row["Key"].encode("utf-8") > key.encode("utf-8")), len(records))
        selected = records[start:start + self.page_size]
        truncated = start + len(selected) < len(records)
        page = {
            "Name": request["Bucket"], "Prefix": request["Prefix"], "MaxKeys": 1000,
            "KeyMarker": key or "", "VersionIdMarker": identifier or "",
            "EncodingType": "url", "IsTruncated": truncated,
            "ResponseMetadata": {"RetryAttempts": self.retries, "RequestId": "private-request-id"},
            "Versions": [], "DeleteMarkers": [],
        }
        for field, row in selected:
            page[field].append(copy.deepcopy(row))
        if truncated:
            page["NextKeyMarker"] = selected[-1][1]["Key"]
            page["NextVersionIdMarker"] = selected[-1][1]["VersionId"]
        return page


class ScriptedClient:
    def __init__(self, pages):
        self.pages, self.calls = list(pages), []

    def list_object_versions(self, **request):
        self.calls.append(request)
        item = self.pages.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def page(rows=(), *, truncated=False, next_key=None, next_version=None):
    result = {"Versions": [], "DeleteMarkers": [], "IsTruncated": truncated}
    for field, row in rows:
        result[field].append(copy.deepcopy(row))
    if next_key is not None:
        result["NextKeyMarker"] = next_key
    if next_version is not None:
        result["NextVersionIdMarker"] = next_version
    return result


def run(client, **kwargs):
    return scan.scan_versions(client, bucket="private-bucket", prefix="rhea/", **kwargs)


class EnumerationTests(unittest.TestCase):
    def test_full_histories_serial_and_concurrent_exact_raw_union(self):
        records = [version("rhea/a", "v6"),
                   version("rhea/a", "v5", latest=False, delete=True),
                   version("rhea/a", "v4", latest=False),
                   version("rhea/a", "v3", latest=False),
                   version("rhea/a", "v2", latest=False),
                   version("rhea/a", "v1", latest=False, delete=True),
                   version("rhea/b", "null", delete=True),
                   version("rhea/b", "older", latest=False),
                   version("rhea/c", "arbitrary-order-Z"),
                   version("rhea/c", "arbitrary-order-a", latest=False),
                   version("rhea/unexpected-metadata", "opaque")]
        serial_client = ListingClient(records, page_size=4)
        serial, serial_metrics = run(serial_client)
        parallel_client = ListingClient(records, page_size=4)
        parallel, parallel_metrics = run(
            parallel_client, boundaries=("rhea/a", "rhea/b", "rhea/c"), workers=4)
        self.assertEqual(expected(records), serial)
        self.assertEqual(serial, parallel)
        self.assertEqual(3, serial_metrics["pages"])
        self.assertEqual(4, parallel_metrics["range_count"])
        self.assertEqual(4, parallel_metrics["workers"])
        self.assertGreater(parallel_metrics["discarded_rows"], 0)
        self.assertEqual(len(records), parallel_metrics["retained_versions"]
                         + parallel_metrics["retained_delete_markers"])
        # The first range's last page contains >upper Versions and <=upper
        # DeleteMarkers. Its old delete marker must survive the split arrays.
        self.assertIn(("rhea/a", "v1"), parallel["DeleteMarkers"])
        for boundary in ("rhea/a", "rhea/b", "rhea/c"):
            self.assertIn({"Bucket": "private-bucket", "Prefix": "rhea/", "MaxKeys": 1000,
                           "KeyMarker": boundary}, parallel_client.calls)

    def test_absent_boundaries_and_empty_ranges_are_complete(self):
        records = [version("rhea/a"), version("rhea/c"), version("rhea/z")]
        for workers in (1, 4):
            with self.subTest(workers=workers):
                result, metrics = run(ListingClient(records, page_size=1),
                                      boundaries=("rhea/0", "rhea/b", "rhea/zz"), workers=workers)
                self.assertEqual(expected(records), result)
                self.assertEqual(4, metrics["range_count"])
                self.assertEqual("exhausted", metrics["ranges"][-1]["termination"])

    def test_empty_listing_has_one_complete_page(self):
        result, metrics = run(ListingClient([]))
        self.assertEqual({"Versions": {}, "DeleteMarkers": {}}, result)
        self.assertEqual(1, metrics["pages"])
        self.assertEqual(0, metrics["version_rows"])

    def test_unicode_percent_sequences_and_null_version_are_not_transformed(self):
        keys = ["rhea/a spaced", "rhea/a%20literal", "rhea/e\u0301", "rhea/é", "rhea/\U00010000"]
        records = [version(key, "null") for key in keys]
        records.insert(2, version("rhea/a%20literal", "%2Fopaque+", latest=False))
        client = ListingClient(records, page_size=1)
        result, _ = run(client, boundaries=("rhea/a%20literal", "rhea/é"), workers=3)
        self.assertEqual(expected(records), result)
        self.assertTrue(any(call.get("VersionIdMarker") == "null" for call in client.calls))
        self.assertTrue(any(call.get("VersionIdMarker") == "%2Fopaque+" for call in client.calls))
        self.assertFalse(any("EncodingType" in call for call in client.calls))

    def test_raw_optional_fields_are_deep_copied(self):
        original = page([version("rhea/a")])
        result, _ = run(ScriptedClient([original]))
        row = result["Versions"][("rhea/a", "v1")]
        self.assertEqual(original["Versions"][0], row)
        self.assertIsNot(original["Versions"][0], row)
        row["Owner"]["ID"] = "changed"
        row["ChecksumAlgorithm"].append("extra")
        self.assertEqual("opaque-owner", original["Versions"][0]["Owner"]["ID"])
        self.assertEqual(["CRC32C"], original["Versions"][0]["ChecksumAlgorithm"])

    def test_nonmember_continuation_is_forwarded_exactly(self):
        client = ScriptedClient([
            page([version("rhea/a")], truncated=True,
                 next_key="rhea/b", next_version="opaque-not-in-rows%2F"),
            page([version("rhea/c")]),
        ])
        result, _ = run(client)
        self.assertEqual(expected([version("rhea/a"), version("rhea/c")]), result)
        self.assertEqual("rhea/b", client.calls[1]["KeyMarker"])
        self.assertEqual("opaque-not-in-rows%2F", client.calls[1]["VersionIdMarker"])

    def test_retry_metrics_and_sanitized_fixed_schema(self):
        records = [version("rhea/private-key-a"), version("rhea/private-key-b")]
        _, metrics = run(ListingClient(records, page_size=1, retries=2))
        self.assertEqual(2, metrics["responses_with_retry_metadata"])
        self.assertEqual(4, metrics["reported_retry_attempts"])
        self.assertEqual(2, metrics["max_reported_retry_attempts"])
        self.assertEqual(2, metrics["requests"])
        text = repr(metrics)
        for forbidden in ("private-key", "private-bucket", "private-owner", "opaque", "rhea/", "private-request"):
            self.assertNotIn(forbidden, text)
        for field in ("wall_seconds", "cpu_seconds", "api_wall_seconds"):
            self.assertGreaterEqual(metrics[field], 0)
        _, missing = run(ScriptedClient([page([version("rhea/a")])]))
        self.assertEqual(0, missing["responses_with_retry_metadata"])

    def test_malformed_pages_and_rows_fail_closed(self):
        base = page([version("rhea/a")])
        cases = []
        for field, value in (("IsTruncated", 0), ("Versions", ()), ("DeleteMarkers", {}),
                             ("FutureObjectRecords", []), ("MaxKeys", True),
                             ("Prefix", "other/"), ("Name", "wrong-bucket"),
                             ("CommonPrefixes", [{"Prefix": "rhea/"}]),
                             ("Delimiter", "/"), ("EncodingType", "unknown"),
                             ("ResponseMetadata", []), ("KeyMarker", "unexpected")):
            candidate = copy.deepcopy(base)
            candidate[field] = value
            cases.append(candidate)
        for field, value in (("Key", "outside/a"), ("Key", "rhea/\ud800"),
                             ("VersionId", ""), ("VersionId", None), ("IsLatest", 1),
                             ("Size", True), ("Size", -1), ("ETag", "")):
            candidate = copy.deepcopy(base)
            candidate["Versions"][0][field] = value
            cases.append(candidate)
        cases.extend([
            page([version("rhea/b"), version("rhea/a")]),
            page([version("rhea/a"), version("rhea/a")]),
            page([version("rhea/a"), version("rhea/a", delete=True)]),
            page([version("rhea/a", latest=False)]),
            page([version("rhea/a"), version("rhea/a", "v2", delete=True)]),
            page(truncated=True, next_key="rhea/a", next_version="v1"),
        ])
        for index, candidate in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(scan.ScanRefusal):
                    run(ScriptedClient([candidate]))

    def test_truncated_markers_missing_empty_or_backward_are_refused(self):
        for key, identifier in ((None, "v1"), ("", "v1"), ("rhea/a", None),
                                ("rhea/a", ""), ("rhea/0", "v1"), ("outside/x", "v1")):
            with self.subTest(key=key, identifier=identifier):
                with self.assertRaises(scan.ScanRefusal):
                    run(ScriptedClient([page([version("rhea/a")], truncated=True,
                                            next_key=key, next_version=identifier)]))

    def test_stalled_cycle_and_backward_page_are_refused(self):
        cases = [
            [page([version("rhea/a")], truncated=True, next_key="rhea/a", next_version="cursor"),
             page([version("rhea/a", "v2", latest=False)], truncated=True,
                  next_key="rhea/a", next_version="cursor")],
            [page([version("rhea/a")], truncated=True, next_key="rhea/a", next_version="cursor1"),
             page([version("rhea/a", "v2", latest=False)], truncated=True,
                  next_key="rhea/a", next_version="cursor2"),
             page([version("rhea/a", "v3", latest=False)], truncated=True,
                  next_key="rhea/a", next_version="cursor1")],
            [page([version("rhea/b")], truncated=True, next_key="rhea/b", next_version="v1"),
             page([version("rhea/a")])],
            [page([version("rhea/a")], truncated=True, next_key="rhea/a", next_version="v1"),
             page([version("rhea/a")])],
        ]
        for index, pages in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(scan.ScanRefusal):
                    run(ScriptedClient(pages))

    def test_initial_exclusive_lower_bound_is_enforced(self):
        class BadLower:
            def list_object_versions(self, **request):
                return page([version(request.get("KeyMarker") or "rhea/a")])
        with self.assertRaises(scan.ScanRefusal):
            run(BadLower(), boundaries=("rhea/a",), workers=1)

    def test_configuration_is_bounded_before_any_call(self):
        client = ListingClient([])
        cases = [{"workers": 0}, {"workers": 5}, {"workers": True},
                 {"max_pages": 0}, {"max_rows": -1}, {"boundaries": "rhea/a"},
                 {"boundaries": ("rhea/b", "rhea/a")}, {"boundaries": ("rhea/a", "rhea/a")},
                 {"boundaries": ("outside/a",)}, {"boundaries": ("rhea/\ud800",)},
                 {"boundaries": ("rhea/a", "rhea/b", "rhea/c", "rhea/d")},
                 {"stop_event": object()}]
        for options in cases:
            with self.subTest(options=options):
                with self.assertRaises(scan.ScanRefusal):
                    run(client, **options)
        self.assertEqual([], client.calls)

    def test_row_budget_includes_discarded_lookahead(self):
        records = [version("rhea/" + key) for key in "abcd"]
        with self.assertRaises(scan.ScanRefusal):
            run(ListingClient(records, page_size=4), boundaries=("rhea/b",), max_rows=5)
        result, metrics = run(ListingClient(records, page_size=4), boundaries=("rhea/b",), max_rows=6)
        self.assertEqual(expected(records), result)
        self.assertEqual(6, metrics["version_rows"])
        self.assertEqual(2, metrics["discarded_rows"])
        self.assertEqual(4, metrics["retained_versions"])

    def test_page_budget_reserved_before_call_and_inflight_call_is_drained(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        calls, failures = [], []

        class BlockedClient:
            def list_object_versions(self, **request):
                calls.append(request)
                entered.set()
                if not release.wait(3):
                    raise AssertionError("test release was not delivered")
                return page()

        def invoke():
            try:
                run(BlockedClient(), boundaries=("rhea/a", "rhea/b", "rhea/c"), workers=4, max_pages=1)
            except BaseException as error:
                failures.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=invoke)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assertFalse(finished.wait(0.05))
            self.assertEqual(1, len(calls))
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(1, len(calls))
        self.assertEqual(1, len(failures))
        self.assertIsInstance(failures[0], scan.ScanRefusal)
        self.assertIn("request budget", str(failures[0]))

    def test_sdk_failure_after_successful_page_is_not_retried_or_wrapped(self):
        failure = RuntimeError("private SDK diagnostic")
        client = ScriptedClient([
            page([version("rhea/a")], truncated=True, next_key="rhea/a", next_version="v1"),
            failure,
        ])
        with self.assertRaises(RuntimeError) as caught:
            run(client)
        self.assertIs(failure, caught.exception)
        self.assertEqual(2, len(client.calls))

    def test_cancellation_before_and_after_response_stops_new_requests(self):
        class Flag:
            cancelled = True
            def is_set(self):
                return self.cancelled
        flag, client = Flag(), ListingClient([version("rhea/a")])
        with self.assertRaises(scan.ScanCancelled):
            run(client, stop_event=flag)
        self.assertEqual([], client.calls)
        flag.cancelled = False

        class CancelsAfterResponse(ListingClient):
            def list_object_versions(self, **request):
                result = super().list_object_versions(**request)
                flag.cancelled = True
                return result

        client = CancelsAfterResponse([version("rhea/a"), version("rhea/b")], page_size=1)
        with self.assertRaises(scan.ScanCancelled):
            run(client, stop_event=flag)
        self.assertEqual(1, len(client.calls))

    def test_worker_failure_preserved_while_sibling_is_drained(self):
        both_started = threading.Barrier(2)
        release, failed, finished = threading.Event(), threading.Event(), threading.Event()
        original = RuntimeError("original SDK exception must survive cancellation")
        errors, calls = [], []

        class ConcurrentFailure:
            def list_object_versions(self, **request):
                calls.append(request)
                both_started.wait(3)
                if "KeyMarker" not in request:
                    failed.set()
                    raise original
                if not release.wait(3):
                    raise AssertionError("test release was not delivered")
                return page()

        def invoke():
            try:
                run(ConcurrentFailure(), boundaries=("rhea/b",), workers=2)
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=invoke)
        thread.start()
        try:
            self.assertTrue(failed.wait(2))
            self.assertFalse(finished.wait(0.05))
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([original], errors)
        self.assertEqual(2, len(calls))


if __name__ == "__main__":
    unittest.main()
