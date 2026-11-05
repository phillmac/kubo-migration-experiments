"""Pure request-boundary and retained-metric gates; no host or SDK setup."""
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
from pathlib import Path
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "integrated_verifier_runner_tests", ROOT / "scripts/run_rhea_integrated_verification_profile.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
BUCKET = "fixed-fixture-bucket"


def page(*, versions=(), deletes=(), truncated=False, **changes):
    return dict({"Name": BUCKET, "Prefix": "rhea/", "IsTruncated": truncated,
                 "Versions": list(versions), "DeleteMarkers": list(deletes)}, **changes)


class Client:
    """Independent paginator and direct-call recorder with observable I/O."""
    def __init__(self, pages=(), on_response=None):
        self.pages = list(pages)
        self.on_response = on_response
        self.calls = []
        self.advances = 0
        self.lock = threading.Lock()
        self.body = io.BytesIO(b"fixture payload")

    def get_paginator(self, name):
        self.calls.append(("get_paginator", name))
        return self

    def paginate(self, **kwargs):
        self.calls.append(("paginate", kwargs))
        return self

    def __iter__(self):
        return self

    def __next__(self):
        self.advances += 1
        if not self.pages:
            raise StopIteration
        result = self.pages.pop(0)
        if isinstance(result, BaseException):
            raise result
        if self.on_response is not None:
            self.on_response()
        return result

    def list_object_versions(self, **kwargs):
        with self.lock:
            self.calls.append(("list_object_versions", kwargs))
        if self.on_response is not None:
            self.on_response()
        return page(versions=[{"Key": "rhea/a", "VersionId": "version", "IsLatest": True}])

    def get_object(self, **kwargs):
        self.calls.append(("get_object", kwargs))
        if self.on_response is not None:
            self.on_response()
        return {"Body": self.body}

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        return {"ContentLength": 15}


def guarded(client, stop=None):
    return m.GuardedClient(client, BUCKET, stop if stop is not None else m.Cancellation())


def direct(client, **changes):
    return client.list_object_versions(**dict(
        {"Bucket": BUCKET, "Prefix": "rhea/", "MaxKeys": 1000}, **changes))


def walk(client):
    return list(client.get_paginator("list_object_versions").paginate(Bucket=BUCKET, Prefix="rhea/"))


class GuardedReadTests(unittest.TestCase):
    def test_serial_preserves_pages_and_terminal_exhaustion_at_exact_request_cap(self):
        pages = [page(versions=[{"private": "retained exactly"}], truncated=True), page()]
        sdk = Client(pages)
        client = guarded(sdk)
        with patch.object(m, "MAX_PAGES", 2):
            result = walk(client)
        self.assertTrue(all(actual is original for actual, original in zip(result, pages)))
        self.assertEqual((client.requests, client.rows, sdk.advances), (2, 1, 3))
        self.assertTrue(client.serial_exhausted)
        self.assertEqual(sdk.calls, [("get_paginator", "list_object_versions"),
                                    ("paginate", {"Bucket": BUCKET, "Prefix": "rhea/"})])

    def test_serial_request_budget_stops_before_next_remote_advance(self):
        sdk = Client([page(truncated=True), page()])
        client = guarded(sdk)
        with patch.object(m, "MAX_PAGES", 1), self.assertRaisesRegex(RuntimeError, "request budget"):
            walk(client)
        self.assertEqual((sdk.advances, client.requests), (1, 1))
        self.assertFalse(client.serial_exhausted)

    def test_row_budget_counts_versions_and_deletes_before_following_page(self):
        sdk = Client([page(versions=[{}], deletes=[{}], truncated=True), page()])
        client = guarded(sdk)
        with patch.object(m, "MAX_ROWS", 1), self.assertRaisesRegex(RuntimeError, "row budget"):
            walk(client)
        self.assertEqual((sdk.advances, client.rows), (1, 2))
        self.assertFalse(client.serial_exhausted)

    def test_serial_refuses_scope_grouping_malformed_arrays_and_incomplete_walks(self):
        cases = [[page(**change)] for change in (
            {"Name": "wrong"}, {"Prefix": "other/"}, {"IsTruncated": 1},
            {"Versions": ()}, {"DeleteMarkers": None}, {"Delimiter": "/"},
            {"CommonPrefixes": [{"Prefix": "rhea/group/"}]})]
        cases.extend(([], [page(truncated=True)], [page(), page()]))
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaises(RuntimeError):
                walk(guarded(Client(pages)))

    def test_pagination_setup_scope_reuse_and_mixed_listing_paths_fail_closed(self):
        client = guarded(Client([page()]))
        paginator = client.get_paginator("list_object_versions")
        with self.assertRaises(RuntimeError):
            list(paginator.paginate(Bucket=BUCKET, Prefix="outside/"))
        self.assertEqual(list(paginator.paginate(Bucket=BUCKET, Prefix="rhea/")), [page()])
        with self.assertRaises(RuntimeError):
            list(paginator.paginate(Bucket=BUCKET, Prefix="rhea/"))
        with self.assertRaises(RuntimeError):
            client.get_paginator("list_object_versions")
        with self.assertRaises(RuntimeError):
            direct(client)
        client = guarded(Client())
        direct(client)
        with self.assertRaises(RuntimeError):
            client.get_paginator("list_object_versions")

    def test_serial_and_direct_sdk_failures_preserve_original_identity(self):
        for direct_mode in (False, True):
            error = OSError("fixture SDK error")
            sdk = Client([page(truncated=True), error])
            if direct_mode:
                sdk.list_object_versions = lambda **kwargs: (_ for _ in ()).throw(error)
            client = guarded(sdk)
            with self.subTest(direct=direct_mode), self.assertRaises(OSError) as raised:
                direct(client) if direct_mode else walk(client)
            self.assertIs(raised.exception, error)
            self.assertFalse(client.serial_exhausted)

    def test_cancellation_before_or_during_listing_prevents_following_calls(self):
        for direct_mode in (False, True):
            stop = m.Cancellation()
            sdk = Client([page(truncated=True), page()], on_response=stop.set)
            client = guarded(sdk, stop)
            with self.subTest(direct=direct_mode), self.assertRaisesRegex(RuntimeError, "cancelled"):
                direct(client) if direct_mode else walk(client)
            self.assertEqual((client.requests, client.rows), (1, 0))
            calls, advances = list(sdk.calls), sdk.advances
            for operation in (lambda: direct(client), lambda: client.get_paginator("list_object_versions"),
                              lambda: client.get_object(Bucket=BUCKET, Key="rhea/a")):
                with self.assertRaises(RuntimeError):
                    operation()
            self.assertEqual((sdk.calls, sdk.advances), (calls, advances))

    def test_shared_request_budget_reserves_before_each_concurrent_sdk_call(self):
        sdk, cap = Client(), 7
        client = guarded(sdk)

        def attempt(_):
            try:
                direct(client)
                return True
            except RuntimeError:
                return False

        with patch.object(m, "MAX_PAGES", cap), ThreadPoolExecutor(max_workers=4) as workers:
            completed = list(workers.map(attempt, range(24)))
        self.assertEqual(sum(completed), cap)
        self.assertEqual((len(sdk.calls), client.requests, client.rows), (cap, cap, cap))

    def test_direct_cursor_is_forwarded_exactly_but_scope_and_extra_options_are_denied(self):
        sdk = Client()
        client = guarded(sdk)
        direct(client, KeyMarker="rhea/a%2Fb", VersionIdMarker="null")
        self.assertEqual(sdk.calls[0][1], {"Bucket": BUCKET, "Prefix": "rhea/", "MaxKeys": 1000,
                                        "KeyMarker": "rhea/a%2Fb", "VersionIdMarker": "null"})
        cases = ({"Bucket": "other"}, {"Prefix": "rhea/pebbleds/"}, {"MaxKeys": 1},
                 {"Delimiter": "/"}, {"EncodingType": "url"}, {"KeyMarker": "outside"},
                 {"KeyMarker": 1}, {"VersionIdMarker": "version"},
                 {"KeyMarker": "rhea/key", "VersionIdMarker": ""},
                 {"KeyMarker": "rhea/key", "VersionIdMarker": 1})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                direct(client, **change)
        self.assertEqual(len(sdk.calls), 1)

    def test_get_body_ownership_survives_cancellation_during_sdk_response(self):
        stop = m.Cancellation()
        sdk = Client(on_response=stop.set)
        client = guarded(sdk, stop)
        response = client.get_object(Bucket=BUCKET, Key="rhea/object", VersionId="version")
        self.assertIs(response["Body"], sdk.body)
        try:
            self.assertEqual(response["Body"].read(), b"fixture payload")
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                client.head_object(Bucket=BUCKET, Key="rhea/object")
        finally:
            response["Body"].close()
        self.assertTrue(sdk.body.closed)
        self.assertEqual(len(sdk.calls), 1)

    def test_reads_and_unknown_operations_cannot_escape_fixed_prefix(self):
        sdk, client = Client(), None
        client = guarded(sdk)
        for method in (client.get_object, client.head_object):
            for change in ({"Bucket": "other"}, {"Key": "outside"}, {"Key": 3},
                           {"VersionId": ""}, {"VersionId": 1}, {"Range": "bytes=0-1"}):
                with self.subTest(method=method.__name__, change=change), self.assertRaises(RuntimeError):
                    method(**dict({"Bucket": BUCKET, "Key": "rhea/object"}, **change))
        for name in ("put_object", "delete_object", "copy_object", "close", "meta"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                getattr(client, name)
        self.assertEqual(sdk.calls, [])

    def test_cancellation_is_latched_and_broken_diagnostic_output_is_nonfatal(self):
        stop = m.Cancellation()
        self.assertFalse(stop.is_set())
        stop.set(); stop.set()
        self.assertTrue(stop.is_set())
        with self.assertRaises(RuntimeError):
            m.cancelled(stop)
        with patch("builtins.print", side_effect=BrokenPipeError("closed diagnostic pipe")):
            m.emit({"phase": "fixture"})


def valid_measurement(candidate):
    direct_stats = dict(calls=0, pages=0, failed_calls=0, in_flight=0, max_in_flight=0,
                        version_rows=0, delete_marker_rows=0, responses_with_retry_metadata=0,
                        reported_retry_attempts=0, max_reported_retry_attempts=0)
    serial = dict(paginator_creations=1, paginations=1, exhaustions=1, pages=94,
                  failed_advances=0, setup_failures=0, version_rows=93_763, delete_marker_rows=54)
    metrics = {"verifier_returned": True, "denied_operations": 0,
               "functions": {"_collect_latest": {"calls": 1, "failed_calls": 0},
                             "_head_matches": {"calls": 14, "failed_calls": 0}},
               "s3": {"get_object": {"calls": 10, "failed_calls": 0},
                      "head_object": {"calls": 14, "failed_calls": 0},
                      "list_object_versions": serial, "list_object_versions_direct": direct_stats},
               "body": dict(bytes_returned=114_660_926, opened=10, closed=10, close_calls=10,
                            read_failures=0, close_failures=0)}
    audit = dict(max_pages=512, max_received_rows=500_000, logical_listing_requests_reserved=94,
                 received_rows=93_817, sdk_paginator_created=True, sdk_paginator_exhausted=True)
    enumeration = {}
    if candidate:
        ranges = []
        for index, (retained, discarded) in enumerate(((23_424, 24), (23_424, 20), (23_424, 16), (23_491, 0))):
            deletes = 54 if index == 3 else 0
            ranges.append(dict(index=index, termination="exhausted" if index == 3 else "upper-crossed",
                requests=24, pages=24, version_rows=retained + discarded, delete_marker_rows=deletes,
                retained_versions=retained, retained_delete_markers=deletes, discarded_rows=discarded,
                responses_with_retry_metadata=24, reported_retry_attempts=0, max_reported_retry_attempts=0,
                api_wall_seconds=float(index + 1)))
        enumeration = dict(complete=True, workers=4, range_count=4, max_pages=512, max_rows=500_000,
                           ranges=ranges, max_reported_retry_attempts=0)
        for key in ranges[0].keys() - {"index", "termination", "max_reported_retry_attempts"}:
            enumeration[key] = sum(row[key] for row in ranges)
        serial.update(paginator_creations=0, paginations=0, exhaustions=0, pages=0, version_rows=0,
                      delete_marker_rows=0)
        direct_stats.update(calls=96, pages=96, max_in_flight=4, version_rows=93_823,
                            delete_marker_rows=54, responses_with_retry_metadata=96)
        audit.update(logical_listing_requests_reserved=96, received_rows=93_877,
                     sdk_paginator_created=False, sdk_paginator_exhausted=False)
    return metrics, enumeration, audit


class MeasurementGateTests(unittest.TestCase):
    def test_accepts_complete_serial_and_candidate_measurements_without_fake_pagination(self):
        for candidate in (False, True):
            args = valid_measurement(candidate)
            unchanged = copy.deepcopy(args)
            m.validate_pass(*args, candidate=candidate)
            self.assertEqual(args, unchanged)

    def test_rejects_incomplete_proof_open_bodies_wrong_payload_and_guard_bounds(self):
        for candidate in (False, True):
            mutations = (
                lambda a: a[0].update(verifier_returned=False),
                lambda a: a[0].update(denied_operations=1),
                lambda a: a[0]["functions"]["_collect_latest"].update(calls=2),
                lambda a: a[0]["functions"]["_head_matches"].update(failed_calls=1),
                lambda a: a[0]["s3"]["get_object"].update(calls=9),
                lambda a: a[0]["s3"]["head_object"].update(failed_calls=1),
                lambda a: a[0]["body"].update(closed=9),
                lambda a: a[0]["body"].update(bytes_returned=114_660_925),
                lambda a: a[0]["body"].update(close_failures=1),
                lambda a: a[2].update(max_pages=513),
                lambda a: a[2].update(logical_listing_requests_reserved=513),
                lambda a: a[2].update(received_rows=500_001),
                lambda a: a[0]["s3"]["list_object_versions_direct"].update(in_flight=1),
                lambda a: a[0]["s3"]["list_object_versions_direct"].update(max_in_flight=5))
            for index, mutate in enumerate(mutations):
                args = valid_measurement(candidate)
                mutate(args)
                with self.subTest(candidate=candidate, case=index), self.assertRaises(RuntimeError):
                    m.validate_pass(*args, candidate=candidate)

    def test_candidate_requires_four_completed_ranges_exact_sums_and_retry_parity(self):
        mutations = (
            lambda a: a[1].update(complete=False), lambda a: a[1].update(workers=3),
            lambda a: a[1].update(retained_versions=93_762),
            lambda a: a[1].update(discarded_rows=61),
            lambda a: a[1]["ranges"][0].update(index=1),
            lambda a: a[1]["ranges"][2].update(termination="exhausted"),
            lambda a: a[1]["ranges"][3].update(termination="upper-crossed"),
            lambda a: a[1]["ranges"][1].update(pages=23),
            lambda a: a[1]["ranges"][1].update(api_wall_seconds=2.5),
            lambda a: a[1]["ranges"][1].update(max_reported_retry_attempts=1),
            lambda a: a[0]["s3"]["list_object_versions_direct"].update(responses_with_retry_metadata=95),
            lambda a: a[0]["s3"]["list_object_versions_direct"].update(reported_retry_attempts=1),
            lambda a: a[0]["s3"]["list_object_versions_direct"].update(max_in_flight=0),
            lambda a: a[0]["s3"]["list_object_versions"].update(pages=1),
            lambda a: a[2].update(sdk_paginator_created=True))
        for index, mutate in enumerate(mutations):
            args = valid_measurement(True)
            mutate(args)
            with self.subTest(case=index), self.assertRaises(RuntimeError):
                m.validate_pass(*args, candidate=True)

    def test_serial_requires_one_exhausted_walk_and_no_direct_listing(self):
        mutations = (
            lambda a: a[1].update(complete=True),
            lambda a: a[0]["s3"]["list_object_versions"].update(exhaustions=0),
            lambda a: a[0]["s3"]["list_object_versions"].update(failed_advances=1),
            lambda a: a[0]["s3"]["list_object_versions"].update(version_rows=93_762),
            lambda a: a[0]["s3"]["list_object_versions_direct"].update(calls=1),
            lambda a: a[0]["s3"]["list_object_versions_direct"].update(max_in_flight=1),
            lambda a: a[2].update(sdk_paginator_exhausted=False))
        for index, mutate in enumerate(mutations):
            args = valid_measurement(False)
            mutate(args)
            with self.subTest(case=index), self.assertRaises(RuntimeError):
                m.validate_pass(*args, candidate=False)


if __name__ == "__main__":
    unittest.main()
