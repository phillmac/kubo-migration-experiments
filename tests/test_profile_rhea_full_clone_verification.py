"""Local profiling transparency and read-only API boundary regressions."""
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p = load("full_clone_profile_tests", ROOT / "scripts/profile_rhea_full_clone_verification.py")
fixtures = load("full_clone_profile_verifier_fixtures", ROOT / "tests/test_verify_rhea_full_clone.py")
v = fixtures.m


def profile_fixture(fixture, metrics=None):
    with patch.object(v.base, "EXPECTED_SSTS", 2), patch.object(v.base, "EXPECTED_SST_BYTES", 300), patch.object(
        v.base, "EXPECTED_INVENTORY", v.base.inventory_digest({1: 100, 2: 200})
    ):
        return p.profile_verify_generation(
            v, fixture.s3, fixture.ledger, fixture.previous, fixture.report, fixture.metadata,
            fixture.hashes, fixture.mode, v.canonical_sha256(fixture.previous), metrics=metrics)


def stub_verifier(callback):
    module = types.ModuleType("profile_stub_verifier")
    for name in p.FUNCTIONS:
        setattr(module, name, lambda *args, **kwargs: None)
    module.verify_generation = callback
    return module


def profile_stub(module, client=None, metrics=None):
    return p.profile_verify_generation(module, client, {}, {}, {}, {}, {}, "final", "a" * 64, metrics=metrics)


class ProfileTests(unittest.TestCase):
    def originals(self, module=v):
        return {name: getattr(module, name) for name in p.FUNCTIONS}

    def assert_restored(self, originals, module=v):
        for name, original in originals.items():
            self.assertIs(getattr(module, name), original)

    def test_real_verifier_result_and_exact_body_bytes_are_unchanged(self):
        for mode in ("before-markers", "final"):
            with self.subTest(mode=mode):
                fixture = fixtures.StageFixture(mode=mode)
                original = self.originals()
                with patch.object(v.time, "time", return_value=123456.0):
                    expected = fixture.verify()
                    gets, heads = list(fixture.s3.gets), list(fixture.s3.heads)
                    fixture.s3.gets.clear(); fixture.s3.heads.clear()
                    result, metrics = profile_fixture(fixture)
                self.assertEqual(result, expected)
                self.assertEqual(fixture.s3.gets, gets)
                self.assertEqual(fixture.s3.heads, heads)
                self.assertEqual(metrics["s3"]["get_object"]["calls"], len(gets))
                self.assertEqual(metrics["s3"]["head_object"]["calls"], len(heads))
                self.assertEqual(metrics["body"]["bytes_returned"],
                                 sum(len(fixture.s3.history[key, version][1]) for key, version in gets))
                self.assertEqual(metrics["body"]["opened"], len(gets))
                self.assertEqual(metrics["body"]["closed"], len(gets))
                self.assertEqual(metrics["body"]["read_failures"], 0)
                self.assertEqual(metrics["functions"]["_decode_tables"]["calls"], 2)
                self.assertEqual(metrics["functions"]["_get_bytes"]["calls"], len(gets) - 1)
                self.assertEqual(metrics["functions"]["_hash_new_sst"]["calls"], 1)
                self.assertTrue(metrics["verifier_returned"])
                self.assertIn("inclusive", metrics["timing_semantics"])
                self.assertIn("non-additive", metrics["timing_semantics"])
                for stats in metrics["functions"].values():
                    self.assertGreaterEqual(stats["wall_seconds"], 0)
                    self.assertGreaterEqual(stats["cpu_seconds"], 0)
                self.assertLess(len(json.dumps(metrics, allow_nan=False)), 16_384)
                self.assert_restored(original)

    def test_all_pages_history_rows_retries_and_empty_pages_are_measured(self):
        fixture = fixtures.StageFixture()
        expected = fixture.verify()
        rows = list(fixture.s3.latest.values())
        deleted = list(fixture.s3.deleted.values())
        historical = dict(rows[0], VersionId="private-historical-version", IsLatest=False)
        old_delete = {"Key": "private-history-key", "VersionId": "private-delete-version", "IsLatest": False}
        pages = [
            {"Versions": rows[:2] + [historical], "DeleteMarkers": [old_delete],
             "ResponseMetadata": {"RetryAttempts": 2, "RequestId": "private-request-id"}},
            {"Versions": [], "DeleteMarkers": [], "ResponseMetadata": {"RetryAttempts": 0}},
            {"Versions": rows[2:], "DeleteMarkers": deleted, "ResponseMetadata": {"RetryAttempts": 1}},
        ]
        scopes = []

        def paginate(**kwargs):
            scopes.append(kwargs)
            yield from pages

        fixture.s3.paginate = paginate
        head, get = fixture.s3.head_object, fixture.s3.get_object
        fixture.s3.head_object = lambda **kwargs: dict(head(**kwargs), ResponseMetadata={"RetryAttempts": 1})
        fixture.s3.get_object = lambda **kwargs: dict(get(**kwargs), ResponseMetadata={"RetryAttempts": 2})
        result, metrics = profile_fixture(fixture)
        self.assertEqual({k: value for k, value in result.items() if k != "verified_unix"},
                         {k: value for k, value in expected.items() if k != "verified_unix"})
        self.assertEqual(scopes, [{"Bucket": v.BUCKET, "Prefix": "rhea/"}])
        listed = metrics["s3"]["list_object_versions"]
        self.assertEqual((listed["paginator_creations"], listed["paginations"], listed["pages"], listed["exhaustions"]), (1, 1, 3, 1))
        self.assertEqual(listed["iterator_advances"], 4)
        self.assertEqual(listed["version_rows"], len(rows) + 1)
        self.assertEqual(listed["latest_version_rows"], len(rows))
        self.assertEqual(listed["delete_marker_rows"], len(deleted) + 1)
        self.assertEqual(listed["latest_delete_marker_rows"], len(deleted))
        self.assertEqual(listed["responses_with_retry_metadata"], 3)
        self.assertEqual(listed["reported_retry_attempts"], 3)
        self.assertEqual(listed["max_reported_retry_attempts"], 2)
        for name, attempts in (("head_object", 1), ("get_object", 2)):
            stats = metrics["s3"][name]
            self.assertEqual(stats["responses_with_retry_metadata"], stats["calls"])
            self.assertEqual(stats["reported_retry_attempts"], stats["calls"] * attempts)
        encoded = json.dumps(metrics)
        for private in ("private-", v.BUCKET, "MANIFEST-", "VersionId", "ETag"):
            self.assertNotIn(private, encoded)

    def test_request_stream_and_inclusive_function_timers_are_separate(self):
        class Clock:
            wall = 0.0
            cpu = 0.0

            def advance(self, wall, cpu):
                self.wall += wall
                self.cpu += cpu

        clock = Clock()

        class Body:
            def read(self):
                clock.advance(5, 1)
                return b"abc"

            def close(self):
                clock.advance(0.5, 0.01)

        class Pages:
            def __init__(self):
                self.done = False

            def __iter__(self):
                return self

            def __next__(self):
                if self.done:
                    clock.advance(0.1, 0.005)
                    raise StopIteration
                self.done = True
                clock.advance(4, 0.2)
                return {"Versions": [], "DeleteMarkers": []}

        class Paginator:
            def paginate(self):
                clock.advance(0.3, 0.02)
                return Pages()

        class Client:
            def get_paginator(self, name):
                clock.advance(0.2, 0.01)
                return Paginator()

            def get_object(self):
                clock.advance(2, 0.25)
                return {"Body": Body()}

            def head_object(self):
                clock.advance(1, 0.1)
                return {}

        module = stub_verifier(lambda **kwargs: module._hash_new_sst(kwargs["s3"]))

        def get_bytes(client):
            body = client.get_object()["Body"]
            try:
                return body.read()
            finally:
                body.close()

        def whole(client):
            result = module._get_bytes(client)
            client.head_object()
            module._collect_latest(client)
            return result

        module._get_bytes = get_bytes
        module._hash_new_sst = whole
        module._collect_latest = lambda client: list(client.get_paginator("list_object_versions").paginate())
        with patch.object(p.time, "perf_counter", side_effect=lambda: clock.wall), patch.object(
            p.time, "process_time", side_effect=lambda: clock.cpu
        ):
            result, metrics = profile_stub(module, Client())
        self.assertEqual(result, b"abc")
        self.assertAlmostEqual(metrics["s3"]["get_object"]["wall_seconds"], 2)
        self.assertAlmostEqual(metrics["body"]["read_wall_seconds"], 5)
        self.assertAlmostEqual(metrics["body"]["close_wall_seconds"], 0.5)
        self.assertAlmostEqual(metrics["s3"]["list_object_versions"]["setup_wall_seconds"], 0.5)
        self.assertAlmostEqual(metrics["s3"]["list_object_versions"]["wall_seconds"], 4.1)
        self.assertAlmostEqual(metrics["functions"]["_get_bytes"]["wall_seconds"], 7.5)
        self.assertAlmostEqual(metrics["functions"]["_get_bytes"]["cpu_seconds"], 1.26)
        self.assertAlmostEqual(metrics["functions"]["_hash_new_sst"]["wall_seconds"], 13.1)
        self.assertAlmostEqual(metrics["wall_seconds"], 13.1)

    def test_late_pagination_failure_is_not_swallowed_or_retried(self):
        fixture = fixtures.StageFixture()
        error = RuntimeError("private pagination failure details")
        error.response = {"ResponseMetadata": {"RetryAttempts": 2}, "Error": {"Message": "private SDK message"}}
        progressed = []

        def pages(**kwargs):
            progressed.append("first")
            yield {"Versions": [{"IsLatest": False}], "DeleteMarkers": [],
                   "ResponseMetadata": {"RetryAttempts": 0}}
            progressed.append("failure")
            raise error

        fixture.s3.paginate = pages
        metrics, original = {}, self.originals()
        with self.assertRaises(RuntimeError) as caught:
            profile_fixture(fixture, metrics)
        self.assertIs(caught.exception, error)
        self.assertEqual(progressed, ["first", "failure"])
        listed = metrics["s3"]["list_object_versions"]
        self.assertEqual((listed["pages"], listed["failed_advances"], listed["exhaustions"]), (1, 1, 0))
        self.assertEqual(listed["reported_retry_attempts"], 2)
        self.assertEqual(metrics["functions"]["_collect_latest"]["failed_calls"], 1)
        self.assertFalse(metrics["verifier_returned"])
        self.assertNotIn("private", json.dumps(metrics))
        self.assert_restored(original)

    def test_sdk_exception_and_baseexception_identity_survive_restoration(self):
        for error in (RuntimeError("private SDK exception"), KeyboardInterrupt("private interruption")):
            with self.subTest(kind=type(error).__name__):
                fixture = fixtures.StageFixture()
                metrics, original, calls = {}, self.originals(), []

                def fail(**kwargs):
                    calls.append(1)
                    raise error

                fixture.s3.get_object = fail
                with self.assertRaises(type(error)) as caught:
                    profile_fixture(fixture, metrics)
                self.assertIs(caught.exception, error)
                self.assertEqual(calls, [1])
                self.assertEqual(metrics["s3"]["get_object"]["failed_calls"], 1)
                self.assertEqual(metrics["functions"]["_get_bytes"]["failed_calls"], 1)
                self.assertNotIn("private", json.dumps(metrics))
                self.assert_restored(original)

    def test_stream_read_and_close_failures_preserve_original_error(self):
        for failing in ("read", "close"):
            with self.subTest(failing=failing):
                fixture = fixtures.StageFixture()
                error = OSError("private stream failure")
                get = fixture.s3.get_object
                bodies = []

                class Body:
                    def __init__(self, stream):
                        self.stream, self.reads, self.closes = stream, 0, 0

                    def read(self, *args, **kwargs):
                        self.reads += 1
                        if failing == "read":
                            raise error
                        return self.stream.read(*args, **kwargs)

                    def close(self):
                        self.closes += 1
                        self.stream.close()
                        if failing == "close":
                            raise error

                def response(**kwargs):
                    value = get(**kwargs)
                    body = Body(value["Body"]); bodies.append(body)
                    return dict(value, Body=body)

                fixture.s3.get_object = response
                metrics, original = {}, self.originals()
                with self.assertRaises(OSError) as caught:
                    profile_fixture(fixture, metrics)
                self.assertIs(caught.exception, error)
                self.assertEqual((bodies[0].reads, bodies[0].closes), (1, 1))
                self.assertEqual(metrics["body"][failing + "_failures"], 1)
                self.assertEqual(metrics["body"]["close_calls"], 1)
                self.assertEqual(metrics["body"]["bytes_returned"], 0 if failing == "read" else len(fixture.metadata[fixture.old_manifest]))
                self.assertNotIn("private", json.dumps(metrics))
                self.assert_restored(original)

    def test_mutating_and_unknown_client_operations_never_reach_client(self):
        for name in ("put_object", "delete_object", "delete_objects", "copy_object", "list_objects_v2", "get_bucket_versioning"):
            with self.subTest(name=name):
                module = stub_verifier(lambda **kwargs: getattr(kwargs["s3"], name)(Bucket="private"))
                original, metrics = self.originals(module), {}
                with self.assertRaises(p.ProfileRefusal):
                    profile_stub(module, object(), metrics)
                self.assertEqual(metrics["denied_operations"], 1)
                self.assert_restored(original, module)
        module = stub_verifier(lambda **kwargs: kwargs["s3"].get_paginator("list_objects_v2"))
        with self.assertRaises(p.ProfileRefusal):
            profile_stub(module, object())

    def test_unknown_paginator_and_stream_operations_are_refused(self):
        fixture = fixtures.StageFixture()
        module = stub_verifier(lambda **kwargs: kwargs["s3"].get_paginator("list_object_versions").build_full_result())
        with self.assertRaises(p.ProfileRefusal):
            profile_stub(module, fixture.s3)
        stream = io.BytesIO(b"private payload")
        client = types.SimpleNamespace(get_object=lambda **kwargs: {"Body": stream})

        def attempt(**kwargs):
            body = kwargs["s3"].get_object(Key="private key")["Body"]
            try:
                body.write(b"mutation")
            finally:
                body.close()

        metrics = {}
        with self.assertRaises(p.ProfileRefusal):
            profile_stub(stub_verifier(attempt), client, metrics)
        self.assertTrue(stream.closed)
        self.assertEqual(metrics["body"]["closed"], 1)
        self.assertNotIn("private", json.dumps(metrics))

    def test_original_result_object_and_read_close_results_are_preserved(self):
        returned = object()
        original_response = {"Body": io.BytesIO(b"abcdef")}
        client = types.SimpleNamespace(get_object=lambda **kwargs: original_response)

        def verify(**kwargs):
            body = kwargs["s3"].get_object(Key="private key")["Body"]
            self.assertEqual((body.read(2), body.read(), body.read(1)), (b"ab", b"cdef", b""))
            self.assertIsNone(body.close())
            return returned

        result, metrics = profile_stub(stub_verifier(verify), client)
        self.assertIs(result, returned)
        self.assertIsInstance(original_response["Body"], io.BytesIO)
        self.assertEqual(metrics["body"]["bytes_returned"], 6)
        self.assertEqual(metrics["body"]["read_calls"], 3)

    def test_nested_profiles_are_refused_without_corrupting_wrappers(self):
        module = stub_verifier(lambda **kwargs: profile_stub(module))
        original = self.originals(module)
        with self.assertRaisesRegex(p.ProfileRefusal, "already active"):
            profile_stub(module)
        self.assert_restored(original, module)
        module.verify_generation = lambda **kwargs: "reusable"
        self.assertEqual(profile_stub(module)[0], "reusable")


if __name__ == "__main__":
    unittest.main()
