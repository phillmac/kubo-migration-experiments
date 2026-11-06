"""Offline adoption wiring plus the unchanged controller/recovery regressions."""
import copy
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/run_rhea_full_clone_steps_bounded.py"
OLD_SOURCE = SOURCE.with_name("run_rhea_full_clone_steps.py")
OLD_CONTROLLER_SHA256 = "7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb"
OLD_VERIFIER_SHA256 = "e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849"
GO_SHA256 = "1bc58ef8ca76a97fc9886d90f4a3df4fdd3d07549403988e3798834a61207125"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Use a private fixture module: discovery of the original tests remains intact.
fixtures = load("bounded_controller_legacy_fixtures", Path(__file__).with_name("test_run_rhea_full_clone_steps.py"))
old = fixtures.m
m = load("bounded_controller_tests", SOURCE)
fixtures.m = m
fixtures.SOURCE = SOURCE


class ValidationTests(fixtures.ValidationTests):
    pass


class BudgetTests(fixtures.BudgetTests):
    pass


class ControllerTests(fixtures.ControllerTests):
    pass


class RuntimeTests(fixtures.RuntimeTests):
    pass


class BoundedWiringTests(unittest.TestCase):
    @contextmanager
    def installation(self, *, pin_changes=None, source_changes=None, read_failure=None):
        events = []
        own_path = m.TRUST / SOURCE.name
        pins = {"schema": 1, "controller_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                "go_sha256": GO_SHA256, "verifier_sha256": m.VERIFIER_SHA256}
        pins.update(pin_changes or {})
        sources = {own_path: SOURCE.read_bytes(), m.PINS: m.canonical(pins),
                   m.SCANNER: SOURCE.with_name(m.SCANNER.name).read_bytes(),
                   m.DECODER: SOURCE.with_name(m.DECODER.name).read_bytes()}
        sources.update(source_changes or {})
        host = SimpleNamespace(dependencies=Mock(side_effect=lambda: events.append(("dependencies",))))
        wrapper = SimpleNamespace(RealHost=lambda: host, PROFILES={"full-clone": object()})
        verifier = SimpleNamespace()

        def read(path, **kwargs):
            events.append(("read", path, kwargs))
            if read_failure is not None and path == read_failure[0]:
                raise read_failure[1]
            return sources[path]

        def import_source(path, expected, name):
            events.append(("import", path, expected))
            if path == m.WRAPPER:
                self.assertEqual(expected, m.WRAPPER_SHA256)
                return wrapper
            self.assertEqual(path, m.VERIFIER)
            self.assertEqual(expected, m.VERIFIER_SHA256)
            return verifier

        wrapper.read_protected = Mock(side_effect=read)
        with patch.object(m, "__file__", str(own_path)), patch.object(m.os, "geteuid", return_value=0), \
                patch.object(m, "load_pinned_module", side_effect=import_source) as importer, \
                patch.object(m.Runtime, "check_tool", autospec=True) as check_tool:
            yield SimpleNamespace(events=events, pins=pins, wrapper=wrapper, verifier=verifier,
                                  importer=importer, check_tool=check_tool)

    def test_fixed_sources_paths_and_limits_preserve_historical_controller(self):
        self.assertEqual(hashlib.sha256(OLD_SOURCE.read_bytes()).hexdigest(), OLD_CONTROLLER_SHA256)
        self.assertEqual(hashlib.sha256(SOURCE.with_name("verify_rhea_full_clone.py").read_bytes()).hexdigest(),
                         OLD_VERIFIER_SHA256)
        self.assertEqual(m.PINS, m.TRUST / "full-clone-bounded-step-pins.json")
        self.assertEqual(m.VERIFIER, m.TRUST / "verify_rhea_full_clone_bounded.py")
        for path, expected in ((m.VERIFIER, m.VERIFIER_SHA256), (m.SCANNER, m.SCANNER_SHA256),
                               (m.DECODER, m.DECODER_SHA256), (m.WRAPPER, m.WRAPPER_SHA256)):
            with self.subTest(path=path.name):
                self.assertEqual(hashlib.sha256(SOURCE.with_name(path.name).read_bytes()).hexdigest(), expected)
        for name in ("LIMITS", "STAGES", "PHASES", "MAX_REWRITES", "MAX_GENERATION", "STATE_ROOT",
                     "SEED", "SEED_SHA256", "TOOL", "STOP_FILE", "DB", "BUCKET", "PREFIX"):
            with self.subTest(name=name):
                self.assertEqual(getattr(m, name), getattr(old, name))
        self.assertEqual((m.MAX_REWRITES, m.MAX_GENERATION), (5, 9))

    def test_protected_dependencies_checked_before_candidate_import_and_binding_unchanged(self):
        with self.installation() as env:
            runtime = m.Runtime()
            self.assertIs(runtime.profile, env.wrapper.PROFILES["full-clone"])
            self.assertIs(runtime.verifier, env.verifier)
            verifier_import = next(index for index, event in enumerate(env.events)
                                   if event[:2] == ("import", m.VERIFIER))
            for path in (m.SCANNER, m.DECODER):
                expected = ("read", path, {"mode": 0o600, "max_bytes": m.MAX_JSON})
                self.assertIn(expected, env.events[:verifier_import])
                self.assertEqual(env.events.count(expected), 1)
            self.assertEqual(runtime.binding, dict(env.pins, wrapper_sha256=m.WRAPPER_SHA256,
                                                  seed_sha256=m.SEED_SHA256, bucket=m.BUCKET,
                                                  prefix=m.PREFIX, limits=m.LIMITS))
            self.assertEqual(set(runtime.pins), {"schema", "controller_sha256", "go_sha256", "verifier_sha256"})
            env.check_tool.assert_called_once_with(runtime)

    def test_missing_unprotected_or_changed_dependency_never_imports_candidate(self):
        for path in (m.SCANNER, m.DECODER):
            failures = (FileNotFoundError("offline fixture"), PermissionError("offline fixture"))
            for failure in failures:
                with self.subTest(path=path.name, failure=type(failure).__name__), \
                        self.installation(read_failure=(path, failure)) as env:
                    with self.assertRaises(type(failure)) as raised:
                        m.Runtime()
                    self.assertIs(raised.exception, failure)
                    self.assertEqual([call.args[0] for call in env.importer.call_args_list], [m.WRAPPER])
                    env.check_tool.assert_not_called()
            with self.subTest(path=path.name, failure="digest"), \
                    self.installation(source_changes={path: b"changed source"}) as env:
                with self.assertRaisesRegex(m.Refusal, "dependency digest mismatch"):
                    m.Runtime()
                self.assertEqual([call.args[0] for call in env.importer.call_args_list], [m.WRAPPER])
                env.check_tool.assert_not_called()

    def test_old_or_malformed_verifier_pin_never_imports_candidate(self):
        for changes in ({"verifier_sha256": OLD_VERIFIER_SHA256}, {"verifier_sha256": "bad"},
                        {"enumeration_workers": 1}, {"schema": True}):
            with self.subTest(changes=changes), self.installation(pin_changes=changes) as env:
                with self.assertRaises(m.Refusal):
                    m.Runtime()
                self.assertEqual([call.args[0] for call in env.importer.call_args_list], [m.WRAPPER])
                self.assertFalse(any(event[:2] == ("read", m.SCANNER) for event in env.events))

    def test_adopted_state_changes_only_two_bindings_and_old_load_refuses_it(self):
        certificate = m.json_object((ROOT / "docs/evidence/rhea-full-clone-000009-step-20261104.json").read_bytes())
        with self.installation() as env, tempfile.TemporaryDirectory() as location:
            runtime = m.Runtime()
            previous_binding = dict(runtime.binding, controller_sha256=OLD_CONTROLLER_SHA256,
                                    verifier_sha256=OLD_VERIFIER_SHA256)
            previous_state = {"schema": 1, "binding": previous_binding, "checkpoint": certificate,
                              "generation": 9, "rewrites": 5, "pending": None}
            old_runtime = old.Runtime.__new__(old.Runtime)
            old_runtime.binding = previous_binding
            old_runtime.validate_state(previous_state)
            adopted_state = copy.deepcopy(previous_state)
            adopted_state["binding"] = runtime.binding
            self.assertEqual({key for key in previous_binding if previous_binding[key] != runtime.binding[key]},
                             {"controller_sha256", "verifier_sha256"})
            raw = m.canonical(adopted_state)
            directory = Path(location)
            (directory / "state.json").write_bytes(raw)
            runtime.wrapper = old_runtime.wrapper = SimpleNamespace(secure_path=Mock(),
                                                                    read_protected=Mock(return_value=raw))
            with patch.object(m, "STATE_ROOT", directory), patch.object(old, "STATE_ROOT", directory):
                self.assertEqual(runtime.load_state(), adopted_state)
                with self.assertRaisesRegex(old.Refusal, "journal binding mismatch"):
                    old_runtime.load_state()
                runtime.lock = Mock(return_value=nullcontext())
                runtime.guard = Mock()
                runtime.run_tool = Mock()
                runtime.write_state = Mock()
                with self.assertRaisesRegex(m.Refusal, "rewrite limit has already been reached"):
                    m.Controller(runtime).run("step", apply=True)
                runtime.guard.assert_not_called()
                runtime.run_tool.assert_not_called()
                runtime.write_state.assert_not_called()
                self.assertEqual((directory / "state.json").read_bytes(), raw)

    def verification_runtime(self, mode, *, failure=None):
        events = []
        runtime = m.Runtime.__new__(m.Runtime)
        runtime.profile = object()
        runtime.guard = Mock(side_effect=lambda **kwargs: events.append(("guard", kwargs)))
        runtime.check_snapshot = Mock(side_effect=lambda snapshot: events.append(("snapshot",)))
        queued = [{"name": "pebbleds/marker.manifest.000002.MANIFEST-000012", "uploading": False}]
        queue = {"queue": {"queue": queued if mode == "before-markers" else []}}
        runtime._checked_queue = Mock(side_effect=lambda *args: (events.append(("queue",)), queue)[1])
        runtime.stop_present = Mock(side_effect=AssertionError("verification must retain recovery semantics"))
        ledger, s3, sts = object(), SimpleNamespace(), SimpleNamespace()
        s3.close = Mock(side_effect=lambda: events.append(("s3-close",)))
        sts.close = Mock(side_effect=lambda: events.append(("sts-close",)))
        runtime.wrapper = SimpleNamespace(LEDGER=Path("fixture-ledger"), CONFIG=Path("fixture-config"))
        runtime.wrapper.read_protected = Mock(side_effect=lambda path, **kwargs: (
            events.append(("read", path.name)), b"offline fixture")[1])
        runtime.wrapper.load_ledger = Mock(side_effect=lambda raw: (events.append(("ledger",)), ledger)[1])
        runtime.wrapper.parse_config = Mock(side_effect=lambda raw: (events.append(("config",)), {})[1])
        runtime.wrapper.verify_cloud_identity = Mock(side_effect=lambda *args: (
            events.append(("identity",)), "fixture-identity")[1])
        runtime.host = SimpleNamespace(
            cloud=Mock(side_effect=lambda credentials: (events.append(("cloud",)), (s3, sts))[1]),
            read_admission=Mock(side_effect=lambda profile: (events.append(("admission",)),
                                                              {"identity": "fixture-identity"})[1]))
        result = {"certificate-must-be-returned-unchanged": True}

        def verify(*args, **kwargs):
            events.append(("verify", args[-2], kwargs))
            if failure is not None:
                raise failure
            return result

        runtime.verifier = SimpleNamespace(verify_generation=Mock(side_effect=verify))
        return SimpleNamespace(runtime=runtime, events=events, ledger=ledger, s3=s3, sts=sts, result=result)

    def test_both_proof_modes_force_four_workers_and_preserve_guard_close_order(self):
        previous, report, snapshot, created = {"previous": True}, {}, {"LOCK": b""}, {}
        for mode in ("before-markers", "final"):
            with self.subTest(mode=mode):
                env = self.verification_runtime(mode)
                result = env.runtime.verify(previous, report, snapshot, created, mode)
                self.assertIs(result, env.result)
                env.runtime.verifier.verify_generation.assert_called_once_with(
                    env.s3, env.ledger, previous, report, snapshot, created, mode, m.digest(previous),
                    enumeration_workers=4)
                self.assertEqual(env.events, [
                    ("guard", {"new_work": False, "clean": mode == "final"}), ("snapshot",), ("queue",),
                    ("read", "fixture-ledger"), ("ledger",), ("read", "fixture-config"), ("config",),
                    ("cloud",), ("identity",), ("admission",), ("verify", mode, {"enumeration_workers": 4}),
                    ("s3-close",), ("sts-close",),
                    ("guard", {"new_work": False, "clean": mode == "final"}), ("snapshot",)])
                env.runtime.stop_present.assert_not_called()

    def test_bounded_failure_closes_clients_and_propagates_without_serial_fallback(self):
        failure = RuntimeError("offline enumeration failure")
        for mode in ("before-markers", "final"):
            with self.subTest(mode=mode):
                env = self.verification_runtime(mode, failure=failure)
                with self.assertRaises(RuntimeError) as raised:
                    env.runtime.verify({}, {}, {}, {}, mode)
                self.assertIs(raised.exception, failure)
                self.assertEqual(env.runtime.verifier.verify_generation.call_count, 1)
                self.assertEqual(env.events[-2:], [("s3-close",), ("sts-close",)])
                env.s3.close.assert_called_once_with()
                env.sts.close.assert_called_once_with()
                self.assertEqual(env.runtime.guard.call_count, 1)

    def test_snapshot_and_pending_data_gates_still_precede_any_cloud_operation(self):
        for reason in ("snapshot", "pending-data"):
            with self.subTest(reason=reason):
                env = self.verification_runtime("before-markers")
                if reason == "snapshot":
                    env.runtime.check_snapshot.side_effect = m.Refusal("snapshot changed")
                else:
                    env.runtime._checked_queue.side_effect = None
                    env.runtime._checked_queue.return_value = {
                        "queue": {"queue": [{"name": "pebbleds/000001.sst", "uploading": False}]}}
                with self.assertRaises(m.Refusal):
                    env.runtime.verify({}, {}, {}, {}, "before-markers")
                env.runtime.host.cloud.assert_not_called()
                env.runtime.wrapper.load_ledger.assert_not_called()
                env.runtime.verifier.verify_generation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
