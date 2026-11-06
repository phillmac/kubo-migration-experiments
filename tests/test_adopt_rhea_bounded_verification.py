"""Real generation-nine preimages and interrupted fixed-transaction regressions."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("bounded_adoption_transaction_tests", ROOT / "scripts/adopt_rhea_bounded_verification.py")
legacy = load("bounded_adoption_old_controller_fixture", ROOT / "scripts/run_rhea_full_clone_steps.py")


def plan_fixture():
    pins = {"schema": 1, "controller_sha256": m.OLD_CONTROLLER_SHA256,
            "go_sha256": "1bc58ef8ca76a97fc9886d90f4a3df4fdd3d07549403988e3798834a61207125",
            "verifier_sha256": m.OLD_VERIFIER_SHA256}
    certificate = json.loads((ROOT / "docs/evidence/rhea-full-clone-000009-step-20261104.json").read_bytes())
    state = {"schema": 1, "binding": dict(pins, wrapper_sha256=legacy.WRAPPER_SHA256,
        seed_sha256=legacy.SEED_SHA256, bucket=legacy.BUCKET, prefix=legacy.PREFIX, limits=legacy.LIMITS),
        "checkpoint": certificate, "generation": 9, "rewrites": 5, "pending": None}
    sources = {role: (ROOT / "scripts" / path).read_bytes()
               for role, path in m.TARGETS.items() if role != "pins"}
    provenance = {"schema": 1, "source_commit": "1" * 40, "deployment_sha256": "2" * 64,
                  "recipe_sha256": "3" * 64, "engine_sha256": "4" * 64, "health_sha256": "5" * 64}
    return m.build_plan(m.canonical(state), m.canonical(pins), sources, provenance)


class Interrupted(BaseException):
    pass


class Adapter:
    """In-memory protected adapter; every simulated durable operation is visible."""
    def __init__(self, plan, *, interrupt_after=None):
        self.plan = plan
        self.state = plan.state_before
        self.targets = {}
        self.receipts = {}
        self.acceptances = {}
        self.events = []
        self.locked = False
        self.durable_operations = 0
        self.interrupt_after = interrupt_after
        self.interruption = Interrupted("injected interruption")
        self.replacements = 0
        self.state_seals = 0
        self.state_durable = True
        self.interrupt_after_rename = False
        self.interrupt_before_completion_sync = False
        self.completion_durable = False
        self.observations = 0
        self.verifications = 0
        self.fail_observation = None
        self.verification_error = None
        self.verification_change = None
        self.after_verification = None
        self.clock = 1000
        # Historical paths are outside the adapter's replacement interface.
        self.historical = {"controller": (ROOT / "scripts/run_rhea_full_clone_steps.py").read_bytes(),
                           "verifier": (ROOT / "scripts/verify_rhea_full_clone.py").read_bytes(),
                           "pins": plan.pins_before,
                           "certificate": m.canonical(json.loads(plan.state_before)["checkpoint"])}

    @contextmanager
    def lock(self):
        assert not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def _durable(self, operation, name):
        assert self.locked
        self.events.append((operation, name))
        self.durable_operations += 1
        if self.durable_operations == self.interrupt_after:
            raise self.interruption

    def state_bytes(self):
        assert self.locked
        return self.state

    def target_bytes(self, role):
        assert self.locked and role in m.TARGETS
        return self.targets.get(role)

    def receipt_bytes(self, name):
        assert self.locked and name in m.RECEIPTS
        return self.receipts.get(name)

    def write_new(self, name, raw):
        assert self.locked and name in m.RECEIPTS
        assert name not in self.receipts or self.receipts[name] == raw
        self.receipts[name] = raw
        if name == "completed.json":
            self.completion_durable = False
            if self.interrupt_before_completion_sync:
                raise self.interruption
            self.completion_durable = True
        self._durable("receipt", name)

    def install_new(self, role, raw):
        assert self.locked and role in m.TARGETS
        assert self.receipts["state-before.json"] == self.plan.state_before
        assert self.receipts["pins-before.json"] == self.plan.pins_before
        assert "intent.json" in self.receipts
        assert role not in self.targets or self.targets[role] == raw
        self.targets[role] = raw
        self._durable("install", role)

    def replace_state(self, expected, raw):
        assert self.locked and self.state == expected == self.plan.state_before
        assert raw == self.plan.state_after and self.targets == dict(self.plan.sources)
        self.state = raw
        self.replacements += 1
        self.state_durable = False
        if self.interrupt_after_rename:
            raise self.interruption
        self.state_durable = True
        self._durable("activate", "state.json")

    def seal_state(self, expected_raw):
        assert self.locked and self.state == expected_raw == self.plan.state_after
        self.state_durable = True
        self.state_seals += 1
        self._durable("seal", "state.json")

    def observe(self, phase, intent_sha256=None):
        assert self.locked
        if intent_sha256 is not None:
            assert m.sha(self.receipts["intent.json"]) == intent_sha256
        self.observations += 1
        self.events.append(("observe", phase))
        if self.observations == self.fail_observation:
            raise self.interruption
        if "completed.json" in self.receipts:
            completed = m.json_object(self.receipts["completed.json"])
            if completed["verification"] != self.acceptances.get(completed["verification"]["attempt"]):
                raise m.AdoptionRefusal("retained acceptance proof differs")
        return {"phase": phase, "generation": 9, "rewrites": 5,
                "baseline_state_sha256": m.OLD_STATE_SHA256, "checkpoint_sha256": m.CHECKPOINT_SHA256,
                "state_sha256": m.sha(self.state),
                "pins_sha256": m.sha(self.plan.pins_before if phase == "before" else self.plan.pins_after),
                "observation_index": self.observations}

    def verify(self, intent_sha256):
        assert self.locked and self.state == self.plan.state_after and self.state_durable
        assert m.sha(self.receipts["intent.json"]) == intent_sha256
        self.verifications += 1
        if self.verification_error is not None:
            raise self.verification_error
        attempt = self.verifications
        value = {"schema": 1, "verified": True, "attempt": attempt, "path": f"acceptance/{attempt:06d}",
                 "checkpoint_sha256": m.CHECKPOINT_SHA256, "semantic_projection_sha256": m.PROJECTION_SHA256,
                 "result_sha256": "a" * 64, "metrics_sha256": "b" * 64, "receipt_sha256": "c" * 64}
        if self.verification_change is not None:
            self.verification_change(value)
        self.acceptances[attempt] = copy.deepcopy(value)
        self._durable("verify", attempt)
        if self.after_verification is not None:
            self.after_verification(self)
        return value

    def now(self):
        assert self.locked
        self.clock += 1
        return self.clock


class PlanTests(unittest.TestCase):
    def test_real_certified_preimage_changes_exactly_two_binding_hashes(self):
        plan = plan_fixture()
        self.assertEqual((len(plan.state_before), m.sha(plan.state_before)), (7318, m.OLD_STATE_SHA256))
        self.assertEqual((len(plan.pins_before), m.sha(plan.pins_before)), (264, m.OLD_PINS_SHA256))
        before, after = map(m.json_object, (plan.state_before, plan.state_after))
        old_binding, new_binding = before.pop("binding"), after.pop("binding")
        self.assertEqual(before, after)
        self.assertEqual({key for key in old_binding if old_binding[key] != new_binding[key]},
                         {"controller_sha256", "verifier_sha256"})
        self.assertEqual(new_binding["limits"], legacy.LIMITS)
        self.assertEqual((after["generation"], after["rewrites"], after["pending"]), (9, 5, None))
        self.assertEqual(m.sha(m.canonical(after["checkpoint"])), m.CHECKPOINT_SHA256)
        self.assertEqual(set(plan.artifacts()), {"controller", "verifier", "scanner", "pins"})
        self.assertNotIn("run_rhea_full_clone_steps.py", {row["path"] for row in plan.artifacts().values()})

    def test_refuses_changed_preimages_sources_or_unbound_provenance(self):
        plan = plan_fixture()
        sources = {role: raw for role, raw in plan.sources if role != "pins"}
        provenance = m.json_object(plan.provenance_raw)
        cases = [dict(state_before_raw=plan.state_before + b" "),
                 dict(pins_before_raw=plan.pins_before + b" "),
                 dict(sources=dict(sources, controller=sources["controller"] + b"\n")),
                 dict(sources={key: value for key, value in sources.items() if key != "scanner"}),
                 dict(sources=dict(sources, arbitrary=b"not allowed")),
                 dict(provenance=dict(provenance, source_commit="not a commit")),
                 dict(provenance=dict(provenance, engine_sha256="")),
                 dict(provenance=dict(provenance, schema=True)),
                 dict(provenance=dict(provenance, arbitrary_path="/outside"))]
        for changed in cases:
            args = dict(state_before_raw=plan.state_before, pins_before_raw=plan.pins_before,
                        sources=sources, provenance=provenance)
            args.update(changed)
            with self.subTest(changed=list(changed)), self.assertRaises(m.AdoptionRefusal):
                m.build_plan(**args)

    def test_refuses_forged_plan_even_when_constructed_without_builder(self):
        plan = plan_fixture()
        for changed in (plan._replace(state_after=plan.state_before), plan._replace(pins_after=plan.pins_before),
                        plan._replace(sources=plan.sources[:-1]), plan._replace(provenance_raw=b"{}\n")):
            with self.subTest(changed=changed._fields), self.assertRaises(m.AdoptionRefusal):
                m.Transaction(Adapter(plan), changed)

    def test_receipt_parser_refuses_duplicate_noncanonical_and_nonfinite_json(self):
        for raw in (b'{"schema":1,"schema":1}\n', b'{ "schema": 1 }\n', b'{"x":NaN}\n',
                    b'[]\n', b'{}', "{}\n", b"x" * (m.MAX_JSON + 1)):
            with self.subTest(raw_type=type(raw)), self.assertRaises(m.AdoptionRefusal):
                m.json_object(raw)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()

    def engine(self, adapter):
        return m.Transaction(adapter, self.plan)

    def test_success_preserves_history_and_orders_intent_commit_proof_final_health(self):
        adapter = Adapter(self.plan)
        history = copy.deepcopy(adapter.historical)
        result = self.engine(adapter).run("apply")
        durable = [event for event in adapter.events if event[0] != "observe"]
        self.assertEqual(durable, [("receipt", "state-before.json"), ("receipt", "pins-before.json"),
            ("receipt", "intent.json"), ("install", "controller"), ("install", "verifier"),
            ("install", "scanner"), ("install", "pins"), ("activate", "state.json"),
            ("verify", 1), ("receipt", "completed.json")])
        self.assertEqual(adapter.events[-3:], [("verify", 1), ("observe", "after"), ("receipt", "completed.json")])
        self.assertEqual(adapter.historical, history)
        self.assertEqual(adapter.state, self.plan.state_after)
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 1))
        self.assertFalse(result["resumed"])
        self.assertTrue(result["state_replaced_this_run"])
        self.assertFalse(result["database_writer_invoked"])
        self.assertFalse(result["pebble_open_performed"])
        self.assertEqual(result["after"]["observation_index"], 4)
        self.assertFalse(adapter.locked)

    def test_check_never_installs_activates_or_runs_acceptance(self):
        adapter = Adapter(self.plan)
        result = self.engine(adapter).run("check")
        self.assertEqual(result["phase"], "unprepared")
        self.assertEqual((adapter.durable_operations, adapter.verifications, adapter.replacements), (0, 0, 0))
        self.assertEqual(adapter.state, self.plan.state_before)
        with self.assertRaises(m.AdoptionRefusal):
            self.engine(adapter).run("resume")
        with self.assertRaises(m.AdoptionRefusal):
            self.engine(adapter).run("--arbitrary")

    def test_interruption_after_every_durable_boundary_resumes_without_second_activation(self):
        for boundary in range(1, 11):
            with self.subTest(boundary=boundary):
                adapter = Adapter(self.plan, interrupt_after=boundary)
                history = copy.deepcopy(adapter.historical)
                with self.assertRaises(Interrupted) as raised:
                    self.engine(adapter).run("apply")
                self.assertIs(raised.exception, adapter.interruption)
                self.assertFalse(adapter.locked)
                self.assertIn(adapter.state, (self.plan.state_before, self.plan.state_after))
                old_intent = adapter.receipts.get("intent.json")
                old_completed = adapter.receipts.get("completed.json")
                adapter.interrupt_after = None
                result = self.engine(adapter).run("resume")
                self.assertEqual(adapter.state, self.plan.state_after)
                self.assertEqual(adapter.replacements, 1)
                self.assertEqual(adapter.historical, history)
                self.assertEqual(adapter.receipts["state-before.json"], self.plan.state_before)
                self.assertEqual(adapter.receipts["pins-before.json"], self.plan.pins_before)
                if old_intent is not None:
                    self.assertEqual(adapter.receipts["intent.json"], old_intent)
                if old_completed is not None:
                    self.assertEqual(adapter.receipts["completed.json"], old_completed)
                    self.assertEqual(result["phase"], "completed")
                else:
                    self.assertTrue(result["resumed"])
                    self.assertEqual(result["state_replaced_this_run"], boundary < 8)
                self.assertEqual(adapter.verifications, 2 if boundary == 9 else 1)

    def test_existing_exact_targets_are_resealed_and_never_replaced(self):
        adapter = Adapter(self.plan)
        adapter.targets = dict(self.plan.sources)
        originals = dict(adapter.targets)
        self.engine(adapter).run("apply")
        self.assertEqual(adapter.targets, originals)
        self.assertEqual([name for event, name in adapter.events if event == "install"], list(m.TARGETS))

    def test_resume_seals_rename_before_directory_fsync_gap_without_replacing_again(self):
        adapter = Adapter(self.plan)
        adapter.interrupt_after_rename = True
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        self.assertEqual(adapter.state, self.plan.state_after)
        self.assertFalse(adapter.state_durable)
        self.assertEqual((adapter.replacements, adapter.verifications, adapter.state_seals), (1, 0, 0))
        intent = adapter.receipts["intent.json"]
        adapter.interrupt_after_rename = False
        result = self.engine(adapter).run("resume")
        self.assertEqual((adapter.replacements, adapter.verifications, adapter.state_seals), (1, 1, 1))
        self.assertTrue(adapter.state_durable)
        self.assertLess(adapter.events.index(("seal", "state.json")), adapter.events.index(("verify", 1)))
        self.assertEqual(adapter.receipts["intent.json"], intent)
        self.assertTrue(result["resumed"])
        self.assertFalse(result["state_replaced_this_run"])

    def test_apply_never_replays_a_prepared_or_completed_transaction(self):
        for boundary in (1, 3, 7, 8, 10):
            adapter = Adapter(self.plan, interrupt_after=boundary)
            with self.assertRaises(Interrupted):
                self.engine(adapter).run("apply")
            adapter.interrupt_after = None
            before = (adapter.state, dict(adapter.targets), dict(adapter.receipts), adapter.durable_operations)
            with self.subTest(boundary=boundary), self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("apply")
            self.assertEqual((adapter.state, adapter.targets, adapter.receipts, adapter.durable_operations), before)

    def test_completed_resume_reseals_same_receipt_and_check_only_observes(self):
        adapter = Adapter(self.plan)
        self.engine(adapter).run("apply")
        before = (dict(adapter.receipts), adapter.verifications, adapter.replacements, adapter.state_seals)
        durable = adapter.durable_operations
        for action in ("resume", "check"):
            result = self.engine(adapter).run(action)
            self.assertEqual(result["phase"], "completed")
            self.assertEqual(result["completed_sha256"], m.sha(adapter.receipts["completed.json"]))
        self.assertEqual((adapter.receipts, adapter.verifications, adapter.replacements, adapter.state_seals), before)
        self.assertEqual(adapter.durable_operations, durable + 1)

    def test_completed_resume_closes_receipt_directory_fsync_gap_without_new_proof(self):
        adapter = Adapter(self.plan)
        adapter.interrupt_before_completion_sync = True
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        saved = adapter.receipts["completed.json"]
        self.assertFalse(adapter.completion_durable)
        self.assertTrue(adapter.state_durable)
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 1))
        adapter.interrupt_before_completion_sync = False
        result = self.engine(adapter).run("resume")
        self.assertEqual((adapter.replacements, adapter.verifications, adapter.state_seals), (1, 1, 0))
        self.assertTrue(adapter.completion_durable)
        self.assertEqual(adapter.receipts["completed.json"], saved)
        self.assertEqual(result["completed_sha256"], m.sha(saved))

    def test_completed_resume_refuses_receipt_changed_after_health_before_reseal(self):
        adapter = Adapter(self.plan)
        self.engine(adapter).run("apply")
        observe = adapter.observe

        def changed_after_observation(*args, **kwargs):
            result = observe(*args, **kwargs)
            adapter.receipts["completed.json"] += b" "
            return result

        adapter.observe = changed_after_observation
        durable = adapter.durable_operations
        with self.assertRaisesRegex(m.AdoptionRefusal, "immutable adoption receipt differs"):
            self.engine(adapter).run("resume")
        self.assertEqual(adapter.durable_operations, durable)
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 1))

    def test_unknown_state_or_conflicting_target_refuses_before_any_write(self):
        for tamper in (lambda a: setattr(a, "state", a.state + b" "),
                       lambda a: a.targets.update(controller=b"unknown controller"),
                       lambda a: a.targets.update(pins=self.plan.pins_before)):
            adapter = Adapter(self.plan)
            tamper(adapter)
            with self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("apply")
            self.assertEqual((adapter.durable_operations, adapter.verifications, adapter.replacements), (0, 0, 0))

    def activated(self):
        adapter = Adapter(self.plan, interrupt_after=8)
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        adapter.interrupt_after = None
        return adapter

    def test_activated_resume_requires_all_exact_sources_and_durable_preimages_intent(self):
        mutations = (lambda a: a.targets.pop("verifier"), lambda a: a.targets.update(scanner=b"different"),
                     lambda a: a.receipts.pop("intent.json"), lambda a: a.receipts.pop("state-before.json"),
                     lambda a: a.receipts.update({"pins-before.json": self.plan.pins_after}),
                     lambda a: a.receipts.update({"intent.json": b"{}\n"}))
        for mutate in mutations:
            adapter = self.activated()
            mutate(adapter)
            durable = adapter.durable_operations
            with self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("resume")
            self.assertEqual(adapter.durable_operations, durable)
            self.assertEqual((adapter.replacements, adapter.verifications), (1, 0))

    def test_verification_failure_leaves_activated_state_and_requires_explicit_fresh_acceptance(self):
        adapter = Adapter(self.plan)
        error = OSError("injected read-only verification failure")
        adapter.verification_error = error
        with self.assertRaises(OSError) as raised:
            self.engine(adapter).run("apply")
        self.assertIs(raised.exception, error)
        self.assertEqual(adapter.state, self.plan.state_after)
        self.assertNotIn("completed.json", adapter.receipts)
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 1))
        adapter.verification_error = None
        result = self.engine(adapter).run("resume")
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 2))
        self.assertFalse(result["state_replaced_this_run"])
        self.assertEqual(result["verification"]["path"], "acceptance/000002")

    def test_final_health_failure_cannot_emit_completion_after_good_proof(self):
        adapter = Adapter(self.plan)
        adapter.fail_observation = 4
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 1))
        self.assertNotIn("completed.json", adapter.receipts)
        adapter.fail_observation = None
        self.engine(adapter).run("resume")
        self.assertEqual((adapter.replacements, adapter.verifications), (1, 2))

    def test_state_sources_and_intent_are_rechecked_after_acceptance(self):
        mutations = (lambda a: setattr(a, "state", self.plan.state_before),
                     lambda a: a.targets.update(controller=b"changed after proof"),
                     lambda a: a.receipts.update({"state-before.json": b"changed"}))
        for mutate in mutations:
            adapter = Adapter(self.plan)
            adapter.after_verification = mutate
            with self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("apply")
            self.assertNotIn("completed.json", adapter.receipts)
            self.assertEqual(adapter.replacements, 1)

    def test_invalid_acceptance_refs_do_not_complete_or_roll_back(self):
        changes = ({"verified": False}, {"attempt": True}, {"path": "../outside"},
                   {"attempt": 2}, {"checkpoint_sha256": "d" * 64},
                   {"semantic_projection_sha256": "d" * 64}, {"result_sha256": ""},
                   {"extra_callback": "forbidden"})
        for change in changes:
            adapter = Adapter(self.plan)
            adapter.verification_change = lambda value: value.update(change)
            with self.subTest(change=change), self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("apply")
            self.assertNotIn("completed.json", adapter.receipts)
            self.assertEqual(adapter.state, self.plan.state_after)
            self.assertEqual(adapter.replacements, 1)

    def test_completed_check_rejects_changed_receipt_and_independently_rechecked_proof(self):
        for field, value in (("intent_sha256", "d" * 64), ("state_sha256", m.OLD_STATE_SHA256),
                             ("database_writer_invoked", True), ("completed_unix", 0)):
            adapter = Adapter(self.plan)
            self.engine(adapter).run("apply")
            completed = m.json_object(adapter.receipts["completed.json"])
            completed[field] = value
            adapter.receipts["completed.json"] = m.canonical(completed)
            with self.subTest(field=field), self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("check")
        adapter = Adapter(self.plan)
        self.engine(adapter).run("apply")
        completed = m.json_object(adapter.receipts["completed.json"])
        completed["verification"]["result_sha256"] = "d" * 64
        adapter.receipts["completed.json"] = m.canonical(completed)
        with self.assertRaisesRegex(m.AdoptionRefusal, "retained acceptance proof"):
            self.engine(adapter).run("resume")

    def test_adapter_readback_mismatch_prevents_following_phase(self):
        for operation in ("write_new", "install_new", "replace_state"):
            adapter = Adapter(self.plan)
            setattr(adapter, operation, lambda *args: None)
            with self.subTest(operation=operation), self.assertRaises(m.AdoptionRefusal):
                self.engine(adapter).run("apply")
            self.assertEqual(adapter.verifications, 0)
            self.assertNotIn("completed.json", adapter.receipts)


if __name__ == "__main__":
    unittest.main()
