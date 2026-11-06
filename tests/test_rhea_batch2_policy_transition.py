"""Exact public preimages and crash-boundary checks for the policy-only engine."""
from contextlib import contextmanager
import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "batch2_policy_transaction_tests", ROOT / "scripts/rhea_batch2_policy_transition.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def plan_fixture():
    return m.build_plan(
        (ROOT / "docs/evidence/rhea-bounded-adoption-state-after-20261106.json").read_bytes(),
        (ROOT / "docs/evidence/rhea-bounded-adoption-pins-after-20261106.json").read_bytes(),
        {"controller": (ROOT / "scripts/run_rhea_full_clone_steps_batch2.py").read_bytes()},
        {"schema": 1, "source_commit": "1" * 40, "deployment_sha256": "2" * 64,
         "recipe_sha256": "3" * 64, "engine_sha256": "4" * 64, "health_sha256": "5" * 64})


class Interrupted(BaseException):
    pass


class Adapter:
    """No host/filesystem fallback; every mutation must hold the original lock."""
    def __init__(self, plan, *, interrupt_after=None):
        self.plan = plan
        self.state = plan.state_before
        self.targets, self.receipts = {}, {}
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
        self.fail_observation = None
        self.after_observation = None
        self.observation_change = None
        self.clock = 1000
        self.historical = {
            "controller": (ROOT / "scripts/run_rhea_full_clone_steps_bounded.py").read_bytes(),
            "verifier": (ROOT / "scripts/verify_rhea_full_clone_bounded.py").read_bytes(),
            "pins": plan.pins_before,
            "certificate": m.canonical(m.json_object(plan.state_before)["checkpoint"]),
        }

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
            assert self.state_durable
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
        value = {"phase": phase, "generation": 9, "rewrites": 5,
                 "baseline_state_sha256": m.OLD_STATE_SHA256, "checkpoint_sha256": m.CHECKPOINT_SHA256,
                 "state_sha256": m.sha(self.state),
                 "pins_sha256": m.sha(self.plan.pins_before if phase == m.BEFORE else self.plan.pins_after),
                 "observation_index": self.observations}
        if self.observation_change is not None:
            self.observation_change(value)
        if self.after_observation is not None:
            self.after_observation(self)
        return value

    def now(self):
        assert self.locked
        self.clock += 1
        return self.clock


class PlanTests(unittest.TestCase):
    def test_exact_two_leaf_policy_delta_preserves_checkpoint_and_all_other_limits(self):
        plan = plan_fixture()
        self.assertEqual((len(plan.state_before), m.sha(plan.state_before)), (7318, m.OLD_STATE_SHA256))
        self.assertEqual((len(plan.state_after), m.sha(plan.state_after)), (7318, m.NEW_STATE_SHA256))
        self.assertEqual((len(plan.pins_before), m.sha(plan.pins_before)), (264, m.OLD_PINS_SHA256))
        self.assertEqual((len(plan.pins_after), m.sha(plan.pins_after)), (264, m.NEW_PINS_SHA256))
        before, after = map(m.json_object, (plan.state_before, plan.state_after))
        original = copy.deepcopy(after)
        after["binding"]["controller_sha256"] = before["binding"]["controller_sha256"]
        after["binding"]["limits"]["maximum_rewrites"] = 5
        self.assertEqual(after, before)
        self.assertEqual(original["binding"]["limits"]["maximum_rewrites"], 9)
        self.assertEqual((original["generation"], original["rewrites"], original["pending"]), (9, 5, None))
        self.assertEqual(m.sha(m.canonical(original["checkpoint"])), m.CHECKPOINT_SHA256)
        pins_before, pins_after = map(m.json_object, (plan.pins_before, plan.pins_after))
        self.assertEqual({key for key in pins_before if pins_before[key] != pins_after[key]},
                         {"controller_sha256"})
        self.assertEqual(set(plan.artifacts()), {"controller", "pins"})
        self.assertEqual(m.expected_transition(plan.state_before, plan.pins_before),
                         (plan.state_after, plan.pins_after))

    def test_refuses_changed_preimages_source_scope_or_unbound_provenance(self):
        plan = plan_fixture()
        sources = {"controller": dict(plan.sources)["controller"]}
        provenance = m.json_object(plan.provenance_raw)
        cases = [dict(before_raw=plan.state_before + b" "), dict(pins_raw=plan.pins_before + b" "),
                 dict(before_raw=plan.state_after), dict(pins_raw=plan.pins_after),
                 dict(sources={}), dict(sources=dict(sources, verifier=b"not an install target")),
                 dict(sources={"controller": sources["controller"] + b"\n"}),
                 dict(provenance=dict(provenance, source_commit="invalid")),
                 dict(provenance=dict(provenance, engine_sha256="")),
                 dict(provenance=dict(provenance, schema=True)),
                 dict(provenance=dict(provenance, arbitrary_path="/outside"))]
        for changed in cases:
            args = dict(before_raw=plan.state_before, pins_raw=plan.pins_before,
                        sources=sources, provenance=provenance)
            args.update(changed)
            with self.subTest(changed=list(changed)), self.assertRaises(m.PolicyRefusal):
                m.build_plan(**args)

    def test_forged_plan_is_rebuilt_and_refused(self):
        plan = plan_fixture()
        for changed in (plan._replace(state_after=plan.state_before), plan._replace(pins_after=plan.pins_before),
                        plan._replace(sources=plan.sources[:-1]), plan._replace(provenance_raw=b"{}\n")):
            with self.subTest(changed=changed._fields), self.assertRaises(m.PolicyRefusal):
                m.Transaction(Adapter(plan), changed)

    def test_receipt_parser_refuses_duplicates_noncanonical_and_nonfinite_json(self):
        for raw in (b'{"schema":1,"schema":1}\n', b'{ "schema": 1 }\n', b'{"x":NaN}\n',
                    b'[]\n', b'{}', "{}\n", b"x" * (m.MAX_JSON + 1)):
            with self.subTest(raw_type=type(raw)), self.assertRaises(m.PolicyRefusal):
                m.json_object(raw)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()

    def engine(self, adapter):
        return m.Transaction(adapter, self.plan)

    def activated(self):
        adapter = Adapter(self.plan, interrupt_after=6)
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        adapter.interrupt_after = None
        return adapter

    def test_success_orders_intent_installs_single_commit_and_after_health(self):
        adapter = Adapter(self.plan)
        history = copy.deepcopy(adapter.historical)
        result = self.engine(adapter).run("apply")
        self.assertEqual(adapter.events, [("observe", m.BEFORE),
            ("receipt", "state-before.json"), ("receipt", "pins-before.json"), ("receipt", "intent.json"),
            ("install", "controller"), ("install", "pins"), ("observe", m.BEFORE),
            ("activate", "state.json"), ("observe", m.AFTER), ("receipt", "completed.json")])
        self.assertEqual(adapter.historical, history)
        self.assertEqual(adapter.state, self.plan.state_after)
        self.assertEqual(adapter.replacements, 1)
        self.assertFalse(result["resumed"])
        self.assertTrue(result["state_replaced_this_run"])
        for key in ("database_writer_invoked", "pebble_open_performed", "service_action_performed"):
            self.assertIs(result[key], False)
        self.assertNotIn("verification", result)
        self.assertEqual(m.validate_intent(adapter.receipts["intent.json"], self.plan)["before"]["phase"], m.BEFORE)
        self.assertEqual(m.validate_completed(adapter.receipts["completed.json"],
                                             adapter.receipts["intent.json"], self.plan), result)
        self.assertFalse(adapter.locked)

    def test_check_is_read_only_at_unprepared_partial_intent_and_activated_states(self):
        for boundary, phase in ((None, "unprepared"), (1, "preparing"), (3, "prepared"), (6, "activated")):
            adapter = Adapter(self.plan, interrupt_after=boundary)
            if boundary is not None:
                with self.assertRaises(Interrupted):
                    self.engine(adapter).run("apply")
                adapter.interrupt_after = None
            before = (adapter.state, dict(adapter.targets), dict(adapter.receipts), adapter.durable_operations)
            self.assertEqual(self.engine(adapter).run("check")["phase"], phase)
            self.assertEqual((adapter.state, adapter.targets, adapter.receipts, adapter.durable_operations), before)
        with self.assertRaises(m.PolicyRefusal):
            self.engine(Adapter(self.plan)).run("resume")
        with self.assertRaises(m.PolicyRefusal):
            self.engine(Adapter(self.plan)).run("arbitrary")

    def test_every_durable_boundary_resumes_without_second_activation(self):
        for boundary in range(1, 8):
            with self.subTest(boundary=boundary):
                adapter = Adapter(self.plan, interrupt_after=boundary)
                history = copy.deepcopy(adapter.historical)
                with self.assertRaises(Interrupted) as raised:
                    self.engine(adapter).run("apply")
                self.assertIs(raised.exception, adapter.interruption)
                self.assertFalse(adapter.locked)
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
                    self.assertEqual(result["state_replaced_this_run"], boundary < 6)

    def test_apply_never_replays_recorded_work_and_existing_exact_targets_are_resealed(self):
        for boundary in (1, 3, 5, 6, 7):
            adapter = Adapter(self.plan, interrupt_after=boundary)
            with self.assertRaises(Interrupted):
                self.engine(adapter).run("apply")
            adapter.interrupt_after = None
            before = (adapter.state, dict(adapter.targets), dict(adapter.receipts), adapter.durable_operations)
            with self.subTest(boundary=boundary), self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("apply")
            self.assertEqual((adapter.state, adapter.targets, adapter.receipts, adapter.durable_operations), before)
        adapter = Adapter(self.plan)
        adapter.targets = dict(self.plan.sources)
        original = dict(adapter.targets)
        self.engine(adapter).run("apply")
        self.assertEqual(adapter.targets, original)
        self.assertEqual([name for event, name in adapter.events if event == "install"], list(m.TARGETS))

    def test_resume_reseals_rename_before_directory_sync_without_replacing_again(self):
        adapter = Adapter(self.plan)
        adapter.interrupt_after_rename = True
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        self.assertFalse(adapter.state_durable)
        self.assertEqual(adapter.state, self.plan.state_after)
        intent = adapter.receipts["intent.json"]
        adapter.interrupt_after_rename = False
        result = self.engine(adapter).run("resume")
        self.assertTrue(adapter.state_durable)
        self.assertEqual((adapter.replacements, adapter.state_seals), (1, 1))
        self.assertLess(adapter.events.index(("seal", "state.json")),
                        adapter.events.index(("receipt", "completed.json")))
        self.assertEqual(adapter.receipts["intent.json"], intent)
        self.assertTrue(result["resumed"])
        self.assertFalse(result["state_replaced_this_run"])

    def test_completed_check_only_observes_and_resume_reseals_identical_completion(self):
        adapter = Adapter(self.plan)
        adapter.interrupt_before_completion_sync = True
        with self.assertRaises(Interrupted):
            self.engine(adapter).run("apply")
        saved = adapter.receipts["completed.json"]
        self.assertFalse(adapter.completion_durable)
        adapter.interrupt_before_completion_sync = False
        before = (dict(adapter.receipts), adapter.replacements, adapter.state_seals, adapter.durable_operations)
        result = self.engine(adapter).run("check")
        self.assertEqual((adapter.receipts, adapter.replacements, adapter.state_seals, adapter.durable_operations), before)
        self.assertFalse(adapter.completion_durable)
        resumed = self.engine(adapter).run("resume")
        self.assertEqual(resumed, result)
        self.assertEqual(adapter.receipts["completed.json"], saved)
        self.assertTrue(adapter.completion_durable)
        self.assertEqual((adapter.replacements, adapter.state_seals), (1, 0))
        self.assertEqual(adapter.durable_operations, before[-1] + 1)

    def test_unknown_state_conflicting_sources_and_partial_receipts_refuse_without_write(self):
        mutations = (lambda a: setattr(a, "state", a.state + b" "),
                     lambda a: a.targets.update(controller=b"unknown"),
                     lambda a: a.targets.update(pins=self.plan.pins_before),
                     lambda a: a.receipts.update({"state-before.json": b"partial"}))
        for mutate in mutations:
            adapter = Adapter(self.plan)
            mutate(adapter)
            with self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("apply")
            self.assertEqual((adapter.durable_operations, adapter.replacements), (0, 0))

    def test_activated_resume_requires_all_sources_exact_preimages_and_intent(self):
        mutations = (lambda a: a.targets.pop("pins"), lambda a: a.targets.update(controller=b"different"),
                     lambda a: a.receipts.pop("intent.json"), lambda a: a.receipts.pop("state-before.json"),
                     lambda a: a.receipts.update({"pins-before.json": self.plan.pins_after}),
                     lambda a: a.receipts.update({"intent.json": b"{}\n"}))
        for mutate in mutations:
            adapter = self.activated()
            mutate(adapter)
            durable = adapter.durable_operations
            with self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("resume")
            self.assertEqual(adapter.durable_operations, durable)
            self.assertEqual(adapter.replacements, 1)

    def test_after_health_failure_keeps_activation_without_completion_or_automatic_retry(self):
        adapter = Adapter(self.plan)
        adapter.fail_observation = 3
        with self.assertRaises(Interrupted) as raised:
            self.engine(adapter).run("apply")
        self.assertIs(raised.exception, adapter.interruption)
        self.assertEqual(adapter.state, self.plan.state_after)
        self.assertNotIn("completed.json", adapter.receipts)
        self.assertEqual(adapter.replacements, 1)
        adapter.fail_observation = None
        self.engine(adapter).run("resume")
        self.assertEqual((adapter.replacements, adapter.state_seals), (1, 1))

    def test_health_phase_progress_and_full_state_sources_are_rechecked(self):
        changes = ({"phase": "before"}, {"generation": 10}, {"rewrites": True},
                   {"baseline_state_sha256": "0" * 64}, {"checkpoint_sha256": "0" * 64},
                   {"state_sha256": m.NEW_STATE_SHA256}, {"pins_sha256": m.NEW_PINS_SHA256})
        for change in changes:
            adapter = Adapter(self.plan)
            adapter.observation_change = lambda value: value.update(change)
            with self.subTest(change=change), self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("apply")
            self.assertEqual(adapter.durable_operations, 0)
        for mutate in (lambda a: setattr(a, "state", self.plan.state_before),
                       lambda a: a.targets.update(controller=b"changed"),
                       lambda a: a.receipts.update({"state-before.json": b"changed"})):
            adapter = Adapter(self.plan)
            adapter.after_observation = lambda a: mutate(a) if a.observations == 3 else None
            with self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("apply")
            self.assertNotIn("completed.json", adapter.receipts)

    def test_completed_receipts_reject_changed_types_links_and_mutations_during_health(self):
        for field, value in (("schema", True), ("intent_sha256", "d" * 64),
                             ("state_sha256", m.OLD_STATE_SHA256), ("generation", 10),
                             ("database_writer_invoked", 0), ("pebble_open_performed", True),
                             ("service_action_performed", True), ("completed_unix", 0),
                             ("resumed", 0), ("extra", "unrecognized")):
            adapter = Adapter(self.plan)
            self.engine(adapter).run("apply")
            completed = m.json_object(adapter.receipts["completed.json"])
            completed[field] = value
            adapter.receipts["completed.json"] = m.canonical(completed)
            durable = adapter.durable_operations
            with self.subTest(field=field), self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("resume")
            self.assertEqual(adapter.durable_operations, durable)
        for name in m.RECEIPTS:
            adapter = Adapter(self.plan)
            self.engine(adapter).run("apply")
            adapter.after_observation = lambda a: a.receipts.update({name: a.receipts[name] + b" "})
            durable = adapter.durable_operations
            with self.subTest(name=name), self.assertRaisesRegex(m.PolicyRefusal, "evidence changed"):
                self.engine(adapter).run("resume")
            self.assertEqual(adapter.durable_operations, durable)

    def test_public_intent_validation_rejects_coerced_types_and_other_delta(self):
        adapter = Adapter(self.plan)
        self.engine(adapter).run("apply")
        intent = m.json_object(adapter.receipts["intent.json"])
        for change in ({"schema": True}, {"new_state_sha256": "d" * 64}, {"started_unix": False},
                       {"scope": "other"}, {"rewrites": 6}, {"extra": "field"}):
            value = copy.deepcopy(intent)
            value.update(change)
            with self.subTest(change=change), self.assertRaises(m.PolicyRefusal):
                m.validate_intent(m.canonical(value), self.plan)

    def test_adapter_readback_mismatch_stops_before_following_phase(self):
        for operation in ("write_new", "install_new", "replace_state"):
            adapter = Adapter(self.plan)
            setattr(adapter, operation, lambda *args: None)
            with self.subTest(operation=operation), self.assertRaises(m.PolicyRefusal):
                self.engine(adapter).run("apply")
            self.assertNotIn("completed.json", adapter.receipts)


if __name__ == "__main__":
    unittest.main()
