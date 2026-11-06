#!/usr/bin/env python3
"""Pure transaction for the fixed generation-nine second-batch policy change.

The separately pinned root adapter owns protected paths, source staging, process
deadlines and health observations. All adapter calls below run under its original
lifecycle lock; the original Runtime and its wrapper keep ownership of host and
Profile objects. This module performs no filesystem setup, service operation,
SDK call, Pebble open or writer launch. Only the shared journal activates policy.

Adapter contract:
  lock() -> original lifecycle lock context manager
  state_bytes(), target_bytes(role), receipt_bytes(name) -> bytes or None
  write_new(name, raw), install_new(role, raw)
      Exclusive create, or validate and fsync existing exact bytes; never replace.
      Fsync the file and parent directory before returning.
  replace_state(expected_raw, new_raw)
      Compare the exact preimage, write/fsync a temporary file, atomically replace
      the one journal path, then fsync its parent before returning.
  seal_state(expected_raw)
      Validate and fsync the already activated file and parent without replacing
      it; used only by explicit unfinished resume.
  observe(phase, intent_sha256=None) -> independently validated health dictionary
      Phases are policy-before and policy-after. Both require the restored reader
      active, writer absent, frozen production and the retained post-reboot proof.
      Before permits absent-or-exact successor files; after validates their full
      binding and all fixed preimages/intent. Host work stays on the original rt.
  now() -> finite nonnegative Unix timestamp

The adapter must pin this engine, reject symlinks/unsafe ownership or modes, and
expose only TARGETS and RECEIPTS in the fixed pacing-batch2-20261107 namespace.
Original sources/pins, certificates, services and caches are never replacements.
Exceptions propagate without retry or rollback. An incomplete exclusive file is
an unknown endpoint and requires inspection; resume never overwrites it. Resume
may finish absent-or-exact prepared work or reseal exact activated/completed bytes.
Check remains read-only. This transaction authorizes no rewrite invocation: the
first new unit and each subsequent unit require separate controller commands.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from typing import NamedTuple


OPS_NAME = "pacing-batch2-20261107"
OLD_STATE_SHA256 = "22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2"
NEW_STATE_SHA256 = "0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9"
OLD_PINS_SHA256 = "684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c"
NEW_PINS_SHA256 = "1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363"
CHECKPOINT_SHA256 = "220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2"
OLD_CONTROLLER_SHA256 = "56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a"
CONTROLLER_SHA256 = "b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828"
VERIFIER_SHA256 = "43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796"
GO_SHA256 = "1bc58ef8ca76a97fc9886d90f4a3df4fdd3d07549403988e3798834a61207125"
TARGETS = {
    "controller": "run_rhea_full_clone_steps_batch2.py",
    "pins": "full-clone-batch2-step-pins.json",
}
SOURCE_HASHES = {"controller": CONTROLLER_SHA256}
RECEIPTS = ("state-before.json", "pins-before.json", "intent.json", "completed.json")
BEFORE = "policy-before"
AFTER = "policy-after"
INTENT_SCOPE = "fixed-generation-nine-batch2-policy-intent"
COMPLETED_SCOPE = "fixed-generation-nine-batch2-policy-completed"
MAX_JSON = 256 * 1024
MAX_SOURCE = 512 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


class PolicyRefusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise PolicyRefusal(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def json_object(raw):
    require(type(raw) is bytes and len(raw) <= MAX_JSON, "receipt type or size differs")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate receipt field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        require(type(value) is dict and canonical(value) == raw, "receipt must be a canonical JSON object")
    except (UnicodeError, ValueError, TypeError) as error:
        raise PolicyRefusal("invalid JSON receipt") from error
    return value


def timestamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def hash_string(value):
    return type(value) is str and SHA256.fullmatch(value) is not None


def validate_provenance(value):
    require(type(value) is dict and set(value) == {"schema", "source_commit", "deployment_sha256",
            "recipe_sha256", "engine_sha256", "health_sha256"}, "provenance fields differ")
    require(type(value["schema"]) is int and value["schema"] == 1
            and type(value["source_commit"]) is str and COMMIT.fullmatch(value["source_commit"]),
            "provenance schema or commit differs")
    require(all(hash_string(value[key]) for key in value if key.endswith("_sha256")),
            "provenance digest differs")


def expected_transition(before_raw, pins_raw):
    """Return exact new journal/pins bytes; only the two approved leaves change."""
    require(type(before_raw) is bytes and sha(before_raw) == OLD_STATE_SHA256,
            "original certified state differs")
    require(type(pins_raw) is bytes and sha(pins_raw) == OLD_PINS_SHA256,
            "original deployment pins differ")
    before, old_pins = json_object(before_raw), json_object(pins_raw)
    require(before["generation"] == 9 and before["rewrites"] == 5 and before["pending"] is None
            and before["binding"]["limits"]["maximum_rewrites"] == 5
            and sha(canonical(before["checkpoint"])) == CHECKPOINT_SHA256,
            "historical checkpoint progress differs")
    require(old_pins["controller_sha256"] == before["binding"]["controller_sha256"] == OLD_CONTROLLER_SHA256
            and old_pins["verifier_sha256"] == before["binding"]["verifier_sha256"] == VERIFIER_SHA256
            and old_pins["go_sha256"] == before["binding"]["go_sha256"] == GO_SHA256,
            "historical tool binding differs")
    after, new_pins = copy.deepcopy(before), dict(old_pins)
    after["binding"]["controller_sha256"] = new_pins["controller_sha256"] = CONTROLLER_SHA256
    after["binding"]["limits"]["maximum_rewrites"] = 9
    state_after, pins_after = canonical(after), canonical(new_pins)
    require(sha(state_after) == NEW_STATE_SHA256 and sha(pins_after) == NEW_PINS_SHA256,
            "derived policy endpoint differs")
    return state_after, pins_after


class Plan(NamedTuple):
    state_before: bytes
    pins_before: bytes
    state_after: bytes
    pins_after: bytes
    sources: tuple[tuple[str, bytes], ...]
    provenance_raw: bytes

    def artifacts(self):
        return {role: {"path": TARGETS[role], "sha256": sha(raw), "bytes": len(raw)}
                for role, raw in self.sources}

    def intent_fields(self):
        return {"schema": 1, "scope": INTENT_SCOPE, "provenance": json_object(self.provenance_raw),
                "generation": 9, "rewrites": 5, "checkpoint_sha256": CHECKPOINT_SHA256,
                "old_state_sha256": sha(self.state_before), "new_state_sha256": sha(self.state_after),
                "old_pins_sha256": sha(self.pins_before), "new_pins_sha256": sha(self.pins_after),
                "old_binding": json_object(self.state_before)["binding"],
                "new_binding": json_object(self.state_after)["binding"], "artifacts": self.artifacts()}


def build_plan(before_raw, pins_raw, sources, provenance):
    """Bind the exact adopted journal, old pins and reviewed successor controller."""
    state_after, pins_after = expected_transition(before_raw, pins_raw)
    require(type(sources) is dict and set(sources) == set(SOURCE_HASHES), "source role set differs")
    for role, expected in SOURCE_HASHES.items():
        require(type(sources[role]) is bytes and 0 < len(sources[role]) <= MAX_SOURCE
                and sha(sources[role]) == expected, "reviewed source differs: " + role)
    validate_provenance(provenance)
    artifacts = tuple((role, sources[role] if role != "pins" else pins_after) for role in TARGETS)
    return Plan(before_raw, pins_raw, state_after, pins_after, artifacts, canonical(provenance))


def validate_observation(value, phase, plan):
    require(phase in (BEFORE, AFTER), "policy health phase differs")
    require(type(value) is dict and value.get("phase") == phase
            and type(value.get("generation")) is int and value["generation"] == 9
            and type(value.get("rewrites")) is int and value["rewrites"] == 5
            and value.get("baseline_state_sha256") == OLD_STATE_SHA256
            and value.get("checkpoint_sha256") == CHECKPOINT_SHA256,
            "policy health checkpoint or phase differs")
    require(value.get("state_sha256") == sha(plan.state_before if phase == BEFORE else plan.state_after)
            and value.get("pins_sha256") == sha(plan.pins_before if phase == BEFORE else plan.pins_after),
            "policy health binding differs")
    require(len(canonical(value)) <= MAX_JSON, "health observation exceeds bound")


def validate_intent(raw, plan):
    """Validate the retained intent without consulting host or current state."""
    value = json_object(raw)
    fields = plan.intent_fields()
    require(set(value) == set(fields) | {"started_unix", "before"}
            and canonical({key: value[key] for key in fields}) == canonical(fields)
            and timestamp(value["started_unix"]), "durable policy intent differs")
    validate_observation(value["before"], BEFORE, plan)
    return value


def validate_completed(raw, intent_raw, plan):
    """Validate fixed completion semantics; current health remains the caller's job."""
    intent = validate_intent(intent_raw, plan)
    value = json_object(raw)
    expected = {"schema": 1, "scope": COMPLETED_SCOPE, "intent_sha256": sha(intent_raw),
                "generation": 9, "rewrites": 5, "checkpoint_sha256": CHECKPOINT_SHA256,
                "state_sha256": sha(plan.state_after), "pins_sha256": sha(plan.pins_after),
                "artifacts": plan.artifacts(), "database_writer_invoked": False,
                "pebble_open_performed": False, "service_action_performed": False}
    require(set(value) == set(expected) | {"completed_unix", "after", "resumed", "state_replaced_this_run"}
            and canonical({key: value[key] for key in expected}) == canonical(expected)
            and timestamp(value["completed_unix"]) and value["completed_unix"] >= intent["started_unix"]
            and type(value["resumed"]) is type(value["state_replaced_this_run"]) is bool,
            "completed policy receipt differs")
    validate_observation(value["after"], AFTER, plan)
    return value


class Transaction:
    """Fixed two-artifact installation with one state-only policy activation."""
    def __init__(self, adapter, plan):
        require(isinstance(plan, Plan), "validated policy plan required")
        source_bytes = {role: raw for role, raw in plan.sources if role != "pins"}
        require(plan == build_plan(plan.state_before, plan.pins_before, source_bytes,
                                  json_object(plan.provenance_raw)), "policy plan changed")
        self.adapter, self.plan = adapter, plan

    def _state(self):
        raw = self.adapter.state_bytes()
        require(raw in (self.plan.state_before, self.plan.state_after),
                "current state is not an exact transition endpoint")
        return BEFORE if raw == self.plan.state_before else AFTER

    def _targets(self, *, complete=False):
        installed = []
        for role, expected in self.plan.sources:
            raw = self.adapter.target_bytes(role)
            require(raw is None or raw == expected, "installed artifact differs: " + role)
            require(not complete or raw is not None, "activated artifact is missing: " + role)
            if raw is not None:
                installed.append(role)
        return installed

    def _observe(self, phase, intent_sha256=None):
        value = self.adapter.observe(phase, intent_sha256=intent_sha256)
        validate_observation(value, phase, self.plan)
        require(self._state() == phase, "state changed during health observation")
        self._targets(complete=phase == AFTER)
        return value

    def _write(self, name, raw):
        require(name in RECEIPTS and type(raw) is bytes and len(raw) <= MAX_JSON,
                "receipt destination or size differs")
        existing = self.adapter.receipt_bytes(name)
        require(existing is None or existing == raw, "immutable policy receipt differs: " + name)
        self.adapter.write_new(name, raw)
        require(self.adapter.receipt_bytes(name) == raw, "durable policy receipt readback differs: " + name)

    def _same_receipts(self, expected):
        require(all(self.adapter.receipt_bytes(name) == raw for name, raw in expected.items()),
                "policy evidence changed during health observation")

    def run(self, action):
        require(action in ("check", "apply", "resume"), "explicit fixed policy action required")
        with self.adapter.lock():
            phase = self._state()
            installed = self._targets(complete=phase == AFTER)
            saved = {name: self.adapter.receipt_bytes(name) for name in RECEIPTS}
            for name, expected in (("state-before.json", self.plan.state_before),
                                   ("pins-before.json", self.plan.pins_before)):
                require(saved[name] is None or saved[name] == expected, "policy preimage changed: " + name)
            intent_raw = saved["intent.json"]
            if intent_raw is not None:
                validate_intent(intent_raw, self.plan)
                require(saved["state-before.json"] == self.plan.state_before
                        and saved["pins-before.json"] == self.plan.pins_before,
                        "intent lacks exact durable preimages")
            require(phase != AFTER or intent_raw is not None, "activated state lacks policy intent")
            if saved["completed.json"] is not None:
                require(phase == AFTER and intent_raw is not None, "completion lacks activated state or intent")
                validate_completed(saved["completed.json"], intent_raw, self.plan)
                require(action in ("check", "resume"), "policy already completed; use check or explicit resume")
                self._observe(AFTER, sha(intent_raw))
                self._same_receipts(saved)
                if action == "resume":
                    # Completion may be visible before its directory fsync.
                    # Reseal the same bytes only after all validation succeeds.
                    self._write("completed.json", saved["completed.json"])
                return {"phase": "completed", "state_sha256": NEW_STATE_SHA256,
                        "pins_sha256": NEW_PINS_SHA256, "intent_sha256": sha(intent_raw),
                        "completed_sha256": sha(saved["completed.json"])}
            if action == "check":
                self._observe(phase, sha(intent_raw) if intent_raw is not None else None)
                self._same_receipts(saved)
                status = ("activated" if phase == AFTER else "prepared" if intent_raw is not None
                          else "preparing" if any(saved.values()) else "unprepared")
                return {"phase": status, "state_sha256": sha(self.adapter.state_bytes()),
                        "intent_sha256": sha(intent_raw) if intent_raw is not None else None,
                        "installed": installed}
            if action == "apply":
                require(phase == BEFORE and not any(value is not None for value in saved.values()),
                        "policy evidence exists; inspect and explicitly resume")
            else:
                require(any(value is not None for value in saved.values()), "no recorded policy to resume")
            before = self._observe(phase, sha(intent_raw) if intent_raw is not None else None)
            self._same_receipts(saved)
            if intent_raw is None:
                require(phase == BEFORE, "new intent requires the exact original state")
                started = self.adapter.now()
                require(timestamp(started), "invalid policy timestamp")
                intent_raw = canonical(dict(self.plan.intent_fields(), started_unix=started, before=before))
            # Revalidate and fsync exact existing preimages/intent on resume.
            self._write("state-before.json", self.plan.state_before)
            self._write("pins-before.json", self.plan.pins_before)
            self._write("intent.json", intent_raw)
            intent_sha256, replaced = sha(intent_raw), False
            retained = {"state-before.json": self.plan.state_before,
                        "pins-before.json": self.plan.pins_before, "intent.json": intent_raw}
            if phase == BEFORE:
                for role, expected in self.plan.sources:
                    require(self._state() == BEFORE, "state changed before source installation")
                    self._targets()
                    self.adapter.install_new(role, expected)
                    require(self.adapter.target_bytes(role) == expected,
                            "installed source readback differs: " + role)
                self._targets(complete=True)
                self._observe(BEFORE, intent_sha256)
                self._same_receipts(retained)
                self.adapter.replace_state(self.plan.state_before, self.plan.state_after)
                require(self._state() == AFTER, "state activation readback differs")
                replaced = True
            else:
                # Exact state may be visible after rename but before parent fsync.
                self.adapter.seal_state(self.plan.state_after)
                require(self._state() == AFTER, "activated state changed during resealing")
            after = self._observe(AFTER, intent_sha256)
            self._same_receipts(retained)
            ended = self.adapter.now()
            require(timestamp(ended) and ended >= validate_intent(intent_raw, self.plan)["started_unix"],
                    "policy completion time differs")
            completed = {"schema": 1, "scope": COMPLETED_SCOPE, "completed_unix": ended,
                         "intent_sha256": intent_sha256, "generation": 9, "rewrites": 5,
                         "checkpoint_sha256": CHECKPOINT_SHA256, "state_sha256": NEW_STATE_SHA256,
                         "pins_sha256": NEW_PINS_SHA256, "artifacts": self.plan.artifacts(),
                         "after": after, "resumed": action == "resume",
                         "state_replaced_this_run": replaced, "database_writer_invoked": False,
                         "pebble_open_performed": False, "service_action_performed": False}
            raw = canonical(completed)
            validate_completed(raw, intent_raw, self.plan)
            self._write("completed.json", raw)
            return completed
