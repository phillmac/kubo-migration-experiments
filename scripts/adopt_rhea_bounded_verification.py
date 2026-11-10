#!/usr/bin/env python3
"""Pure transaction engine for one fixed generation-nine verifier adoption.

The separately pinned root runner owns the protected adapter, process deadlines,
source staging, health observations, and fresh read-only acceptance proof. This
module has no CLI, filesystem setup, SDK client, service operation, or writer.
Only the shared journal activates the new toolchain. Original controller,
verifier, pins, checkpoints, services, and caches are never replacement targets.

Adapter contract (all operations run under adapter.lock()):
  state_bytes(), target_bytes(role), receipt_bytes(name) -> bytes or None
  write_new(name, raw), install_new(role, raw)
      Exclusive create, or validate and fsync existing exact bytes; never replace.
      Fsync both the file and its parent before returning.
  replace_state(expected_raw, new_raw)
      Compare exact preimage, write/fsync temporary file, atomically replace the
      one state path, and fsync its parent before returning.
  seal_state(expected_raw)
      Validate exact already activated bytes, fsync the existing state file and
      its parent without replacement; used only by unfinished explicit resume.
  observe(phase, intent_sha256=None) -> fixed health observation dictionary
  verify(intent_sha256) -> fixed references to a fresh, separately receipted,
      read-only final proof in acceptance/<six-digit attempt>/.
  now() -> finite Unix timestamp

Root's adapter must pin this engine and all source bytes, reject symlinks and
unsafe ownership/modes, and expose only the four TARGETS and four RECEIPTS below.
Exceptions propagate without retry, compensation, or rollback. An explicit
resume may finish exact prepared work or validate the already activated state.
An interrupted exclusive file write can leave incomplete final bytes. Such a
file is an unknown endpoint and requires manual inspection; resume never
overwrites or removes it. Recovery covers absent or exact immutable files and
either complete state endpoint, including a rename awaiting directory fsync.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from typing import NamedTuple


OLD_STATE_SHA256 = "7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1"
OLD_PINS_SHA256 = "0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575"
CHECKPOINT_SHA256 = "220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2"
PROJECTION_SHA256 = "0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57"
OLD_CONTROLLER_SHA256 = "7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb"
CONTROLLER_SHA256 = "56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a"
OLD_VERIFIER_SHA256 = "e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849"
VERIFIER_SHA256 = "43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796"
SCANNER_SHA256 = "512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359"
TARGETS = {
    "controller": "run_rhea_full_clone_steps_bounded.py",
    "verifier": "verify_rhea_full_clone_bounded.py",
    "scanner": "enumerate_rhea_versions.py",
    "pins": "full-clone-bounded-step-pins.json",
}
SOURCE_HASHES = {"controller": CONTROLLER_SHA256, "verifier": VERIFIER_SHA256, "scanner": SCANNER_SHA256}
RECEIPTS = ("state-before.json", "pins-before.json", "intent.json", "completed.json")
INTENT_SCOPE = "fixed-generation-nine-bounded-verifier-adoption-intent"
COMPLETED_SCOPE = "fixed-generation-nine-bounded-verifier-adoption-completed"
MAX_JSON = 256 * 1024
MAX_SOURCE = 512 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


class AdoptionRefusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise AdoptionRefusal(message)


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
        raise AdoptionRefusal("invalid JSON receipt") from error
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


def build_plan(state_before_raw, pins_before_raw, sources, provenance):
    """Bind exact historical preimages and the three reviewed new source files."""
    require(type(state_before_raw) is bytes and sha(state_before_raw) == OLD_STATE_SHA256,
            "original certified state differs")
    require(type(pins_before_raw) is bytes and sha(pins_before_raw) == OLD_PINS_SHA256,
            "original deployment pins differ")
    before, old_pins = json_object(state_before_raw), json_object(pins_before_raw)
    require(type(sources) is dict and set(sources) == set(SOURCE_HASHES), "source role set differs")
    for role, expected in SOURCE_HASHES.items():
        require(type(sources[role]) is bytes and 0 < len(sources[role]) <= MAX_SOURCE
                and sha(sources[role]) == expected, "reviewed source differs: " + role)
    validate_provenance(provenance)
    require(before["generation"] == 9 and before["rewrites"] == 5 and before["pending"] is None
            and before["binding"]["limits"]["maximum_rewrites"] == 5
            and sha(canonical(before["checkpoint"])) == CHECKPOINT_SHA256,
            "historical checkpoint progress differs")
    require(old_pins["controller_sha256"] == before["binding"]["controller_sha256"] == OLD_CONTROLLER_SHA256
            and old_pins["verifier_sha256"] == before["binding"]["verifier_sha256"] == OLD_VERIFIER_SHA256,
            "historical tool binding differs")
    after, new_pins = copy.deepcopy(before), dict(old_pins)
    for key, value in (("controller_sha256", CONTROLLER_SHA256), ("verifier_sha256", VERIFIER_SHA256)):
        after["binding"][key] = new_pins[key] = value
    pins_after = canonical(new_pins)
    artifacts = tuple((role, sources[role] if role != "pins" else pins_after) for role in TARGETS)
    return Plan(state_before_raw, pins_before_raw, canonical(after), pins_after,
                artifacts, canonical(provenance))


def validate_observation(value, phase, plan):
    require(type(value) is dict and value.get("phase") == phase and value.get("generation") == 9
            and value.get("rewrites") == 5 and value.get("baseline_state_sha256") == OLD_STATE_SHA256
            and value.get("checkpoint_sha256") == CHECKPOINT_SHA256,
            "adoption health checkpoint or phase differs")
    require(value.get("state_sha256") == sha(plan.state_before if phase == "before" else plan.state_after)
            and value.get("pins_sha256") == sha(plan.pins_before if phase == "before" else plan.pins_after),
            "adoption health binding differs")
    require(len(canonical(value)) <= MAX_JSON, "health observation exceeds bound")


def validate_verification(value):
    require(type(value) is dict and set(value) == {"schema", "verified", "attempt", "path",
            "checkpoint_sha256", "semantic_projection_sha256", "result_sha256", "metrics_sha256",
            "receipt_sha256"}, "acceptance proof reference fields differ")
    require(type(value["schema"]) is int and value["schema"] == 1 and value["verified"] is True
            and type(value["attempt"]) is int and 1 <= value["attempt"] <= 999_999
            and value["path"] == f"acceptance/{value['attempt']:06d}", "acceptance proof path or schema differs")
    require(value["checkpoint_sha256"] == CHECKPOINT_SHA256
            and value["semantic_projection_sha256"] == PROJECTION_SHA256
            and all(hash_string(value[key]) for key in ("result_sha256", "metrics_sha256", "receipt_sha256")),
            "acceptance proof checkpoint or digest differs")


class Transaction:
    """Fixed source installation with one state-only activation commit."""
    def __init__(self, adapter, plan):
        require(isinstance(plan, Plan), "validated adoption plan required")
        source_bytes = {role: raw for role, raw in plan.sources if role != "pins"}
        require(plan == build_plan(plan.state_before, plan.pins_before, source_bytes,
                                  json_object(plan.provenance_raw)), "adoption plan changed")
        self.adapter, self.plan = adapter, plan

    def _state(self):
        raw = self.adapter.state_bytes()
        require(raw in (self.plan.state_before, self.plan.state_after), "current state is not an exact transition endpoint")
        return "before" if raw == self.plan.state_before else "after"

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
        self._targets(complete=phase == "after")
        return value

    def _write(self, name, raw):
        require(name in RECEIPTS and type(raw) is bytes and len(raw) <= MAX_JSON, "receipt destination or size differs")
        existing = self.adapter.receipt_bytes(name)
        require(existing is None or existing == raw, "immutable adoption receipt differs: " + name)
        self.adapter.write_new(name, raw)
        require(self.adapter.receipt_bytes(name) == raw, "durable adoption receipt readback differs: " + name)

    def _intent(self, raw):
        value = json_object(raw)
        fields = self.plan.intent_fields()
        require(set(value) == set(fields) | {"started_unix", "before"}
                and all(value[key] == item for key, item in fields.items())
                and timestamp(value["started_unix"]), "durable adoption intent differs")
        validate_observation(value["before"], "before", self.plan)
        return value

    def _completed(self, raw, intent_raw):
        value = json_object(raw)
        expected = {"schema": 1, "scope": COMPLETED_SCOPE, "intent_sha256": sha(intent_raw),
                    "generation": 9, "rewrites": 5, "checkpoint_sha256": CHECKPOINT_SHA256,
                    "state_sha256": sha(self.plan.state_after), "pins_sha256": sha(self.plan.pins_after),
                    "artifacts": self.plan.artifacts(), "database_writer_invoked": False, "pebble_open_performed": False}
        require(set(value) == set(expected) | {"completed_unix", "after", "verification", "resumed", "state_replaced_this_run"}
                and all(value[key] == item for key, item in expected.items())
                and timestamp(value["completed_unix"])
                and value["completed_unix"] >= self._intent(intent_raw)["started_unix"]
                and type(value["resumed"]) is type(value["state_replaced_this_run"]) is bool,
                "completed adoption receipt differs")
        require(value["database_writer_invoked"] is value["pebble_open_performed"] is False,
                "completed adoption claims an unexpected writer or reopen")
        validate_observation(value["after"], "after", self.plan)
        validate_verification(value["verification"])
        return value

    def run(self, action):
        require(action in ("check", "apply", "resume"), "explicit fixed adoption action required")
        with self.adapter.lock():
            phase = self._state()
            installed = self._targets(complete=phase == "after")
            saved = {name: self.adapter.receipt_bytes(name) for name in RECEIPTS}
            for name, expected in (("state-before.json", self.plan.state_before), ("pins-before.json", self.plan.pins_before)):
                require(saved[name] is None or saved[name] == expected, "adoption preimage changed: " + name)
            intent_raw = saved["intent.json"]
            if intent_raw is not None:
                self._intent(intent_raw)
                require(saved["state-before.json"] == self.plan.state_before
                        and saved["pins-before.json"] == self.plan.pins_before, "intent lacks exact durable preimages")
            require(phase != "after" or intent_raw is not None, "activated state lacks adoption intent")
            if saved["completed.json"] is not None:
                require(phase == "after" and intent_raw is not None, "completion lacks activated state or intent")
                complete = self._completed(saved["completed.json"], intent_raw)
                require(action in ("check", "resume"), "adoption already completed; use check or explicit resume")
                self._observe("after", sha(intent_raw))
                if action == "resume":
                    # Exact complete bytes may be visible before the previous
                    # process fsynced their directory entry. Reseal only after
                    # the adapter independently validates the retained proof.
                    self._write("completed.json", saved["completed.json"])
                return {"phase": "completed", "state_sha256": sha(self.plan.state_after),
                        "completed_sha256": sha(saved["completed.json"]), "verification": complete["verification"]}
            if action == "check":
                self._observe(phase, sha(intent_raw) if intent_raw is not None else None)
                status = "activated" if phase == "after" else "prepared" if intent_raw is not None else "preparing" if any(saved.values()) else "unprepared"
                return {"phase": status, "state_sha256": sha(self.adapter.state_bytes()),
                        "intent_sha256": sha(intent_raw) if intent_raw is not None else None, "installed": installed}
            if action == "apply":
                require(phase == "before" and not any(value is not None for value in saved.values()),
                        "adoption evidence exists; inspect and explicitly resume")
            else:
                require(any(value is not None for value in saved.values()), "no recorded adoption to resume")
            before = self._observe(phase, sha(intent_raw) if intent_raw is not None else None)
            if intent_raw is None:
                require(phase == "before", "new intent requires the exact original state")
                started = self.adapter.now()
                require(timestamp(started), "invalid adoption timestamp")
                intent_raw = canonical(dict(self.plan.intent_fields(), started_unix=started, before=before))
            # Revalidate and fsync exact existing preimages/intent on resume.
            self._write("state-before.json", self.plan.state_before)
            self._write("pins-before.json", self.plan.pins_before)
            self._write("intent.json", intent_raw)
            intent_sha256, replaced = sha(intent_raw), False
            if phase == "before":
                for role, expected in self.plan.sources:
                    require(self._state() == "before", "state changed before source installation")
                    self._targets()
                    self.adapter.install_new(role, expected)
                    require(self.adapter.target_bytes(role) == expected, "installed source readback differs: " + role)
                self._targets(complete=True)
                self._observe("before", intent_sha256)
                require(self.adapter.receipt_bytes("intent.json") == intent_raw, "adoption intent changed before activation")
                self.adapter.replace_state(self.plan.state_before, self.plan.state_after)
                require(self._state() == "after", "state activation readback differs")
                replaced = True
            else:
                # The previous process may have renamed the complete state but
                # died before fsync of STATE.parent. Visible exact bytes alone
                # do not establish durability of that activation directory entry.
                self.adapter.seal_state(self.plan.state_after)
                require(self._state() == "after", "activated state changed during resealing")
            self._observe("after", intent_sha256)
            verification = self.adapter.verify(intent_sha256)
            validate_verification(verification)
            # Completion describes the observation after the full fresh proof.
            after = self._observe("after", intent_sha256)
            require(all(self.adapter.receipt_bytes(name) == expected for name, expected in
                        (("state-before.json", self.plan.state_before), ("pins-before.json", self.plan.pins_before),
                         ("intent.json", intent_raw))), "adoption evidence changed during acceptance proof")
            ended = self.adapter.now()
            require(timestamp(ended) and ended >= self._intent(intent_raw)["started_unix"], "adoption completion time differs")
            completed = {"schema": 1, "scope": COMPLETED_SCOPE, "completed_unix": ended,
                         "intent_sha256": intent_sha256, "generation": 9, "rewrites": 5,
                         "checkpoint_sha256": CHECKPOINT_SHA256, "state_sha256": sha(self.plan.state_after),
                         "pins_sha256": sha(self.plan.pins_after), "artifacts": self.plan.artifacts(),
                         "after": after, "verification": verification, "resumed": action == "resume",
                         "state_replaced_this_run": replaced, "database_writer_invoked": False,
                         "pebble_open_performed": False}
            raw = canonical(completed)
            self._completed(raw, intent_raw)
            self._write("completed.json", raw)
            return completed
