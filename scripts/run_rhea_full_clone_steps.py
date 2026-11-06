#!/usr/bin/env python3
"""Run one explicitly selected stage on the fixed disposable Rhea full clone.

No service launch, production writes, automatic writer retry, force kill, or
format-14 finalization is exposed. An interrupted writer is reconciled only
from its closed success report and a read-only reopen, never run again.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import types


TRUST = Path("/root/.local/share/rhea-wasabi-lab-admin-20261101")
WRAPPER = TRUST / "rhea_wasabi_lab_mount.py"
WRAPPER_SHA256 = "76635430d99daa65a816dc1ae444145bbdfe844559b4b4bed2e30fbae0302545"
TOOL = TRUST / "realstep"
VERIFIER = TRUST / "verify_rhea_full_clone.py"
PINS = TRUST / "full-clone-step-pins.json"
STATE_ROOT = TRUST / "full-clone-steps"
SEED = TRUST / "format3-20261103/full-clone-format3-certified.json"
SEED_SHA256 = "a7438699846ca71af61ad7c7622f9807be2846273c75fd3559730a51988f1eaf"
STOP_FILE = Path("/run/rhea-wasabi-lab/full-clone-step-budget-stop")
BUCKET = "rhea-pebble-lab-20261101-39037c6f01"
PREFIX = "rhea/"
DB = Path("/mnt/rhea-pebble-lab-writable-20261102/pebbleds")
BASELINE_DIGEST = "57b04d9508272a17df72aea1a6675fff1e13944ae83c884f988668b7f77cd134"
MAX_INPUT = 256 * 1024**2
MAX_OUTPUT = 512 * 1024**2
MAX_METADATA_WRITES = 64 * 1024**2
MAX_CACHE = 96 * 1024**3
MIN_FREE = 2 * 1024**4
MAX_BACKLOG_BYTES = 768 * 1024**2
MAX_BACKLOG_FILES = 256
RESERVATION = MAX_INPUT + MAX_OUTPUT + MAX_METADATA_WRITES
MAX_JSON = 16 * 1024**2
MAX_METADATA_FILE = 128 * 1024**2
MAX_METADATA_TOTAL = 512 * 1024**2
MAX_METADATA_FILES = 64
MONITOR_INTERVAL = 5
UPLOAD_TIMEOUT = 1800
STAGES = {
    "ratchet6": ("003", "006"), "ratchet7": ("006", "007"),
    "ratchet10": ("007", "010"), "ratchet13": ("010", "013"),
    "step": ("013", "013"),
}
PREPARATORY_STAGES = tuple(action for action in STAGES if action != "step")
MAX_REWRITES = 5  # The certified first rewrite plus four separately admitted units.
MAX_GENERATION = len(PREPARATORY_STAGES) + MAX_REWRITES
PHASES = {"executing", "closed", "flushing", "preverified", "publishing", "verifying"}
HEX = re.compile(r"[0-9a-f]{64}")
SST = re.compile(r"[0-9]{6,20}\.sst")
METADATA = re.compile(
    r"(?:CURRENT|LOCK|[0-9]{6,20}\.log|(?:MANIFEST|OPTIONS)-[0-9]{6,20}|"
    r"marker\.manifest\.[0-9]{6,20}\.MANIFEST-[0-9]{6,20}|"
    r"marker\.format-version\.[0-9]{6,20}\.[0-9]{3})"
)
LIMITS = {"input_bytes": MAX_INPUT, "sst_output_bytes": MAX_OUTPUT,
          "metadata_write_bytes": MAX_METADATA_WRITES, "cache_bytes": MAX_CACHE,
          "minimum_free_bytes": MIN_FREE, "backlog_bytes": MAX_BACKLOG_BYTES,
          "backlog_files": MAX_BACKLOG_FILES, "maximum_rewrites": MAX_REWRITES}


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def json_object(data: bytes) -> dict:
    require(len(data) <= MAX_JSON, "JSON evidence exceeds bound")

    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON field")
            out[key] = value
        return out

    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite JSON value")))
    except (ValueError, UnicodeError):
        raise Refusal("invalid JSON evidence") from None
    require(isinstance(value, dict), "JSON evidence must be an object")
    return value


def integer(value, message, minimum=0):
    require(type(value) is int and value >= minimum, message)
    return value


def stage_action(index: int) -> str:
    require(type(index) is int and 1 <= index <= MAX_GENERATION, "invalid stage generation")
    return PREPARATORY_STAGES[index - 1] if index <= len(PREPARATORY_STAGES) else "step"


def checkpoint_state(checkpoint: dict) -> dict:
    require(checkpoint.get("bucket", BUCKET) == BUCKET and checkpoint.get("prefix", PREFIX) == PREFIX,
            "checkpoint scope mismatch")
    fmt = checkpoint.get("after_format", checkpoint.get("format_major_version"))
    marks = checkpoint.get("marked_after", checkpoint.get("marked_files"))
    require(fmt in ("003", "006", "007", "010", "013"), "unsupported checkpoint format")
    sha = checkpoint.get("sst_inventory_sha256")
    require(isinstance(sha, str) and HEX.fullmatch(sha), "invalid checkpoint inventory digest")
    return {"format": fmt, "marked": integer(marks, "invalid checkpoint marked count"),
            "count": integer(checkpoint.get("sst_count"), "invalid checkpoint SST count", 1),
            "bytes": integer(checkpoint.get("sst_bytes"), "invalid checkpoint SST bytes", 1),
            "inventory": sha}


def report_state(report: dict, side: str) -> dict:
    sha = report.get(f"sst_inventory_sha256_{side}")
    require(isinstance(sha, str) and HEX.fullmatch(sha), "invalid Go inventory digest")
    fmt = report.get(f"{side}_format")
    require(fmt in ("003", "006", "007", "010", "013"), "unsupported Go format")
    return {"format": fmt, "marked": integer(report.get(f"marked_{side}"), "invalid Go marked count"),
            "count": integer(report.get(f"sst_files_{side}"), "invalid Go SST count", 1),
            "bytes": integer(report.get(f"sst_bytes_{side}"), "invalid Go SST bytes", 1), "inventory": sha}


def validate_inspection(report: dict, expected: dict, *, action="inspect") -> None:
    require(report.get("action") == action and not report.get("error"), "read-only Go inspection failed")
    require(report_state(report, "before") == report_state(report, "after") == expected,
            "read-only Go state differs from certified checkpoint")
    require(not report.get("compactions"), "read-only inspection reported a compaction")


def validate_plan(report: dict, expected: dict) -> dict:
    validate_inspection(report, expected, action="plan")
    plan = report.get("picker_plan")
    require(isinstance(plan, dict), "missing authoritative picker plan")
    names = plan.get("input_files")
    require(isinstance(names, list) and names and len(set(names)) == len(names)
            and all(isinstance(name, str) and SST.fullmatch(name) for name in names), "invalid picker input names")
    require(0 < integer(plan.get("input_bytes"), "invalid picker input size") <= MAX_INPUT,
            "authoritative picker input exceeds 256 MiB")
    for key in ("plan_sha256", "candidate_sha256"):
        require(isinstance(plan.get(key), str) and HEX.fullmatch(plan[key]), "invalid picker digest")
    for key in ("input_level", "output_level"):
        require(type(plan.get(key)) is int and 0 <= plan[key] <= 6, "invalid picker level")
    return plan


def table_rows(rows) -> dict[str, dict]:
    require(isinstance(rows, list), "missing SST delta rows")
    result = {}
    for row in rows:
        require(isinstance(row, dict), "invalid SST delta row")
        number = integer(row.get("number"), "invalid SST file number", 1)
        name = row.get("name")
        require(isinstance(name, str) and SST.fullmatch(name) and name == f"{number:06d}.sst"
                and name not in result, "invalid or duplicate SST delta name")
        integer(row.get("size"), "invalid SST delta size", 1)
        require(type(row.get("level")) is int and 0 <= row["level"] <= 6, "invalid SST delta level")
        result[name] = row
    return result


def validate_result(report: dict, action: str, expected: dict, plan: dict | None) -> None:
    require(report.get("action") == action and not report.get("error") and not report.get("blocked_budget_error"),
            "writer did not report a successful closed stage")
    require(report_state(report, "before") == expected, "writer began at an unexpected checkpoint")
    after = report_state(report, "after")
    require((expected["format"], after["format"]) == STAGES[action], "unexpected format transition")
    io = report.get("io")
    require(isinstance(io, dict) and io.get("max_sst_write_bytes") == MAX_OUTPUT
            and io.get("max_metadata_write_bytes") == MAX_METADATA_WRITES, "writer budget settings differ")
    require(not io.get("blocked_budget_error"), "writer reported a blocked I/O budget")
    require(integer(io.get("sst_write_bytes"), "missing SST write count") <= MAX_OUTPUT
            and integer(io.get("metadata_write_bytes"), "missing metadata write count") <= MAX_METADATA_WRITES,
            "writer exceeded a hard output budget")
    delta = report.get("sst_diff")
    require(isinstance(delta, dict), "missing SST delta")
    created, retired = table_rows(delta.get("created")), table_rows(delta.get("retired"))
    created_bytes = sum(row["size"] for row in created.values())
    retired_bytes = sum(row["size"] for row in retired.values())
    require(delta.get("created_bytes") == created_bytes and delta.get("retired_bytes") == retired_bytes,
            "SST delta byte totals disagree")
    require(not (created.keys() & retired.keys()) and created_bytes <= MAX_OUTPUT, "invalid SST replacement delta")
    require(after["count"] == expected["count"] + len(created) - len(retired)
            and after["bytes"] == expected["bytes"] + created_bytes - retired_bytes,
            "SST delta does not reconcile with after inventory")
    events = report.get("compactions")
    require(isinstance(events, list), "missing compaction evidence")
    if action != "step":
        require(not created and not retired and not events and io["sst_write_bytes"] == 0
                and after["inventory"] == expected["inventory"], "metadata stage changed SSTs or compacted")
        return
    require(plan is not None and report.get("picker_plan") == plan, "writer picker differs from reviewed plan")
    require(set(retired) == set(plan["input_files"]) and retired_bytes == plan["input_bytes"] and created,
            "rewritten SSTs differ from authoritative atomic input")
    require(0 < expected["marked"] - after["marked"] <= len(retired), "marked-file count did not decrease correctly")
    begins = [event for event in events if event.get("type") == "begin"]
    ends = [event for event in events if event.get("type") == "end"]
    require(len(events) == 2 and len(begins) == len(ends) == 1
            and all(event.get("reason") == "rewrite" for event in events)
            and not ends[0].get("error"), "stage did not perform exactly one successful marked rewrite")


def health(observation: dict, free_bytes: int, *, new_work=False) -> None:
    stats = observation.get("stats", {}).get("diskCache", {})
    queued = observation.get("queue", {}).get("queue")
    require(isinstance(queued, list), "missing queue evidence")
    require(integer(stats.get("erroredFiles"), "missing error count") == 0
            and stats.get("outOfSpace") is False, "upload error or out-of-space condition")
    for key in ("uploadsQueued", "uploadsInProgress"):
        require(integer(stats.get(key), "invalid upload counters") <= MAX_BACKLOG_FILES, "upload count exceeds bound")
    used = integer(stats.get("bytesUsed"), "missing cache byte count")
    total = 0
    identities, names = set(), set()
    for row in queued:
        require(isinstance(row, dict), "invalid queued item")
        number = integer(row.get("id"), "invalid queue id", 1)
        name = row.get("name")
        require(isinstance(name, str) and number not in identities and name not in names, "duplicate queue identity")
        identities.add(number)
        names.add(name)
        total += integer(row.get("size"), "invalid pending file size")
        require(type(row.get("uploading")) is bool, "missing upload state")
    require(len(queued) <= MAX_BACKLOG_FILES and total <= MAX_BACKLOG_BYTES, "upload backlog exceeds bound")
    reserve = RESERVATION if new_work else 0
    require(integer(free_bytes, "invalid free-space evidence") >= MIN_FREE + reserve, "cache filesystem reserve is exhausted")
    require(used <= MAX_CACHE - reserve, "cache budget has insufficient headroom")
    if new_work:
        require(not queued and stats["uploadsQueued"] == stats["uploadsInProgress"] == 0,
                "new work requires a completely clean queue")


def upload_priority(name: str) -> int:
    require(name.startswith("pebbleds/"), "queued object outside pebbleds")
    basename = name[len("pebbleds/"):]
    if SST.fullmatch(basename): return 0
    if re.fullmatch(r"[0-9]{6,20}\.log", basename): return 1
    if re.fullmatch(r"OPTIONS-[0-9]{6,20}", basename): return 2
    if re.fullmatch(r"MANIFEST-[0-9]{6,20}", basename): return 3
    if basename == "CURRENT": return 4
    if re.fullmatch(r"marker\.manifest\.[0-9]{6,20}\.MANIFEST-[0-9]{6,20}", basename): return 5
    if re.fullmatch(r"marker\.format-version\.[0-9]{6,20}\.[0-9]{3}", basename): return 6
    raise Refusal("unexpected queued object type")


class Controller:
    def __init__(self, runtime):
        self.runtime = runtime

    def status(self):
        state = self.runtime.load_state()
        return {"state": state, "observation": self.runtime.observe(),
                "budget_stop_present": self.runtime.stop_present()}

    def run(self, action: str, *, apply=False):
        require(action in STAGES, "unknown stage")
        with self.runtime.lock():
            state = self.runtime.load_state()
            require(state["pending"] is None, "unfinished stage: reconcile it; never repeat its writer")
            require(action != "step" or state["rewrites"] < MAX_REWRITES, "real rewrite limit has already been reached")
            require(action == stage_action(state["generation"] + 1), "stage is out of order")
            expected = checkpoint_state(state["checkpoint"])
            require(expected["format"] == STAGES[action][0], "stage is out of order")
            if action in ("ratchet6", "ratchet7", "ratchet10"):
                require(expected["marked"] == 0, "preparatory stage would cross unfinished marked-file work")
            self.runtime.guard(new_work=True)
            probe = self.runtime.run_tool("plan" if action == "step" else "inspect")
            if action == "step":
                plan = validate_plan(probe, expected)
            else:
                validate_inspection(probe, expected)
                plan = None
            self.runtime.guard(new_work=True)
            if not apply:
                return {"action": action, "applied": False, "before": expected, "picker_plan": plan, "limits": LIMITS}
            pending = {"index": state["generation"] + 1, "action": action, "phase": "executing",
                       "previous_checkpoint_sha256": digest(state["checkpoint"]), "picker_plan": plan}
            self.runtime.create_stage(pending)
            state["pending"] = pending
            self.runtime.write_state(state)  # Must be durable before any writer starts.

            def launched(identity):
                pending["process"] = identity
                self.runtime.write_state(state)

            def monitor_failed(failure):
                pending["monitor_failure"] = failure
                self.runtime.write_state(state)

            report = self.runtime.run_tool(action, expected=expected, plan=plan,
                                           pending=pending, launched=launched, monitor_failed=monitor_failed)
            validate_result(report, action, expected, plan)
            pending.update(phase="closed", report=report)
            self.runtime.write_state(state)
            return self._finish(state)

    def recover(self, *, apply=False):
        with self.runtime.lock():
            state = self.runtime.load_state()
            pending = state["pending"]
            require(pending is not None, "no unfinished stage to reconcile")
            require(not self.runtime.writer_alive(pending), "the recorded writer is still running")
            self.runtime.guard(new_work=False)
            report = pending.get("report") or self.runtime.closed_report(pending)
            validate_result(report, pending["action"], checkpoint_state(state["checkpoint"]), pending["picker_plan"])
            reopened = self.runtime.run_tool("inspect")
            validate_inspection(reopened, report_state(report, "after"))
            if not apply:
                return {"action": "recover-checkpoint", "applied": False, "writer_will_be_repeated": False,
                        "closed_report": report, "reconciled_reopen": reopened}
            pending["report"] = report
            if pending["phase"] == "executing":
                pending["phase"] = "closed"
            self.runtime.write_state(state)
            return self._finish(state)

    def _finish(self, state):
        pending = state["pending"]
        report = pending["report"]
        self.runtime.guard(new_work=False)
        snapshot, created = self.runtime.snapshot(pending, report)
        if "snapshot_sha256" in pending:
            require(pending["snapshot_sha256"] == digest({name: hashlib.sha256(data).hexdigest() for name, data in snapshot.items()})
                    and pending["created_ssts"] == created, "closed snapshot changed during recovery")
        else:
            pending["snapshot_sha256"] = digest({name: hashlib.sha256(data).hexdigest() for name, data in snapshot.items()})
            pending["created_ssts"] = created
            self.runtime.write_state(state)
        if "before_markers" not in pending:
            pending["phase"] = "flushing"
            self.runtime.write_state(state)
            self.runtime.defer_markers(snapshot, created)
            self.runtime.drain_data(snapshot, created)
            before = self.runtime.verify(state["checkpoint"], report, snapshot, created, "before-markers")
            pending.update(phase="preverified", before_markers=before, before_markers_sha256=digest(before))
            self.runtime.write_state(state)  # Publication proof precedes every marker mutation.
        require(digest(pending["before_markers"]) == pending["before_markers_sha256"], "publication proof changed")
        pending["phase"] = "publishing"
        self.runtime.write_state(state)
        self.runtime.publish_markers(pending["before_markers"], snapshot, created)
        pending["phase"] = "verifying"
        self.runtime.write_state(state)
        final = self.runtime.verify(state["checkpoint"], report, snapshot, created, "final")
        require(final.get("remote_generation_verified") is True, "remote generation was not certified")
        require(checkpoint_state(final) == report_state(report, "after"), "remote certificate differs from closed writer result")
        self.runtime.guard(new_work=False, clean=True)
        reopened = self.runtime.run_tool("inspect")
        validate_inspection(reopened, report_state(report, "after"))
        self.runtime.check_snapshot(snapshot)
        self.runtime.guard(new_work=False, clean=True)
        final.update(bucket=BUCKET, prefix=PREFIX, reopen=reopened, pebble_reopen_verified=True,
                     reopen_scope="guarded lab mount; closed metadata bound to independent S3 bytes",
                     generation=pending["index"], action=pending["action"],
                     previous_checkpoint_sha256=pending["previous_checkpoint_sha256"])
        final = self.runtime.save_certificate(pending, final)
        state.update(checkpoint=final, generation=pending["index"], pending=None,
                     rewrites=state["rewrites"] + int(pending["action"] == "step"))
        self.runtime.write_state(state)
        return {"action": pending["action"], "applied": True, "checkpoint": final,
                "rewrites_completed": state["rewrites"], "production_cutover": False}


def load_pinned_module(path: Path, sha256: str, name: str):
    """Read trusted source once; execute exactly the bytes whose hash was checked."""
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_mode & 0o022 == 0, "untrusted tool path")
        if part != path:
            require(stat.S_ISDIR(info.st_mode), "tool ancestor is not a directory")
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "tool is not a private regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            source = stream.read(MAX_JSON + 1)
    finally:
        os.close(fd)
    require(len(source) <= MAX_JSON and hashlib.sha256(source).hexdigest() == sha256, "trusted tool digest mismatch")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


class Runtime:
    def __init__(self):
        require(os.geteuid() == 0, "root required for protected lab tools")
        self.wrapper = load_pinned_module(WRAPPER, WRAPPER_SHA256, "full_clone_step_mount")
        self.host = self.wrapper.RealHost()
        self.profile = self.wrapper.PROFILES["full-clone"]
        self.host.dependencies()
        pins = json_object(self.wrapper.read_protected(PINS, mode=0o600, max_bytes=16_384))
        require(set(pins) == {"schema", "controller_sha256", "go_sha256", "verifier_sha256"}
                and type(pins["schema"]) is int and pins["schema"] == 1, "invalid deployment pins")
        require(all(isinstance(pins[key], str) and HEX.fullmatch(pins[key])
                    for key in ("controller_sha256", "go_sha256", "verifier_sha256")), "invalid tool hash pin")
        own_path = TRUST / "run_rhea_full_clone_steps.py"
        require(Path(__file__).resolve() == own_path, "controller must run from its fixed trusted installation")
        require(hashlib.sha256(self.wrapper.read_protected(own_path)).hexdigest() == pins["controller_sha256"],
                "controller deployment digest mismatch")
        self.pins = pins
        self.verifier = load_pinned_module(VERIFIER, pins["verifier_sha256"], "full_clone_step_verifier")
        self.binding = dict(pins, wrapper_sha256=WRAPPER_SHA256, seed_sha256=SEED_SHA256,
                            bucket=BUCKET, prefix=PREFIX, limits=LIMITS)
        self.pid = None
        self.check_tool()

    def check_tool(self):
        data = self.wrapper.read_protected(TOOL)
        require(hashlib.sha256(data).hexdigest() == self.pins["go_sha256"], "realstep binary digest mismatch")
        require(TOOL.stat().st_mode & 0o111, "realstep binary is not executable")

    def lock(self):
        return self.host.lock()

    def _sync_dir(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def atomic_json(self, path: Path, value):
        data = canonical(value)
        require(len(data) <= MAX_JSON, "durable evidence exceeds JSON bound")
        self.host.mkdir_private(path.parent)
        self.wrapper.secure_path(path, leaf_mode=0o600, missing=True)
        fd, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self._sync_dir(path.parent)
            self._sync_dir(path.parent.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def load_state(self):
        self.wrapper.secure_path(STATE_ROOT, leaf_mode=0o700, missing=True)
        path = STATE_ROOT / "state.json"
        if not path.exists() and not path.is_symlink():
            raw = self.wrapper.read_protected(SEED, mode=0o600, max_bytes=MAX_JSON)
            require(hashlib.sha256(raw).hexdigest() == SEED_SHA256, "certified format3 seed digest mismatch")
            seed = json_object(raw)
            require(seed.get("remote_format3_closure_verified") is True
                    and seed.get("pebble_reopen_verified") is True
                    and seed.get("reader_generation_bound_to_s3_metadata") is True,
                    "format3 seed lacks completed independent verification")
            require(checkpoint_state(seed) == {"format": "003", "marked": 0, "count": 93_697,
                                               "bytes": 7_786_594_080_785, "inventory": BASELINE_DIGEST},
                    "format3 seed inventory mismatch")
            return {"schema": 1, "binding": self.binding, "checkpoint": seed,
                    "generation": 0, "rewrites": 0, "pending": None}
        state = json_object(self.wrapper.read_protected(path, mode=0o600, max_bytes=MAX_JSON))
        self.validate_state(state)
        return state

    def validate_state(self, state):
        require(set(state) == {"schema", "binding", "checkpoint", "generation", "rewrites", "pending"}
                and type(state["schema"]) is int and state["schema"] == 1
                and state["binding"] == self.binding, "migration journal binding mismatch")
        generation = integer(state["generation"], "invalid generation")
        rewrites = integer(state["rewrites"], "invalid rewrite count")
        require(generation <= MAX_GENERATION and rewrites <= MAX_REWRITES,
                "migration progress exceeds this experiment")
        require(rewrites == max(0, generation - len(PREPARATORY_STAGES)),
                "journal generation and rewrite count disagree")
        prior = checkpoint_state(state["checkpoint"])
        expected_format = "003" if generation == 0 else STAGES[stage_action(generation)][1]
        require(prior["format"] == expected_format, "checkpoint format disagrees with journal generation")
        if generation or "generation" in state["checkpoint"]:
            require(integer(state["checkpoint"].get("generation"), "invalid checkpoint generation") == generation,
                    "checkpoint generation disagrees with journal")
        lineage = state["checkpoint"].get("sst_lineage")
        require((lineage is None and generation == 0) or
                (isinstance(lineage, dict) and
                 integer(lineage.get("rewrite_operations"), "invalid checkpoint rewrite count") == rewrites),
                "checkpoint lineage and journal rewrite count disagree")
        require(state["checkpoint"].get("pebble_reopen_verified") is True
                and (state["checkpoint"].get("remote_generation_verified") is True
                     or state["checkpoint"].get("remote_format3_closure_verified") is True),
                "journal checkpoint is not certified")
        pending = state["pending"]
        if pending is not None:
            require(isinstance(pending, dict) and pending.get("action") in STAGES
                    and pending.get("phase") in PHASES and pending.get("index") == state["generation"] + 1,
                    "invalid unfinished stage")
            require(pending["action"] == stage_action(pending["index"]), "unfinished stage is out of order")
            require(STAGES[pending["action"]][0] == prior["format"]
                    and pending.get("previous_checkpoint_sha256") == digest(state["checkpoint"]),
                    "unfinished stage is bound to a different checkpoint")

    def write_state(self, state):
        require(self.host.locked, "migration journal write requires writer lock")
        self.validate_state(state)
        self.atomic_json(STATE_ROOT / "state.json", state)

    def stage_dir(self, pending):
        require(pending.get("action") == stage_action(pending.get("index")), "invalid stage directory identity")
        return STATE_ROOT / "stages" / f"{pending['index']:06d}-{pending['action']}"

    def create_stage(self, pending):
        path = self.stage_dir(pending)
        require(not path.exists() and not path.is_symlink(), "stage evidence already exists; refuse writer replay")
        self.host.mkdir_private(path)
        self._sync_dir(path.parent)
        self._sync_dir(path.parent.parent)

    def stop_present(self):
        return STOP_FILE.exists() or STOP_FILE.is_symlink()

    def free_bytes(self):
        info = os.statvfs(self.profile.cache)
        return info.f_bavail * info.f_frsize

    def observe(self):
        observation = self.host.observe(self.profile)
        require(self.pid is None or observation["pid"] == self.pid, "lab rclone PID changed during stage")
        return observation

    def _no_realstep_process(self):
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                require(os.readlink(proc / "exe").removesuffix(" (deleted)") != str(TOOL),
                        "another realstep process remains active")
            except FileNotFoundError:
                continue

    def guard(self, *, new_work, clean=False):
        self.host.guard(self.profile, running=True, admission=False)
        self._no_realstep_process()
        self.host.no_open_users(self.profile, expected_pid=self.pid)
        observation = self.observe()
        self.pid = observation["pid"]
        health(observation, self.free_bytes(), new_work=new_work)
        if new_work:
            require(not self.stop_present(), "budget-stop sentinel requires reviewed recovery")
        if clean:
            self.wrapper.clean_queue(observation["stats"], observation["queue"])
        return observation

    def _process_identity(self, pid):
        raw = (Path("/proc") / str(pid) / "stat").read_text()
        start = raw.rsplit(")", 1)[1].split()[19]
        return {"pid": pid, "start_ticks": start, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}

    def writer_alive(self, pending):
        recorded = pending.get("process")
        if recorded is None:
            return False  # guard also scans exact tool executables, including pre-open children.
        require(isinstance(recorded, dict) and type(recorded.get("pid")) is int and recorded["pid"] > 1,
                "invalid recorded writer identity")
        try:
            return self._process_identity(recorded["pid"]) == recorded
        except FileNotFoundError:
            return False

    def signal_budget_stop(self, reason):
        self.wrapper.secure_path(STOP_FILE.parent, leaf_mode=0o700)
        try:
            fd = os.open(STOP_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical({"reason": reason, "created_unix": int(time.time())}))
            stream.flush()
            os.fsync(stream.fileno())
        self._sync_dir(STOP_FILE.parent)

    def run_tool(self, action, *, expected=None, plan=None, pending=None, launched=None, monitor_failed=None):
        require(action in STAGES or action in ("inspect", "plan"), "unsupported Go action")
        self.check_tool()
        command = [str(TOOL), action]
        if action in STAGES:
            require(expected is not None and pending is not None, "writer requires durable intent and expected state")
            command += ["--expected-format", expected["format"], "--expected-marked", str(expected["marked"]),
                        "--expected-inventory-sha256", expected["inventory"]]
            if action == "step":
                command += ["--expected-plan-sha256", plan["plan_sha256"]]
        if pending is None:
            # A long read-only open also populates the cache. Monitor it without
            # creating migration progress or hiding a forced timeout or retry.
            with tempfile.TemporaryFile(dir=TRUST) as out, tempfile.TemporaryFile(dir=TRUST) as err:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                         env=self.wrapper.CLEAN_ENV, cwd=TRUST)
                result_code, failure = self._wait_tool(child)
                require(result_code == 0 and failure is None,
                        "read-only realstep process failed or exceeded monitored bounds; no automatic retry")
                out.seek(0)
                return json_object(out.read(MAX_JSON + 1))
        directory = self.stage_dir(pending)
        stdout_path, stderr_path = directory / "writer.json", directory / "writer.stderr"
        for path in (stdout_path, stderr_path):
            self.wrapper.secure_path(path, leaf_mode=0o600, missing=True)
        out_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        err_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out_fd, "wb") as out, os.fdopen(err_fd, "wb") as err:
            self._sync_dir(directory)
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     env=self.wrapper.CLEAN_ENV, cwd=TRUST)
            identity = {"pid": child.pid, "start_ticks": "unrecorded", "boot_id": "unrecorded"}
            failure = None
            try:
                try:
                    identity = self._process_identity(child.pid)
                except FileNotFoundError:
                    identity = {"pid": child.pid, "start_ticks": "exited", "boot_id": "exited"}
                launched(identity)
            except Exception:
                # The durable intent already exists. A child must remain under
                # supervision even if its identity cannot be read or journaled.
                failure = self._request_stop("could not durably record spawned realstep identity", monitor_failed)
            result_code, failure = self._wait_tool(child, monitor_failed=monitor_failed, failure=failure)
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
        self.atomic_json(directory / "process-exit.json", {"returncode": result_code, "monitor_failure": failure,
                                                           "process": identity, "budget_stop_present": self.stop_present()})
        require(result_code == 0 and failure is None, "writer failed or exceeded monitored bounds; no automatic retry")
        return self.closed_report(pending)

    def _request_stop(self, reason, monitor_failed=None):
        failure = {"reason": reason, "unix": int(time.time()), "sentinel_written": False}
        try:
            self.signal_budget_stop(reason)
            failure["sentinel_written"] = True
        except Exception:
            pass
        if monitor_failed is not None:
            try:
                monitor_failed(failure)
            except Exception:
                failure["monitor_journal_error"] = True
        try:
            print("BUDGET_STOP_REQUESTED: " + reason, file=sys.stderr, flush=True)
        except Exception:
            failure["diagnostic_error"] = True
        return failure

    def _wait_tool(self, child, *, monitor_failed=None, failure=None):
        next_observation = time.monotonic()
        while child.poll() is None:
            if failure is None and time.monotonic() >= next_observation:
                try:
                    health(self.observe(), self.free_bytes())
                except Exception as exc:
                    reason = str(exc) if isinstance(exc, (Refusal, self.wrapper.Refusal)) else "authenticated budget monitor failed"
                    failure = self._request_stop(reason, monitor_failed)
                next_observation = time.monotonic() + MONITOR_INTERVAL
            time.sleep(0.2)
        return child.wait(), failure

    def closed_report(self, pending):
        return json_object(self.wrapper.read_protected(self.stage_dir(pending) / "writer.json",
                                                       mode=0o600, max_bytes=MAX_JSON))

    def _live_metadata(self):
        result, total = {}, 0
        self.wrapper.secure_path(DB, leaf_mode=0o700)
        for path in DB.iterdir():
            if SST.fullmatch(path.name):
                continue
            require(METADATA.fullmatch(path.name), "unknown closed database metadata filename")
            require(len(result) < MAX_METADATA_FILES, "too many metadata files")
            data = self.wrapper.read_protected(path, mode=0o600, max_bytes=MAX_METADATA_FILE)
            total += len(data)
            require(total <= MAX_METADATA_TOTAL, "closed metadata exceeds snapshot bound")
            result[path.name] = data
        require(result, "closed metadata snapshot is empty")
        return result

    def check_snapshot(self, snapshot):
        require(self._live_metadata() == snapshot, "closed database metadata changed")

    def _hash_sst(self, name, expected_size):
        require(SST.fullmatch(name), "invalid created SST filename")
        path = DB / name
        self.wrapper.secure_path(path, leaf_mode=0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        sha, size = hashlib.sha256(), 0
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size == expected_size, "created SST size/type mismatch")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                while block := stream.read(1024 * 1024):
                    size += len(block)
                    require(size <= expected_size, "created SST grew during hashing")
                    sha.update(block)
            after = os.fstat(fd)
            require(size == expected_size and (before.st_size, before.st_ino, before.st_mtime_ns) ==
                    (after.st_size, after.st_ino, after.st_mtime_ns), "created SST changed during hashing")
        finally:
            os.close(fd)
        return {"size": size, "sha256": sha.hexdigest()}

    def snapshot(self, pending, report):
        self.host.no_open_users(self.profile, expected_pid=self.pid)
        destination = self.stage_dir(pending) / "snapshot"
        if destination.exists() or destination.is_symlink():
            self.wrapper.secure_path(destination, leaf_mode=0o700)
            snapshot, total = {}, 0
            files = list(destination.iterdir())
            require(0 < len(files) <= MAX_METADATA_FILES, "closed snapshot file count outside bound")
            for path in files:
                require(METADATA.fullmatch(path.name), "unexpected closed snapshot file")
                data = self.wrapper.read_protected(path, mode=0o600, max_bytes=MAX_METADATA_FILE)
                total += len(data)
                require(total <= MAX_METADATA_TOTAL, "closed snapshot exceeds total bound")
                snapshot[path.name] = data
            self.check_snapshot(snapshot)
        else:
            snapshot = self._live_metadata()
            temporary = Path(tempfile.mkdtemp(prefix=".snapshot-", dir=self.stage_dir(pending)))
            for name, data in snapshot.items():
                fd = os.open(temporary / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            self._sync_dir(temporary)
            os.rename(temporary, destination)
            self._sync_dir(destination.parent)
            self.check_snapshot(snapshot)
        created = table_rows(report["sst_diff"]["created"])
        require(sum(row["size"] for row in created.values()) <= MAX_OUTPUT, "created SST snapshot exceeds output cap")
        hashes = {name: self._hash_sst(name, row["size"]) for name, row in created.items()}
        hashes_path = self.stage_dir(pending) / "created-sst-hashes.json"
        if hashes_path.exists() or hashes_path.is_symlink():
            previous_hashes = json_object(self.wrapper.read_protected(hashes_path, mode=0o600, max_bytes=MAX_JSON))
            require(previous_hashes == hashes, "created SST hashes differ from preserved closed evidence")
        else:
            self.atomic_json(hashes_path, hashes)
        return snapshot, hashes

    def _checked_queue(self, snapshot, created):
        observation = self.observe()
        health(observation, self.free_bytes())
        allowed = {"pebbleds/" + name: len(data) for name, data in snapshot.items()}
        allowed.update({"pebbleds/" + name: value["size"] for name, value in created.items()})
        for row in observation["queue"]["queue"]:
            require(row["name"] in allowed and row["size"] == allowed[row["name"]], "pending file is outside the closed generation")
            upload_priority(row["name"])
        return observation

    def _expiry(self, row, choice):
        require(self.host.locked, "selected queue change requires existing writer lock")
        self.host.no_open_users(self.profile, expected_pid=self.pid)
        fresh = self.observe()
        self.wrapper.validate_queue_selection(self.profile, fresh, item_id=row["id"], name=row["name"],
                                             size=row["size"], pid=self.pid, expiry=choice)
        self.host.rc(self.profile, "vfs/queue-set-expiry",
                     {"id": row["id"], "expiry": self.wrapper.QUEUE_EXPIRIES[choice]}, expected_pid=self.pid)

    def _settle(self, row, snapshot, created):
        if not row["uploading"]:
            self._expiry(row, "expedite")
        deadline = time.monotonic() + UPLOAD_TIMEOUT
        while True:
            observation = self._checked_queue(snapshot, created)
            if not any(item["id"] == row["id"] or item["name"] == row["name"] for item in observation["queue"]["queue"]):
                return
            require(time.monotonic() < deadline, "selected upload did not settle; keep cache and inspect")
            time.sleep(0.5)

    def defer_markers(self, snapshot, created):
        for row in self._checked_queue(snapshot, created)["queue"]["queue"]:
            if upload_priority(row["name"]) >= 5:
                require(not row["uploading"], "publication marker started uploading before verification")
                self._expiry(row, "defer")

    def drain_data(self, snapshot, created):
        while True:
            candidates = [row for row in self._checked_queue(snapshot, created)["queue"]["queue"]
                          if upload_priority(row["name"]) < 5]
            if not candidates:
                return
            self._settle(min(candidates, key=lambda row: (upload_priority(row["name"]), row["name"])), snapshot, created)

    @contextmanager
    def cloud(self):
        credentials = self.wrapper.parse_config(self.wrapper.read_protected(self.wrapper.CONFIG, mode=0o600).decode())
        s3, sts = self.host.cloud(credentials)
        try:
            identity = self.wrapper.verify_cloud_identity(s3, sts)
            require(identity == self.host.read_admission(self.profile)["identity"], "admitted cloud identity changed")
            yield s3
        finally:
            s3.close()
            sts.close()

    def verify(self, previous, report, snapshot, created, mode):
        self.guard(new_work=False, clean=mode == "final")
        self.check_snapshot(snapshot)
        observation = self._checked_queue(snapshot, created)
        if mode == "before-markers":
            require(all(upload_priority(row["name"]) >= 5 and row["uploading"] is False
                        for row in observation["queue"]["queue"]), "data is still pending before publication")
        ledger = self.wrapper.load_ledger(self.wrapper.read_protected(self.wrapper.LEDGER))
        with self.cloud() as s3:
            result = self.verifier.verify_generation(s3, ledger, previous, report, snapshot, created,
                                                     mode, digest(previous))
        self.guard(new_work=False, clean=mode == "final")
        self.check_snapshot(snapshot)
        return result

    def publish_markers(self, before, snapshot, created):
        names = before.get("changed_markers")
        require(isinstance(names, list) and len(set(names)) == len(names)
                and all(name in snapshot and upload_priority("pebbleds/" + name) >= 5 for name in names),
                "invalid changed-marker publication set")
        for name in sorted(names, key=lambda value: (upload_priority("pebbleds/" + value), value)):
            observation = self._checked_queue(snapshot, created)
            require(all(row["name"] in {"pebbleds/" + marker for marker in names}
                        for row in observation["queue"]["queue"]), "unexpected upload remains during marker publication")
            with self.cloud() as s3:
                self.verifier.recheck_publication_inputs(s3, before)
            selected = [row for row in observation["queue"]["queue"] if row["name"] == "pebbleds/" + name]
            if selected:
                self._settle(selected[0], snapshot, created)
            with self.cloud() as s3:
                key = "rhea/pebbleds/" + name
                head = s3.head_object(Bucket=BUCKET, Key=key)
                require(head.get("ContentLength") == 0 and isinstance(head.get("VersionId"), str)
                        and head["VersionId"] not in ("", "null"), "published marker lacks exact empty version")
                response = s3.get_object(Bucket=BUCKET, Key=key, VersionId=head["VersionId"])
                try:
                    require(response.get("VersionId") == head["VersionId"] and response.get("ContentLength") == 0
                            and response["Body"].read(1) == b"", "published marker bytes/version mismatch")
                finally:
                    response["Body"].close()
        self.guard(new_work=False, clean=True)

    def save_certificate(self, pending, certificate):
        path = STATE_ROOT / "checkpoints" / f"{pending['index']:06d}-{pending['action']}.json"
        if path.exists() or path.is_symlink():
            previous = json_object(self.wrapper.read_protected(path, mode=0o600, max_bytes=MAX_JSON))
            require(checkpoint_state(previous) == checkpoint_state(certificate)
                    and previous.get("pebble_reopen_verified") is True
                    and all(previous.get(key) == certificate.get(key) for key in
                            ("remote_metadata", "sst_lineage", "generation", "action", "previous_checkpoint_sha256")),
                    "existing generation certificate differs")
            return previous
        self.atomic_json(path, certificate)
        return certificate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=(*STAGES, "status", "recover-checkpoint"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "status" and args.apply:
        parser.error("status is read-only")
    runtime = None
    try:
        runtime = Runtime()
        controller = Controller(runtime)
        if args.command == "status":
            result = controller.status()
        elif args.command == "recover-checkpoint":
            result = controller.recover(apply=args.apply)
        else:
            result = controller.run(args.command, apply=args.apply)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        safe_errors = (Refusal,) if runtime is None else (Refusal, runtime.wrapper.Refusal, runtime.verifier.VerificationError)
        message = str(exc) if isinstance(exc, safe_errors) else "protected host, tool, or cloud operation failed; inspect durable evidence"
        print("FAIL_CLOSED: " + message, file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
