#!/usr/bin/env python3
"""Explicitly certify the one captured failed-close metadata generation.

This fixed recovery never opens Pebble for writing or calls the successful-step
validator with a fabricated report. It preserves the failed exit/report/journal,
publishes only their independently verified closed metadata, then acknowledges
the failure through a distinct checkpoint. A later step remains an explicit
operator action after a separately reviewed binary/pins transition.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import time
import types

TRUST = Path("/root/.local/share/rhea-wasabi-lab-admin-20261101")
INSTALL = TRUST / "reconcile_rhea_failed_step.py"
CONTROLLER = TRUST / "run_rhea_full_clone_steps.py"
CONTROLLER_SHA256 = "2a8b075e12bb467dc83941a9314343362d21a2776123763b6a0ffa9211701860"
WRAPPER_SHA256 = "76635430d99daa65a816dc1ae444145bbdfe844559b4b4bed2e30fbae0302545"
OLD_GO_SHA256 = "10a20266f97ef123e9357b20bcb14dbd16494ffb4c38e49eb473e0eeaf03bfbf"
GENERIC_SHA256 = "e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849"
DECODER_SHA256 = "edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b"
VERIFIER = TRUST / "verify_rhea_failed_step_close.py"
VERIFIER_SHA256 = "843ec340dcf9bee85d9d9e2b2f433fb27873ddf1a5c82ec7d16bc5edfcb83c92"
CAPTURE = TRUST / "realstep-20261103/failed-step-closed-capture"
STATE_ROOT = TRUST / "full-clone-steps"
STATE = STATE_ROOT / "state.json"
FAILED_STAGE = STATE_ROOT / "stages/000005-step"
ARCHIVE = STATE_ROOT / "failed-attempts/000005-step-01"
RECOVERY = STATE_ROOT / "recoveries/000005-step-failed-close-01"
PRIOR = STATE_ROOT / "checkpoints/000004-ratchet13.json"
BRIDGE = STATE_ROOT / "checkpoints/000004-failed-step-close-01.json"
PINS = {
    "capture.json": "81a5582329873fcc961fc23e7f704b4adb1df2ef367c4b9017039c680b1261b0",
    "writer.json": "2f1f914dad3679f43c101084d2037eb6209d9a571168d529477be144ef5492a1",
    "process-exit.json": "19809adc6d890b0d090dd09c924b6f28de16a69a6ae905653591537ace524dc5",
    "state.json": "d0abdfc8f5ba2457bf2dcd55d7e2bb5b94ab624bfdce5bb265bfe7adcf16bc6c",
    "checkpoint-gen4.json": "62a288014d932a0272a0083e6ccf02ab640f2d6cca2822d661987b03b1c03ad5",
}
FAILED_FILES = {"writer.json", "writer.stderr", "process-exit.json"}
EXPECTED_ERROR = ("creating object 47475309: stat /mnt/rhea-pebble-lab-writable-20261102/"
                  "pebbleds/47475309.sst: no such file or directory")
EXPECTED_STATE = {"format": "013", "marked": 93695, "count": 93697, "bytes": 7786594080785,
                  "inventory": "57b04d9508272a17df72aea1a6675fff1e13944ae83c884f988668b7f77cd134"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_controller():
    for path in (*reversed(CONTROLLER.parents), CONTROLLER):
        info = path.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, "untrusted controller path")
        require(stat.S_ISDIR(info.st_mode) if path != CONTROLLER else
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "invalid controller path type")
    fd = os.open(CONTROLLER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(16 * 1024**2 + 1)
    require(sha(raw) == CONTROLLER_SHA256, "controller source digest mismatch")
    module = types.ModuleType("rhea_failed_close_controller")
    module.__file__ = str(CONTROLLER)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(CONTROLLER), "exec"), module.__dict__)
    return module


def validate_captured(mod, state, previous, failed, exit_report, capture):
    require(state["generation"] == 4 and state["rewrites"] == 0 and state["checkpoint"] == previous,
            "captured completed-stage state differs")
    pending = state.get("pending")
    require(isinstance(pending, dict) and pending.get("index") == 5 and pending.get("action") == "step"
            and pending.get("phase") == "executing" and pending.get("previous_checkpoint_sha256") == mod.digest(previous)
            and pending.get("picker_plan") == failed.get("picker_plan")
            and pending.get("process") == exit_report.get("process") and pending == capture.get("pending"),
            "captured failed intent differs")
    require(mod.checkpoint_state(previous) == mod.report_state(failed, "before")
            == mod.report_state(failed, "after") == EXPECTED_STATE, "failed writer changed certified SST state")
    require(failed.get("action") == "step" and failed.get("error") == EXPECTED_ERROR
            and failed.get("io", {}).get("sst_write_bytes") == 0
            and failed.get("sst_diff") == {"created": [], "retired": [], "created_bytes": 0,
                                          "retired_bytes": 0, "created_count": 0, "retired_count": 0},
            "recovery is not the captured pre-create failure")
    require(exit_report.get("returncode") == 1 and exit_report.get("monitor_failure") is None
            and exit_report.get("budget_stop_present") is False, "failed process outcome differs")


def reconciled_state(mod, original, certificate):
    """Acknowledge the failure only through a complete, distinct bridge proof."""
    require(original["generation"] == 4 and original["rewrites"] == 0 and original.get("pending") is not None,
            "failed attempt is no longer pending")
    require(certificate.get("action") == "reconcile-failed-step-close" and certificate.get("generation") == 4
            and certificate.get("scope") == "fixed-disposable-full-clone-failed-step-close"
            and certificate.get("recovery_index") == certificate.get("failed_attempts") == 1
            and certificate.get("remote_generation_verified") is True and certificate.get("pebble_reopen_verified") is True
            and certificate.get("previous_checkpoint_sha256") == mod.digest(original["checkpoint"])
            and certificate.get("failed_attempt", {}).get("writer_sha256") == PINS["writer.json"]
            and certificate.get("failed_attempt", {}).get("state_sha256") == PINS["state.json"]
            and certificate.get("failed_attempt", {}).get("process_exit_sha256") == PINS["process-exit.json"]
            and certificate.get("failed_attempt", {}).get("capture_sha256") == PINS["capture.json"]
            and certificate.get("failed_attempt", {}).get("archive_path") == str(ARCHIVE.relative_to(TRUST))
            and certificate.get("sst_lineage", {}).get("rewrite_operations") == 0
            and mod.checkpoint_state(certificate) == EXPECTED_STATE, "failed-close bridge is incomplete or mismatched")
    mod.validate_inspection(certificate.get("reopen", {}), EXPECTED_STATE)
    result = copy.deepcopy(original)
    result.update(checkpoint=certificate, pending=None)
    return result


class Recovery:
    def __init__(self, mod, runtime, verifier):
        self.mod, self.rt, self.verifier = mod, runtime, verifier

    def new_bytes(self, path, data):
        self.rt.wrapper.secure_path(path, leaf_mode=0o600, missing=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.rt._sync_dir(path.parent)

    def record(self, name, value):
        self.new_bytes(RECOVERY / name, self.mod.canonical(value))

    def inputs(self):
        rt, mod = self.rt, self.mod
        rt.guard(new_work=False)
        require(not rt.stop_present(), "budget-stop sentinel requires separate reconciliation")
        rt.wrapper.secure_path(CAPTURE, leaf_mode=0o700)
        raw = {name: rt.wrapper.read_protected(CAPTURE / name, mode=0o600, max_bytes=mod.MAX_JSON) for name in PINS}
        require(all(sha(raw[name]) == digest for name, digest in PINS.items()), "captured failure evidence changed")
        data = {name: mod.json_object(value) for name, value in raw.items()}
        state, previous, failed, exit_report, capture = (data[name] for name in (
            "state.json", "checkpoint-gen4.json", "writer.json", "process-exit.json", "capture.json"))
        rt.validate_state(state)
        require(rt.wrapper.read_protected(STATE, mode=0o600, max_bytes=mod.MAX_JSON) == raw["state.json"]
                and rt.wrapper.read_protected(PRIOR, mode=0o600, max_bytes=mod.MAX_JSON) == raw["checkpoint-gen4.json"],
                "live journal or generation4 certificate differs from the capture")
        validate_captured(mod, state, previous, failed, exit_report, capture)
        require(not rt.writer_alive(state["pending"]), "failed writer is still alive")
        rt.wrapper.secure_path(FAILED_STAGE, leaf_mode=0o700)
        require({path.name for path in FAILED_STAGE.iterdir()} == FAILED_FILES, "unexpected failed-stage artifacts")
        stage = {name: rt.wrapper.read_protected(FAILED_STAGE / name, mode=0o600, max_bytes=mod.MAX_JSON)
                 for name in FAILED_FILES}
        require(stage["writer.json"] == raw["writer.json"] and stage["process-exit.json"] == raw["process-exit.json"],
                "original failed-stage bytes differ")
        rt.wrapper.secure_path(CAPTURE / "closed-metadata", leaf_mode=0o700)
        require({path.name for path in (CAPTURE / "closed-metadata").iterdir()} == set(capture["metadata"]),
                "captured metadata inventory changed")
        snapshot = {}
        for name, pin in capture["metadata"].items():
            require(mod.METADATA.fullmatch(name) and set(pin) == {"size", "sha256"}
                    and type(pin["size"]) is int and 0 <= pin["size"] <= mod.MAX_METADATA_FILE, "invalid captured metadata pin")
            blob = rt.wrapper.read_protected(CAPTURE / "closed-metadata" / name, mode=0o600, max_bytes=pin["size"])
            require(len(blob) == pin["size"] and sha(blob) == pin["sha256"], "captured metadata bytes changed")
            snapshot[name] = blob
        require(len(snapshot) == 8 and sum(map(len, snapshot.values())) <= mod.MAX_METADATA_TOTAL,
                "captured metadata bounds differ")
        rt.check_snapshot(snapshot)
        tables, stats = rt.verifier._decode_tables(snapshot[capture["markers"]["manifest"]])
        require(stats["marked_files"] == EXPECTED_STATE["marked"]
                and rt.verifier.base.inventory_digest(rt.verifier._inventory(tables)) == EXPECTED_STATE["inventory"]
                and {path.name for path in mod.DB.iterdir() if mod.SST.fullmatch(path.name)} == set(tables),
                "live SST inventory includes an unexpected or missing object")
        require(not (mod.DB / "47475309.sst").exists() and not (mod.DB / "47475309.sst").is_symlink(),
                "failed output name unexpectedly exists")
        require(rt.pid == capture["observation"]["pid"], "rclone process changed since closed capture")
        rt._checked_queue(snapshot, {})
        return raw, state, previous, failed, exit_report, capture, snapshot, stage

    def unchanged(self, raw, snapshot, stage):
        rt, mod = self.rt, self.mod
        require(rt.wrapper.read_protected(STATE, mode=0o600, max_bytes=mod.MAX_JSON) == raw["state.json"]
                and rt.wrapper.read_protected(PRIOR, mode=0o600, max_bytes=mod.MAX_JSON) == raw["checkpoint-gen4.json"],
                "journal/cert changed before explicit recovery commit")
        require(all(rt.wrapper.read_protected(CAPTURE / name, mode=0o600, max_bytes=mod.MAX_JSON) == blob
                    for name, blob in raw.items()), "captured evidence changed")
        require({path.name for path in FAILED_STAGE.iterdir()} == FAILED_FILES, "failed-stage file set changed")
        require(all(rt.wrapper.read_protected(FAILED_STAGE / name, mode=0o600, max_bytes=mod.MAX_JSON) == blob
                    for name, blob in stage.items()), "original failed-stage evidence changed")
        require(all(rt.wrapper.read_protected(CAPTURE / "closed-metadata" / name, mode=0o600,
                                             max_bytes=mod.MAX_METADATA_FILE) == blob
                    for name, blob in snapshot.items()), "captured metadata evidence changed")
        rt.check_snapshot(snapshot)
        require(not rt.stop_present(), "budget-stop sentinel appeared")

    def verify(self, previous, failed, exit_report, snapshot, mode):
        rt, mod = self.rt, self.mod
        rt.guard(new_work=False, clean=mode == "final")
        rt.check_snapshot(snapshot)
        rt._checked_queue(snapshot, {})
        ledger = rt.wrapper.load_ledger(rt.wrapper.read_protected(rt.wrapper.LEDGER))
        with rt.cloud() as s3:
            result = self.verifier.verify_failed_close(s3, ledger, previous, failed, exit_report,
                                                       snapshot, mode, mod.digest(previous))
        rt.check_snapshot(snapshot)
        rt.guard(new_work=False, clean=mode == "final")
        return result

    def publish(self, before, snapshot):
        rt = self.rt
        require(before.get("changed_markers") == ["marker.manifest.000007.MANIFEST-47475307"],
                "recovery publication is not the captured MANIFEST barrier")
        name = before["changed_markers"][0]
        with rt.cloud() as s3:
            self.verifier.recheck_failed_close_publication(s3, before)
        observed = rt._checked_queue(snapshot, {})
        require(all(row["name"] == "pebbleds/" + name for row in observed["queue"]["queue"]),
                "unverified data remains queued at recovery publication")
        selected = [row for row in observed["queue"]["queue"] if row["name"] == "pebbleds/" + name]
        if selected:
            rt._settle(selected[0], snapshot, {})
        with rt.cloud() as s3:
            key = "rhea/pebbleds/" + name
            head = s3.head_object(Bucket=self.mod.BUCKET, Key=key)
            require(head.get("ContentLength") == 0 and isinstance(head.get("VersionId"), str)
                    and head["VersionId"] not in ("", "null"), "published recovery marker has no empty version")
            obj = s3.get_object(Bucket=self.mod.BUCKET, Key=key, VersionId=head["VersionId"])
            try:
                require(obj.get("VersionId") == head["VersionId"] and obj.get("ContentLength") == 0
                        and obj["Body"].read(1) == b"", "published recovery marker differs")
            finally:
                obj["Body"].close()
            self.verifier.recheck_failed_close_publication(s3, before)
        rt.guard(new_work=False, clean=True)

    def run(self, *, apply):
        rt, mod = self.rt, self.mod
        with rt.lock():
            raw, state, previous, failed, exit_report, capture, snapshot, stage = self.inputs()
            initial = rt.run_tool("inspect")  # Pinned old binary, read-only action only.
            mod.validate_inspection(initial, EXPECTED_STATE)
            self.unchanged(raw, snapshot, stage)
            if not apply:
                return {"action": "reconcile-failed-step-close", "applied": False,
                        "state": EXPECTED_STATE, "failed_exit_code": 1, "initial_reopen": initial,
                        "writer_will_be_repeated": False, "logical_stage_generation": 4, "rewrites": 0}
            for path in (RECOVERY, ARCHIVE, BRIDGE):
                rt.wrapper.secure_path(path, missing=True)
                require(not path.exists() and not path.is_symlink(), "recovery artifact already exists; reconcile explicitly")
            rt.host.mkdir_private(RECOVERY)
            rt._sync_dir(RECOVERY.parent)
            rt._sync_dir(RECOVERY.parent.parent)
            for name, blob in raw.items():
                self.new_bytes(RECOVERY / ("captured-" + name), blob)
            artifact_hashes = {name: sha(blob) for name, blob in stage.items()}
            self.record("intent.json", {"started_unix": time.time(), "scope": "captured-failed-step-close-only",
                "capture_sha256": PINS, "failed_stage_sha256": artifact_hashes,
                "before_state_sha256": PINS["state.json"], "prior_checkpoint_sha256": mod.digest(previous),
                "closed_metadata": capture["metadata"], "archive_path": str(ARCHIVE), "bridge_path": str(BRIDGE),
                "recipe_sha256": sha(rt.wrapper.read_protected(INSTALL, mode=0o600)),
                "verifier_sha256": VERIFIER_SHA256, "execution_binding": state["binding"],
                "initial_reopen": initial, "writer_retry_performed": False})
            try:
                rt.defer_markers(snapshot, {})
                self.record("markers-deferred.json", rt.observe())
                rt.drain_data(snapshot, {})
                self.record("data-settled.json", rt.observe())
                self.unchanged(raw, snapshot, stage)
                before = self.verify(previous, failed, exit_report, snapshot, "before-markers")
                self.record("before-markers.json", before)
                require(mod.digest(mod.json_object(rt.wrapper.read_protected(RECOVERY / "before-markers.json", mode=0o600)))
                        == mod.digest(before), "durable recovery publication proof changed")
                self.publish(before, snapshot)
                self.record("marker-published.json", rt.observe())
                final = self.verify(previous, failed, exit_report, snapshot, "final")
                self.record("remote-final.json", final)
                reopened = rt.run_tool("inspect")
                mod.validate_inspection(reopened, EXPECTED_STATE)
                self.unchanged(raw, snapshot, stage)
                rt.guard(new_work=False, clean=True)
                final.update(generation=4, recovery_index=1, failed_attempts=1,
                    failed_close_verifier_sha256=VERIFIER_SHA256,
                    reopen=reopened, pebble_reopen_verified=True,
                    reopen_scope="guarded lab mount; failed-close metadata bound to independent S3 bytes",
                    failed_attempt={"writer_sha256": PINS["writer.json"], "state_sha256": PINS["state.json"],
                        "process_exit_sha256": PINS["process-exit.json"], "capture_sha256": PINS["capture.json"],
                        "original_stage_path": str(FAILED_STAGE.relative_to(TRUST)),
                        "archive_path": str(ARCHIVE.relative_to(TRUST)), "stage_file_sha256": artifact_hashes,
                        "returncode": 1, "successful_rewrite": False,
                        "execution_binding": state["binding"]}, recovery_recipe_sha256=sha(rt.wrapper.read_protected(INSTALL)))
                updated = reconciled_state(mod, state, final)
                self.new_bytes(BRIDGE, mod.canonical(final))
                self.record("commit-intent.json", {"before_state_sha256": PINS["state.json"],
                    "after_state_sha256": mod.digest(updated), "bridge_sha256": mod.digest(final),
                    "original_stage_path": str(FAILED_STAGE), "archive_path": str(ARCHIVE),
                    "archived_file_sha256": artifact_hashes, "changed_journal_fields": ["checkpoint", "pending"],
                    "logical_generation": 4, "rewrites": 0, "failed_attempts": 1})
                self.unchanged(raw, snapshot, stage)
                rt.host.mkdir_private(ARCHIVE.parent)
                rt._sync_dir(ARCHIVE.parent.parent)
                os.rename(FAILED_STAGE, ARCHIVE)
                rt._sync_dir(FAILED_STAGE.parent)
                rt._sync_dir(ARCHIVE.parent)
                require(all(rt.wrapper.read_protected(ARCHIVE / name, mode=0o600) == blob
                            for name, blob in stage.items()), "archived failure bytes differ")
                rt.write_state(updated)
                require(rt.load_state() == updated and rt.wrapper.read_protected(PRIOR, mode=0o600) == raw["checkpoint-gen4.json"],
                        "bridge commit or retained generation4 certificate differs")
                result = {"action": "reconcile-failed-step-close", "applied": True, "completed_unix": time.time(),
                    "generation": 4, "rewrites": 0, "pending": None, "failed_attempts": 1,
                    "checkpoint_sha256": mod.digest(final), "state_sha256": mod.digest(updated),
                    "archived_stage_path": str(ARCHIVE), "checkpoint_path": str(BRIDGE),
                    "writer_retry_performed": False, "new_step_requires_separate_explicit_apply": True}
                self.record("completed.json", result)
                return result
            except BaseException as exc:
                self.record("failure.json", {"failed_unix": time.time(), "error_type": type(exc).__name__,
                    "instruction": "Preserve all evidence/cache. Reconcile actual archive/journal/publication phase; never replay a writer automatically."})
                raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choices = parser.add_mutually_exclusive_group(required=True)
    choices.add_argument("--check", action="store_true")
    choices.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, "fixed root-protected installation required")
    sys.dont_write_bytecode = True
    mod = load_controller()
    wrapper = mod.load_pinned_module(mod.WRAPPER, WRAPPER_SHA256, "rhea_failed_close_bootstrap")
    wrapper.secure_path(INSTALL, leaf_mode=0o600)
    pins = mod.json_object(wrapper.read_protected(mod.PINS, mode=0o600, max_bytes=16_384))
    require(pins == {"schema": 1, "controller_sha256": CONTROLLER_SHA256,
                     "go_sha256": OLD_GO_SHA256, "verifier_sha256": GENERIC_SHA256},
            "failed-close recovery requires the unchanged captured deployment")
    require(sha(wrapper.read_protected(TRUST / "verify_rhea_lab_format3.py")) == DECODER_SHA256, "decoder pin mismatch")
    verifier = mod.load_pinned_module(VERIFIER, VERIFIER_SHA256, "rhea_failed_close_verifier")
    runtime = mod.Runtime()
    result = Recovery(mod, runtime, verifier).run(apply=args.apply)
    print(mod.canonical(result).decode(), end="", flush=True)


if __name__ == "__main__":
    main()
