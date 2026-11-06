#!/usr/bin/env python3
"""Read-only certification of the one known failed full-clone step's close.

This is a distinct metadata bridge, never a successful rewrite report. The
caller owns the lifecycle lock, exact failed-receipt/capture hashes, closed
snapshot, publication, and fresh read-only Pebble reopen. Only injected S3 read
APIs are used by verification; no host state, queues, or objects are changed.
Every baseline SST's latest version is preserved. Historical uniqueness of
baseline SSTs is not claimed; the failed output must be absent from all history.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

GENERIC_SHA256 = "e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849"
DECODER_SHA256 = "edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b"
EXPECTED_PREVIOUS_SHA256 = "62a288014d932a0272a0083e6ccf02ab640f2d6cca2822d661987b03b1c03ad5"
EXPECTED_MARKED = 93_695
EXPECTED_LAST_SEQUENCE = 46_560_704
FAILED_OUTPUT = "47475309.sst"
FAILED_INPUT = {"name": "46893047.sst", "number": 46893047, "size": 67057322, "level": 6}
FAILURE = ("creating object 47475309: stat /mnt/rhea-pebble-lab-writable-20261102/"
           "pebbleds/47475309.sst: no such file or directory")
FAILED_METADATA_WRITE_BYTES = 15_780_604
OLD_MANIFEST = "MANIFEST-47475304"
MANIFEST = "MANIFEST-47475307"
MANIFEST_MARKER = "marker.manifest.000007." + MANIFEST
FORMAT_MARKER = "marker.format-version.000012.013"
WAL = "47475306.log"
WAL_SHA256 = "f0e3e4a176a44e86a5d7960f40e4e70a743a6a9b23dd3fdcb2563b25a0fa50a8"
OPTIONS = "OPTIONS-47475308"
METADATA_NAMES = {"CURRENT", "LOCK", OLD_MANIFEST, MANIFEST, MANIFEST_MARKER, FORMAT_MARKER, WAL, OPTIONS}
SCOPE = "fixed-disposable-full-clone-failed-step-close"
ACTION = "reconcile-failed-step-close"


def _load_generic():
    # The driver checks this module's protected installation and source hash.
    # Execute the checked generic source bytes, without modifying its internals.
    path = Path(__file__).with_name("verify_rhea_full_clone.py")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("generic verifier is not a private regular source file")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != GENERIC_SHA256:
        raise RuntimeError("generic verifier source hash mismatch")
    module = types.ModuleType("rhea_failed_step_generic")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    finally:
        sys.dont_write_bytecode = previous
    if module.DECODER_SHA256 != DECODER_SHA256:
        raise RuntimeError("generic verifier decoder pin differs")
    return module


# Source loading occurs only at import. The verification API reads no local files.
generic = _load_generic()
base = generic.base
VerificationError = generic.VerificationError
require = generic.require
canonical_sha256 = generic.canonical_sha256
BUCKET, PREFIX = generic.BUCKET, generic.PREFIX


def _validate_failure(report, process_exit, tables, stats):
    require(isinstance(report, dict) and report.get("action") == "step" and report.get("error") == FAILURE,
            "not the reviewed failed SST creation attempt")
    require(not report.get("blocked_budget_error"), "failed step also reported a budget failure")
    generic._state_report(report, "before", tables, stats, "013")
    generic._state_report(report, "after", tables, stats, "013")
    diff = report.get("sst_diff")
    require(isinstance(diff, dict) and set(diff) == {
        "created", "retired", "created_bytes", "retired_bytes", "created_count", "retired_count"
    } and diff["created"] == diff["retired"] == []
            and all(type(diff[key]) is int and diff[key] == 0 for key in
                    ("created_bytes", "retired_bytes", "created_count", "retired_count")),
            "failed step changed the SST inventory")
    io = report.get("io")
    expected_io = {"sst_write_bytes": 0, "metadata_write_bytes": FAILED_METADATA_WRITE_BYTES,
                   "max_sst_write_bytes": generic.MAX_OUTPUT_BYTES,
                   "max_metadata_write_bytes": generic.MAX_METADATA_WRITE_BYTES}
    require(isinstance(io, dict) and set(io) == set(expected_io)
            and all(type(io[key]) is int and io[key] == value for key, value in expected_io.items()),
            "failed step I/O evidence differs or includes SST writes")
    require(0 < io["metadata_write_bytes"] <= io["max_metadata_write_bytes"], "metadata write budget exceeded")
    seconds = report.get("seconds")
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0, "invalid failed-step duration")
    selected = generic._table_rows([FAILED_INPUT], "invalid fixed failed input")
    require(FAILED_INPUT["name"] in tables and tables[FAILED_INPUT["name"]]["marked"] is True
            and all(tables[FAILED_INPUT["name"]][key] == value for key, value in FAILED_INPUT.items() if key != "name"),
            "failed picker input differs from the prior MANIFEST")
    plan = report.get("picker_plan")
    require(isinstance(plan, dict) and set(plan) == {
        "input_level", "output_level", "input_files", "input_bytes", "candidate_sha256", "plan_sha256"
    } and type(plan["input_level"]) is int and type(plan["output_level"]) is int
            and plan["input_level"] == plan["output_level"] == FAILED_INPUT["level"]
            and plan["input_files"] == [FAILED_INPUT["name"]]
            and type(plan["input_bytes"]) is int and plan["input_bytes"] == FAILED_INPUT["size"]
            and plan["input_bytes"] <= generic.MAX_INPUT_BYTES, "failed authoritative picker plan differs")
    candidate = (f"pebble-lab-candidate-v1\ninput-level\t{plan['input_level']}\n"
                 f"output-level\t{plan['output_level']}\n{FAILED_INPUT['number']}\t{FAILED_INPUT['size']}\n")
    require(plan["candidate_sha256"] == hashlib.sha256(candidate.encode()).hexdigest(), "failed candidate hash differs")
    bound = (f"fullclone-plan-v1\nformat\t013\nmarked\t{stats['marked_files']}\n"
             f"inventory\t{base.inventory_digest(generic._inventory(tables))}\ncandidate\t{plan['candidate_sha256']}\n")
    require(plan["plan_sha256"] == report.get("expected_plan_sha256") == hashlib.sha256(bound.encode()).hexdigest(),
            "failed picker was not bound to the unchanged certified state")
    events = report.get("compactions")
    require(isinstance(events, list) and len(events) == 2 and all(isinstance(row, dict) for row in events),
            "failed step lacks exactly one compaction pair")
    begin, end = events
    require(set(begin) == {"type", "job", "reason", "error"}
            and begin == {"type": "begin", "job": 2, "reason": "rewrite", "error": ""}
            and type(begin["job"]) is int and type(end.get("job")) is int and end["job"] == 2
            and end.get("type") == "end" and end.get("reason") == "rewrite" and end.get("error") == FAILURE
            and set(end) in ({"type", "job", "reason", "input", "error", "milliseconds"},
                             {"type", "job", "reason", "input", "output", "error", "milliseconds"})
            and generic._table_rows(end["input"], "invalid failed compaction input") == selected
            and end.get("output", []) == [] and type(end["milliseconds"]) is int and end["milliseconds"] >= 0,
            "compaction events do not describe the reviewed failure with no output")
    require(isinstance(process_exit, dict) and set(process_exit) == {
        "returncode", "monitor_failure", "budget_stop_present", "process"
    } and type(process_exit["returncode"]) is int and process_exit["returncode"] == 1
            and process_exit["monitor_failure"] is None and process_exit["budget_stop_present"] is False,
            "failed child did not exit with the expected monitored failure")
    process = process_exit["process"]
    require(isinstance(process, dict) and set(process) == {"pid", "start_ticks", "boot_id"}
            and type(process["pid"]) is int and process["pid"] > 1
            and isinstance(process["start_ticks"], str) and process["start_ticks"].isdigit()
            and isinstance(process["boot_id"], str) and re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", process["boot_id"]),
            "failed child process identity missing")


def _collect_latest(s3):
    latest, deleted, seen = {}, {}, set()
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=BUCKET, Prefix="rhea/"):
        for is_delete, rows in ((False, page.get("Versions", [])), (True, page.get("DeleteMarkers", []))):
            for row in rows:
                key = row.get("Key")
                require(isinstance(key, str) and key.startswith("rhea/"), "listing returned an object outside scope")
                require(key != PREFIX + FAILED_OUTPUT, "failed output has object or delete-marker history")
                if row.get("IsLatest") is not True:
                    continue
                require(key not in seen, "duplicate latest object or delete marker")
                seen.add(key)
                require(isinstance(row.get("VersionId"), str) and row["VersionId"] not in ("", "null"),
                        "latest object lacks a pinned VersionId")
                if is_delete:
                    deleted[key] = row
                else:
                    require(generic._integer(row.get("Size")) and isinstance(row.get("ETag"), str) and row["ETag"],
                            "invalid latest object size/ETag")
                    latest[key] = row
    return latest, deleted


def verify_failed_close(s3, ledger, previous_checkpoint, failed_report, process_exit,
                        metadata_bytes, mode, previous_checkpoint_sha256):
    """Certify the known failed step's closed metadata, without any publication."""
    require(mode in ("before-markers", "final"), "unknown failed-close verification mode")
    require(previous_checkpoint_sha256 == EXPECTED_PREVIOUS_SHA256, "failed-close parent is not the pinned generation 4")
    baseline = generic._baseline_pins(ledger)
    current, lineage = generic._lineage(previous_checkpoint, baseline)
    require(lineage["created"] == lineage["retired"] == {} and lineage["rewrite_operations"] == 0
            and current == baseline, "failed-close parent already contains SST rewrites")
    previous_metadata = generic._metadata_pins(previous_checkpoint)
    old_markers, reopen = generic._validate_previous(previous_checkpoint, previous_checkpoint_sha256, previous_metadata)
    require(previous_checkpoint.get("generation") == 4 and previous_checkpoint.get("action") == "ratchet13"
            and previous_checkpoint.get("mode") == "final" and previous_checkpoint.get("pebble_reopen_verified") is True
            and old_markers["after_format"] == "013" and old_markers["manifest"] == OLD_MANIFEST
            and old_markers["format_marker"] == FORMAT_MARKER, "unexpected failed-close predecessor")
    old_data = generic._get_bytes(s3, OLD_MANIFEST, previous_metadata[OLD_MANIFEST])
    before, before_stats = generic._decode_tables(old_data)
    require({name: row["size"] for name, row in before.items()} == {name: pin["size"] for name, pin in baseline.items()},
            "prior MANIFEST differs from immutable baseline SST inventory")
    inventory = base.inventory_digest(generic._inventory(before))
    require(previous_checkpoint.get("sst_count") == len(before)
            and previous_checkpoint.get("sst_bytes") == sum(row["size"] for row in before.values())
            and previous_checkpoint.get("sst_inventory_sha256") == inventory
            and previous_checkpoint.get("marked_after") == before_stats["marked_files"] == EXPECTED_MARKED,
            "prior checkpoint counters or marks differ from its MANIFEST")
    require(isinstance(reopen, dict) and reopen.get("action") == "inspect" and not reopen.get("error")
            and reopen.get("compactions") == [], "prior read-only reopen proof missing")
    generic._state_report(reopen, "before", before, before_stats, "013")
    generic._state_report(reopen, "after", before, before_stats, "013")
    _validate_failure(failed_report, process_exit, before, before_stats)
    require(isinstance(metadata_bytes, dict) and set(metadata_bytes) == METADATA_NAMES
            and all(isinstance(data, bytes) and len(data) <= base.MAX_METADATA_BYTES for data in metadata_bytes.values())
            and sum(map(len, metadata_bytes.values())) <= base.MAX_METADATA_TOTAL,
            "closed failed-step metadata inventory differs")
    require(metadata_bytes["CURRENT"] == b"MANIFEST-000000\n" and metadata_bytes["LOCK"] == b""
            and metadata_bytes[MANIFEST_MARKER] == metadata_bytes[FORMAT_MARKER] == b""
            and metadata_bytes[OLD_MANIFEST] == old_data, "retained metadata or publication marker changed")
    require(len(metadata_bytes[WAL]) == 11 and hashlib.sha256(metadata_bytes[WAL]).hexdigest() == WAL_SHA256,
            "closed WAL differs from the captured empty WAL")
    old_options = [pin for name, pin in previous_metadata.items() if name.startswith("OPTIONS-")]
    require(len(old_options) == 1 and len(metadata_bytes[OPTIONS]) == old_options[0]["size"]
            and hashlib.sha256(metadata_bytes[OPTIONS]).hexdigest() == old_options[0]["sha256"],
            "closed OPTIONS differs from the prior configuration")
    markers = generic._marker_info(metadata_bytes)
    changed = generic.changed_marker_names(previous_checkpoint, metadata_bytes)
    require(markers == {"manifest": MANIFEST, "manifest_marker": MANIFEST_MARKER,
                        "format_marker": FORMAT_MARKER, "after_format": "013"}
            and changed == [MANIFEST_MARKER], "failed close changed more than the MANIFEST publication barrier")
    after, after_stats = generic._decode_tables(metadata_bytes[MANIFEST])
    require(after == before, "failed close changed SST number, size, level, or per-file mark")
    require(after_stats.get("min_unflushed_log") == int(WAL[:-4])
            and before_stats.get("last_sequence") == after_stats.get("last_sequence") == EXPECTED_LAST_SEQUENCE,
            "failed close changed sequence state or required WAL identity")
    latest, deleted = _collect_latest(s3)
    require(not any(key.endswith(".sst") for key in deleted), "latest SST delete marker found after failed step")
    require(all(key.startswith(PREFIX) and base.META_NAME.fullmatch(key[len(PREFIX):]) for key in deleted),
            "delete marker outside permitted Pebble metadata")
    base.unchanged_ssts_and_repo(latest, ledger)
    names = {key[len(PREFIX):] for key in latest if key.startswith(PREFIX) and not key.endswith(".sst")}
    expected_names = METADATA_NAMES - ({MANIFEST_MARKER} if mode == "before-markers" else set())
    require(names == expected_names, "remote closed metadata/publication inventory differs")
    remote_metadata = {}
    for name in sorted(names):
        data = metadata_bytes[name]
        pin = generic._row_pin(latest[PREFIX + name], hashlib.sha256(data).hexdigest())
        require(pin["size"] == len(data), "closed metadata size differs remotely")
        require(generic._get_bytes(s3, name, pin) == data, "closed metadata bytes differ remotely")
        generic._head_matches(s3, name, pin)
        if name in previous_metadata:
            require(pin == previous_metadata[name], "retained metadata version changed during failed close")
        remote_metadata[name] = pin
    if mode == "before-markers":
        try:
            s3.head_object(Bucket=BUCKET, Key=PREFIX + MANIFEST_MARKER)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            require(str(code) in ("404", "NoSuchKey", "NotFound"), "cannot establish unpublished MANIFEST marker")
        else:
            raise VerificationError("failed-close MANIFEST marker appeared before publication")
    return dict(markers, schema=1, scope=SCOPE, action=ACTION, mode=mode, bucket=BUCKET, prefix="rhea/",
                verified_unix=time.time(), previous_checkpoint_sha256=previous_checkpoint_sha256,
                failed_report_sha256=canonical_sha256(failed_report), process_exit_sha256=canonical_sha256(process_exit),
                failed_process=dict(process_exit["process"]), failed_action="step", failure_preserved=True,
                failure=FAILURE, successful_rewrites=0, failed_output=FAILED_OUTPUT,
                failed_output_absent_all_versions=True, sst_latest_versions_unchanged=True,
                sst_history_scope="latest versions for baseline SSTs; all versions/delete markers for the failed output",
                generic_verifier_sha256=GENERIC_SHA256, decoder_sha256=DECODER_SHA256,
                ledger_sha256=generic.LEDGER_SHA256, remote_generation_verified=mode == "final",
                pebble_reopen_verified=False, changed_markers=changed, marked_after=after_stats["marked_files"],
                manifest_stats=after_stats, sst_count=len(after), sst_bytes=sum(row["size"] for row in after.values()),
                sst_inventory_sha256=inventory, sst_file_state_sha256=canonical_sha256(after), sst_lineage=lineage,
                unchanged_sst_versions=len(baseline), new_sst_payload_bytes_downloaded=0,
                unchanged_sst_payload_bytes_downloaded=0, retired_sst_states={}, created_sst_versions={},
                remote_metadata=remote_metadata, latest_delete_markers=len(deleted),
                closed_metadata_sha256=canonical_sha256({name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                                        for name, data in metadata_bytes.items()}))


def recheck_failed_close_publication(s3, before_report):
    """HEAD exact preverified metadata; allow the marker to be published already."""
    require(isinstance(before_report, dict) and before_report.get("scope") == SCOPE
            and before_report.get("action") == ACTION and before_report.get("mode") == "before-markers"
            and before_report.get("remote_generation_verified") is False
            and before_report.get("bucket") == BUCKET and before_report.get("prefix") == "rhea/"
            and before_report.get("previous_checkpoint_sha256") == EXPECTED_PREVIOUS_SHA256
            and before_report.get("successful_rewrites") == 0 and before_report.get("failure_preserved") is True
            and before_report.get("failed_output_absent_all_versions") is True
            and before_report.get("sst_latest_versions_unchanged") is True
            and before_report.get("after_format") == "013" and before_report.get("marked_after") == EXPECTED_MARKED
            and before_report.get("changed_markers") == [MANIFEST_MARKER]
            and before_report.get("manifest_marker") == MANIFEST_MARKER
            and before_report.get("format_marker") == FORMAT_MARKER
            and before_report.get("created_sst_versions") == before_report.get("retired_sst_states") == {},
            "invalid failed-close prepublication evidence")
    lineage = before_report.get("sst_lineage", {})
    require(lineage.get("created") == lineage.get("retired") == {} and lineage.get("rewrite_operations") == 0,
            "failed-close publication contains SST rewrites")
    pins = generic._metadata_pins(before_report)
    require(set(pins) == METADATA_NAMES - {MANIFEST_MARKER}, "failed-close prepublication metadata inventory differs")
    for name, pin in pins.items():
        generic._head_matches(s3, name, pin)
    return {"metadata_rechecked": len(pins), "new_ssts_rechecked": 0, "checked_unix": time.time()}
