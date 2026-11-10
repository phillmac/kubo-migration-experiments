#!/usr/bin/env python3
"""NOT DEPLOYED / NOT LIVE TESTED. Pure candidate proof API; no SDK or writer.

The pinned historical module supplies the unchanged decoder, version scanner,
object hashing and baseline/retirement checks. Its source and globals are never
modified. The new batch stage validator reconstructs intermediate states; the
new orchestration below performs one fresh full proof per invocation. An actual
host/controller/publication/recovery adapter remains UNIMPLEMENTED.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import secrets
import sys
import time
import types


HISTORICAL_VERIFIER_SHA256 = "43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796"
GENERATION13_SHA256 = "2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774"
WRITER_SCHEMA = "rhea-multi-sst-writer-v1"
CERTIFICATE_SCHEMA = 2
SCOPE = "disposable-full-clone-multi-sst-candidate"
MAX_UNITS = 2
MAX_INPUT = 256 * 1024**2
MAX_OUTPUT = 512 * 1024**2
MAX_METADATA = 64 * 1024**2
LIMITS = {"maximum_units": MAX_UNITS, "input_bytes": MAX_INPUT,
          "sst_output_bytes": MAX_OUTPUT, "metadata_write_bytes": MAX_METADATA,
          "cache_bytes": 96 * 1024**3, "minimum_free_bytes": 2 * 1024**4,
          "backlog_bytes": 768 * 1024**2, "backlog_files": 256}


def _load_proof():
    path = Path(__file__).with_name("verify_rhea_full_clone_bounded.py")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != HISTORICAL_VERIFIER_SHA256:
        raise RuntimeError("historical proof dependency hash mismatch")
    module = types.ModuleType("rhea_multi_sst_pinned_proof")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


proof = _load_proof()
require = proof.require
VerificationError = proof.VerificationError
canonical_sha256 = proof.canonical_sha256
BUCKET, PREFIX = proof.BUCKET, proof.PREFIX


def _stats(tables):
    return {"marked_files": sum(row["marked"] for row in tables.values())}


def _state(tables):
    return {"format": "013", "marked": _stats(tables)["marked_files"],
            "files": len(tables), "bytes": sum(row["size"] for row in tables.values()),
            "inventory_sha256": proof.base.inventory_digest(proof._inventory(tables))}


def _equal_json(actual, expected, message):
    # bool is not accepted as an integer anywhere in evidence.
    require(canonical_sha256(actual) == canonical_sha256(expected), message)


def _delta(diff):
    require(isinstance(diff, dict) and set(diff) == {
        "created", "retired", "created_count", "retired_count", "created_bytes", "retired_bytes"
    }, "invalid batch SST delta schema")
    result = []
    for label in ("created", "retired"):
        rows = proof._table_rows(diff[label], "invalid or duplicated batch SST row")
        require(diff[label] == sorted(rows.values(), key=lambda row: row["number"]), "unsorted SST delta")
        _equal_json(diff[label + "_count"], len(rows), "SST delta count mismatch")
        _equal_json(diff[label + "_bytes"], sum(row["size"] for row in rows.values()), "SST delta bytes mismatch")
        result.append(rows)
    require(not (result[0].keys() & result[1].keys()), "non-disjoint created/retired SSTs")
    return tuple(result)


def _plan(plan, tables):
    require(isinstance(plan, dict) and set(plan) == {
        "input_level", "output_level", "input_files", "input_bytes", "candidate_sha256", "plan_sha256"
    }, "invalid picker schema")
    names = plan["input_files"]
    require(isinstance(names, list) and names and all(isinstance(name, str) for name in names)
            and names == sorted(set(names)) and set(names) <= set(tables), "invalid picker inputs")
    level = plan["input_level"]
    require(type(level) is int and 0 <= level <= 6 and type(plan["output_level"]) is int
            and plan["output_level"] == level
            and all(tables[name]["level"] == level for name in names), "picker level mismatch")
    size = sum(tables[name]["size"] for name in names)
    require(type(plan["input_bytes"]) is int and 0 < size == plan["input_bytes"] <= MAX_INPUT,
            "picker input size mismatch")
    candidate_text = f"pebble-lab-candidate-v1\ninput-level\t{level}\noutput-level\t{level}\n"
    for name in sorted(names, key=lambda name: tables[name]["number"]):
        row = tables[name]
        candidate_text += f"{row['number']}\t{row['size']}\n"
    candidate = hashlib.sha256(candidate_text.encode()).hexdigest()
    state = _state(tables)
    plan_text = (f"fullclone-plan-v1\nformat\t013\nmarked\t{state['marked']}\n"
                 f"inventory\t{state['inventory_sha256']}\ncandidate\t{candidate}\n")
    require(plan["candidate_sha256"] == candidate
            and plan["plan_sha256"] == hashlib.sha256(plan_text.encode()).hexdigest(),
            "picker digest is not bound to exact prestate and inputs")
    return plan


def _io(io):
    require(isinstance(io, dict) and not io.get("blocked_budget_error"), "failed or missing cumulative I/O evidence")
    for label, limit in (("sst", MAX_OUTPUT), ("metadata", MAX_METADATA)):
        require(type(io.get("max_" + label + "_write_bytes")) is int
                and io["max_" + label + "_write_bytes"] == limit
                and type(io.get(label + "_write_bytes")) is int
                and 0 <= io[label + "_write_bytes"] <= limit, "aggregate write budget mismatch")


def validate_batch(report, before, after, before_stats, after_stats,
                   before_format, after_format, hashes):
    """Pure exact stage proof, including all intermediate picker/event/deltas.

    before/after are decoded MANIFEST inventories, with explicit marked bits.
    The cloud proof independently hashes every entry in hashes on EACH pass.
    Successful per-unit receipts alone do not satisfy this closed-stage proof.
    """
    # The pinned decoder uses the map key for names; Go rows include a name.
    for tables in (before, after):
        require(all(row.get("name", name) == name for name, row in tables.items()), "MANIFEST SST name mismatch")
    before = {name: dict(row, name=name) for name, row in before.items()}
    after = {name: dict(row, name=name) for name, row in after.items()}
    require(isinstance(report, dict) and report.get("schema") == WRITER_SCHEMA
            and report.get("action") == "multi-step", "unsupported batch writer schema/action")
    require(report.get("closed") is True and not report.get("error") and not report.get("attempted_unit"),
            "partial/failed/unclosed batch requires independent recovery or restore")
    require(before_format == after_format == "013", "batch must remain at format 013")
    require(_stats(before) == {"marked_files": before_stats["marked_files"]}
            and _stats(after) == {"marked_files": after_stats["marked_files"]}, "MANIFEST mark statistics mismatch")
    _equal_json(report.get("before"), _state(before), "batch initial state differs from MANIFEST")
    _equal_json(report.get("after"), _state(after), "batch final state differs from MANIFEST")
    request = report.get("request")
    require(isinstance(request, dict) and set(request) == {"maximum_units", "before", "initial_plan_sha256"},
            "invalid batch request schema")
    maximum = request["maximum_units"]
    require(type(maximum) is int and 1 <= maximum <= MAX_UNITS, "unit ceiling exceeds pilot")
    _equal_json(request["before"], _state(before), "batch expectation differs from exact prestate")
    units = report.get("units")
    require(isinstance(units, list) and 1 <= len(units) <= maximum
            and type(report.get("physical_compactions")) is int
            and report["physical_compactions"] == len(units), "physical compaction count mismatch")
    _io(report.get("io"))
    require(isinstance(hashes, dict), "closed output hashes missing")
    created, retired = _delta(report.get("sst_diff"))
    require(set(hashes) == set(created), "closed hashes differ from aggregate output")
    current, all_created, all_retired = copy.deepcopy(before), {}, {}
    events, jobs, touched = [], set(), set()
    total_input, prior_io = 0, {"sst_write_bytes": 0, "metadata_write_bytes": 0}
    for index, unit in enumerate(units):
        require(isinstance(unit, dict) and unit.get("action") == "step" and not unit.get("error"), "failed unit receipt")
        fresh, gone = _delta(unit.get("sst_diff"))
        names = set(fresh) | set(gone)
        require(fresh and gone and not touched.intersection(names), "missing/duplicated/non-disjoint unit delta")
        require(set(gone) <= set(current) and not set(fresh).intersection(current), "unrelated unit delta")
        for name, row in gone.items():
            require(all(current[name][key] == row[key] for key in row), "unit retired identity mismatch")
        plan = _plan(unit.get("picker_plan"), current)
        if index == 0:
            require(plan["plan_sha256"] == request["initial_plan_sha256"], "inspected first plan mismatch")
        next_state = {name: row for name, row in current.items() if name not in gone}
        next_state.update({name: dict(row, marked=False) for name, row in fresh.items()})
        unit_hashes = {name: hashes[name] for name in fresh if name in hashes}
        proof._validate_stage(unit, current, next_state, _stats(current), _stats(next_state), "013", "013", unit_hashes)
        _io(unit.get("io"))
        require(unit["io"]["sst_write_bytes"] - prior_io["sst_write_bytes"] >= sum(row["size"] for row in fresh.values()),
                "SST writes undercount unit output")
        for key in prior_io:
            require(prior_io[key] <= unit["io"][key] <= report["io"][key], "unit I/O counter reset or exceeds batch")
        prior_io = {key: unit["io"][key] for key in prior_io}
        begin, end = unit["compactions"]
        require(type(end.get("job")) is int and not begin.get("error") and end["job"] not in jobs,
                "duplicate or invalid compaction job")
        jobs.add(end["job"])
        events.extend(unit["compactions"])
        total_input += plan["input_bytes"]
        touched.update(names)
        all_created.update(fresh)
        all_retired.update(gone)
        current = next_state
    _equal_json(report.get("compactions"), events, "aggregate compaction events missing/duplicated/unrelated")
    require(current == after and all_created == created and all_retired == retired,
            "aggregate unit delta differs from final MANIFEST")
    require(type(report.get("input_bytes")) is int and report["input_bytes"] == total_input <= MAX_INPUT,
            "aggregate input exceeds pilot budget or differs from units")
    require(sum(row["size"] for row in created.values()) <= report["io"]["sst_write_bytes"] <= MAX_OUTPUT,
            "aggregate output exceeds write evidence")
    reason = report.get("stop_reason")
    require(reason in ("unit-limit", "no-marked-files", "next-unit-budget"), "missing successful bounded stop")
    if reason == "unit-limit":
        require(len(units) == maximum and not report.get("stopped_plan"), "premature unit-limit stop")
    elif reason == "no-marked-files":
        require(_state(after)["marked"] == 0 and len(units) < maximum
                and not report.get("stopped_plan"), "false no-marked stop")
    else:
        stopped = _plan(report.get("stopped_plan"), after)
        require(len(units) < maximum and not touched.intersection(stopped["input_files"]), "invalid stopped picker")
        require(total_input + stopped["input_bytes"] > MAX_INPUT
                or stopped["input_bytes"] > (MAX_OUTPUT - report["io"]["sst_write_bytes"]) // 2
                or report["io"]["metadata_write_bytes"] >= MAX_METADATA, "stopped candidate fits all budgets")
    return created, retired


def _predecessor(previous, expected_hash):
    require(isinstance(previous, dict) and canonical_sha256(previous) == expected_hash,
            "previous certificate hash mismatch")
    require(previous.get("remote_generation_verified") is True and previous.get("pebble_reopen_verified") is True,
            "previous certificate requires both remote proof and read-only reopen")
    require(type(previous.get("schema")) is int, "unknown predecessor schema")
    generation = previous.get("generation")
    require(type(generation) is int, "invalid predecessor generation")
    if previous["schema"] == 1:
        require(generation == 13 and expected_hash == GENERATION13_SHA256
                and previous.get("scope") == "fixed-disposable-full-clone-stage"
                and previous.get("sst_lineage", {}).get("rewrite_operations") == 9,
                "legacy predecessor must be exact protected generation-13 proof")
        return 1
    require(previous["schema"] == CERTIFICATE_SCHEMA and previous.get("scope") == SCOPE
            and previous.get("anchor_checkpoint_sha256") == GENERATION13_SHA256,
            "unknown candidate certificate ancestry/schema")
    count = previous.get("batch_checkpoint_count")
    require(type(count) is int and count >= 1 and generation == 13 + count
            and type(previous.get("physical_rewrite_total")) is int
            and previous["physical_rewrite_total"] == previous.get("sst_lineage", {}).get("rewrite_operations")
            and 9 + count <= previous["physical_rewrite_total"] <= 9 + MAX_UNITS * count,
            "checkpoint count and physical rewrite ancestry disagree")
    return count + 1


def recheck_publication_inputs(s3, before_report, expected_sha256):
    """Read-only HEAD gate for a future publisher; never uploads a marker."""
    require(isinstance(before_report, dict) and canonical_sha256(before_report) == expected_sha256
            and type(before_report.get("schema")) is int and before_report["schema"] == CERTIFICATE_SCHEMA
            and before_report.get("scope") == SCOPE and before_report.get("mode") == "before-markers"
            and before_report.get("remote_generation_verified") is False
            and before_report.get("pebble_reopen_verified") is False
            and before_report.get("bucket") == BUCKET and before_report.get("prefix") == "rhea/",
            "invalid protected prepublication candidate proof")
    metadata = proof._metadata_pins(before_report)
    changed = before_report.get("changed_markers")
    # This candidate stays at format 013: only the new MANIFEST marker changes.
    require(changed == [before_report.get("manifest_marker")] and not set(changed).intersection(metadata),
            "invalid candidate publication marker order/set")
    for name, pin in metadata.items():
        proof._head_matches(s3, name, pin)
    created = before_report.get("created_sst_versions")
    require(isinstance(created, dict) and 1 <= len(created) <= proof.MAX_CREATED_FILES,
            "new SST version evidence missing")
    for name, pin in created.items():
        proof._sst_name(name)
        proof._head_matches(s3, name, proof._pin(pin, content_hash=True))
    return {"metadata_rechecked": len(metadata), "new_ssts_rechecked": len(created)}


def verify_generation(s3, ledger: dict, previous_checkpoint: dict, go_report: dict,
                      metadata_bytes: dict[str, bytes], created_sst_hashes: dict,
                      mode: str, previous_checkpoint_sha256: str, *,
                      enumeration_workers=4, enumeration_stop=None, enumeration_metrics=None) -> dict:
    """Fresh four-worker full cloud proof for a CLOSED candidate batch.

    The caller supplies the protected ledger/previous proof and ONE closed
    snapshot. No SDK is constructed here and no object is written. Both calls
    use the same predecessor; before-markers output is never a predecessor.
    """
    require(enumeration_workers == 4 and type(enumeration_workers) is int,
            "candidate requires four-worker full enumeration on every pass")
    checkpoint_count = _predecessor(previous_checkpoint, previous_checkpoint_sha256)
    require(mode in ("before-markers", "final"), "unknown checkpoint verification mode")
    proof._enumeration_controls(enumeration_workers, enumeration_stop, enumeration_metrics)
    baseline = proof._baseline_pins(ledger)
    current_pins, lineage = proof._lineage(previous_checkpoint, baseline)
    previous_metadata = proof._metadata_pins(previous_checkpoint)
    old_markers, reopen = proof._validate_previous(previous_checkpoint, previous_checkpoint_sha256, previous_metadata)
    old_manifest = old_markers["manifest"]
    require(old_manifest in previous_metadata, "prior active MANIFEST pin missing")
    proof._check_enumeration_cancelled(enumeration_stop)
    before, before_stats = proof._decode_tables(proof._get_bytes(s3, old_manifest, previous_metadata[old_manifest]))
    require({name: row["size"] for name, row in before.items()} == {name: pin["size"] for name, pin in current_pins.items()},
            "prior MANIFEST differs from certified SST lineage")
    old_digest = proof.base.inventory_digest(proof._inventory(before))
    require(previous_checkpoint.get("sst_inventory_sha256") == old_digest
            and type(previous_checkpoint.get("sst_count")) is int and previous_checkpoint["sst_count"] == len(before)
            and type(previous_checkpoint.get("sst_bytes")) is int
            and previous_checkpoint["sst_bytes"] == sum(row["size"] for row in before.values()), "prior certificate inventory mismatch")
    declared_marked = previous_checkpoint.get("marked_after", previous_checkpoint.get("marked_files", previous_checkpoint.get("manifest_stats", {}).get("marked_files")))
    require(type(declared_marked) is int and declared_marked == before_stats["marked_files"], "prior marked-file certificate mismatch")
    if previous_checkpoint.get("remote_generation_verified") is True or previous_checkpoint.get("pebble_reopen_verified") is not True:
        require(isinstance(reopen, dict) and reopen.get("action") == "inspect" and not reopen.get("error"),
                "prior read-only reopen evidence missing or failed")
        proof._state_report(reopen, "after", before, before_stats, old_markers["after_format"])
    require(isinstance(metadata_bytes, dict) and 0 < len(metadata_bytes) <= proof.base.MAX_METADATA_FILES
            and all(isinstance(name, str) and proof.base.META_NAME.fullmatch(name) and isinstance(data, bytes)
                    and len(data) <= proof.base.MAX_METADATA_BYTES for name, data in metadata_bytes.items())
            and sum(map(len, metadata_bytes.values())) <= proof.base.MAX_METADATA_TOTAL, "invalid closed metadata snapshot")
    require(metadata_bytes.get("CURRENT") == b"MANIFEST-000000\n" and metadata_bytes.get("LOCK", b"") == b"", "invalid CURRENT/LOCK metadata")
    markers = proof._marker_info(metadata_bytes)
    changed = proof.changed_marker_names(previous_checkpoint, metadata_bytes)
    require(markers["manifest"] in metadata_bytes, "current MANIFEST marker target missing")
    after, after_stats = proof._decode_tables(metadata_bytes[markers["manifest"]])
    minimum = after_stats.get("min_unflushed_log", 0)
    require(minimum > 0 and f"{minimum:06d}.log" in metadata_bytes
            and any(name.startswith("OPTIONS-") for name in metadata_bytes), "required WAL/OPTIONS missing")
    created, retired = validate_batch(go_report, before, after, before_stats, after_stats,
                                       old_markers["after_format"], markers["after_format"], created_sst_hashes)
    require(not (set(created) & (set(baseline) | set(lineage["created"]))), "new SST reused a historical filename")
    for name in retired:
        lineage["retired"][name] = dict(current_pins[name])
    proof._check_enumeration_cancelled(enumeration_stop)
    latest, deleted = proof._collect_latest(s3, baseline, enumeration_workers=enumeration_workers,
                                      enumeration_stop=enumeration_stop, enumeration_metrics=enumeration_metrics)
    proof._check_enumeration_cancelled(enumeration_stop)
    expected_repo = {key: entry for key, entry in ledger.items() if not key.startswith(PREFIX)}
    require({key for key in latest if not key.startswith(PREFIX)} == set(expected_repo), "repository object inventory changed")
    for key, entry in expected_repo.items():
        require(proof._same_version(latest[key], {"size": entry.size, "version_id": entry.version_id, "etag": entry.etag}), "repository object version changed")
    known_ssts = set(baseline) | set(lineage["created"]) | set(created)
    remote_ssts = {key[len(PREFIX):]: row for key, row in latest.items() if key.startswith(PREFIX) and key.endswith(".sst")}
    require(all(key.startswith(PREFIX) for key in deleted if key.endswith(".sst")), "unexpected SST delete marker outside pebbleds")
    deleted_ssts = {key[len(PREFIX):]: row for key, row in deleted.items() if key.startswith(PREFIX) and key.endswith(".sst")}
    require(set(remote_ssts) <= known_ssts and set(deleted_ssts) <= set(lineage["retired"]), "unexpected SST object or delete marker")
    untouched = set(current_pins) - set(retired)
    require(untouched <= set(remote_ssts) and set(created) <= set(remote_ssts), "referenced SST object missing")
    for name in untouched:
        require(proof._same_version(remote_ssts[name], current_pins[name]), "untouched SST version changed")
    retirement = {}
    for name, pin in lineage["retired"].items():
        if name in remote_ssts:
            require(proof._same_version(remote_ssts[name], pin), "retired SST was overwritten")
            retirement[name] = {"state": "unchanged-unreferenced-latest", "version_id": pin["version_id"]}
        else:
            require(name in deleted_ssts, "retired SST lost without a recorded delete marker")
            retirement[name] = {"state": "latest-delete-marker", "delete_marker_version_id": deleted_ssts[name]["VersionId"]}
        proof._check_enumeration_cancelled(enumeration_stop)
        proof._head_matches(s3, name, pin, historical=True)
    new_bytes = 0
    for name, row in created.items():
        proof._check_enumeration_cancelled(enumeration_stop)
        lineage["created"][name] = proof._hash_new_sst(s3, name, remote_ssts[name], created_sst_hashes[name])
        new_bytes += row["size"]
    names = {key[len(PREFIX):] for key in latest if key.startswith(PREFIX) and not key.endswith(".sst")}
    require(all(proof.base.META_NAME.fullmatch(name) for name in names), "unknown latest metadata object")
    expected_names = set(metadata_bytes) - (set(changed) if mode == "before-markers" else set())
    require(names == expected_names, "remote metadata/publication barrier inventory mismatch")
    remote_metadata = {}
    for name in sorted(names):
        proof._check_enumeration_cancelled(enumeration_stop)
        data = metadata_bytes[name]
        row = latest[PREFIX + name]
        pin = proof._row_pin(row, hashlib.sha256(data).hexdigest())
        require(pin["size"] == len(data), "closed metadata size mismatch")
        require(proof._get_bytes(s3, name, pin) == data, "closed metadata bytes mismatch")
        proof._check_enumeration_cancelled(enumeration_stop)
        proof._head_matches(s3, name, pin)
        if name.startswith("marker.") and name not in changed:
            require(pin == previous_metadata[name], "unchanged marker version changed")
        remote_metadata[name] = pin
    if mode == "before-markers":
        for name in changed:
            proof._check_enumeration_cancelled(enumeration_stop)
            try:
                s3.head_object(Bucket=BUCKET, Key=PREFIX + name)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code")
                require(str(code) in ("404", "NoSuchKey", "NotFound"), "cannot confirm unpublished marker")
            else:
                raise VerificationError("publication marker appeared during verification")
    proof._check_enumeration_cancelled(enumeration_stop)
    lineage["rewrite_operations"] += go_report["physical_compactions"]
    return dict(markers, schema=CERTIFICATE_SCHEMA, scope=SCOPE,
                generation=previous_checkpoint["generation"] + 1,
                batch_checkpoint_count=checkpoint_count, anchor_checkpoint_sha256=GENERATION13_SHA256,
                physical_compactions=go_report["physical_compactions"],
                physical_rewrite_total=lineage["rewrite_operations"], unit_evidence=copy.deepcopy(go_report["units"]),
                limits=dict(LIMITS), historical_verifier_sha256=HISTORICAL_VERIFIER_SHA256,
                scanner_sha256=proof.SCANNER_SHA256, enumeration_workers=4, proof_pass_id=secrets.token_hex(16), bucket=BUCKET, prefix="rhea/",
                mode=mode, action=go_report["action"], verified_unix=time.time(),
                previous_checkpoint_sha256=previous_checkpoint_sha256, go_report_sha256=canonical_sha256(go_report),
                closed_output_hashes_sha256=canonical_sha256(created_sst_hashes), decoder_sha256=proof.DECODER_SHA256,
                ledger_sha256=proof.LEDGER_SHA256, remote_generation_verified=mode == "final", pebble_reopen_verified=False,
                changed_markers=changed, marked_after=after_stats["marked_files"], manifest_stats=after_stats,
                sst_count=len(after), sst_bytes=sum(row["size"] for row in after.values()),
                sst_inventory_sha256=proof.base.inventory_digest(proof._inventory(after)), sst_lineage=lineage,
                unchanged_sst_versions=len(untouched), new_sst_payload_bytes_downloaded=new_bytes,
                unchanged_sst_payload_bytes_downloaded=0, retired_sst_states=retirement,
                created_sst_versions={name: lineage["created"][name] for name in created},
                remote_metadata=remote_metadata, latest_delete_markers=len(deleted))


def finalize_checkpoint(before_proof, final_proof, reopen, reopened_metadata):
    """Pure final gate: two separate proofs, then exact read-only reopen.

    This does not publish markers, issue a writer, or mutate a durable journal.
    A future controller must retain its pending phase until this gate and a
    durable compare-and-swap certificate commit have BOTH succeeded.
    """
    for item, mode in ((before_proof, "before-markers"), (final_proof, "final")):
        require(isinstance(item, dict) and type(item.get("schema")) is int
                and item["schema"] == CERTIFICATE_SCHEMA and item.get("scope") == SCOPE
                and item.get("mode") == mode and item.get("pebble_reopen_verified") is False
                and item.get("remote_generation_verified") is (mode == "final")
                and item.get("anchor_checkpoint_sha256") == GENERATION13_SHA256
                and item.get("limits") == LIMITS
                and item.get("enumeration_workers") == 4
                and isinstance(item.get("proof_pass_id"), str) and len(item["proof_pass_id"]) == 32,
                "missing separate candidate proof pass")
    require(before_proof["proof_pass_id"] != final_proof["proof_pass_id"], "proof pass was reused")
    for key in ("generation", "batch_checkpoint_count", "physical_compactions", "physical_rewrite_total",
                "anchor_checkpoint_sha256", "previous_checkpoint_sha256", "go_report_sha256",
                "closed_output_hashes_sha256", "unit_evidence", "sst_inventory_sha256", "sst_count",
                "sst_bytes", "sst_lineage", "created_sst_versions", "changed_markers", "marked_after",
                "manifest", "manifest_marker", "format_marker", "after_format"):
        _equal_json(before_proof.get(key), final_proof.get(key), "proof passes disagree: " + key)
    changed = set(final_proof["changed_markers"])
    require(set(final_proof["remote_metadata"]) - set(before_proof["remote_metadata"]) == changed,
            "publication metadata inventory differs across proofs")
    for name, pin in before_proof["remote_metadata"].items():
        require(final_proof["remote_metadata"].get(name) == pin, "publication input version changed between passes")
    require(isinstance(reopened_metadata, dict) and set(reopened_metadata) == set(final_proof["remote_metadata"]),
            "reopen metadata inventory differs from independent cloud proof")
    for name, pin in final_proof["remote_metadata"].items():
        value = reopened_metadata[name]
        require(isinstance(value, bytes) and len(value) == pin["size"]
                and hashlib.sha256(value).hexdigest() == pin["sha256"], "reopen metadata bytes differ")
    require(isinstance(reopen, dict) and reopen.get("action") == "inspect" and not reopen.get("error")
            and reopen.get("compactions") == [], "read-only reopen missing or compacted")
    expected = {"format": "013", "marked": final_proof["marked_after"], "files": final_proof["sst_count"],
                "bytes": final_proof["sst_bytes"], "inventory_sha256": final_proof["sst_inventory_sha256"]}
    for side in ("before", "after"):
        observed = {"format": reopen.get(side + "_format"), "marked": reopen.get("marked_" + side),
                    "files": reopen.get("sst_files_" + side), "bytes": reopen.get("sst_bytes_" + side),
                    "inventory_sha256": reopen.get("sst_inventory_sha256_" + side)}
        _equal_json(observed, expected, "read-only reopen differs from closed checkpoint")
    fresh, gone = _delta(reopen.get("sst_diff"))
    _io(reopen.get("io"))
    require(not fresh and not gone and reopen["io"]["sst_write_bytes"] == reopen["io"]["metadata_write_bytes"] == 0,
            "read-only reopen performed writes")
    result = copy.deepcopy(final_proof)
    result.update(pebble_reopen_verified=True, reopen=copy.deepcopy(reopen),
                  before_markers_proof_sha256=canonical_sha256(before_proof),
                  final_remote_proof_sha256=canonical_sha256(final_proof))
    return result


def validate_fixture_file(path):
    """Cross-language harness input from the genuine Go fixture, never S3."""
    raw = Path(path).read_bytes()
    require(len(raw) <= 16 * 1024**2, "fixture evidence exceeds bound")
    data = json.loads(raw)
    before, before_stats = proof._decode_tables(base64.b64decode(data["before_manifest"], validate=True))
    after, after_stats = proof._decode_tables(base64.b64decode(data["after_manifest"], validate=True))
    validate_batch(data["report"], before, after, before_stats, after_stats, "013", "013", data["hashes"])
    return {"offline_fixture_validated": True, "physical_compactions": data["report"]["physical_compactions"]}


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--offline-go-fixture":
        raise SystemExit("NOT DEPLOYED / NOT LIVE TESTED: only --offline-go-fixture FILE is exposed")
    print(json.dumps(validate_fixture_file(sys.argv[2]), sort_keys=True))
