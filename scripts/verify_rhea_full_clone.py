#!/usr/bin/env python3
"""Read-only S3 certification of one guarded full-clone migration stage.

Imported by run_rhea_full_clone_steps.py, which owns the host lock, credentials,
closed-file snapshot, upload ordering and reopen. This module never opens Pebble,
changes a queue, writes S3, or downloads an unchanged SST. The caller must obtain
the ledger through the pinned wrapper's load_ledger/read_protected functions.

The existing, certified format-3 decoder is retained unchanged and hash pinned.
The pure verify_generation API accepts injected S3/ledger fixtures for tests.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import time

DECODER_SHA256 = "edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b"
LEDGER_SHA256 = "38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96"
decoder_path = Path(__file__).with_name("verify_rhea_lab_format3.py")
if hashlib.sha256(decoder_path.read_bytes()).hexdigest() != DECODER_SHA256:
    raise RuntimeError("certified MANIFEST decoder source hash mismatch")
decoder_spec = importlib.util.spec_from_file_location("rhea_full_clone_decoder", decoder_path)
base = importlib.util.module_from_spec(decoder_spec)
sys.modules[decoder_spec.name] = base
decoder_spec.loader.exec_module(base)

VerificationError = base.VerificationError
require = base.require
BUCKET = base.BUCKET
PREFIX = base.PREFIX
MAX_INPUT_BYTES = 256 * 1024**2
MAX_OUTPUT_BYTES = 512 * 1024**2
MAX_METADATA_WRITE_BYTES = 64 * 1024**2
MAX_CREATED_FILES = 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
TRANSITIONS = {
    "ratchet6": ("003", "006"), "ratchet7": ("006", "007"),
    "ratchet10": ("007", "010"), "ratchet13": ("010", "013"),
    "step": ("013", "013"),
}


def canonical_sha256(value) -> str:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    return hashlib.sha256(encoded).hexdigest()


def _integer(value, minimum=0) -> bool:
    return type(value) is int and value >= minimum


def _sst_name(name: str) -> int:
    require(isinstance(name, str) and base.SST_NAME.fullmatch(name), "invalid SST basename")
    number = int(name[:-4])
    require(number > 0 and name == f"{number:06d}.sst", "noncanonical SST filename")
    return number


def _pin(value: dict, *, content_hash=False) -> dict:
    require(isinstance(value, dict), "invalid object-version pin")
    keys = {"size", "version_id", "etag"} | ({"sha256"} if content_hash else set())
    require(set(value) == keys, "unexpected object-version pin fields")
    require(_integer(value["size"]) and isinstance(value["version_id"], str)
            and value["version_id"] not in ("", "null") and isinstance(value["etag"], str)
            and value["etag"], "invalid object-version pin values")
    if content_hash:
        require(isinstance(value["sha256"], str) and SHA256.fullmatch(value["sha256"]), "invalid content SHA256")
    return dict(value)


def _baseline_pins(ledger: dict) -> dict:
    inventory = base.baseline_inventory(ledger)
    require(len(inventory) == base.EXPECTED_SSTS and sum(inventory.values()) == base.EXPECTED_SST_BYTES
            and base.inventory_digest(inventory) == base.EXPECTED_INVENTORY, "baseline inventory pin mismatch")
    pins = {}
    for key, entry in ledger.items():
        if key.endswith(".sst"):
            name = key[len(PREFIX):]
            _sst_name(name)
            pins[name] = _pin({"size": entry.size, "version_id": entry.version_id, "etag": entry.etag})
    return pins


def _lineage(previous: dict, baseline: dict) -> tuple[dict, dict]:
    source = previous.get("sst_lineage", {
        "schema": 1, "baseline_ledger_sha256": LEDGER_SHA256,
        "created": {}, "retired": {}, "rewrite_operations": 0,
    })
    require(isinstance(source, dict) and set(source) == {
        "schema", "baseline_ledger_sha256", "created", "retired", "rewrite_operations"
    }, "invalid SST lineage schema")
    require(type(source["schema"]) is int and source["schema"] == 1
            and source["baseline_ledger_sha256"] == LEDGER_SHA256
            and _integer(source["rewrite_operations"]), "SST lineage anchor mismatch")
    require(isinstance(source["created"], dict) and isinstance(source["retired"], dict), "invalid SST lineage maps")
    created, retired = {}, {}
    all_pins = dict(baseline)
    for name, value in source["created"].items():
        _sst_name(name)
        require(name not in all_pins, "created SST reuses a baseline filename")
        created[name] = all_pins[name] = _pin(value, content_hash=True)
    for name, value in source["retired"].items():
        _sst_name(name)
        require(name in all_pins and value == all_pins[name], "retired SST pin differs from its origin")
        retired[name] = dict(value)
    current = {name: pin for name, pin in all_pins.items() if name not in retired}
    lineage = {"schema": 1, "baseline_ledger_sha256": LEDGER_SHA256,
               "created": created, "retired": retired, "rewrite_operations": source["rewrite_operations"]}
    return current, lineage


def _metadata_pins(previous: dict) -> dict:
    pins = previous.get("remote_metadata")
    require(isinstance(pins, dict) and 0 < len(pins) <= base.MAX_METADATA_FILES, "previous metadata certificate missing")
    result = {}
    for name, value in pins.items():
        require(isinstance(name, str) and base.META_NAME.fullmatch(name), "invalid prior metadata basename")
        result[name] = _pin(value, content_hash=True)
        require(value["size"] <= base.MAX_METADATA_BYTES, "prior metadata exceeds size bound")
    return result


def _marker_info(names) -> dict:
    manifests = [name for name in names if base.MANIFEST_MARKER.fullmatch(name)]
    formats = [name for name in names if base.FORMAT_MARKER.fullmatch(name)]
    require(len(manifests) == len(formats) == 1, "ambiguous or missing current markers")
    manifest, fmt = manifests[0], formats[0]
    return {"manifest_marker": manifest, "format_marker": fmt,
            "manifest": base.MANIFEST_MARKER.fullmatch(manifest)[2],
            "after_format": base.FORMAT_MARKER.fullmatch(fmt)[2]}


def changed_marker_names(previous_checkpoint: dict, metadata_bytes: dict) -> list[str]:
    """Return only fresh publication barriers, manifest before format marker."""
    previous_pins = _metadata_pins(previous_checkpoint)
    before, after = _marker_info(previous_pins), _marker_info(metadata_bytes)
    changed = []
    for key, pattern in (("manifest_marker", base.MANIFEST_MARKER), ("format_marker", base.FORMAT_MARKER)):
        old, new = before[key], after[key]
        require(metadata_bytes[new] == b"", "nonempty current marker")
        if new != old:
            require(int(pattern.fullmatch(new)[1]) > int(pattern.fullmatch(old)[1]), "marker sequence failed to advance")
            require(new not in previous_pins, "new marker was already present in previous checkpoint")
            changed.append(new)
    require(after["manifest_marker"] in changed, "stage did not publish a new MANIFEST marker")
    require((before["after_format"] != after["after_format"]) == (after["format_marker"] in changed),
            "format marker transition mismatch")
    return changed


def _decode_tables(data: bytes) -> tuple[dict, dict]:
    state = {}
    stats = {"records": 0, "additions": 0, "deletions": 0}
    for record in base.manifest_records(data):
        base.parse_edit(record, state, stats)
        stats["records"] += 1
    require(stats["records"] > 0, "empty MANIFEST")
    tables = {}
    for (level, number), (size, marked) in state.items():
        name = f"{number:06d}.sst"
        require(name not in tables, "SST appears at multiple levels")
        tables[name] = {"number": number, "size": size, "level": level, "marked": marked}
    stats["marked_files"] = sum(row["marked"] for row in tables.values())
    stats["levels"] = {str(level): sum(row["level"] == level for row in tables.values()) for level in range(7)}
    return tables, stats


def _inventory(tables: dict) -> dict:
    return {row["number"]: row["size"] for row in tables.values()}


def _head_matches(s3, name: str, pin: dict, *, historical=False) -> None:
    kwargs = {"VersionId": pin["version_id"]} if historical else {}
    head = s3.head_object(Bucket=BUCKET, Key=PREFIX + name, **kwargs)
    require(not head.get("DeleteMarker", False) and
            (head.get("VersionId"), head.get("ContentLength"), head.get("ETag")) ==
            (pin["version_id"], pin["size"], pin["etag"]), "object HEAD no longer matches pinned version")


def _get_bytes(s3, name: str, pin: dict) -> bytes:
    require(pin["size"] <= base.MAX_METADATA_BYTES, "metadata GET exceeds bound")
    response = s3.get_object(Bucket=BUCKET, Key=PREFIX + name, VersionId=pin["version_id"])
    body = response["Body"]
    try:
        data = body.read(pin["size"] + 1)
    finally:
        body.close()
    require((response.get("VersionId"), response.get("ContentLength"), response.get("ETag")) ==
            (pin["version_id"], pin["size"], pin["etag"]), "metadata GET version identity mismatch")
    require(len(data) == pin["size"] and hashlib.sha256(data).hexdigest() == pin["sha256"], "metadata GET content mismatch")
    return data


def _validate_previous(previous: dict, expected_hash: str, pins: dict) -> tuple[dict, dict]:
    require(isinstance(expected_hash, str) and SHA256.fullmatch(expected_hash)
            and canonical_sha256(previous) == expected_hash, "previous checkpoint hash mismatch")
    require(previous.get("remote_generation_verified") is True or previous.get("remote_format3_closure_verified") is True,
            "previous report is not a final remote checkpoint")
    require(previous.get("bucket", BUCKET) == BUCKET and previous.get("prefix", "rhea/") == "rhea/",
            "previous checkpoint scope mismatch")
    markers = _marker_info(pins)
    require(all(previous.get(key) == markers[key] for key in ("manifest", "manifest_marker", "format_marker")),
            "previous certificate marker mismatch")
    declared_format = previous.get("after_format", previous.get("format_major_version", markers["after_format"]))
    require(declared_format == markers["after_format"], "previous certificate format mismatch")
    return markers, previous.get("reopen", {})


def _table_rows(rows, message: str) -> dict:
    require(isinstance(rows, list) and len(rows) <= MAX_CREATED_FILES, message)
    result = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"name", "number", "size", "level"}, message)
        number = _sst_name(row["name"])
        require(type(row["number"]) is int and row["number"] == number
                and _integer(row["size"], 1) and _integer(row["level"]) and row["level"] <= 6
                and row["name"] not in result, message)
        result[row["name"]] = dict(row)
    return result


def _state_report(report: dict, suffix: str, tables: dict, stats: dict, fmt: str) -> None:
    expected = {"sst_files_" + suffix: len(tables), "sst_bytes_" + suffix: sum(t["size"] for t in tables.values()),
                "sst_inventory_sha256_" + suffix: base.inventory_digest(_inventory(tables)),
                "marked_" + suffix: stats["marked_files"]}
    require(report.get(suffix + "_format") == fmt, "Go report format differs from checkpoint")
    require(all(type(report.get(key)) is type(value) and report[key] == value for key, value in expected.items()),
            "Go report inventory/mark counters differ from MANIFEST")


def _validate_stage(report: dict, before: dict, after: dict, before_stats: dict, after_stats: dict,
                    before_format: str, after_format: str, hashes: dict) -> tuple[dict, dict]:
    action = report.get("action")
    require(action in TRANSITIONS and TRANSITIONS[action] == (before_format, after_format), "unsupported stage transition")
    require(not report.get("error"), "Go mutation reported an error")
    _state_report(report, "before", before, before_stats, before_format)
    _state_report(report, "after", after, after_stats, after_format)
    diff = report.get("sst_diff")
    require(isinstance(diff, dict), "Go SST diff missing")
    created = _table_rows(diff.get("created"), "invalid created SST report")
    retired = _table_rows(diff.get("retired"), "invalid retired SST report")
    require(set(created) == set(after) - set(before) and set(retired) == set(before) - set(after), "Go SST delta differs from MANIFEST")
    for label, rows, state in (("created", created, after), ("retired", retired, before)):
        for name, row in rows.items():
            require(all(state[name][key] == row[key] for key in ("number", "size", "level")), "Go SST delta metadata mismatch")
        for field, expected in ((label + "_count", len(rows)), (label + "_bytes", sum(row["size"] for row in rows.values()))):
            if field in diff:
                require(type(diff[field]) is int and diff[field] == expected, "Go SST delta totals mismatch")
    common = set(before) & set(after)
    require(all((before[name]["size"], before[name]["level"]) == (after[name]["size"], after[name]["level"]) for name in common),
            "untouched SST identity or level changed")
    require(isinstance(hashes, dict) and set(hashes) == set(created), "closed-output hashes do not match created SST set")
    for name, value in hashes.items():
        require(isinstance(value, dict) and set(value) == {"size", "sha256"}
                and type(value["size"]) is int and value["size"] == created[name]["size"]
                and isinstance(value["sha256"], str) and SHA256.fullmatch(value["sha256"]), "invalid closed SST hash evidence")
    require(sum(row["size"] for row in created.values()) <= MAX_OUTPUT_BYTES, "created SST output exceeds bound")
    io = report.get("io")
    require(isinstance(io, dict) and not io.get("blocked_budget_error"), "Go I/O budget evidence missing or failed")
    for label, maximum in (("sst", MAX_OUTPUT_BYTES), ("metadata", MAX_METADATA_WRITE_BYTES)):
        limit, written = io.get("max_" + label + "_write_bytes"), io.get(label + "_write_bytes")
        require(_integer(limit, 1) and limit <= maximum and _integer(written) and written <= limit,
                "Go write budget exceeded or invalid")
    events = report.get("compactions")
    require(isinstance(events, list), "Go compaction events missing")
    if action != "step":
        require(not created and not retired and not events and io["sst_write_bytes"] == 0,
                "metadata-only stage performed SST work")
        if action in ("ratchet6", "ratchet7", "ratchet10"):
            require(before_stats["marked_files"] == 0, "preliminary stage crossed unfinished marked work")
        if action == "ratchet7":
            require(after_stats["marked_files"] == 0, "format 7 left unfinished marked work")
        if action == "ratchet13":
            require(all(before[name]["marked"] == after[name]["marked"] for name in common),
                    "format 13 preliminary stage changed file marks")
        return created, retired
    require(retired, "rewrite retired no input SST")
    require(all(before[name]["marked"] == after[name]["marked"] for name in common), "unselected SST marks changed")
    require(all(not after[name]["marked"] for name in created), "new rewrite output remains marked")
    marked_inputs = sum(before[name]["marked"] for name in retired)
    require(marked_inputs > 0 and before_stats["marked_files"] - after_stats["marked_files"] == marked_inputs,
            "rewrite marked-file delta differs from selected inputs")
    plan = report.get("picker_plan")
    require(isinstance(plan, dict) and isinstance(plan.get("input_files"), list)
            and len(plan["input_files"]) == len(set(plan["input_files"]))
            and set(plan["input_files"]) == set(retired), "authoritative picker input set mismatch")
    planned_hash = plan.get("plan_sha256")
    require(isinstance(planned_hash, str) and SHA256.fullmatch(planned_hash)
            and report.get("expected_plan_sha256") == planned_hash, "expected picker plan hash mismatch")
    input_bytes = sum(row["size"] for row in retired.values())
    require(type(plan.get("input_bytes")) is int and plan["input_bytes"] == input_bytes
            and 0 < input_bytes <= MAX_INPUT_BYTES, "authoritative picker input budget mismatch")
    require(type(plan.get("input_level")) is int and type(plan.get("output_level")) is int
            and plan["output_level"] == plan["input_level"]
            and all(row["level"] == plan["input_level"] for row in retired.values())
            and all(row["level"] == plan["output_level"] for row in created.values()), "rewrite level changed")
    require(len(events) == 2, "expected exactly one compaction begin/end pair")
    begin, end = events
    require(begin.get("type") == "begin" and end.get("type") == "end"
            and _integer(begin.get("job"), 1) and end.get("job") == begin["job"]
            and begin.get("reason") == end.get("reason") == "rewrite" and end.get("error") == "",
            "expected one successful authoritative rewrite job")
    require(_table_rows(end.get("input"), "invalid compaction input") == retired
            and _table_rows(end.get("output"), "invalid compaction output") == created, "compaction event delta mismatch")
    return created, retired


def _collect_latest(s3) -> tuple[dict, dict]:
    latest, deleted, seen = {}, {}, set()
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=BUCKET, Prefix="rhea/"):
        for is_delete, rows in ((False, page.get("Versions", [])), (True, page.get("DeleteMarkers", []))):
            for row in rows:
                if row.get("IsLatest") is not True:
                    continue
                key = row.get("Key")
                require(isinstance(key, str) and key.startswith("rhea/") and key not in seen, "invalid/duplicate latest object")
                seen.add(key)
                require(isinstance(row.get("VersionId"), str) and row["VersionId"] not in ("", "null"), "missing latest VersionId")
                if is_delete:
                    deleted[key] = row
                else:
                    require(_integer(row.get("Size")) and isinstance(row.get("ETag"), str) and row["ETag"], "invalid latest object metadata")
                    latest[key] = row
    return latest, deleted


def _row_pin(row: dict, sha256: str | None = None) -> dict:
    result = {"size": row["Size"], "version_id": row["VersionId"], "etag": row["ETag"]}
    if sha256 is not None:
        result["sha256"] = sha256
    return result


def _same_version(row: dict, pin: dict) -> bool:
    return (row["VersionId"], row["Size"], row["ETag"]) == (pin["version_id"], pin["size"], pin["etag"])


def _hash_new_sst(s3, name: str, row: dict, expected: dict) -> dict:
    require(row["Size"] == expected["size"] <= MAX_OUTPUT_BYTES, "new SST remote size mismatch")
    response = s3.get_object(Bucket=BUCKET, Key=PREFIX + name, VersionId=row["VersionId"])
    digest, total, body = hashlib.sha256(), 0, response["Body"]
    try:
        while True:
            chunk = body.read(min(1024**2, expected["size"] + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            require(total <= expected["size"], "new SST payload exceeds expected length")
            digest.update(chunk)
    finally:
        body.close()
    require((response.get("VersionId"), response.get("ContentLength"), response.get("ETag")) ==
            (row["VersionId"], row["Size"], row["ETag"]), "new SST GET version mismatch")
    require(total == expected["size"] and digest.hexdigest() == expected["sha256"], "new SST remote content hash mismatch")
    pin = _row_pin(row, expected["sha256"])
    _head_matches(s3, name, pin)
    return pin


def recheck_publication_inputs(s3, before_report: dict) -> dict:
    """Recheck durable prepublication evidence during partial publication.

    The controller must first validate its stored canonical report hash. Changed
    markers may already exist here; they are verified by the controller, and by
    final verify_generation. This helper performs HEADs only, never publication.
    """
    require(before_report.get("mode") == "before-markers"
            and before_report.get("remote_generation_verified") is False
            and before_report.get("scope") == "fixed-disposable-full-clone-stage"
            and before_report.get("bucket") == BUCKET and before_report.get("prefix") == "rhea/",
            "invalid prepublication report scope/state")
    metadata = _metadata_pins(before_report)
    changed = before_report.get("changed_markers")
    require(isinstance(changed, list) and 1 <= len(changed) <= 2 and len(set(changed)) == len(changed)
            and all(name in (before_report.get("manifest_marker"), before_report.get("format_marker")) for name in changed)
            and not (set(changed) & set(metadata)), "invalid prepublication marker evidence")
    for name, pin in metadata.items():
        _head_matches(s3, name, pin)
    created = before_report.get("created_sst_versions")
    require(isinstance(created, dict) and len(created) <= MAX_CREATED_FILES, "new SST version evidence missing")
    for name, pin in created.items():
        _sst_name(name)
        _head_matches(s3, name, _pin(pin, content_hash=True))
    return {"metadata_rechecked": len(metadata), "new_ssts_rechecked": len(created), "checked_unix": time.time()}


def verify_generation(s3, ledger: dict, previous_checkpoint: dict, go_report: dict,
                      metadata_bytes: dict[str, bytes], created_sst_hashes: dict,
                      mode: str, previous_checkpoint_sha256: str) -> dict:
    """Verify one closed stage; caller owns lifecycle lock and publication."""
    require(mode in ("before-markers", "final"), "unknown checkpoint verification mode")
    baseline = _baseline_pins(ledger)
    current_pins, lineage = _lineage(previous_checkpoint, baseline)
    previous_metadata = _metadata_pins(previous_checkpoint)
    old_markers, reopen = _validate_previous(previous_checkpoint, previous_checkpoint_sha256, previous_metadata)
    old_manifest = old_markers["manifest"]
    require(old_manifest in previous_metadata, "prior active MANIFEST pin missing")
    before, before_stats = _decode_tables(_get_bytes(s3, old_manifest, previous_metadata[old_manifest]))
    require({name: row["size"] for name, row in before.items()} == {name: pin["size"] for name, pin in current_pins.items()},
            "prior MANIFEST differs from certified SST lineage")
    old_digest = base.inventory_digest(_inventory(before))
    require(previous_checkpoint.get("sst_inventory_sha256") == old_digest
            and type(previous_checkpoint.get("sst_count")) is int and previous_checkpoint["sst_count"] == len(before)
            and type(previous_checkpoint.get("sst_bytes")) is int
            and previous_checkpoint["sst_bytes"] == sum(row["size"] for row in before.values()), "prior certificate inventory mismatch")
    declared_marked = previous_checkpoint.get("marked_after", previous_checkpoint.get("marked_files", previous_checkpoint.get("manifest_stats", {}).get("marked_files")))
    require(type(declared_marked) is int and declared_marked == before_stats["marked_files"], "prior marked-file certificate mismatch")
    if previous_checkpoint.get("remote_generation_verified") is True or previous_checkpoint.get("pebble_reopen_verified") is not True:
        require(isinstance(reopen, dict) and reopen.get("action") == "inspect" and not reopen.get("error"),
                "prior read-only reopen evidence missing or failed")
        _state_report(reopen, "after", before, before_stats, old_markers["after_format"])
    require(isinstance(metadata_bytes, dict) and 0 < len(metadata_bytes) <= base.MAX_METADATA_FILES
            and all(isinstance(name, str) and base.META_NAME.fullmatch(name) and isinstance(data, bytes)
                    and len(data) <= base.MAX_METADATA_BYTES for name, data in metadata_bytes.items())
            and sum(map(len, metadata_bytes.values())) <= base.MAX_METADATA_TOTAL, "invalid closed metadata snapshot")
    require(metadata_bytes.get("CURRENT") == b"MANIFEST-000000\n" and metadata_bytes.get("LOCK", b"") == b"", "invalid CURRENT/LOCK metadata")
    markers = _marker_info(metadata_bytes)
    changed = changed_marker_names(previous_checkpoint, metadata_bytes)
    require(markers["manifest"] in metadata_bytes, "current MANIFEST marker target missing")
    after, after_stats = _decode_tables(metadata_bytes[markers["manifest"]])
    minimum = after_stats.get("min_unflushed_log", 0)
    require(minimum > 0 and f"{minimum:06d}.log" in metadata_bytes
            and any(name.startswith("OPTIONS-") for name in metadata_bytes), "required WAL/OPTIONS missing")
    created, retired = _validate_stage(go_report, before, after, before_stats, after_stats,
                                       old_markers["after_format"], markers["after_format"], created_sst_hashes)
    require(not (set(created) & (set(baseline) | set(lineage["created"]))), "new SST reused a historical filename")
    for name in retired:
        lineage["retired"][name] = dict(current_pins[name])
    latest, deleted = _collect_latest(s3)
    expected_repo = {key: entry for key, entry in ledger.items() if not key.startswith(PREFIX)}
    require({key for key in latest if not key.startswith(PREFIX)} == set(expected_repo), "repository object inventory changed")
    for key, entry in expected_repo.items():
        require(_same_version(latest[key], {"size": entry.size, "version_id": entry.version_id, "etag": entry.etag}), "repository object version changed")
    known_ssts = set(baseline) | set(lineage["created"]) | set(created)
    remote_ssts = {key[len(PREFIX):]: row for key, row in latest.items() if key.startswith(PREFIX) and key.endswith(".sst")}
    require(all(key.startswith(PREFIX) for key in deleted if key.endswith(".sst")), "unexpected SST delete marker outside pebbleds")
    deleted_ssts = {key[len(PREFIX):]: row for key, row in deleted.items() if key.startswith(PREFIX) and key.endswith(".sst")}
    require(set(remote_ssts) <= known_ssts and set(deleted_ssts) <= set(lineage["retired"]), "unexpected SST object or delete marker")
    untouched = set(current_pins) - set(retired)
    require(untouched <= set(remote_ssts) and set(created) <= set(remote_ssts), "referenced SST object missing")
    for name in untouched:
        require(_same_version(remote_ssts[name], current_pins[name]), "untouched SST version changed")
    retirement = {}
    for name, pin in lineage["retired"].items():
        if name in remote_ssts:
            require(_same_version(remote_ssts[name], pin), "retired SST was overwritten")
            retirement[name] = {"state": "unchanged-unreferenced-latest", "version_id": pin["version_id"]}
        else:
            require(name in deleted_ssts, "retired SST lost without a recorded delete marker")
            retirement[name] = {"state": "latest-delete-marker", "delete_marker_version_id": deleted_ssts[name]["VersionId"]}
        _head_matches(s3, name, pin, historical=True)
    new_bytes = 0
    for name, row in created.items():
        lineage["created"][name] = _hash_new_sst(s3, name, remote_ssts[name], created_sst_hashes[name])
        new_bytes += row["size"]
    names = {key[len(PREFIX):] for key in latest if key.startswith(PREFIX) and not key.endswith(".sst")}
    require(all(base.META_NAME.fullmatch(name) for name in names), "unknown latest metadata object")
    expected_names = set(metadata_bytes) - (set(changed) if mode == "before-markers" else set())
    require(names == expected_names, "remote metadata/publication barrier inventory mismatch")
    remote_metadata = {}
    for name in sorted(names):
        data = metadata_bytes[name]
        row = latest[PREFIX + name]
        pin = _row_pin(row, hashlib.sha256(data).hexdigest())
        require(pin["size"] == len(data), "closed metadata size mismatch")
        require(_get_bytes(s3, name, pin) == data, "closed metadata bytes mismatch")
        _head_matches(s3, name, pin)
        if name.startswith("marker.") and name not in changed:
            require(pin == previous_metadata[name], "unchanged marker version changed")
        remote_metadata[name] = pin
    if mode == "before-markers":
        for name in changed:
            try:
                s3.head_object(Bucket=BUCKET, Key=PREFIX + name)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code")
                require(str(code) in ("404", "NoSuchKey", "NotFound"), "cannot confirm unpublished marker")
            else:
                raise VerificationError("publication marker appeared during verification")
    if go_report["action"] == "step":
        lineage["rewrite_operations"] += 1
    return dict(markers, schema=1, scope="fixed-disposable-full-clone-stage", bucket=BUCKET, prefix="rhea/",
                mode=mode, action=go_report["action"], verified_unix=time.time(),
                previous_checkpoint_sha256=previous_checkpoint_sha256, go_report_sha256=canonical_sha256(go_report),
                closed_output_hashes_sha256=canonical_sha256(created_sst_hashes), decoder_sha256=DECODER_SHA256,
                ledger_sha256=LEDGER_SHA256, remote_generation_verified=mode == "final", pebble_reopen_verified=False,
                changed_markers=changed, marked_after=after_stats["marked_files"], manifest_stats=after_stats,
                sst_count=len(after), sst_bytes=sum(row["size"] for row in after.values()),
                sst_inventory_sha256=base.inventory_digest(_inventory(after)), sst_lineage=lineage,
                unchanged_sst_versions=len(untouched), new_sst_payload_bytes_downloaded=new_bytes,
                unchanged_sst_payload_bytes_downloaded=0, retired_sst_states=retirement,
                created_sst_versions={name: lineage["created"][name] for name in created},
                remote_metadata=remote_metadata, latest_delete_markers=len(deleted))
