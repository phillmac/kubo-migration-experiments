#!/usr/bin/env python3
"""Independently verify the fixed disposable Rhea lab's metadata-only format 3.

Only S3 read APIs are used. No database is opened and no SST is downloaded.
The snapshot is a flat, root-protected directory containing every closed
pebbleds metadata file, including the final manifest/format markers.

The MANIFEST decoder derives from the existing exercised Rhea closure parser;
tag semantics were checked against cockroachdb/pebble v1.1.3
internal/manifest/version_edit.go. Unsupported tags fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

BUCKET = "rhea-pebble-lab-20261101-39037c6f01"
PREFIX = "rhea/pebbleds/"
WRAPPER = Path("/root/.local/share/rhea-wasabi-lab-admin-20261101/rhea_wasabi_lab_mount.py")
WRAPPER_SHA256 = "6c1affe9cd791bd8f16435df6f0db284b105f94829ae270b1242dd3cfaef785c"
EXPECTED_SSTS = 93_697
EXPECTED_SST_BYTES = 7_786_594_080_785
EXPECTED_INVENTORY = "57b04d9508272a17df72aea1a6675fff1e13944ae83c884f988668b7f77cd134"
MAX_METADATA_BYTES = 128 * 1024**2
MAX_METADATA_TOTAL = 512 * 1024**2
MAX_METADATA_FILES = 64
BLOCK = 32768
SST_NAME = re.compile(r"[0-9]{6,20}\.sst")
META_NAME = re.compile(
    r"(?:CURRENT|LOCK|[0-9]{6,20}\.log|(?:MANIFEST|OPTIONS)-[0-9]{6,20}|"
    r"marker\.manifest\.[0-9]{6,20}\.MANIFEST-[0-9]{6,20}|"
    r"marker\.format-version\.[0-9]{6,20}\.[0-9]{3})"
)
MANIFEST_MARKER = re.compile(r"marker\.manifest\.([0-9]{6,20})\.(MANIFEST-[0-9]{6,20})")
FORMAT_MARKER = re.compile(r"marker\.format-version\.([0-9]{6,20})\.([0-9]{3})")


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _crc_table() -> tuple[int, ...]:
    result = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        result.append(value)
    return tuple(result)


CRC_TABLE = _crc_table()


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for byte in data:
        value = CRC_TABLE[(value ^ byte) & 255] ^ (value >> 8)
    return (value ^ 0xFFFFFFFF) & 0xFFFFFFFF


def masked_crc(data: bytes) -> int:
    value = crc32c(data)
    return (((value >> 15) | (value << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def manifest_records(data: bytes):
    """Decode complete LevelDB physical log fragments with CRC32C checks."""
    offset = 0
    pieces = None
    while offset < len(data):
        end = min((offset // BLOCK + 1) * BLOCK, len(data))
        if end - offset < 7:
            require(not data[offset:end].strip(b"\0"), "nonzero MANIFEST block trailer")
            offset = end
            continue
        checksum, length, kind = struct.unpack_from("<IHB", data, offset)
        if kind == 0 and length == 0:
            require(not data[offset:end].strip(b"\0"), "invalid MANIFEST padding")
            offset = end
            continue
        require(kind in (1, 2, 3, 4), "unsupported MANIFEST fragment type")
        require(offset + 7 + length <= end, "truncated MANIFEST fragment")
        fragment = data[offset + 7:offset + 7 + length]
        require(checksum == masked_crc(bytes([kind]) + fragment), "MANIFEST CRC32C mismatch")
        offset += 7 + length
        if kind == 1:
            require(pieces is None, "full record inside fragmented MANIFEST record")
            yield fragment
        elif kind == 2:
            require(pieces is None, "nested MANIFEST first fragment")
            pieces = [fragment]
        else:
            require(pieces is not None, "orphan MANIFEST continuation")
            pieces.append(fragment)
            if kind == 4:
                yield b"".join(pieces)
                pieces = None
    require(pieces is None, "unfinished MANIFEST logical record")


def parse_uvar(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        require(offset < len(data), "truncated MANIFEST varint")
        byte = data[offset]
        offset += 1
        require(shift != 63 or byte <= 1, "overflowing MANIFEST varint")
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise VerificationError("oversized MANIFEST varint")


def parse_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    size, offset = parse_uvar(data, offset)
    require(size <= len(data) - offset, "truncated MANIFEST byte field")
    return data[offset:offset + size], offset + size


def parse_edit(payload: bytes, state: dict, stats: dict) -> None:
    offset = 0
    while offset < len(payload):
        tag, offset = parse_uvar(payload, offset)
        if tag == 1:
            _, offset = parse_bytes(payload, offset)
        elif tag in (2, 3, 4, 9):
            value, offset = parse_uvar(payload, offset)
            stats[{2: "min_unflushed_log", 3: "next_file_number", 4: "last_sequence", 9: "previous_log"}[tag]] = value
        elif tag == 5:
            level, offset = parse_uvar(payload, offset)
            require(level <= 6, "invalid compaction pointer level")
            _, offset = parse_bytes(payload, offset)
        elif tag == 6:
            level, offset = parse_uvar(payload, offset)
            number, offset = parse_uvar(payload, offset)
            require((level, number) in state, "MANIFEST deletes an absent table")
            del state[level, number]
            stats["deletions"] += 1
        elif tag in (7, 100, 102, 103, 104):
            level, offset = parse_uvar(payload, offset)
            number, offset = parse_uvar(payload, offset)
            require(level <= 6 and number > 0, "invalid MANIFEST table identity")
            if tag == 102:
                path_id, offset = parse_uvar(payload, offset)
                require(path_id == 0, "nonzero table path ID unsupported")
            size, offset = parse_uvar(payload, offset)
            require(size > 0, "zero-sized SST in MANIFEST")
            if tag == 104:
                require(offset < len(payload), "missing range-key bounds marker")
                bounds = payload[offset]
                offset += 1
                require(bounds <= 7 and (bounds & 4 or bounds == 0), "invalid range-key bounds marker")
                if bounds & 4:
                    _, offset = parse_bytes(payload, offset)
                    _, offset = parse_bytes(payload, offset)
            _, offset = parse_bytes(payload, offset)
            _, offset = parse_bytes(payload, offset)
            if tag != 7:
                smallest, offset = parse_uvar(payload, offset)
                largest, offset = parse_uvar(payload, offset)
                require(smallest <= largest, "invalid SST sequence bounds")
            marked = False
            if tag in (103, 104):
                seen = set()
                while True:
                    custom, offset = parse_uvar(payload, offset)
                    if custom == 1:
                        break
                    require(custom in (2, 6) and custom not in seen, "unsupported or duplicate MANIFEST custom tag")
                    seen.add(custom)
                    field, offset = parse_bytes(payload, offset)
                    if custom == 2:
                        require(field in (b"\0", b"\1"), "invalid needs-compaction field")
                        marked = field == b"\1"
                    else:
                        _, consumed = parse_uvar(field, 0)
                        require(consumed == len(field), "invalid table creation time")
            state[level, number] = (size, marked)
            stats["additions"] += 1
        else:
            # Virtual SST/backing-table and column-family tags are deliberately
            # outside the format-1 -> 3 experiment and must not be ignored.
            raise VerificationError("unsupported MANIFEST version-edit tag: " + str(tag))


def decode_manifest(data: bytes) -> tuple[dict[int, int], dict]:
    state = {}
    stats = {"records": 0, "additions": 0, "deletions": 0}
    for record in manifest_records(data):
        parse_edit(record, state, stats)
        stats["records"] += 1
    require(stats["records"] > 0, "empty MANIFEST")
    inventory = {number: value[0] for (_, number), value in state.items()}
    require(len(inventory) == len(state), "SST appears in multiple MANIFEST levels")
    stats["marked_files"] = sum(value[1] for value in state.values())
    stats["levels"] = {str(level): sum(lv == level for lv, _ in state) for level in range(7)}
    return inventory, stats


def inventory_digest(inventory: dict[int, int]) -> str:
    digest = hashlib.sha256()
    for number, size in sorted(inventory.items()):
        digest.update(f"{number}\t{size}\n".encode())
    return digest.hexdigest()


def baseline_inventory(ledger: dict) -> dict[int, int]:
    inventory = {}
    for key, entry in ledger.items():
        if not key.endswith(".sst"):
            continue
        require(key.startswith(PREFIX) and SST_NAME.fullmatch(key[len(PREFIX):]), "invalid baseline SST key")
        number = int(key[len(PREFIX):-4])
        require(number not in inventory, "duplicate baseline SST number")
        inventory[number] = entry.size
    return inventory


def collect_latest(s3) -> tuple[dict, set]:
    latest, deleted, seen = {}, set(), set()
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=BUCKET, Prefix="rhea/"):
        for marker, rows in ((False, page.get("Versions", [])), (True, page.get("DeleteMarkers", []))):
            for row in rows:
                if row.get("IsLatest") is not True:
                    continue
                key = row.get("Key")
                require(isinstance(key, str) and key.startswith("rhea/") and key not in seen, "invalid or duplicate latest S3 key")
                seen.add(key)
                require(isinstance(row.get("VersionId"), str) and row["VersionId"] not in ("", "null"), "latest object lacks a VersionId")
                if marker:
                    deleted.add(key)
                else:
                    require(type(row.get("Size")) is int and row["Size"] >= 0 and isinstance(row.get("ETag"), str), "invalid latest S3 metadata")
                    latest[key] = row
    return latest, deleted


def unchanged_ssts_and_repo(latest: dict, ledger: dict) -> None:
    expected = {key: entry for key, entry in ledger.items() if key.endswith(".sst") or not key.startswith(PREFIX)}
    actual = {key: row for key, row in latest.items() if key.endswith(".sst") or not key.startswith(PREFIX)}
    require(set(actual) == set(expected), "SST/repository object inventory changed")
    for key, entry in expected.items():
        row = actual[key]
        require((row["VersionId"], row["Size"], row["ETag"]) == (entry.version_id, entry.size, entry.etag), "baseline SST/repository object version changed")


def local_closure(snapshot: dict[str, bytes], expected: dict[int, int]) -> dict:
    require(snapshot and len(snapshot) <= MAX_METADATA_FILES, "metadata snapshot file count outside bound")
    require(all(META_NAME.fullmatch(name) for name in snapshot), "unknown metadata filename")
    require(sum(map(len, snapshot.values())) <= MAX_METADATA_TOTAL, "metadata snapshot exceeds total bound")
    require(all(len(data) <= MAX_METADATA_BYTES for data in snapshot.values()), "metadata file exceeds size bound")
    require(snapshot.get("CURRENT") == b"MANIFEST-000000\n", "format-3 CURRENT placeholder mismatch")
    require(snapshot.get("LOCK", b"") == b"", "nonempty Pebble LOCK file")
    manifests = [name for name in snapshot if MANIFEST_MARKER.fullmatch(name)]
    formats = [name for name in snapshot if FORMAT_MARKER.fullmatch(name)]
    require(len(manifests) == len(formats) == 1, "ambiguous or missing final markers")
    manifest_marker, format_marker = manifests[0], formats[0]
    require(FORMAT_MARKER.fullmatch(format_marker)[2] == "003", "final format marker is not 003")
    require(snapshot[manifest_marker] == snapshot[format_marker] == b"", "nonempty Pebble marker")
    manifest_name = MANIFEST_MARKER.fullmatch(manifest_marker)[2]
    require(manifest_name in snapshot, "manifest marker target is missing")
    inventory, stats = decode_manifest(snapshot[manifest_name])
    require(inventory == expected, "MANIFEST exact SST inventory differs from baseline")
    require(stats["marked_files"] == 0, "format-3 MANIFEST unexpectedly has marked files")
    wal_names = sorted(name for name in snapshot if name.endswith(".log"))
    minimum = stats.get("min_unflushed_log", 0)
    require(minimum > 0 and f"{minimum:06d}.log" in snapshot, "minimum unflushed WAL is missing")
    require(any(name.startswith("OPTIONS-") for name in snapshot), "OPTIONS metadata is missing")
    return {"manifest": manifest_name, "manifest_marker": manifest_marker, "format_marker": format_marker,
            "sst_count": len(inventory), "sst_bytes": sum(inventory.values()),
            "sst_inventory_sha256": inventory_digest(inventory), "manifest_stats": stats, "wal_files": wal_names}


def verify_remote(s3, ledger: dict, snapshot: dict[str, bytes], mode: str) -> dict:
    require(mode in ("before-markers", "final"), "unknown verification mode")
    expected = baseline_inventory(ledger)
    closure = local_closure(snapshot, expected)
    latest, deleted = collect_latest(s3)
    require(not any(key.endswith(".sst") for key in deleted), "latest SST delete marker found")
    unchanged_ssts_and_repo(latest, ledger)
    remote_names = {key[len(PREFIX):] for key in latest if key.startswith(PREFIX) and not key.endswith(".sst")}
    require(all(META_NAME.fullmatch(name) for name in remote_names), "unknown latest remote metadata object")
    marker_names = {closure["manifest_marker"], closure["format_marker"]}
    if mode == "before-markers":
        require(closure["format_marker"] not in remote_names, "format marker already published; pre-marker verification is too late")
        require(remote_names - marker_names == set(snapshot) - marker_names, "remote non-marker inventory differs from closed snapshot")
        require(remote_names <= set(snapshot), "unexpected remote marker")
    else:
        require(remote_names == set(snapshot), "remote metadata inventory differs from closed snapshot")
    verified = {}
    for name in sorted(remote_names):
        key = PREFIX + name
        row = latest[key]
        data = snapshot[name]
        require(row["Size"] == len(data) and len(data) <= MAX_METADATA_BYTES, "remote metadata size mismatch")
        response = s3.get_object(Bucket=BUCKET, Key=key, VersionId=row["VersionId"])
        body = response["Body"]
        try:
            remote = body.read(len(data) + 1)
        finally:
            body.close()
        require(response.get("VersionId") == row["VersionId"] and response.get("ContentLength") == len(data)
                and response.get("ETag") == row["ETag"], "versioned metadata GET identity mismatch")
        require(remote == data, "remote metadata bytes differ from closed snapshot")
        head = s3.head_object(Bucket=BUCKET, Key=key)
        require((head.get("VersionId"), head.get("ContentLength"), head.get("ETag")) ==
                (row["VersionId"], row["Size"], row["ETag"]), "latest metadata changed during verification")
        verified[name] = {"version_id": row["VersionId"], "etag": row["ETag"], "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()}
    if mode == "before-markers":
        try:
            s3.head_object(Bucket=BUCKET, Key=PREFIX + closure["format_marker"])
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            require(str(code) in ("404", "NoSuchKey", "NotFound"), "cannot independently confirm absent format marker")
        else:
            raise VerificationError("format marker appeared during pre-marker verification")
    return dict(closure, mode=mode, remote_format3_closure_verified=mode == "final", pebble_reopen_verified=False,
                remote_metadata=verified, latest_delete_markers=len(deleted),
                unchanged_sst_versions=len(expected), sst_payload_bytes_downloaded=0)


def load_wrapper():
    # Do not execute a substituted source file while privileged.
    for path in (*reversed(WRAPPER.parents), WRAPPER):
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0,
                "untrusted installed wrapper path")
    require(hashlib.sha256(WRAPPER.read_bytes()).hexdigest() == WRAPPER_SHA256, "installed wrapper hash mismatch")
    spec = importlib.util.spec_from_file_location("rhea_lab_checkpoint_guard", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_snapshot(path: Path, wrapper) -> dict[str, bytes]:
    require(path.is_absolute() and path.resolve() == path, "snapshot path must be absolute without symlinks")
    wrapper.secure_path(path, leaf_mode=0o700)
    require(path.is_dir(), "snapshot is not a directory")
    files = list(path.iterdir())
    require(len(files) <= MAX_METADATA_FILES, "too many metadata snapshot files")
    result = {}
    for child in files:
        require(META_NAME.fullmatch(child.name), "unexpected metadata snapshot file")
        result[child.name] = wrapper.read_protected(child, mode=0o600, max_bytes=MAX_METADATA_BYTES)
    return result


def validate_pending_markers(wrapper, profile, observation: dict, snapshot: dict, mode: str) -> None:
    disk = observation["stats"]["diskCache"]
    require(disk["uploadsInProgress"] == disk["erroredFiles"] == 0 and not disk["outOfSpace"],
            "lab upload activity/error prevents verification")
    if mode == "final":
        wrapper.clean_queue(observation["stats"], observation["queue"])
        return
    allowed = {"pebbleds/" + name for name in snapshot if name.startswith("marker.")}
    pending = observation["queue"]["queue"]
    names = set()
    for row in pending:
        name = row.get("name")
        require(name in allowed and name not in names, "unexpected/duplicate pending metadata file")
        names.add(name)
        require(row.get("size") == len(snapshot[name[len("pebbleds/"):]]), "pending marker size changed")
        wrapper.validate_queue_selection(profile, observation, item_id=row.get("id"), name=name,
                                         size=row.get("size"), pid=observation["pid"], expiry="defer")
    require(any(name.startswith("pebbleds/marker.format-version.") for name in names),
            "final format marker is no longer pending")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("before-markers", "final"))
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, "root is required for fixed lab credentials/evidence")
        wrapper = load_wrapper()
        host = wrapper.RealHost()
        profile = wrapper.PROFILES["full-clone"]
        with host.lock():
            running = host.running(profile)
            host.guard(profile, running=running, admission=False)
            snapshot = read_snapshot(args.snapshot, wrapper)
            starting_pid = None
            if running:
                host.no_open_users(profile)
                observation = host.observe(profile)
                starting_pid = observation["pid"]
                validate_pending_markers(wrapper, profile, observation, snapshot, args.mode)
            ledger = wrapper.load_ledger(wrapper.read_protected(wrapper.LEDGER))
            inventory = baseline_inventory(ledger)
            require(len(inventory) == EXPECTED_SSTS and sum(inventory.values()) == EXPECTED_SST_BYTES
                    and inventory_digest(inventory) == EXPECTED_INVENTORY, "frozen baseline inventory pin mismatch")
            credentials = wrapper.parse_config(wrapper.read_protected(wrapper.CONFIG, mode=0o600).decode())
            s3, sts = host.cloud(credentials)
            try:
                wrapper.verify_cloud_identity(s3, sts)
                result = verify_remote(s3, ledger, snapshot, args.mode)
            finally:
                s3.close()
                sts.close()
            require(read_snapshot(args.snapshot, wrapper) == snapshot, "closed snapshot changed during verification")
            host.guard(profile, running=running, admission=False)
            if running:
                host.no_open_users(profile, expected_pid=starting_pid)
                observation = host.observe(profile)
                require(observation["pid"] == starting_pid, "lab restarted during checkpoint verification")
                validate_pending_markers(wrapper, profile, observation, snapshot, args.mode)
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        if isinstance(exc, VerificationError):
            print("FAIL_CLOSED: " + str(exc), file=sys.stderr)
        else:
            print("FAIL_CLOSED: protected-input, host, or cloud verification failed (details suppressed)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
