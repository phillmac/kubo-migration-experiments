#!/usr/bin/env python3
"""Read a bounded tail sample from the certified format-007 disposable clone.

Default: 128 deterministic SSTs spread across occupied levels. --all reads the
exact certified inventory. This only opens database files read-only; it does not
alter the controller, database, cache files, services, or upload queue directly.
"""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types


TRUST = Path("/root/.local/share/rhea-wasabi-lab-admin-20261101")
INSTALLED = TRUST / "warm_rhea_full_clone_tails.py"
PINS = TRUST / "warm-rhea-full-clone-tails-pins.json"
CONTROLLER = TRUST / "run_rhea_full_clone_steps.py"
CONTROLLER_SHA256 = "7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb"
TAIL_BYTES = 64 * 1024
MAX_FILES = 93_697
MAX_REQUESTED_BYTES = MAX_FILES * TAIL_BYTES
PILOT_FILES = 128
WORKERS = 8
MAX_PENDING = 8
HEADROOM = 8 * 1024**3
MAX_WINDOW_FILES = 128
MAX_WINDOW_BYTES = MAX_WINDOW_FILES * TAIL_BYTES
SUBMISSION_SECONDS = 5
FREE_CHECK_SECONDS = 1
MAX_UNOBSERVED_SECONDS = 120
SST_NAME = re.compile(r"[0-9]{6,20}\.sst")
SHA256 = re.compile(r"[0-9a-f]{64}")


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def protected_bootstrap_read(path: Path, maximum: int) -> bytes:
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_mode & 0o022 == 0, "untrusted bootstrap path")
        if component != path:
            require(stat.S_ISDIR(info.st_mode), "bootstrap ancestor is not a directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                "bootstrap file is not private root-owned mode0600")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum, "bootstrap file exceeds bound")
        return data
    finally:
        os.close(fd)


def bootstrap():
    require(os.geteuid() == 0, "root required for fixed full-clone tail warmup")
    require(Path(__file__).resolve() == INSTALLED, "helper must run from its fixed trusted installation")
    source = protected_bootstrap_read(CONTROLLER, 1024 * 1024)
    require(hashlib.sha256(source).hexdigest() == CONTROLLER_SHA256, "controller source digest mismatch")
    module = types.ModuleType("rhea_tail_warmup_controller")
    module.__file__ = str(CONTROLLER)
    sys.modules[module.__name__] = module
    exec(compile(source, str(CONTROLLER), "exec"), module.__dict__)
    pins = module.json_object(protected_bootstrap_read(PINS, 16_384))
    require(set(pins) == {"schema", "helper_sha256"} and type(pins["schema"]) is int
            and pins["schema"] == 1 and isinstance(pins["helper_sha256"], str)
            and SHA256.fullmatch(pins["helper_sha256"]), "invalid tail-warmup deployment pins")
    require(hashlib.sha256(protected_bootstrap_read(INSTALLED, 1024 * 1024)).hexdigest() == pins["helper_sha256"],
            "tail-warmup helper deployment digest mismatch")
    return module, module.Runtime(), pins["helper_sha256"]


def select_tables(tables: dict, *, all_files=False) -> list[dict]:
    """Select all, or evenly spaced files within deterministically shared level quotas."""
    require(isinstance(tables, dict) and 0 < len(tables) <= MAX_FILES, "active inventory exceeds file bound")
    groups = {level: [] for level in range(7)}
    numbers = set()
    for name, value in tables.items():
        require(isinstance(value, dict), "invalid active SST row")
        number, size, level = value.get("number"), value.get("size"), value.get("level")
        require(type(number) is int and number > 0 and number not in numbers
                and isinstance(name, str) and SST_NAME.fullmatch(name) and name == f"{number:06d}.sst",
                "noncanonical or duplicate active SST identity")
        require(type(size) is int and size > 0 and type(level) is int and 0 <= level <= 6
                and value.get("marked") is False, "invalid or marked active SST")
        numbers.add(number)
        groups[level].append({"name": name, "number": number, "size": size, "level": level,
                              "requested_bytes": min(TAIL_BYTES, size)})
    groups = {level: sorted(rows, key=lambda row: row["number"]) for level, rows in groups.items() if rows}
    if all_files:
        selected = [row for rows in groups.values() for row in rows]
    else:
        count = min(PILOT_FILES, len(tables))
        quotas = {level: 0 for level in groups}
        allocated = 0
        while allocated < count:
            for level, rows in groups.items():
                if allocated < count and quotas[level] < len(rows):
                    quotas[level] += 1
                    allocated += 1
        selected = []
        for level, rows in groups.items():
            quota = quotas[level]
            indices = ([len(rows) // 2] if quota == 1 else
                       [index * (len(rows) - 1) // (quota - 1) for index in range(quota)])
            selected.extend(rows[index] for index in indices)
    require(len({row["name"] for row in selected}) == len(selected), "duplicate selected SST")
    require(sum(row["requested_bytes"] for row in selected) <= MAX_REQUESTED_BYTES,
            "tail-read request exceeds byte bound")
    return selected


def selection_digest(rows: list[dict]) -> str:
    sha = hashlib.sha256(b"rhea-tail-warmup-v1\n")
    for row in rows:
        sha.update(f"{row['name']}\t{row['level']}\t{row['size']}\t{row['requested_bytes']}\n".encode())
    return sha.hexdigest()


def read_tail(directory_fd: int, row: dict) -> dict:
    started = time.monotonic()
    name = row["name"]
    require(SST_NAME.fullmatch(name) and name == f"{row['number']:06d}.sst", "noncanonical tail-read filename")
    length = min(TAIL_BYTES, row["size"])
    require(length == row["requested_bytes"] and 0 < length <= TAIL_BYTES, "tail request outside bound")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == row["size"],
                "tail-read SST differs from protected certified size/type")
        read_bytes = 0
        while read_bytes < length:
            block = os.pread(fd, length - read_bytes, before.st_size - length + read_bytes)
            require(block, "unexpected EOF while reading certified SST tail")
            read_bytes += len(block)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "SST changed during read-only tail warmup")
    finally:
        os.close(fd)
    return {"name": name, "level": row["level"], "requested_bytes": length,
            "read_bytes": read_bytes, "seconds": time.monotonic() - started}


def sample_free_space(module, runtime, summary: dict) -> int:
    """Check the local cache filesystem without depending on rclone's locks."""
    free = runtime.free_bytes()
    require(type(free) is int and free >= 0, "invalid cache-filesystem free-space observation")
    summary["free_space_samples"] = summary.get("free_space_samples", 0) + 1
    summary["last_free_bytes"] = free
    summary["last_free_unix"] = time.time()
    summary["minimum_free_bytes"] = min(summary.get("minimum_free_bytes", free), free)
    require(free >= module.MIN_FREE + HEADROOM, "tail warmup requires 8 GiB beyond the free-space floor")
    return free


def sample_health(module, runtime, summary: dict) -> dict:
    observation = runtime.observe()
    free = sample_free_space(module, runtime, summary)
    module.health(observation, free)
    runtime.wrapper.clean_queue(observation["stats"], observation["queue"])
    used = observation["stats"]["diskCache"]["bytesUsed"]
    require(used <= module.MAX_CACHE - HEADROOM, "tail warmup requires 8 GiB cache headroom")
    now = time.time()
    summary["samples"] += 1
    summary["last_unix"] = now
    summary["maximum_reported_cache_bytes"] = max(summary.get("maximum_reported_cache_bytes", used), used)
    return {"observed_unix": now, "free_bytes": free, "observation": observation}


def safe_error(module, runtime, exc) -> str:
    safe = (Refusal, module.Refusal, runtime.wrapper.Refusal, runtime.verifier.VerificationError)
    return str(exc) if isinstance(exc, safe) else "protected tail-read, observation, or evidence operation failed"


def warm_selected(module, runtime, rows, receipt, receipt_path, directory_fd):
    """Bound reads between authenticated observations; observe only after draining.

    A cold FUSE lookup may hold rclone's directory mutex longer than its RC
    timeout. Local statvfs checks remain independent while those reads finish.
    A stale observation stops admission, but does not cancel a blocking pread.
    """
    progress = receipt["progress"]
    monitor = receipt["monitor"]
    started = time.monotonic()
    last_healthy = None
    next_free_check = started
    cursor = 0
    failure = None
    with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="rhea-tail") as executor:
        pending = {}

        def observe_quiescent():
            nonlocal failure, last_healthy, next_free_check
            require(not pending, "authenticated observation requires all tail reads to finish")
            try:
                if last_healthy is not None:
                    require(time.monotonic() - last_healthy < MAX_UNOBSERVED_SECONDS,
                            "tail warmup exceeded 120 seconds without authenticated health")
                receipt["latest_health"] = sample_health(module, runtime, monitor)
                now = time.monotonic()
                if last_healthy is not None:
                    gap = now - last_healthy
                    monitor["maximum_observation_gap_seconds"] = max(monitor.get("maximum_observation_gap_seconds", 0), gap)
                    require(gap < MAX_UNOBSERVED_SECONDS,
                            "tail warmup exceeded 120 seconds without authenticated health")
                last_healthy = now
                next_free_check = now + FREE_CHECK_SECONDS
                progress["elapsed_seconds"] = now - started
                runtime.atomic_json(receipt_path, receipt)
            except Exception as exc:
                failure = failure or safe_error(module, runtime, exc)
            return failure is None

        while cursor < len(rows) and failure is None:
            if not observe_quiescent():
                break
            window_started = last_healthy
            window_files = window_bytes = 0
            drain_started = None

            def may_submit():
                return (failure is None and cursor < len(rows) and window_files < MAX_WINDOW_FILES
                        and time.monotonic() - window_started < SUBMISSION_SECONDS)

            while pending or may_submit():
                now = time.monotonic()
                if now - last_healthy >= MAX_UNOBSERVED_SECONDS:
                    failure = failure or "tail warmup exceeded 120 seconds without authenticated health"
                if now >= next_free_check:
                    try:
                        sample_free_space(module, runtime, monitor)
                    except Exception as exc:
                        failure = failure or safe_error(module, runtime, exc)
                    next_free_check = now + FREE_CHECK_SECONDS
                while may_submit() and len(pending) < MAX_PENDING:
                    row = rows[cursor]
                    requested = row["requested_bytes"]
                    require(type(requested) is int and 0 < requested <= TAIL_BYTES
                            and window_bytes + requested <= MAX_WINDOW_BYTES, "observation-window read bound exceeded")
                    pending[executor.submit(read_tail, directory_fd, row)] = row
                    cursor += 1
                    window_files += 1
                    window_bytes += requested
                    progress["scheduled_files"] += 1
                    progress["scheduled_bytes"] += requested
                    monitor["maximum_pending_reads"] = max(monitor.get("maximum_pending_reads", 0), len(pending))
                if pending and not may_submit() and drain_started is None:
                    drain_started = time.monotonic()
                if not pending:
                    break
                done, _ = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for future in done:
                    row = pending.pop(future)
                    try:
                        result = future.result()
                        progress["completed_files"] += 1
                        progress["read_bytes"] += result["read_bytes"]
                        progress["sum_read_seconds"] += result["seconds"]
                        progress["maximum_read_seconds"] = max(progress["maximum_read_seconds"], result["seconds"])
                        if receipt["mode"] == "pilot":
                            receipt["pilot_results"].append(result)
                    except Exception as exc:
                        progress["failed_files"] += 1
                        if len(receipt["read_failures"]) < MAX_PENDING:
                            receipt["read_failures"].append({"name": row["name"], "error": safe_error(module, runtime, exc)})
                        failure = failure or safe_error(module, runtime, exc)
            now = time.monotonic()
            gap = now - last_healthy
            monitor["maximum_observation_gap_seconds"] = max(monitor.get("maximum_observation_gap_seconds", 0), gap)
            monitor["windows"] = monitor.get("windows", 0) + 1
            monitor["maximum_window_files"] = max(monitor.get("maximum_window_files", 0), window_files)
            monitor["maximum_window_bytes"] = max(monitor.get("maximum_window_bytes", 0), window_bytes)
            if drain_started is not None:
                monitor["maximum_drain_seconds"] = max(monitor.get("maximum_drain_seconds", 0), now - drain_started)
            if gap >= MAX_UNOBSERVED_SECONDS:
                failure = failure or "tail warmup exceeded 120 seconds without authenticated health"
        if failure is None:
            observe_quiescent()
    progress["elapsed_seconds"] = time.monotonic() - started
    progress["stopped_scheduling"] = failure is not None
    return failure


def run(module, runtime, helper_sha256, *, all_files=False):
    with runtime.lock():
        state = runtime.load_state()
        checkpoint = state["checkpoint"]
        expected = module.checkpoint_state(checkpoint)
        require(state["pending"] is None and state["rewrites"] == 0
                and expected["format"] == "007" and expected["marked"] == 0,
                "tail warmup requires a certified format007 checkpoint with zero marks and no unfinished stage")
        require(checkpoint.get("remote_generation_verified") is True
                and checkpoint.get("pebble_reopen_verified") is True, "checkpoint lacks completed remote/reopen proof")
        module.validate_inspection(checkpoint.get("reopen", {}), expected)
        mode = "full" if all_files else "pilot"
        receipt_path = module.STATE_ROOT / "warmups" / f"{mode}-{time.time_ns()}-{os.getpid()}.json"
        runtime.wrapper.secure_path(receipt_path, leaf_mode=0o600, missing=True)
        require(not receipt_path.exists() and not receipt_path.is_symlink(), "warmup receipt already exists")
        started = time.monotonic()
        receipt = {"schema": 1, "scope": "fixed-disposable-full-clone-tail-warmup", "mode": mode,
                   "status": "checking", "started_unix": time.time(), "pid": os.getpid(),
                   "helper_sha256": helper_sha256, "controller_sha256": CONTROLLER_SHA256,
                   "checkpoint_sha256": module.digest(checkpoint), "format": "007",
                   "workers": WORKERS, "maximum_in_flight": MAX_PENDING, "tail_bytes": TAIL_BYTES,
                   "headroom_bytes": HEADROOM, "maximum_files": MAX_FILES,
                   "maximum_requested_bytes": MAX_REQUESTED_BYTES,
                   "read_byte_accounting": "logical bytes returned by completed tail reads; scheduled_bytes also bounds failed reads",
                   "monitor": {"samples": 0, "maximum_window_files_limit": MAX_WINDOW_FILES,
                               "maximum_window_bytes_limit": MAX_WINDOW_BYTES, "submission_window_seconds": SUBMISSION_SECONDS,
                               "free_space_check_seconds": FREE_CHECK_SECONDS, "maximum_unobserved_seconds": MAX_UNOBSERVED_SECONDS,
                               "cache_accounting": "rclone cached used-range counter; one-minute cleaner accounting lag"},
                   "progress": {"scheduled_files": 0, "scheduled_bytes": 0, "completed_files": 0,
                                "read_bytes": 0, "failed_files": 0, "sum_read_seconds": 0,
                                "maximum_read_seconds": 0, "stopped_scheduling": False},
                   "pilot_results": [], "read_failures": [], "errors": []}
        runtime.atomic_json(receipt_path, receipt)
        snapshot = None
        metadata_bound = False
        try:
            runtime.guard(new_work=True, clean=True)
            receipt["before"] = sample_health(module, runtime, receipt["monitor"])
            snapshot = runtime._live_metadata()
            pins = runtime.verifier._metadata_pins(checkpoint)
            markers, _ = runtime.verifier._validate_previous(checkpoint, module.digest(checkpoint), pins)
            require(set(snapshot) == set(pins), "closed metadata names differ from the certified checkpoint")
            for name, data in snapshot.items():
                require(len(data) == pins[name]["size"] and hashlib.sha256(data).hexdigest() == pins[name]["sha256"],
                        "closed metadata bytes differ from the certified checkpoint")
            require(snapshot.get("LOCK") == b"", "certified empty LOCK must exist before read-only Pebble inspection")
            require(runtime.verifier._marker_info(snapshot) == markers, "active marker identities changed")
            manifest = markers["manifest"]
            tables, stats = runtime.verifier._decode_tables(snapshot[manifest])
            inventory = runtime.verifier.base.inventory_digest(runtime.verifier._inventory(tables))
            require(len(tables) == expected["count"] and sum(row["size"] for row in tables.values()) == expected["bytes"]
                    and inventory == expected["inventory"] and stats["marked_files"] == 0,
                    "certified MANIFEST inventory differs from the exact checkpoint")
            metadata_bound = True
            receipt["initial_inspect"] = runtime.run_tool("inspect")
            module.validate_inspection(receipt["initial_inspect"], expected)
            runtime.check_snapshot(snapshot)
            runtime.guard(new_work=True, clean=True)
            rows = select_tables(tables, all_files=all_files)
            receipt.update(manifest=manifest, manifest_pin=pins[manifest], inventory_files=len(tables),
                           sst_inventory_sha256=inventory, selected_files=len(rows), selection_sha256=selection_digest(rows),
                           requested_bytes=sum(row["requested_bytes"] for row in rows),
                           selected_levels={str(level): sum(row["level"] == level for row in rows) for level in range(7)},
                           status="warming")
            if not all_files:
                receipt["pilot_selection"] = rows
            runtime.atomic_json(receipt_path, receipt)
            runtime.wrapper.secure_path(module.DB, leaf_mode=0o700)
            directory_fd = os.open(module.DB, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                failure = warm_selected(module, runtime, rows, receipt, receipt_path, directory_fd)
            finally:
                os.close(directory_fd)
            if failure is not None:
                receipt["errors"].append(failure)
            require(receipt["progress"]["completed_files"] == len(rows)
                    and receipt["progress"]["failed_files"] == 0
                    and receipt["progress"]["read_bytes"] == receipt["requested_bytes"],
                    "bounded tail warmup did not complete every selected read")
        except Exception as exc:
            receipt["errors"].append(safe_error(module, runtime, exc))
        try:
            runtime.guard(new_work=False, clean=True)
            receipt["after_reads"] = sample_health(module, runtime, receipt["monitor"])
            require(metadata_bound, "metadata admission did not complete; read-only Pebble inspection remains blocked")
            runtime.check_snapshot(snapshot)
            receipt["final_inspect"] = runtime.run_tool("inspect")
            module.validate_inspection(receipt["final_inspect"], expected)
            if snapshot is not None:
                runtime.check_snapshot(snapshot)
            require(runtime.load_state() == state, "migration journal changed during read-only warmup")
            runtime.guard(new_work=False, clean=True)
            receipt["after"] = sample_health(module, runtime, receipt["monitor"])
        except Exception as exc:
            receipt["errors"].append(safe_error(module, runtime, exc))
        receipt["status"] = "failed" if receipt["errors"] else "succeeded"
        receipt["finished_unix"] = time.time()
        receipt["elapsed_seconds"] = time.monotonic() - started
        receipt["pilot_results"].sort(key=lambda result: result["name"])
        runtime.atomic_json(receipt_path, receipt)
        return receipt_path, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="read bounded tails of the entire certified active inventory")
    args = parser.parse_args(argv)
    module = runtime = None
    try:
        module, runtime, own_hash = bootstrap()
        path, receipt = run(module, runtime, own_hash, all_files=args.all)
        print(json.dumps({"receipt": str(path), "status": receipt["status"], "mode": receipt["mode"],
                          "selected_files": receipt.get("selected_files"), "requested_bytes": receipt.get("requested_bytes"),
                          "progress": receipt["progress"], "elapsed_seconds": receipt["elapsed_seconds"],
                          "errors": receipt["errors"]}, indent=2, sort_keys=True))
        return 0 if receipt["status"] == "succeeded" else 1
    except Exception as exc:
        message = safe_error(module, runtime, exc) if runtime is not None else (
            str(exc) if isinstance(exc, Refusal) else "protected helper bootstrap failed")
        print("FAIL_CLOSED: " + message, file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
