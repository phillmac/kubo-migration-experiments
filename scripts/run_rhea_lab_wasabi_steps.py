#!/usr/bin/env python3
"""Fail-closed controller for the 2026-11-02 Wasabi *scratch* fixture only.

Exercises one marked SST rewrite per Pebble process, drains rclone VFS
in dependency order, independently compares remote contents, downloads
and reopens each completed checkpoint. Never operates on Rhea production
or the frozen 7 TiB lab baseline. Requires a disposable Pebble v1.1.3
adapter (not official upstream API).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path("/home/ubuntu/pebble-recovery-analysis/kubo-lab-rhea-step-20261102")
DB = ROOT / "run" / "pebbleds"
DEMO = ROOT / "pebble-stepper"
RCLONE = Path("/home/ubuntu/pebble-recovery-analysis/lab-rclone-tooling-20261102/rclone-v1.68.1")
READER_CONFIG = "/root/.config/rclone/rhea-pebble-lab-reader-20261102.conf"
DEST = "rhea_pebble_lab_reader:rhea-pebble-lab-20261101-39037c6f01/__rhea_step_rewrite_20261102/pebbleds"
RC = "127.0.0.1:55845"
EXPECTED_SHA = "dd9260adf5212eca8dd68e5f4099d9620536bc64076f21df67d6db8b3ba05466"
EXPECTED_DEMO_BIN_SHA = "781b60bf09dadd33e55b96fc2344855a8d4d32092cd9923cc41a25e1b713130d"


def call(args: list[str], timeout: int = 90) -> str:
    p = subprocess.run(args, capture_output=True, text=True, check=True, timeout=timeout)
    return p.stdout


def run_demo(action: str, directory: Path) -> dict:
    args = [str(DEMO), "--action", action, "--lab-root", str(ROOT), "--db", str(directory),
            "--groups", "4", "--keys-per-group", "2048",
            "--max-overlap-bytes", str(8 * 1024 * 1024)]
    return json.loads(call(args, timeout=120))


def rc(method: str, **kwargs: object) -> dict:
    return json.loads(call([str(RCLONE), "rc", "--rc-addr", RC, method,
                            *(f"{k}={v}" for k, v in kwargs.items())], timeout=18))


def validate() -> None:
    assert os.geteuid() == 0
    assert DB.is_dir() and ROOT.name.startswith("kubo-lab-")
    assert hashlib.sha256(DEMO.read_bytes()).hexdigest() == EXPECTED_DEMO_BIN_SHA
    assert call(["systemctl", "show", "rhea-ipfs-wasabi-kubo.service",
                 "-p", "ActiveState", "--value"]).strip() == "inactive"
    assert call(["systemctl", "show", "rhea-broken-pin-walk-20261026.service",
                 "-p", "ActiveState", "--value"]).strip() == "inactive"
    assert call(["systemctl", "show", "rhea-kubo-lab-step-vfs-20261102.service",
                 "-p", "ActiveState", "--value"]).strip() == "active"
    mounts = Path("/proc/self/mountinfo").read_text()
    matching = [x for x in mounts.splitlines() if f" {ROOT}/run " in x and " - fuse.rclone " in x]
    assert len(matching) == 1
    assert "rhea_pebble_lab" in matching[0] and "__rhea_step_rewrite_20261102" in matching[0]
    s = rc("vfs/stats")
    assert "__rhea_step_rewrite_20261102" in s["fs"]
    q = s["diskCache"]
    assert not q["uploadsQueued"] and not q["uploadsInProgress"] and not q["erroredFiles"] and not q["outOfSpace"]
    assert os.statvfs(str(ROOT)).f_bavail * os.statvfs(str(ROOT)).f_frsize > 1 * 1024**3


def priority(name: str) -> int:
    if name.endswith(".sst"): return 0
    if name.endswith(".log"): return 1
    if "/OPTIONS-" in name: return 2
    if "/MANIFEST-" in name: return 3
    if name.endswith("/CURRENT"): return 4
    if "/marker.manifest." in name: return 5
    if "/marker.format-version." in name: return 6
    raise RuntimeError("Unknown pending object type: " + name)


def settle_one(item: dict) -> None:
    rc("vfs/queue-set-expiry", id=item["id"], expiry=-1000000000)
    started = time.monotonic()
    while any(z["id"] == item["id"] for z in rc("vfs/queue")["queue"]):
        if time.monotonic() - started > 45:
            raise TimeoutError("S3 upload did not complete: " + item["name"])
        time.sleep(.3)
    print("UPLOADED", item["name"], item["size"], flush=True)


def verify_remote(exclude_markers: bool) -> None:
    command = [str(RCLONE), "--config", READER_CONFIG, "check",
               str(DB), DEST, "--one-way", "--download", "--checkers", "4",
               "--log-level", "NOTICE"]
    if exclude_markers:
        command += ["--exclude", "/marker.*"]
    output = call(command, timeout=150)
    print("REMOTE_BYTE_CHECK_PASS", "data_without_markers" if exclude_markers else "all", flush=True)


def verify_download(marked: int, fmt: str, ordinal: int) -> dict:
    child = ROOT / f"recover-after-step-{ordinal}"
    child.mkdir(mode=0o700, exist_ok=False)
    out = child / "pebbleds"
    call([str(RCLONE), "--config", READER_CONFIG, "--s3-no-check-bucket", "copy",
          DEST, str(out), "--transfers", "4", "--retries", "2",
          "--log-level", "ERROR"], timeout=120)
    result = run_demo("inspect", out)
    assert result["format_after"] == fmt
    assert result["marked_after"] == marked
    assert result["keys_after"] == 8192
    assert result["keys_sha256_after"] == EXPECTED_SHA
    return result


def run() -> None:
    validate()
    # The independent S3-downloaded checkpoint is the read preflight;\n    # the demo inspector opens Pebble writable even in inspect mode.\n    # Never let an unnecessary live-FUSE inspection enqueue metadata.\n    before = run_demo("inspect", ROOT / "recovery" / "pebbleds")
    assert before["format_after"] == "013" and before["marked_after"] == 3
    assert before["keys_after"] == 8192 and before["keys_sha256_after"] == EXPECTED_SHA
    reports = []
    for ordinal, goal in ((2, 2), (3, 1), (4, 0), (5, 0)):
        action = "step" if ordinal < 5 else "finish"
        assert not rc("vfs/queue")["queue"]
        result = run_demo(action, DB)
        expected_format = "013" if action == "step" else "014"
        assert result["format_after"] == expected_format
        assert result["marked_after"] == goal
        if action == "step":
            assert result["marked_before"] == goal + 1
            diff = result["sst_diff"]
            assert diff["created_count"] == diff["retired_count"] == 1
            assert result["preflight_overlap_bytes"] <= 8 * 1024 * 1024
            assert sum(c.get("reason") == "rewrite" and c.get("type") == "end" for c in result["compactions"]) == 1
        else:
            assert result["marked_before"] == 0
            assert result["sst_diff"]["created_count"] == 0
        pending = rc("vfs/queue")["queue"]
        byname = {x["name"]: x for x in pending}
        assert len(pending) == len(byname)
        ordered = sorted(pending, key=lambda x: (priority(x["name"]), x["name"]))
        first = [x for x in ordered if priority(x["name"]) < 5]
        last = [x for x in ordered if priority(x["name"]) >= 5]
        for item in first:
            settle_one(item)
        assert all(priority(x["name"]) >= 5 for x in rc("vfs/queue")["queue"])
        verify_remote(True)
        for item in last:
            settle_one(item)
        stats = rc("vfs/stats")["diskCache"]
        assert stats["uploadsQueued"] == stats["uploadsInProgress"] == stats["erroredFiles"] == 0
        assert not stats["outOfSpace"]
        verify_remote(False)
        independent = verify_download(goal, expected_format, ordinal)
        result["independent_reopen_verified"] = True
        result["reopen_sha256"] = independent["keys_sha256_after"]
        result["flush_order"] = [x["name"] for x in ordered]
        reportfile = ROOT / "evidence" / f"rhea-lab-closed-checkpoint-{ordinal}.json"
        reportfile.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        reports.append(result)
        print("CLOSED_CHECKPOINT", ordinal, expected_format, "remaining_marked", goal, flush=True)
    print("PASSED_3_MORE_REWRITES_AND_FINAL_FORMAT14", flush=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        print("FAIL_CLOSED", type(exc).__name__, str(exc), file=sys.stderr, flush=True)
        raise
