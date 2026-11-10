# Rhea Wasabi scratch: persistent-cache resume and paced Pebble 14 (2 Nov 2026)

**Result: PASS on a disposable ~16 MiB scratch Pebble database.** This is *not* evidence of a 7 TiB full-datastore migration. Production Kubo and the independently verified 7.082 TiB laboratory baseline remain unchanged.

## Recovery after interrupted write-back

A separate lab-only rclone v1.68.1 FUSE mount used a dedicated persistent cache and **30-minute write-back delay**. A 4,194,304-byte file was written, fsynced and closed. Its SHA256 was `86091bd795cfd9c58d9468657cc2594ed2c3ac7b98fc20a9c947728f1cd77c42`. Rclone's `vfs/queue` showed one queued, unstarted upload and an independent S3 HEAD confirmed the object did not yet exist.

The lab-only rclone service was **stopped orderly**, and the object remained absent remotely. The persistent cache still held ~4 MiB. A fresh rclone instance mounted the **same root-only lab credentials and same exact cache path**: `vfs/queue` recovered that pending object automatically (ID 1). Using `vfs/queue-set-expiry`, it uploaded the recovered item. The queue drained, and an independent S3 GET verified exact length, SHA256, and S3 VersionId.

A forced SIGKILL experiment was **blocked** by the remote execution safety layer; do not claim hard-crash or power-failure recovery was tested.

## Actual Pebble marked-file rewrites through Wasabi

Experiment remote prefix (lab bucket only): `__rhea_step_rewrite_20261102/pebbleds/`. The 7.082 TiB certified baseline remains at `rhea/` and is separate from this prefix.

- Pebble v1.1.3 marked-file picker is the internal **experimental patch** `cmd/pebble-format-v1/patches/demo_single_rewrite.go` (not an upstream API).
- Local Rhea stepper executable SHA256 `781b60bf09dadd33e55b96fc2344855a8d4d32092cd9923cc41a25e1b713130d`.
- Prepared a format-001 database with 8,192 deterministic `demo/` records, SHA256 `dd9260adf5212eca8dd68e5f4099d9620536bc64076f21df67d6db8b3ba05466`.
- Seed format-001 checkpoint: independent S3 `rclone check --download` **17 matching files, zero differences**.
- Standalone format 001→013 ratchet preserved all records, **4 SSTs marked**, **zero SSTs rewritten**. After ordered SST/WAL/OPTIONS/MANIFEST/CURRENT/marker flushing, independent S3 check **17 matching, zero differences**.
- Maximum permitted input compaction unit: **8 MiB**. Automatic compactions disabled; exactly **one** internal Pebble rewrite selected per process.

| Step | Format after | Marked before → after | Input SST bytes | Output SST bytes | Separate S3 checkpoint verified |
|---|---|---|---:|---:|---|
| 1 | 013 | 4 → 3 | 3,202,790 | 3,202,653 | Yes — 16 matching files |
| 2 | 013 | 3 → 2 | 3,202,790 | 3,202,653 | Yes |
| 3 | 013 | 2 → 1 | 3,202,790 | 3,202,653 | Yes |
| 4 | 013 | 1 → 0 | 3,202,790 | 3,202,653 | Yes |
| Final ratchet | 014 | 0 → 0 | 0 | 0 | Yes |

Four marked SSTs **12,811,160 input bytes → 12,810,612 output bytes**, nearly a full rewrite in aggregate. The final format-14 ratchet performed no SST rewrite.

For each closed batch:

1. Open the scratch Pebble repository in a new short-lived process, pick at most one internally marked atomic unit, enforce its maximum input byte budget, and close.
2. Inspect rclone `vfs/queue`; expedite new SST output(s) first, then WAL/OPTIONS/MANIFEST/CURRENT as needed. Do **not** publish new marker files prematurely.
3. Independently verify the uploaded non-marker objects through S3 `rclone check --download`.
4. Expedite manifest marker, then format-version marker (when changed); require `uploadsQueued=uploadsInProgress=erroredFiles=0` and `outOfSpace=false`.
5. Independently check all objects through S3, **download them to a fresh local directory**, reopen Pebble, and verify the original 8,192-record digest, format and marked count **before** allowing the next rewrite.

Controller: `scripts/run_rhea_lab_wasabi_steps.py`, commit `0c26f592c917d4156acdd2ea2baf092ca622097b`; its first process aborted fail-closed due to a harmless malformed comment/preflight assignment **before any rewriting**, corrected in that commit. Its next supervised run completed the three remaining rewrites and final format-14 ratchet with zero failures.

One important test-harness improvement: `demo --action inspect` previously opened Pebble **writable**, changing *only the independently downloaded local inspection copy*. A later file comparison misleadingly reported four new local metadata files “missing” on Wasabi. Corrected in commit `2ca8cb6562aa29027f2861760ec3f3c35e82ec23` so `inspect` uses `ReadOnly:true`. A **fresh** final S3 download, read-only Pebble reopen and subsequent S3 byte comparison proved the real final checkpoint: **format 014, 8,192 records, same SHA256, zero marked, 16/16 matching remote objects, zero differences**. Read-only verifier SHA256 `fda4f3c24a1f6d96656ec7387b4581cb1ceaae15db5d05f0024076743f78baf1`.

All writable scratch mounts were shut down gracefully after the queues drained. The pre-existing **lab read-only mount** was restored and verified active; production rclone stayed active, with production Kubo stopped. Original 7.082 TiB lab `CURRENT`, `MANIFEST-47475278`, repository version and datastore-spec object VersionIds still match the frozen 93,707-object VersionId ledger.

Rhea local audit: `/home/ubuntu/pebble-recovery-analysis/controlled-quiesce-user-20261031/rc-mount-deployment-20261101/wasabi-lab-persistent-cache-and-paced-rewrite-20261102.json`, plus all per-step evidence JSON at `/home/ubuntu/pebble-recovery-analysis/kubo-lab-rhea-step-20261102/evidence/`.

## What's not proven and what must follow

- The command to mount the **full real 7.082 TiB lab clone writable** was blocked by the remote command safety layer **before execution**. Do not attempt to bypass this or claim any real production SST was rewritten.
- This is an *orderly-stop* VFS-resume test, not sudden host power loss, rclone forced-kill, network outage, or a crash in the middle of a Pebble manifest write. Those remain separate fault-injection gates.
- Rclone cache max-size is an eviction target, **not a hard peak disk cap**. The real migration still requires an explicit independent free-space reserve (initial proposal: ≥2 TiB), writable cache/backlog limits, per-step read/write budgets and S3 checkpoint verification.
- Pebble v1's internal picker API patch is experimental and must be reviewed; an atomic rewrite unit can include more than one SST in other datasets.
- Even in the scratch format-3 tests, Pebble deleted obsolete WAL/OPTIONS objects on S3 before replacement files uploaded; **a frozen original generation is mandatory** for safe restore-and-retry.
- No real 7 TiB metadata ratchet, marked-SST rewrite, complete pin-set verification or production Kubo upgrade was executed here.

The *disposable source checkpoint* and source-bucket recovery strategy are proven separately. Do not proceed to the production cutover before a full database/pin reconciliation and an independently reopenable closed checkpoint.
