# Rhea Wasabi format-3 marker and VFS checkpoint demonstrations — 2 Nov 2026

**Outcome: synthetic test PASS, production NOT touched.**
**Lab PR:** https://github.com/phillmac/kubo-migration-experiments/pull/3

All remote operations were confined to the disposable lab bucket `rhea-pebble-lab-20261101-39037c6f01`, in three additional unique scratch prefixes outside the certified 7.082 TiB `rhea/` baseline. The production Wasabi Kubo daemon remained stopped and its independent rclone service was not reconfigured or restarted.

## Lab utility

- `cmd/pebble-format-v1/checkpoint3/main.go`, Pebble v1.1.3, Go 1.23.
- Commit `c505507b97b10a550ecb5abef3b7aaf07692070e`, Rhea binary SHA-256 `ca3eacb08b39f1aed818d75ff4e2717357198d12d53bd5bee92853cf484f519a`.
- Three modes: `seed`, `ratchet3`, `inspect`. Supports only the explicitly approved synthetic local scratch root and the specifically verified `/mnt/rhea-pebble-format3-live-20261102/pebbleds` rclone lab scratch mount. It refuses the real production repository and the 7TiB lab baseline.
- Seeded **4,096** deterministic 1KiB values across four SSTs, SHA-256 over sorted keys/values: `fc4adb6675540bce789a18734e055e3d29eedad553f6f75e80552ea4fdf53291`.
- Local Pebble `RatchetFormatMajorVersion(3)` succeeded with data digest preserved. Independent local reopen succeeded both before (`001`) and after (`003`).

## Staged S3 marker publication

1. Uploaded a complete source format-1 baseline under `__pebble_format3_checkpoint_20261102/seed1/pebbleds/`, independently downloaded through the *reader-only* lab identity, verified format 001 and all 4,096 keys.
2. Uploaded the upgraded format-3 database to a **separate scratch generation**, excluding `marker.*`, leaving `CURRENT = MANIFEST-000000\n` (deliberately invalid). Independent download+Pebble open failed as expected, citing missing `MANIFEST-000000`.
3. Uploaded `marker.manifest.000001.MANIFEST-000016` only; independent read still failed as expected.
4. Independently ran `rclone check --download --one-way` against all 11 staged SST/WAL/MANIFEST/OPTIONS/CURRENT/manifest-marker objects: **zero differences**.
5. Uploaded `marker.format-version.000002.003` **last**; independently downloaded it. Pebble read-only reopened as format 003, all 4,096 records and digest unchanged.

## Queue-managed rclone VFS publication

Used **rclone 1.68.1** in a separate systemd-managed scratch mount, with root-only lab IAM identity, cache limit 256 MiB, and a **10-minute VFS write-back delay**. No production FUSE or cache was used.

1. Copied 10 closed non-marker files into the FUSE mount. `vfs/queue` reported all 10 delayed and no active uploads.
2. Executed `vfs/queue-set-expiry` against each precisely identified queue entry in a fixed order: SSTs, WAL, OPTIONS, both MANIFESTs, then invalid `CURRENT`. Each operation was awaited until the queue ID disappeared. Result: zero pending/in-progress/errored files.
3. Independently compared all 10 files at the **remote S3 path**, full contents, against the closed source. **Zero differences**.
4. Added only the new manifest marker to the FUSE mount and expedited its single queue entry (ID 11). A fresh independent download **still failed** to open while the format marker remained absent.
5. Added and explicitly expedited only `marker.format-version.000002.003` (ID 12). All VFS queues empty, zero errors; full independent remote `rclone check --download`: **12 matching files, no differences**. Downloaded remotely, Pebble opened format 003 with exact 4,096 records/digest.
6. Quit the lab rclone service via loopback `core/quit exitCode=0`, verified clean exit and unmount.

Rhea audit: `.../rc-mount-deployment-20261101/wasabi-lab-format3-ordered-marker-checkpoint-20261102.json`.

## Actual *live* Pebble ratchet on an isolated FUSE mount

For an additional compatibility test, copied the format-1 seed into a **third, empty scratch prefix**, `__pebble_format3_live_20261102/pebbleds/`. Mounted it with the pinned **lab-only** rclone 1.68.1 executable, with its own 256MiB cache, 10-minute writeback, and private loopback RC.

- Pebble `inspect` first opened format 001, with digest unchanged.
- **Actually ran `RatchetFormatMajorVersion(3)` against the writable FUSE mount**, not just against local disk. **PASS**, 0.166s; same 4,096 records and digest.
- Rclone held six changed files in its queue: OPTIONS, new WAL, new MANIFEST, invalid CURRENT, manifest marker and format marker. They were flushed in this order and each queue entry was separately awaited. Result: zero uploads pending/in-progress/errors and no out-of-space condition.
- Independent `rclone check --download` found **12 matching S3 objects**, no differences. Independent S3 download + Pebble read-only reopen: format 003 and all records/digest correct. The temporary lab FUSE service exited gracefully via `core/quit`.

**Important adverse finding: Pebble's obsolete-file deletions were *not* held behind the VFS upload queue.** Before flushing new objects, an independent direct S3 listing already showed the old WAL files and OPTIONS removed from the visible latest generation. A subsequent `ListObjectVersions` showed **five latest delete markers** for `000008.log`, `000009.log`, `000011.log`, `000013.log` and `OPTIONS-000003`. Although Wasabi's versioning preserves the earlier bytes, the old *latest* generation is no longer guaranteed to remain openable during this window. **Therefore: even an excellent marker-last upload controller is insufficient to protect readers of an in-place generation.**

Rhea audit: `.../rc-mount-deployment-20261101/wasabi-lab-format3-live-fuse-checkpoint-20261102.json`.

## Required design for the real 7 TiB dataset

**Do not run Pebble in-place against the production repository.** Prefer an independently addressable *new remote object generation / prefix*, with its own manifest and marker state, populated from a verified immutable source snapshot. Keep the original generation and its 93,707 recorded S3 VersionIds untouched while migrating the new generation. Enforce limits on atomic input SST size, output bytes, cache free space, dirty uploads, and upload errors.

For every closed checkpoint, verify complete referenced-SST/WAL/OPTIONS/MANIFEST data first; then publish marker.manifest and marker.format-version in dependency order; verify contents and version IDs independently through S3; perform a fresh read-only reopen before advancing. Do not rely on the rclone cache limit as a hard throttle or on FUSE fsync as proof of remote durability. Roll back or discard only the isolated generation on failure.

Next gates: implement the generation-scoped migration controller, per-batch restart/recovery tests, and explicit marker checkpoint validation against a *separate disposable generation* of Rhea's real 7 TiB lab copy before any production cutover. **No real Rhea SST was rewritten during this demonstration.**
