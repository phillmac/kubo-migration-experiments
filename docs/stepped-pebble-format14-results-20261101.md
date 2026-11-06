# Stepped Pebble format-14 rewrite: executed synthetic demonstration

**Date:** 1 November 2026 (AEDT). **Production safety:** no production migration.
**Exact commit:** `ce4886f250e272ea781d8b87b96221d6c9fe003e`.
**Passing workflow:** https://github.com/phillmac/kubo-migration-experiments/actions/runs/41248855236
**Evidence artifact:** https://github.com/phillmac/kubo-migration-experiments/actions/runs/41248855236/artifacts/13059849182

## Key outcome

The normal `DB.Compact(start,end,false)` operation was **not sufficient**: on a 3.20 MB isolated L6 SST it returned without rewriting the table or decrementing the marked-file count (earlier failed run 41248247748). Pebble's bottom-level manual compaction is not the same as its marked-file rewrite.

The successful demonstration used a **test-only additive adapter** compiled into a **disposable copy** of Pebble v1.1.3 on a GitHub-hosted runner. The adapter invokes the original Pebble `pickRewriteCompaction` picker and compaction executor once, checks the chosen *atomic unit* byte budget before scheduling, waits for its completion, and has automatic compactions disabled. The runner uses a network namespace and no production mounts or secrets.

A Kubo 0.31 synthetic pebbleds fixture plus four seeded L6 SSTs produced **five** marked legacy tables after ratcheting to format 13 without an unattended format-14 migration. All five marked SSTs were rewritten incrementally while the datastore stayed at format 13. Every batch used a new short-lived standalone process, closed Pebble, and was separately reopened/verified before the next batch.

| Step | Input L6 SST | Output L6 SST | Input bytes | Output bytes | Traced SST read bytes | Traced SST write bytes | Marked files after |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | 000019 | 000080 | 2,101,077 | 2,100,940 | 2,104,885 | 2,100,940 | 4 |
| 2 | 000054 | 000087 | 3,202,790 | 3,202,653 | 3,206,418 | 3,202,653 | 3 |
| 3 | 000058 | 000094 | 3,202,790 | 3,202,653 | 3,206,281 | 3,202,653 | 2 |
| 4 | 000062 | 000101 | 3,202,790 | 3,202,653 | 3,206,144 | 3,202,653 | 1 |
| 5 | 000066 | 000108 | 3,202,790 | 3,202,653 | 3,206,007 | 3,202,653 | 0 |
| **Total** | **5 retired** | **5 created** | **14,912,237** | **14,911,552** | **14,929,735** | **14,911,552** | **0** |

The trace values are **successful SST-file read/write syscall return bytes** during each standalone step, using per-thread `strace -ff -yy`. Full application-content integrity scans were **deferred to separate post-close invocations**, so those scans do not inflate the compaction step's counted bytes. The minor extra read bytes may include database opening/metadata access. These are not necessarily physical disk I/O or remote-object throughput.

Each step's Pebble `CompactionEnd` event reported `reason=rewrite`, **exactly one input and one output file**, and the same file numbers and sizes as the independently enumerated before/after SST inventory. The harness rejects any mismatch, any errors, and failure to reduce `DB.Metrics().Compact.MarkedFiles`.

The five output files total **14,911,552 bytes**, very nearly a complete rewrite of the five corresponding inputs. **Incremental migration reduces peak in-flight work; it does not eliminate total rewrite I/O.**

## Backpressure negative acceptance

An explicit 1,048,576-byte input budget was tested against Pebble's next internally selected **2,101,077-byte** marked atomic rewrite unit. The adapter rejected the operation before scheduling. A subsequent fresh process verified:

- zero SSTs created or retired;
- marked SST count remained five;
- test key/value digest unchanged;
- Pebble remained reopenable.

This demonstrates a fail-closed input-size guard, **not** a complete production disk-space/throttle controller.

## Final format and application compatibility

After independently verifying five closed checkpoints with marked count `5 → 4 → 3 → 2 → 1 → 0`, the explicit Pebble `RatchetFormatMajorVersion(14)` completed with **zero additional SSTs created or retired**. The synthetic repository then underwent explicit embedded Kubo schema 16→17→18 migrations, with datastore `formatMajorVersion:14` pinned to avoid upgrading to Pebble's newest format on first Kubo 0.43.1 use.

The **Kubo 0.43.1 offline CLI**, not the daemon, opened the migrated repository and verified exact block payloads, recursive and direct pins, and MFS. A frozen Kubo 0.31.0 physical rollback generation remained independently readable.

## Important limitations and production gates

- This only proves *one chosen marked atomic unit at a time* on these fixtures. Some SSTs share key boundaries and must be rewritten as a larger atomic group; a Rhea operation must refuse any group exceeding configured input/output and free-space budgets.
- The adapter is **not upstream Pebble API**, and needs independent code review, crash interruption/recovery tests and static/race checks before a real migration.
- The standalone experiment used local Linux storage; it did **not** itself attach rclone, exercise its VFS write-back cache, or validate versioned Wasabi recovery. That separately proved checkpoint mechanism must be integrated and retested for Pebble's format-version and manifest-marker semantics.
- Production rclone's cache cap is a soft eviction target. Enforce backpressure **before** spawning a new rewrite, with actual free-space floor, dirty and queued VFS bytes, error counts, object version retention, and no competing Kubo daemon. When a bounded rewrite completes, close Pebble, flush immutable SST outputs and WAL, verify the finalized manifest and format/manifest markers **in correct dependency order**, then permit the next unit.
- The format 7 and 10 preliminary migrations still require their own production-size I/O/memory budgets. Synthetic format 13 did not rewrite the 7 TiB source, but does not prove the same for production with unusual historical SST layouts.
- The previously verified Rhea production checkpoint (`MANIFEST-47475278`, 93,697 referenced SSTs) is untouched. Installed Kubo is still 0.31.0; staged 0.43.1 was not installed into the active path, and the Wasabi Kubo service remains stopped.

Next recommended gates: add disposable rclone/VFS + versioned-object-store checkpoint tests, inject crashes during marked rewrite and manifest-marker transition, test oversized atomic units, and measure a larger multilevel synthetic fixture. Production format ratchet and Kubo restart remain separate, explicit maintenance decisions.
