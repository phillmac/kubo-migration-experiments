# Paced Pebble format-14 rewrite — design and test gates

Status: source-reviewed design, **not implemented, not approved on production**. The standalone format-13 synthetic migration already passed in GitHub CI run 41244941190.

## Relevant exact Pebble v1.1.3 behaviour

- Format 10 scans pre-Pebblev1 SST tables in levels 1–6 and marks them for rewrite. The marked state is persisted in a rotated MANIFEST.
- Format 14 calls compactMarkedFilesLocked, which repeatedly picks same-level rewrite compactions until every marked file is gone. The picker starts with one SST but can expand to an *atomic compaction unit* if key boundaries require it.
- MaxConcurrentCompactions=1 limits simultaneous jobs; it does **not** pause between completed jobs.
- Public DB.SSTables exposes key ranges and sizes. Public DB.Compact(start,end,false) allows manually requested key-range compactions, but these can involve multiple SSTs and levels; exact one-file rewrites are not guaranteed.
- DisableAutomaticCompactions=true can inhibit background work while running manually requested compactions. It cannot be combined naively with a format-14 ratchet *while files remain marked*: the format-14 migration requires its compaction scheduling loop to make progress. Ratchet to 14 only once no marked files remain, or implement a separately reviewed Pebble fork/adapter.
- The format-7 migration can also require blocking compaction. Reaching format 13 on tiny fixtures does not prove a massive database can reach it cheaply.

Sources:
https://github.com/cockroachdb/pebble/blob/v1.1.3/format_major_version.go
https://github.com/cockroachdb/pebble/blob/v1.1.3/compaction_picker.go
https://github.com/cockroachdb/pebble/blob/v1.1.3/db.go
https://github.com/cockroachdb/pebble/blob/v1.1.3/compaction.go

## Proposed bounded standalone controller

1. Create a fresh synthetic all-Pebble store with many SSTs, including pre-Pebblev1 tables in lower levels, and freeze a separate rollback generation. Never use production Rhea FUSE for development.
2. Advance format cautiously to 10/13 with explicitly controlled automatic compaction, preserving evidence of marked-file count, SST format distribution, and actual migration IO.
3. Plan one small candidate via SST key ranges, overlap counts and byte budgets. Prefer an isolated lower-level candidate. Reject anything larger than the configured budget.
4. On an expendable clone, use public DB.Compact with MaxConcurrentCompactions=1 and DisableAutomaticCompactions=true. Record CompactionBegin/End input and output SST file numbers, bytes, duration and changes to DB.Metrics().Compact.MarkedFiles. This is a *bounded key-range experiment*, not proof of exactly one file changed.
5. Close the standalone Pebble process gracefully between checkpoint batches. Inspect rclone RC queue on a **separate test prefix and cache**. Upload and verify new immutable SSTs, WALs and options, then the closed MANIFEST and format/manifest markers in appropriate dependency order.
6. Independently parse the resulting MANIFEST and verify every referenced SST object and necessary marker, including version IDs, sizes and hashes. Keep prior S3 versions for rollback.
7. Resume at a new bounded key range, using a durable journal and actual MANIFEST state to reconcile interrupted work. When MarkedFiles is zero, test final ratchet to 14. Verify target Kubo 0.43.1 offline CLI reads and pin/MFS invariants, plus old-generation rollback.

If public manual DB.Compact is too broad, investigate a small, separately reviewed Pebble v1.1.3 fork exposing **one marked atomic rewrite** from the existing picker. Avoid raw SST rewrites or custom MANIFEST surgery.

## Backpressure and migration boundaries

Rclone VFS cache max size is a soft eviction target, **not** a hard write throttle. Open files cannot be evicted; dirty files need to stay until uploaded. The Rhea observations were approximately 7.082 TiB in 93,697 SSTs, a 4 TiB configured VFS cache cap, 1 TiB minimum free reserve and about 2.7 TB filesystem free. The controller must stop producing new outputs if free disk space, dirty cached bytes or queue errors breach conservative thresholds. Do not trust automatic eviction alone. Do not force a queue expiry on an active MANIFEST/CURRENT/marker.

Format >=3 replaces the original CURRENT semantics with atomic manifest markers; the old format-1 pointer-checkpoint procedure must be adapted and independently tested before any real ratchet. A correct intermediate checkpoint is not just an empty RC queue. It is a fully closed and verified MANIFEST, its referenced SSTs, WALs, and the relevant format/pointer markers.

The candidate format-13 migration and Kubo 0.43.1 compatibility already passed on synthetic fixtures. The format-14 staged rewrite, write-volume measurements, crash restart, S3 marker replay and resumable controller are **still unproven**. Keep Rhea Kubo stopped and its verified recovery generation unchanged during these experiments.
