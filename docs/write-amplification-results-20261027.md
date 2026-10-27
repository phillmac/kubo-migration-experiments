# Kubo/Pebble migration file-write volume — 27 October 2026

## Result

For the tested all-Pebble repositories, the **0.31.0 -> 0.34.1 -> 0.43.1**
upgrade wrote approximately **1 MiB to repository files per MiB already in the
original repository**. Across eight cases the measured range was
**0.992277 to 1.018832 MiB/MiB**. This is essentially one full data rewrite,
not a metadata-only upgrade. It is an observed range, **not a production bound**.

The bulk writes occurred on the first **0.34.1 bridge open**, in SST files.
The explicit repository-schema16->18 migration wrote **11,713 bytes** in every
case. The first0.43.1 datastore open wrote only metadata/WAL in these cases:
**3,637 to31,604 bytes, with zero SST write bytes** observed in that phase.

## Measurements

Two deterministic non-repeating fixtures were tested at each size. Sizes below
are MiB (1,048,576bytes); the ratio is equally valid as MBwritten/MBrepo when both
sides use the same units. The denominator is actual closed original repo file
lengths, not just source-file bytes or a logical cumulative DAG size.

| Input fixture MiB | Original repo MiB, two cases | Migration file writes MiB, two cases | MiB written per MiB repo, observed range |
|---:|---:|---:|---:|
|16|16.021855–16.021862|16.033545–16.033545|1.000729–1.000730|
|64|64.066535–64.069462|64.075326–64.077677|1.000092–1.000174|
|256|256.211208–256.216261|254.237527–256.236263|0.992277–1.000098|
|1024|1024.788429–1024.805064|1024.839271–1044.103761|1.000050–1.018832|

Migration total = bridge_first_open + schema_16_to_18 + target_first_open.
It excludes fixture creation, baseline checks, physical lab copies, rollback
copies, the separate acceptance-read phase and the later new-data write test.
Gross migration-phase writes include normal startup/background compaction; an
independent old-reopen control is not subtracted as though it were identical work.

### Why size deltas would have been misleading

The1GiB cases grew by only **22,301 and10,320 bytes** during migration, despite
writing **1,074,621,863 and1,094,822,145 bytes** to repository files. A before/after
folder-size comparison would miss almost all of the write volume.

In the higher-write1GiB case, the trace additionally shows:

- `pebbleds/003494.sst`:12,851,494bytes written, then successfully unlinked.
- `pebbleds/003499.sst`:8,393,039bytes written, then successfully unlinked.

Those two transient SSTs account for **21,244,533bytes /20.260365MiB** of writes
that do not survive in the final directory. The independent trace audit checked
the successful unlink syscalls as well as the write return values. Background
compaction is a source of variability: the old-version reopen control in that
same case also wrote6,064,613bytes, without any version upgrade. Tracing can
perturb scheduling, so do not regard the largest measured ratio as a worst case.

### Acceptance reads and new writes

All cases passed full fixture hashing, recursive and **nonempty direct pin** set
comparison, unpinned block reads, MFS root comparison, identity/datastore schema
invariants, old-generation restoration, and unchanged-original checks.

The six separately opened target acceptance-read commands added21,834–189,624
file-write bytes. Including these checks changed the largest observed overall
ratio to **1.019008**. Reads of a repository via CLI can still generate startup/
shutdown metadata writes; this experiment did not run a long-lived daemon.

Separately adding a fresh **1MiB raw block** with0.43.1 wrote **2,102,522–2,130,493
bytes**, i.e. **2.005121–2.031796MiB per MiB of new data**. The per-file ledger
shows both WAL and SST writes. A subsequent independent reopen/read/hash passed.
This measures a small newly added block under these fixtures, not long-run ingest
amplification or additional migration overhead. It must not be mixed into the
migration numerator.

## Evidence and independent audit

- 16/64/256MiB, two cases each: run
  [40476134520](https://github.com/phillmac/kubo-migration-experiments/actions/runs/40476134520),
  tested commit `4e2844ebafdfe9c621e56d6a0831faf77293bc8b`.
- 1024MiB, two cases: run
  [40476805266](https://github.com/phillmac/kubo-migration-experiments/actions/runs/40476805266),
  tested commit `fe778bf7b8846ce7470c7e3e100b01a581a9a5a1`, branch
  `experiment/write-volume-1g-20261027`. Measurement scripts are identical to the
  smaller sweep; only workflow name/trigger/size matrix differ.
- **All eight jobs passed. All36 unit tests passed in each job.**
- Every runtime meter calibration counted exactly **1,704,320known repository
  write bytes**, including overwrite, writev, rename and subsequently deleted
  data, while excluding stdout.
- All eight artifact ZIPs were independently downloaded and matched to their
  GitHub SHA-256 records. Every measured command's per-file write ledger was
  independently recomputed from the compressed raw strace logs and matched the
  report. Artifact inventories were checked for absence of repo configs,
  keystores and actual SST files.
- Exact per-case bytes, phase breakdowns, artifact IDs/hashes are retained in
  [small-sweep JSON](../results/write-amplification-16-256mib-20261027.json) and
  [1GiB JSON](../results/write-amplification-1g-20261027.json).
- The original prototype run40476016663 failed during calibration because
  reading an exited child's `/proc/PID/io` was denied. It provides **no accepted
  migration measurement**. The corrected collector uses waited-child accounting
  in the observer's own `/proc/self/io`, without changing host security settings.

Only synthetic data was used, on disposable hosted Ubuntu24.04 with Kubo commands
unprivileged and network-disabled. Official executable SHA-256s were pinned and
archives verified against SHA-512 manifests. No production access or mutation.

## Interpretation and limits

**File writes are not hardware writes, cloud upload bytes or retained-version
storage.** The primary measurement sums actual successful repository-file write
syscalls across threads, including overwrites and deleted files. It excludes
filesystem journal/device amplification, trace/journal output and all lab copies.
Whole changed-file volumes and kernel write counters are separately retained.

In particular, the initial lab clones were not explicitly fsynced before each
phase. Kernel `cancelled_write_bytes` includes deletion of some old dirty pages
created by the copying parent. Do **not** subtract it from `write_bytes` to
pretend the migration had almost no physical IO. The kernel documentation allows
cancellation of IO charged to another process. A separate clean-cache/storage-
layer experiment is needed for physical-write totals. The primary per-file
syscall measurement is unaffected by that accounting caveat.

A near-full SST rewrite means a remote-backed physical datastore deserves a
separate test: a replacement SST set may need substantial uploading, and old
versions may remain retained. Object versioning helps recovery but does not make
the rewrite free, nor select a consistent MANIFEST/WAL/SST recovery generation.
Remote upload timing can omit transient files or upload them before deletion;
this experiment deliberately does not guess which will happen.

For planning, allow approximately one complete rewritten Pebble data set **plus
headroom, a consistent rollback generation, and any retained remote versions**.
That is a provisional inference from this workload, not a capacity guarantee.
If another deployment stores only metadata in Pebble and blocks elsewhere, do
not apply the all-Pebble ratio blindly to the entire archive.

Remaining gates include realistic/private physical snapshots, older/damaged SST
and WAL cases, crash/interrupted migration, pin-stream cancellation/locking,
long-lived daemon lifecycle, clean-source physical IO and separate object-store
writeback/retention tests. No production migration is authorised by these results.

See [measurement method](write-measurement-method.md) for phase definitions and
counter semantics. Primary counter reference:
https://man7.org/linux/man-pages/man5/proc_pid_io.5.html
