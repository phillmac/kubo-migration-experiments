# Migration file-write measurement

This experiment is synthetic-only. No existing repository, live service, remote
object store, credentials or production data are used. Binaries are checksum
pinned to Kubo 0.31.0, 0.34.1 and 0.43.1. Commands run unprivileged in a private
network namespace on disposable GitHub-hosted Ubuntu 24.04.

## Question and denominator

How many bytes are written to repository files while migrating, per byte already
in the original repository? The primary denominator is the **sum of regular-file
lengths in the closed original Kubo repository**, not the requested input size,
not allocated disk blocks, and not an IPFS cumulative logical-DAG size (which may
count deduplicated content repeatedly). Results also retain input bytes, SST bytes
and allocated filesystem bytes so this choice can be audited.

MiB means 1,048,576 bytes. The write/input ratio is dimensionless, so 0.1 MiB/MiB
is also 0.1 MB/MB when both sides use the same unit.

Fixtures contain 16, 64 and 256 MiB of deterministic SHAKE-256 output, with each
MiB using a different domain-separated input. They are not repeating-byte or
compressible zero fixtures. Two seeds/repetitions are used per size. Every case
also includes a nonempty direct pin, an unpinned raw block and an MFS reference.
The old-generation copy is sealed after baseline reads and independently restored.

## Four different quantities, not interchangeable

1. **Repository file-write bytes (primary).** strace follows all threads, decodes
   descriptor paths and records the successful return values of write/pwrite/
   writev and supported copy syscalls. Only destinations inside the active
   synthetic repo count. Repeated writes and writes to subsequently deleted files
   count. stdout/stderr, trace files, observer journals and copied lab repositories
   do not. Failed writes add no bytes. Unsupported asynchronous or writable-shared
   mmap paths abort instead of reporting a false zero.
2. **Kernel write_bytes (secondary).** A small parent samples /proc/self/io before
   fork and after reaping the command and draining its pipes. Linux includes
   waited-for children. The parent writes no files between samples, and its
   journal is created afterward. This avoids exited-child /proc access restrictions
   and excludes strace's own output. write_bytes is accounted at page-dirtying
   time; cancelled_write_bytes is reported separately. These are NOT hardware
   device-write or S3-transfer measurements. Read counters include observer
   pipe-draining and are not target-only storage reads.
3. **Surviving new/changed-file bytes.** Hash manifests before/after each phase
   count the full final lengths of added/changed files. Useful for judging whole-
   file churn, but not equivalent to remote upload bytes: transient files, upload
   timing, re-uploads and version retention are not modelled.
4. **Net repository growth.** Final minus initial file lengths. A zero-growth
   database can still have rewritten all of its contents. Never substitute this
   for write amplification.

Before touching a Kubo fixture, each runner calibrates the primary meter against
**1,704,320 known write bytes**, including an overwrite, vectored write, renamed
file, subsequently deleted file and excluded stdout. Parser tests independently
cover short writes, failed writes, path-prefix collisions and incomplete traces.
The first prototype could not read exited-child /proc IO on the runner; that
attempt failed during calibration and supplies no accepted migration numbers.
The corrected parent-delta approach does not weaken host permissions.

## Phase boundaries

- old_reopen_control: one unchanged 0.31.0 recursive-pin listing, on its own copy.
- bridge_first_open: first 0.34.1 open of an independent old physical copy.
- schema_16_to_18: explicit 0.43.1 `--offline repo migrate --to=18`.
- target_first_open: first datastore-opening 0.43.1 recursive-pin listing.
- target_read_acceptance: full payload hash, direct/unpinned bytes, both pin sets
  and MFS root, using six separately closed CLI commands.
- target_reopen_control: another unchanged 0.43.1 open.
- target_new_1mib and target_new_readback: add a new independent 1 MiB raw block,
  then reopen/read/hash it. This is a new-data write test, not migration overhead.

**Migration total** is bridge_first_open + schema_16_to_18 + target_first_open.
Acceptance-read overhead is reported separately and also as an optional combined
ratio. Fixture generation, baseline verification, physical lab copying,
old-generation restore, new-data write and controls are excluded from that total.

The tracer can perturb scheduling/compaction. CLI opens/closes do not model a
long-running daemon or its eventual background compaction. Larger old databases,
older SST formats, tombstones, corruption and custom tuning can change results.
Neither two repeats nor three modest sizes justify a universal production bound.
Remote writeback and retained-object storage require their own isolated test.

## Reproducibility

Every accepted result must identify workflow run, commit, matrix size/seed,
executable hashes, kernel/strace version, exact command journals, per-file write
ledgers, before/after totals and compressed syscall traces. Original fixture
hashes and all content/pin/MFS/restore checks must pass. Artifacts contain reports
and buffer-redacted traces, never repository copies or generated private keys.

Primary method references:
- https://man7.org/linux/man-pages/man5/proc_pid_io.5.html
- https://docs.kernel.org/filesystems/proc.html
- https://strace.io/
