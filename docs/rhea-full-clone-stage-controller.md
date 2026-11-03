# Fixed full-clone stage controller

`scripts/run_rhea_full_clone_steps.py` coordinates the already admitted,
disposable Rhea clone from its certified format-003 checkpoint through deliberate
preparatory stages and **one** bounded marked SST rewrite. It does not start or
stop services, run Kubo, touch the production bucket, remove a cache, retry a
writer, or expose format-14 finalization. The original scratch stepper and mount
wrapper are unchanged.

## Fixed inputs and deployment

The only database is
`/mnt/rhea-pebble-lab-writable-20261102/pebbleds`, on the guarded full-clone mount
of `rhea-pebble-lab-20261101-39037c6f01/rhea`. Production Kubo and the walker must
remain inactive, production rclone must remain active, and the unrelated
`/data/ipfs` instance is left alone. The mount wrapper enforces these identities.

Install reviewed, root-owned copies under
`/root/.local/share/rhea-wasabi-lab-admin-20261101/`:

- `run_rhea_full_clone_steps.py`
- `realstep`, built from the exact reviewed Go sources and pinned Pebble adapter
- `verify_rhea_full_clone.py`
- the existing `rhea_wasabi_lab_mount.py` and `verify_rhea_lab_format3.py`

The controller pins wrapper SHA-256
`75c908c6ffb154264905f858f8b26e0fa7ab9fd22cd1dd75914918257ec5628d`.
The generic verifier separately pins the previously certified MANIFEST decoder.
The controller must execute from its fixed trusted installation, and every
dependency must pass the protected-path checks. It accepts no alternate host,
bucket, prefix, executable, database, credential, socket, or journal path.

`full-clone-step-pins.json` in that same directory is a root-owned mode-0600 file
with exactly these fields. Substitute the independently verified digests of the
three installed artifacts:

```json
{
  "schema": 1,
  "controller_sha256": "<64 lowercase hexadecimal characters>",
  "go_sha256": "<64 lowercase hexadecimal characters>",
  "verifier_sha256": "<64 lowercase hexadecimal characters>"
}
```

Those pins, all fixed limits, the wrapper hash, and the seed certificate hash are
bound into the migration journal. Changing code or limits does not silently
readmit an existing journal.

The seed is the already completed certificate at
`format3-20261103/full-clone-format3-certified.json` under the trusted directory.
Its exact-byte SHA-256 is
`a7438699846ca71af61ad7c7622f9807be2846273c75fd3559730a51988f1eaf`.
It records independent S3 closure verification and a generation-bound read-only
reopen, with all 93,697 original SSTs and their exact inventory digest preserved.
The controller checks this existing evidence; it does not repeat a broad
synthetic campaign or make another full clone.

### Isolated build and initial installation

From the reviewed repository root, use the same Go 1.24 toolchain as CI. The
following builds in a fresh private directory, verifies the downloaded module,
and adds the picker adapter only to a disposable Pebble v1.1.3 copy:

```bash
set -euo pipefail
umask 077
lab_build="$(mktemp -d /tmp/rhea-realstep-build.XXXXXX)"
cp -a cmd/pebble-format-v1 "$lab_build/command"
cd "$lab_build/command"
go version
go mod tidy
go mod download github.com/cockroachdb/pebble@v1.1.3
go mod verify
lab_pebble_source="$(go env GOMODCACHE)/github.com/cockroachdb/pebble@v1.1.3"
test -f "$lab_pebble_source/format_major_version.go"
cp -a "$lab_pebble_source" "$lab_build/pebble-v1.1.3"
chmod -R u+w "$lab_build/pebble-v1.1.3"
cp patches/demo_single_rewrite.go "$lab_build/pebble-v1.1.3/demo_single_rewrite.go"
gofmt -w "$lab_build/pebble-v1.1.3/demo_single_rewrite.go"
go mod edit -replace "github.com/cockroachdb/pebble=$lab_build/pebble-v1.1.3"
go mod tidy
go test -count=1 ./realstep ./reallab ./demo
go build -trimpath -o "$lab_build/realstep" ./realstep
go version -m "$lab_build/realstep"
sha256sum "$lab_build/realstep"
```

Retain the exact source revision, adapter digest, test output, toolchain version,
binary build information, and binary SHA-256 with the deployment receipt. The
new picker tests exercise the additive adapter through a small in-memory
database. These commands never invoke the fixed-host command against a database.

For the first installation, hold the existing
`/run/rhea-wasabi-lab/writer.lock` and require no running `realstep` process.
Atomically install the reviewed controller and verifier as root-owned mode-0600
files and the built `realstep` as a root-owned mode-0500 file in the fixed trusted
directory. Preserve the existing wrapper, decoder, certified seed, admission
journal, and cache. Install the mode-0600 pins file last, with the hashes of the
exact installed bytes; fsync the files and trusted directory before releasing
the lock. An existing `full-clone-steps/state.json` must already match those pins;
changing a bound deployment requires separate reviewed reconciliation.

Before the first controller dry run, the hostname's first label must be `rhea`
(case-insensitive), the lab reader must be inactive, and the full-clone writer
must be active through the existing guarded wrapper. Production Kubo and the
walker remain inactive and production rclone remains active. The controller
uses the same hostname rule as the wrapper. It creates its own state journal at
`full-clone-steps/state.json` only when a stage is applied; it does not treat the
reader-active/writer-inactive state as writable admission.

## Explicit commands

Each command defaults to a dry run. A dry run checks current host/queue/budget
state and opens the Go tool **read-only** to inspect or plan; it never runs a
writer or creates migration progress. Add `--apply` for the selected stage only.
Each mutation stage has its own closed process, snapshot, upload sequence,
independent remote certificate, and read-only reopen.

| Command | Required format | Result | SST writes |
| --- | --- | --- | --- |
| `ratchet6` | 003 | 006 | Forbidden |
| `ratchet7` | 006 | 007 | Forbidden |
| `ratchet10` | 007 | 010 | Forbidden |
| `ratchet13` | 010 | 013 | Forbidden |
| `step` | 013 | 013, one authoritative marked rewrite | At most one selected atomic unit |

For example, after the separately managed guarded mount is active:

```console
sudo python3 /root/.local/share/rhea-wasabi-lab-admin-20261101/run_rhea_full_clone_steps.py ratchet6
sudo python3 /root/.local/share/rhea-wasabi-lab-admin-20261101/run_rhea_full_clone_steps.py ratchet6 --apply
```

The controller does not loop into the next stage. A later stage is admitted only
after the preceding certificate is durable. After one successful `step`, a
second `step` is refused. There is no `finish`, `ratchet14`, or arbitrary action.
Formats 6, 7, and 10 require zero marked files before their operation. If format 6
discovers split-user-key work, format 7 remains blocked for deliberate review;
the controller does not enter its potentially blocking rewrite migration.

`status` reports the existing journal, current authenticated VFS observation,
and any budget-stop sentinel. The mount wrapper's own `status` remains the
independent lifecycle diagnostic if controller deployment inputs are unavailable.

## Independent limits

| Limit | Value and enforcement |
| --- | --- |
| Authoritative selected input | At most 256 MiB; Pebble's internal picker supplies the atomic unit, which is reselected and digest-checked under Pebble locks immediately before scheduling |
| Cumulative SST output writes | At most 512 MiB, enforced within the Go filesystem adapter |
| Cumulative metadata writes | At most 64 MiB, enforced separately within Go |
| Filesystem reserve | 2 TiB; new work additionally reserves 832 MiB for input, SST output, and metadata |
| Cache budget | 96 GiB in sampled authenticated telemetry; new work requires the same 832 MiB observed headroom |
| Pending upload bytes | At most 768 MiB |
| Pending upload files | At most 256 |
| New-stage backlog | Exactly zero queued, uploading, or errored files, with `outOfSpace=false` |

The controller requires explicit authenticated `diskCache.bytesUsed` telemetry;
an unavailable statistic is not interpreted as zero. It polls every Go child's
cache, queue, free space, and rclone PID every five seconds, including read-only
inspection and planning because those reads can populate the cache. On a bound or
health failure it durably requests an in-process stop through the fixed root-only
file `/run/rhea-wasabi-lab/full-clone-step-budget-stop`. The Go read/write guards
check that sentinel and return an error. The controller keeps waiting for the
child; it does not send a termination signal, force-kill, restart, or clear the
sentinel. Thus cache/backlog monitoring has a sampling interval, while the
separate Go output and free-space checks remain authoritative for individual I/O.
Failure to read or durably record a newly spawned writer's process identity also
requests the sentinel and waits for that same child; it cannot escape supervision
or cause a replacement writer to be launched.

Rclone's `diskCache.bytesUsed` is its cached used-range total, refreshed by its
cache cleaner. The admitted unit runs that cleaner every minute; polling RC
every five seconds does not make this cache counter synchronous. The cache gate
therefore has accounting lag as well as a polling interval. The Go write limits
and cache-filesystem free-space checks remain independent synchronous guards.
Format 10 reads table footers, metaindexes, and optional properties serially;
those sparse tail reads can fit the cache while remote request latency still
makes the stage long-running.

Any sentinel or unsuccessful writer result blocks new work and requires reviewed
reconciliation. An I/O stop can leave a partially advanced disposable generation;
the error must not be relabelled a completed checkpoint.

## Closed stages and publication

The controller holds the existing root-protected lifecycle `writer.lock` across
the stage. It validates the admitted mount, exact service/socket peer PID, absence
of competing realstep processes and open database users, and current queue health.
It durably records the intended action and prior checkpoint **before launching
the writer**. Expected format, marked count, inventory digest, and the selected
plan digest are passed to the fixed Go tool; no command text or extra arguments
come from the database.

A successful closed report must reconcile counts, byte totals, exact inventory,
created and retired file identities, marked-file reduction, and compaction events.
Preparatory stages must have no SST changes or compactions. A rewrite must have
exactly one successful rewrite event, and its retired SSTs must match the
authoritative selected input. An error, unrecognized state, budget violation,
or changed plan stops further work.

Every closed metadata file is copied to a root-owned, flat snapshot directory
with mode 0700 and mode-0600 files. The snapshot is atomically published and
checked against the live closed metadata again. Only newly created SSTs are
stream-hashed locally, within the output cap; their hashes are retained unchanged
for recovery. The entire original dataset is not downloaded.

The admitted mount retains its existing two-hour automatic writeback. Marker
deferral runs after the writer closes. A long open stage can therefore upload
intermediate markers or metadata, and this procedure certifies closed checkpoints
without claiming continuous consistency of the remote prefix. The independent
before-marker pass requires every changed final publication marker to remain
absent and fails closed if a final marker has already been uploaded.

After close, pending markers are deferred for 24 hours. The controller then
expedites and awaits exact queue entries in this order:

1. Created SSTs.
2. WALs.
3. OPTIONS.
4. MANIFESTs.
5. CURRENT.

Every expiry request rechecks the exact ID/name/size tuple, closed users, and the
same authenticated Unix-socket PID. No TCP RC endpoint, batch wildcard, arbitrary
duration, discard, or forced upload method is exposed.

The independent verifier then establishes the new closed generation before
publication. It preserves the exact original SST identities for untouched files,
retains historical pins for retired files, independently streams and hashes only
newly created SSTs, and validates current metadata and MANIFEST closure. The
prepublication proof and its canonical hash are journaled before any marker is
expedited.

Only the verifier's changed markers are published, in manifest-marker then
format-marker order. For a same-format rewrite, the old format-013 marker already
exists: the fresh MANIFEST marker is the publication barrier. Before every marker,
the exact preverified metadata and created-SST identities are re-HEADed. Each
published marker is independently read as a pinned empty S3 object. Final
verification then certifies the complete remote generation.

A fresh read-only Go `inspect` must match that certificate's format, marked count,
exact inventory digest, count, and bytes. The mounted metadata must still match
the closed snapshot already compared byte-for-byte with independent S3 reads.
The combined certificate describes this reopen as using the guarded lab mount;
it does not imply a fresh full-dataset download, complete block/pin reconciliation,
or production cutover.

## Journal and interrupted work

Persistent evidence is under `full-clone-steps/` in the trusted directory:

- `state.json`: bound checkpoint and any unfinished stage.
- `stages/000001-ratchet6/` and subsequent fixed stage directories: writer output,
  process receipt, closed snapshot, and created-SST hashes.
- `checkpoints/000001-ratchet6.json` and subsequent immutable certificates.

Journal files are written through private temporary files, fsynced, atomically
replaced, and followed by directory and parent-directory fsyncs. An existing
generation certificate is reused only if its stable identities match; it is not
overwritten with a conflicting result.

After interruption, use `recover-checkpoint` first without `--apply`. It refuses
a still-running writer, loads the existing closed success report, and performs a
read-only reopen against that report. Applying recovery resumes only snapshot,
upload, publication, and verification work. **It never repeats the writer.**
If publication was partially completed, it uses the durable prepublication proof
and fresh version checks to finish remaining markers, then performs full final
verification. It does not claim that unpublished markers are still absent.

Missing or invalid writer output, a mismatched reopen, a budget error, substituted
evidence, or unresolved host state remains blocked for reviewed recovery. Preserve
the exact cache/configuration and frozen production source. If reconstruction is
necessary, rebuild a consistent disposable generation from that source; do not
copy old files over an unreconciled mixed-format directory.

## Offline checks

```console
python3 -m unittest discover -s tests -p 'test_run_rhea_full_clone_steps.py' -v
python3 -m unittest discover -s tests
```

The focused tests cover stage ordering, durable intent and publication proof,
one total rewrite, exact plan/delta validation, independent budgets, no writer
replay after interruption, partial-publication recovery, and the actual process
monitor path requesting cooperative stop without signals or retry. They do not
claim that a live full-clone rewrite has happened.

The existing `standalone-format13.yml` workflow discovers the Python tests and
also builds a disposable patched Pebble v1.1.3 module, runs
`go test -count=1 ./realstep ./reallab ./demo`, and compiles `realstep`. Its pull
request paths cover the new controller, verifier, tests, and all command/adapter
sources. This adds focused command and adapter coverage to the existing job.
