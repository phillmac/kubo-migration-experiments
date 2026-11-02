# Rhea full-clone format-3 checkpoint — 3 November 2026

## Certified outcome

**The 7.082 TiB disposable full clone's Pebble format 001 → 003 metadata upgrade
is complete and independently certified. All 93,697 original SST versions
and their exact inventory are preserved. Ordered metadata publication, final
S3 closure verification, and a fresh read-only reader reopen passed. Production
remains frozen; no real SST rewrite or production cutover was performed.**

The combined certificate was created at **07:51:57.72 AEDT on 3 November
2026** (20:51:57.72 UTC on 2 November). An exact copy accompanies this report:
[rhea-full-clone-format3-certified-20261103.json](evidence/rhea-full-clone-format3-certified-20261103.json).
Its SHA-256 is
`a7438699846ca71af61ad7c7622f9807be2846273c75fd3559730a51988f1eaf`.

Production Wasabi Kubo and the broken-pin walker remain stopped. Production
rclone remains active with a clean upload queue. The unrelated `/data/ipfs`
Kubo instance and production cache were not changed.

This report distinguishes admission, mount operation, and checkpoint
certification. Successful admission proves the original clone matched the frozen
ledger at that point. A migration journal permits management of the intentionally
modified clone; it does not certify its new database generation. The format-3
checkpoint now has independent remote metadata and reference-closure
certification and a successful fresh read-only reopen of that exact generation.

## Code, deployment, and tests

Changes were published on the existing draft PR #3 branch
`experiment/standalone-pebble-format13-20261101`:

| Change | Published commit |
| --- | --- |
| Mutation-aware lifecycle journal and scoped queue-expiry control | `3d294519…` |
| Canonical exact SST inventory digest in the real-lab Go tool | `339d451…` |
| Independent format-3 checkpoint verifier | `cd053c5…` |
| Live remote-name compatibility and HTTP client fixes | `8bdfee2b1b3a57e79be294135cd483c12e394d8c` |
| Server-modtime optimization and clean-stop systemd compatibility | `dd11b9c0bb8205f0df7a6929758c3b3f508cfe2a` |

The recorded validation result is **175 Python tests and 3 focused Go tests
passing**. These results validate the code paths exercised by the tests; the
runtime observations below establish the separate live progress.
The tested deployed code commit is `dd11b9c0bb8205f0df7a6929758c3b3f508cfe2a`;
[CI run 41520122224](https://github.com/phillmac/kubo-migration-experiments/actions/runs/41520122224)
completed successfully.

Trusted deployed artifacts:

| Artifact | SHA-256 |
| --- | --- |
| Lab mount wrapper | `75c908c6ffb154264905f858f8b26e0fa7ab9fd22cd1dd75914918257ec5628d` |
| Independent checkpoint verifier | `edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b` |
| Real-lab format-3 binary | `a8498931cc20bcf7dcdfa90ee84a3dd8f3f4353097d06d05196ac4295988bab4` |
| Fresh reader inspector binary | `6c0f7cb23cb4f5dcf42898334c70df65574ab21769024091c5036123bbbb3bc8` |

The binary is installed at:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/reallab-format3-20261103
```

Session evidence is retained under:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/format3-20261103/
```

## Live admission and mount findings

The first full-clone preflight passed in **155.7717 seconds**. The writable
service then became active with PID **2713456**, but its initial wrapper call
timed out after **419.61 seconds**. The service was already running: rclone's
valid decorated remote suffix `{Dn7qA}` did not match the wrapper's assumed
underscore-prefixed decoration.

A subsequent read-only RC probe also exposed a local `http` name shadowing
the HTTP client module. Both defects were corrected under the lifecycle lock.
The rendered service unit, running PID, and admission journal were preserved;
this was not a second mount launch. Exact bucket and prefix identity checks
remain in place.

After those corrections, live `status` returned **zero queued uploads, zero
uploads in progress, and zero errors**. The lifecycle fix allows status and
clean shutdown after intentional object-version or obsolete-file changes while
retaining the protected service, socket, cache, and queue checks.

### Read-only opening cost and controlled metadata adjustment

The initial read-only plan was cancelled after **370.4995 seconds**, before
any ratchet, by sending SIGTERM to its verified plan PID only. A five-second
trace observed **292 stat calls**, costing roughly **14–20 milliseconds per
SST**. Extrapolating that cost over the full inventory suggested approximately
**25 minutes per open**; this was a performance estimate, not a database error.

The only rclone option added to the full-clone unit was
`--use-server-modtime`. Independent object-version, inventory, and checkpoint
consistency checks remain required. The adjustment was performed while stopped
under the old lifecycle lock, preserving the persistent cache, backups, original
ledger, and admission values except the recorded unit digest. All three cached
metadata files explicitly reported `Dirty:false`.

The journal's unit SHA-256 changed from `7bcfc9…` to
`edaecb5c5a6db1254151b252ed9a9b11c982979e769da0f5ea92be0fffeac112`.
The root-owned transition receipt `metadata-tune-completed.json` records
`post_guard_passed: true`.

During the controlled stop, RC shutdown actually completed cleanly, but the
wrapper initially misreported it because systemd cleared `ExecMainCode` to
`0`. The observed tuple was `Result=success`, `ExecMainStatus=0`,
`ActiveState=inactive`, `SubState=dead`, and `MainPID=0`, with both mount and
socket absent. The service journal recorded “Deactivated successfully” at
**20:28 UTC on 2 November / 07:28 AEDT on 3 November**. The wrapper now accepts
this narrowly defined successful state, using one coherent service-state
observation and the subsequent mount/socket checks.

The tuned restart passed in **6.51 seconds**, with PID **2715973**, the same
cache path and `{Dn7qA}` remote decoration, **zero queued uploads, zero uploads
in progress, and zero errors**. The subsequent plan and local metadata ratchet
completed as recorded below.

## Independently verified starting inventory

Direct S3 metadata retrieval and MANIFEST decoding verified the original
full-clone checkpoint:

| Evidence | Result |
| --- | --- |
| Manifest-referenced SST count | 93,697 |
| Referenced SST bytes | 7,786,594,080,785 |
| Immutable baseline ledger SHA-256 | `38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96` |
| Exact inventory SHA-256 | `57b04d9508272a17df72aea1a6675fff1e13944ae83c884f988668b7f77cd134` |
| Original MANIFEST SHA-256 | `f563cc9c81da4e661562d131c01f12abb4bf84a15a8f9f604cbb1f551ddc86a6` |

The inventory digest hashes decimal file number, a tab, decimal size, and a
newline for every referenced SST, ordered by numeric file number. This detects
same-count, same-total-byte substitutions that aggregate counters alone miss.

The independent S3 verifier downloaded **zero SST payload bytes**. It compares the
exact referenced inventory and original latest SST versions against the frozen
ledger, independently reads and hashes changed metadata, and verifies the closed
MANIFEST and marker relationship. This certifies closed metadata, complete SST
references, and continuity of the original SST object versions. It does not
constitute a fresh byte-by-byte validation of all SST contents or full block/pin
reconciliation. No real SST rewrite is claimed.

## Local format-3 stage completed

The tuned read-only plan completed in **73.1386 seconds** including the
directory gate; Pebble reported **5.650177 seconds**. It confirmed format
`001`, zero marked files, the original count and byte sum, and the exact
baseline inventory digest. The upload queue was clean.

At **20:36 UTC on 2 November / 07:36 AEDT on 3 November**, the actual
`ratchet3` operation succeeded: **8.61999 seconds** overall and **8.57006
seconds** reported by the Go tool. Format changed from `001` to `003` with
all **93,697 SSTs / 7,786,594,080,785 bytes**, their canonical inventory digest,
and zero marked files preserved. An immediate read-only Go `inspect` passed
in **5.118816 seconds**, confirming format `003` and the same inventory.
This inspection used the writable mount's cache; the separate fresh reader
reopen is recorded below.

The closed metadata snapshot contains:

| File or marker | Size / relationship |
| --- | --- |
| `47475290.log` | 11 bytes |
| `OPTIONS-47475292` | 1,170 bytes |
| `MANIFEST-47475291` | 15,498,275 bytes |
| `CURRENT` | 16 bytes |
| `marker.manifest.000001.MANIFEST-47475291` | Selects the new closed MANIFEST |
| `marker.format-version.000002.003` | Final format-3 publication marker |

The snapshot decoder confirmed the exact original SST inventory. It decoded
two MANIFEST records containing 93,697 SST additions and zero SST deletions;
these are entries in the complete snapshot. The minimum WAL number is
`47475290`, and the last sequence number is `46560704`.

There were **six metadata uploads and no SST uploads**. The two markers were
deferred for 24 hours. The controller then flushed and awaited the four data
objects in order: **WAL → OPTIONS → MANIFEST → CURRENT**. All four settled;
only the two deferred markers remained queued, with zero upload errors.

Independent S3 verification **before marker publication passed with exit 0**
in **188.920486 seconds**. It confirmed the same **93,697 original SST
versions / 7,786,594,080,785 bytes** and the closed data/metadata checkpoint.
The new `MANIFEST-47475291` SHA-256 is:

```text
fabc71207f6e456eab9a4ccda56ceb0e8294e05484503ae5d7606db9ff1f2026
```

The two markers were still deferred when this check completed. They were then
published and independently verified in dependency order:

| Marker | Verified VersionId | Verification time (Unix seconds) |
| --- | --- | --- |
| `marker.manifest.000001.MANIFEST-47475291` | `001793652345188159841-eJzLMuUgM0` | `1793652346.2158177` |
| `marker.format-version.000002.003` | `001793652349827504452-ekrLRtagHt` | `1793652350.9565465` |

Both markers are zero-byte objects with SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Fresh metadata HEAD checks matched the pre-marker report before each marker
and after the final marker. `marker-publication-completed.json` records
completion at Unix time `1793652351.239049`, approximately **20:45:51 UTC on
2 November / 07:45:51 AEDT on 3 November**.

After publication, the VFS observations were **zero queued uploads, zero uploads
in progress, zero errors, and `outOfSpace=false`**; cache bytes were
**31,129,730**. The final independent verifier started at approximately
20:46 UTC / 07:46 AEDT and **passed with exit 0 in 188.519010387 seconds**.
It completed at Unix time `1793652553.590613`, **20:49:13.59 UTC on 2 November /
07:49:13.59 AEDT on 3 November**.

The S3-only report records `remote_format3_closure_verified=true` and
`pebble_reopen_verified=false`, because that verifier does not perform the
separate Pebble reopen. The subsequent combined certificate includes the reader
evidence and correctly records both flags as `true`. The S3 verifier checked
all **93,697 unchanged SST versions**, the
same total bytes and canonical inventory digest, and **eight metadata files'
SHA-256 values, latest VersionIds, and ETags**. Four latest delete markers were
present, all for obsolete metadata. **SST payload bytes downloaded: 0.**

### Writer shutdown and fresh reader reopen

The writable mount stopped cleanly in **7.250003 seconds**, with receipt time
`1793652587.9022405`. The observed service tuple was `inactive/dead`, PID `0`,
`Result=success`, `ExecMainCode=0`, and `ExecMainStatus=0`; its mount and socket
were absent. The persistent cache was retained.

The original reader unit was restored with its exact original arguments and
PID **2717693**, at Unix time `1793652616.3644624`. Its source is:

```text
rhea_pebble_lab_reader{_9Ic9}:rhea-pebble-lab-20261101-39037c6f01/rhea
```

An initial confirmation assertion expected the undecorated remote name. The
existing mount was reconciled against the valid suffix and exact process
arguments, executable, root identity, cgroup, bucket, and prefix. No duplicate
reader launch occurred.

The fresh reader verification **passed with exit 0** at Unix time
`1793652693.2802837`, **20:51:33.28 UTC on 2 November / 07:51:33.28 AEDT on
3 November**. Before and after the Go open, all **eight metadata filenames,
sizes, and SHA-256 values** exactly matched the final independent S3 report.
The reader also observed **93,697 SST filenames**. Matching MANIFEST bytes bind
this reopen to the exact inventory already certified through S3.

The Go report used `ReadOnly=true`, scope `lab-reader-only`, format `003`,
zero marked files, **93,697 SSTs / 7,786,594,080,785 bytes**, and WAL replay of
zero keys and zero batches. Go elapsed time was **4.552969326 seconds**
(**4.58433865 seconds** for its process); generation checks and the process
together took **72.32 seconds**.

The reader's maximum estimated atomic input remained **134,491,640 bytes**,
with zero multi-file units and no estimated units above 256 MiB. This is a
preflight estimate; the actual Pebble picker remains authoritative for later
rewrites.

Reader receipts:

- `reader-generation-before-open.json`
- `fresh-reader-reopen.json`
- `reader-generation-after-open.json`

### Final operational state and combined certificate

The final operational recheck passed, and
`full-clone-format3-certified.json` was created in the root evidence directory
at Unix time `1793652717.7245631`. Its exact copy is linked at the beginning of
this report. The combined flags are all true:

- `remote_format3_closure_verified`
- `pebble_reopen_verified`
- `reader_generation_bound_to_s3_metadata`
- `writer_stopped`, `writer_mount_absent`, and `writer_socket_absent`

The final service observations were:

| Component | Verified final state |
| --- | --- |
| Production Wasabi Kubo | Inactive / unit not found; hidden-writer check passed |
| Broken-pin walker | Loaded, inactive, disabled |
| Production rclone | Active, same PID **2554927**; zero queued/uploading/errored files, `outOfSpace=false`, cache bytes `0` |
| Disposable writable lab mount | Cleanly stopped; service PID 0, mount and socket absent; cache retained |
| Original lab reader | Active, PID **2717693** |
| Unrelated `/data/ipfs` Kubo | Active, PID **549370**, left untouched |

The `final-operational-state.json` receipt has SHA-256
`de4bc2cc11d5ba4571c47914e9235c3df4dc73c75a0e61f25b1836787d75bfee`.
The combined certificate also binds the preceding stage receipts by SHA-256.

## Accepted recovery model

The existing 7.082 TiB disposable clone is the experimental target. Production
remains frozen as the restoration source. Temporary remote inconsistency during
the experiment is accepted: obsolete-object deletions can become visible before
replacement files leave the VFS upload queue.

If interrupted, first recover pending uploads with the same persistent cache
and configuration. If that cannot produce a consistent checkpoint, reconstruct
a consistent generation from the frozen source and retry. Lost experimental
progress and restoration time are acceptable; mutation of the original archive
is not. Another full clone or broad synthetic campaign is not a routine
prerequisite.

## Final format-3 checkpoint — all milestone gates passed

**The local metadata stage, independent pre-marker S3 verification, and ordered
marker publication passed. Final independent remote closure certification also
passed, followed by a successful fresh read-only reader reopen, final operational
recheck, and combined certificate.**

| Gate | Recorded outcome |
| --- | --- |
| Read-only `plan`: format 001, zero marked files, exact baseline digest | Passed; tuned Pebble operation 5.650177 seconds |
| Closed `ratchet3`: format 001 → 003 | Passed at 07:36 AEDT; Go operation 8.57006 seconds |
| Before/after SST inventory and digest equal frozen baseline | Passed; 93,697 SSTs, 7,786,594,080,785 bytes, exact digest unchanged |
| Immediate read-only inspection through current mount | Passed; format 003, unchanged inventory, 5.118816 seconds |
| Closed data/metadata uploads verified before marker publication | Passed; independent S3 verifier exit 0 in 188.920486 seconds, all original SST versions preserved |
| Manifest marker and final format marker publication verified | Passed in dependency order; completion receipt at 07:45:51 AEDT |
| Independent S3 checkpoint verification and metadata hashes | Passed at 07:49:13.59 AEDT; exit 0 in 188.519010387 seconds, eight metadata files checked, all original SST versions preserved, zero SST payload bytes downloaded |
| Queue/upload/error/out-of-space observations after publication | Passed: 0 queued, 0 uploading, 0 errors, `outOfSpace=false`; cache 31,129,730 bytes |
| Fresh reader metadata hashes and read-only reopen at format 003 | Passed at 07:51:33.28 AEDT; eight exact metadata files checked before/after open, format 003, original count/bytes, zero marked files |
| Final lab mount/service state and evidence filenames | Writer cleanly stopped; original reader restored as PID 2717693; three reader receipts recorded above |
| Final production-state recheck | Passed; production frozen, rclone active at the original PID and clean, unrelated Kubo untouched |
| Combined checkpoint receipt | Passed; `full-clone-format3-certified.json`, created at 07:51:57.72 AEDT; exact copy and SHA-256 linked above |

The format-3 milestone is complete. The next development step is to adapt the
real-data controller for the remaining preliminary format stages and one
authoritative, bounded real SST rewrite, initially capped at
**256 MiB input**, with separate output, cache, free-space, and upload-backlog
controls. The existing scratch-specific stepper must not be pointed at this
full clone. Neither production Kubo restart nor production cutover follows
automatically from format-3 success.
