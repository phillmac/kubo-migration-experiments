# Rhea full-clone one-rewrite milestone — 3 November 2026

## Outcome — certified and finalized

**One bounded real SST rewrite is certified on the disposable full clone.** The
clone reached format **013**, replaced one L6 SST, and reduced the marked count
from **93,695 to 93,694**. Independent S3 verification, a fresh stage reopen, the
restored reader's reopen, and final operational checks all passed. The writer is
stopped; its mount and socket are absent; its cache and evidence are retained.
Production Wasabi Kubo and the walker remain inactive, and the existing
production rclone process remains unchanged and clean.

The first attempt failed before any SST write. Its metadata changes were
separately certified, its original evidence was archived, and a corrected binary
was installed before a new explicit apply. The result is **two attempts, one
certified rewrite**. This is not a completed migration, format-14 transition, or
production cutover. **93,694 files remain marked.**

The [combined milestone certificate][combined] records the final observation at
**13:51:13.175 AEDT**, Unix `1793674273.175206`. Its exact file SHA-256 is
`931c5ec9eabc6de4ad13d5e807e842b5d667cd27117d84ea3b6d59e14a350c0d`.
It was exported at **13:51:37.987 AEDT**. All times in this report are **AEDT
(UTC+11), 3 November 2026**, unless stated otherwise.

## Certified stages

The starting [format-003 checkpoint][seed-report] contained **93,697 SSTs,
7,786,594,080,785 bytes**, with inventory digest
`57b04d9508272a17df72aea1a6675fff1e13944ae83c884f988668b7f77cd134`.
Every stage below passed successful local close, independent remote
certification, and a fresh read-only Pebble reopen bound to that generation.
The full duration includes publication, verification, and reopening; the Go
column measures the database operation alone. [Combined evidence][combined]

| Generation / action | Format | Marks before→after | Go / full stage, seconds | Certified at |
| --- | --- | --- | --- | --- |
| [1 / ratchet6][cert6] | 003→006 | 0→0 | 10.703227156 / 411.886568546 | 12:14:33.867 |
| [2 / ratchet7][cert7] | 006→007 | 0→0 | 10.677513322 / 359.712463140 | 12:33:44.568 |
| [3 / ratchet10][cert10] | 007→010 | 0→93,695 | 146.973143546 / 491.276100397 | 13:04:35.176 |
| [4 / ratchet13][cert13] | 010→013 | 93,695→93,695 | 16.022417573 / 429.206413984 | 13:12:32.932 |
| [5 / explicit step retry][cert-step] | 013→013 | 93,695→93,694 | 17.11223705 / 404.550872326 | 13:48:55.647 |

The four preliminary stages wrote **zero SST bytes** and preserved the exact
baseline SST inventory. Their cumulative metadata write counts were
15,499,456; 15,499,456; 31,278,874; and 15,780,604 bytes respectively. Between
generations 4 and 5, the separately certified [failed-close bridge][bridge-certificate]
retained generation **4** and **zero successful rewrites**; it did not turn the
unsuccessful first writer into a successful stage.

## The single rewritten SST and independent proof

The authoritative picker selected one complete atomic input unit below the
256 MiB cap. The writer reselected it under Pebble's locks and matched the
expected plan before scheduling exactly one rewrite. [Writer report][step-writer]

| Result | Exact value |
| --- | --- |
| Input retired from MANIFEST | `46893047.sst`, L6, **67,057,322 bytes** |
| Output added to MANIFEST | `47475312.sst`, L6, **67,057,185 bytes** |
| SST delta | One retired, one created; **137 bytes smaller** |
| Referenced SST count / bytes | **93,697 / 7,786,594,080,648** |
| Compaction | One begin/end pair, job **2**, reason **rewrite**, no error; **1.557 s** |
| Stage read-only reopen | **6.95119203 s**, zero writes, matching state and inventory |
| Untouched original SSTs | **93,696** latest object identities and sizes unchanged |
| Final verification pass | **0 original SST payload bytes**, **67,057,185 new-output bytes** downloaded |

The final exact inventory digest is
`6c4125a75d05755dc4ca8666c50e7ddc8cbdaf3ebdccd7dbd23fc4e9baf45fa2`.
The candidate digest is
`7169413d3752f398f4f2fd4d3532e5657c96ec00c7c9a48cd52f8c41f4daf076`;
its before-state-bound plan digest is
`285edd29278c9fb8ff3a4cfd38b8429210167f7eedb81f12eb6f5bddd9dd1a2c`.
Both match the plan retained from the failed attempt. [Generation-5 certificate][cert-step]

The new SST's closed local SHA-256 matched independently streamed S3 bytes:
`0b0522cea2620a941860a1c60cda7a433cd7edef837223aa2666034a6e91e4b9`.
Its latest VersionId is `001793673773073984245-QRDVBWEFDq`, with ETag
`69cf7591289d496257daee0bf7bf01fe`. The retired input's baseline VersionId remains
recorded as `001793505429148961727-LFMLX5fft_`; its final latest state is the
delete marker `001793673760301871939-WzgQ_GNhZF`. These are distinct checks of
new content, retained lineage, and retirement state. [Generation-5 certificate][cert-step]

The final current MANIFEST is `MANIFEST-47475310`, SHA-256
`e5abd5a5855d01693bb443a9b75cdc1d64f7b00253125559d7801029d715e8b1`.
Its publication barrier is `marker.manifest.000008.MANIFEST-47475310`; the
format marker remains `marker.format-version.000012.013`. Independent decoding
found three records, 93,698 additions, one deletion, 93,694 marked files, and
last sequence **46,560,704**. All eight closed metadata files were bound to
latest remote identities and byte hashes. [Generation-5 certificate][cert-step]

| Writer I/O scope | SST writes | Metadata writes |
| --- | ---: | ---: |
| Successful rewrite process | 67,057,185 | 15,780,800 |
| Five successful stage writers | 67,057,185 | 93,839,190 |
| All six writers, including failed attempt | 67,057,185 | 109,619,794 |

These counters measure filesystem writes, not remote transfer traffic. The
input was read after tail warmup, and the failed attempt may have prefetched it.
The **1.557 s** compaction therefore does not measure cold S3 throughput.
Verification download counters describe the **final pass**, not aggregate
traffic across prepublication, recovery, and final passes. [Combined evidence][combined]

## Controls and verification scope

The [controller][controller] runs one explicitly selected action per invocation.
Every mutation binds its expected format, marked count, and inventory digest.
The [Go command][go-command] uses an additive adapter in an isolated copy of
**Pebble v1.1.3**; reviewed core source files matched Rhea's cached module
byte-for-byte. The original module and production Kubo/Pebble implementation
were preserved. Automatic compactions and background table-stat scans are
disabled, and competing compaction/flush work is refused. The controller permits
one successful rewrite. [Adapter][adapter] [Controller design][design]

| Resource | Enforcement |
| --- | --- |
| Selected physical SST input | **256 MiB**, authoritative atomic input set |
| Cumulative SST writes | **512 MiB**, checked before Go writes |
| Cumulative metadata writes | **64 MiB**, checked independently before writes |
| Free cache-filesystem space | **2 TiB** floor during I/O; admission reserves **832 MiB** |
| Cache allowance | **96 GiB** in authenticated sampled telemetry, with admission headroom |
| Upload backlog | At most **768 MiB / 256 files** |
| New-stage queue | Zero queued/uploading/errors; `outOfSpace=false` |

The controller monitors read-only and writable children every five seconds.
A budget or health failure requests cooperative stop through a fixed root-only
sentinel, then waits for that same process. It never kills or automatically
replays the writer. Rclone's cache counter has one-minute cleaner lag; synchronous
Go write caps and free-space checks provide separate bounds. [Budget guard][budget]

The [independent verifier][verifier] reconciles MANIFEST membership, per-file
marks, plan, compaction events, and SST delta. Untouched originals are checked
by latest VersionId/ETag/size without downloading their payloads again. New
SSTs are independently streamed and hashed. Closed metadata receives byte-hash
and latest-identity checks. A successful reopen proves the certified generation
opens; it does not revalidate every original SST payload, block, or pin.

Publication uses exact closed snapshots and queue identities: new SSTs, WALs,
OPTIONS, MANIFESTs, and CURRENT first; independent prepublication proof next;
then the new MANIFEST marker and any changed format marker, with fresh checks
before publication. Final S3 verification and the fresh read-only reopen follow.
The admitted two-hour writeback can expose intermediate metadata during a long
open stage. This disposable-clone procedure certifies **closed checkpoints**;
it does not claim continuous crash-safe object-prefix consistency. [Controller design][design]

## Directory-cache repair and measured warmup

Two cold directory listings interrupted read-only admission checks before any
writer launch. The first preserved all eight seed metadata files and retried
successfully in **9.5169 s**. The first format-007 apply then stopped during its
read-only precheck after **55.26813 s**, leaving certified format 006 intact.

A clean **9.40780 s** stop enabled a protected transition adding only
`--dir-cache-time 12h` to the full-clone unit. It preserved checkpoint/history,
journal progress, cache, configuration, rclone, ledger, verifiers, and Go binary.
Consistency checks and two-hour writeback remained unchanged. Restart passed in
**6.57203 s**, PID **2733239**, with the same cache/config; the first enumeration
took **57.59675 s** and checked the eight exact format-006 metadata files. The
tuned format-007 dry run passed in **9.58605 s**. The helper update included the
reviewed quiescent-window monitoring fix. [Lifecycle configuration][mount-doc]
[Transition evidence][combined]

Format 10 examines table formats serially through footers, metaindex, and
optional properties. Ordinary data/index/filter blocks are not required merely
to obtain a format. Rclone begins its range at the requested offset; its 128 MiB
chunk default does not force a backward 128 MiB read at EOF. Clean SST caches can
remain sparse. [Pebble migration][upstream-formats] [Reader][upstream-reader]
[Rclone range reader][rclone-ranges]

After a successful 128-file pilot, the [warmup helper][warmup] read the final
`min(64 KiB, file size)` through the fixed FUSE mount with eight workers and
bounded quiescent observation windows. The full helper ran from
**12:35:38.793 to 12:55:33.404**; the outer invocation returned at
**12:55:33.632**. [Warmup receipts and metrics][combined]

| Full warmup measurement | Result |
| --- | --- |
| Completed files / failures | **93,697 / 0** |
| Logical tail bytes returned | **6,134,213,797** |
| Helper / outer elapsed | **1,194.611546 / 1,194.977908 s** |
| Read phase / longest single read | **1,166.547239 / 3.339648 s** |
| Maximum pending reads / window | **8 / 128 files, 8 MiB** |
| Authenticated samples / windows | **737 / 733** |
| Largest health gap / drain | **4.233968 / 2.815552 s** |
| Reported cache bytes, before→after/max | **39,594,335 → 6,260,726,785** |
| Free bytes, before→after/minimum | **7,283,403,218,944 → 7,276,505,800,704** |

There were **1,483 free-space checks**, including health observations and
additional local checks on a one-second schedule. Cache figures
retain accounting lag. Logical tail bytes exclude prefetch and other
filesystem/network traffic and do not constitute complete SST content
validation. The pilot covered **128 files / 8,324,097 bytes** and took
**26.723242 s** including inspection and health checks. The combined certificate
pins both original warmup receipts; full-run SHA-256 is
`addfa336588980a9c97fa1eb789dabbc1cde5cbd0303c3b9d98ddef41bb27b4e`.

## Failed attempt, precise fix, and preserved recovery

The [first writer][failed-writer] failed while preparing output `47475309.sst`:

```text
creating object 47475309: stat /mnt/rhea-pebble-lab-writable-20261102/pebbleds/47475309.sst: no such file or directory
```

Its Go operation took **16.148672929 s**; the failed compaction lasted **136 ms**.
It wrote **0 SST bytes** and **15,780,604 metadata bytes**, with an empty SST delta
and unchanged 93,695 marks. The outer call exited **1** after **28.242384195 s**,
at **13:14:08.639**. Its original timing/report/exit/state remained separate from
the retry's evidence. Zero SST writes did not imply zero metadata changes.

The guard used `os.IsNotExist` on Pebble's stack-wrapped normal missing-file
error, so it refused the expected absent output before calling `Create`. This
was a default disk-VFS error-classification bug, not a FUSE visibility assumption.
The minimal correction uses `errors.Is(err, os.ErrNotExist)`, preserving
existing-SST refusal and rejection of genuine permission/I/O failures.
[Pebble VFS][upstream-vfs] [Object creation][upstream-object-create]
[Go error classification][go-os-errors]

The [strict failed-close verifier][failed-verifier] established identical
MANIFEST per-file numbers, sizes, levels, marks, and sequence state; unchanged
**latest VersionIds and sizes for all original SSTs**; and absence of failed
output `47475309.sst` across **all versions and delete markers**. It verified the
closed metadata. The recovery driver published the new MANIFEST marker after
that proof and performed a fresh read-only reopen with the old binary. No SST
payloads were downloaded.

The [bridge certificate][bridge-certificate] completed at **13:39:28.755**, after
**376.438631058 s** overall; its read-only reopen took **7.250991791 s**. The
[recovery driver][failed-driver] archived the exact original stage under
`failed-attempts/000005-step-01` and changed only checkpoint and outstanding-stage
fields. The journal remained **generation 4 / rewrites 0 / pending null**; its
nested bridge and completion receipt record **one failed attempt** and explicitly
state that no writer retry was performed. The bridge SHA-256 is
`066cd75f6af19b51bbbbd647589203b26e9fb03e41b240b878401c405451152d`.

A separate binary deployment then passed in **19.260229 s**, at
**13:40:40.886**. It retained the old executable, preserved metadata/admission,
and changed only the Go pin in the controller binding. Post-deployment read-only
inspection passed in **7.366512277 s**, with zero write I/O and unchanged SST
state. The corrected binary SHA-256 is
`1bc58ef8ca76a97fc9886d90f4a3df4fdd3d07549403988e3798834a61207125`.
Only then was a new apply explicitly invoked. The successful generation-5
certificate's parent is the failed-close bridge, preserving the entire chain.
[Deployment and ancestry proof][combined]

## Final reader and operational state — all gates passed

Finalization completed at **13:50:52.725**, taking **85.188949 s**. A separately
authenticated production RC observation followed at **13:51:13.175**. These are
operational proofs after the generation-5 certificate, rather than assumptions
from a successful database close. [Combined evidence][combined]

| Final gate | Verified result |
| --- | --- |
| Lab writer | `inactive/dead`, PID **0**, result **success**; mount and socket absent |
| Recovery material | Writer cache, failed attempt, checkpoint, and protected state retained |
| Restored reader | Original reader arguments restored; PID **2744687** |
| Reader generation | All eight metadata filenames/sizes/SHA-256 values matched S3 before and after the read-only open |
| Reader reopen | Passed in **4.70204749 s**, matching format **013**, **93,694 marks**, and final inventory state |
| Production Wasabi Kubo / walker | Both inactive; walker **disabled** |
| Production service leader | Original PID **2554927**, executable **`/usr/bin/bash`**, unchanged |
| Actual production RC server | Original PID **2554974**, executable **`/usr/bin/rclone`**, unchanged and bound to its listener |
| Authenticated production RC | **0 queued, 0 uploading, 0 errors, 0 cache bytes; `outOfSpace=false`** |

The service leader and RC server are distinct processes. The authenticated server
retains start ticks `6346700274` in the existing Docker scope and owns the
verified loopback listener. The final RC receipt has SHA-256
`271a00b750c08fdfc7954fffb759236417841c02e1bbbc886ae2305aa13f525c`;
finalization completion is
`b874f6887e59ce478c73961390733b5651062a47f7b8fdbfb3ee9661bd0f43eb`.
The unrelated `/data/ipfs` instance was outside this work; these receipts do not
certify its current process identity. [Combined evidence][combined]

## Validation and source provenance

Initial validation passed **228 Python tests and 13 Go tests**. The new
[disk-backed regression][budget-tests] reproduced the exact missing-file failure
against the old guard; with the correction, **all 15 focused Go tests passed**.
It also checks collision refusal without changing existing contents, cumulative
write limits, and rejection of a wrapped permission error before `Create`.
The recovery helpers and existing Python suite passed **250 tests**, including
six driver and 16 strict-verifier tests. The initial regression harness's
`noexec` temporary mount prevented test startup; its retained logs were not
counted as a regression result.

The successful isolated build used **Go 1.25.14**, networking disabled, and a
read-only module cache, with Docker image
`sha256:07d6e65bb14b257e518eb70088f0c6826c86ff6185538bdb946bcda8e211d03b`.
The red/green build receipt is bound by the combined evidence as
`realstep-20261103/enoent-fix-build-v2/report.json`, SHA-256
`66c7ade3bc91933f441fcb5135c289b02e68e8abc401f51c3d07496350a6b6b3`.
The [workflow][workflow] verifies the module, tests `realstep`, `reallab`, and
`demo`, and builds the command. The [integration fixture][fixture] exercises
preliminary opens, authoritative planning, stale-plan/input refusals, one
rewrite, and durable progress after reopening.

| Published source change | Commit | CI |
| --- | --- | --- |
| Lifecycle/cache transition | `46cd7fdccfded4786fa32edebe6ec8c2e9f2456d` | [41559526935 — passed][ci-cache] |
| Wrapped-error correction | `b37bb0410b41646b881ef617a35c03a10b9be419` | [41565828099 — passed][ci-fix] |
| Failed-close recovery helpers | `5ca4d6721696252ff0c6a4d1a1f9a9d4292225ea` | [41566603251 — passed][ci-recovery] |

Initial implementation [CI 41556660320][ci-initial] also passed. The source head
for this evidence is `5ca4d6721696252ff0c6a4d1a1f9a9d4292225ea`; no later
artifact-publication commit is implied. Exact controller, wrapper, verifier,
recovery, binary, finalizer, reader-inspector, and exporter hashes are recorded
in the combined certificate.

## Evidence and practical limits

The [combined certificate][combined] binds **75 retained evidence references**,
including source pins, all five stage certificates/writers, warmups, failed
attempt, bridge, binary transition, final reader, and production observations.
Its exporter validates retained files without making new host or cloud queries.
The exact small certificates and writer reports are included alongside it:

| Evidence | Exact file SHA-256 |
| --- | --- |
| [Format 006][cert6] | `4ae193b3c8d88b3be8405c90b1beb1a70aba41c3057c9127dd40f254d19ce809` |
| [Format 007][cert7] | `65d72c8c2c30f644613d39d193a285b2a7007f914ed05cca1262705cb5b53d46` |
| [Format 010][cert10] | `d0febdcfc77d8ec92456ca429e1768e67677b12ca91bfb0db49447622b5dab00` |
| [Format 013][cert13] | `62a288014d932a0272a0083e6ccf02ab640f2d6cca2822d661987b03b1c03ad5` |
| [Failed writer][failed-writer] | `2f1f914dad3679f43c101084d2037eb6209d9a571168d529477be144ef5492a1` |
| [Failed-close bridge][bridge-certificate] | `066cd75f6af19b51bbbbd647589203b26e9fb03e41b240b878401c405451152d` |
| [Successful writer][step-writer] | `b4c734c6480d64916cfea73dfd24f14ea20fba8a8a84926faae2bef6927ea0b1` |
| [Generation 5][cert-step] | `53295fea8edf8abb35c89b9eefa864bc8b044f5ede6eeabfcba5ca3ee540925b` |

The [format-003 seed certificate][seed-certificate] remains pinned at
`a7438699846ca71af61ad7c7622f9807be2846273c75fd3559730a51988f1eaf`;
the immutable baseline ledger SHA-256 is
`38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96`.
No credentials, raw stderr logs, complete SST inventories, or MANIFEST/SST
payloads are exported in this evidence set.

The milestone establishes one bounded, remotely certified rewrite and safe
operational closure on the disposable clone. It leaves **93,694 marked files**.
The next development step is a deliberate pacing decision for further bounded
units, retaining the initial **256 MiB input cap** and separate output,
metadata, free-space, cache, and backlog controls. The existing scratch stepper
must not be pointed at this full clone. The present controller refuses a second
successful rewrite. Completing the remaining migration and proving production
cutover readiness are separate milestones; neither follows from this result.

[seed-report]: rhea-full-clone-format3-20261103.md
[seed-certificate]: evidence/rhea-full-clone-format3-certified-20261103.json
[combined]: evidence/rhea-full-clone-one-rewrite-certified-20261103.json
[cert6]: evidence/rhea-full-clone-000001-ratchet6-20261103.json
[cert7]: evidence/rhea-full-clone-000002-ratchet7-20261103.json
[cert10]: evidence/rhea-full-clone-000003-ratchet10-20261103.json
[cert13]: evidence/rhea-full-clone-000004-ratchet13-20261103.json
[cert-step]: evidence/rhea-full-clone-000005-step-20261103.json
[step-writer]: evidence/rhea-full-clone-one-rewrite-writer-20261103.json
[bridge-certificate]: evidence/rhea-full-clone-failed-close-certified-20261103.json
[failed-writer]: evidence/rhea-full-clone-failed-step-writer-20261103.json
[design]: rhea-full-clone-stage-controller.md
[mount-doc]: rhea_wasabi_lab_mount.md
[controller]: ../scripts/run_rhea_full_clone_steps.py
[verifier]: ../scripts/verify_rhea_full_clone.py
[warmup]: ../scripts/warm_rhea_full_clone_tails.py
[go-command]: ../cmd/pebble-format-v1/realstep/main.go
[budget]: ../cmd/pebble-format-v1/realstep/budget.go
[adapter]: ../cmd/pebble-format-v1/patches/demo_single_rewrite.go
[fixture]: ../cmd/pebble-format-v1/realstep/picker_test.go
[budget-tests]: ../cmd/pebble-format-v1/realstep/budget_test.go
[failed-driver]: ../scripts/reconcile_rhea_failed_step.py
[failed-verifier]: ../scripts/verify_rhea_failed_step_close.py
[fix-commit]: https://github.com/phillmac/kubo-migration-experiments/commit/b37bb0410b41646b881ef617a35c03a10b9be419
[recovery-commit]: https://github.com/phillmac/kubo-migration-experiments/commit/5ca4d6721696252ff0c6a4d1a1f9a9d4292225ea
[workflow]: ../.github/workflows/standalone-format13.yml
[ci-initial]: https://github.com/phillmac/kubo-migration-experiments/actions/runs/41556660320
[ci-cache]: https://github.com/phillmac/kubo-migration-experiments/actions/runs/41559526935
[upstream-formats]: https://github.com/cockroachdb/pebble/blob/v1.1.3/format_major_version.go
[upstream-reader]: https://github.com/cockroachdb/pebble/blob/v1.1.3/sstable/reader.go
[rclone-ranges]: https://github.com/rclone/rclone/blob/v1.68.1/fs/chunkedreader/sequential.go
[upstream-vfs]: https://github.com/cockroachdb/pebble/blob/v1.1.3/vfs/vfs.go
[upstream-object-create]: https://github.com/cockroachdb/pebble/blob/v1.1.3/objstorage/objstorageprovider/vfs.go
[go-os-errors]: https://github.com/golang/go/blob/go1.25.0/src/os/error.go
[ci-fix]: https://github.com/phillmac/kubo-migration-experiments/actions/runs/41565828099
[ci-recovery]: https://github.com/phillmac/kubo-migration-experiments/actions/runs/41566603251
