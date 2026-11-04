# Rhea full-clone pacing milestone — 4 November 2026

## Status and scope

**All four additional rewrite units are fully certified: generations 6–9 passed
local close, independent S3 verification, and fresh read-only reopening. The
certified state has five total successful rewrites and 93,690 marked files.
The writable mount is cleanly stopped, the reader is restored and reopened,
and the original production processes have passed authenticated RC checks.**
The milestone completed **four additional independently certified rewrite
units**, advancing from generation **5 / total rewrites 1**
to generation **9 / total rewrites 5**. Each unit required a separate explicit
`step` invocation, successful local close, full independent S3 verification, and
a fresh read-only reopen before another writer is admitted. Production Wasabi
Kubo and the walker remain frozen. This does not authorize format 14, complete
migration, or production cutover.

The reader-stop infrastructure interruption was separately reconciled, and
startup completed before the first new rewrite. A second infrastructure
interruption occurred in the finalization precheck, before any service action;
the corrected finalizer subsequently completed. Neither added a failed Pebble
attempt. All times below are **AEDT (UTC+11), 4 November 2026**, unless stated
otherwise.

The [combined certificate][combined] binds all four units, the final reader,
production health, and retained failure evidence. Its SHA-256 is
`accbfa2151490cef4dcba979ff3c5ad89f07923a105586c648d008720bf1b51e`
(**60,399 bytes**). It contains **201 retained evidence references**, including
all **75** references from the prior milestone with their exact byte counts and
SHA-256 values preserved. The four exact stage certificates and four writer
reports linked below match the bundle's recorded hashes.

The starting point is the [completed one-rewrite milestone][previous-report].
Its [generation-5 certificate][anchor] has exact and canonical SHA-256
`53295fea8edf8abb35c89b9eefa864bc8b044f5ede6eeabfcba5ca3ee540925b`:

| Certified starting state | Value |
| --- | --- |
| Format / marked files | **013 / 93,694** |
| Referenced SST count / bytes | **93,697 / 7,786,594,080,648** |
| Total successful rewrites | **1**, preceded by one separately reconciled failed attempt |
| Inventory SHA-256 | `6c4125a75d05755dc4ca8666c50e7ddc8cbdaf3ebdccd7dbd23fc4e9baf45fa2` |
| Existing created output | `47475312.sst`, **67,057,185 bytes** |

The policy transition rechecked this certified anchor and preserved its metadata
and admission. Pre-start health checks at **13:38:50.797** also passed, with production RC
clean, zero upload queue, and the original production processes unchanged.
Yesterday's report, five stage certificates, failed-close bridge, failed writer,
and combined evidence remain unchanged.

## Certified additional units and measured latency

Each completed unit below retired one original L6 SST and created one L6 output
**137 bytes smaller**. That observed one-file selection does not change the
atomic-unit definition or limits. Full duration includes publication,
verification, and the stage reopen; Go and reopen durations are separate
components, not measurements of cold S3 throughput.

| Generation / total rewrites | Input → output | Bytes in → out | Go / full / reopen, seconds | Marks after / completion |
| --- | --- | --- | --- | --- |
| 6 / 2 — **certified** | `46893048.sst` → `47475316.sst` | 67,307,651 → 67,307,514 | 11.826642567 / 393.750087738 / 5.361251259 | **93,693 / 14:21:00.291** |
| 7 / 3 — **certified** | `46893049.sst` → `47475320.sst` | 67,118,363 → 67,118,226 | 11.619545547 / 394.305652216 / 5.317575817 | **93,692 / 14:28:50.755** |
| 8 / 4 — **certified** | `46893050.sst` → `47475324.sst` | 67,220,981 → 67,220,844 | 12.663098613 / 383.078834109 / 5.078098056 | **93,691 / 14:36:29.743** |
| 9 / 5 — **certified** | `46893051.sst` → `47475328.sst` | 67,321,066 → 67,320,929 | 11.971792699 / 383.113947764 / 5.428700110 | **93,690 / 14:44:17.917** |

The four compaction events took **916, 812, 1,068, and 831 ms**. Their selected
inputs total **268,968,061 bytes**, created outputs **268,967,513 bytes**, and
metadata writes **63,123,134 bytes**. The sum of their full operation times is
**1,554.248521827 s** (25 min 54.249 s), excluding inter-operation gaps,
admission, and finalization; the corresponding Go total is **48.081079426 s**.
These component timings show why compaction duration alone does not describe
checkpoint pacing. [Measured stages and totals][combined]

| Certified unit / writer | Certificate SHA-256 | New output SHA-256 |
| --- | --- | --- |
| [6 certificate][cert6] / [writer][writer6] | `d45cf581915bcf8e6047eae5c7d2d0fb5afea2d9cd13ddc5c927073c48c4b16f` | `fd9ea1ff683495dbdb5dc3c2cf363f90c1435c9631135245c8369ed1e5f30c8e` |
| [7 certificate][cert7] / [writer][writer7] | `46350c4b120ac5e4661a83e49fbaa8296ad8986b5f7a3d1f62fd4d1fa4411a32` | `bf333632987797bd69af5b775e18d6ee16dd16c12fbaaf3cf85303c02d8f224a` |
| [8 certificate][cert8] / [writer][writer8] | `5b5740422c3f50cd52bf5190b64c8d4b6a1c6473ebdc3569a26ecdf302a21aa1` | `c72fbf16879b68b378b31f4f057ca48c89ec42f6adc2fb122810a64fa2dcdac0` |
| [9 certificate][cert9] / [writer][writer9] | `220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2` | `ab9ca63855d1c180db6bbb85bb22b21825f6479584eafa104a5cda99a1e57c55` |

The final certified database remains format **013**, with **93,697 SSTs** and
**7,786,594,080,100 referenced bytes**: a **548-byte** decrease across these four
rewrites. Its inventory SHA-256 is
`b150b4860f87f9273afa85641fac61010134e0e99a6922b5a4acaa86e37a5c58`;
the protected generation-9 state SHA-256 is
`7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1`.
There is no pending database stage. The controller has reached its successful
rewrite ceiling; another `step` is outside this policy.

## Four separate units and their limits

The four new stage directories and certificates are `000006-step` through
`000009-step`. A unit means one authoritative Pebble compaction selection; it
does not promise one input file, one output file, or a one-file decrease in the
marked count. Each plan must be obtained from the current certified state and
rechecked by the writer immediately before scheduling. [Go command][go]
[Authoritative adapter][adapter]

| Bound | Per unit |
| --- | --- |
| Physical atomic input set | **256 MiB** |
| Cumulative SST writes | **512 MiB** |
| Cumulative metadata writes | **64 MiB** |
| Free cache-filesystem space | **2 TiB**, with **832 MiB** admission reserve |
| Sampled cache allowance | **96 GiB**, including admission headroom |
| Upload backlog | At most **768 MiB / 256 files** |
| Admission of another writer | Queue/upload/error counts **0**, `outOfSpace=false`, no unresolved stage or stop sentinel |

Four successful new processes therefore permit at most **1 GiB selected input,
2 GiB cumulative SST writes, and 256 MiB metadata writes** in aggregate. These
totals do not replace per-process limits or cache/free-space checks. Existing
cached input and historical outputs can survive across steps. A failure stops
the sequence; it does not automatically consume a replacement attempt.

The Go binary remains pinned to
`1bc58ef8ca76a97fc9886d90f4a3df4fdd3d07549403988e3798834a61207125`.
Automatic compactions and background table statistics remain disabled. The
controller's existing cooperative stop monitoring, closed-file snapshots,
ordered queue expiry, and protected journal remain part of each unit.

## Completed policy transition and preserved startup reconciliation

The controller source used for this milestone is
[`bfcd17e89daf89d28dade4d372e712851fa18e1b`][source-commit]. Its controller raises
only the successful-rewrite ceiling to **5** and the corresponding generation
ceiling to **9**, while reconciling journal generation, certificate generation,
format, and cumulative lineage count. Every step still requires its own
certificate and reopen. The controller SHA-256 is
`7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb`.

The protected live transition completed in **65.504049 s**. It changed only the
controller hash and `limits.maximum_rewrites` binding, preserved the generation-5
checkpoint and old state/pins, and left the Go/verifier/decoder, wrapper,
admission, mount settings, credentials, and database metadata unchanged. The
retained completion and resulting protected files are:

| Transition evidence | SHA-256 |
| --- | --- |
| Completion receipt | `7b5be4aa2ea97fb2b14f53483fa462242976802cd3f807b84ce6a583c695b246` |
| Post-transition state | `7d63d080879383fe43e55972b86578e0e76abab469fc8cde43e80c60d371862f` |
| Post-transition deployment pins | `0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575` |

The requested normal stop of reader PID **2744687** then produced exit status
**143**. Its process was gone and its mount absent, but systemd retained the
transient unit as **loaded/failed**. The startup recipe required full collection
of the stopped unit and failed closed in phase **`reader-stop`**, after
**5.362578 s**. The writer-start phase was never executed; generation **5** and
post-transition state `7d63d080…` remained unchanged.

This infrastructure interruption added **no Pebble writer attempt**. At that
point the journal still recorded one successful rewrite, and the historical
failed Pebble-attempt count remained **1**. Its original evidence is preserved
separately:

| Startup evidence | SHA-256 |
| --- | --- |
| Original startup failure | `03070fdd6e2a7ab4d63d1ecfbfc8751d0a432303cc7e8ea5d647ad10ad842218` |
| Reader stop intent | `4a3019bb5a62beec984bc021ae05baa78cf7a392b67e6367e34798513db66ef7` |
| Captured exit observation | `107d5cba702fcb9a623ea1781ccc422344a82efc69e38de52e6b7b433975586d` |

A separate reviewed continuation cleared the failed state of only that exact
stopped reader unit, then executed the previously unexecuted writer-start tail.
It did not repeat the reader stop, restart the reader, or replay the entire
startup. It preserved the original failure, intent, observation, state, and
checkpoint. Resume completed in **86.695949122 s**, at **14:13:03.245**, with
writable mount PID **2783799**. The fresh seed read-only reopen passed in
**5.544922543 s**, with metadata bound to the unchanged generation-5 certificate.

| Completed startup proof | SHA-256 |
| --- | --- |
| Reader-stop reconciliation | `66ba4e311f5cab6a11bd3ac572cee56855fbe621d4cca589e4e1472a535ac9dc` |
| Collected reader / mount absence | `46f357fefe5e7573c407e6769f2bbada60d79a1e79d54ce372ed14770ff894b6` |
| Resumed startup completion | `70a76320e8e99eff89331ec81cbdfb0ddb933f2871fcb82d462f5d0e285221ed` |
| Actual receipt-contract validation | `029a6952c5356a1507ed9808cde1085b3c292c9454303a524ecdd5961ab5b71e` |

The startup proof was validated against the actual retained receipts before the
new finalization recipes were admitted. The historical failed Pebble-attempt
count remains **one**; the infrastructure interruption has its own classification.

The ordinary database checkpoint recovery path remains distinct: it can resume
publication and verification of an already successful closed writer, never
rerun that writer. The older failed-close helper remains pinned to the specific
historical Pebble failure.

No tail warmup was rerun. The installed historical helper
`7fbf8acf9454ff9bfda7ab133e93e64b554bbd74856077dd87d00bb3761eb926`
remains untouched and unused. A repository-only controller-pin update preserves
source compatibility; it does not replace that installed historical helper.

## What cumulative verification already proves

The verifier reconstructs current references as:

`(immutable baseline names ∪ all historically created names) − all retired names`.

`sst_lineage.created` and `sst_lineage.retired` are cumulative. A created file
retains its original content hash and VersionId/ETag/size pin even if a later
unit retires it. `created_sst_versions` contains only the current unit's new
outputs. Historical filenames cannot be reused. Every previously retired file
must still have its exact historical version available; its latest state must
be either the same unreferenced object or a recorded delete marker.

The prior active MANIFEST is fetched by its exact certified VersionId, hashed,
decoded, and matched to that reconstructed lineage. The new closed MANIFEST is
checked against the Go before/after state, selected inputs, compaction events,
exact delta, levels, marks, and budgets. Every surviving referenced SST must
retain its latest VersionId, ETag, and size. Only this unit's new outputs are
downloaded and hashed again. Unknown current SSTs/deletions, changed surviving
versions, missing historical versions, and unexpected metadata refuse
certification. [Verifier implementation][verifier]

No runtime verifier change was required for this continuation. Its retained
SHA-256 is
`e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849`;
the unchanged decoder is
`edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b`.

### Counter semantics

| Field | Meaning across repeated steps |
| --- | --- |
| `sst_lineage.rewrite_operations` | Total successful rewrites, including the original generation-5 rewrite |
| `unchanged_sst_versions` | All surviving previously referenced SSTs, including earlier-created outputs |
| `new_sst_payload_bytes_downloaded` | Bytes of this unit's new outputs in this verification pass |
| `unchanged_sst_payload_bytes_downloaded` | **0**; verification does not download unchanged original or earlier-created SST payloads |
| `retired_sst_states` | Latest recorded state of every cumulatively retired file |
| Writer I/O counters | Cumulative writes within that Go process; aggregate only across explicitly identified receipts |

Original survivors and earlier-created survivors are counted separately.
Original survivors are baseline names minus cumulatively retired original
names. Earlier-created survivors are cumulative created names minus cumulative
retired names and this unit's new names. Their sum equals
`unchanged_sst_versions`. The recorded one-for-one replacements through generation
9 leave **93,692 original survivors and five live created outputs**. During the
generation-9 verification, **four** of those outputs were earlier-created and
one was new: its unchanged set therefore consists of **93,692 originals plus
four earlier-created outputs**, totaling **93,696**. The newest output belongs
in the new-output hash/download count, not the unchanged count.
[Generation-9 certificate][cert9]

Content hashes of surviving earlier outputs are retained from their original
certificates; their immutable object identities are rechecked without another
payload download. The four final verification passes downloaded and hashed
**268,967,513 bytes of new SST payload**, and **zero bytes of surviving original
or earlier-created SST payload**. These counters exclude prepublication passes,
retries, compaction reads, and other filesystem/network traffic. This milestone
does not establish fresh byte validation of the full corpus or complete
block/pin reconciliation. [Verification scope and counters][combined]

## Verification cost and batching decision

Each normal unit runs `verify_generation` twice: before its fresh MANIFEST
marker is published, then after publication. Each call performs a complete
paginated **ListObjectVersions over `rhea/`**, retaining latest rows while
walking historical rows returned by the service. It verifies repository objects,
all referenced SST identities, every retired historical pin, the new SST
payloads, and exact closed metadata. Publication adds fresh HEAD checks; a
read-only reopen follows the final proof. [Verifier][verifier]
[Publication controller][controller]

The four-unit path retained **eight complete version
enumerations**, plus the metadata/output reads and HEADs. A listing spans the
whole clone and its history, not just the files touched by that unit. It grows
with accumulated versions; surviving earlier outputs add identity checks but
no repeated SST payload downloads. Retired files add historical HEADs.

The previous successful unit took **404.550872326 s** overall, compared with
**17.11223705 s** in Go and **6.95119203 s** in the stage reopen. Verification,
publication, and orchestration account for the remaining elapsed time; the
receipts do not isolate all of those costs. The four new operations took
**383.079–394.306 s each**, while their Go writers took **11.620–12.663 s**.
Cold reads, input size, version-list latency, and cache state can change these
measurements. The earlier **1.557 s** compaction event was measured with warmed
data and is not a cold S3 throughput benchmark.
[Previous measured result][previous-combined] [New measured stages][combined]

**All eight independent scans were preserved for this milestone.** A changed-file-only
check, a reused prepublication listing, or one final proof after four writers
would change the current completeness and recovery guarantees. Safe future
optimizations could reuse deterministic work derived from a still-pinned
immutable ledger, avoid duplicate identical metadata work within a single pass,
or bound concurrency for independent pinned reads. They require separate review
and measurement; none is included in this four-unit continuation.

## Focused local validation

The added [repeated-step fixture][tests] first obtains a valid certificate for
one rewrite, attaches its read-only reopen, then verifies a second rewrite that
retires the next original while preserving the first created output. It checks:

- the first certificate is unchanged and remains the exact parent;
- both created and retired maps accumulate, with total rewrite count **2**;
- the earlier output's SHA/version pin survives exactly, and it contributes to
  `unchanged_sst_versions` without another payload GET;
- only the newest output is downloaded; historical HEADs retain both originals;
- changed VersionId, ETag, or size for the earlier output fails certification.

**All 256 Python tests pass**, including **24 targeted verifier tests** and
**26 targeted controller tests**. The runtime verifier and decoder are
unchanged. Both [push CI 41763169841][ci-push] and
[PR CI 41763174468][ci-pr] passed for source `bfcd17e…`. These results establish
the tested implementation; they do not substitute for the new live certificates.

## Completed operational closure and preserved precheck failure

The first finalization attempt stopped during its precheck after **22.062625 s**.
Two imports of the pinned wrapper had created distinct Python `Profile`
classes, so an object from one helper instance was rejected by the other. This
occurred **before any service action** or creation of the finalization evidence
directory. The original finalizer source, stderr, timing, and observed state
were preserved; the capture SHA-256 is
`cf557a903be1f674dd6f69fb9f5d9a627b9de03b52fa18534c7bedb4096be8b4`.

That captured state showed the writable mount still clean at PID **2783799**,
the unchanged generation-9 state, and the reader still stopped. The correction
uses the wrapper instance owned by the controller runtime, avoiding the
duplicate class identity. The corrected finalizer SHA-256 is
`3e522bae660ded45fb0160e122fd46c711fd5460b9b5b4d1e9234ae0786ebad2`.
This is the second infrastructure interruption in the milestone, separate from
the **one historical failed Pebble rewrite**. All four new Pebble writers and
their database certification gates succeeded.

Finalization attempt 2 completed successfully. Its receipt records
**14:57:52.187**; the outer invocation finished at **14:57:52.288**, after
**101.203737743 s**. It cleanly stopped the writable mount and restored reader PID
**2788642**. The fresh read-only reopen passed in **4.550131702 s**, reporting
format **013**, **93,690** marked files, **93,697** SSTs, and
**7,786,594,080,100** referenced bytes. The reader's metadata generation is bound
to the final S3 certificate. Protected state and the retained history are
unchanged.

| Final operational observation | Result |
| --- | --- |
| Writable mount service | **Inactive/dead**, `MainPID=0`, `Result=success`, `ExecMainStatus=0` |
| Writable mount and RC socket | **Absent**; cache retained |
| Restored reader | **PID 2788642**, metadata generation and read-only reopen passed |
| Production service leader | Original **PID 2554927**, the bash service leader |
| Actual production rclone server | Original **PID 2554974**, authenticated RC clean |
| Production RC cache and queue | **0** cached bytes, queued uploads, active uploads, and errors; `outOfSpace=false` |
| Production Wasabi Kubo / walker | **Inactive**; walker remains **disabled** |
| Protected journal | Generation **9**, successful rewrites **5**, no pending stage |

The finalization completion receipt SHA-256 is
`e2cbae5c26f9b757321146edc94e9459b9cd7de2f82ea52605efec9ad84078f5`;
the production RC receipt SHA-256 is
`90673e8a7fbf630a1efb1b4876757a43ee2d331dea4ad103cc2104f5dd18f1b2`.
That authenticated production observation was recorded at **14:57:52.163**.
[Final operational evidence][combined]

| Gate / generation | Local close | S3 certification and stage reopen | Result |
| --- | --- | --- | --- |
| Policy transition and pre-start health | **Passed**; 65.504049 s transition | Generation-5 anchor and metadata preserved | New state/pins recorded above |
| Reader-to-writer startup | **Reconciled and completed** | Seed read-only reopen passed; original failure preserved | No additional failed Pebble attempt |
| 6 / total rewrites 2 | **Passed** | **Passed** | Certificate recorded above |
| 7 / total rewrites 3 | **Passed** | **Passed** | Certificate recorded above |
| 8 / total rewrites 4 | **Passed** | **Passed** | Certificate recorded above |
| 9 / total rewrites 5 | **Passed** | **Passed** | Certificate recorded above |
| Final writer stop / reader restoration | **Passed** on finalization attempt 2 | Metadata generation and restored-reader checks **passed** | Cache retained; first precheck failure preserved |
| Production RC | **Passed** | Original service leader and rclone server preserved | Authenticated RC clean |
| Public evidence collection | **Passed** | Combined certificate and eight exact stage/writer files reconciled | 201 retained references, including all 75 prior references |

The public evidence export was recorded at **15:02:50.827**. It preserves the exact
per-unit certificates and writer reports, their parent chain and object pins,
the original failed-attempt and bridge provenance, and both infrastructure
interruptions. Its local reconciliation passed for all eight exported stage and
writer files, the generation-5 through generation-9 chain, measured totals,
survivor counters, and prior evidence hashes. All database, operational, and
collection gates are complete. The measured result is four additional certified
rewrite units, with **five successful rewrites in total**, while **93,690 files
remain marked**.

[combined]: evidence/rhea-full-clone-pacing-certified-20261104.json
[cert6]: evidence/rhea-full-clone-000006-step-20261104.json
[writer6]: evidence/rhea-full-clone-000006-writer-20261104.json
[cert7]: evidence/rhea-full-clone-000007-step-20261104.json
[writer7]: evidence/rhea-full-clone-000007-writer-20261104.json
[cert8]: evidence/rhea-full-clone-000008-step-20261104.json
[writer8]: evidence/rhea-full-clone-000008-writer-20261104.json
[cert9]: evidence/rhea-full-clone-000009-step-20261104.json
[writer9]: evidence/rhea-full-clone-000009-writer-20261104.json
[previous-report]: rhea-full-clone-one-rewrite-20261103.md
[previous-combined]: evidence/rhea-full-clone-one-rewrite-certified-20261103.json
[anchor]: evidence/rhea-full-clone-000005-step-20261103.json
[controller]: ../scripts/run_rhea_full_clone_steps.py
[verifier]: ../scripts/verify_rhea_full_clone.py
[go]: ../cmd/pebble-format-v1/realstep/main.go
[adapter]: ../cmd/pebble-format-v1/patches/demo_single_rewrite.go
[tests]: ../tests/test_verify_rhea_full_clone.py
[source-commit]: https://github.com/phillmac/kubo-migration-experiments/commit/bfcd17e89daf89d28dade4d372e712851fa18e1b
[ci-push]: https://github.com/phillmac/kubo-migration-experiments/actions/runs/41763169841
[ci-pr]: https://github.com/phillmac/kubo-migration-experiments/actions/runs/41763174468
