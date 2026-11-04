# Rhea full-clone pacing milestone — 4 November 2026

## Status and scope

**Plan and local verifier regression complete; live continuation results are
pending.** The next milestone permits **four additional independently certified
rewrite units**, advancing from generation **5 / total rewrites 1** to at most
generation **9 / total rewrites 5**. Each unit requires a separate explicit
`step` invocation, successful local close, full independent S3 verification, and
a fresh read-only reopen before another writer is admitted. Production Wasabi
Kubo and the walker remain frozen. This does not authorize format 14, complete
migration, or production cutover.

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

These are retained certificate facts, not a new live observation. Fresh host,
mount, admission, process, queue, and certificate checks are required for this
continuation. Yesterday's report, five stage certificates, failed-close bridge,
failed writer, and combined evidence remain unchanged.

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

## Minimal controller extension

The [current verifier][verifier] has no one-rewrite or generation ceiling. Its
`step` transition is already **013→013**, with one compaction pair and unchanged
input/output/write limits. The controller owns the global ceiling. Raising only
one constant would leave other limits or state bindings inconsistent.

The local implementation follows this reviewed plan:

1. Permit a maximum of **five successful rewrites** and **generation 9**, while
   retaining one writer per invocation. Replace the generation bounds currently
   derived from the five distinct action names; repeated `step` actions need
   distinct generation numbers, not new action aliases.
2. Require the fixed generation-5 anchor and subsequent certificate parent
   chain. Reconcile journal generation and total rewrites with the certificate
   generation and cumulative `sst_lineage.rewrite_operations`; reject skipped,
   replayed, regressed, or substituted progress.
3. Use a reviewed binding transition for the new controller hash and
   `limits.maximum_rewrites`. Preserve the old state, deployment pins, anchor,
   earlier receipts, and every unrelated binding/admission value. Do not reset
   the journal or manufacture a new seed.
4. Keep the Go command, verifier, decoder, per-unit limits, mount profile, and
   credentials unchanged. After the fourth additional certified unit, refuse a
   further writer. Finish with a clean writer stop, exact reader restoration,
   generation checks, and separate production RC verification.

The reviewed controller source SHA-256 is
`7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb`;
its **26 targeted controller tests pass**. The live deployment revision and
transition receipt will be recorded below when available. The ordinary checkpoint recovery path may resume
publication and verification of an already successful closed writer. It must
never rerun that writer. The older failed-close helper is pinned to the specific
first-attempt failure and is not a generic recovery tool for a new failure.

No tail warmup is rerun. The installed historical helper
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

No production verifier change is required for this continuation. Its retained
SHA-256 is
`e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849`;
the unchanged decoder is
`edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b`.

### Counter semantics for the new report

| Field | Meaning across repeated steps |
| --- | --- |
| `sst_lineage.rewrite_operations` | Total successful rewrites, including the original generation-5 rewrite |
| `unchanged_sst_versions` | All surviving previously referenced SSTs, including earlier-created outputs |
| `new_sst_payload_bytes_downloaded` | Bytes of this unit's new outputs in this verification pass |
| `unchanged_sst_payload_bytes_downloaded` | **0**; verification does not download unchanged original or earlier-created SST payloads |
| `retired_sst_states` | Latest recorded state of every cumulatively retired file |
| Writer I/O counters | Cumulative writes within that Go process; aggregate only across explicitly identified receipts |

The final report must split original survivors from earlier-created survivors.
Original survivors are baseline names minus cumulatively retired original
names. Earlier-created survivors are cumulative created names minus cumulative
retired names and this unit's new names. Their sum equals
`unchanged_sst_versions`. For example, retiring one more original while keeping
the first output would leave **93,695 original survivors plus one earlier-created
survivor**, although `unchanged_sst_versions` would still be **93,696**. This is
an illustration, not a prediction of the next atomic unit.

Content hashes of surviving earlier outputs are retained from their original
certificates; their immutable object identities are rechecked. The report must
not describe this as downloading and rehashing all historical outputs. Final-pass
download counters also exclude prepublication passes, retries, compaction reads,
and other filesystem/network traffic.

## Verification cost and batching decision

Each normal unit runs `verify_generation` twice: before its fresh MANIFEST
marker is published, then after publication. Each call performs a complete
paginated **ListObjectVersions over `rhea/`**, retaining latest rows while
walking historical rows returned by the service. It verifies repository objects,
all referenced SST identities, every retired historical pin, the new SST
payloads, and exact closed metadata. Publication adds fresh HEAD checks; a
read-only reopen follows the final proof. [Verifier][verifier]
[Publication controller][controller]

The normal four-unit path therefore entails **eight complete version
enumerations**, plus the metadata/output reads and HEADs. A listing spans the
whole clone and its history, not just the files touched by that unit. It grows
with accumulated versions; surviving earlier outputs add identity checks but
no repeated SST payload downloads. Retired files add historical HEADs.

The previous successful unit took **404.550872326 s** overall, compared with
**17.11223705 s** in Go and **6.95119203 s** in the stage reopen. Verification,
publication, and orchestration account for the remaining elapsed time; the
receipts do not isolate all of those costs. Four repeats at that observed rate
would be about **27 minutes**, as a planning estimate only. Cold reads, input
size, version-list latency, cache accounting, and retries can change it. The
earlier **1.557 s** compaction event was measured with warmed data and is not a
cold S3 throughput benchmark. [Previous measured result][previous-combined]

**Keep all eight independent scans for this milestone.** A changed-file-only
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

**All 24 targeted verifier tests pass**, including the existing bounds and
publication tests. The runtime verifier and decoder are unchanged. Combined
suite/CI, deployment, and live outcomes will be recorded
from their actual results.

## Live result ledger — awaiting receipts

| Gate / generation | Local close | S3 certification and stage reopen | Result |
| --- | --- | --- | --- |
| Fresh admission and binding transition | Pending | Anchor/protected-state checks pending | No live result claimed |
| 6 / total rewrites 2 | Pending | Pending | No live result claimed |
| 7 / total rewrites 3 | Pending | Pending | No live result claimed |
| 8 / total rewrites 4 | Pending | Pending | No live result claimed |
| 9 / total rewrites 5 | Pending | Pending | No live result claimed |
| Final writer stop / reader restoration | Pending | Metadata generation and fresh reader checks pending | No live result claimed |
| Production RC / combined evidence | Pending | Frozen writers and preserved process/queue checks pending | No live result claimed |

For each completed unit, record the exact input/output set, plan and parent
hashes, marked delta, inventory, write counters, full/Go/reopen times, original
and earlier-created survivor counts, final-pass download counters, remote object
pins, and certificate hash. The final certificate must retain the original
failed-attempt/bridge provenance and distinguish five total successful rewrites
from four additional units. No new live success is inferred from the local
regression tests.

[previous-report]: rhea-full-clone-one-rewrite-20261103.md
[previous-combined]: evidence/rhea-full-clone-one-rewrite-certified-20261103.json
[anchor]: evidence/rhea-full-clone-000005-step-20261103.json
[controller]: ../scripts/run_rhea_full_clone_steps.py
[verifier]: ../scripts/verify_rhea_full_clone.py
[go]: ../cmd/pebble-format-v1/realstep/main.go
[adapter]: ../cmd/pebble-format-v1/patches/demo_single_rewrite.go
[tests]: ../tests/test_verify_rhea_full_clone.py
