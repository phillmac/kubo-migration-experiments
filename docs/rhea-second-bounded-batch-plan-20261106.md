# Rhea second bounded rewrite batch — local candidate, 6 November 2026

## Status and objective

**Prepared and tested locally; not deployed or executed.** The current restoration
task first reconciles the new boot, restored mounts and a fresh verification of
certified generation 9. This candidate leaves the installed five-rewrite ceiling
unchanged until a separate reviewed policy transition is completed.

The proposed window is **four additional separately admitted atomic rewrite
units**, generations **10–13**, bringing successful rewrites from **5 to 9**.
Generation 10 is the first operational checkpoint to exercise the adopted
four-range verifier in both `before-markers` and `final` modes. Its completed
certificate, timings and queue state must be examined before issuing the separate
generation-11 command. There is no automatic loop or new mutable review field.
Every invocation returns after one certified unit.

The [adoption report](rhea-bounded-verifier-adoption-20261106.md) records final-mode
acceptance only. The [earlier pacing report](rhea-full-clone-pacing-20261104.md)
records five successful rewrites and the original failed-attempt history. Neither
is modified by this candidate.

## Protected starting point

The [retained journal](evidence/rhea-bounded-adoption-state-after-20261106.json)
has generation 9, rewrites 5, `pending: null`, format 013, 93,690 marked SSTs,
93,697 total SSTs and 7,786,594,080,100 SST bytes. Its checkpoint remains
[generation 9](evidence/rhea-full-clone-000009-step-20261104.json), SHA-256
`220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2`.

Restoration must preserve that journal, certificate, immutable baseline ledger,
existing certificates/stages, caches, configuration and admission. New boot and
process identities require new operational evidence: the historical adoption
health helper intentionally pins the old live identities. Do not rewrite its
constants or reuse its old process observation as current acceptance. A successful
post-reboot read-only validation does not require a new database certificate or
reset of SST lineage.

## Successor installation and exact policy delta

Both installation paths are beneath
`/root/.local/share/rhea-wasabi-lab-admin-20261101`:

| Role | New fixed path |
|---|---|
| Controller | `run_rhea_full_clone_steps_batch2.py` |
| Pins | `full-clone-batch2-step-pins.json` |
| Shared journal and stages | Existing `full-clone-steps/` |

The [candidate controller](../scripts/run_rhea_full_clone_steps_batch2.py) preserves
the adopted controller and pins at their historical paths. Its only policy change
is `MAX_REWRITES = 9`, which derives `MAX_GENERATION = 13`. The existing verifier
`43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796`, scanner,
decoder, Go binary and wrapper remain unchanged; both proof calls still explicitly
request four workers.

The state transition changes exactly these two leaves:

```text
binding.controller_sha256: 56fe3af2… → b10ab6b3…
binding.limits.maximum_rewrites: 5 → 9
```

The pins change only `controller_sha256`. The embedded certificate, generation,
rewrites, pending state, verifier/Go/wrapper/seed hashes, scope and every other
limit must remain byte-equivalent after canonical serialization. For the exact
candidate bytes below, the proposed endpoints are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Candidate controller | 51,239 | `b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828` |
| Existing controller, preserved | 49,144 | `56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a` |
| Existing journal | 7,318 | `22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2` |
| Proposed journal | 7,318 | `0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9` |
| Existing pins, preserved | 264 | `684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c` |
| Proposed pins | 264 | `1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363` |

These are calculated candidates, not host deployment receipts. A later transition
must retain exact preimages and intent, install absent-or-exact new files under the
lifecycle lock, and fsync them before atomically replacing the journal as the sole
activation. Validate the complete expected binding and fresh operational identity
before and after. The previous fixed adoption runner is not a generic policy-edit
command. Do not reset the journal, renumber stages or replace certificate 9.

## Four explicit admissions and the first-unit gate

| New generation | Successful rewrites after certification | Admission |
|---|---:|---|
| 10 | 6 | First bounded unit after policy transition |
| 11 | 7 | Separate command after reviewing generation 10 |
| 12 | 8 | Separate command after generation 11 is certified |
| 13 | 9 | Separate command after generation 12 is certified |

For each unit, the controller performs the existing guarded read-only picker
plan, durably records intent, starts one Go writer, closes and validates it,
snapshots/hashes its closed files, defers markers, drains data, verifies the full
remote generation before publication, publishes markers, performs a second full
remote proof, and reopens read-only before committing the next certificate.
The next certificate references the preceding certificate's exact canonical hash.
Four atomic units do not necessarily mean four files or four removed marks.

Review generation 10's exact plan/input/output and mark deltas, complete parent
linkage, both proofs, reopened state, returned phase timings, and zero upload/error
backlog before admitting generation 11. Failure retains existing reconciliation
rules; never repeat a writer automatically. At nine successful rewrites, both
dry and applied `step` commands refuse further work before guard/writer entry.

All per-unit limits from the [controller design](rhea-full-clone-stage-controller.md)
are retained: **256 MiB input, 512 MiB SST output writes, 64 MiB metadata writes,
96 GiB cache, 2 TiB free reserve, and 768 MiB/256-file backlog**. New work requires
a completely clean queue and reserves the same 832 MiB headroom. Production Kubo
and the walker remain frozen. No warmup rerun, format-14 action or production
cutover is introduced.

## Timings without certificate changes

Successful apply, dry-run and recovery results add one top-level `phase_timings`
object. The caller retains the ordinary stdout receipt. No timing fields enter
the journal, Go report, checkpoint or verification input, and timing adds no
filesystem writes, retry behavior or exception handling that swallows failures.

For a normal apply, ordered intervals cover `plan`, `writer`, `snapshot`,
`defer_markers`, `drain_data`, `verify_before_markers`, `publish_markers`,
`verify_final` and `reopen`. Each reports monotonic elapsed seconds. Controller
elapsed time starts before lock acquisition and ends while constructing the
successful result; it excludes Runtime construction and later output/teardown.
It includes other guards and journal/certificate work not separately timed.

Proof intervals wrap the entire existing `Runtime.verify()` call, including its
guards, snapshot checks, cloud setup/closure and independent verification. They
are not the pure-verifier timings from the earlier profiling experiment. No
profiler or extra listing is introduced. Recovery reports only phases actually
executed in that invocation: a retained prepublication proof has no new timing.
Failed invocations still raise their original error and rely on their existing
durable stage evidence; no successful timing result is manufactured.

Retained disk caches and a freshly rebuilt rclone directory cache affect the next
measurements. Report actual input/output sizes and cache conditions; do not label
them cold-S3 throughput or project a full-migration completion time from four units.

## Local validation and remaining scope

The [new test file](../tests/test_run_rhea_full_clone_steps_batch2.py), SHA-256
`44dfaa89f2eb1c83c07781c2a0db42a6585158570e5ab8c3d66a7748a8441524`, passes
**36 focused tests**. Full local discovery passes **487 tests**. Compilation,
indentation and trailing-whitespace checks pass. Existing source and evidence
files remain unchanged. No deployment, live rewrite or new CI result is claimed.

Coverage includes the exact two-field transition from the public generation-9
journal, old/new binding rejection, four separate admissions and the ninth-total
ceiling, protected dependencies, both four-worker proof modes/client cleanup,
failure/recovery without writer replay, and timing parity with the predecessor's
exact checkpoint, journal and ordered runtime calls.

The first unit's review is followed by three separate commands only if its
evidence is satisfactory. This candidate is a pacing experiment; it does not
solve full-migration checkpoint batching, growing history/lineage bounds, general
crash recovery, format-14 completion or Kubo compatibility/cutover validation.
