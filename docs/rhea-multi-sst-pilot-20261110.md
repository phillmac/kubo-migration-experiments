# Rhea Pebble multi-SST checkpoint pilot — 10 November 2026

## Status and scope

**Implemented as an isolated, offline-tested candidate. NOT DEPLOYED / NOT LIVE TESTED. No live controller, mount, bucket, production Kubo or walker has been changed.**

The certified disposable full-clone starting point is **generation 13, format 013, nine previously successful single-unit rewrites, 93,686 marked SSTs, 93,697 referenced SSTs, no pending operation**. Its certificate is `docs/evidence/rhea-batch2-000013-certificate-20261107.json`; the protected Rhea journal is not modified by this candidate.

Existing full-clone controller/verifier and historical certificates remain unchanged. All code in `cmd/pebble-format-v1/multistep/` is separately named; its `main.go` **refuses every CLI execution**. This is intentional: a root-owned, authenticated live controller with durable journal activation and recovery is not yet part of this candidate. No unattended loop or auto-admission exists.

## Intended operation

The current path opens and closes Pebble, publishes a checkpoint, and performs two complete S3 version proofs for **each selected atomic rewrite unit**. The newly implemented `runBatch` path performs **at most two authoritative marked SST compactions in one writable Pebble session**, with **one shared I/O budget and one close**. It records each step's exact picker digest, SST inputs/outputs and event pair; after its final close it emits one combined closed writer report.

A future controller may then use the new candidate cloud verifier twice against the same closed generation: **one fresh proof before markers, one fresh proof after publishing markers**, followed by a fresh read-only reopen and durable generation certificate. It must not publish intermediate markers between subunits or reuse a version-listing snapshot across proofs. The **new certificate generation increments by one for the batch**, while `physical_rewrite_total` increments by the number of actual successful compactions. The candidate introduces **schema 2** certificates to distinguish these from the old schema-1 one-unit generations. The exact generation-13 hash remains the first predecessor anchor.

The initial pilot deliberately **does not increase** the former per-checkpoint resource limits:

| Resource | Pilot bound |
|---|---:|
| Physical compactions | At most 2 |
| Aggregate picked input | 256 MiB |
| Aggregate SST output/write budget | 512 MiB |
| Aggregate metadata writes | 64 MiB |
| Existing cache bound (for future live integration) | 96 GiB |
| Minimum free-space reserve (for future live integration) | 2 TiB |
| Max queued upload allowance (for future live integration) | 768 MiB / 256 files |

The in-memory writer has no live host or rclone command. Its `freeCheck` callback must become a continuously enforced authenticated writer/queue/free-space guard **before** any real-host adaptation; the offline tests supply a no-op callback only for synthetic data. The initial selected picker plan must equal an explicit read-only digest. Before every subsequent compaction, the code obtains another authoritative picker plan, checks remaining budgets and disjoint inputs, records a durable unit intent, and only then schedules that one rewrite. If the next candidate exceeds the total bound it stops successfully **before** performing it and reports fewer than two successful units. A hard write-budget violation or any failure is **not** certified as success.

## Evidence, publication and partial failures

The offline journal uses an explicitly protected `0700` directory and exclusive `0600` files with file and directory fsync. It writes `pending.json` before writable open, `unit-NNN-intent.json` before each compaction, `unit-NNN-receipt.json` after an independently checked unit and `closed.json` on close, including failures. Existing evidence filenames refuse overwrite/replay. The filesystem write budget never refunds deleted output bytes.

**Pebble's two compactions are not an atomic transaction.** The first can commit before the second errors, loses its process or cannot create an SST. A pending/failed/incompletely closed batch must therefore be inspected and reconciled to actual closed MANIFEST/SST state; it must **never automatically rerun** either unit or advance the journal from its last certificate on the strength of receipts alone. An interrupted write before receipt fsync can leave an unreceipted committed compaction. If a complete, independently proven checkpoint cannot be reconstructed, the supported lab recovery is to restore the disposable clone from the protected frozen source. An actual live recovery/admission recipe is not yet implemented.

The candidate verifier `scripts/verify_rhea_multi_sst_candidate.py` is separate from the installed original. It validates the complete batch of unit receipts and events, intermediate inventory transitions, mutually disjoint created/retired SST sets, cumulative limits, mark deltas, exact closed output hashes and prior certificate ancestry. It performs fresh complete four-worker S3 listing and checks unchanged pinned object versions, retired delete markers, every new SST's content SHA-256, metadata bytes, unpublished/publication markers and unexpected keys. Its pure finalization gate rejects a reused proof-pass ID, missing second proof, inconsistent proof metadata, or reader reopen not matching certified output.

**Do not infer that the offline Go unit tests prove real Wasabi checkpoint consistency.** Live S3 performance, queue pressure, upload visibility, MANIFEST rotation, interrupted process/cloud write recovery and reader restoration remain unmeasured for multi-unit checkpoints.

## Offline tests and source artifacts

- Go engine: `cmd/pebble-format-v1/multistep/` (compaction loop, cumulative budget FS, journal, state and tests).
- Cloud proof candidate: `scripts/verify_rhea_multi_sst_candidate.py` and `tests/test_verify_rhea_multi_sst_candidate.py`.
- Isolated fixture runner: `scripts/test_rhea_multi_sst_offline.py`. Requires an already installed Go toolchain and populated offline module cache containing **Pebble v1.1.3**. Copies the module/command to temporary scratch and does not touch Rhea or download dependencies.
- GitHub CI: `.github/workflows/rhea-multi-sst-candidate.yml`; downloads only pinned Go dependencies on an ephemeral runner, runs original + new Go tests, `go vet`, `go test -race`, full Python regression and cross-language fixture verification.
- Fixture verification: `RHEA_MULTI_FIXTURE_OUTPUT=fixture.json go test -run '^TestTwoGenuineSequentialRewritesAndClosedReopen$' ./multistep` against the exact patched v1.1.3 module, followed by `python3 scripts/verify_rhea_multi_sst_candidate.py --offline-go-fixture fixture.json`.

Offline coverage specifically verifies **two genuine sequential Pebble rewrites**, mismatched initial state/digest refusal before any write, stopping before an over-budget next pick, second compaction output failure after the first has committed, rejected replay when an intent/receipt already exists, exclusive durable journal files, disk write-budget enforcement, complete cloud proof both before and after marker publication, unexpected remote versions and schema ancestry rejection.

## Remaining gates before any live adoption

1. Independent code/security review and green GitHub CI against the exact source commit, including race-detector and Go/Python fixture parity.
2. Design and implement a separate **root-only live controller** and protected immutable deployment pins. It must prove installed binary/source hashes; boot/process/mount/cloud identities; reader-to-writer handoff; clean authenticated rclone queue; continuous cache/free-space headroom; and a single durable pending-stage journal before the first writer invocation. Do not reuse the old generation-to-rewrites equality assumption.
3. Implement a complete **crash/partial-batch recovery procedure** that either independently certifies actual closed state, safely recovers from the frozen copy or leaves the lab stopped for inspection. Simulate interruptions at every unit-intent, compaction completion, metadata flush and publication boundary without any writer replay.
4. Authorize one separately admitted **two-unit disposable clone** pilot (generation 14 only after reviewed policy transition), verify before/after S3 independently, publish markers in order, freshly reopen through the reader and verify unchanged production state. Retain the nine-unit historical ceiling and frozen production state until all prerequisite gates pass.
5. Compare real elapsed time, cache, upload backlog and SST byte amplification against the single-step baseline before changing the permitted batch size or attempting large-scale rewriting.

This is a working offline candidate for the core batching and verification algorithms, **not a production-ready migration controller or approval to modify the 7.082 TiB clone**.
