# Rhea disposable full-clone: second bounded rewrite window

## Certified outcome — 7 November 2026

Four separately admitted and certified SST rewrites advanced the disposable Wasabi/Pebble full clone from generation 9 to 13. It remains at format 013, with 9 total successful rewrites, 93,686 remaining marked SSTs, and no pending operation. Production Kubo and the pin walker remain stopped. Format 14, production cutover, and full pin reconciliation have not occurred.

The source for this controlled window was published at fccc14dca36d72258f90c723506d674e310ff976. The four actual writer reports, stage certificates, operation outputs, timing receipts and independent reviewer approvals are published alongside this report.

| Generation | Input SST to output SST | Input to output bytes | Controller elapsed | Whole step elapsed | Marks remaining |
|---|---|---:|---:|---:|---:|
| 10 | 46893052.sst to 47475332.sst | 67,350,713 to 67,350,576 | 160.069 s | 171.812 s | 93,689 |
| 11 | 46893053.sst to 47475336.sst | 67,094,513 to 67,094,376 | 167.803 s | 183.138 s | 93,688 |
| 12 | 46893054.sst to 47475340.sst | 67,278,175 to 67,278,038 | 179.397 s | 198.683 s | 93,687 |
| 13 | 46893055.sst to 47475344.sst | 67,235,814 to 67,235,677 | 180.671 s | 203.601 s | 93,686 |

The four writers selected 268,959,215 input bytes and wrote 268,958,667 SST bytes and 63,123,086 metadata bytes. Each writer remained within the fixed 256 MiB input, 512 MiB SST-write, 64 MiB metadata-write, 96 GiB cache and 2 TiB free-space reserve budgets.
The four complete controller invocations totaled 687.941 seconds; the four whole one-step operations totaled 757.234 seconds, excluding startup, finalization and gaps between commands.

## Proof and review

Each unit had a fresh authoritative picker plan, one writer, closed metadata snapshot, data upload drain, an independent four-worker S3 proof before marker publication, a second independent proof after marker publication, and a read-only Pebble reopen. The generation 10–13 certificates form a continuous parent-hash chain from the already published generation 9. All four certificates report remote generation verified and read-only reopen verified.

| Generation | Prepublication proof | Postpublication proof | Read-only reopen | Certificate SHA-256 |
|---|---:|---:|---:|---|
| 10 | 52.640 s | 54.774 s | 5.508 s | 6a8d7fbbd46fa26102eafe3d803b1a65286d5331c9eaaa2a3656c3e51907c0fc |
| 11 | 51.659 s | 56.131 s | 5.509 s | c4cbad183a4646a148fe74275c4fab6dbfbf4abaf1501e814725913e80158b9a |
| 12 | 59.016 s | 55.142 s | 5.706 s | 10d0b19e80d9b449b9d8f6334414e5fd7a83bfb25117432a3d12acfa9d801fbe |
| 13 | 55.762 s | 56.509 s | 5.712 s | 2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774 |

The generation 10, 11 and 12 operator-review receipts explicitly admitted only the following individual unit. Generation 11 also retains the remote-command submission timeout reconciliation; no writer or stage was found after the timed-out submission, and the subsequent submission was explicit rather than an automatic replay.

## Finalization and fresh health

The writer stopped cleanly; its mount/socket are absent and cache retained. The original lab reader was restored and freshly reopened against the generation 13 certificate, with 93,697 referenced SSTs. The finalization completed at 06 November 2026 23:45:32 UTC and did not invoke another writer or mutate the journal.
A new read-only health check at 10 November 2026 06:49:06 UTC on 10 November confirmed the same reader PID 78502, production service PID 3786, and rclone RC PID 3905. Authenticated production RC showed zero queued uploads, active uploads, errors or cached bytes, with no space warning. Protected anchors and reader restoration are intact; production Kubo and walker remain inactive. The available cache space was 7.28 TB.

## Evidence and limits

Latest certificate SHA-256: 2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774. Protected state SHA-256: c1563e322c496ca479c26501ef3f8ae2b71091565ee8fa227e24b4292f2cd90c. The evidence index records the SHA-256 and sizes of the exported raw receipts. All original root-owned operation records remain on Rhea and were not changed by this publication.

These certificates prove the stated remote generation, SST lineage and read-only Pebble reopen for the disposable clone. They do not establish full block/pin completeness, cold-S3 throughput, crash recovery for all failure modes, format 14, or production cutover readiness. The nine-total rewrite ceiling is reached; any additional rewrite needs a separate reviewed policy change. There are still 93,686 marked SSTs.

Machine-readable evidence index: [rhea-batch2-evidence-index-20261110.json](evidence/rhea-batch2-evidence-index-20261110.json).
