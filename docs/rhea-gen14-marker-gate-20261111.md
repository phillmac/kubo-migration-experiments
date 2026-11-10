# Rhea gen14 marker isolation and proof gate — 11 November 2026

**Draft, offline-only, not deployed.** This milestone adds independent marker queue, S3 version-history proof, and crash-recovery models. It does not authorize a clone rewrite, edit the historical cap9/gen13 journal, install IAM policies, or start/stop services.

## Crucial live blocker

The historical writable clone rclone mount has a two-hour VFS write-back. Its queue-set-expiry API can postpone a queued upload, but cannot stop one that has started. Polling/deferring after Pebble closes therefore cannot prove that publication markers stayed invisible. The model requires a separately enforced, authenticated process-independent pre-open PUT/COPY/DELETE denial for changed publication markers, bound to the exact disposable bucket and signed writer identity. The historical mount and this change DO NOT implement that denial. Wasabi supports S3 explicit Deny and wildcard object resources, so a distinct scoped writer IAM principal plus separately authorized publishing principal might supply it (https://docs.wasabi.com/docs/how-do-i-restrict-bucket-access-with-resource-based-policies). IAM propagation, queued dirty marker retries, re-denial and multipart behavior must be tested independently. No IAM changes were performed.

## Source and safety contracts

- scripts/rhea_multi_sst_marker_gate.py: strictly binds a two-SST closed batch to certified gen13 (format 013, nine rewrites, unchanged CURRENT, actual metadata, outputs and hashes). Changed CURRENT is forbidden in this pilot instead of being published as normal data.
- Strict timing policy with NO production defaults. Authenticated RC queue checks bind process/boot/mount/Unix socket/source/cache/cloud identity, strict file and byte caps, unique ID/name tuples, relative expiries, no premature uploading/retries, expiry deadlines, fail-closed monitoring and independent observation during long cloud scans.
- Synthetic OfflinePilot: durable O_EXCL 0600/fsynced one-shot selected expiry intents, data-first release, marker withholding, four-worker before/final complete S3 proofs, exhaustive marker-version-history checks, exact latest/version HEAD/GET body validation and no implicit replay after unknown RC outcome or missing receipt.
- RootQueueRuntime: read-only observation through the pinned historical RealHost and shared writer lock. All production mutation, admission, writer launch, expiry, publication and reader restoration methods deliberately REFUSE.
- scripts/rhea_multi_sst_marker_gate_inspector.py: independent read-only evidence reconciliation with fresh cloud checks, no writer replay, no republish, no rollback, no journal alteration. A reader service name alone cannot prove an actually read-only FUSE mount; Rhea's historical reader FUSE is rw.
- No historical controller, original file, certificate, cap9 journal, Go binary, credential, or production service changed.

## Test and future gates

The focused suite tests late/early queued uploads, changed queue ID, hidden marker version, state/identity swaps, stale/slow polling, unknown expiry mutation, crash after intent or after RC, partial publication, HEAD/GET mismatch, full-proof identity mismatch, wrong reader reopen and an immutable recovery inspector. A passed OFFLINE suite does not constitute live admission. New CI runs focused and full Python regression tests plus frozen source/disabled entrypoint checks.

Before the first real generation-14 two-SST clone test we still need (1) independently installed and tested pre-open marker write denial; (2) a new signed root controller, separate read-only-reader handoff and actual Go writer entrypoint; (3) continuous live monitoring, preserved cache, durable close and data drain; (4) both independent complete Wasabi version proofs, one-shot publication and read-only reader reopen; (5) fail-closed independent crash reconciliation. Production Kubo/walker must stay stopped; the original generation-13 checkpoint and cap9 remain intact.
