# Reader bridge integration and partial crash rehearsal

Development base: `e8941f178ac3f7639e5fe1e8f8751e553312dcab`. **Not ready for
the first disposable-clone pilot. Not installed, deployed, or live tested.**
No Rhea, SSH, cloud, production, service, mount, database, commit, push or merge
operation was performed in this coding session. This document does not approve
any operation. The operator separately inspects and tests the reviewed artifacts.

The new `scripts/rhea_multi_sst_reader_bridge.py` is a concrete read-only host
guard plus durable, signed stop **proposal**. It deliberately does not implement
the historical controller's HostAdapter interface. No method can stop a service,
start a FUSE mount, launch Go, drain data, publish a marker, reopen a database or
certify gen14. Its CLI always exits 2 without constructing a host. Root trust
pins remain unprovisioned. None of the original pinned controller, inspector,
wrapper, lifecycle, certificate, cap9 journal or Go sources were edited by this
integration. Concurrent reader-preflight corrections in this worktree are
separate inputs; include them in any subsequent signed artifact review.

The certified parked reader is PID 78502, start ticks 5054051, boot
`6fc54ca7-d64a-4125-98fa-d0a728485237`. Its service name does not prove read-only
FUSE behavior: the concurrently corrected preflight pins the exact certified
command, which lacks `--read-only`, and its FUSE options include `rw`. The
executable SHA is
`dc1ec3109000e4d36c8d14efac6d4c4158d1b860853cb75c09dcc9f6dded420b`;
the bounded executable read is 64 MiB. No writable database open occurs here.

## Implemented integration

1. Validate the existing independent root deployment and installation signatures,
   complete artifact byte pins and baseline installed repository source pins.
   Require the bridge's own fixed installed path. A third deployment-key signed
   `bridge.json`/`bridge.sig` binds the exact new bridge bytes, development base,
   boot, both original manifest digests and the full protected-file inventory.
   The bridge also checks the decoder and enumeration scanner's protected bytes
   before importing the historical controller; these transitive files are absent
   from its baseline SOURCE_PINS table and must be installed separately.
2. Invoke the pinned historical reader health **child outside writer.lock**.
   Obtain its complete evidence and original kernel lock inode identity. Load
   the exact historical health library, which constructs its original runtime.
3. Take that runtime's historical exclusive writer.lock exactly once. Independently
   prove current-PID ownership of that exact inode using `/proc/locks` and a
   separate nonblocking contention probe. Invoke the pinned library's read-only
   `observe(..., phase='reader-restored')` directly. Never invoke its CLI, a
   second lock, or the writer-active full-clone guard under this lock.
4. Recheck the entire historical evidence chain and fresh health report against
   independent `/proc`, executable, command, cgroup, raw mountinfo, open users,
   retained cache device/inodes, protected file metadata, stop sentinel and
   writer-socket observations. Check full protected source/config/ledger/state
   bytes against the third signed manifest. Mandatory files are derived from
   the pinned historical context, not a caller-selected allowlist. Historical
   public production inputs retain their original owner/mode/alias policy and
   full byte pins; this does not claim they are root-owned. The health library
   authenticates production RC and validates frozen Kubo/walker and production
   mount identities. Independently recheck STS and bucket versioning through the
   historical lab credentials, and compare the existing admission identity.
   Recheck source, process, mount and lock identities afterward.
5. Optionally retain a signed proposal under the **same** lock. The separate
   strict proposal schema binds gen14, physical rewrite base9, exactly two units,
   exact gen13 state and initial Go plan digest, installed writer hash, both
   original manifests, bridge manifest and exact parked reader witness. A new
   admission scope signs all of these plus the full current observation and
   nonce. Fresh report timestamps are checked on every read but excluded from
   the stable signed identity, allowing independent signing before revalidation.
   Never invent a writer RC tuple for a parked reader.
6. Require a preinstalled empty root 0700 `reader-bridge-gen14` directory. Burn
   the admission nonce through the existing durable O_EXCL primitive while the
   current PID holds the shared lock. Retain the exact full intent, exact signed
   claim bytes, detached signature, locked observation, then `reader-stop-intent.json`.
   Every file is O_EXCL, 0600, file-fsynced, directory-fsynced and read back.
   The stop-intent explicitly says `executable=false` and `automatic_retry=false`.
   Existing/torn evidence refuses; no service action follows it.

The new proposal is **not** the historical Engine's schema-v2 intent. That
controller requires adapter `v2.1`; the root adapter is `v2.2` and its binding
requires its own version. The original controller/inspector are hash pinned.
A new separately reviewed controller version and new signed installation are
required; do not patch historical pins to make a candidate pass.

## Lifecycle gating matrix

All future irreversible clone actions must revalidate signed admission validity,
boot, current lock ownership, complete protected bytes, original gen13/cap9
journal, production freeze, retained caches and prior immutable receipts at the
action boundary. Each action needs its own O_EXCL 0600 file+directory-fsynced
intent **before** execution. Missing receipts are uncertainty, never permission
to repeat the action. The current implementation stops at the proposal boundary.

| Boundary | Required evidence/control | Current status |
|---|---|---|
| Reader preflight | Outside child followed by independent locked observation; exact source bytes, reader PID/start/boot/exe/argv, mount/cache, production and fresh lab cloud identity | Implemented; offline tested only |
| Signed intent | Independently pinned keys, three signed manifests, separate complete two-unit proposal, durable nonce under original writer.lock | Implemented as library; root installation absent |
| Old reader stop | Recheck exact sealed PID/start/boot/argv/cgroup and unit; one stop of `rhea-pebble-lab-reader-fast-mount-20261102.service`; never signal a replacement PID; prove original process and mount absent, no new users, caches unchanged; separate reset intent only for independently proven known exit143 state | Proposal only; no service execution |
| New writer mount | One launch of fixed `rhea-pebble-lab-full-clone-20261102.service`; pinned historical rendered unit/argv/config/remote/cache; original reader absent; authenticate new boot/PID/start/executable, raw FUSE identity and RC SO_PEERCRED/socket inode; retain cache admission | Refused; historical lifecycle start is gen9-only |
| Marker isolation | Prove every changed CURRENT/MANIFEST/format marker withheld throughout Go, close, snapshot, drain and proofs, including writeback expiry and restart behavior | Blocker; historical 2h writeback timer alone cannot prove withholding |
| Go child | Fixed installed path and independent binary/fixture SHA; root; same exact signed two-unit request; exclusive child identity; cooperative cancellation and continuously enforced freeCheck on every guarded operation; monitor watchdog and authenticated RC | No new CLI; multistep/main.go unchanged and disabled |
| Resource enforcement | Shared 256 MiB input, 512 MiB SST writes, 64 MiB metadata writes; 2 TiB reserve, 96 GiB cache, 768 MiB/256-file backlog; count metadata/close writes and fail on unknown counters | Go caps exist; complete active-backlog/host monitor absent |
| Close/snapshot | Exact child exit/process tuple, actual closed MANIFEST/SST/output hashes and per-unit intents/receipts; no writable recovery open | Controller model only; real host implementation absent |
| Data drain/stop | Separate data vs withheld-marker queues; exact authenticated writer; no errors/transfers/data backlog; immutable stop intent and proof of writer absence | Refused |
| S3 proof | Two fresh complete version enumerations, independent IDs, exact predecessor, before/final marker semantics and unchanged source/retirement checks | Pure verifier exists; live read client integration absent |
| Marker publication | Fsynced exact publication intent, rechecked input versions/bodies; controlled version-addressed publication; uncertainty remains manual | Refused |
| Reader reopen | Fresh read-only inspector plus actual closed metadata bytes, writer/mount/socket absent, new exact reader tuple and retained caches; keep Kubo/walker stopped | Refused; historical finalization only gen10–13 |
| Gen14 checkpoint | New immutable journal; one batch checkpoint; 9 prior physical rewrites plus actual one/two compactions = 10/11; do not count generation number as rewrite total | Controller model tests only |
| Crash reconciliation | Independent stopped host/process/MANIFEST/SST/version observations, signed retained evidence, exact original bodies; no replay, rollback, publication or repair | Read-only version reconciliation implemented; full host recovery remains manual |

## Exact original S3 version bodies and rehearsal

`scripts/rhea_multi_sst_version_snapshot.py` uses only version-addressed GETs
against the fixed disposable bucket/prefix. It requires independent metadata
pins (version ID, ETag, size, SHA), refuses latest/null versions, and checks GET
response identity. A dedicated empty evidence Store retains a durable snapshot
intent, exact raw chunks and a completion reference. Original bytes, including
binary data, line endings and ordering, are never reserialized. A partial capture
is preserved and cannot be recaptured in that directory. Do not use the original
cap9 state directory or the controller journal for this supplemental store.

`audit` reads retained raw bytes against independent pins. `reconcile` repeats
fresh version-addressed GETs and compares every byte without modifying the
store or cloud. It explicitly claims neither a full enumeration nor controller
readiness. This library constructs no SDK client and has no live CLI. It is not
yet part of a signed installed root artifact set.

The new tests simulate effects inside host methods **before** their receipts:
reader stop, writer mount start, first compaction MANIFEST fsync, queued data
with markers withheld, and successful publication followed by missing receipt.
They exercise the real immutable controller journal and real pure cloud verifier
using test-only hosts/clients. Repeated read-only inspection leaves evidence
unchanged and never replays the writer. A separate chunk-fsync crash preserves
the exact orphan bytes and forbids recapture. Existing tests also exercise all
15 controller phases, journal rename/fsync failures and partial batch accounting.
These are offline simulations; no host recovery qualification is implied.

## Authorized Rhea read-only acceptance — 10 November 2026

Separately from the bridge's offline-only tests, the authorized operator ran
the real, fixed-path historical health check and a staged root-only copy of the
reader preflight on Rhea against the **disposable full clone**, without stopping
the reader or starting a writer. The first probe exposed two assumptions:
the installed `/usr/bin/rclone` executable is **58,268,944 bytes**, exceeding
the old 32 MiB bound, and the certified 36-argument reader mount has no
`--read-only` flag (the FUSE mount reports `rw`). Replacing either finding
with a broad bypass would be unsafe.

The revised preflight now uses a **64 MiB maximum read**, pins the exact
reader executable SHA-256
`dc1ec3109000e4d36c8d14efac6d4c4158d1b860853cb75c09dcc9f6dded420b`,
and pins the complete command digest
`5f26b553381556118778c7499234cb1e2ffcd6d21ca2c51af43cf302cf6cd65b`.
The strengthened root probe **passed** with reader PID 78502 and evidence seal
`6f14276ec33c7f1466cf4d26c0273f118ccc2d14754ded557af2a660b0539840`.
It returned `controller_ready=false` and `admission=false`.
The private two-file test staging directory on Rhea was removed only after
exact SHA and ownership checks. The historical controller, root journal,
reader, production Kubo/walker, and Wasabi objects were not changed.
**This proves read-only acceptance of the preflight, NOT live qualification
of this bridge, a mount handoff or a two-SST rewrite.**

## Review and first-pilot blockers

The next review must supply independently pinned/signed fixture and executable
artifacts, an installed source tree including transitive decoder/scanner, complete
root byte inventory and bridge manifest, separate deployment/admission key pins
and validity windows, and the root 0700 evidence/nonce directories. Qualify the
bootstrap's import trust, durable storage and lock behavior on the real host.
No installer, signer, key generator or self-authorization flow is supplied.

Before **any** clone write, a new versioned controller/adapter and a genuine Go
entrypoint must resolve every refused row above, especially continuously enforced
monitoring, marker withholding and post-crash independent host reconciliation.
The multistep batch functions live in a `main` package; exporting/reusing them in
a separate command would also require changes to pinned Go sources. This change
does not create a wrapper that pretends to launch them safely.

Run full Python discovery and the existing isolated Go fixture/race harness from
this checkout. The new CI workflow runs Python on Ubuntu22.04/24.04, checks frozen
pins and disabled gates, and runs the existing Go fixture/race/vet/build harness
in scratch. Dependency downloads are restricted to CI's cache-priming step; the
harness itself sets GOPROXY/GOSUMDB off and copies the cache. CI has no deployment,
SSH, live credentials or host-operation job. No CI result is claimed until run.
