# Rhea Pebble multi-SST checkpoint pilot — 10 November 2026

Next source milestone: [reader-restored preflight and dry-run handoff planner](rhea-reader-restored-preflight-20261110.md),
on base `4b60910e7b5c901bae50c9dd69207f00b0e71eac`. It adds independent
reader evidence and proposed postconditions while keeping admission, handoff and
the production CLI disabled. **NOT DEPLOYED / NOT LIVE TESTED.**

## Status and scope

**Implemented as an isolated, offline-tested candidate. NOT DEPLOYED / NOT LIVE TESTED. No live controller, mount, bucket, production Kubo or walker has been changed.**

The certified disposable full-clone starting point is **generation 13, format 013, nine previously successful single-unit rewrites, 93,686 marked SSTs, 93,697 referenced SSTs, no pending operation**. Its certificate is `docs/evidence/rhea-batch2-000013-certificate-20261107.json`; the protected Rhea journal is not modified by this candidate.

Existing full-clone controller/verifier and historical certificates remain unchanged. All code in `cmd/pebble-format-v1/multistep/` is separately named; its `main.go` **refuses every CLI execution**. This is intentional: the separately named Python checkpoint engine and recovery inspector are offline-injected candidates; an installed root-owned authenticated host adapter is still absent. No unattended loop or auto-admission exists.

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

**Pebble's two compactions are not an atomic transaction.** The first can commit before the second errors, loses its process or cannot create an SST. A pending/failed/incompletely closed batch must therefore be inspected and reconciled to actual closed MANIFEST/SST state; it must **never automatically rerun** either unit or advance the journal from its last certificate on the strength of receipts alone. An interrupted write before receipt fsync can leave an unreceipted committed compaction. If a complete, independently proven checkpoint cannot be reconstructed, the supported lab recovery is to restore the disposable clone from the protected frozen source. The new independent recovery inspector implements conservative offline decisions; a qualified installed live recovery/admission adapter is not implemented.

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
2. Install and independently qualify the separate **root-only host adapter** for the Python controller contract and protected immutable deployment pins. It must prove installed binary/source hashes; boot/process/mount/cloud identities; reader-to-writer handoff; clean authenticated rclone queue; continuous cache/free-space headroom; and a single durable pending-stage journal before the first writer invocation. Do not reuse the old generation-to-rewrites equality assumption.
3. Independently qualify the offline inspector and implement the installed **crash/partial-batch recovery procedure** that either independently certifies actual closed state, safely recovers from the frozen copy or leaves the lab stopped for inspection. Simulate interruptions at every unit-intent, compaction completion, metadata flush and publication boundary without any writer replay.
4. Authorize one separately admitted **two-unit disposable clone** pilot (generation 14 only after reviewed policy transition), verify before/after S3 independently, publish markers in order, freshly reopen through the reader and verify unchanged production state. Retain the nine-unit historical ceiling and frozen production state until all prerequisite gates pass.
5. Compare real elapsed time, cache, upload backlog and SST byte amplification against the single-step baseline before changing the permitted batch size or attempting large-scale rewriting.

This is a working offline candidate for the core batching and verification algorithms, **not a production-ready migration controller or approval to modify the 7.082 TiB clone**.


## Guarded checkpoint controller milestone

**NOT DEPLOYED / NOT LIVE TESTED. Generation 14 is not admitted.**
`scripts/rhea_multi_sst_checkpoint_controller.py` now implements the ordered DI
engine. `scripts/rhea_multi_sst_recovery_inspector.py` is a separate read-only
inspector. Neither file contains an executable live host adapter, subprocess
launcher, SDK construction or live credentials. The Go main stays disabled, the
historical controller stays unchanged, and the historical cap9 is not amended.

The default CLI is `python3 scripts/rhea_multi_sst_checkpoint_controller.py`
(`status`). `preflight` reports the missing installation/admission qualification
and exits 2. `apply` always refuses: it first requires the exact fixed installation
`/root/.local/share/rhea-multi-sst-controller-v2/rhea_multi_sst_checkpoint_controller.py`, root ownership,
private modes and trusted parents, and then requires the unprovisioned exact
adapter digest and admission verification key. There is no flag, environment
variable, plugin import, test token or caller-selected state path that enables
it. Even copying these sources into that directory does not enable apply.

`inspect --evidence DIRECTORY` reads an offline retained attempt under an existing
exclusive lock. It creates no lock or receipt and does not change journal bytes.
Without an independent observer it always returns `preserve/manual-inspection` and exits nonzero; inspection output is not authorization to mutate.
An injected `RecoveryObserver` has only read/lock methods; it cannot invoke a
writer, publish a marker, restore a clone or install a certificate. Inspection is
safe to repeat; an interrupted apply has **no resume operation**.

The engine's exact sequence is:

1. Acquire store and host locks; independently authenticate the signed admission,
   immutable deployment/source/pins, exact idle legacy journal, reader identity
   and protected production/source guards. Only the exact anchored generation-13
   certificate can precede this generation-14 pilot. Admit one or two units.
2. Retain immutable intent; retain handoff intent before stopping the reader and
   sealing the authenticated writer mount with changed markers withheld. Retain
   writer intent before exactly one Go child attempt. Continuously monitor queue,
   free space/cache, source and process identity through the host contract.
3. Retain the child source process tuple (PID/start ticks/boot/executable), exit,
   monitor evidence, full Go report and actual raw Go intent/receipt files. Reject
   partial/error/unclosed reports. Snapshot closed metadata, output hashes and
   **all predecessor metadata bytes** before any publication.
4. Retain data-drain intent; drain only data/metadata while withholding changed
   markers; prove zero queue/transfers/errors and the exact writer mount stopped.
5. Call the existing real `verify_generation` algorithm with four-worker fresh
   enumeration in `before-markers` mode. Recheck exact publication input versions.
   Retain marker intent before publishing the exact changed marker set once.
6. Call `verify_generation` again in `final` mode with the **same predecessor,
   closed Go report, snapshot and output hashes**. No listing or proof-pass reuse.
   Retain reopen intent; authenticate the fresh read-only reader and require the
   existing `finalize_checkpoint` exact two-proof/reopen gate.
7. Retain the immutable certificate and atomically advance the new schema-v2
   journal to generation 14, pending null, batch count 1 in the certificate and
   physical rewrite total **9 + actual successful units (10 or 11)**. Never write
   the historical journal, certificate, deployment pins or protected source.

The single mutable `journal.json` is replaced using exclusive `journal.next`, file
fsync, rename and directory fsync. Each state also has an immutable exclusive
`stage-NNN.json` containing its predecessor state's SHA-256 and all receipt
hashes. Intents, receipts and stage records use exclusive creation, mode 0600,
file/directory fsync and readback in a 0700 owned directory. Closed and predecessor
metadata are retained as immutable hash-addressed binary chunks (at most 16 MiB
each), referenced by the snapshot/reopen receipts and bounded by the existing
metadata file/count/total limits. Chunks can be shared only after exact readback;
missing, corrupt or unreferenced orphan chunks require manual inspection. The complete stage
chain, phase order, preserved receipts and journal head must agree. A receipt or
stage stranded by interruption before journal rename causes manual inspection;
it is not silently adopted, overwritten or deleted. Compare-and-swap requires the
exact prior state SHA under the exclusive lock. Until certification, the journal
keeps generation 13, physical total 9 and pending generation 14; attempted physical
compactions are recorded separately in retained Go evidence. The stage chain does
not turn a failed Pebble compaction into an atomic transaction.

## Installation contract and operational readiness

`HostAdapter`, `RecoveryObserver`, `validate_provisioning_manifest`, fixed install
constants, immutable baseline `SOURCE_PINS`, and strict intent validation define
the executable contract. The manifest validator checks structure/bindings only;
it does **not** verify a signature or grant readiness. A future independently
installed provisioner must authenticate a detached signature from an independently
pinned key and verify actual artifact bytes/ownership, including the new Python
sources, adapter, writer, key, baseline sources under `INSTALL/sources`, deployment
and all protected guards. The admission signature must cover the entire immutable
intent, exact unit request, binary, installation, boot/mount/RC/process/cloud
identities, nonce and initial journal digest. The installed adapter must consume
the nonce durably and exclude the historical controllers with the same host lock.
The development engine trusts the injected contract implementation; its synthetic
host is **not** an authentication implementation.

Before any live admission, all of these remain required:

- [ ] Independent source/security review and green stacked-branch CI targeting
  `experiment/rhea-multi-sst-batch-20261110`.
- [ ] Independently provisioned root-owned private fixed installation, sealed
  controller/inspector/adapter/writer/source digests and signature key. No dynamic
  adapter loader or writable caller-specified live path.
- [ ] Real exact-version host adapter with authenticated reader/writer/RC/mount,
  protected source/production freeze checks, shared exclusive lock, durable nonce
  consumption and admission signature verification. **Partial read-only source
  implementation below; complete live integration remains UNIMPLEMENTED.**
- [ ] Qualified cooperative child monitor and stop protocol; per-unit interruption,
  lost receipts, power loss during fsync/rename, closing failures and reader
  restoration tested against disposable lab state.
- [ ] Real queue drain and marker withholding proven with 96 GiB cache, 2 TiB free
  reserve, 768 MiB / 256-file backlog and unchanged 256/512/64 MiB batch budgets.
- [ ] Independent read-only recovery observer reconciling actual local retained
  MANIFEST/SST/process state and fresh remote marker/version proofs. **UNIMPLEMENTED
  on the live host.** Restore procedure from protected frozen source rehearsed.
- [ ] Separately signed and authorized generation-14-only disposable pilot. No
  admission inferred from this PR; production Kubo/walker remain frozen.

## Interruption and recovery matrix

All decisions preserve evidence and never rerun either compaction, republish a
marker, roll back S3 publication or advance the journal. If independent complete
proof cannot be obtained, the supported lab outcome is restore from frozen source.

| Last evidence / failure | Decision and required next action |
|---|---|
| Missing guard, lock, process identity, source pin, signature or cloud access | `preserve/manual-inspection`; missing prerequisites never imply safety |
| Writer intent, lost process/report/first or second receipt | `preserve/manual-inspection`; actual commit count is unknown; no replay |
| Failed/partial/unclosed Go report without independent local reconciliation | `preserve/manual-inspection`; if independent proof unavailable, lab restore required |
| Independently reconciled partial/failed local MANIFEST/SST state | `restore-only`; inspector performs no restore and cannot finish a compaction |
| Go files differ, snapshot/output/lineage hash mismatch, missing previous metadata | `preserve/manual-inspection`; no publication or certification |
| Closed snapshot or data drain interrupted, nonzero queue/transfers/errors | `preserve/manual-inspection`; retain writer lifecycle evidence |
| Before-proof complete, no marker intent | A new read-only before-proof may confirm marker absence; still manual, no publication |
| Marker intent exists, publication failed/timed out/receipt lost | `preserve/manual-inspection`; marker may already be visible; publication is not reversible |
| Marker receipt exists but second full proof or read-only reopen missing | `preserve/manual-inspection`; never certify from a subset |
| Both distinct proofs, exact reopen, independent current guards/local files and fresh cloud/marker proof all agree | `certifiable-without-writer`; returns certificate digest for independent operator action only |
| Torn receipt/stage/journal rename, stale CAS, orphan file or concurrent run | `preserve/manual-inspection`; no automatic journal repair |

## Controller validation

The new focused suite uses a synthetic host and an independently modeled in-memory
versioned object store, while calling the actual existing decoder, fresh full
cloud proof and finalization algorithms. Synthetic anchors are patched only in
test memory; the shipping CLI and pin table have no test bypass. The suite covers
one/two units, ordering/drains, every durable phase failpoint, source/admission/
identity refusal, lost commit and publication receipts, independent recovery,
proof reuse, output/lineage mismatch, atomic-rename failure, torn/missing files,
concurrent exclusion, replay and unauthorized transitions.

Local validation results will be recorded below after final self-review. The new
`.github/workflows/rhea-multi-sst-controller.yml` runs the focused suite, full
Python unittest discovery, static compilation, frozen source pin checks and
whitespace checks. Existing Go CI is unchanged. Offline tests do not qualify
real host identity, Wasabi performance, publication interruption or root install.

## Signed root adapter source milestone (10 November 2026)

**NOT DEPLOYED / NOT LIVE TESTED. No generation-14 authorization.** This milestone
adds source and offline tests on base commit
`5e3130097c1f02de944bf17403912fcb3b365537`. The historical controller, inspector,
wrapper, certificates, source pins, Go entry point and existing CI remain byte
identical. Earlier references to a missing adapter mean a missing **qualified
installed integration**; the following safe library portions now exist.

`scripts/rhea_multi_sst_signed_admission.py` verifies detached **Ed25519**
signatures with the absolute `/usr/bin/openssl pkeyutl -verify -pubin -rawin`
executable. It requires a public-only Ed25519 SubjectPublicKeyInfo PEM, exact PEM
SHA-256, trusted executable ownership/permissions, and a 64-byte signature.
There is no Python cryptography dependency and no signing implementation. The
OpenSSL child receives a clean environment, disabled ambient OpenSSL config,
regular message/signature/public-key files in a private temporary directory,
no shell, no stdin and a deadline. No private key enters shipping code.

The exact signed message is the bytes
`RHEA-MULTI-SST-ADMISSION-v1`, followed by one NUL byte, followed by canonical
UTF-8 JSON: sorted keys, compact separators, no nonfinite numbers, one trailing
newline. Duplicate keys, unknown fields and alternate encodings refuse. Claims
bind the **SHA-256 of the entire canonical immutable intent**, the exact
historical generation-13 certificate (`2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774`),
cap9/pending null and exact legacy journal bytes; one/two requested units; Rhea
hostname and boot UUID; installed writer/controller/adapter/admission-module,
source-table, deployment and installation hashes; bucket and `rhea/` prefix;
actual mountinfo, process PID/start/executable/boot, root RC socket device/inode
and authenticated peer PID/UID/GID, services and cloud account/ARN/user identity.
The observed identities must equal the signed identities exactly.

Issued/expiry times are integer Unix seconds with no future skew allowance,
`issued <= now < expires`, at most 900 seconds lifetime, and the entire lifetime
inside independently provisioned key validity. A signer must generate **32
cryptographically random bytes** encoded as lowercase hex for the nonce. The
verifier rejects short/degenerate nonces; no verifier can infer actual entropy
from a single signed value. Signer randomness is an independent operational gate.

Production verification accepts no caller key/path/clock/ownership parameters.
It requires root and fixed `INSTALL/admission.pub`, root-owned 0600, regular,
single-link, with nonsymlink root-owned trusted ancestors. The compiled public-key
SHA-256 and validity are deliberately **unprovisioned**. Pure offline APIs accept
explicit test parameters; production calls never expose those parameters. Tests
use disposable OpenSSL Ed25519 private keys only inside test temporary directories
and remove those directories on completion; no key is committed or installed.

`RootHostAdapter.authenticate_admission` verifies a fixed `admission.json` and
`admission.sig`, then consumes its nonce **before** the engine could retain an
intent. Consumption requires the actual historical `RealHost.lock`, sharing
`/run/rhea-wasabi-lab/writer.lock` with prior controllers. In addition to the
wrapper's lock state, nonce code probes exclusion and checks `/proc/locks` for
the current PID's exclusive flock on that exact device/inode. Unknown or hidden
kernel lock evidence refuses. The independently provisioned
`INSTALL/consumed-nonces` must already be root-owned 0700. Traversal uses directory
FDs and `O_NOFOLLOW`; the nonce record uses `O_CREAT|O_EXCL|O_NOFOLLOW`, 0600,
file fsync, parent-directory fsync and readback. It retains claims/signature hashes
and the nonce. An existing name, including a symlink or partial record, is never
reused. Unknown/torn records anywhere in the nonce store block fresh admissions.
Failure after creation burns the nonce even before journal intent; there is no
automatic deletion, repair, rollback or retry. Durable replay protection assumes
the root store is preserved and not rolled back from a snapshot; disaster recovery
must preserve consumed evidence or revoke the old signing authority before reuse.

`scripts/rhea_multi_sst_root_host_adapter.py` validates **two independently signed
fixed-path manifests**, `deployment.json/.sig` and `installation.json/.sig`, using
`INSTALL/deployment.pub` with a separately provisioned compiled key pin and key
validity. This public key must differ from the admission key. Both signatures use
the `RHEA-MULTI-SST-DEPLOYMENT-v1` plus NUL domain and bind their distinct scopes,
issue/expiry, Rhea boot, fixed install path, base commit, exact artifact hashes,
source-table digest and exact initial legacy-journal digest. Installation also
binds the deployment's raw SHA-256. Actual artifact permissions/bytes, all frozen
sources and historical wrapper bytes are checked before module execution; the
historical controller/inspector also have immutable baseline pins. The wrapper
is loaded from its fixed historical root path by compiling the exact checked
bytes, pinned to
`76635430d99daa65a816dc1ae444145bbdfe844559b4b4bed2e30fbae0302545`.
There is no self-signing provisioner or unsigned-manifest readiness path.

Manifest hashes are measured from independently authenticated bytes and then
bound by admission. They are not embedded into adapter source hashed by the same
manifest, which would create an unsatisfiable hash cycle. For the same reason,
the existing intent's `admission_sha256` has a precise adapter interpretation:
the SHA-256 of canonical `{scope: "rhea-gen14-one-batch", deployment_sha256: D,
installation_sha256: I}`. It is an authorization-descriptor digest, not the digest
of claims which themselves hash the entire intent. The detached signature always
covers the full intent hash including this descriptor field.

Under the shared lock, `observe_host` revalidates the installation and exact
legacy journal, generation13/rewrites9/cap9/pending null, legacy deployment pins,
then calls the real pinned wrapper's `guard`, `no_open_users` and `observe`.
These perform actual protected rclone/config/ledger checks, production-unit freeze
checks, competitor/mount/process checks, fresh STS and bucket-versioning identity,
and peer-credential-checked Unix RC stats/queue requests. The adapter also binds
raw mountinfo, socket inode/device and PID start/boot/executable identity and
rechecks identities/journal after observation. Queue health is deliberately
limited to a **clean** authenticated queue: missing/malformed counters, pending
uploads/transfers/errors, out-of-space, >96 GiB cache or <2 TiB free all refuse.
It never interprets unavailable backlog bytes as zero for a nonempty queue.

The full-clone wrapper checks a previously admitted writable FUSE mount and
requires the separate reader service inactive. Its rclone PID is explicitly the
**mount process**, not proof of the controller's database reader. No method here
claims to qualify the separate reader handoff, all protected production source
bytes or a full remote generation/version proof. `preflight` and
`protected_guards` perform real observations and then **explicitly refuse** those
missing integrations. A successfully verified signature or host observation
therefore cannot make the controller ready.

| Capability / gate | Implemented source behavior | Operational status |
|---|---|---|
| Detached admission verification | Real OpenSSL Ed25519, strict binding/time/key checks | Offline tested; production key pin/validity absent |
| Independent deployment + installation | Two signed fixed-path manifests, actual byte/permission/source checks | Offline tested; no provisioner or trusted manifests installed |
| Shared writer exclusion + nonce | Historical RealHost lock, own-PID flock proof, exclusive durable record | Offline tested; root store/power-loss/host qualification outstanding |
| Host, legacy anchor, service, mount, process, RC, cloud identity | Real pinned read-only checks and exact signed comparison | No live commands executed; host/cloud qualification outstanding |
| Queue health | Authenticated clean-queue counters and free/cache bounds | Offline tested; continuous monitoring/backlog integration absent |
| Full protected-source and production byte guards | Explicit refusal after available observations | Blocker |
| Separate reader and writer handoff | Explicit refusal; no stop/start path | Blocker |
| Go child, continuous monitor, close/snapshot, data drain | Explicit refusal; no subprocess writer launch | Blocker |
| Marker publication, reader reopen/restart | Explicit refusal | Blocker |
| Independent recovery | Fresh locked host observation; manual finding only | Local MANIFEST/SST and cloud proofs absent; no certifiability |
| Controller/live CLI | Historical controller remains disabled; both new CLIs return 2 without host construction | NOT DEPLOYED / NOT LIVE TESTED |

`ReadOnlyRecoveryObserver` is independently read-only and rereads current host
state, rather than trusting retained success flags. It always supplies a manual
finding, has no mutation methods and explicitly refuses closed snapshot/cloud/
reopen proof. Passing it to the historical inspector cannot satisfy that
inspector's guard/admission/stop requirements and cannot yield certifiability.
An absent/stopped/changed mount or missing observation remains a refusal; this
observer does not reconcile a crashed batch or authorize restore.

Before enabling any library use on Rhea: independently review source and Python
bootstrap/import trust; provision separate offline signing authorities, fixed
public-key pins/validity and signed manifests; qualify strict root ownership,
lock contention, socket/process replacement, boot changes and durable nonce
behavior on the actual host/OpenSSL 3.0.13. Full protected-source/production byte
proof, separate reader identity/handoff, cooperative child supervision, marker
withholding/drain, per-unit crash recovery and independently scoped cloud proofs
remain blockers. No source flag or environment variable enables them. The
controller has no adapter loader, its installation/key sentinels stay unset, and
its live CLI remains disabled even if new trust files were copied into place.

The new `.github/workflows/rhea-root-host-adapter.yml` checks `/usr/bin/openssl`,
runs focused signed-admission/adapter suites and full Python discovery on Ubuntu
22.04/24.04, compiles the new sources/tests in memory, verifies frozen baseline
source/wrapper/controller/inspector pins and checks disabled/unprovisioned gates.
It changes no existing workflow and has no credentials, deploy or live job.
Local results below use OpenSSL 3.5.5; CI and real-host 3.0 qualification must not
be inferred from local results. These tests prove offline behavior only.
