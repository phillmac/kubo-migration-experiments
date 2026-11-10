# Reader-restored preflight and dry-run handoff planner

**NOT DEPLOYED / NOT LIVE TESTED. No installation attempted. No live observation,
SSH, deployment, writer, service transition, cloud operation, source/marker change
or journal change was performed. Production CLI remains disabled.**

This source milestone uses base `4b60910e7b5c901bae50c9dd69207f00b0e71eac`.
It separates observing the parked reader from the historical guard for an already
active writer. It does not enable a production handoff. The clone remains
format013, generation13, nine successful physical rewrites, pending null.
The historical nine-rewrite ceiling is unchanged.

## Evidence contract

[`rhea_multi_sst_reader_preflight.py`](../scripts/rhea_multi_sst_reader_preflight.py)
contains pure report/witness validators, an unsigned evidence seal, and a
two-observation planning state machine. Literal immutable expectations come from
the [archived health report](evidence/rhea-batch2-fresh-health-20261110.json),
[reader finalization](evidence/rhea-batch2-reader-finalization-20261107.json), and
[gen13 certificate](evidence/rhea-batch2-000013-certificate-20261107.json).

Required certificate SHA-256:
`2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774`.
Required state SHA-256:
`c1563e322c496ca479c26501ef3f8ae2b71091565ee8fa227e24b4292f2cd90c`.
Required state: **93,697 SSTs, 93,686 marks, 7,786,594,079,552 SST bytes**, exact
inventory, cap9, rewrites9, no pending operation, retained deployment/identity
pins, boot `6fc54ca7-d64a-4125-98fa-d0a728485237`, kernel `6.8.0-149-generic`,
original restored reader PID **78502**, start ticks **5054051**, same boot.
Restored receipt SHA-256:
`a306a23027ccaf1fd7f6c3a130af6723dea51f382ba780d0676d4435d5ab4b7f`.
Its canonical bytes equal the finalization's `reader` object. Reader restart,
reboot or kernel change requires separate reconciliation; caller replacements
never become trusted implicitly.

All **thirteen ordered generation certificates** have exact raw-byte pins and
predecessor checks, including the separately pinned failed-close bridge between
gen4 and gen5. Historical health reports only **four** `certified_stages`
(gen10–13); this suffix is checked exactly against the full chain and gen13
terminal lineage. The historical schema is preserved.

The exact known schema-1 fields are required. Unknown/missing fields, duplicate
JSON keys, nonfinite values, bool-as-integer substitutions, changed immutable
values, nonzero production RC counters, writer presence, missing retained caches,
non-disabled walker, or less than **2 TiB** free refuse. Report freshness is at
most **120 seconds**, with no future skew. Production service/RC process tuples
and identity hashes remain bound to retained freeze evidence. Source, restoration
and certificate bytes and independent process/mount evidence are required;
success booleans alone cannot establish a seal. Pure validation still cannot
authenticate who collected supplied bytes.

## Read-only root probe and lock boundary

`probe_reader_restored()` accepts no caller path, clock, environment or keys.
It requires root on Rhea and validates root-owned trusted nonsymlink ancestors,
single-link 0600 source/receipt/certificate/journal/pin files and exact byte pins.
Before and after the child it compares protected file device/inode/size/times,
cache directory device/inodes, PID/start/boot tuples independently read from
`/proc`, reader executable bytes, read-only command, service cgroup, and raw
mountinfo. Independent production service and RC process start times are checked.
Extra lab mounts and lab mount users through cwd/root/exe/fds/maps refuse.
Historical health additionally checks namespaces, service properties, protected
inputs, production freeze, authenticated clean RC and other lab users under lock.
The independent service check binds the process cgroup; it is not a second
systemd RPC implementation. Retained FUSE mount options contain `rw`; the actual
rclone command must have `--read-only`.

Exactly one possible child invocation exists:

```text
/usr/bin/python3 -I -B /root/.local/share/rhea-wasabi-lab-admin-20261101/pacing-batch2-20261107/health.py --phase reader-restored --reader-sha256 a306a23027ccaf1fd7f6c3a130af6723dea51f382ba780d0676d4435d5ab4b7f
```

Health source SHA-256 must equal
`2781718c06389a0753cc23b6ff39d97bac388f492399dbb1bb637d57dbf4db1e`.
Historical source is never imported or executed in the new module's interpreter.
The absolute interpreter is protected; the child has isolated imports, no pyc,
no stdin, a deadline, and only PATH/HOME/LANG/LC_ALL in its environment. Ambient
AWS/rclone/Python/proxy configuration is absent. The historical child may perform
its existing authenticated read-only checks using fixed protected configuration.
No probe was executed for this milestone.

**Do not hold `writer.lock` before invoking health.** The child takes that lock
itself. The probe only opens the existing lock read-only and examines kernel
`/proc/locks`; it never calls flock or creates the lock. Self-held/concurrent
locks refuse before child execution. A later contender must also pass the
historical child's exclusion; absence is not a reservation. Child observation
time must lie between real start/finish; wall and monotonic durations are checked.
Snapshots must agree before/after. There remains a gap after health releases its
lock. **Separate signed admission must revalidate identities and full protected
source bytes under the exclusive historical lock.** This seal cannot close that
gap or authorize work.

`RootHostAdapter(mode='reader-restored').observe_reader_restored()` verifies the
existing independent installation contract, then loads the new module from its
signed artifact pin outside `exclusive()`. The manifest artifact table now
requires `reader_preflight`; existing manifests cannot silently accept this
addition. Constructor keys remain unprovisioned. Reader observation does not
call the historical writer guard or require a writer mount. `observe_host()`
keeps its writer-active guard and refuses reader mode. Reader mode also refuses
preflight/protected-guard approval and signed admission. Reader process identity
is never substituted into writer-active signed claims.

## Unsigned seal and proposed handoff

The evidence seal binds the **exact raw report SHA-256**, fixed source/path and
restoration pins, reader PID/start/boot, raw mountinfo, independent witness hash,
gen13 state/certificate, rewrites9, pre-existing cap9 and observation time.
The pure transition intent includes both seals and exact preserved cache
identities. These hashes are not signatures, nonce consumption, authorization or
live handoff.

The planner revalidates two complete bundles with distinct increasing health
timestamps. Reusing one report twice refuses. States are `unobserved`,
`before-validated`, `after-validated`, `stable-reader-restored`, `plan-only-ready`,
or terminal `blocked`. Changed old reader PID/boot, production process, mount ID,
executable, protected file inode, retained cache, open user, stop sentinel, RC
backlog, live writer or stale report blocks the proposal.

`dry_run_go=true` means a proposal can be reviewed. All results still have
`admission=false`, `execution_allowed=false`, `controller_ready=false` and
`mutations_performed=false`. Six non-executable stages describe independent
review/admission, immutable intent retention, old-reader stop, separate writer
start with withheld markers, N2 pilot review, and final reader restoration, each
with explicit expected postconditions. No callback, service change, remount,
writer launch, publication, signer or journal writer is implemented.

Exact directories and their identities must be preserved:

- `/data/rhea-pebble-lab-reader-cache-fast-20261102`
- `/data/rhea-pebble-lab-real-cache-20261102`
- `/data/ipfs-wasabi-cache`

The separate offline CLI accepts `--verify-report FILE --evidence-dir DIR` and
labels success **not admission**. DIR is an exported `docs/evidence` directory;
source comparison uses the checked-out historical source without executing it.
It uses the current clock, so archived reports correctly refuse when stale.
Offline tests inject historical time only into pure APIs; no production clock
override or freshness-bypass CLI exists.

## Distance to production and S3 timing

This completes an offline reader-observation/planning gate. Production still
requires independent complete protected-source byte guard review, separate
signing authorities/key pins and fixed root installation, signed admission under
lock with durable nonce integration, qualified reader/writer handoff and monitor,
marker withholding/drain, per-unit interruption recovery and independent full
cloud/reopen proofs. Kubo/walker stay frozen. No live signer, root deployment or
installed handoff exists here.

The [gen10–13 results](rhea-second-bounded-batch-results-20261107.md) and operation
phase timings show why an N2 pilot is necessary, but cannot establish scalability
for **93,686** remaining marked files:

| Generation / evidence | Controller total | Writer | First full cloud proof | Second full cloud proof |
|---|---:|---:|---:|---:|
| [10](evidence/rhea-batch2-000010-operation-20261107.json) | 160.069 s | 11.911 s | 52.640 s | 54.774 s |
| [11](evidence/rhea-batch2-000011-operation-20261107.json) | 167.803 s | 12.170 s | 51.659 s | 56.131 s |
| [12](evidence/rhea-batch2-000012-operation-20261107.json) | 179.397 s | 12.362 s | 59.016 s | 55.142 s |
| [13](evidence/rhea-batch2-000013-operation-20261107.json) | 180.671 s | 11.699 s | 55.762 s | 56.509 s |

Each rewrite costs roughly **160–181 s** within the controller, **~12 s** for
the writer, and **~52–59 s** for each full S3 proof. Whole supervised one-step
operations include further overhead and took **172–204 s**. N2 tests amortizing
the two proofs over two successful units and its failure/recovery contract.
It remains too small for full production. At current one-mark-per-operation
controller timings, 93,686 operations imply roughly 174–196 days before added
overhead. This is illustrative arithmetic, not a throughput forecast. Separately
reviewed larger safe batches or proof amortization are required before full-corpus
production work. This change provides neither proof reuse nor a ceiling change.

## Offline validation

Tests use real archived health/restoration/certificate bytes and synthetic
independent witnesses. Host probes and children are mocked. Coverage includes
chain/bridge/source tampering, process/mount/cache replacement, freshness/replay,
RC/free-space failures, actual disposable flock contention, admission/nonce
separation and mutation/CLI refusals. Existing tests run unchanged.

The added CI workflow runs focused reader/adapter/signed-admission tests, the full
Python suite, AST read-only lint, static compilation, frozen source/certificate
pins and disabled/unprovisioned checks on Ubuntu 22.04 and 24.04. There are no
credentials or deploy jobs. Local results follow after final checks; CI and live
qualification remain separate gates.
