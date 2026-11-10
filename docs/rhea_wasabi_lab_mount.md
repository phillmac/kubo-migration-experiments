# Guarded Rhea Wasabi lab mount

`scripts/rhea_wasabi_lab_mount.py` is an admission and lifecycle wrapper for two
fixed, disposable Rhea laboratory mounts. It never invokes Kubo, starts a
migration, or changes the production mount. Its checks are deliberately specific
to the 2 November 2026 laboratory baseline. Arbitrary buckets, remotes, prefixes,
mountpoints, cache paths, credentials, and rclone binaries are not supported.

This change supplies code and mocked, offline tests. It is not deployment or
permission to start a live mount. A separately authorized operator must review
the code, stage its dependencies on Rhea, and decide whether live execution is
allowed. Do not infer live validation from the unit-test results.

## Fixed profiles

Both profiles use bucket `rhea-pebble-lab-20261101-39037c6f01` in region
`ca-central-1`, through rclone remote `rhea_pebble_lab`.

| Setting | `full-clone` | `resume-fixture` |
| --- | --- | --- |
| Remote suffix | `rhea` | `__rhea_pebble_resume_probe_20261102` |
| Mountpoint | `/mnt/rhea-pebble-lab-writable-20261102` | `/home/ubuntu/pebble-recovery-analysis/kubo-lab-rhea-resume-20261102/run` |
| Persistent cache | `/data/rhea-pebble-lab-real-cache-20261102` | `/data/kubo-lab-rhea-resume-cache-20261102` |
| VFS cache size target | 96 GiB | 512 MiB |
| VFS write-back delay | 2 hours | 30 minutes |
| systemd unit | `rhea-pebble-lab-full-clone-20261102.service` | `rhea-pebble-lab-resume-fixture-20261102.service` |
| RC socket | `/run/rhea-wasabi-lab/full-clone.sock` | `/run/rhea-wasabi-lab/resume-fixture.sock` |

The full remote is `rhea_pebble_lab:<bucket>/<remote suffix>`. These are exact
values, not templates accepting user substitution. Identity checks accept the
exact remote or rclone's configuration-hash spelling
`rhea_pebble_lab{<safe suffix>}:<exact bucket>/<exact prefix>`. The suffix is
1–64 base64url characters (`A-Z`, `a-z`, `0-9`, `_`, `-`); an initial underscore
is optional. Observed spellings include `{_9Ic9}` and `{Dn7qA}`. The decoration
never permits a different bucket or prefix. The cache size is an rclone
eviction target, not a hard limit on dirty or peak disk use. Preflight and start require
at least **2 TiB free** on the cache filesystem. Status, clean stop, and selected
queue-expiry changes retain the identity checks without this admission floor, so
low-space or out-of-space conditions can still be diagnosed and drained. An independent migration controller
would still need write budgets, backlog limits, and ongoing disk monitoring.

The full-clone mount alone uses `--use-server-modtime`. This uses S3's server
modification time and avoids a custom-mtime HEAD request for every SST stat
during Pebble's consistency check. It does not bypass Pebble's file-existence or
size checks. The full-clone mount also sets `--dir-cache-time 12h`: a cold
directory listing can hold rclone's directory mutex long enough to block an RC
statistics request, so long guarded stages retain the listing across the
default five-minute expiry boundary. The first cold listing still needs to
finish before a monitored Go open. RC timeouts, independent S3 verification,
writeback, cache size, and all resource limits are unchanged. The resume-fixture
command is unchanged.

The only permitted credential source is the root-owned, mode-0600 file:

```text
/root/.config/rclone/rhea-pebble-lab-20261101.conf
```

It must identify only the approved laboratory remote and IAM user
`rhea-pebble-lab-20261101`. The S3 bucket is signed in `ca-central-1`,
while the global Wasabi STS endpoint is separately signed in `us-east-1`;
using the S3 region for STS returns `AuthorizationHeaderMalformed`.
STS identity acceptance allows only the exact lab username at IAM's root path
or the explicitly provisioned `/experiments/` path; other paths and root
identities are rejected.
Host root credentials, environment credential fallback,
instance credentials, alternate profiles, and root IAM credentials are not valid
substitutes. Keep credentials out of command arguments, documentation, and logs.
The wrapper does not change global rclone or Codex configuration.

The rclone executable is pinned to:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/rclone-v1.68.1
SHA256 3afdc72c395651badd72426cc218b0420249ceb10960c03b539939e56e60bf2e
```

It is a Rhea-only copy of rclone 1.68.1, staged into a trusted root-owned store.
The supplied original remains at
`/home/ubuntu/pebble-recovery-analysis/lab-rclone-tooling-20261102/rclone-v1.68.1`.
The wrapper verifies the trusted copy's bytes and path rather than using a global
`rclone` from `PATH`.

## Commands and dry runs

Run from the reviewed checkout as root on the intended host, after separate
operator authorization. A profile is required on every command:

```console
python3 scripts/rhea_wasabi_lab_mount.py preflight --profile full-clone
python3 scripts/rhea_wasabi_lab_mount.py start --profile full-clone
python3 scripts/rhea_wasabi_lab_mount.py start --profile full-clone --apply
python3 scripts/rhea_wasabi_lab_mount.py status --profile full-clone
python3 scripts/rhea_wasabi_lab_mount.py stop --profile full-clone
python3 scripts/rhea_wasabi_lab_mount.py stop --profile full-clone --apply
```

Use `--profile resume-fixture` for the isolated resume probe. No other profile is
accepted. `preflight` is read-only. `start`, `stop`, and `queue-expiry` default to dry-run mode and
require `--apply` to change the laboratory service. A dry run can still read local
host state and perform read-only Wasabi requests; it is not an offline simulation.
All required checks must pass before an applied operation proceeds. Repeating an
old preflight result does not replace checks immediately before execution.

`status` verifies the selected service, process, mount, and root-protected RC
socket before requesting `vfs/stats` and `vfs/queue`. Treat an unavailable socket,
unexpected response schema, wrong filesystem identity, or failed dependency as a
refusal, not as an empty queue.
Status also returns the authenticated rclone `pid`; queue IDs are valid only for
that process instance.

`stop --apply` requires zero pending uploads, zero uploads in progress, zero
errored files, an empty queue, and `outOfSpace=false`. It refuses dirty or
ambiguous state. It does not expedite uploads, discard pending writes, or provide
a force option. It also verifies there are no processes using the mount. VFS
`inUse` alone is not an open-user check: an idle instance can report 1, and that
counter does not prevent a clean stop. After rechecking users and queue state,
applied stop sends `core/quit` with `exitCode=0` through the authenticated,
root-protected Unix RC socket and waits for service exit and unmount. It does not
use `systemctl stop`. Resolve an upload failure using a separately reviewed
recovery procedure, then inspect status again. The persistent cache is
retained after a clean stop and must not be removed to make a refusal disappear.

The final service observation reads active/substate, MainPID, Result, and exit
fields together. Clean shutdown requires `inactive/dead`, `MainPID=0`,
`Result=success`, `ExecMainStatus=0`, the exact bound unit, and no remaining mount
or RC socket. `ExecMainCode=1` is a retained normal-exit result; `ExecMainCode=0`
means no wait status is retained (for example after manager cleanup), **not** a
literal normal-exit assertion. Zero is accepted only with the preceding
acknowledged `core/quit(0)` and clean-queue/user checks plus all final conditions.
Signal, failed, nonzero-status, unknown-code, or still-running outcomes are refused.

### Selected closed-file queue expiry

Only the full-clone profile supports this narrowly scoped operation. Take the
exact `pid` from status and the exact `id`, `name`, and `size` from its queue:

```console
python3 scripts/rhea_wasabi_lab_mount.py queue-expiry --profile full-clone \
  --pid <observed-pid> --id <observed-id> --name pebbleds/<observed-file> \
  --size <observed-bytes> --expiry expedite
```

Add `--apply` only to execute the reviewed selection. `expedite` sets expiry to
`-1000000000` seconds from now; `defer` sets it to `86400` seconds from now. These
are the only choices; the caller cannot supply an RC endpoint, filesystem,
arbitrary parameters, or another duration. The pinned rclone 1.68.1 API defines
expiry in seconds **from now**, not as an absolute Unix timestamp.

The wrapper requires a valid admission journal, the expected active peer PID,
no process using or mapping the mounted database, and one unambiguous live queue
entry matching the supplied ID, filename, and size with `uploading=false`. Only
recognized `pebbleds/` SST, WAL, MANIFEST, OPTIONS, CURRENT, and Pebble marker
filenames are accepted. It repeats the selection and closed-user checks under
the writer lock, pins that PID through the authenticated Unix-socket request,
and refuses a restarted instance. No batch-wide expiry, forced upload, discard,
or automatic retry is provided. Already uploading files cannot be deferred;
natural queue expiry can race an operator, so inspect the queue and independent
S3 evidence after each operation. A successful request is not a verified upload
or checkpoint. The migration controller remains responsible for publication
order and independent verification.

## Admission checks

The production invariants are:

| Service | Required state |
| --- | --- |
| `rhea-ipfs-wasabi-kubo.service` | inactive |
| `rhea-broken-pin-walk-20261026.service` | inactive |
| `rhea-ipfs-wasabi-rclone-mount.service` | active |
| `rhea-pebble-lab-reader-fast-mount-20261102.service` | inactive before `full-clone` |

The verified Rhea host currently has no installed unit named
`rhea-ipfs-wasabi-kubo.service`: systemd reports `LoadState=not-found`,
`ActiveState=inactive`. The wrapper accepts **only this specific absent
Kubo unit**, and only after inspecting active `ipfs`/`kubo` processes'
arguments, environment, and open file descriptors for references to
`/home/ubuntu/.ipfs-wasabi`. This does not prohibit the separate regular
IPFS daemon on `/data/ipfs`. The pin walker still must be loaded and
inactive; active or unexpected service states always fail closed.

The wrapper only observes production services. It must never stop, restart,
reconfigure, or replace the production rclone mount. It also does not stop the
read-only lab reader on an operator's behalf. Unexpected service states and a
concurrent lab writer cause refusal.

Local checks reject substituted or unsafe paths, symlinks, unexpected mount
sources, an unexpected nonempty mountpoint, unsafe configuration permissions,
changed executable bytes, and insufficient cache free space. Mountpoint and cache
leaf directories must be root-owned and mode 0700. Every checked path ancestor
must be root-owned and have no group or other write permission, including the
`/home/ubuntu` ancestry used by the fixed resume-fixture mountpoint. This is an
explicit provisioning gate; the wrapper does not repair ownership or permissions.
A selected active mount must match its approved remote, target, service process,
and RC identity; matching a directory name alone is insufficient.

Only `start --apply` stages directories and its root-owned unit in
`/run/systemd/system`. The generated unit is started explicitly and never enabled
for boot. It uses `Type=simple`; the wrapper explicitly waits for the correct
mount in the host mount namespace before declaring start successful. It has
explicit resource bounds and uses a root-protected Unix RC
socket under `/run/rhea-wasabi-lab`. A shared `writer.lock` in that directory
serializes lifecycle operations across both profiles. Socket ownership and the
systemd service identity are checked before sending RC requests. There is no
public TCP RC listener. The unit explicitly sets `PrivateTmp=no` and must not
hide the FUSE mount from its intended host namespace. Runtime and service
artifacts are separate from persistent cache data.

Missing Python modules, executables, unreadable evidence, malformed responses,
and command failures cause refusal. The wrapper does not install software,
download dependencies, search for alternative credentials, or weaken a check to
continue.

## Independent baseline evidence

The approved compressed VersionId ledger is:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/wasabi-lab-baseline-version-ledger-20261102.jsonl.gz
SHA256 38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96
```

The expected original `rhea/` generation contains 93,707 objects, including
93,697 SSTs, totaling 7,786,625,086,413 bytes. Its `rhea/pebbleds/CURRENT`
contains exactly `MANIFEST-47475278` followed by one LF byte.

The wrapper requires Python 3.10 or newer and boto3, plus the expected host
systemd and FUSE tooling; missing dependencies cause refusal rather than
installation. Verify Rhea's Python version before attempting live preflight. It uses
explicit boto3 clients independently of the mount and its VFS cache, extracting
only the approved config credentials. S3 uses
`https://s3.ca-central-1.wasabisys.com` and STS uses
`https://sts.wasabisys.com`, without ambient credentials or proxy fallback. S3
bucket versioning must be enabled. STS `GetCallerIdentity` must identify
the approved laboratory IAM user and must not identify a root principal. Ledger
validation binds the local evidence to the exact compressed-file SHA256 and
rejects malformed or unexpected entries. Entries use `Key`, `VersionId`, `Size`,
and `ETag`, or the corresponding lowercase aliases `key`, `version_id`, `size`,
and `etag`. Counts, SST counts, and aggregate bytes must match the fixed baseline.
For **first admission**, the complete latest-object inventory from `ListObjectVersions` must match all
93,707 ledger entries. Critical HEAD checks address both latest and pinned
versions of the original `CURRENT`, its active MANIFEST, repository `version`,
and `datastore_spec`; a versioned GET also checks the exact CURRENT bytes. A
modified, missing, deleted, or replaced baseline object is a refusal before
first admission. The cache must also be absent or empty at first admission;
an unexplained existing VFS cache must not replay writes immediately after an
otherwise correct cloud-baseline check.

### Durable admission and mutation-aware management

The original VersionId ledger is never modified. A first applied start records
that baseline admission in a separate, root-owned mode-0600 journal:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/admissions/full-clone.json
```

The fixed resume-fixture profile uses `resume-fixture.json` in the same directory.
The containing directory is root-owned mode 0700 and passes the same trusted
ancestor checks. The record binds the exact profile, remote, region/endpoint,
mountpoint, persistent cache, unit name and rendered-unit SHA-256, pinned rclone,
configuration and baseline-ledger fingerprints, and the admitted IAM identity.
The rendered-unit digest includes the RC socket, cache settings, writeback delay,
and resource limits. Malformed, duplicate-field, oversized, substituted, or
improperly owned journal files are refusals, never permission to readmit a clone.

Under the writer lock, start checks the exact baseline, stages its fixed unit,
rechecks admission, and durably records admission **before launching rclone**.
The journal file is fsynced, atomically renamed, and both the containing directory
and its parent are fsynced. Preflight, status, and dry-run start do not create a
journal. A failed launch preserves the journal and cache for controlled
continuation. An active mount without a valid journal is refused.

Once admitted, later starts and management verify the same protected inputs,
exact admitted IAM identity, enabled bucket versioning, service/process/mount/RC
identity, conflicting writers and relevant queue checks. They allow the lab's
latest objects to differ from the original ledger: new MANIFEST versions and
obsolete-object delete markers are expected during migration. They do not repeat
the unchanged-baseline inventory check or clear a nonempty persistent cache.
Preflight and start still require the free-space reserve; status, clean stop,
and selected queue draining do not require that reserve.

The journal is explicitly an **admission record, not a checkpoint certificate**.
Its presence does not establish database consistency, remote upload durability,
or successful migration. An inactive, unadmitted status only checks identity and
host state; it is not a baseline preflight. Independently certify each new closed
generation's MANIFEST, referenced SSTs, WALs and markers, retaining separate
progress/evidence records. Never remove a journal or rewrite the frozen ledger
to force a modified clone through first admission.

`resume-fixture` uses its separate probe prefix; checking the original `rhea/`
baseline does not move the fixture into that prefix or authorize modifying it.
The wrapper does not upload objects, repair a ledger, change versioning, or
restore S3 versions during preflight.

## Trusted local staging gate

An already admitted full-clone deployment needs a reviewed one-time transition
when adding a fixed unit option such as `--use-server-modtime` or
`--dir-cache-time 12h`, because the rendered unit digest changes.
Close all Pebble clients, verify no pending/in-progress/errored writes and no
out-of-space condition, and cleanly stop/unmount using the existing wrapper and
its exact previously admitted unit. Under that wrapper's writer lock, verify the
old journal's `unit_sha256` against the known old unit before deploying the
reviewed replacement. Preserve protected backups and a transition receipt;
change only the journal's `unit_sha256` binding alongside the reviewed unit/code.
Keep every other admission field and the persistent cache unchanged. Stop on
unexpected state or digest mismatch. The wrapper neither performs this
transition automatically nor provides a general reconfiguration/readmission
command; an active or dirty mount is not eligible for the transition.

When the stage controller has already recorded progress, the same stopped,
reviewed transition must also update its bound wrapper/controller source hashes
and deployment pins. Preserve its certified checkpoint, generation, rewrite
count, and absent pending stage. The exact fields and installation ordering are
described in `rhea-full-clone-stage-controller.md`; this is not a new admission
or a reset of migration progress.

The following are installation instructions for a separately authorized live
operator; they were not executed while authoring or testing this change. First
verify that `/root`, `/root/.local`, and `/root/.local/share` are root-owned,
nonsymlink directories without group or other write permissions, and that the
trusted store and destination files are absent or already match this policy.
Do not replace a substituted path. Copy the supplied Rhea originals into that
store and verify the **destination** bytes before invoking the wrapper:

```sh
set -eu
install -d -o root -g root -m 0700 /root/.local/share/rhea-wasabi-lab-admin-20261101
install -o root -g root -m 0700 \
  /home/ubuntu/pebble-recovery-analysis/lab-rclone-tooling-20261102/rclone-v1.68.1 \
  /root/.local/share/rhea-wasabi-lab-admin-20261101/rclone-v1.68.1
install -o root -g root -m 0600 \
  /home/ubuntu/pebble-recovery-analysis/controlled-quiesce-user-20261031/rc-mount-deployment-20261101/wasabi-lab-baseline-version-ledger-20261102.jsonl.gz \
  /root/.local/share/rhea-wasabi-lab-admin-20261101/wasabi-lab-baseline-version-ledger-20261102.jsonl.gz
printf '%s  %s\n' \
  3afdc72c395651badd72426cc218b0420249ceb10960c03b539939e56e60bf2e \
  /root/.local/share/rhea-wasabi-lab-admin-20261101/rclone-v1.68.1 \
  38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96 \
  /root/.local/share/rhea-wasabi-lab-admin-20261101/wasabi-lab-baseline-version-ledger-20261102.jsonl.gz \
  | sha256sum --check --strict
```

Stop on any copy or digest failure. This staging does not move the resume target:
its `/home/ubuntu` ancestors still require explicit root-owned, non-writable
provisioning before that profile can pass. The wrapper never changes those
ancestors automatically. Provisioning must account for other host users and
processes; do not change a shared home directory as an incidental workaround.

## Original generation and deployment gates

An admission check is a point-in-time validation. A writable mount can modify or
delete objects once another process accesses it; bucket versioning preserves old
versions but does not keep the latest generation unchanged. The earlier
[format-3 demonstration](wasabi-format3-marker-checkpoint-20261102.md) observed
obsolete-file deletions reaching S3 before replacement files left the VFS queue.
An empty queue and FUSE `fsync` are therefore insufficient proof of a recoverable
checkpoint. Do not treat a successful mount as permission to run Pebble or Kubo
against the original generation.

Before any live use, the operator must independently confirm the host, exact
lab-only IAM policy, pinned executable, root-only configuration, local ledger,
service states, free-space reserve, and absence of other lab writers. Review the
generated unit and namespace behavior for Rhea's systemd/FUSE versions. Confirm
that the intended rclone supports Unix RC sockets and the RC schemas exercised
by the wrapper. These are deployment gates; mocked tests do not establish them.

Any migration or publication controller requires separate authorization and
review. Preserve the original generation and its ledger; operate on a separately
addressable generation; verify complete closed data and marker order directly
through S3; download and reopen a checkpoint independently before advancing.
Neither automatic migration nor Kubo invocation is part of this wrapper.

The earlier [persistent-cache resume demonstration](rhea-wasabi-scratch-paced-restore-retry-20261102.md)
covered an orderly stop of a small scratch fixture. It did not prove power-loss,
hard-crash, network-outage, or 7 TiB migration recovery. Preserve the same exact
cache and identity for any separately approved resume exercise.

## Offline verification

The accompanying `tests/test_rhea_wasabi_lab_mount.py` replaces network and host
interactions with mocks and temporary staging directories. Run it locally with:

```console
python3 -m unittest discover -s tests -p 'test_rhea_wasabi_lab_mount.py'
```

The tests exercise refusal and lifecycle behavior without SSH, Wasabi access,
real systemd changes, mounting FUSE, or invoking Kubo. Formatting and existing
repository tests should also pass before a local commit is considered ready for
review. No test result authorizes deployment or production cutover.

The mutation-aware regressions exercise the real guard with mocked host/cloud
boundaries: a changed baseline fails first admission, while admitted status and
clean shutdown accept changed latest versions and delete markers; dirty/error
queues remain visible and still prevent ordinary stop. Additional tests cover
journal binding/durability, first-start cache refusal, continuation cache
preservation, low-space management, and closed-file queue tuple/PID checks.
