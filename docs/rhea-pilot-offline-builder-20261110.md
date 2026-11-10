# Executable offline acceptance; signed root gate inactive

This change is **NON-DEPLOYABLE / NOT LIVE TESTED**. It adds an executable
on-disk exercise of the existing `runBatch`, with two sequential real SST
rewrites, and a pilot command which unconditionally refuses writable use.
It does not complete the Rhea writer or root HostAdapter. No command here
stops a reader, starts a mount, contacts S3, publishes a marker, or installs
anything. Production cutover remains out of scope.

The parent is `e5420cac0b20cb8e78e6ea785b4fcdad6787ae03`. Historical
`multistep/*.go`, `patches/demo_single_rewrite.go`, controllers, reader bridge,
root adapter, installed artifacts and cap9 journal are unchanged. The normal
`go build ./multistep` still builds its original exit-2 command. There is no
controller adapter loader, test flag, environment switch or signed-admission
claim that enables the new command to write.

## Build inputs and isolation

`scripts/build_rhea_pilot_offline.py --check-sources` works without Go. The
canonical `pilot/inputs.lock.json` records known SHA256 values for every local
source consumed by the assembly and independent verifier, including the
unchanged historical entrypoint. It checks the complete historical Go file
set and new source-artifact set, refuses symlinks and changed bytes, and retains
the checked bytes for copying. The reviewed checkout and lock are its trust
anchor; a mutable caller-supplied manifest is not supported. New changes require
independent source review and explicit lock updates; there is no regenerate-pin
or trust-current-cache mode in the builder.

The dependency bundle keeps the Pebble v1.1.3 release's complete `go.sum` and
explicit dependency versions from its `go.mod`. Its only additions are the
exact Pebble dependency and checksums. Origins:

- [Pebble v1.1.3 go.mod](https://github.com/cockroachdb/pebble/blob/v1.1.3/go.mod)
- [Pebble v1.1.3 go.sum](https://github.com/cockroachdb/pebble/blob/v1.1.3/go.sum)
- [go-ds-pebble v0.4.1 checksums](https://github.com/ipfs/go-ds-pebble/blob/v0.4.1/go.sum)

Pebble's source checksum is
`h1:GM5YY3Yb09KCGUQoyWdi3vsLErXHsmc3qRRWsX+tBqw=` and its go.mod checksum is
`h1:4exszw1r40423ZsmkG/09AFEG83I0uDgfujJdbL6kYU=`. These are SHA256 directory
digests, using the Go [Hash1 algorithm](https://github.com/golang/mod/blob/v0.20.0/sumdb/dirhash/hash.go):
SHA256 of ordered rows containing each file's SHA256 and name. ZIP container
timestamps/compression are not part of source identity. The builder additionally
records the raw ZIP SHA256 it actually read.

The builder reads only cached ZIPs and go.mod graph inputs. It verifies the h1
SHA256 values itself before extracting, rejects duplicate/traversal/symlink
members and excessive sizes, ignores the caller's expanded cache and ziphash
claims, and reconstructs a private cache. Pre-module releases' synthesized
go.mod files require their separate pinned checksums. Only authenticated modules
may supply compiled packages. Older go.mod-only entries can supply graph inputs,
not unpinned compiled source. A missing dependency refuses without downloading.

It copies the checked multistep files into temporary storage, omits `main.go`,
and injects `pilot/src/pilot_main.go` and `pilot_disk_test.go`. Those source-only
artifacts carry `//go:build ignore`; the builder removes exactly that prefix in
the temporary copy. The actual Pebble v1.1.3 source is copied separately and the
exact historical `demo_single_rewrite.go` is injected without editing either
original. A generated relative replacement points exclusively at that copy.
The build report hashes the transformed sources and patch. No `go mod tidy`,
dependency upgrade, historical formatting edit or live binary invocation occurs.

Every Go invocation uses `GOPROXY=off`, `GOSUMDB=off`, `GOVCS=*:off`,
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, readonly modules and private module,
build and temporary caches. Child environments come from an allowlist, dropping
credentials, proxy settings, GOFLAGS overlays and test child selectors. The
script has no network/priming implementation. It sets a two-thread build limit
and subprocess deadlines. Temporary assemblies/caches/DBs are removed on normal
completion and exceptions; after abrupt machine loss, leftover scratch is
untrusted and must never be reused as admission or recovery evidence.

This is hermetic **source/module assembly**, not signed toolchain attestation.
Linux/amd64 Go 1.24.x, its standard library, C compiler/linker, Python runtime and
OS are independently trusted build prerequisites. The report measures the Go
executable hash/version; it does not authenticate the complete toolchain. Binary
SHA256 is an observation of this exact build, not an independently signed root
installation pin or a claim of reproducibility across toolchain patch releases.

## Development/CI invocation

Do not run Go on the jump box or Rhea. On the EU development host, use a
resource-bounded `golang:1.24` Podman container if needed. The new CI workflow
performs the following two deliberately separate operations on a disposable
Ubuntu runner with Go 1.24. No deployment job, secrets or privileged host mount
is present. Network isolation of the build container (`--network=none`) is an
additional boundary when running in Podman; Go's dependency downloader is already
disabled inside the builder.

Explicit cache priming (network permitted only here), in a **new scratch
directory**, with a separately provisioned toolchain:

```bash
umask 077
mkdir "$scratch/prime"
cp cmd/pebble-format-v1/pilot/deps/go.mod cmd/pebble-format-v1/pilot/deps/go.sum "$scratch/prime/"
cd "$scratch/prime"
GOWORK=off GOENV=off GOTOOLCHAIN=local GOFLAGS= \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  GOPATH="$scratch/gopath" GOMODCACHE="$scratch/modules" \
  GOCACHE="$scratch/prime-build-cache" go mod download
```

Then, from this worktree, with that cache mounted read-only if containerized:

```bash
python3 scripts/build_rhea_pilot_offline.py --check-sources
python3 scripts/build_rhea_pilot_offline.py \
  --go /usr/local/go/bin/go --module-cache "$scratch/modules" \
  --output "$scratch/pilot-NON-DEPLOYABLE"
```

`scratch` denotes a newly created development scratch directory, not any Rhea
path. `--output` must not exist. It receives `rhea-pilot-NON-DEPLOYABLE`, its
SHA256 in `build-report.json`, `abi.json`, and a generated
`sample-offline-fixture.json`. A failed build produces no acceptance report;
an empty output directory may remain. Never interpret its existence as success.
The CLI exposes only `--abi` (exit 0); all other invocations return 2 before any
DB/journal/host operation. No caller DB path is supported.

## Acceptance and report ABI

The sample input is the bounded recipe `pilot/fixtures/offline-case.json`:
two disjoint groups of 128 records, freshly flushed/compacted and ratcheted through
3/6/7/10/13 to two marked SSTs. Every test invocation constructs a new OS-backed
Pebble database using **`vfs.Default`**, Pebble v1.1.3's actual OS implementation
(there is no exported `vfs.OS` in this version). Saved DB fixtures are never used.

The injected Go suite runs `runBatch` in a separate **test executable**, not
through an executable writer flag. Only that `_test.go` code accepts temporary
DB/journal paths or injected faults. Tests assert:

- Two sequential successful marked rewrites, disjoint picker inputs/outputs,
  two physical compactions, unchanged format 013 and zero remaining marked SSTs.
- Exit status, exact retained pending/intents/receipts/closed bytes and modes,
  evidence byte/record counts, actual successful DB Sync/SyncData operations,
  and continuous `freeCheck` calls including actual writes. Journal sync counts
  are explicitly labeled as implied by successful historical `put` calls
  (one file and one directory fsync each), not syscall instrumentation.
- A second-compaction output creation failure and a monitor revocation during
  second-unit writes: first receipt retained, failure evidence, recovery-required
  result, exit 23 and successful close. A newly inspected request cannot reuse
  the retained evidence directory or perform additional writes.
- Abrupt process exit 73 immediately after the durable second intent: first
  commit retained, no fabricated closed/second receipt. The OS releases the DB
  lock; a fresh reader reopens it. This is an interruption boundary test, not a
  power-loss simulation or proof about partial remote uploads.
- All 256 original values survive reopen after success and both failure modes.

The generated sample fixture contains actual before/after MANIFEST bytes, output
hashes, the unchanged `rhea-multi-sst-writer-v1` report, and separately labeled
offline sync/evidence observations. The pinned Python
`verify_rhea_multi_sst_candidate.validate_fixture_file` independently decodes the
MANIFESTs, reconstructs both unit transitions and checks picker/event/delta/I/O
accounting. The builder also runs the entire historical multistep suite, new disk
tests under `-race`, `go vet`, and checks the compiled CLI's refusal.

`--abi` returns `rhea-pilot-offline-abi-v1`, deployable=false, exact writer request
fields, schema/format/unit ceiling, fixed future clone/evidence scope, and
256 MiB input / 512 MiB SST writes / 64 MiB metadata writes / 2 TiB free /
96 GiB cache limits. The builder compares these against the Python verifier's
actual constants. The journal's writer report schema remains unchanged; the
extra offline observations are outside it. ABI parity and fixture validation
are independent tests, not a signed controller-child protocol.

## Live blockers

The entrypoint deliberately supplies **none** of the following. Each remains a
blocking requirement before an independently reviewed signed root installation:

| Gate | Current behavior |
|---|---|
| Root on Rhea, exact boot/mount/UID/process and signed parent admission | Every writable invocation refuses |
| Canonical signed two-unit request binding exact gen13 prestate/picker and installed SHA pins | No parser/verifier or private signer in pilot CLI |
| Parent-owned exclusive shared writer.lock, PID/start proof, stale-parent death | No child supervision or lock admission |
| Authenticated writer FUSE mount, SO_PEERCRED RC, frozen production, stop sentinel | No host/mount/RC/production observations |
| Continuous free/cache/queue/identity/lock/admission monitoring during all writes | Test callbacks only; no live monitor or 2 TiB/96 GiB enforcement |
| Reader stop, writer mount launch, marker withholding, drain, exact version proof, reopen/restart | Existing adapter/bridge refusals remain unchanged |
| Signed root toolchain/build/deployment/installation/nonce integration | No trusted live binary pin or active signing/install gate |

The historical disk write caps are unchanged and exercised offline. That does
not satisfy the missing free-space/cache/host safeguards on Rhea. No binary from
this builder may be installed into the historical root tree or used on the clone.
The reader remains running and production frozen because this change performs
no live action; it makes no fresh claim about observed host state.

Local validation is recorded with the change's test results. Until Go acceptance
actually runs in an authorized development environment or CI, the Go suite and
build are **unverified**, even if all Python tests pass. CI evidence requires
separate review and still cannot activate the signed root gate.
