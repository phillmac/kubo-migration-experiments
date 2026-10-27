# Synthetic failure and cancellation results — 27 October 2026

Tested code: `3a7b806313aacd34a050f67a571fbdc278168dc1`.
Run: https://github.com/phillmac/kubo-migration-experiments/actions/runs/40481731376
PR: https://github.com/phillmac/kubo-migration-experiments/pull/1

**All four integration jobs passed; the unit-test step ran52 tests successfully.**
A passing fault-injection job means that the intended failure was demonstrated
and the specified recovery control succeeded. It does not mean the injected
operation itself succeeded. Scope is small synthetic copies only, not production
acceptance. No real repository, private inventory, credentials or remote storage
were involved. Code runs unprivileged on disposable hosted Ubuntu24.04 in a
private network namespace with loopback only.

## 1. SIGKILL during the Pebble format bridge

A fresh64MiB non-repeating fixture was created under0.31.0 with a recursive pin,
a nonempty direct pin and an MFS reference. An independent copied generation
was fsynced before the experiment. The0.34.1 process group was killed only after
observing a new replacement SST with **1,311,733 bytes**; the persisted format
marker at that point was **013**, not the completed default bridge format016.
Write entry was slowed by1ms under strace to make the interruption window
observable. This is not a speed benchmark.

The process exited bySIGKILL. Reopening the interrupted copy with0.34.1 succeeded,
and full fixture/raw-block hashes, recursive/direct pin sets and MFS root matched
the baseline. Separately restoring an untouched old generation under0.31.0 also
passed. Original seed file hashes remained unchanged.

Sampled allocated peak during interrupted command:68,562,944bytes; during resume:
72,773,632bytes. These3ms samples are **lower bounds**, not exact maximum space
requirements and not a multi-terabyte sizing factor. SIGKILL does not simulate
power loss, lost filesystem writeback or torn sector writes.

## 2. Actual filesystem-full: recovery works, failure behaviour is problematic

The64MiB fixture copy was placed on a dedicated **128MiB tmpfs**, with a separate
pressure file leaving exactly **65,536 bytes free**. Only that scratch mount was
filled; the runner root filesystem and report storage were not filled.

The0.34.1 bridge produced **29,823 `no space left on device` messages** and
**5,189,202 stderr bytes** in the bounded **20.00777-second** attempt. It did not
return a clean error within that interval. The lab watchdog killed the process
group at its20-second deadline. These are error-message counts, not a claim
that29,823 complete SST files were created or retained.

After removing only the lab-created pressure file, the same copy reopened under
0.34.1 and matched full content/pin/MFS checks. Independent restoration of the
untouched0.31.0 generation passed too; original seed hashes were unchanged.

**Operational implication:** disk-full cannot be treated as a harmless, clean
pause. A real migration plan needs validated free-space thresholds, progress/error
monitoring and a supervised stop/recovery policy. Do not simply let a full VFS
cache retry indefinitely. This experiment does not authorise stopping any live
service. Tmpfs tests logical ENOSPC/retry behaviour, not durable-device failure.

## 3. Missing referenced SST

On a separate closed copy, the lab removed one exact **4,206,469-byte** SST,
`pebbleds/000172.sst`. The0.34.1 open failed promptly with exit1 in0.02437seconds
and identified file000172 as missing from the object-storage provider. It did not
silently declare the repository healthy.

Restoration from the complete untouched generation reopened under0.31.0 and
matched baseline content, pins and MFS. **No repair of the damaged copy is
claimed**; `same_copy_recovered` is null for this test.

The prototype initially misclassified this valid engine error because it expected
the literal `.sst` extension in stderr. The corrected test matches the exact
removed file number and missing-file diagnostic, with regression tests.

## 4. Abandoned verifier streams and long-lived daemon lifecycle

This is an explicitly separate **flatfs + default metadata datastore** fixture,
not a Pebble locking test. It allows exact removal of one generated child block
from a closed fixture without bypassing live pin protection or editing a database.

4096 recursive DAG-PB roots share a DAG-PB child. After pinning the complete CAR,
the exact child's payload/hash was checked and its flatfs file removed. Two
independent copies were then used for old0.31.0 and target0.43.1. The target copy
received the normal embedded schema16->18 migration. Offline API, swarm,
bootstrap and AutoConf/delegated settings were normalized explicitly for the
isolated test; this is not acceptance of production configuration migration.

For **each version** the test:

- Started a long-lived offline daemon and verified its generated peer identity.
- Abandoned8 `pin/verify` streams after reading one complete record.
- After each disconnect, successfully listed recursive pins, added a direct pin
  and removed that direct pin, each with a5-second socket deadline.
- Fully drained a final verifier: **4096 broken roots out of4097 total** (the
  extra initial empty root is healthy).
- Shut the daemon down gracefully; exit status0.

In the accepted target case, pin-list calls took7.493–8.897ms; the final verifier
took0.08914s. These figures describe this tiny local fixture, not remote-backed
production performance.

**Both versions passed. Therefore this accepted test does NOT reproduce or close
the original pin-lock regression.** It establishes target cancellation/lifecycle
smoke coverage, not proof that all abandoned-error/lock paths are fixed.

An earlier raw-child prototype observed an old-version timeout and forced
shutdown while the target stayed responsive, but it failed its broken-DAG
acceptance criterion: a raw CID's empty link set was handled without detecting
that deliberately missing raw payload in this traversal. That prototype is not
accepted as the broken-DAG regression result, and its stall was not captured with
an identifying stack. Retain it as a separate lead to reproduce rigorously.
The first prototype also expected nested `PinStatus` JSON; actual responses are
flattened, with false `Ok` omitted. The parser now tests this distinction and
refuses to classify a pin-index error record as an ordinary broken DAG.

## 5. Source-level caveat: pin-index error send remains to be tested

The tagged0.43.1 CLI/RPC implementation contains a separate branch in `pinVerify`:

```go
if p.Err != nil {
    out <- PinVerifyRes{Err: p.Err.Error()}
    return
}
```

This send is not guarded by `ctx.Done()`, unlike the nearby ordinary per-pin
result send. It concerns **pin-index enumeration errors**, not merely a missing
DAG child. The accepted broken-DAG test does not force that branch.

Primary source:
https://github.com/ipfs/kubo/blob/v0.43.1/core/commands/pin/pin.go
Reviewed blob: `1810f1b5a7b9421233e8906322f2c26503a363ce`.

This is a static finding and a reason for a targeted test; by itself it does not
prove a reachable production leak. Do not assume fixes to Boxo/CoreAPI remove
every separate CLI/RPC path. Next reproduce a controlled enumeration error after
consumer cancellation, capture stacks and verify bounded shutdown/lock release.

## Evidence audit

All four final ZIPs were independently downloaded, SHA-256 matched to the GitHub
artifact records, and their reports/command journals inspected. Artifact entries
contain reports/checksums only, not configs, keys, CAR payloads or SST files.
Artifacts expire after14days; keep independent copies as required.

| Case | Artifact ID | ZIP SHA-256 |
|---|---|---|
|SIGKILL|12723118633|`f8ace986fbe045e6ef7d60d533997f53dfd51e19151d47fae488fe1f9cf18b3b`|
|ENOSPC|12722318478|`1dd7a8bb1042cf8fcdf64a7fde809cec1d007fa3e46316ff7f0f958d4c8007ff`|
|Missing SST|12722992794|`eeb4f21a75c05034f56fe6fad9e2f98a3c37e8bc20fed9033d543d4f04d13761`|
|Pin stream|12722859299|`b973526e7799ac101243df42ca7da3c89bdacd6a7375be7d766abf1be28b7c8f`|

Prototype run40480822538 is not an all-pass acceptance. Corrected intermediate
run40481325898 still had an unsuitable raw-child broken-DAG fixture. Final
run40481731376 is the accepted four-case run. None of these results establishes
physical power-failure safety, target-after-interruption full-chain acceptance,
WAL corruption recovery, remote upload/retention behaviour or large-repo peak
space. Explicit format-floor comparisons were not performed in this pass.

## Next gates

Prioritize deterministic pin-enumeration-error/cancellation reproduction and
ENOSPC containment, then persistent-filesystem crash/WAL tests and completion of
the entire0.43.1 chain from interrupted/recovered copies. Repeat at varied crash
points and larger, aged datasets. Test supported explicit format settings to
establish whether rewriting is avoidable or merely deferred; retain the existing
approximately1x cumulative-write budget until measurements demonstrate otherwise.
