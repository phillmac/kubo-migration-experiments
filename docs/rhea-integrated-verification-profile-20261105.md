# Rhea integrated-verification comparison — 5 November 2026

## Result

**The bounded candidate completed a fresh, full final-verifier pass in
56.780 seconds, compared with 159.310 seconds before it and 218.611 seconds after
it for the unchanged serial verifier.** All three results matched the exact
semantic projection of the certified generation-9 checkpoint. This is an
observed **2.81–3.85× full-verifier speedup** in one ordered comparison, with
64.36–74.03% lower elapsed time. It includes fresh remote enumeration and the
normal live metadata/output GET, HEAD, and hash checks in every pass.
[Complete measurement receipt][profile]

The run completed at **17:24:59 AEDT / 06:24:59 UTC on 5 November 2026**. The
protected database remained **generation 9, five successful rewrites, format
013**, with **93,690 marked files**, **93,697 SSTs**, and
**7,786,594,080,100 referenced bytes**. No writer or Pebble open ran, no marker
was published, and no checkpoint or installed migration toolchain was replaced.
The rewrite ceiling remains five. [Certified starting state][pacing-report]

This advances the [preceding enumeration experiment][enumeration-report]: the
candidate enumerated inside the measured verifier call. It did not preload a
snapshot, reuse another phase's listing, or represent a captured listing as a
fresh remote call. Operational adoption remains a separate change.

## Three complete live verification passes

The passes used the same immutable generation-9 inputs and scoped client. Times
below are measured wall time and process CPU, not estimates.

| Pass, in execution order | Full verifier wall | Process CPU | `_collect_latest` wall | Remote listing pages | Received version/delete rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| [Unchanged serial before][serial-before] | 159.309521 s | 18.466932 s | 149.723802 s | 94 | 93,817 |
| [Integrated bounded candidate][candidate-result] | 56.780462 s | 21.822594 s | 46.593583 s | 96 | 95,537 |
| [Unchanged serial after][serial-after] | 218.611069 s | 18.972364 s | 208.288869 s | 94 | 93,817 |

The first pass ran from 17:17:43.397 to 17:20:22.707 AEDT; the candidate from
17:20:22.830 to 17:21:19.610; and the final serial pass from 17:21:19.770 to
17:24:58.381. Listing collection accounted for **93.98%, 82.06%, and 95.28%**
of the respective verifier calls. Time outside collection was approximately
9.586, 10.187, and 10.322 seconds. Each pass decoded two MANIFESTs in
5.944, 5.899, and 5.888 seconds respectively. These observations identify the
collection path as the main measured difference; its timings include SDK
processing and are not a measurement of network wait alone. [Profile][profile]

The runner took **439.889933 seconds through its postchecks**; the enclosing
supervisor invocation took **440.135365 seconds**. Peak process RSS was
**452,212 KiB / 441.613 MiB**. The configured **2 GiB address-space limit** is a
separate bound, not the measured RSS. The child exited 0 and was reaped, with
empty stderr, no timeout, no TERM or KILL, and no process-group guard failure.
[Invocation receipt][invocation]

### Actual enumeration work

Both serial passes used the original SDK paginator, reached exhaustion, and
received **93,763 version rows plus 54 delete-marker rows**. Of their version
rows, 93,708 were latest and 55 were historical. The candidate made real direct
`ListObjectVersions` calls with a maximum observed concurrency of four and no
in-flight requests at return. Its four disjoint ranges retained the same
**93,763 versions and 54 delete markers**, while receiving **1,720 additional
lookahead rows** and using two more pages than either serial pass.

| Range | Pages / requests | Retained versions | Retained delete markers | Discarded lookahead | Range wall | Termination |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 0 | 24 | 23,427 | 0 | 573 | 38.049925 s | Upper boundary crossed |
| 1 | 24 | 23,424 | 0 | 576 | 46.350429 s | Upper boundary crossed |
| 2 | 24 | 23,424 | 5 | 571 | 46.132449 s | Upper boundary crossed |
| 3 | 24 | 23,488 | 49 | 0 | 43.752750 s | Prefix exhausted |

The scanner itself took 46.435286 seconds. Its aggregate API wall time was
171.697256 seconds because concurrent calls overlap; it must not be added to
elapsed verifier time. The direct-request profiler independently counted 96
calls/pages and 95,537 returned rows, including lookahead. Candidate SDK
paginator counters remained zero. Serial direct-request counters remained zero.
[Measurement counters][profile]

There were **284 actual listing responses** across the three passes, plus
**30 GET and 42 HEAD responses**: **356 actual SDK response observations** in
all. Every response included retry metadata, and every reported retry count was
zero. There were no failed API calls, denied operations, failed body reads, or
failed body closes. These are SDK-reported retry observations, not a claim that
the network performed no lower-level retransmissions.

### Live byte verification remained intact

Every pass made **10 GETs and 14 HEADs**, read **114,660,926 body bytes**, and
closed all ten opened bodies. This comprised **47,339,997 metadata bytes** and
**67,320,929 bytes from `47475328.sst`**, the output already created by generation
9. The parent MANIFEST is also part of the current metadata set and is therefore
read twice by the existing proof. Across all three passes, body reads totalled
**343,982,778 bytes**. Per-pass body-read wall times were 1.073480, 1.079551, and
1.187507 seconds; GET header timings exclude those body reads. [Profile][profile]

The verifier checked **93,696 surviving SST identities**: 93,692 original
baseline files and four earlier-created outputs. Their latest VersionIds,
ETags, and sizes remained pinned without redownloading their payloads. The
current stage's output was downloaded and hashed on each pass. Accordingly,
`new_sst_payload_bytes_downloaded` means new relative to parent generation 8;
this benchmark created no SST. [Candidate result][candidate-result]

## Exact equivalence and completeness scope

All three pure results have `remote_generation_verified=true` and
`pebble_reopen_verified=false`. The latter is correct: their historical
reference checkpoint contains a successful reopen, but this experiment did not
perform another one. For comparison, the reference projection removes its
controller-only `generation`, `reopen`, `reopen_scope`, and `verified_unix`
fields and sets `pebble_reopen_verified=false`. Each actual result must have a
finite, non-Boolean `verified_unix` inside its measured call interval; that
single timestamp is removed before exact canonical comparison.

All three projections matched this SHA-256:

`0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57`

That equality covers the complete proof result, including metadata content and
version pins, surviving and retired SST lineage, the current output hash,
MANIFEST statistics, marks, and inventory. The unchanged inventory digest is:

`b150b4860f87f9273afa85641fac61010134e0e99a6922b5a4acaa86e37a5c58`

The runner bound **13 retained inputs** by exact path, length, and SHA-256:
the immutable baseline ledger, parent-generation-8 certificate, generation-9
certificate and writer report, created-output hash record, and eight closed
metadata snapshot files. The three public result files and their hashes are
bound by the completed measurement receipt. [Input and result bindings][profile]

**This run establishes complete semantic-result equality, not a new
full-history raw-dictionary equality measurement.** It records fresh listing
counts and completion guards without adding a raw-map capture observer. The
earlier isolated enumeration experiment separately established three equal raw
history snapshots with digest `70616b…`; that remains separate evidence. The
current public receipts contain no complete listing maps or SST payloads.
[Earlier raw-history comparison][enumeration-report]

The collection scope remained the entire **`rhea/`** prefix, including
repository objects outside `rhea/pebbleds/`. The scanner partitions the full key
space into disjoint exhaustive intervals, retains all versions of an upper
boundary key across pages and both response arrays, forwards opaque pagination
cursors, and rejects malformed, duplicate, incomplete, cancelled, or over-budget
results. Boundaries are derived from the validated baseline ledger but do not
exclude unexpected keys. The existing latest-null-VersionId rejection and all
original verifier checks remain in force. [Range proof and source contract][range-proof]

## Integration contract and both controller proof passes

The [candidate verifier][candidate] preserves the existing eight positional
arguments and serial default, adding only explicit keyword controls:

```python
verify_generation(..., *, enumeration_workers=None,
                  enumeration_stop=None, enumeration_metrics=None)
```

`None` retains the original SDK paginator. Exact integer `4` selects the bounded
four-range scan at the existing collection point; `1` selects one bounded
range. Metrics remain outside the certificate. Each invocation makes its own
fresh scan, and workers are joined before downstream proof checks or client
closure. The profiler records real direct requests separately from real SDK
paginator activity; metrics locking does not serialize SDK calls.

The candidate has a separate source path. The original verifier and the
historical failed-close helper's exact source pin remain unchanged. Independent
source comparison confirmed that existing proof helper functions and the
returned result expression are unchanged. [Original verifier][original-verifier]

The installed [controller][controller] still requires both complete proof
passes and its existing publication boundaries:

| Boundary | Existing requirement retained |
| --- | --- |
| `before-markers` | Data is drained; changed markers are deferred. A full scan and separate HEAD checks prove their absence while validating the closed generation. |
| Marker publication | The stored prepublication report is hash-bound. Data-version HEAD checks precede each ordered marker publication and verification. |
| `final` | A new complete scan includes all published markers and repeats the content/version proof. |
| Checkpoint commit | Clean queue, snapshot guards, and a fresh read-only Pebble reopen precede committing the checkpoint. |

**The live comparison exercised `final` mode only.** Generation 9 already
contains its published marker; a real `before-markers` call should refuse it.
Controlled fixtures cover both modes and the associated absence, early-marker,
and partial-publication checks. No live response was filtered to fabricate a
prepublication condition, and no controller proof pass was merged or removed.

## Isolation, limits, and observed end state

The fixed runner held the existing host lock and used the reviewed health checks
for an active reader and stopped writer. Each verifier pass was limited to
**512 logical listing requests and 500,000 received rows**, including
lookahead; the candidate was limited to four ranges/workers. The run used a
780-second cooperative deadline, a 900-second supervisor deadline, and a
15-second TERM grace. No deadline fired. Received-row accounting occurs after a
response arrives; it is not a hard wire-byte ceiling. [Runner][runner],
[supervisor][supervisor]

Runtime pins were **boto3 1.34.46 and botocore 1.34.46**, with the reviewed
botocore handlers hash
`3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2`.
Client configuration retained 10-second connect and 30-second read timeouts,
ten pooled connections, and standard retries with at most three total attempts.
The existing SDK key-decoding behavior and opaque version cursors were preserved.
[Runtime receipt][profile]

Authenticated health checks before and after the run confirmed:

- The generation-9 checkpoint and protected state retained hashes
  `220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2`
  and `7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1`.
- Reader **PID 2788642**, production service leader **PID 2554927**, and the
  actual production rclone RC server **PID 2554974** retained their boot ID and
  process start ticks. The service leader is distinct from the rclone server.
- Production RC reported **zero queued uploads, active uploads, errors, and
  cache bytes**, with `outOfSpace=false`.
- The writer remained inactive/dead, MainPID 0, Result success, status 0, with
  its mount and socket absent. Reader and writer caches were retained.
- Wasabi Kubo and the walker remained inactive; the walker remained disabled.
  Installed migration-toolchain and protected-anchor checks passed unchanged.

These are the recorded pre/post conditions, not an atomic remote snapshot or
continuous observation of every service. [Bound host observations][profile]

## Validation and exact source set

The complete local Python suite passed **372 tests**, including **34 candidate
verifier tests**, **17 profiler tests**, and **16 fixed-runner tests**. The
candidate suite runs 24 inherited proof regressions through bounded enumeration
and ten integration tests. It compares exact results and GET/HEAD sequences for
all five stage actions in both modes and covers default compatibility,
one/four-worker selection, fresh rescans, latest-null refusal, invalid controls,
source pins, cancellation, and worker draining. [Candidate tests][candidate-tests],
[profiler tests][profiler-tests], [runner tests][runner-tests]

**Four separate local real-process supervisor exercises passed:** normal exit,
timeout escalation, hangup after launch, and interruption during process
construction. Five compile-valid dummy payloads and retained helper source pins
were used with owned scratch paths and short local deadlines. Every child was
reaped, its PID and group were absent, and no fallback cleanup was needed. These
are local lifecycle tests, distinct from the successful live benchmark.
[Exact supervisor exercise receipt][supervisor-tests]

The rendered supervisor placed these five pinned payloads in the new root-owned
measurement directory
`/root/.local/share/rhea-wasabi-lab-admin-20261101/integrated-verification-profile-20261105/`.
It uses directory mode 0700, file mode 0600, and refuses an existing namespace;
this mapping describes a once-only fixed probe, not a general deployment CLI.
Historical health/equivalence helpers and operational pins stayed in place.

| Installed payload | Repository source | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `compare.py` | [Fixed runner][runner] | 27,140 | `4437ac23d767a5164d42f1c8bb33caf21f7e35c10ab1853ce54f3ce104c4c913` |
| `verify_rhea_full_clone_bounded.py` | [Candidate verifier][candidate] | 35,063 | `43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796` |
| `profile_rhea_full_clone_verification.py` | [Profiler][profiler] | 15,830 | `e0fd6cbfc1e6a44830a550cc4993fd486a1d23df29c4d127879c16dc2a84cccd` |
| `enumerate_rhea_versions.py` | [Bounded scanner][scanner] | 16,289 | `512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359` |
| `verify_rhea_lab_format3.py` | [MANIFEST decoder][decoder] | 21,459 | `edf2a1bf7ba3184113c5b0f53d188f2f6b7157f802ea8595c6558ba92662ec4b` |

The [supervisor template][supervisor] has SHA-256
`80aca6594bb2b0a4ef55a2c33b29277e3b93ebe830bad946b05c65b11dd48b1e`.
The rendered launcher is 164,577 bytes, SHA-256
`9aaa93630322e0ac888c3d099d2d252ad49c0853daddad57218dde4172a5ee26`.
The read-only collector has SHA-256
`88a4569d16c8660284c41be8eb4471c09d9c647b8de7742ab432c15c33262581`.
The original installed verifier retains SHA-256
`e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849`.
No new operational source hash was admitted by this experiment.

## Collected evidence and interpretation

The five exact host JSONs were collected and hash-verified; the sixth file below
is the exact local supervisor-test receipt. Collection bound the three results,
ordered invocation intervals, source/input pins, child stdout and empty stderr,
request/body counters, and pre/post host evidence. No configuration contents,
credentials, raw listing maps, or SST payloads were exported.

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| [Complete profile][profile] | 21,375 | `f96981138dfd9527c41c098bcf5c33da6368a083bb4c1a5d12243f42e277bbb1` |
| [Serial-before result][serial-before] | 5,732 | `24cb57f7e3e725a284d1fc06541febf981e46def5daf5e0f4de15372265d578d` |
| [Bounded-candidate result][candidate-result] | 5,733 | `08e46abd20cc67645be93e9e0d9c98a522828f2d6555a0702744a9a5bec3e11d` |
| [Serial-after result][serial-after] | 5,733 | `db344687af89298f285e1ed1f53406a374621acc254bab8b72f5fb528a0f2a47` |
| [Supervisor invocation][invocation] | 1,295 | `0b68793021590a265e1617c04ddc8f25c770029744a91b0e9db97949dda52b14` |
| [Local supervisor tests][supervisor-tests] | 8,483 | `aed39b630722af10aebcf1e74a491d38ad571a2f83d62fce2aee1dadfc36d37c` |

The measured improvement applies to one complete final-verifier call on this
frozen generation. Execution order, connection reuse, provider variation, and
cache effects were not isolated; the two serial durations themselves differ
substantially. It is not a cold-throughput measurement or a whole-checkpoint
speedup. Publication, queue settling, a fresh Pebble reopen, and controller
lifecycle work remain outside these timed calls. Concurrent API timings overlap,
and nested function timings are inclusive and non-additive.

The result supports a separately reviewed operational-integration change while
retaining both independent proof passes, all content/version checks, bounded
workers and requests, failure cleanup, historical source-pin compatibility,
and the five-rewrite ceiling. **This milestone completed the protected
read-only comparison; it did not deploy that change or perform another rewrite.**

[profile]: evidence/rhea-integrated-verification-profile-20261105.json
[serial-before]: evidence/rhea-integrated-verification-serial-before-20261105.json
[candidate-result]: evidence/rhea-integrated-verification-bounded-candidate-20261105.json
[serial-after]: evidence/rhea-integrated-verification-serial-after-20261105.json
[invocation]: evidence/rhea-integrated-verification-invocation-20261105.json
[supervisor-tests]: evidence/rhea-integrated-verification-supervisor-tests-20261105.json
[enumeration-report]: rhea-version-enumeration-profile-20261105.md
[range-proof]: rhea-version-enumeration-range-proof-20261105.md
[pacing-report]: rhea-full-clone-pacing-20261104.md
[controller]: ../scripts/run_rhea_full_clone_steps.py
[original-verifier]: ../scripts/verify_rhea_full_clone.py
[candidate]: ../scripts/verify_rhea_full_clone_bounded.py
[candidate-tests]: ../tests/test_verify_rhea_full_clone_bounded.py
[runner]: ../scripts/run_rhea_integrated_verification_profile.py
[runner-tests]: ../tests/test_run_rhea_integrated_verification_profile.py
[profiler]: ../scripts/profile_rhea_full_clone_verification.py
[profiler-tests]: ../tests/test_profile_rhea_full_clone_verification.py
[scanner]: ../scripts/enumerate_rhea_versions.py
[decoder]: ../scripts/verify_rhea_lab_format3.py
[supervisor]: ../scripts/supervise_rhea_integrated_verification_profile.py
