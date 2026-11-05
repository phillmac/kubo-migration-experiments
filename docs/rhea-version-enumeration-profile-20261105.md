# Rhea version-enumeration comparison — 5 November 2026

## Result and scope

**Four concurrent ranges completed in 53.212 seconds, compared with independent
SDK serial walks of 164.508 seconds before and 197.865 seconds after. All three
complete record collections matched exactly.** The observed serial/concurrent
wall-time ratios are **3.09–3.72× for listing and capture**. The unchanged
verifier also matched generation 9's semantic projection using the candidate's
captured records. [Completed measurement][profile-evidence]

The [preceding verification profile][prior-profile] identified enumeration as
the largest measured component and motivated this comparison.

This validates the isolated candidate on the frozen generation. **No enumeration
optimization was installed in the migration controller or its verifier.** The
checkpoint remains **generation 9 / five successful rewrites / format 013**,
with **93,690 marked files, 93,697 SSTs, and 7,786,594,080,100 referenced bytes**.
The five-rewrite ceiling is unchanged. The probe invoked no database writer,
opened no Pebble database, published no marker, and replaced no checkpoint.
Production Wasabi Kubo and the walker remained stopped.
[Preserved host state][profile-evidence] [Earlier checkpoint][pacing]

All human-readable times below are **AEDT (UTC+11), 5 November 2026**. The
supervised invocation ran from **16:32:26.584 to 16:39:45.749**, returned **0**,
and reaped its child. The completed measurement receipt was recorded at
**16:39:45.479**. [Invocation receipt][invocation-evidence]

## Exhaustive equality and checkpoint binding

The experiment compared three complete remote `ListObjectVersions` walks over
the disposable clone's fixed `rhea/` prefix: the original SDK paginator, four
concurrent disjoint ranges, and the original SDK paginator again. The
[range proof][proof] explains the key, version, delete-marker, UTF-8, and
pagination rules. Ledger-derived boundaries balance work without restricting
which names are included.

The runner compared complete raw record dictionaries, including every returned
field and nonlatest history. It rejected duplicate identities and also computed
a type-tagged canonical digest. This was not a counts-only or latest-files-only
comparison.

| Item in each retained collection | Count |
| --- | ---: |
| Version records | **93,763** |
| Latest version records | **93,708** |
| Nonlatest version records | **55** |
| Delete-marker records / latest delete markers | **54 / 54** |
| All retained records | **93,817** |

All three complete-record digests are identical:
`70616b991a9ef0c99133afa44d6a73174261b4e4cdeb462f2362bac599b9585a`.
The digest algorithm is `typed-sdk-row-v1`; the receipt also explicitly records
successful direct dictionary equality. [Raw-record comparison][profile-evidence]
The public receipt retains these counters, digests, and source/input bindings;
the full record maps were not exported.

The runner pinned and rechecked **13 retained input files**: certificates 8 and
9, writer report 9, its created-output hash map, eight closed metadata files,
and the immutable baseline ledger. The reference checkpoint remains
`220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2`.
The resulting pure-verifier semantic projection is exactly
`0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57`.
Only the controlled verification timestamp and the reference certificate's
controller-only generation/reopening fields are excluded by the established
comparison; the pure verifier's reopening flag must remain exactly `False`.
[Retained bindings][profile-evidence] [Exact replay result][replay-evidence]

The serial walks bracket the candidate observation and detect observed change.
They do not create an atomic S3 snapshot or prove that no transient external
change could occur between observations. Complete listing equality is equality
of version metadata, not a fresh byte-level validation of every SST payload.

## Measured remote listing work

| Walk | Wall seconds | Process CPU seconds | Logical pages | Received records | SDK-reported retries |
| --- | ---: | ---: | ---: | ---: | ---: |
| SDK serial before | **164.507727362** | 10.475727690 | 94 | 93,817 | 0 |
| Four concurrent ranges | **53.211848192** | 13.200183176 | 96 | 95,537 | 0 |
| SDK serial after | **197.864594050** | 11.155101460 | 94 | 93,817 | 0 |

The candidate used **two extra logical requests, or 2.13%**, and received
**1,720 extra records, or 1.83%**, compared with either serial walk. Those records
were boundary lookahead, excluded from the retained union. All **284 actual
listing responses** supplied retry metadata and reported **zero retries**.
This describes SDK-reported attempts, not independently measured transport
retransmission or provider-internal work. [Listing counters][profile-evidence]

The serial timers include paginator iteration, validation, and raw-record
capture. Their paginator advances took **164.356504709 s** and
**197.465978384 s** respectively. The candidate timer includes thread management,
deep copies, range merging, and complete-key checks. Digest calculations and
cross-snapshot comparisons add overhead outside those individual scan timers.
The capture implementations therefore differ.

Concurrent SDK-call durations sum to **179.761280440 s**, while the candidate's
elapsed time is 53.212 s. These calls overlap; their sum is not another elapsed
time. Candidate CPU use was also higher than either serial scan. The observed
wall-time reduction comes with extra requests, lookahead, and local work.

Execution order, connection reuse, and service-cache effects were not isolated.
The 3.09–3.72× ratios describe this single serial/concurrent/serial sequence.
They do not isolate network latency, establish cold-cache throughput, or measure
a whole rewrite/publication/checkpoint speedup.

### Range balance

The three boundaries were `rhea/pebbleds/43509664.sst`,
`rhea/pebbleds/45167795.sst`, and `rhea/pebbleds/46940552.sst`. Each finite range
excludes its lower boundary and includes its upper boundary. The first and last
ranges have no outer bound. [Exact interval definitions][proof]

| Range | Pages | Received versions | Received deletes | Retained records | Lookahead | Wall seconds | SDK-call seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| First, through boundary 1 | 24 | 24,000 | 0 | 23,427 | 573 | 42.299235642 | 41.698876068 |
| Boundary 1 through boundary 2 | 24 | 24,000 | 0 | 23,424 | 576 | 42.474882007 | 41.890909746 |
| Boundary 2 through boundary 3 | 24 | 23,995 | 5 | 23,429 | 571 | 53.116659977 | 52.545265704 |
| Above boundary 3 | 24 | 23,488 | 49 | 23,537 | 0 | 44.465185404 | 43.626228921 |

All four workers used 24 pages, but their completion times differed. The third
range was the slowest at 53.117 s. The first three workers finished after
processing a complete page that crossed their upper boundary; the last exhausted
the prefix. All 1,720 discarded lookahead records were data versions. Adjacent
workers can observe these rows again, but only the worker whose range contains
the key includes them. No record was duplicated in the accepted union.
[Per-range measurements][profile-evidence]

## Verifier replay over the captured candidate

After every listing worker joined and the final serial comparison passed, the
runner supplied one explicitly synthetic in-memory page containing the
candidate records to the unchanged verifier. **This was not a fourth remote
listing walk.** GET and HEAD calls still used the scoped live client.

| Replay measurement | Observed result |
| --- | --- |
| Pure verifier wall / CPU | **10.182167090 s / 8.304516635 s** |
| Two MANIFEST decodes, including CRC checks | 5.886014007 s wall |
| Collection from captured rows | 0.136884443 s wall |
| Live GET / HEAD calls | **10 / 14** |
| Live GET body bytes | **114,660,926** |
| GET body reads / bodies opened and closed | 75 / 10 and 10 |
| Live response retry metadata / reported retries | **24 / 0** |
| Semantic projection match | **Passed, exact** |

The synthetic page has **no SDK response metadata**. Its profiler counter of
one listing page must not be added to the 284 actual remote listing responses
or described as another remote response reporting zero retries. The 24 actual
GET/HEAD responses all supplied retry metadata. Their call timings were
**0.510003656 s** for GET headers and **0.269993261 s** for HEAD; subsequent body
reads took **1.456867799 s**. Function and body timings are nested and
non-additive. No API, iterator, body-read, or body-close failure was reported.
[Replay instrumentation][profile-evidence]

The body bytes comprise the pinned parent MANIFEST (**15,779,601 bytes**), eight
current metadata files (**31,560,396 bytes**), and the existing generation-9
output `47475328.sst` (**67,320,929 bytes**). The parent MANIFEST also belongs to
the current metadata set and was therefore fetched twice by the unchanged
algorithm. The output's payload hash remains
`ab9ca63855d1c180db6bbb85bb22b21825f6479584eafa104a5cda99a1e57c55`.

The replay checked **93,696 unchanged SST identities**: **93,692 original
survivors plus four earlier-created outputs**, without downloading those
payloads. Its `new_sst` fields refer to the newest output's role relative to
parent generation 8; this experiment created no SST. The result retains
`remote_generation_verified=true` and `pebble_reopen_verified=false`.
The successful fresh-reader reopening remains the earlier checkpoint's result.
[Exact verifier result][replay-evidence] [Earlier reopening][pacing]

## Runtime bounds and operational result

The complete runner took **438.853969686 s through postchecks**; the enclosing
invocation took **439.164678015 s**. These include all three scans, comparisons,
verifier replay, input/source checks, and health work. Peak process RSS was
**507,360 KiB (495.47 MiB)**. The child exited normally, was reaped, produced a
completed receipt and empty stderr, and produced no failure receipt. No timeout,
TERM, KILL, or process-group guard failure occurred.
[Measurement][profile-evidence] [Supervisor result][invocation-evidence]

The fixed limits were **four workers/four ranges**, **512 logical listing
requests/pages per scan**, **500,000 received rows per scan**, a **660-second
cooperative cancellation deadline**, and **2 GiB address space**. The separate
supervisor applies a **780-second outer wait with a 15-second TERM grace** to
its owned read-only child. Request slots are reserved before calls; row limits
are checked after responses arrive. An over-budget response can already have
been received before refusal, but no over-budget snapshot is accepted.
[Runner][runner] [Supervisor template][supervisor]

Authenticated health checks passed before and after the run, at
**16:32:27.948** and **16:39:45.316**. The final state was:

| Check | Verified outcome |
| --- | --- |
| Reader | Same PID **2788642**, boot identity, and process start ticks |
| Writable service | `inactive/dead`, MainPID **0**, result `success`, exit status **0** |
| Writer mount and Unix socket | Absent; reader and writer caches retained |
| Production service leader | Same PID **2554927** and start identity |
| Actual production rclone RC server | Same PID **2554974** and start identity |
| Authenticated production RC | **0 queued, 0 uploading, 0 errors, 0 cache bytes; outOfSpace=false** |
| Production Wasabi Kubo / walker | Both inactive; walker disabled |
| Protected state/checkpoint and installed migration toolchain | Unchanged |

The before/after identities distinguish the service's shell leader from its
actual rclone server. The protected state hash remains
`7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1`.
[Both health observations and preserved bindings][profile-evidence]

## Source and validation

The runtime was **boto3/botocore 1.34.46**. Its checked `handlers.py` hash is
`3f2d8de7f1f780377f5d10998146e0587bac68439b11b78cbcad384900eb54e2`.
The client used a **10-second connect timeout**, **30-second read timeout**,
a connection pool limit of **10**, and standard SDK retries with at most
**three total attempts**. The [proof][proof] links the exact versioned decoding
source. The measurement records repository base
`c389aa103a28cd5144db9e3afd53353528d47146`; the new probe sources are identified
by their exact hashes below.

| Source | SHA-256 |
| --- | --- |
| [Scanner][scanner] | `512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359` |
| [Fixed comparison runner][runner] | `43572fd2a12ac25fffad1680803a75a2184412748e884dcfa2f970381e1e5887` |
| [Supervisor template][supervisor] | `19ed1c41ef74d2cda5505d757285bcebccfb1f4954534df5c39f6cf5a4947c89` |

The runner and scanner were installed as `compare.py` and
`enumerate_rhea_versions.py` under the root-owned
`/root/.local/share/rhea-wasabi-lab-admin-20261101/enumeration-profile-20261105/`
namespace, with a `0700` directory and `0600` files. The supervisor template
accepts only those two exact source payloads and rejects an existing namespace.
The earlier pinned health, profiler, and equivalence helpers were reused from
`verification-profile-20261105/`. The installed controller/verifier and their
admission bindings were not replaced. [Installed source bytes][invocation-evidence]

**315 local Python tests passed**, including **17 scanner tests** and **24
fixed-runner tests**. The focused files are linked below. **Four controlled
supervisor exercises also passed**: normal completion, timeout escalation,
parent hangup after launch, and interruption during process construction. They
used owned local scratch fixtures and shortened deadlines; all reaped the child
and confirmed that its PID and process group were absent, without fallback
cleanup. These are local supervisor tests, distinct from the live invocation's
normal exit. [Scanner tests][scanner-tests] [Runner tests][runner-tests]
[Exact supervisor exercise evidence][supervisor-tests-evidence]

## Retained public evidence

The following are exact collected JSON files, not rewritten summaries:

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| [Completed profile, including before/after health][profile-evidence] | 14,414 | `595c229c3d9218f18e94bfad4b1969cb46c93874129bd0dda8551b7ee20c4428` |
| [Unchanged verifier replay result][replay-evidence] | 5,733 | `b0767722a4a13e010dbe73d2427c3bc8439e6951d1cdad5098e70a432a548ad6` |
| [Supervised invocation][invocation-evidence] | 900 | `deab9115201d6968d0837f8ee92c9b8597d88c3f2213c148c3ccb508847cbe17` |
| [Four local supervisor exercises][supervisor-tests-evidence] | 6,324 | `f974874479258e361422500cffd8c6eff4b3d27f7c2ca8782c3b870166f0570d` |

## Interpretation and next decision

The measured candidate preserved exhaustive enumeration and the existing
verification result while substantially reducing elapsed listing/capture time
in this sequence. The equal page counts across ranges and the slower third
worker are useful inputs for further performance work; they do not identify a
specific server or network bottleneck.

This supports a separate review of bounded concurrency as a verifier
optimization candidate, followed by measurement of the complete verification
path before operational adoption. The current controller still uses its
original complete serial proof passes. The experiment neither raises the
five-rewrite ceiling nor authorizes another writer, format 14, full migration,
or production cutover.

[proof]: rhea-version-enumeration-range-proof-20261105.md
[prior-profile]: rhea-full-clone-verification-profile-20261105.md
[pacing]: rhea-full-clone-pacing-20261104.md
[scanner]: ../scripts/enumerate_rhea_versions.py
[scanner-tests]: ../tests/test_enumerate_rhea_versions.py
[runner]: ../scripts/run_rhea_version_enumeration_profile.py
[runner-tests]: ../tests/test_run_rhea_version_enumeration_profile.py
[supervisor]: ../scripts/supervise_rhea_version_enumeration_profile.py
[profile-evidence]: evidence/rhea-version-enumeration-profile-20261105.json
[replay-evidence]: evidence/rhea-version-enumeration-replay-20261105.json
[invocation-evidence]: evidence/rhea-version-enumeration-invocation-20261105.json
[supervisor-tests-evidence]: evidence/rhea-version-enumeration-supervisor-tests-20261105.json
