# Rhea full-clone verification profile — 5 November 2026

## Result and scope

**The unchanged generation-9 final verifier was replayed successfully, with an
exact semantic match to its published certificate. Version-list collection took
136.969 seconds: 93.39% of the measured verifier wall time of 146.670 seconds.**
This identifies the first performance investigation target. No optimization was
installed and no speedup is demonstrated. [Completed profile][profile-proof]

The database remains at **generation 9 / five successful rewrites / format 013**,
with **93,690 marked files**, **93,697 SSTs**, and **7,786,594,080,100 referenced
bytes**. The successful-rewrite ceiling remains **five**. The reader remained
active, the writable mount remained stopped, and production stayed frozen.
This probe invoked no database writer, opened no Pebble database, published no
marker, and replaced no checkpoint. The [preceding pacing report][pacing-report]
remains the record of the completed rewrites and reader reopening.

All times below are **AEDT (UTC+11), 5 November 2026**. The initial authenticated
health check passed at **10:09:02.977**. The replay's outer invocation ran from
**10:15:39.200** to **10:18:11.075**, returning **0** with empty stderr. The
completion receipt was recorded at **10:18:10.951**.
[Health proof][health-proof] [Invocation timing][timing-proof]

## Measured time and resource use

| Measurement | Wall seconds | Process CPU seconds |
| --- | ---: | ---: |
| Complete profiled verifier | **146.670223363** | **18.439943679** |
| `_collect_latest`, including version enumeration and collection | **136.969097674** | **10.251898806** |
| Paginator iterator advances, including exhaustion | **136.864826590** | Not separately measured |
| Two MANIFEST decodes, including CRC checks | **5.915920988** | **5.915822811** |
| Nine metadata GET/validation calls, `_get_bytes` | **1.047257468** | **0.234147812** |
| One stage-9 output fetch/hash/check, `_hash_new_sst` | **0.764403440** | **0.258759412** |
| Baseline-pin construction | **0.422135986** | **0.422139389** |
| Stage/delta validation | **0.421925128** | **0.421921267** |

**These timings are inclusive, nested, and non-additive.** For example,
paginator time is inside collection time, and the new-output check includes
its GET, body reads, hash, and HEAD. The collection share is calculated directly
as `136.969097674 / 146.670223363`, not by summing the rows.

Collection includes remote request waits, SDK response processing, iteration,
and local validation. Its **10.252 CPU seconds** make clear that its wall time
is not a network-only measurement. This instrumentation does not separate
server latency, connection effects, XML parsing, and scheduling into independent
components. [Timing semantics and measured counters][profile-proof]

Outside the profiled verifier, ledger decoding took **0.817204170 s** and cloud
client creation plus identity verification took **2.100575618 s**. The runner
measured **151.699391641 s through its final checks**; the enclosing process
invocation took **151.875427999 s**. Peak process RSS was **426,600 KiB
(416.60 MiB)**. The receipt's outer verifier-call timer is **146.670694567 s**,
which includes a small amount of wrapper overhead beyond the profiler's own
146.670223363-second interval. These are distinct measurement boundaries.
[Profile receipt][profile-proof] [Outer timing receipt][timing-proof]

## Complete enumeration, requests, and payloads

The final pass retained the complete paginated `ListObjectVersions` walk over
the fixed disposable bucket's `rhea/` prefix. It completed one paginator,
one enumeration, **94 pages**, and **95 iterator advances including final
exhaustion**. No enumeration was truncated or replaced by a changed-file check.

| Observed item | Count |
| --- | ---: |
| Version rows, including nonlatest rows | **93,763** |
| Latest version rows | **93,708** |
| Delete-marker rows / latest delete-marker rows | **54 / 54** |
| Logical GET calls / HEAD calls | **10 / 14** |
| GET bodies opened / closed | **10 / 10** |
| Body read calls | **75** |
| Failed API calls, iterator advances, body reads or closes | **0** |
| Denied profiling-interface operations | **0** |

All **118 response records**—94 listing pages, 10 GETs, and 14 HEADs—contained
SDK retry metadata. Every record reported **zero retries**. This describes
SDK-reported retry attempts, not independently observed transport retransmission
or provider-internal work.

Logical GET calls took **0.500904068 s** before their subsequent body reads;
HEAD calls took **0.261601910 s**. Body reads returned **114,660,926 bytes** in
**1.046634831 s**. Those body bytes comprise:

| Verified payload | Bytes |
| --- | ---: |
| Parent generation's active MANIFEST, fetched by its pinned VersionId | **15,779,601** |
| Eight current closed metadata files | **31,560,396** |
| Replayed generation-9 output `47475328.sst` | **67,320,929** |
| **Total GET body bytes** | **114,660,926** |

The parent MANIFEST also belongs to the eight-file current metadata set, so its
payload was fetched twice by the unchanged verification algorithm. The output
SST is an already existing generation-9 object during this probe; the verifier's
`new_sst_payload_bytes_downloaded` field describes its role relative to parent
generation 8. No SST was created by this replay.

The replay preserved **93,696 unchanged referenced SST identities**: **93,692
original survivors plus four earlier-created outputs**. Their payload-download
counter remained **zero**. The fifth created output was fetched and hashed
separately as shown above. Listing response bodies, guard calls, and other
protocol traffic are outside the GET-body byte counter. These measurements do
not establish cold-cache transfer throughput or fresh byte validation of the
full corpus. [Exact verifier result][replay-proof]

## Exact certificate equivalence and retained inputs

The replay used the original **generation-8 parent certificate**, **generation-9
writer report**, **generation-9 created-output hashes**, all **eight retained
closed metadata files**, and the immutable baseline ledger. Protected paths,
raw hashes, lengths, and snapshot filenames were checked before use and again
after verification. Each snapshot file also matched generation 9's certified
metadata size and SHA-256. The unchanged verifier performed its usual remote
version, content-hash, MANIFEST, lineage, and marker checks.

The expected result was the [published generation-9 certificate][certificate9]
with only these deliberate comparison differences:

- `verified_unix` is fresh and must lie within this invocation's verification
  interval; only this timestamp is omitted from semantic comparison.
- Historical controller fields `generation`, `reopen`, and `reopen_scope` are
  absent from the pure verifier's result.
- The replay must report the Boolean `pebble_reopen_verified=false`. The earlier
  certificate's completed reopen remains historical evidence; this probe did
  not repeat it.

Every other field matched canonical JSON exactly, including **54 latest delete
markers**, object VersionIds/ETags/sizes/hashes, current metadata, lineage,
inventory, counts, marks, and payload counters. The semantic projection SHA-256
is:

```text
0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57
```

The checkpoint remains
`220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2`;
the protected state remains
`7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1`.
The replay result correctly reports `remote_generation_verified=true` and
`pebble_reopen_verified=false`. It is separately receipted evidence, not a new
migration checkpoint. [Comparison and retained-input proof][profile-proof]

## Host preservation

Fresh checks retained reader **PID 2788642**, production service leader
**PID 2554927**, and the actual production rclone server **PID 2554974**, with
matching boot/start identities. The writable service remained **inactive/dead**,
`MainPID=0`, `Result=success`, `ExecMainStatus=0`, with its mount and socket
absent. Both lab cache directories were retained.

Production Wasabi Kubo and the walker remained inactive; the walker remained
disabled. Authenticated production RC checks before the probe and after the
replay reported **zero queued uploads, active uploads, errors, and cached
bytes**, with `outOfSpace=false`. The immediate replay-start observation checked
processes and protected state; its `production_rc_checked=false` is explicit,
and is not treated as a zero-valued RC observation. The separate initial health
receipt and the post-replay observation contain the authenticated RC results.
[Initial health][health-proof] [Before/after observations][profile-proof]

The installed controller, verifier, decoder, Go binary, wrapper, admission,
deployment pins, and checkpoint were preserved. The new probe files and their
separate receipts do not change the five-rewrite policy.

## Probe source and fixed installation

The [profiling utility][profiler] is importable and has no filesystem, credential,
SDK-creation, or controller setup. It temporarily wraps eight named functions in
an exclusively held verifier module, restores them on completion or exception,
and exposes only the verifier's read-only S3/body interface. It does not modify
the SDK. Function metrics and request counters contain no payloads, API argument
values, credentials, or exception text.

The [health helper][health-source] and [fixed runner][runner] own the protected
installation, unchanged source/input pins, lifecycle lock, identity checks,
exclusive receipts, semantic comparison, and postchecks. The runner imposes a
**600-second alarm on cloud identity and verification**; input preparation and
postchecks are outside that alarm. Its private `BaseException` deadline unwinds
cleanup without entering ordinary SDK `Exception` retry handlers. It does not
invoke the controller's writable-mount admission path.

The executed root-owned installation directory is:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/verification-profile-20261105/
```

| Repository source | Installed basename | SHA-256 |
| --- | --- | --- |
| [profile_rhea_full_clone_verification.py][profiler] | `profile_rhea_full_clone_verification.py` | `282643a0f8a209681c984d236ddc594978951faad25e0bb7b80be33f2975e741` |
| [rhea_full_clone_profile_health.py][health-source] | `health.py` | `617108d7b87b9879c622fcf22bc4ddf47ae258f680625cd4119661338c47a3f8` |
| [run_rhea_full_clone_verification_profile.py][runner] | `replay.py` | `6660de99fce5982bfcb66975b0e3869b891825a5d07942ea4a29bf56a2e125a1` |

The directory is mode **0700**, sources are root-owned mode **0600**, and pinned
ancestors must pass the protected-path checks. The recorded invocation order was:

```console
sudo python3 -B /root/.local/share/rhea-wasabi-lab-admin-20261101/verification-profile-20261105/health.py --check
sudo python3 -B /root/.local/share/rhea-wasabi-lab-admin-20261101/verification-profile-20261105/replay.py --verify-current
```

These describe the completed execution. Receipts use exclusive creation and
the runner refuses an occupied receipt namespace. A further measurement needs
a separately reviewed namespace and pins; the completed evidence must not be
overwritten or removed to repeat the command. No arbitrary host, bucket, prefix,
database, checkpoint, credential path, or mutation action is accepted.

The unchanged verifier SHA-256 is
`e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849`.
The receipt's `unchanged_verifier_source_commit`,
`08a1c49918659b10b26e3119304d50eb9ee90a6e`, identifies the preceding migration
source; the new probe's executed source is identified by the hashes above.

## Validation and next bounded proposal

**All 274 local Python tests passed**, including **10 profiler tests** and
**8 replay-equivalence tests**. The [profiler regressions][profiler-tests] check
unchanged verifier results/reads, metrics, cleanup, failures, and denied API
operations. The [runner regressions][runner-tests] use the actual public
generation-9 certificate to reject timestamp/type errors, reopened-state claims,
extra or missing fields, changed delete counts, and altered earlier-output pins;
they also check deadline cleanup. These tests perform no live host/SDK lifecycle
campaign. The Go binary remains unchanged.

The next useful proposal is a **read-only investigation of version enumeration**,
followed by a separately reviewed experiment with bounded parallel key ranges
if its completeness can be demonstrated. Any partitioning must cover the whole
versioned prefix, including unexpected keys, historical versions, and delete
markers; complete exhaustion, boundary handling, duplicate detection, and the
union of results must reconcile with the existing serial walk. Listing only
known SST names or reusing a previous pass would weaken the present proof.

A candidate would need a matched serial comparison on the same frozen
generation, bounded concurrency/resource use, exact result equivalence, and
separate timing/retry counters. No parallel listing or other optimization is
installed by this milestone. The existing per-unit before-publication and final
verification passes remain intact.

This one replay establishes where this final pass spent time. It does not
attribute every second of the previous **383–394-second rewrite operations**:
those also include planning, writer work, snapshots, queue drainage,
publication, a second verifier pass, and reopening. It does not establish a
latency distribution, cold-cache throughput, full-corpus validation, or a
production-cutover result. Further identical writes would add little evidence
about the now-measured listing cost and remain outside the current cap.

## Exact public evidence

All four files are unmodified copies of the protected receipts. Their raw
lengths/hashes, result linkage, semantic projection, source pins, process
identities, request counts, and timing boundaries were reconciled locally.

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| [Completed profile][profile-proof] | **11,263** | `58f1273346af54e47d73025e4a6a20752f73dcf4437e61fb9b5cdf435f9d6ae4` |
| [Exact verifier replay][replay-proof] | **5,732** | `1bea8752a6ed4987c798d496b7192ec4987e3a9299396f4b88f3fc1d32c19887` |
| [Initial authenticated health][health-proof] | **1,547** | `f28cd11a2a2765c1b2e4bc031a41219b4b85fc24b2e9ad039fdf281e589b1de5` |
| [Outer invocation timing][timing-proof] | **425** | `d90fe1f2a018db32db82f7cca41f072d93189263a5a0373f830c0528a70fda70` |

[profile-proof]: evidence/rhea-full-clone-verification-profile-20261105.json
[replay-proof]: evidence/rhea-full-clone-verification-replay-20261105.json
[health-proof]: evidence/rhea-full-clone-verification-health-20261105.json
[timing-proof]: evidence/rhea-full-clone-verification-profile-timing-20261105.json
[pacing-report]: rhea-full-clone-pacing-20261104.md
[certificate9]: evidence/rhea-full-clone-000009-step-20261104.json
[profiler]: ../scripts/profile_rhea_full_clone_verification.py
[health-source]: ../scripts/rhea_full_clone_profile_health.py
[runner]: ../scripts/run_rhea_full_clone_verification_profile.py
[profiler-tests]: ../tests/test_profile_rhea_full_clone_verification.py
[runner-tests]: ../tests/test_run_rhea_full_clone_verification_profile.py
