# Rhea bounded-verifier operational adoption — 6 November 2026

## Outcome

The bounded verifier is now installed and selected by the operational controller. The first `--apply` succeeded, with one journal replacement and one fresh final-verification acceptance. Adoption completion was recorded at **05:12:50.507 UTC / 16:12:50.507 AEDT on 6 November 2026**. No resume was needed. The dedicated child exited zero, was reaped, and was subsequently confirmed absent along with its process group; no timeout, TERM or KILL occurred. The complete supervised operation took **76.878785 seconds**. These results are linked by the [adoption completion](evidence/rhea-bounded-adoption-completed-20261106.json), [invocation](evidence/rhea-bounded-adoption-invocation-20261106.json) and [independent health observation](evidence/rhea-bounded-adoption-health-20261106.json).

The database remains **generation 9, five successful rewrites, format 013**, with 93,690 marked SSTs, 93,697 total SSTs and 7,786,594,080,100 SST bytes. Its retained certificate remains `220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2`; its inventory digest remains `b150b4860f87f9273afa85641fac61010134e0e99a6922b5a4acaa86e37a5c58`. The rewrite ceiling remains five and `pending` remains null. This operation invoked no database writer, Go process or Pebble open, performed no marker publication, and left the reader active and writable mount absent. It installed protected code and pins, updated the journal binding and recorded evidence.

The deployed source is [commit eaddd6a4395a7eb7d33d1993ce1e1af31e30908b](https://github.com/phillmac/kubo-migration-experiments/commit/eaddd6a4395a7eb7d33d1993ce1e1af31e30908b). Its exact-head [push CI 42166503422](https://github.com/phillmac/kubo-migration-experiments/actions/runs/42166503422) and [PR CI 42166509895](https://github.com/phillmac/kubo-migration-experiments/actions/runs/42166509895) both passed before deployment. The [deployment manifest](evidence/rhea-bounded-adoption-deployment-20261106.json) binds that source commit and all staged inputs. These CI results cover the deployed source; this report makes no claim about CI for the subsequent evidence publication.

## Recorded timeline

Times below are rounded to the nearest millisecond. Every row is on 6 November 2026; AEDT is UTC+11.

| Event | UTC | AEDT |
|---|---|---|
| Supervisor started its single apply | 05:11:33.777 | 16:11:33.777 |
| Durable transition intent recorded | 05:11:35.226 | 16:11:35.226 |
| First retained observation of adopted state | 05:11:38.206 | 16:11:38.206 |
| Pure final verifier started | 05:11:41.423 | 16:11:41.423 |
| Pure final verifier returned | 05:12:48.456 | 16:12:48.456 |
| Acceptance completion recorded | 05:12:49.530 | 16:12:49.530 |
| Adoption completion recorded | 05:12:50.507 | 16:12:50.507 |
| Supervisor finished, child reaped | 05:12:50.656 | 16:12:50.656 |
| Independent health observation | 05:13:40.296 | 16:13:40.296 |

The journal rename has no separate timestamp. Its completion is established by the first retained after-activation observation, rather than assigning that observation's timestamp to the rename. Source timestamps are retained in the [transition intent](evidence/rhea-bounded-adoption-intent-20261106.json), [acceptance metrics](evidence/rhea-bounded-adoption-acceptance-metrics-20261106.json), [acceptance completion](evidence/rhea-bounded-adoption-acceptance-completed-20261106.json), invocation and health receipts.

## Fresh installed-verifier acceptance

Acceptance used the installed bounded verifier with four workers and a fresh remote enumeration. It retained the same thirteen protected inputs: generation-eight and generation-nine certificates, generation-nine writer report and created-SST hashes, eight closed metadata snapshots, and the immutable baseline ledger. The [acceptance completion](evidence/rhea-bounded-adoption-acceptance-completed-20261106.json) gives each input's exact path, byte count and hash. No captured listing was substituted for a remote call.

| Measurement | Observed value |
|---|---:|
| Complete pure verifier wall time | 67.032470 s |
| Complete verifier process CPU | 21.844927 s |
| Inclusive latest-version collection | 57.116329 s |
| Four-range scanner wall time | 56.955627 s |
| Acceptance overall time, including setup and checks | 71.090176 s |
| Entire supervised operation | 76.878785 s |
| Peak process RSS | 443,252 KiB, or 432.86 MiB |
| Actual low-level version-list requests/pages | 96 / 96 |
| GET / HEAD requests | 10 / 14 |
| Downloaded payload bytes | 114,660,926 |
| Measured verifier SDK responses carrying retry metadata | 120 |
| Reported retries / failed API calls | 0 / 0 |

Function timings are inclusive and overlap; they must not be added. The scanner's summed concurrent API time was 215.329774 seconds, while its elapsed time was 56.955627 seconds. The 2 GiB address-space limit was a separate guard, not an RSS measurement. Full precision and counter definitions are in the [metrics receipt](evidence/rhea-bounded-adoption-acceptance-metrics-20261106.json).

Each range made 24 requests. The first three stopped after crossing their upper boundary; the last exhausted the prefix. Together they received 95,483 version rows and 54 delete-marker rows. Discarding 1,720 expected range-lookahead rows left **93,763 versions and 54 delete markers**. All four workers drained: maximum concurrent calls was four and calls still in flight at return was zero. SDK-paginator counters remained zero because this acceptance used direct low-level listing. The unchanged bounds were 512 logical listing requests and 500,000 received rows.

All ten GET bodies were closed, with no read or close failures. The downloaded bytes comprised 47,339,997 metadata bytes and 67,320,929 bytes for the already-certified generation-nine output `47475328.sst`. Its payload SHA-256 remained `ab9ca63855d1c180db6bbb85bb22b21825f6479584eafa104a5cda99a1e57c55`, with VersionId `001793763507244273287--TsLq7uDS5`. No untouched SST payload was downloaded. The result's 93,696 unchanged SST versions include surviving outputs from earlier rewrites; this is not a count of untouched original SSTs. See the [acceptance result](evidence/rhea-bounded-adoption-acceptance-result-20261106.json).

All 120 measured verifier SDK responses—96 listings, ten GETs and fourteen HEADs—contained retry metadata and reported zero retries. Cloud identity checks lie outside these verifier counters. Boto3 and Botocore were both 1.34.46, with 10-second connection and 30-second read timeouts, a ten-connection pool and standard retries capped at three total attempts. Every profiled proof function completed without failure, and the acceptance recorded closed SDK clients and drained workers.

The fresh result matched semantic projection `0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57`. Comparison accounts explicitly for the fresh verification timestamp, the stored certificate's generation/reopen augmentation, and the fresh result's `pebble_reopen_verified: false`. The result verifies the historical generation-nine `step` report; that action label does not represent a new step. `remote_generation_verified` is true. The stored certificate and its earlier reopen evidence were preserved, with no fresh reopen claimed.

The [5 November integrated comparison](rhea-integrated-verification-profile-20261105.md) measured 56.78 seconds for the candidate between serial passes of 159.31 and 218.61 seconds. That separate comparison motivated adoption. Today's 67.03-second acceptance is one installed-system observation, not another paired speedup trial. It establishes semantic agreement for this fresh proof, without adding a new cross-run raw-history equality claim.

## Preserved host state

The transition observations, acceptance observations and final [health receipt](evidence/rhea-bounded-adoption-health-20261106.json) agree on these process identities:

| Role | PID | Process start ticks |
|---|---:|---|
| Original lab reader | 2,788,642 | `6375779347` |
| Production bash service leader | 2,554,927 | `6346700159` |
| Actual production rclone RC server | 2,554,974 | `6346700274` |

All three retained boot ID `727cc0aa-6827-403b-b97c-3f7ad839528e`. The writable service remained inactive/dead with `MainPID=0`, `Result=success` and exit status zero; its mount and socket were absent. Reader and writer caches were retained. Kubo and the walker stayed inactive, and the walker unit remained disabled.

Authenticated production RC observations showed zero bytes used, queued uploads, uploads in progress and errored files, with `outOfSpace=false`. The free-space observation moved from 7,275,835,277,312 bytes before transition to 7,275,835,088,896 bytes at the independent health check, remaining above the 2 TiB reserve. Protected historical anchors and the production identity hashes were unchanged.

The independent health check also proved that the old controller refuses the adopted binding and that adoption child/process group 2866853 was absent. It validated the retained acceptance; it did not run another full S3 verification.

## Operational paths and exact activation

All relative installation paths in this section are beneath `/root/.local/share/rhea-wasabi-lab-admin-20261101`.

| Role | Original retained path | Adopted path |
|---|---|---|
| Controller | `run_rhea_full_clone_steps.py` | `run_rhea_full_clone_steps_bounded.py` |
| Verifier | `verify_rhea_full_clone.py` | `verify_rhea_full_clone_bounded.py` |
| Pins | `full-clone-step-pins.json` | `full-clone-bounded-step-pins.json` |
| Scanner | Historical benchmark namespaces | `enumerate_rhea_versions.py` |
| Journal | `full-clone-steps/state.json` | Same journal, with two binding hashes changed |
| Current health helper | Historical helpers retained | `bounded-adoption-20261106/health.py` |

The sole journal change was to `binding.controller_sha256` and `binding.verifier_sha256`. The [before](evidence/rhea-bounded-adoption-state-before-20261106.json) and [after](evidence/rhea-bounded-adoption-state-after-20261106.json) files preserve the exact endpoints. Their embedded checkpoint, generation, rewrites, pending state and every other binding value are identical. The unchanged limits are 256 MiB input, 512 MiB SST output, 64 MiB metadata writes, 96 GiB cache, 2 TiB minimum free space, and 768 MiB/256-file backlog, with at most five successful rewrites. The Go binary, wrapper, seed, bucket and prefix remain pinned as before.

| Endpoint item | SHA-256 |
|---|---|
| Original controller, retained | `7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb` |
| Original verifier, retained | `e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849` |
| Original journal | `7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1` |
| Adopted journal | `22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2` |
| Original pins, retained | `0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575` |
| New pins | `684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c` |

The [new controller](../scripts/run_rhea_full_clone_steps_bounded.py) preserves the original guard, snapshot, queue, publication, recovery and client-close ordering. Both `before-markers` and `final` proof calls explicitly request `enumeration_workers=4`; protected scanner and decoder bytes are checked before importing the candidate. The candidate's standalone default remains serial for compatibility. The operational caller has no fallback to serial enumeration and adds no stop-sentinel behavior.

For the present reader-active, writer-stopped state, use the dedicated health command:

```sh
sudo python3 /root/.local/share/rhea-wasabi-lab-admin-20261101/bounded-adoption-20261106/health.py --check
```

The operational controller entry point is `/root/.local/share/rhea-wasabi-lab-admin-20261101/run_rhea_full_clone_steps_bounded.py`. Its status, guard and verification paths require the writable mount and are not the stopped-system health check. The retained historical health helper intentionally rejects the changed journal binding. Another rewrite requires a separately reviewed milestone; adoption has not raised the cap.

## Durable transition and recovery

The [transaction engine](../scripts/adopt_rhea_bounded_verification.py), [fixed runner](../scripts/run_rhea_bounded_adoption.py) and [health helper](../scripts/rhea_bounded_adoption_health.py) operate in `bounded-adoption-20261106`. The supervisor staged nine protected files: runner, health helper, engine, three candidate sources, exact original state and pins, and a deployment manifest. The manifest binds the other eight files to published source commit `eaddd6a…`; its `parent_commit` identifies accepted pre-adoption baseline `8fa1c296bbe1e8c3687710ddcf1a72c36510b4cb`.

Under the original lifecycle lock, the actual apply validated the original endpoint, retained certificate and sources, absent-or-exact target files, original process identities, stopped writer, caches and authenticated clean production queue. It then:

1. Wrote and fsynced immutable state/pins backups and transition intent, binding both endpoints and all new source bytes.
2. Exclusively installed the new controller, verifier, scanner and pins, leaving their historical counterparts intact.
3. Rechecked health and the exact journal preimage, fsynced a same-directory temporary journal, atomically replaced `state.json`, and fsynced its directory. This was the sole activation commit.
4. Validated the new binding, ran the fresh final acceptance, checked health again, and recorded completion linked to `acceptance/000001`.

Host observations continue to use the original wrapper and its own profile instance. The new runtime is used for source and binding validation; it does not supply a profile to a different wrapper instance. Acceptance calls the pure verifier under the original admitted cloud client and lock, without entering writable-mount lifecycle methods.

The recovery contract is retained for future inspection, although this live apply exercised no resume:

- **Before activation:** explicit `--resume` accepts only the exact original endpoint and complete, matching prepared files. It can finish missing work, preserves an existing exact intent, and reseals byte-identical immutable files by fsyncing the file and parent directory.
- **After activation, unfinished:** resume accepts only the exact adopted endpoint. It fsyncs the existing journal and its directory to cover interruption after rename but before directory fsync, without replacing the journal again. It then requires a fresh acceptance in the next numbered attempt directory.
- **After durable completion:** resume validates the exact completion, linked proof and current health, then reseals those same completion bytes and parent directory. It changes no timestamp, reference or state and runs no new proof. Read-only `--check` validates without repair.
- **Unknown or partial files:** differing targets, unknown journal bytes, missing required preimages and conflicting receipts are refused. Interruption during an exclusive immutable-file write can leave zero or partial final bytes; such cases require independent inspection. Resume never overwrites them. A completion linked to incomplete acceptance is also refused. There is no automatic rollback or writer retry.

The [supervisor](../scripts/supervise_rhea_bounded_adoption.py) owns a dedicated process group, a 600-second timeout and a 15-second TERM grace interval, followed by KILL/reaping if required. It handles signals during process creation and records per-attempt launch and timing evidence. Explicit resume requires exact staged bytes and prior reaped timing receipts; a missing prior receipt requires reconciliation rather than assuming an old child has stopped. Acceptance uses a 420-second cooperative deadline, drains workers before client closure and retains sanitized failure evidence where graceful cleanup is possible. Today all these failure paths remained unused.

## Source pins and validation

The following hashes identify the exact operational sources and orchestration used. The filled launcher is the reviewed supervisor rendered with the nine fixed payloads; the collector read protected receipts and exported the fifteen JSONs below.

| Source or recipe | Bytes | SHA-256 |
|---|---:|---|
| [Bounded controller](../scripts/run_rhea_full_clone_steps_bounded.py) | 49,144 | `56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a` |
| [Bounded verifier](../scripts/verify_rhea_full_clone_bounded.py) | 35,063 | `43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796` |
| [Scanner](../scripts/enumerate_rhea_versions.py) | 16,289 | `512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359` |
| [Adoption runner](../scripts/run_rhea_bounded_adoption.py) | 25,046 | `bffa27f5c5f4b60c05f352f6f63cd2ac414044dc9bc6733662a8c042938d8b58` |
| [Transaction engine](../scripts/adopt_rhea_bounded_verification.py) | 20,124 | `9cf99027eaddd028ef947f2e2867184f9266a0cbfbc20972e787faffa027b7f9` |
| [Adoption health](../scripts/rhea_bounded_adoption_health.py) | 35,817 | `27ef8e7ae0e1b70eaef02b9b37828af2d44d54dc1f703efd9d54a8a42eb32b6f` |
| [Supervisor template](../scripts/supervise_rhea_bounded_adoption.py) | 15,580 | `5344def7b7c62603ae04174a7f6632421763cf75bc86bccab370c086cb1ebc68` |
| Filled launcher | 270,335 | `b3ca42000735954713b645b1a74bbbccebc5cc7f01386ebe7532fe12b64892e8` |
| Receipt collector | 10,021 | `f8ca4f33c495fd9f4fd571c6416346bb5747aad8f41c69a3179a61b4441ffd53` |

All **451 Python tests** passed, including nonroot discovery, along with [eleven controlled supervisor exercises](evidence/rhea-bounded-adoption-supervisor-tests-20261106.json). The initial CI run exposed a test fixture performing a real `/root` status check; the fixture correction explicitly models those checks and rejects unexpected filesystem access. Operational source hashes were unchanged by that correction. The final source-head CI links are recorded above.

Coverage includes both proof modes' explicit four-worker delegation, dependency pins, client cleanup and exceptions, sixth-rewrite refusal before writer entry, exact two-field binding adoption, and interrupted activation/completion durability. Real adapter tests cover atomic replacement and resealing after an injected directory-fsync failure; supervisor exercises cover success, forced timeout, parent interruption and interruption during child construction. These controlled exercises establish the recovery behavior separately from today's successful first apply.

Live acceptance was final mode only because generation-nine markers were already published. Before-marker integration is covered by controlled tests. Remote listing and GET/HEAD verification are fresh but do not form an atomic remote snapshot. This adoption does not establish additional rewrite pacing, a new Pebble reopen, format-14 compatibility on the full clone, or production cutover readiness.

## Exact public evidence

These fifteen host JSONs total 57,924 bytes. They preserve source, endpoint, acceptance, invocation and health bindings without publishing credentials, raw logs, metadata/SST payloads or the full SST inventory. The supervisor-tests artifact linked above is a separate local test record. Hashes below are SHA-256 of the exact exported file bytes.

| Evidence | Bytes | SHA-256 |
|---|---:|---|
| [Deployment manifest](evidence/rhea-bounded-adoption-deployment-20261106.json) | 1,105 | `cc20c1667599a2ccd7c58e6d03f149603621a31807d45c219034c6ee15c231ea` |
| [Original journal](evidence/rhea-bounded-adoption-state-before-20261106.json) | 7,318 | `7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1` |
| [Original pins](evidence/rhea-bounded-adoption-pins-before-20261106.json) | 264 | `0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575` |
| [Transition intent](evidence/rhea-bounded-adoption-intent-20261106.json) | 4,805 | `07b55f1af37ad35fee0d9486975f83664c7b77782a830e91328a92384a8ec13c` |
| [Adoption completion](evidence/rhea-bounded-adoption-completed-20261106.json) | 3,515 | `ee3613fadce8c80d8f4294958130d85ca88401803229f0e611a7479fd9785208` |
| [Adopted journal](evidence/rhea-bounded-adoption-state-after-20261106.json) | 7,318 | `22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2` |
| [Adopted pins](evidence/rhea-bounded-adoption-pins-after-20261106.json) | 264 | `684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c` |
| [Acceptance intent](evidence/rhea-bounded-adoption-acceptance-intent-20261106.json) | 5,712 | `c8ce37be137c0803ebc312abd06cef77ddd68ad7feb659418413c0fee7f7d48e` |
| [Acceptance result](evidence/rhea-bounded-adoption-acceptance-result-20261106.json) | 5,733 | `696cbd8b5f07d36bd857a01adbb2915db21bd7be5c364616d93be313d997cb0a` |
| [Acceptance metrics](evidence/rhea-bounded-adoption-acceptance-metrics-20261106.json) | 5,677 | `97a28992c25d710fba519b1f309265b68544045b0e2bae9451b7937c285457b4` |
| [Acceptance completion](evidence/rhea-bounded-adoption-acceptance-completed-20261106.json) | 8,085 | `97ebb8d9e196726a744e686b83ddeb50530a13dfa2da6cddd499e01919d83b0a` |
| [Supervisor intent](evidence/rhea-bounded-adoption-supervisor-intent-20261106.json) | 1,347 | `076b5da08a98342e285c8480b2d98f04fc84a5e3d732a5ecffbd3a365cf469e2` |
| [Child launch](evidence/rhea-bounded-adoption-launch-20261106.json) | 1,234 | `936fe5e9ea3674027f2e1d5ec98fa0b66e09b4b827097cc1e17288f526591620` |
| [Supervised invocation](evidence/rhea-bounded-adoption-invocation-20261106.json) | 1,811 | `2a6e5c1e063113cd4e3084b9a0bfe755bbd1b8776e29063477257bf4cca18be0` |
| [Independent health](evidence/rhea-bounded-adoption-health-20261106.json) | 3,736 | `5865bfac819c1601bc29c2612682717e3e0c76244f941e302b28a39215d9eca0` |
