# Rhea post-reboot restoration — 6 November 2026

## Outcome

**Restoration and the fresh remote proof completed successfully.** The production rclone mount and lab reader are restored, and one fresh final-verification pass confirmed the unchanged generation nine. The pure verifier took **47.036549 seconds**; the complete supervised operation took **55.275346 seconds**, exited zero, and reaped its child without timeout or cleanup signals. Restoration completion was recorded at **10:25:20.325 UTC / 21:25:20.325 AEDT on 6 November 2026**. The [restoration completion](evidence/rhea-post-reboot-restoration-completed-20261106.json), [proof completion](evidence/rhea-post-reboot-verification-completed-20261106.json), and [supervisor timing](evidence/rhea-post-reboot-supervision-timing-20261106.json) bind these results.

The migration remains at **generation 9, five successful rewrites, format 013**, with `pending: null`. The live rewrite ceiling remains **five**. Restoration invoked no Pebble writer or database open, changed no migration journal or certificate, and performed no marker publication. Production Kubo and the walker remain inactive; the walker remains disabled. The writable lab mount remains stopped. This is restoration of the previously certified experiment, not production cutover or a completed migration.

## Preserved database and restored identities

The retained [adopted journal](evidence/rhea-bounded-adoption-state-after-20261106.json), [pins](evidence/rhea-bounded-adoption-pins-after-20261106.json), and [generation-nine certificate](evidence/rhea-full-clone-000009-step-20261104.json) remain the starting point:

| Artifact | Unchanged SHA-256 |
|---|---|
| Journal | `22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2` |
| Generation-nine certificate | `220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2` |
| Adopted controller pins | `684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c` |

The certificate records **93,690 marked SSTs, 93,697 SSTs, and 7,786,594,080,100 SST bytes**, with inventory digest `b150b4860f87f9273afa85641fac61010134e0e99a6922b5a4acaa86e37a5c58`. The earlier [bounded-verifier adoption](rhea-bounded-verifier-adoption-20261106.md) and [five-rewrite pacing history](rhea-full-clone-pacing-20261104.md), including their failure and recovery evidence, remain intact.

The observed kernel is **`6.8.0-149-generic`**, with new boot ID **`6fc54ca7-d64a-4125-98fa-d0a728485237`**. Restoration recorded these distinct processes:

| Role | PID | Start ticks |
|---|---:|---|
| Production bash service leader | 3,786 | `93876` |
| Actual production rclone RC server | 3,905 | `94049` |
| Lab reader rclone | 4,415 | `109203` |

The actual production rclone belongs to container `c1e4aa8ee9d5e79ecd56927c10628e259bea03f5b47d60b21fb6cdc4522b91c3`; its authenticated loopback RC listener is bound to that process. The restored production and reader were each launched once. The [installed-helper preflight](evidence/rhea-post-reboot-identity-preflight-20261106.json), proof observations, [post-proof health](evidence/rhea-post-reboot-supervision-health-after-20261106.json), and restoration completion agree on the new process identities. Final authenticated production RC showed zero bytes used, queued uploads, uploads in progress and errored files, with `outOfSpace=false`.

All three retained caches were preserved. The [read-only writable-cache scan](evidence/rhea-post-reboot-writer-cache-recheck-20261106.json) examined **93,705 cache metadata records**, finding **zero dirty or invalid records and no symlinks**, and completed in **896.3 seconds**. This measures cache-record inspection; it does not measure SST payload throughput or validate the full corpus. The separate [reader-metadata observation](evidence/rhea-post-reboot-reader-metadata-20261106.json) listed 93,697 SST filenames and matched the eight closed metadata files and decoded MANIFEST state to generation nine, without opening Pebble.

## Preserved orchestration refusals

Two restoration checks required explicit reconciliation. Neither was a Pebble attempt, and neither adds to the historical failed-rewrite count.

First, the preflight called `systemctl is-enabled` for the walker through a helper that required exit status zero. The command returned **status 1 with `disabled`**, the intended walker state. The helper refused before namespace creation or any service launch. The corrected check explicitly accepted that exact status/output pair.

The next operation launched production once, then refused a direct array comparison of Docker `HostConfig.Binds`: the entries were identical but their order differed. A separate read-only reconciliation checked unique sorted bind entries and mount records indexed by destination, rejecting duplicates and confirming the exact image, command, and remaining configuration. It retained the already running production process and recorded its identity; it did not launch production again. The reader was then started once. The [new health helper](../scripts/rhea_post_reboot_health.py) retains these normalized comparisons and duplicate checks.

The original refusal evidence, reconciliation receipt, parking record, and private container inspection are preserved. These are orchestration guard refusals; they do not change the one historical failed-Pebble-attempt count. The public proof binds the new identity receipt, SHA-256 `3821f719ebc3b31df7cb77b02e516e3da2f11db5044df040f6be1129a9a14e67`. Private configuration, credentials, and raw Docker inspection are omitted from the public evidence.

## New health and fresh-proof contract

New helpers are installed beneath `/root/.local/share/rhea-wasabi-lab-admin-20261101/post-reboot-20261106/`. Historical helpers retain their old boot/process pins; their constants were not weakened to accept the reboot.

| Installed helper | Source SHA-256 |
|---|---|
| `health.py` | `4ccc2010e92a7e5202ef76a6f104af887246fa1e828b480d6b3bfcbcb63cb36f` |
| `verify.py` | `f1395771c687e95fae241ed90fe633b9546a1d1bb9c4493f024306a4f3c06f63` |
| `supervise.py` | `34324f1cd2b330149ff1b6335c571a4de4f788cf96c0333feaafe9e5ebc8a521` |

The [verification runner](../scripts/verify_rhea_post_reboot.py) used the original runtime's lifecycle lock and cloud-client context. It retained thirteen immutable inputs: generation-eight and generation-nine certificates, the generation-nine writer report and created-SST hashes, eight closed metadata snapshots, and the baseline ledger. It called the installed adopted verifier with **four workers**, a complete fresh listing, and live GET/HEAD checks. The [fresh result](evidence/rhea-post-reboot-verification-result-20261106.json) exactly matched semantic projection `0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57`, with `remote_generation_verified=true` and `pebble_reopen_verified=false`. Its `action: step` describes the retained generation-nine report, not a new writer invocation.

The runner checked the new health baseline before and after verification. Routine health observations validate the saved reader-metadata receipt rather than repeating a large FUSE directory listing. Its bounds remain four workers, 512 listing requests, a 500,000-row acceptance limit, a 420-second cooperative deadline, and a 2 GiB address-space limit. The [supervisor](../scripts/supervise_rhea_post_reboot.py) recorded a 600-second timeout and 15-second TERM grace, with a 630-second parent backstop and separate bounded after-health check. Cooperative cancellation does not interrupt an in-flight SDK request. Independent review corrected a process-group cleanup fallback before deployment; the deployed wrapper did not encounter that edge or send cleanup signals.

Only new, exclusive proof receipts were written under `verification/`. No writer, Pebble open, journal update, marker change, checkpoint replacement, or automatic retry occurred. Permanent `health.py --check` now validates the completed proof and takes a fresh operational observation without another full remote walk. The supervisor's after-health and the subsequent restoration completion both passed that completed-proof gate. A separate operator follow-up of `health.py --check` also exited zero at **10:26:02.633 UTC**, with the same identities, clean queue, and unchanged protected anchors.

## Measured fresh proof

Full precision and counter definitions are retained in the [metrics](evidence/rhea-post-reboot-verification-metrics-20261106.json), [proof completion](evidence/rhea-post-reboot-verification-completed-20261106.json), and supervisor timing receipts.

| Measurement | Observed value |
|---|---|
| Pure verifier wall / process CPU | 47.036549 s / 21.502865 s |
| Inclusive latest-version collection | 37.376625 s |
| Four-range enumeration wall | 37.217056 s |
| Runner overall, including its setup and health checks | 52.217081 s |
| Supervisor elapsed operation | 55.275346 s |
| Peak process RSS | 440,012 KiB |
| Listing requests / pages | 96 / 96 |
| Retained versions / delete markers | 93,763 / 54 |
| Maximum concurrent listing calls / remaining in flight | 4 / 0 |
| Live GET / HEAD requests | 10 / 14 |
| Returned body bytes / bodies closed | 114,660,926 / 10 |
| Measured SDK responses with retry metadata / reported retries | 120 / 0 |

The remote-command envelope was approximately **58.04 seconds**, including SSH and preflight overhead. It is not the pure-verifier or supervisor duration. Function timings are inclusive and overlap; concurrent API times also overlap and must not be added to elapsed time. The address-space limit is distinct from peak RSS.

Each range made 24 requests. The first three crossed their upper boundaries; the final range exhausted the prefix. The scan received 95,483 version rows and 54 delete-marker rows; 1,720 range-lookahead rows were discarded to leave the complete retained counts above. All 120 measured verifier SDK responses—96 listings, ten GETs and fourteen HEADs—contained retry metadata and reported zero retries. Cloud identity checks are outside those counters. All profiled functions and API calls completed without failure; all ten bodies closed without read or close errors, all workers drained, and both SDK clients closed.

The body bytes comprise 47,339,997 metadata bytes and 67,320,929 bytes for the already-certified output `47475328.sst`. Its payload SHA-256 remained `ab9ca63855d1c180db6bbb85bb22b21825f6479584eafa104a5cda99a1e57c55`. No surviving original or earlier-created SST payload was downloaded by this proof; their exact latest version identities were checked. The result's 93,696 unchanged SST versions include earlier outputs and must not be described as 93,696 untouched original SSTs.

The supervised child/process group **6862** exited zero, was reaped, and had no remaining group members. Supervisor **6815** subsequently exited. The timing receipt records empty stderr and no timeout, TERM, KILL, cleanup error, or completion error; restoration independently confirmed the verification group absent. Final health kept the same restored processes, generation nine, cap five, clean production RC, absent writer mount/socket, retained caches, and 7,275,460,595,712 free bytes. This is one successful post-reboot final proof, not a paired speedup trial, cold-S3 throughput benchmark, new database certificate, or full-migration completion.

## Source validation and retained evidence

CI for source [commit `74f11250c3ef6ecaf2980f4749ca17007b42d848`](https://github.com/phillmac/kubo-migration-experiments/commit/74f11250c3ef6ecaf2980f4749ca17007b42d848) passed in both the [push run 42200713088](https://github.com/phillmac/kubo-migration-experiments/actions/runs/42200713088) and [PR run 42200723384](https://github.com/phillmac/kubo-migration-experiments/actions/runs/42200723384). **514 local Python tests passed**, including the [18 health tests](../tests/test_rhea_post_reboot_health.py), [9 proof-runner tests](../tests/test_verify_rhea_post_reboot.py), and successor-controller coverage. The [deployment receipt](evidence/rhea-post-reboot-deployment-20261106.json) binds that source and the installed health/verifier bytes. The 14,692-byte operational supervisor was reviewed separately before execution; it joins the subsequent evidence-publication commit. CI for the publication commit is tracked in [PR #3](https://github.com/phillmac/kubo-migration-experiments/pull/3); the two source CI results above apply to the earlier source commit.

The same source commit publishes the [second bounded-batch candidate](rhea-second-bounded-batch-plan-20261106.md), which proposes four additional separately admitted units, generations 10–13. That controller is **not installed**. No policy transition or sixth rewrite has occurred; the current journal still enforces the five-rewrite ceiling. Its proposed first-unit review remains a separate later gate.

All thirteen public receipts below are exact copies of their protected host files. The restoration completion binds the other twelve by size and SHA-256. Private launch/configuration/container inputs remain outside this public set; their protected bindings are checked by the identity-bound helper.

| Receipt | Bytes | SHA-256 |
|---|---:|---|
| [Restoration completion](evidence/rhea-post-reboot-restoration-completed-20261106.json) | 4,325 | `784f219e53f1c73e56d452402a51290df585ca989db79c628387e6535f89f2a5` |
| [Helper deployment](evidence/rhea-post-reboot-deployment-20261106.json) | 678 | `96cef07a547d78b0240c18c0781b4a16cbdf00353d3e71d19059309326b8c226` |
| [Identity preflight](evidence/rhea-post-reboot-identity-preflight-20261106.json) | 1,689 | `e8d9eb4010e2e7b515d9b9418d3a1441434384f606696afa0745e51b4425997c` |
| [Reader metadata](evidence/rhea-post-reboot-reader-metadata-20261106.json) | 1,282 | `926e030448377752ebc0926110ae1bac3e6242fa5ef2740ac9c54ff6d245507e` |
| [Writer-cache recheck](evidence/rhea-post-reboot-writer-cache-recheck-20261106.json) | 488 | `3d1dfc41c3000014119f17178c61da12807cbe95b0531cb691c39d34680bdf33` |
| [Proof intent](evidence/rhea-post-reboot-verification-intent-20261106.json) | 5,726 | `1bd2e37b83f888217cd581c2e6f766f438c02e199138e075fe6981533cca3203` |
| [Proof result](evidence/rhea-post-reboot-verification-result-20261106.json) | 5,733 | `24b16db1b1633e0ee5be8041e2c95d9bb5bea567c1bfcfb189c188f56127bb68` |
| [Proof metrics](evidence/rhea-post-reboot-verification-metrics-20261106.json) | 5,621 | `af15ec02f25325edaa278f318929d417198e1dd9f9e2bf6252af2655a40e34d8` |
| [Proof completion](evidence/rhea-post-reboot-verification-completed-20261106.json) | 7,947 | `64c805f7b51950853303c7de4b39ae75c449243913af5f083f98ece9fbda0ade` |
| [Supervisor intent](evidence/rhea-post-reboot-supervision-intent-20261106.json) | 1,510 | `67b5476d18587d48b2d7b485b7595118074a7bb877f70fec70757437fb742a71` |
| [Supervisor launch](evidence/rhea-post-reboot-supervision-launch-20261106.json) | 891 | `00550643770f74b07fc8768e5eef78d1ad531d6822ef6436e4ba882d26130c6f` |
| [Supervisor timing](evidence/rhea-post-reboot-supervision-timing-20261106.json) | 1,707 | `0d6d5ae174631f7c9ce35b3e2a06753282355afbd52b41b1f034f2cfd055a0a5` |
| [Post-proof health](evidence/rhea-post-reboot-supervision-health-after-20261106.json) | 1,689 | `f0326e29e84673b8d5593123b7f7b5c65fbbee9d8ef2bc74e026f85d9f5be38c` |

PR #3 remains open, draft, and unmerged. The next migration action requires a separate reviewed policy transition and explicit bounded-unit admission.
