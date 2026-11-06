# Rhea bounded-verifier operational adoption — 6 November 2026

## Preparation status

This change prepares the reviewed bounded verifier for both operational controller proof passes. Publication of these sources is a prerequisite to live activation; this preparation document does not claim deployment or acceptance has completed. The final evidence update will record the actual host outcome and exact source commit.

The certified database remains generation 9, with five successful rewrites, format 013, 93,690 marked SSTs, 93,697 total SSTs and 7,786,594,080,100 SST bytes. Its certificate stays `220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2`. The rewrite ceiling remains five. This milestone authorizes configuration adoption and a read-only final verification; it does not authorize another rewrite, marker publication, a fresh Pebble open, format-14 finalization or production cutover.

The preceding [integrated verifier comparison](rhea-integrated-verification-profile-20261105.md) measured the exact candidate at 56.78 seconds, between serial passes of 159.31 and 218.61 seconds. Each pass completed its own full remote enumeration and payload proof and returned the same semantic certificate projection. That measurement motivated adoption, but its receipts do not substitute for the new installed-verifier acceptance.

## Operational files and activation

All paths below are relative to `/root/.local/share/rhea-wasabi-lab-admin-20261101`.

| Role | Original retained path | New operational path |
|---|---|---|
| Controller | `run_rhea_full_clone_steps.py` | `run_rhea_full_clone_steps_bounded.py` |
| Verifier | `verify_rhea_full_clone.py` | `verify_rhea_full_clone_bounded.py` |
| Deployment pins | `full-clone-step-pins.json` | `full-clone-bounded-step-pins.json` |
| Bounded scanner | Previous benchmark namespaces | `enumerate_rhea_versions.py` |
| Shared journal | `full-clone-steps/state.json` | Same journal; exactly two binding hashes change |

The new controller preserves the original guard, snapshot, queue, client-close, publication and recovery ordering. It explicitly supplies `enumeration_workers=4` for `before-markers` and `final` proof modes. It checks the protected scanner and decoder bytes before importing the candidate. The candidate remains the exact previously reviewed source; its standalone default remains serial for compatibility, while the operational caller always requests four workers. There is no failure fallback to serial enumeration and no new stop-sentinel cancellation behavior in the controller.

| Pinned item | SHA-256 |
|---|---|
| Original controller, unchanged | `7eb99999d192d8590408aeef1829a456ced9eb3f028e364c388d170772377beb` |
| New controller | `56fe3af27d12992b8e38a0469e2f6b41a0b7d5ecbaa875ea95d84632dc27187a` |
| Original verifier, unchanged | `e2b6ec8b792e1eb98ae3c9f3524401b941e4cf4490dd8fbd09b5a80c79538849` |
| New verifier | `43d7cbe6256bc2479a98b79fe66ef1a3c11b9aee4427175398a539cb4eb12796` |
| Scanner | `512bf925f5ab30a7b84a238c156e313b54da3bb8c0a396af46231ced65dcd359` |
| Original journal | `7a838e76a95e1ea54c7814b723240ee15667dc4de417b21de9e9b15135969be1` |
| Exact intended adopted journal | `22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2` |
| Original pins, unchanged | `0929a3e4ddd7ac9b799c7a24c1ef3baf7fbcf0eca9c2f7e7e2e1e108c2ec4575` |
| New pins | `684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c` |

The journal replacement is the sole activation commit. Before that replacement, the original controller accepts the original journal. After it, the new controller accepts the adopted journal and the original controller rejects its changed binding. Only `binding.controller_sha256` and `binding.verifier_sha256` differ; the embedded checkpoint, all limits, generation, rewrite count, pending state, Go binary, wrapper, seed, bucket and prefix remain identical.

## Durable transition and recovery

The fixed operation namespace is `bounded-adoption-20261106`. The supervisor stages nine protected files: the runner, health helper, transaction engine, three candidate sources, exact original journal and pins, and a deployment manifest. The manifest identifies the published source commit and the eight other staged payloads. It is generated only after source publication and successful exact-head CI, avoiding a self-referential commit hash in a source file.

Under the original host lock, the transaction:

1. Validates the exact original endpoint, absent-or-exact new targets, retained certificate, original sources and pins, reader and production identities, stopped writer, absent writer mount/socket, retained caches and authenticated empty production queues.
2. Writes and fsyncs immutable `state-before.json`, `pins-before.json` and `intent.json` receipts. Intent binds the source commit, deployment manifest, runner, engine, health helper, both endpoints and target source bytes.
3. Installs the new controller, verifier, scanner and pins exclusively. Existing byte-exact files can be revalidated and fsynced after interruption; differing files are refused.
4. Rechecks preactivation health and the exact journal preimage, writes and fsyncs a same-directory temporary journal, atomically replaces `state.json`, then fsyncs its directory.
5. Validates the activated state, runs one fresh installed-verifier final acceptance, checks health again and writes an immutable completion linked to the acceptance receipts.

Explicit `--resume` accepts only exact original or adopted journal bytes. It can finish complete preimages written before intent creation and preserves the exact original intent once present. Before activation it may complete exact prepared work. After activation it never rewrites the journal; an unfinished resume revalidates and fsyncs the exact visible journal and its directory, covering an interruption between rename and directory fsync, before fresh read-only acceptance. If a complete completion receipt is present, resume validates it and its retained proof, then fsyncs those same completion bytes and their parent directory. It preserves the original timestamp and references and performs no new proof or journal replacement. The read-only check observes without repairing a possibly interrupted fsync. Unknown endpoint bytes, differing targets, missing required preimages and conflicting receipts are refused. A completion referring to incomplete acceptance is refused; an unfinished transition preserves any earlier failed attempt and can run a fresh proof in the next numbered directory. There is no automatic rollback or writer retry. Recovery tests cover interruption after complete durable operations. An interruption during an exclusive immutable-file write can leave partial final bytes; these are deliberately refused and require independent inspection. Resume never overwrites such a file, including an incomplete intent or completion receipt.

The outer supervisor owns a separate process group, a 600-second hard deadline and a 15-second TERM grace interval. It handles signals during process creation, reaps its owned child and writes per-attempt launch/timing evidence. Resumes use fresh numbered supervisor receipts; unfinished resumes that need a proof also use a new numbered acceptance directory. A prior launch without a reaped timing receipt is refused rather than guessing whether an old child is still active.

## Health and acceptance

The historical health helper remains immutable and binds the original journal. A separate adoption health helper bootstraps the original controller, wrapper and host without accepting the current journal. It then performs an explicit `before` or `after` observation. The after path validates the exact new endpoint, source manifest, transition intent and installed controller binding. Host helpers continue to use the original wrapper and its own profile; no profile object is mixed across dynamically loaded wrapper instances.

The stopped-writer acceptance does not call the controller's writable-mount guard or status methods. It loads the installed bounded verifier through the new runtime solely for source and binding validation, then calls its pure final-verification function using the original admitted cloud client and reader-active host lock. It retains the same 13 input references: previous/current certificates, writer report, created-SST hashes, eight metadata snapshots and immutable baseline ledger.

Acceptance requires four completed bounded ranges: three stop after crossing their upper boundary and the final range exhausts the prefix. It caps enumeration at 512 logical listing requests and 500,000 received rows and requires exactly 93,763 retained versions and 54 delete markers, ten complete GET bodies, fourteen HEAD requests and 114,660,926 payload bytes. It checks the full semantic result against projection `0a8114cb920606a27c74a0b5fef6c7383ef13f702b192dc6fd2dcb7c3770ad57`, permits only the fresh verification timestamp, and records SDK versions, retry metadata, drained worker calls, closed bodies and closed clients. The installed certificate is not replaced.

Each explicit acceptance attempt has its own `intent.json`, `result.json`, `metrics.json` and `completed.json`. Failed attempts retain a sanitized failure receipt when graceful cleanup is possible. Cancellation is latched, allowing worker joins and GET-body ownership cleanup; the external supervisor enforces the hard deadline. Permanent `health.py --check` requires completed adoption and verifies the linked retained acceptance evidence.

## Validation and limits

The preparation passed all 451 Python tests and eleven separate supervisor exercises. The first CI run exposed a test fixture that attempted a real `/root` status check; the fixture now models those checks explicitly and rejects unexpected filesystem access. Operational source hashes were unchanged by that test correction. The deployment manifest’s `parent_commit` identifies the accepted pre-adoption baseline (`8fa1c296…`); `source_commit` identifies the final reviewed descendant after the fixture correction. The source changes include inherited controller recovery tests, explicit four-worker delegation for both proof modes, dependency pin checks, client cleanup and exception behavior, exact two-field binding adoption, and sixth-rewrite refusal before writer entry. Transaction fault tests interrupt every durable boundary and confirm a single activation, exact recovery, no rollback and no proof shortcut. Independent adapter and supervisor tests exercise file protections, atomic compare-and-replace, signal handling and child reaping.

Live acceptance is final mode only: generation-nine markers are already published. Before-marker integration is established by controlled tests, without changing those markers. Remote enumeration and GET/HEAD checks are fresh but do not constitute an atomic remote snapshot. This adoption does not establish further rewrite pacing, a new Pebble reopen, format-14 compatibility on the full clone, or readiness to cut over production. PR3 stays open, draft and unmerged.
