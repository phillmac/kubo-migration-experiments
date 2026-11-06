# Rhea full-clone pacing: second bounded window

## Status and purpose

**Prepared; not yet activated or executed.** This plan admits up to four more independently requested rewrite units, starting with generation10 and an operator review before generation11. It raises the cumulative ceiling from five to nine successful units, with generation13 as the last permitted checkpoint. It does not schedule a loop or authorize a production cutover.

The starting point is the [verified post-reboot restoration](rhea-post-reboot-restoration-20261106.md): generation9, five successful rewrites, format013, 93,690 marked files, 93,697 live SSTs and 7,786,594,080,100 SST bytes. The reader is PID4415; the preserved production service leader and actual rclone server are PIDs3786 and3905. The boot is `6fc54ca7-d64a-4125-98fa-d0a728485237`, running kernel `6.8.0-149-generic`. Production remains in that restored state; Kubo and the walker remain inactive, and the walker remains disabled. The writable lab mount is absent at the starting point.

This document describes the reviewed operation, not live results. Policy activation, writer startup, generation10, any later units, and reader restoration still require their actual receipts. Source CI must pass before deployment; this draft makes no claim that the new source commit has passed CI.

## Fixed policy and deployment

All new orchestration evidence belongs to:

```text
/root/.local/share/rhea-wasabi-lab-admin-20261101/pacing-batch2-20261107
```

The [policy engine](../scripts/rhea_batch2_policy_transition.py) derives and checks the exact transition below. It changes only the shared journal's controller hash and `binding.limits.maximum_rewrites`. The certificate, current generation, rewrite count and `pending: null` remain unchanged. The separately installed pins change only their controller hash. Existing controllers, pins, verifier, scanner, decoder, Go binary, configuration, admission and caches are preserved.

| Protected artifact | Before SHA256 | After SHA256 |
| --- | --- | --- |
| Shared state | `22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2` | `0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9` |
| Deployment pins | `684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c` | `1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363` |
| Generation9 certificate | `220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2` | Unchanged |

The [successor controller](../scripts/run_rhea_full_clone_steps_batch2.py), SHA256 `b10ab6b32dc3dd6dd9a0aff1263a21dccadbfad603082368e01b81c081c37828`, installs under its own filename with `full-clone-batch2-step-pins.json`. Its four-worker verifier and per-unit budgets remain unchanged. The old controller must reject the new journal binding. Its new invocation timings are diagnostic output; they do not change certificate or journal schemas.

After source review and CI, root stages these eight protected payloads and a `deployment.json` binding their exact bytes to the published source commit and parent `10a088d5f3de8e3c1e555e6b1848f224dbd79451`:

| Installed name in the new namespace | Repository source or retained input |
| --- | --- |
| `run.py` | [Policy adapter](../scripts/run_rhea_batch2_policy.py) |
| `health.py` | [Phase-aware health helper](../scripts/rhea_batch2_health.py) |
| `transaction.py` | [Pure policy engine](../scripts/rhea_batch2_policy_transition.py) |
| `mounts.py` | [Mount lifecycle](../scripts/rhea_batch2_mount_lifecycle.py) |
| `one-step.py` | [Single-unit admission](../scripts/rhea_batch2_one_step.py) |
| `controller-candidate.py` | Frozen successor controller above |
| `expected-state-before.json` | Exact state preimage above |
| `expected-pins-before.json` | Exact pins preimage above |

The following commands describe root's separate, recorded invocations. The policy check is read-only; apply installs only the successor controller and pins, then activates the exact state transition under the original lifecycle lock.

```sh
RHEA_BATCH2_OPS=/root/.local/share/rhea-wasabi-lab-admin-20261101/pacing-batch2-20261107
python3 "$RHEA_BATCH2_OPS/run.py" --check
python3 "$RHEA_BATCH2_OPS/run.py" --apply
```

The policy retains preimages, intent and completion. An interrupted transition requires inspection followed by an explicit `--resume`; there is no automatic retry or rollback. Resume can reseal exact visible files after an interrupted fsync, but refuses incomplete or differing immutable files. Neither policy command opens Pebble or changes services.

## Reader-to-writer handoff

After successful policy completion, root invokes:

```sh
python3 "$RHEA_BATCH2_OPS/mounts.py" start --apply
```

Under the lifecycle lock, startup checks the restored reader and production identities, exact generation9 bytes, retained admission, free-space reserve and reader metadata. It records the reader-stop intent before stopping that reader once.

The known intentional reader exit143 has a narrow, explicit reconciliation branch. Only after the original process and mount are absent, and the exact failed transient-unit tuple matches, startup saves `reader-stop-observed.json` and `reader-reset-intent.json`, calls `reset-failed` once for that unit, and verifies collection before saving `reader-reset-completed.json`. It does not repeat the stop or restart the reader. Any other endpoint or interruption leaves evidence for separate operator reconciliation.

The writer's transient unit disappeared at reboot. Startup therefore validates its rendered digest and existing admission, stages the exact unit with its own receipt, and launches it once using the retained cache. It records the new writer's PID, start ticks and boot identity in `writer-started.json`; later work uses that tuple, never an assumed PID. Closed metadata is checked synchronously before the monitored read-only Go open, warming the new FUSE directory. Matching metadata before and after that open, clean health and unchanged state are required for `start-completed.json`. Startup performs no database rewrite or journal advance.

## Generation10, then a separate review gate

The [single-unit helper](../scripts/rhea_batch2_one_step.py) requires an explicit generation, mode and raw state digest. Generation10 starts from the exact activated state:

```sh
python3 "$RHEA_BATCH2_OPS/one-step.py" --generation 10 --dry-run \
  --expected-state-sha256 0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9
python3 "$RHEA_BATCH2_OPS/one-step.py" --generation 10 --apply \
  --expected-state-sha256 0e9221d610461a170f7cf3fe70bc23f93d5fe8a30cc638143a47e13bb661b1c9
```

Each command has exclusive `step-000010-dry-run-*` or `step-000010-operation-*` intent, stdout, stderr and timing evidence. Apply requires a successful dry-run from those exact state bytes and the same sealed writer. The state, startup evidence and process identity are rechecked **inside the unchanged Controller's own lock**, before any Go call. The freshly computed picker plan must equal the saved dry-run plan before a writer stage is created.

One applied unit retains the existing full sequence: bounded authoritative rewrite, closed snapshot, data flush, complete before-markers S3 proof, ordered marker publication, a second complete final S3 proof, read-only reopen, then durable certificate and journal advance. No listing snapshot is reused between the two proofs. An atomic unit may contain multiple input files; its actual plan and output determine the accounting.

After generation10 completes, root reviews its writer report, selected inputs and outputs, both proof phases, certificate, cumulative lineage, read-only reopen, clean queue, state digest and timings. Only then may root write exclusive `reviews/000010.json` with verdict `admit-next-unit`, binding generation10, next generation11, the current raw state and certificate hashes, and the prior operation's intent/stdout/timing hashes. The helper cannot approve that receipt itself.

Generation11 requires its own dry-run and apply with the newly reviewed raw state digest; generations12 and13 follow the same separate process using reviews of11 and12. There is no automatic next unit. Each applied invocation runs the controller in process: HUP, TERM and INT latch a cooperative stop request, while the existing Go-child monitor writes the stop sentinel and waits for the same child. Operators must not terminate that supervisor or send TERM/KILL to a database writer to enforce a deadline. Failed attempts retain their journal and receipts and cannot be replayed by rerunning this helper.

## Graceful completion or a deliberate pause

Root can finish at any fully certified generation10–13 with `pending: null`; the recipe does not force the remaining units. For example, after reviewing generation10:

```sh
python3 "$RHEA_BATCH2_OPS/mounts.py" finish 10 --apply
```

Finalization binds the selected state, certificate and closed metadata, verifies a clean queue, and asks the wrapper to halt the writer gracefully under the lock. It requires clean service exit and absent writer mount/socket, retaining the cache. It launches the original reader configuration once, records the new reader tuple in `finalization/reader-restored.json`, checks exact metadata, runs the pinned read-only reader inspector, and checks metadata again. Final health binds the restored reader, unchanged production identities and selected certified state. `finalization/completed.json` is the completion authority; failures remain separate receipts and require inspection.

The prepared local checks cover the policy's exact two-leaf transition and durability recovery, health/runtime pairing, explicit single-unit and manual-review admission, state races, receipt preservation and cooperative child supervision. Live timing and output claims will be added only from the resulting receipts. This window remains a disposable full-clone migration experiment; production cutover and completion of the full migration are outside its scope.
