# Kubo migration experiments

Disposable, synthetic-only Kubo/Pebble experiments. This repository must never
contain production repository copies, private keys, cloud credentials, private
operational runbooks, or identifying production inventories.

## Isolation

GitHub-hosted Ubuntu 24.04 runners only. The baseline workflow prints one line.
The Pebble workflow downloads official, versioned binaries and verifies the
published SHA-512 checksums, then runs Kubo commands as an unprivileged user in
a new network namespace containing only loopback. It uses a clean environment
and newly generated synthetic repositories. There are no cloud credentials,
production mounts or existing-repository arguments. Checkout credentials are
not persisted. Only synthetic reports and checksums are uploaded, never configs
or generated identity keys.

## First experiment

1. Confirm a minimal hosted hello-world run.
2. Execute the 17 Python safeguard tests.
3. Download and checksum Kubo 0.31.0, 0.34.1 and 0.43.1.
4. Create a 0.31.0 local `pebbleds` fixture with deterministic file bytes,
   a recursive pin, an unpinned raw block, and an MFS reference.
5. Seal the original, open an independent copy with the 0.34.1 bridge and compare
   payloads, pin sets and MFS root.
6. Probe 0.43.1 opening on another copy. This first probe does **not** invoke
   repository-schema migrations; a schema-version refusal is recorded separately.
7. Restore a copy of the untouched 0.31.0 generation and verify it with 0.31.0.

The harness does not implicitly start a daemon, download a migration tool, edit
repo version markers, change pins outside its synthetic fixture, or perform GC.

**A green bridge-smoke workflow is not successful migration to the target.**
Inspect `target_migration_verified`, the errors and the scope in `report.json`.
No result authorises production deployment. Physical-copy scale, interrupted
migration, locking/cancellation, direct pins, full rollback and remote-storage
behavior require additional tests.

## Evidence

- Hosted hello baseline: run [40471803547](https://github.com/phillmac/kubo-migration-experiments/actions/runs/40471803547), commit `c1961a1086bc4b38995d5f7ab1279235be304fa1`: **passed**.
- First real bridge workflow: run [40472013448](https://github.com/phillmac/kubo-migration-experiments/actions/runs/40472013448), commit `555b403c2f358199fdf0b6980c1a9f32684226d8`: initiated; consult the run and its report for the actual outcome.

Evidence artifacts expire after 14 days; durable summaries should retain exact
run/commit IDs and distinguish failed attempts from successful acceptance.
