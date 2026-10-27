# Kubo migration experiments

Disposable, synthetic-only Kubo/Pebble experiments. This repository must never
contain production repository copies, private keys, cloud credentials, private
operational runbooks, or identifying production inventories.

## Accepted synthetic result — 27 October 2026

[Run40472972184](https://github.com/phillmac/kubo-migration-experiments/actions/runs/40472972184)
at commit `cd0504c41634d8122f74042b84b6a7633084ba37` **passed**:
23guard tests, actual0.31.0->0.34.1 Pebble bridge, explicit bundled repository
schema16->17->18 migration using0.43.1, matching target payload/pin/MFS reads,
and restoration of an untouched0.31.0 generation. The original seed's file
hashes were unchanged. This is a small synthetic acceptance, **not production
approval or a proven in-place downgrade**.

See [dated experiment results and artifact hashes](docs/results-20261027.md)
for the failed download attempt, successful bridge-only control, full target
result, exact executable hashes and untested cases.

## Isolation

GitHub-hosted Ubuntu24.04 runners only. The baseline workflow prints one line.
The Pebble workflow downloads official GitHub release assets and verifies the
published SHA-512 checksums, then runs Kubo commands as an unprivileged user in
a new network namespace containing only loopback. It uses a clean environment
and newly generated synthetic repositories. There are no cloud credentials,
production mounts or existing-repository arguments. Checkout credentials are
not persisted. Only synthetic reports and checksums are uploaded, never configs
or generated identity keys.

## Reproducible experiment

1. Execute the23Python safeguard and migration-boundary tests.
2. Download/checksum Kubo0.31.0,0.34.1 and0.43.1.
3. Create a fresh0.31.0 local `pebbleds` fixture with deterministic file bytes,
   recursive pins, an unpinned raw block and an MFS reference.
4. Seal the original; open an independent copy with0.34.1 and compare bytes,
   pin sets and MFS root.
5. Probe0.43.1 on another copy and retain the expected schema-version refusal.
6. With explicit `--migrate-target`, use another fresh bridge copy and run
   `ipfs --offline repo migrate --to=18`. Check schema18, unchanged identity and
   datastore configuration, then exact target content/pin/MFS preservation.
7. Restore a copy of the untouched0.31.0 generation and verify it with0.31.0.

The harness does not start a daemon, implicitly download a migration tool,
hand-edit version markers, change pins outside its fixture, or perform GC.
Without `--migrate-target` it remains a bridge-only smoke test. A green smoke
run can therefore have `target_migration_verified=false`: inspect the report,
not only the workflow colour. The current workflow explicitly enables migration.

## Limits and next tests

This2MiB repeating fixture deduplicates heavily. Direct pins are an empty set.
Large/real physical copies, varied fixtures, target-side new writes, daemon
lifecycle, interrupted migration, locking/cancellation, nonempty direct pins,
upgraded-copy downgrade compatibility and remote-storage behavior remain untested.
Only restore of the untouched old generation is accepted as rollback here.

No result authorises production deployment. Real data and infrastructure-specific
runbooks must stay private. Evidence artifacts expire after14days; dated results
retain exact run/commit IDs and digests for independently preserved copies.
