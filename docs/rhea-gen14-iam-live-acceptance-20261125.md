# Rhea live IAM/S3 acceptance and the next migration gate

## Recorded live result — 25 November 2026 (Sydney)

**PASS: 207 of 207 service checks, including 123 explicit permission denials.**
The run completed at 09:26:45 AEDT (22:26:45 UTC on 24 November). Both scoped
identities matched their records. Conditional publication returned the required
412 responses for an existing-key create and a mismatched ETag, and succeeded
with the matching ETag. Protected marker version histories matched exactly;
there were no protected delete markers or remaining uploads owned by the run.

The source SHA-256 was
`eb46ed0a0bf0865ceab4176ac816970b7e1d43089821eeeef244b96570a3c4c6`.
All 207 intent/receipt links were verified; the 416 JSON evidence files have a
manifest digest of
`f3a5d60fe8259ef327b786079b7130d45cf1c37ddfc2ccbb8e4e98eebbc314ef`.
See the [sanitized complete case report](evidence/rhea-gen14-live-iam-acceptance-20261125.json).

The buckets, versions and scoped credentials remain available for the next
isolated rehearsal. The API result does not establish dirty-cache quarantine,
continuous denial over time, custom Wasabi operation behavior, or a gen14
compaction result.

## Purpose and scope

Exercise the real writer and publisher access keys created by PR #15 against
the two fixed disposable buckets. Passing this run establishes the tested API
permissions and conditional-write behavior for these identities and this test
scope. Pebble writer readiness still depends on lifecycle integration and crash
qualification; this report is a disposable-bucket acceptance result.

| Item | Fixed value |
| --- | --- |
| Test bucket | `rhea-gen14-iam-test-20261111-48be1ecd7cc848fb` |
| Wrong-bucket control | `rhea-gen14-iam-control-20261111-48be1ecd7cc848fb` |
| Test prefix | `rhea/pebbleds/` |
| Allowed publication | `marker.manifest.000017.MANIFEST-000123` |
| S3 endpoint | `https://s3.ca-central-1.wasabisys.com` |
| Region | `ca-central-1` |
| Maximum fixture payload | 1,024 bytes |

The original offline plan named the global/us-east-1 S3 endpoint. This live
adapter deliberately uses ca-central-1, matching the verified credential
metadata and production account's existing regional configuration. The fixed
bucket and object names and the reviewed permission documents are unchanged.
The adapter requires the two buckets to be absent before it creates them;
it does not adopt pre-existing buckets.

## Service checks

The root fixture client creates only the two test buckets, enables versioning,
and creates small known fixture objects and multipart uploads. Every permission
test uses the relevant scoped user's client, with the actual STS identity checked.

The matrix covers ordinary data and marker positive controls; protected marker
and CURRENT writes, copies, deletion and version deletion; valid multipart
upload/part-copy/completion/abort requests; publisher denial on ordinary data;
wrong bucket and wrong or near-matching prefixes; scoped and unscoped listings;
bucket administration denials; and conditional marker publication. Real version
and multipart identifiers prevent missing-resource errors from masquerading as
permission enforcement. Returned object bodies are bounded and closed.

A negative permission case passes only on explicit `AccessDenied` with HTTP 403,
or, for a multi-delete response, exact per-object AccessDenied entries with no
successful deletions. Timeouts, signature errors, other 403 errors, 404s and
malformed responses are failures. Conditional publication separately requires
the expected precondition result, and protected version histories are checked
against the recorded intended versions.

This first matrix covers the standard S3 operations listed above. Wasabi's
custom MOVE, compose and append operations are explicitly excluded from its
claim, as are access to production or full-clone resources. Early and late
denial observations record their elapsed interval; they do not prove continuous
enforcement between requests.

The script preserves per-operation evidence and stops at the first unexpected
outcome. Cleanup is limited to aborting this run's explicitly recorded multipart
uploads. The buckets, object versions, users, keys, policies and journals remain
available for review and the next isolated rclone rehearsal.

## Runtime compatibility

Rhea has boto3/botocore 1.34.46. Its PutObject model lacks IfMatch and IfNoneMatch.
The adapter adds those conditional headers through a temporary, client-local
`before-call.s3.PutObject` hook before signing and removes it in `finally`.
This tests the real HTTP preconditions without replacing the system SDK or
silently dropping unsupported keyword arguments. Clients have explicit fixed
endpoints, TLS verification, bounded timeouts and one total attempt.

## Root entry point and evidence

```bash
bash /root/.local/share/rhea-gen14-iam-live-acceptance-wrapper-20261125/run_rhea_gen14_live_iam_acceptance.sh status
bash /root/.local/share/rhea-gen14-iam-live-acceptance-wrapper-20261125/run_rhea_gen14_live_iam_acceptance.sh run
```

The source launcher checks fixed hashes and root/private ownership. Credentials
remain in their existing protected files and are used only in process. The
acceptance state is under:

```
/root/.local/share/rhea-gen14-iam-live-acceptance-20261125/
```

Do not rerun a partial attempt by clearing its state. A saved report is evidence
of the recorded run, not an assertion that future requests are already checked.
If a case fails, inspect its sanitized operation/error/version evidence and
correct or qualify the issue before any pilot.

## What comes next after a successful run

The next concrete step is an **isolated rclone dirty-marker and cache-quarantine
rehearsal against the disposable test bucket**. First refresh the current host
baseline, then use a separate mount, configuration, cache and authenticated RC
endpoint. Prove that ordinary data uploads while marker writes remain denied,
including retries. Close the test writer and stop its mount; prove there is no
open writer, uploading marker, outstanding multipart operation, reusable dirty
cache or automatic restart path. Only then exercise the exact publisher release
and inspect the complete version history.

After that rehearsal, implement and qualify the real reader/writer handoff,
continuous monitoring, close/snapshot, data drain and publication integration.
The current RootQueueRuntime, root host adapter mutation paths and multistep Go
entry point still refuse live work; changing a readiness flag is insufficient.
The newly created credentials authorize only the disposable test bucket, so the
full-clone trial also needs separately bound clone-scoped identities and checks.

The first gen14 trial should then perform at most two actual SST compactions in
one writer session against the disposable full clone, with a single close,
independent complete S3 proofs before and after marker publication, and a fresh
read-only reopen. Retain the historical generation-13/cap9 evidence. Qualify
interruptions and uncertain publication outcomes before increasing batch size.
Use measured elapsed time, cache/backlog and write amplification to decide how
to scale the migration.

## References

- [Marker IAM and dirty-cache release plan](rhea-gen14-marker-iam-20261111.md)
- [Marker gate prerequisites](rhea-gen14-marker-gate-20261111.md)
- [Reader/writer lifecycle integration](rhea-reader-bridge-integration-20261110.md)
- [Multi-SST pilot plan](rhea-multi-sst-pilot-20261110.md)
- [Wasabi boto3 endpoints](https://docs.wasabi.com/docs/how-do-i-use-aws-sdk-for-python-boto3-with-wasabi)
- [Boto3 event hooks](https://docs.aws.amazon.com/boto3/latest/guide/events.html)
