# Rhea gen14 marker IAM guardrail — 11 November 2026

Offline implementation on PR #10 base `2b15e03f596648d56a34fc92406f1fb89ae9e294`.
No installation, remote testing, credential creation, IAM changes, or live
admission occurred. Historical cap9/gen13, its nine successful rewrites, null
pending state, original markers, and `CURRENT = b'MANIFEST-000000\n'` remain
unchanged. The original marker gate, source pins, root installation, production
Kubo bucket, Kubo/walker frozen state, and other worktrees remain untouched.

## Policy scope and exact documents

`scripts/rhea_multi_sst_marker_iam.py` contains the pure builder. Its sole target
is bucket `rhea-pebble-lab-20261101-39037c6f01`, prefix `rhea/pebbleds/`. Bucket,
prefix and object resources cannot be supplied by a caller. `Bindings` requires
one ASCII 12 digit account and two different exact usernames without paths,
variables, wildcards, whitespace, or ARN injection. These are offline inputs;
they are not provisioned production identities.

The following object resources are permanently protected against the writer's
`s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`, and
`s3:AbortMultipartUpload`:

```text
arn:aws:s3:::rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/marker.manifest
arn:aws:s3:::rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/marker.manifest.*
arn:aws:s3:::rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/marker.format-version
arn:aws:s3:::rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/marker.format-version.*
arn:aws:s3:::rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/CURRENT
```

The bare marker names are protected as well as their dotted families. The
wildcard suffix also covers a slash-containing suffix. These are direct
publication paths under this exact prefix; unrelated nested application files
are not publication keys. No bucket-wide wildcard Allow is generated.

| Identity | Allowed | Explicit restrictions, including inherited Allow |
| --- | --- | --- |
| Writer | GetObject/GetObjectVersion, PutObject/DeleteObject, AbortMultipartUpload/ListMultipartUploadParts on data within the exact prefix; scoped ListBucket/ListBucketVersions; GetBucketVersioning/GetBucketLocation | Protected marker writes/deletes denied; all version deletion denied; lateral resources, unscoped listings, management APIs, ACL writes and role assumption denied |
| Publisher | PutObject on the exact supplied concrete marker names; GetObject/GetObjectVersion on protected marker families and CURRENT; marker-scoped listing; bucket version/location reads | No SST/data access, arbitrary marker PUT, deletion, version deletion, multipart abort, lateral bucket access, IAM or bucket mutation |

All documents are **identity policies**, individually attached to the new exact
user. They contain no `Principal` element. Each uses the fixed `aws:PrincipalArn`
in its Allow conditions, plus a Deny for the wrong/missing principal context.
Wasabi documents separate identity policies and explicit Deny precedence.
[Resource policy semantics](https://docs.wasabi.com/docs/how-do-i-restrict-bucket-access-with-resource-based-policies),
[identity policy Principal rule](https://docs.wasabi.com/docs/creating-a-policy),
[user separation and NotResource](https://docs.wasabi.com/docs/how-do-i-set-up-wasabi-for-user-access-separation).

`Resource: "*"` occurs only in identity-local Deny statements: wrong identity,
actions outside the permitted API list, and missing/invalid access paths via
`NotResource`. It never grants global access and never applies to all account
principals. `NoOtherAPIs` uses `NotAction` to deny IAM/bucket-policy/versioning
changes and future unlisted operations. STS GetCallerIdentity is excluded from
that Deny for identity checks. No `ListAllMyBuckets` compatibility permission is
added. ValidatePolicy testing uses an independent read-only diagnostic identity
binding outside the installed writer's API restrictions where necessary; the
evaluation itself must be signed by the tested identity, as discussed below.

Canonical documents are UTF-8 JSON with sorted keys, sorted action/resource
arrays, deterministic statements, compact separators and one final newline.
`Policies` retains immutable bytes; `.document(role)` returns a detached copy.
`validate_bundle` regenerates and compares exact bytes before acceptance.
`.binding` includes exact account/ARNs, bucket/prefix, marker set and both policy
hashes; `.sha256` hashes that entire binding. There is no installation CLI.

For an **offline synthetic example only**, print both full exact documents and
their binding without writing files or contacting anything:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts python3 - <<'PY'
import json
from rhea_multi_sst_marker_iam import Bindings, build_policies
p = build_policies(Bindings('123456789012', 'offline-writer', 'offline-publisher'),
                   ('marker.manifest.000017.MANIFEST-000123',))
print(p.writer_raw.decode(), end='')
print(p.publisher_raw.decode(), end='')
print(json.dumps(p.binding, sort_keys=True))
print(p.sha256)
PY
```

Those names/account/marker are synthetic, not installation approvals. Real names
and the exact closed-batch marker name must come from independent review.
Publisher names accept concrete Pebble manifest/format marker syntax, never
wildcard resources. For N2, publish only the independently proven changed
manifest marker. The unchanged format marker stays readable but not writable.

`CURRENT` is denied to both writers and the N2 publisher. The generic offline
builder can represent a publisher CURRENT permission only when also supplied
the SHA256 of a separately signed CURRENT-change artifact. A hash alone is no
signature or permission. **ReleaseModel refuses changed CURRENT even with that
hash**, because N2 requires unchanged CURRENT. Enabling a future changed-CURRENT
pilot needs separate reviewed verification of the signed artifact, its bytes,
scope and timing; this implementation does not admit that pilot.

## Read-only acceptance contract

Wasabi documents ValidatePolicy parameters `PolicyDocument`, `IsPrincipal`,
`UseAction`, `UseResource`, and `UseService`; evaluation assumes the request
signer and can return ALLOW, DENY, or no status. `wasabi_validate_request` creates
only the documented IAM query (`Action=ValidatePolicy`, version `2010-05-08`,
`IsPrincipal=true`). STS uses GetCallerIdentity. No clients or credentials are
created here. [Wasabi IAM/STS API](https://docs.wasabi.com/apidocs/iam-and-sts-support).

`WasabiValidatePolicyDI` takes two already-authenticated read-only endpoint
adapters. Each supplies `evaluate_read_only(query, expected_context=...)` with a
bounded timeout and retries disabled. The query is the exact service request;
`expected_context` is a verifier sidecar, **not** an undocumented wire parameter.
Use form-encoded POST for long IAM requests. The normalized result must contain:

```text
Decision: exactly ALLOW or DENY
RequestSha256: SHA256 of the canonical exact query
PrincipalArn: the independently authenticated signing user
EvaluatedContext: the exact condition context actually evaluated
Propagation: CONFIRMED, based on separate evidence
Source: WASABI_VALIDATE_POLICY
```

These are this module's strict adapter fields, **not claimed Wasabi response
fields**. No raw XML parser or network transport is shipped. A future adapter
must decode the documented/observed response without inventing success fields,
retain request IDs/raw response evidence, bind the same credentials used for STS,
and verify the source of context and propagation evidence. A forged normalized
response is not an authenticated service observation.

The documentation does not expose arbitrary `s3:prefix` context injection.
If a read-only adapter cannot establish that context, it must report unsupported
and this acceptance run refuses. Removing conditions, projecting them to an
unconditional policy, guessing undocumented parameters, or silently running the
local simulator would test different semantics and is forbidden. The same holds
if the tested identity cannot call ValidatePolicy: refusal, no extra IAM grant
or automatic workaround. In particular these installed policies intentionally
deny IAM management/debug actions. A separately reviewed diagnostic arrangement
must establish whether Wasabi permits this read-only evaluation for the exact
signer; an admin signer cannot impersonate the writer by passing an ARN.

`validate_read_only` verifies both STS account/ARN/UserId observations, exact
bucket with `ExpectedBucketOwner`, and Enabled versioning before/after the scan.
Versioning mutations are denied in both policy documents. Request IDs may vary;
the stable Status/MFADelete state must not change. This checks a bounded
observation interval; an administrator outside these principals can still change
the bucket, so signed external controls must hold versioning stable during a
real pilot.

Every publication path is tested for PUT, COPY destination, multipart initiation,
part upload/copy, completion, DELETE and version DELETE. Copy source reads are
separate authorizations; destination copy and multipart completion require
`s3:PutObject`, not invented `s3:CopyObject`/`s3:CompleteMultipartUpload` actions.
This follows the [S3 operation permission mapping](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html);
Wasabi behavior still needs independent disposable testing.

Ordinary data actions must ALLOW for writer, data and management actions must
DENY for publisher, and lateral buckets/prefixes and unscoped listings must DENY
for both. Local `simulate(..., inherited_allow=True)` checks explicit-Deny
precedence even with a hypothetical inherited global Allow, including wrong and
missing principals. It is bounded to the generated policy vocabulary; it is
not a general Wasabi simulator.

Errors, denied/unsupported API, timeout, omitted/duplicate/unknown decision,
unexpected ALLOW/DENY, mismatched request/hash/signer, uncertain propagation, or
unstable versioning return REFUSED. No SDK fallback or retry exists. Successful
results say **POLICY_EVALUATOR_SIMULATED**, with immutable evidence bytes and
`actual_enforcement_proven=False`, `deployment_authorized=False`. ValidatePolicy
evaluates a supplied policy, not all deployed attachment/bucket-policy state.
Neither a local pass nor a Wasabi policy evaluation proves live protection.

## Future independent provisioning and disposable testing

This is a future reviewed manual procedure; no step ran in this coding session.

1. Preserve the historical installation, old credentials, cap9/gen13 journal,
   original marker versions and frozen production state. Confirm the target is
   the disposable full clone, never the production Kubo bucket. Independently
   approve a new writer username and a different publisher username in the
   exact Wasabi account. Use new isolated identities, not an existing user,
   shared group, root identity or shared rclone credentials. Any future credential
   provisioning belongs to that separate administrator workflow, not this code.
2. Before creating/installing anything, independently sign a deployment artifact
   pinning those names/ARNs/account, both canonical policy bytes/hashes and bundle
   hash, target bucket/prefix, exact source hashes, trust-anchor validity, epoch,
   clone baseline, process/boot/mount/cache/RC identities, and maximum two units.
   Install the artifact and independent public verifier pins in a protected,
   reviewed root deployment. No caller/environment signer or on-host signing
   key may become the trust root. This repository has no production IAM trust
   pin, dynamic signer, installer or root controller for this workflow.
3. Attach each exact identity policy **only to its approved new user**, with no
   broad group policy or bucket policy change. Never attach an identity-local
   Deny to old users, groups or all principals. Independently enumerate effective
   attachments, bucket policies, ACLs and service configuration. Confirm no
   unexpected grants or explicit Denies make the positive data cases unusable.
   Keep the writer's marker Deny attached permanently.
4. First test the policy pattern on an independently approved throwaway bucket
   and prefix with no historical objects. This fixed-target builder intentionally
   cannot retarget itself. A separate reviewed scratch-only artifact must pin the
   substituted scratch resources; do not add a bucket override, patch constants
   at runtime, or attach this clone policy as a global policy. A throwaway prefix
   alone must still use marker basenames matching the protected publication
   resources; moving a marker under an unprotected nested directory tests a
   different policy. A distinct throwaway bucket avoids adding canary versions
   to the clone's protected marker history.
5. In that scratch workflow, independently provision sentinel data/marker
   versions and an incomplete multipart marker upload before denial. Establish
   writer ordinary Get/GetVersion/Put/Delete and scoped version listing success;
   denied marker PUT/DELETE/version DELETE, direct COPY, UploadPartCopy and
   completion of the already-open upload. Test bare/dotted marker families and
   CURRENT. Reject any publication or hidden intermediate version, even if later
   removed. Test publisher exact marker PUT/read versions, denied data write/read,
   arbitrary marker write, all deletion, lateral bucket/prefix, IAM/bucket-policy
   and versioning changes. Retain full request/response/version evidence, expected
   denials and positive controls under exact signer identity.
6. Verify conditional marker PUT behavior independently: absent-key
   `IfNoneMatch='*'` or exact reviewed ETag `IfMatch`; repeat deliberately stale
   preconditions in scratch and verify no new version. Expected-owner handling,
   request signing, no implicit SDK retry and interrupted-request reconciliation
   must also be demonstrated. These are future service tests, not implemented
   live probes. Unsupported conditions mean no pilot.
7. After separately installed clone policies have propagated, independently
   establish actual denial **before any Pebble writer open**, with policy hashes,
   both signer identities, complete case/proof IDs, fixed bucket/prefix, versioning,
   and a bounded validity interval. Clone marker history must stay exactly at its
   signed baseline. Scratch success or a caller flag cannot substitute. Do not
   perform successful canary publication against actual clone marker keys.

## Dirty rclone cache and the one-shot release model

rclone v1.68.1 two-hour writeback and RC `vfs/queue-set-expiry` cannot stop uploads
already in flight. Permanent writer IAM marker denial blocks publication even
if rclone begins such an upload. It can also leave failed/dirty marker entries
and later retries. Publishing the same marker with another identity while that
cache remains reusable risks duplicate versions or stale publication later.
Policy generation alone therefore does not make a clone pilot safe.

The pure `ReleaseModel` enforces the following evidence sequence:

```text
independent signed authorization + independent signed PRE-OPEN actual denial
  -> PREOPEN_DENIED
signed complete first four-worker S3/version-history proof + validated RC markers
  + writer closed + mount stopped + zero dirty/queued/uploading markers
  + independently hashed safe cache disposition
  -> DATA_PROVEN_CACHE_SAFE
explicit exact conditional marker intent, matching publication hash in that proof
  -> PENDING_RELEASE
separate witness-signed publisher propagation/enforcement proof for that intent
  + writer marker DENY still active + publisher other keys DENY
  -> RELEASE_READY
separate one-shot release attempt -> RELEASE_ATTEMPTED
signed confirmed exact publication/version receipts -> RELEASE_RECORDED
```

Authorization signatures and witness signatures use separate immutable public
key pins. Records are canonical immutable bytes, domain-separated and bound to
policy/batch/epoch, previous record hash, unique proof ID and ordered timestamps.
The authorization lifetime is at most 900 seconds. The epoch is consumed in the
returned model at start, not after successful release. Empty/missing proof,
reused epoch/ID, altered policy/hash/bytes, wrong anchor, pre-open writer, dirty
markers, incomplete proof, unknown transition or publication result all refuse.
Signatures are verified using existing detached Ed25519 verification primitives;
this module has no signing function. Tests explicitly mock signatures and ship
no cryptographic keys. An unsigned dict or simulation report is not a receipt.

The first proof's details include content hashes of complete S3 proof, RC proof,
safe cache disposition, and exact conditional PUT plan. Do not satisfy these
with empty queue labels alone. Stop and seal the exact writer mount, preserve
forensic cache/evidence, and independently demonstrate no dirty file, open
handle, multipart operation or restart path can later emit a marker. Never
blanket-delete a cache, clear live queue state, remove writer Deny, or resume the
old writable cache as part of this runbook. There is no cache-clearing API here.
The safe quarantine/reconstruction procedure remains a separately reviewed live
integration requirement; if it cannot be proven, release remains blocked.

The publisher release proof concerns its isolated one-shot publication capability
and independently observed effective policy. It never removes writer Deny.
Merely generating/attaching a publisher policy does not establish release timing.
The publisher credentials/capability must be held outside the writer and withheld
until the reviewed release procedure. This model makes no IAM or RC call at any
transition and automatically retries nothing.

A pure immutable model is **not a durable replay ledger**: a Python caller can
retain an old value, fork state, or fabricate an instance. Real release requires
an exclusive authenticated root controller and fsynced, non-reusable epoch,
intent, attempt and receipt records committed before side effects. After intent
or attempt with unknown result, preserve evidence and independently inspect
policy/cache/complete version histories. Do not retry IAM, RC or publication,
reopen the writer or mark success. This code provides no such controller.

An actual two-SST clone pilot additionally requires the signed/pinned real Go
writer integration, continuous monitoring, preserved closed batch and data
drain, two independent complete four-worker proofs, exact one-shot publication,
fresh read-only reader handoff/reopen and crash reconciliation described in the
[prior marker gate runbook](rhea-gen14-marker-gate-20261111.md). Historical root
live mutation methods remain disabled; no deployment authorization is returned.

## Offline validation

Python 3.12+ and the existing suite's system OpenSSL are sufficient. No pip
dependencies, SDK, AWS secret, IAM credential, Rhea connection or Go modification
is needed. From this worktree:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q
git diff --check
```

The new workflow runs the complete existing suite plus the new adversarial
tests on Python 3.12 and 3.13, compiles every Python source in memory, verifies
historical source pins and disabled root mutation methods, and prints a JSON
offline report. Checkout credentials are not persisted; AWS configuration is
empty, metadata discovery disabled, permissions read-only, with no deploy,
remote command, AWS secret, or IAM/S3 transport. The repository evidence report
records the actual local run and its limitations.
