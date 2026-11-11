# Rhea gen14 marker IAM guardrail — 11 November 2026

Offline revision based on `48be1ecd7cc848fb39f295ad90495427931d60d1`.
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
user. They contain no `Principal` element or identity condition. The IAM support
list documents `aws:username`, `aws:userid`, and `aws:accountid`, but does **not**
list `aws:PrincipalArn`. This revision removes that key from every Allow and
removes the unsupported `WrongIdentity` Deny. It introduces no replacement
identity key. Attachment to the new distinct user supplies the identity boundary;
independent STS and authenticated signer checks bind acceptance to that user.
The only generated condition key is the documented `s3:prefix`.

Wasabi's resource-policy guide currently shows PrincipalArn examples despite
its omission from the IAM support list. Those examples are not evidence that
this identity policy supports it. Follow the explicit support list and require
actual disposable-scope API checks. Explicit Deny takes precedence over Allow.
[IAM condition support](https://docs.wasabi.com/apidocs/iam-and-sts-support),
[Resource policy semantics](https://docs.wasabi.com/docs/how-do-i-restrict-bucket-access-with-resource-based-policies),
[identity policy Principal rule](https://docs.wasabi.com/docs/creating-a-policy),
[user separation and NotResource](https://docs.wasabi.com/docs/how-do-i-set-up-wasabi-for-user-access-separation).

`Resource: "*"` occurs only in the identity-local `NoOtherAPIs` Deny.
`NoLateralResources` uses `NotResource` to deny S3 access outside the exact
bucket/prefix or marker families, and `NoOtherPublication` denies publisher PUT
outside the concrete approved marker set. These statements grant no global
access and apply only to the user with the attached policy. `NoOtherAPIs` uses `NotAction` to deny IAM/bucket-policy/versioning
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
It now contains only supported condition context (`s3:prefix` where applicable),
never `aws:PrincipalArn`. `PrincipalArn` remains a separate authenticated signer
field in the diagnostic contract, outside the IAM document and condition map.
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
and this acceptance run refuses. Removing supported listing conditions to make
the evaluator pass, projecting those conditions to an unconditional policy,
guessing undocumented parameters, or silently running the local simulator would
test different semantics and is forbidden. Removing the unsupported PrincipalArn
from the source builder is a reviewed policy change with new hashes, not a
runtime evaluator workaround. The same holds
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

## Published policy hash change

For the exact offline example above (account `123456789012`, names
`offline-writer`/`offline-publisher`, manifest key
`marker.manifest.000017.MANIFEST-000123`, no CURRENT change), canonical SHA256:

| Artifact | Base 48be1ecd | Corrected |
| --- | --- | --- |
| Writer | `405fac7c7cbc119312fc2c7c647976c5be52af9e6785b753edcef862e1bc2ac2` | `8828092941ce0c46eefd9169d0b887a4e6cbb54b9a9e865464c5d4a1e3002dd0` |
| Publisher | `899c556576289eb8b33e8538a9d38ab03a6fed7aa01da6119a7bf9750a64d526` | `c05b027e08f63378f89e639b35d1506077df1edd3b57e83371cae2ca218ebb3f` |
| Entire policy binding | `142f56a51d1ef4db7e628148243cbb9d073796570bd76d6b64df9c7da42c93c7` | `7fe43a7eb3ba6e9ff84640e992580987b4e0a81a51802b4c7733c61547505c7c` |

These are example hashes, not a signature or live approval. Any authorization,
evaluator cases or receipts pinned to the old bytes must be reviewed and signed
again. The certified bucket/prefix, marker families, action/resource denies,
closed N2 marker set, and unchanged CURRENT requirements remain in force. Tests
continue checking Deny precedence with an inherited Allow, and now assert no
unsupported condition keys appear. The local simulator remains offline evidence.

## Conservative admin plan and gate

`scripts/rhea_gen14_iam_admin_acceptance.py` deliberately ships the conservative
offline alternative. **Direct root management is not implemented.** There is no
SDK import, credential lookup, profile loading, remote connection, signer,
secret ingestion/storage, durable host journal, installation or cleanup path.
It does not create users, keys or buckets. `real_acceptance()` always refuses,
even as root. Root account, approval public-key pin, and installed-source pin
remain `None`; arguments and environment variables cannot provision them.
Separate supported admin authorization is still required. The development
session's blocked credential access must not be bypassed through SSH, Codex,
encodings, other worktrees or a different credential source.

Safe commands from this checkout:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rhea_gen14_iam_admin_acceptance.py status
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rhea_gen14_iam_admin_acceptance.py plan
```

Status is the default and reads no files. Plan prints only public target metadata,
fixed names, exact canonical policy documents, hashes and action ordering. No
account/bucket/endpoint/policy/profile/key options exist. All live-like modes
(`temporary-test-bucket`, `provision`, `accept`, `cleanup`, `lockout`) return
`REFUSED` and exit 2 before any external action. No live authorization command
exists in this revision.

The fixed prospective test scope is:

| Item | Immutable value |
| --- | --- |
| Test bucket | `rhea-gen14-iam-test-20261111-48be1ecd7cc848fb` |
| Wrong-bucket control | `rhea-gen14-iam-control-20261111-48be1ecd7cc848fb` |
| Prefix | `rhea/pebbleds/` |
| Writer | `rhea-gen14-test-20261111-48be1ecd7cc848fb-writer` |
| Publisher | `rhea-gen14-test-20261111-48be1ecd7cc848fb-publisher` |
| IAM endpoint | `https://iam.wasabisys.com` |
| S3 endpoint / region | `https://s3.wasabisys.com` / `us-east-1` |
| STS endpoint | `https://sts.wasabisys.com` |
| Test writer policy SHA256 | `b828fad32852d15e813a1f6b300093924e4c743f7e9b111c0dc938d0c7d24d23` |
| Test publisher policy SHA256 | `4cdfa9fe6077be6ec3d37fc82e0c0b3bdd104c2ed5ef24cc6a66bede4ceb8415` |
| Offline plan SHA256 | `eccbf72cab597f0733265f11ce3d7cce12be5b7bc7d1d03acd825e7967225764` |

Both names must be freshly created exclusively for this test and versioned.
Never reuse an existing bucket or substitute a bucket after a name collision.
Changing a name requires a separate source review, new hashes and a new external
signature. The control bucket is also fresh and owned, so a real AccessDenied
can be distinguished from a nonexistent bucket or someone else's bucket.
There is no capability here to read or mutate the historical clone bucket.
The private test builder transforms only resource fields to the fixed test
bucket; the certified-scope public builder still accepts no bucket argument.
It retains the same supported prefix conditions and explicit Deny guardrails.
The temporary identities get no bucket lifecycle, versioning, ACL, policy, IAM,
role-assumption or credential-management grants.

`ProvisioningModel` is an immutable **offline ordering model**, not a durable
controller. Its sequence is both CreateUser calls, both PutUserPolicy calls,
then both CreateAccessKey calls. Each intent precedes its outcome; missing
secret-save confirmation, failed or unknown action permanently stops the model.
An emergency latch stops the model and does not claim remote revocation. A
caller can fabricate or fork a pure model, so it confers no live capability.
The fake IAM tests check partial creation, attachment failures, ambiguous key
creation, missing durable-save receipts and no retry. They generate no keys or
credential strings. Production persistence must not be inferred from these tests.

The private `_quarantine_checks` function exercises the prospective SDK call
sequence with independent fake clients. It checks both STS identities, enabled
versioning before/after, version-specific writer data PUT/GET and publisher exact
marker PUT/GET, negative writer marker PUT/CopyObject/CreateMultipartUpload/
DELETE, publisher negatives for unapproved markers/data, actual version DELETE,
and wrong-bucket PUTs to the control bucket. Copy sources are readable by the
tested identity, preventing source denial from masking a destination mistake.
Only explicit `AccessDenied` with HTTP 403 counts; timeouts, signature failures,
404s and unknown responses stop. Objects contain fixed public bytes under 1KB.
No retry, automatic cleanup or arbitrary bucket input exists. Positive writes
use IfNoneMatch and require non-null version IDs and exact bounded readback.
Every rehearsal result sets actual enforcement and deployment authorization to
false. Raw SDK bodies, credential fields and exception text are excluded from
results and stdout. It is **not** a complete authenticated live adapter.

Copy and multipart destination authorization uses `s3:PutObject`: a publisher
allowed to PUT its exact approved marker may also copy or initiate multipart to
that same marker. No fictional `s3:CopyObject`/multipart IAM actions are used.
The negative checks target the writer's protected markers and the publisher's
unapproved markers. The current fake check sequence covers multipart initiation;
part upload, part copy, completion and abort on admin-seeded upload IDs still
require the separately reviewed live adapter and test setup.

## Root-only live acceptance checklist (not executed)

This is required work for a **separate** supported, user-authorized Rhea admin
session and host-adapter review. Do not deploy this checkout to obtain access.
No current command completes these steps.

1. Independently approve immutable account, endpoints, both new bucket names,
   usernames, prefix, exact objects, policy hashes, installed-source digest,
   root profile name and path, plan digest, expiry and one-use nonce. Obtain a
   user-signed external approval binding all of them. Install the independent
   public verification pin and code only by the supported root provisioning
   process. No self-signing, caller trust anchors or dynamic runtime bypass.
   Sign a distinct cleanup/lockout authorization; do not infer approval from a
   plan, test pass, or `ValidatePolicy` response.
2. Provision code and trusted parents root-owned and not writable by any other
   user. Use a dedicated root-only named admin profile in a root 0700 directory
   and 0600 files; no profile discovery, environment/metadata/default credentials,
   console password lookup, remote credential fetching or credential command
   arguments. Use existing Rhea boto3/botocore, explicit fixed HTTPS endpoints,
   certificate verification and bounded timeouts. Disable SDK retries with
   `total_max_attempts=1`, reject proxies/endpoint overrides, disable debug SDK
   logging and verify the admin STS account/identity before mutations.
   [Wasabi boto3 endpoints](https://docs.wasabi.com/docs/how-do-i-use-aws-sdk-for-python-boto3-with-wasabi).
3. Require an exclusive root state lock and a durable anti-replay ledger.
   Verify the signature, expiry, source pins and fresh nonce before consuming
   that nonce durably. Use no-follow opens and trusted directory descriptors;
   reject symlinks, hardlinks, wrong owners/modes, existing output names and
   writable ancestors. Create every journal/receipt/secret file with `O_EXCL`,
   0600, under a new root 0700 directory; fsync files **and directories** before
   side effects. Persist a sanitized intent before **every** IAM action and an
   outcome afterward. Status must remain local/read-only by default. No automatic
   retry after an ambiguous outcome; independently inspect state and reconcile
   with a separately signed decision. Never restart a pure model as recovery.
4. Durably record intent, then create both fresh disposable buckets and enable
   and verify versioning. Prove ownership, isolation, no preexisting objects,
   versions, delete markers, uploads, bucket grants or policies. Treat collisions
   or ambiguous creation as a stop. Never inspect the historical clone to check
   safety. Scope the admin test adapter to the fixed fresh names; prohibit
   caller-selected account, S3 endpoint or bucket. Neither test identity can
   create/manage buckets or change versioning.
5. Verify exact new usernames are unused via bounded, complete ListUsers reads.
   Create each distinct user **without any key, login profile or group grant**.
   Record returned identity and durable outcome. Attach the exact reviewed inline
   policy to each and independently inspect policy bytes, no group membership
   and no other grants. Persist and fsync both confirmations before key creation.
6. Persist each CreateAccessKey intent first, issue the call once, and store its
   result only in the root directory with exclusive 0600 creation, file fsync
   and directory fsync. Never print/log/upload/commit credentials or put them in
   process arguments. If the response, write or fsync fails, mark UNKNOWN/STOPPED;
   do not create another key, delete users automatically, or claim success.
   Leave created principals intact for evidence. Reconcile ListAccessKeys and
   exact user/policy state under separate authorization; a lost secret cannot
   be recovered by retrying CreateAccessKey.
7. Construct independent writer/publisher S3 and STS clients using their exact
   saved credentials, fixed endpoints and no retries. Authenticate both identities
   and verify their separation from the admin. Use only the two disposable
   buckets. Run real positive data and exact marker PUT/GET with version IDs,
   negative marker PUT/CopyObject/multipart/DELETE (including version deletes),
   arbitrary publisher data/marker negatives and wrong-bucket negatives. Keep
   every object at most 1KB, with fixed public content. Confirm current object
   and version histories remain intact after denied operations. Seed multipart
   upload IDs only via the quarantined admin path, recording ownership/key/IDs
   before exercising UploadPart, UploadPartCopy, CompleteMultipartUpload and
   AbortMultipartUpload denials. Never invent upload IDs and treat their 404s
   as permission evidence.
8. Establish propagation by independently timed, explicit real API observations
   after policy attachment; preserve root-only signed/witnessed request IDs,
   timestamps, policy hashes, exact operation outcomes and version receipts.
   Stop at the first unexpected outcome. Do not retry mutating IAM requests or
   rerun conditional positive writes against existing keys. Review a bounded
   readback/negative-probe phase separately for subsequent observations. A
   single instantaneous pass, local simulator, ValidatePolicy, successful
   attachment or mocked normalized response does not prove deployed enforcement
   or propagation. Quarantine acceptance does not authorize certified-bucket
   deployment, the N2 pilot, Rhea cutover or production Kubo changes.
9. If uncertain, stop issuance/publication and preserve state. Explicit emergency
   lockout must be a separate root action on only these two recorded principals:
   install a deny-all inline identity policy (supported unconditional Deny),
   confirm propagation, revoke exact recorded keys, and independently verify
   loss of access. Unknown IAM outcomes remain UNKNOWN; a local stopped flag
   cannot prove revocation. Keep principals/evidence while acceptance is ongoing.
10. Cleanup is a distinct explicit step after verified state and evidence review.
    Revoke the exact test access keys, remove exact test inline policies, delete
    the two test users only when their full state is verified, then enumerate
    and delete **all versions/delete markers and multipart uploads only in the
    two disposable buckets** and remove those buckets. Persist every intent and
    outcome with no automatic retry or blanket cleanup. No certified/production
    paths, original cap9/gen13 state, or production Kubo actions are in scope.

## Revision offline verification

The new `rhea-iam-provisioning-offline.yml` workflow runs local-only Python
regressions on Python 3.12 and 3.13, compiles scripts/tests in memory, checks
historical source pins, asserts unprovisioned anchors and refusing live modes,
and runs the full suite. It uses no Wasabi provider, credential secrets, SSH,
deployment, dependency installation or SDK. Checkout token persistence is off;
AWS configuration/credential files point to `/dev/null` and metadata is disabled.
The checked-in evidence report records actual local test totals and hashes.
No root-only execution, live IAM/S3 calls, propagation, credential creation,
remote deployment, commit, push or merge has been performed for this revision.
