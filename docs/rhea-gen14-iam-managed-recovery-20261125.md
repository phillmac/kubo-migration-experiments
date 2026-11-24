# Rhea IAM recovery using managed policies

## Problem and observed evidence

The original root provisioner created the two fixed disposable users, then
stopped with a pending writer `PutUserPolicy` operation. Its catch-all exception
handler hid the provider error. The original journal contains successful user
creation receipts at 00 and 01, an intent at 02 without a receipt, and no key
creation records or credential files.

The user's diagnostic returned `NoSuchEntity`, HTTP 404, at `read_writer_policy`
after validating the account, the two user identities, and empty key inventories.
A subsequent authenticated, read-only `GetAccountSummary` on Rhea reported:

| Item | Characters |
| --- | ---: |
| User inline-policy quota | 2,048 |
| Reviewed writer policy | 2,308 |
| Reviewed publisher policy | 2,998 |
| Managed-policy quota | 5,120 |

The saved evidence is `docs/evidence/rhea-gen14-iam-policy-quotas-20261125.json`.
The original provider exception cannot be reconstructed from the old journal.
The size incompatibility is directly established by Wasabi's reported quota;
the original error code remains unknown.

## Recovery decision

Install the same two permission documents as customer managed policies and
attach one to each existing test user before creating its access key. The JSON
documents, their SHA-256 values, bucket scope, prefix scope, and deny statements
are unchanged:

| Role | Policy SHA-256 |
| --- | --- |
| Writer | `b828fad32852d15e813a1f6b300093924e4c743f7e9b111c0dc938d0c7d24d23` |
| Publisher | `4cdfa9fe6077be6ec3d37fc82e0c0b3bdd104c2ed5ef24cc6a66bede4ceb8415` |

The recovery explicitly supersedes the original inline-policy provisioning
sequence. It does not write a false success receipt for the failed original
operation, remove the pending intent, or reset the original journal.

The fixed managed policy names are the original user names plus `-policy`:

- `rhea-gen14-test-20261111-48be1ecd7cc848fb-writer-policy`
- `rhea-gen14-test-20261111-48be1ecd7cc848fb-publisher-policy`

The six new ordered mutations are `CreatePolicy` for writer and publisher,
`AttachUserPolicy` for writer and publisher, then `CreateAccessKey` for writer
and publisher. Both exact policy documents and attachment inventories must
be verified before keys can be created.

### Wasabi read-back representation

The first managed-policy request succeeded, but Wasabi returned singleton
arrays as scalar strings, for example `"Action": ["s3:*"]` became
`"Action": "s3:*"`. A read-only structural comparison found nine such
representation differences and no changed permission values in the writer
policy. The initial strict JSON hash check stopped before any attachment or
key creation.

IAM's grammar permits both representations. Read-back verification now
normalizes only `Action`, `NotAction`, `Resource`, `NotResource`, and
`s3:prefix` under `StringLike`/`StringNotLike` from a string to a one-item
array. The resulting canonical hash must still equal the original reviewed
policy SHA. It does not normalize `Effect`, `Sid`, `Null`, other conditions,
unknown fields, multiple values, or statement order. The submitted documents
remain unchanged. This allows the pending writer policy to be verified
without issuing another `CreatePolicy` request.

The observation is recorded in
`docs/evidence/rhea-gen14-iam-policy-normalization-20261125.json`.

## Durable records and credentials

The original state is preserved at:

```
/root/.local/share/rhea-gen14-iam-credentials-20261111/
```

The new managed-policy recovery journal and new private key files live at:

```
/root/.local/share/rhea-gen14-iam-managed-credentials-20261125/
```

The recovery binds its plan to hashes of the original journal files, the
original caller identity, and the validated original user identities. It
holds the original journal lock while operating and uses its own exclusive
lock and immutable intent/receipt records. A key's secret is saved in its
root-owned 0600 role file before its receipt or the next mutation. The state
directory is root-owned 0700. No secret is printed or included in repository
evidence.

An unresolved key creation is never retried. Unknown policy creation or
attachment outcomes can only be reconciled by checking the exact recorded
resource and unchanged policy document; a missing object does not authorize
automatic repeated creation. An existing unrelated resource is a collision,
not a candidate to adopt. Unexpected user policies, group membership, or
keys stop recovery.

## Commands

The source bundle is installed separately at:

```
/root/.local/share/rhea-gen14-iam-managed-wrapper-20261125/
```

Run the launcher with Bash; all source files are intentionally 0600. The
launcher verifies source hashes, root ownership, single hard links, private
file modes, and protected ancestor directories, then clears the environment.

```bash
bash /root/.local/share/rhea-gen14-iam-managed-wrapper-20261125/run_rhea_gen14_iam_managed.sh status
bash /root/.local/share/rhea-gen14-iam-managed-wrapper-20261125/run_rhea_gen14_iam_managed.sh inspect
bash /root/.local/share/rhea-gen14-iam-managed-wrapper-20261125/run_rhea_gen14_iam_managed.sh recover
bash /root/.local/share/rhea-gen14-iam-managed-wrapper-20261125/run_rhea_gen14_iam_managed.sh verify
```

`status` reports local state without accessing source credentials. `inspect`
performs provider reads. `recover` performs the authorized managed-policy and
key creation sequence. `verify` reports completion only after verifying the
entire six-step sequence. The old wrapper remains installed and intentionally
continues to report its original pending inline-policy state; use the new
launcher for this recovery.

Failures identify the stage, exception class, provider error code, and HTTP
status without printing raw provider messages, request bodies, or credentials.
Retain the journals when a failure occurs. Do not delete intents or fabricate
receipts to make a subsequent run continue.

## Scope and verification limits

Only the two fixed disposable users and their two new fixed managed policies
are in scope. The existing production rclone credentials are used locally
from their original protected configuration; they are not copied or rotated.
The recovery makes no S3 calls and does not change a bucket, mount, Kubo,
walker, datastore marker, or gen13/cap9 checkpoint.

Credential creation and IAM read-back verification do not prove actual S3
enforcement or authorize a gen14 production cutover. Those are separate
acceptance and migration operations.

## Primary references

- [Wasabi IAM and STS support](https://docs.wasabi.com/apidocs/iam-and-sts-support)
  documents `CreatePolicy`, `AttachUserPolicy`, `GetPolicyVersion`, and
  `GetAccountSummary`.
- [Wasabi inline IAM policies](https://docs.wasabi.com/docs/how-to-use-inline-iam-policy-with-wasabi)
  documents API support and the Console limitation.
- [AWS IAM quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
  explains inline versus managed policy size limits. Use the observed Wasabi
  values above rather than assuming AWS's managed-policy quota applies.
- [IAM policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
  documents that array brackets are optional for single values.
