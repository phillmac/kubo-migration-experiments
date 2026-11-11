# User-run Rhea Gen14 IAM credential creation

This is a functional root-run tool for exactly two new Wasabi IAM credentials.
The user runs the reviewed wrapper on Rhea. The coding agent must not SSH,
read production credentials, invoke the remote wrapper, make IAM/S3 requests,
deploy, push, or merge. Installation and execution below are user actions;
none was performed by this coding session.

The only IAM mutations, in order, are:

| Sequence | Action | User suffix |
| --- | --- | --- |
| 00 | CreateUser | writer |
| 01 | CreateUser | publisher |
| 02 | PutUserPolicy | writer |
| 03 | PutUserPolicy | publisher |
| 04 | CreateAccessKey | writer |
| 05 | CreateAccessKey | publisher |

Exact names are `rhea-gen14-test-20261111-48be1ecd7cc848fb-writer` and
`rhea-gen14-test-20261111-48be1ecd7cc848fb-publisher`. Both use inline policy
`rhea-gen14-quarantine-v1`. Resources are limited by the frozen reviewed policies
to `rhea-gen14-iam-test-20261111-48be1ecd7cc848fb`; no bucket is created here.
Production Kubo and the certified full clone bucket
`rhea-pebble-lab-20261101-39037c6f01` are never targets.

| Reviewed artifact | SHA-256 |
| --- | --- |
| Plan | `eccbf72cab597f0733265f11ce3d7cce12be5b7bc7d1d03acd825e7967225764` |
| Writer test policy | `b828fad32852d15e813a1f6b300093924e4c743f7e9b111c0dc938d0c7d24d23` |
| Publisher test policy | `4cdfa9fe6077be6ec3d37fc82e0c0b3bdd104c2ed5ef24cc6a66bede4ceb8415` |

Policies are identity-attached; unsupported `aws:PrincipalArn` conditions are
absent. The plan, original IAM generator, and gen13/cap9 history are unchanged.
The wrapper contains exact source pins for all four Python modules; compare
these against the reviewed files before installing.

The implementation uses Wasabi's documented IAM actions and STS
GetCallerIdentity, with explicit IAM/STS endpoints and IAM region `us-east-1`.
See [Wasabi IAM/STS support](https://docs.wasabi.com/apidocs/iam-and-sts-support)
and [Wasabi boto3 setup](https://docs.wasabi.com/docs/how-do-i-use-aws-sdk-for-python-boto3-with-wasabi/).

## User installation and command

On Rhea, root must have boto3 and botocore available to `/usr/bin/python3`.
From the user-supplied reviewed checkout, install exactly these five files into
`/root/.local/share/rhea-gen14-iam-wrapper-20261111/`, owned by root. Set the
directory to 0700 and every file to 0600:

```text
run_rhea_gen14_iam.sh
rhea_gen14_create_iam_credentials.py
rhea_gen14_iam_admin_acceptance.py
rhea_multi_sst_marker_iam.py
rhea_multi_sst_signed_admission.py
```

Update the previous four-file staging with the reviewed wrapper and new module;
retaining the old wrapper will retain its permanent refusal. No automatic
installer or deployment is shipped. Keep the source ancestors root-owned and
without group/other write permission; do not install live sources under `/tmp`.

As root on Rhea, run exactly:

```bash
bash /root/.local/share/rhea-gen14-iam-wrapper-20261111/run_rhea_gen14_iam.sh provision
```

There are no bucket, user, account, policy, credential, config, endpoint, retry,
or adoption flags. Explicit execution by the user is authorization for the six
fixed actions. Nonroot refuses before opening the credential source.

## Credential source and identity binding

Only `/root/.config/rclone/rclone.conf`, section `wasabi-ca-central-1`, is read.
It must be a single-link regular root-owned 0600 file; all ancestor directories
must be root-owned, without symlinks or group/other write permission. The section must use
`type = s3`, Wasabi provider if specified, the exact
`s3.ca-central-1.wasabisys.com` endpoint (optional `https://`), explicit
`access_key_id` and `secret_access_key`, and no session token or environment
authentication. DEFAULT inheritance is refused. Parsing uses
`ConfigParser(interpolation=None)`; nothing is shell-sourced. No alternate
configuration files or SDK credential discovery are used.

No independent numeric account pin was supplied. On the first run, STS must
return a valid 12-digit account and matching IAM root/user ARN. That identity
from the fixed production credential source becomes the immutable private
journal binding **before the first mutation**. This does not independently
prove an operator-expected account number. Root must ensure the fixed source
belongs to the intended Wasabi account before execution. Every later run
requires that exact account, ARN, and hashed user ID; changes refuse.

Both fixed users must initially return explicit `NoSuchEntity`; existing users
are never adopted. Read capability failures stop before mutation. SDK action
availability is checked. Read-only prechecks cannot prove permission to perform
future mutations; a denied mutation stops at its pending intent, without retry
or fallback. Policy readback must match before its receipt and before keys.
The direct entrypoint also clears inherited environment variables and fixes
HOME to `/nonexistent` before reading credentials. The SDK uses `total_max_attempts=1`, connect timeout 5 seconds, read timeout
10 seconds, TLS, explicit credentials, no environment proxies, and no SDK/HTTP
logging. Neither credentials nor raw provider exceptions appear in output.

## Private results, status and verification

State is exclusively in
`/root/.local/share/rhea-gen14-iam-credentials-20261111/`, root-owned 0700,
with an exclusive nonblocking flock. Every file is root-owned 0600, regular,
single-link, opened without symlink following. No file is replaced or truncated.

`binding.json` pins the plan and identity. Each action gets an exclusive
`NN.intent.json`, fsynced before the IAM call, followed by an exclusive
`NN.receipt.json`. Records bind sequence, exact action/user/policy hash, plan,
identity, and previous receipt hash. Files and parent directories are fsynced.
Receipts contain only hashes and approved metadata, never raw access keys.

`writer.json` and `publisher.json` contain AccessKeyId, SecretAccessKey, account,
user, role, region, endpoint and plan hash. These exclusive files are fsynced
immediately after a valid CreateAccessKey response, before the sanitized
receipt or next request. Keep them private; do not paste them into chat, logs,
arguments, environment variables, Git, or connectors. The production key is
never copied into these files.

The original wrapper `status` and `plan` remain credential-free. To inspect the
local journal without opening source or generated credentials, root can run:

```bash
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent /usr/bin/python3 -E -s -B /root/.local/share/rhea-gen14-iam-wrapper-20261111/rhea_gen14_create_iam_credentials.py status
```

This local status reports completed receipts and pending state; it does not
prove remote outcomes. Remote read-only verification uses the pinned wrapper:

```bash
bash /root/.local/share/rhea-gen14-iam-wrapper-20261111/run_rhea_gen14_iam.sh verify
```

Verify reads the fixed admin source, calls STS/GetUser/GetUserPolicy/ListAccessKeys,
and compares completed receipts plus private key-file hashes. It performs no
IAM mutation and no S3 calls. Status/verify may create the private directory and
lock file. A complete successful provision rerun reconciles all six receipts
and makes **zero mutations**. A clean completed prefix can advance only after
all prior receipts reconcile and future users/keys remain absent. Before
advancing, the provisioner fsyncs the existing records and private key files
again, covering a prior receipt write interrupted at fsync.

## Refusal and manual recovery

Exit 0 means the requested local/provision/verify operation completed; exit 2
means refusal. Output is sanitized. Wrapper errors identify unsafe modes,
ownership or source hash mismatch. A generic source/OS/SDK failure is deliberately
not accompanied by an exception body. Inspect only filenames and private
metadata locally; do not enable SDK debug logging to diagnose this tool.

An intent without a valid receipt means **stop for manual reconciliation**.
Timeouts, crashes after sending, provider denials, unexpected responses,
failed policy readback, failed key-file writes and partial files all stop the
run. There is no automatic retry, adoption, cleanup, revocation or reset.
A partial/corrupt record also refuses. Later runs do not contact the credential
source or provider when a pending intent is detected.

Retain the entire directory, any private key files, and permissions. Under the
user's separate administrator workflow, inspect Wasabi's user IDs/ARNs, inline
policies, access-key inventory and audit history for the exact intended action.
Do not delete intents, fabricate receipts, rerun CreateAccessKey, or delete the
state directory to force progress. A saved key with a missing receipt must be
reconciled as an existing result. A returned key whose secret was not saved may
need explicit administrator revocation; this tool cannot recover its secret.
Any repair/revocation requires a separately reviewed manual action; no command
here claims it has revoked remote access. Preserve history even when no remote
change appears to have occurred.

Credential creation does not prove S3 enforcement or authorize a clone run.
Actual negative S3 testing, bucket/versioning setup, signed migration admission,
reader coordination and any cutover remain separate work.

## Offline checks

```bash
bash -n scripts/run_rhea_gen14_iam.sh
python3 -B -m unittest discover -s tests -q
git diff --check
```

Tests replace the source/config directory and SDK clients with synthetic
fixtures, and block sockets. Wrapper dispatch tests inject a harmless local
module and local hash pin; they never invoke real provision/verify, even as
root. CI does not install boto3 or run the real provisioning CLI. The workflow
runs all Python regressions, source compilation and shell syntax checks without
Wasabi access. Passing tests establish code behavior with fakes, not live IAM
or S3 evidence.
