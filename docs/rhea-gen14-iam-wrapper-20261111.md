# Rhea Gen14 Wasabi IAM wrapper — source-locked, offline only

**Status:** This wrapper has been executed on the jump box in `status`, `plan`, and `provision` modes. Status and plan returned success. Provision returned **REFUSED, exit 2**. It has also been staged as a private root-owned four-file test copy under `/root/.local/share/rhea-gen14-iam-wrapper-20261111/` on Rhea, with identical SHA-256 source pins. An attempted live Rhea invocation was blocked by the connected tool's access controls. **Do not retry through another route to bypass the restriction.**

The wrapper is `scripts/run_rhea_gen14_iam.sh`, stacked on the corrected IAM policy and acceptance source in draft PR #12. No credentials have been read, exposed, created, rotated or revoked; no Wasabi IAM, bucket, S3 object, Pebble, reader, rclone, or production Kubo/walker mutation occurred.

## Why it is fail-closed

The wrapper takes exactly one approved command (`status`, `plan`, `provision`, `accept`, `cleanup`, `lockout`). It resolves its own source directory without symlink traversal, requires the same file owner, private directory/file modes, a single hardlink count, and verifies **exact source SHA-256** for the offline admin, IAM policy and signed-admission modules. It clears the process environment with `/usr/bin/env -i`, ignores Python environment and user-site packages, and supplies no AWS/rclone credentials. The Python entrypoint reports a deterministic, fixed disposable-bucket plan; all mutating modes refuse unconditionally until a separately approved and audited root IAM management adapter exists. Root privileges or an arbitrary environment variable cannot enable these methods.

The user's statement that the **production** rclone credential has IAM access is not independently verified. Production rclone authentication is not automatically authorization for migration-admin operation, and using a wrapper to access a credential path previously blocked by the platform is not permitted. The reviewed management path must be explicitly enabled or connected; do not copy an existing production access key, put credentials in shell arguments, environment variables, Git, or chat.

## Verified commands

From a clean, reviewed repository checkout, run:

```bash
/usr/bin/bash scripts/run_rhea_gen14_iam.sh status
/usr/bin/bash scripts/run_rhea_gen14_iam.sh plan
/usr/bin/bash scripts/run_rhea_gen14_iam.sh provision
```

The third command **must** print `result: REFUSED` and return exit code 2. These commands are usable only if all three source hash pins still match; any change requires a separately reviewed, updated wrapper. This is not an implicit install/upgrade path.

The fixed disposable bucket name is `rhea-gen14-iam-test-20261111-48be1ecd7cc848fb`. It must not be confused with the certified full clone bucket. The generated plan is **offline evidence**, not a live account or a promise that users/credentials exist.

The root staging directory on Rhea is 0700, and the four source files are owned by root and mode 0600. They do not run automatically or modify running services. Only an approved root-management operator should decide whether to retain or delete that isolated staging after reviewing it.

## Tests and remaining live gates

`tests/test_rhea_gen14_iam_wrapper.py` tests status/plan/refusal, fixed scope, modified source bytes, symlinks, bad ownership/permissions, unknown arguments and injected credential canaries. It imports no SDK and never opens a Wasabi network connection. Existing PR #12 IAM/marker tests remain unchanged.

Before the real two-SST clone run, a separately authorized Wasabi IAM-admin connection must provide a fixed, signed root provisioning controller with fsynced intent before each `CreateUser`, `PutUserPolicy` and `CreateAccessKey` and independently reconciled outcomes, securely retained test-user keys, real negative Put/Copy/multipart/delete checks with versioned reads, plus dirty rclone marker reconciliation. After IAM passes, signed reader stop/writer mount/Go execution, two independent S3 proofs, marker publication and safe reader return must also pass. **No production cutover.**
