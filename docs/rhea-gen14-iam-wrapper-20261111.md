# Rhea Gen14 Wasabi IAM user-operated wrapper

The wrapper now dispatches `provision` to the functional
[`rhea_gen14_create_iam_credentials.py`](../scripts/rhea_gen14_create_iam_credentials.py).
When the user runs it as root on Rhea, it creates the two fixed IAM users,
attaches the reviewed isolated test-bucket policies, and creates one actual
access key per user. This coding session performs no remote execution,
credential access, IAM/S3 requests, deployment, push, or merge. The previous
connected-tool restriction remains in force; do not use another connector or
execution route to bypass it.

Historical note: the previous wrapper was tested in offline modes and staged
as a four-file root copy on Rhea; its provision command always refused. A
connected-tool attempt at remote execution was blocked. That history is not
evidence that the new tool has been installed or run.

The frozen admin module, IAM generator, signed admission module, historical
certificates, and their hashes remain unchanged. Historical admin `status`
continues to say `OFFLINE_ONLY`; it describes that frozen module. Wrapper
`status` and `plan` still invoke it without reading credentials. `accept`,
`cleanup`, and `lockout` still refuse; none revokes remote credentials.

The wrapper requires directory mode 0700, file mode 0600, matching ownership,
single-link regular source files, and four exact SHA-256 pins, including the new
provisioner. Live `provision` and read-only remote `verify` additionally require
root and root-owned source ancestors without group/other write permission.
It clears the environment with `env -i` and runs Python with `-E -s -B`.

After reviewing and installing the five files as described in the
[provisioning runbook](rhea-gen14-iam-credentials-20261111.md), the user runs:

```bash
bash /root/.local/share/rhea-gen14-iam-wrapper-20261111/run_rhea_gen14_iam.sh provision
```

Successful output includes only sanitized status and private credential-file
paths. Secrets are written exclusively inside
`/root/.local/share/rhea-gen14-iam-credentials-20261111/`. Pending intents stop
all further provisioning; retain the journal and use the runbook's manual
reconciliation procedure. This creates IAM credentials only: no bucket, S3
object, Kubo process, clone, reader, mount, or migration is changed.

Offline wrapper tests use a harmless replacement module with a locally updated
pin to test dispatch. They never execute the real provisioner, including when
CI runs as root. Provisioner tests use temporary fake configuration/state,
fake IAM/STS clients, and blocked sockets.
