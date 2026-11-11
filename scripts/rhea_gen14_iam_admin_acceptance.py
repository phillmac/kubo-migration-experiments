#!/usr/bin/env python3
"""Conservative OFFLINE plan/gate for a future root-only Wasabi acceptance.

There is deliberately no SDK import, credential discovery, admin transport,
secret ingestion, signing, installation, or live provisioning CLI. The pure
provisioning model is NOT a durable journal. The private S3 check engine is
exercised with fakes; it is NOT an authenticated host adapter or live evidence.
See the runbook for requirements before separately reviewing any live adapter.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import json

import rhea_multi_sst_marker_iam as iam

DOMAIN = 'rhea-gen14-quarantine-acceptance-v1'
# Fixed new names derived from this review's date and base commit, not caller input.
TEST_BUCKET = 'rhea-gen14-iam-test-20261111-48be1ecd7cc848fb'
CONTROL_BUCKET = 'rhea-gen14-iam-control-20261111-48be1ecd7cc848fb'
WRITER = 'rhea-gen14-test-20261111-48be1ecd7cc848fb-writer'
PUBLISHER = 'rhea-gen14-test-20261111-48be1ecd7cc848fb-publisher'
POLICY_NAME = 'rhea-gen14-quarantine-v1'
IAM_ENDPOINT = 'https://iam.wasabisys.com'
S3_ENDPOINT = 'https://s3.wasabisys.com'
STS_ENDPOINT = 'https://sts.wasabisys.com'
REGION = 'us-east-1'
PREFIX = iam.PREFIX
MARKER = 'marker.manifest.000017.MANIFEST-000123'
DATA = '000123.sst'
MARKERS = ('marker.manifest', MARKER, 'marker.manifest.000018.MANIFEST-000124',
           'marker.format-version', 'marker.format-version.000012.013', 'CURRENT')
PAYLOAD = b'gen14 disposable IAM test\n'  # Public, non-sensitive, < 1KB.
# Unprovisioned source anchors. No env/argument/config path can set them.
ROOT_ACCOUNT = None
ROOT_APPROVAL_PUBLIC_KEY_SHA256 = None
ROOT_INSTALLED_SOURCE_SHA256 = None

Refusal = iam.Refusal


def _test_documents():
    """Internal fixed TEST transformation; never a caller-selectable S3 scope.

    The account placeholder is used only to construct identity-free document
    bytes; it is not an account approval or an authentication credential.
    The original certified-scope builder remains immutable and unparameterized.
    """
    source = iam.build_policies(iam.Bindings('000000000000', WRITER, PUBLISHER), (MARKER,))
    result = {}
    for role in ('writer', 'publisher'):
        document = source.document(role)
        for row in document['Statement']:
            for field in ('Resource', 'NotResource'):
                if field in row:
                    row[field] = [r.replace(iam.BUCKET_ARN, 'arn:aws:s3:::' + TEST_BUCKET, 1)
                                  if r.startswith(iam.BUCKET_ARN) else r for r in row[field]]
        raw = iam.canonical(document)
        iam.require(iam.BUCKET.encode() not in raw, 'certified bucket in test policy')
        result[role] = dict(document=document, sha256=iam.sha(raw))
    return result


def plan():
    """Safe JSON and hashes only; no filesystem, credentials, clients or calls."""
    return dict(domain=DOMAIN, mode='OFFLINE_PLAN', live_enabled=False,
                account=ROOT_ACCOUNT, approval_pin=ROOT_APPROVAL_PUBLIC_KEY_SHA256,
                target=dict(bucket=TEST_BUCKET, wrong_bucket_control=CONTROL_BUCKET,
                            prefix=PREFIX, marker=MARKER, data=DATA,
                            versioning='Enabled', require_fresh_buckets=True,
                            maximum_object_bytes=1024),
                users=dict(writer=WRITER, publisher=PUBLISHER), policy_name=POLICY_NAME,
                endpoints=dict(iam=IAM_ENDPOINT, s3=S3_ENDPOINT, sts=STS_ENDPOINT, region=REGION),
                policies=_test_documents(),
                provisioning_order=list(_steps()),
                n2_current_sha256=iam.sha(b'MANIFEST-000000\n'),
                root_adapter_implemented=False, cleanup_automatic=False)


def plan_sha256():
    return iam.digest(plan())


def _steps():
    policies = _test_documents()
    # Both identity policies must be confirmed and durably recorded BEFORE keys.
    return tuple(dict(action=action, role=role, user=user,
                      policy_sha256=policies[role]['sha256'] if action == 'PutUserPolicy' else None)
                 for action in ('CreateUser', 'PutUserPolicy', 'CreateAccessKey')
                 for role, user in (('writer', WRITER), ('publisher', PUBLISHER)))


@dataclass(frozen=True)
class ProvisioningModel:
    """Pure ordering/failure rehearsal, NOT root authorization or persisted state.

    A future host adapter must persist/fsync intent BEFORE sending each action,
    and persist/fsync the sanitized outcome before calling outcome(). An unknown
    result, crash, partial create, failed secret save, or even a known failure
    stops this model permanently. It provides no resume/retry/rollback capability.
    No credential value is accepted by this model.
    """
    index: int = 0
    pending: bool = False
    halted: bool = False
    events: tuple[bytes, ...] = ()

    def intent(self):
        iam.require(not self.halted and not self.pending and self.index < len(_steps()),
                    'stopped, pending, or completed provisioning')
        event = dict(kind='intent', sequence=self.index, plan_sha256=plan_sha256(),
                     **_steps()[self.index])
        return replace(self, pending=True, events=(*self.events, iam.canonical(event)))

    def outcome(self, status, *, secret_durably_saved=False):
        iam.require(self.pending and not self.halted, 'no outstanding action')
        iam.require(status in ('CONFIRMED', 'FAILED', 'UNKNOWN'), 'invalid outcome')
        is_key = _steps()[self.index]['action'] == 'CreateAccessKey'
        iam.require(type(secret_durably_saved) is bool, 'invalid secret receipt')
        confirmed = status == 'CONFIRMED' and (not is_key or secret_durably_saved)
        event = dict(kind='outcome', sequence=self.index,
                     status='CONFIRMED' if confirmed else 'STOPPED',
                     reconciliation_required=not confirmed)
        return replace(self, index=self.index + int(confirmed), pending=False,
                       halted=not confirmed, events=(*self.events, iam.canonical(event)))

    def emergency_lockout(self):
        # A pure STOP latch. Does not claim to revoke remote credentials.
        return replace(self, halted=True, events=(*self.events, iam.canonical(
            dict(kind='emergency-lockout', remote_revocation_proven=False))))

    def status(self):
        return dict(mode='OFFLINE_REHEARSAL', completed_actions=self.index,
                    pending=self.pending, halted=self.halted,
                    credentials='MASKED', live_enabled=False,
                    actual_enforcement_proven=False)


def _access_denied(exc):
    """Only an explicit provider AccessDenied counts, never a timeout/404/403 alone."""
    response = getattr(exc, 'response', None)
    return (type(response) is dict and type(response.get('Error')) is dict
            and response['Error'].get('Code') == 'AccessDenied'
            and type(response.get('ResponseMetadata')) is dict
            and response['ResponseMetadata'].get('HTTPStatusCode') == 403)


def _quarantine_checks(*, writer_sts, publisher_sts, writer_s3, publisher_s3):
    """One attempt per operation; exact fixed buckets only, no admin privileges.

    Internal algorithm for offline fake-client regression tests. ROOT_ACCOUNT is
    unprovisioned and the public live gate always refuses. A future root adapter
    must independently authenticate clients/endpoint, approved plan, fresh owned
    buckets, journal, expiry, source pins and propagation timing BEFORE any call.
    Tests of this algorithm never become live enforcement or deployment evidence.
    SDK errors and credentials are never included in returned data or stdout.
    """
    observations = []
    try:
        iam.require(ROOT_ACCOUNT is not None, 'root account unprovisioned')
        bindings = iam.Bindings(ROOT_ACCOUNT, WRITER, PUBLISHER)
        iam.require(writer_s3 is not publisher_s3 and writer_sts is not publisher_sts,
                    'independent authenticated clients required')
        for role, sts in (('writer', writer_sts), ('publisher', publisher_sts)):
            identity = sts.get_caller_identity()
            iam.require(type(identity) is dict and identity.get('Account') == ROOT_ACCOUNT
                        and identity.get('Arn') == bindings.arn(role)
                        and type(identity.get('UserId')) is str and identity['UserId'],
                        'STS identity mismatch')
            observations.append(dict(check='identity', role=role, result='MATCH'))

        def versioning():
            for client in (writer_s3, publisher_s3):
                response = client.get_bucket_versioning(Bucket=TEST_BUCKET,
                                                       ExpectedBucketOwner=ROOT_ACCOUNT)
                iam.require(response.get('Status') == 'Enabled', 'versioning not enabled')

        def positive(client, key):
            params = dict(Bucket=TEST_BUCKET, ExpectedBucketOwner=ROOT_ACCOUNT, Key=PREFIX + key)
            response = client.put_object(**params, Body=PAYLOAD, IfNoneMatch='*')
            version = response.get('VersionId')
            iam.require(type(version) is str and version and version != 'null', 'missing version receipt')
            result = client.get_object(**params, VersionId=version)
            body = result['Body']
            try:
                iam.require(body.read(1025) == PAYLOAD and result.get('VersionId') == version,
                            'readback mismatch or oversized object')
            finally:
                body.close()
            observations.append(dict(check='put-get-version', key=key, result='MATCH'))
            return version

        def denied(client, method, **params):
            try:
                response = getattr(client, method)(**params)
            except Exception as exc:
                iam.require(_access_denied(exc), 'expected explicit AccessDenied')
                observations.append(dict(check=method, key=params['Key'], result='ACCESS_DENIED'))
                return
            if method == 'get_object' and type(response) is dict and 'Body' in response:
                response['Body'].close()
            raise Refusal('negative request unexpectedly succeeded')

        versioning()
        positive(writer_s3, DATA)
        marker_version = positive(publisher_s3, MARKER)
        for role, client, source in (('writer', writer_s3, DATA),
                                      ('publisher', publisher_s3, MARKER)):
            for key in MARKERS:
                params = dict(Bucket=TEST_BUCKET, ExpectedBucketOwner=ROOT_ACCOUNT, Key=PREFIX + key)
                if role == 'writer' or key != MARKER:
                    denied(client, 'put_object', **params, Body=PAYLOAD)
                    denied(client, 'copy_object', **params,
                           CopySource=dict(Bucket=TEST_BUCKET, Key=PREFIX + source))
                    denied(client, 'create_multipart_upload', **params)
                denied(client, 'delete_object', **params)
                # Real version ID of a readable, existing object avoids a 404
                # masquerading as authorization evidence for version deletion.
                if key == MARKER:
                    denied(client, 'delete_object', **params, VersionId=marker_version)
            denied(client, 'put_object', Bucket=CONTROL_BUCKET, ExpectedBucketOwner=ROOT_ACCOUNT,
                   Key=PREFIX + source, Body=PAYLOAD)
        # Publisher must also be unable to operate on ordinary data.
        for method, extra in (('put_object', dict(Body=PAYLOAD)), ('get_object', {}),
                              ('delete_object', {}), ('create_multipart_upload', {})):
            denied(publisher_s3, method, Bucket=TEST_BUCKET, ExpectedBucketOwner=ROOT_ACCOUNT,
                   Key=PREFIX + DATA, **extra)
        versioning()
        return dict(status='OFFLINE_CHECK_REHEARSAL_PASS', observations=observations,
                    actual_enforcement_proven=False, deployment_authorized=False)
    except Exception:
        # Do not echo SDK error text, request/response dictionaries or traceback.
        return dict(status='REFUSED', observations=observations, reason='quarantine check refused',
                    actual_enforcement_proven=False, deployment_authorized=False)


def real_acceptance():
    """Permanent conservative gate; no root/user/env switch can authorize calls.

    Deliberately unavailable even to root. Separate supported admin authorization
    and review of a pinned root host adapter are needed; no bypass is shipped.
    """
    raise Refusal('live root adapter and external approval anchors are not provisioned')


def status():
    return dict(status='OFFLINE_ONLY', live_enabled=False, credentials='NOT_ACCESSED',
                plan_sha256=plan_sha256(), root_adapter_implemented=False,
                actual_enforcement_proven=False, deployment_authorized=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=('status', 'plan', 'temporary-test-bucket',
                                                  'provision', 'accept', 'cleanup', 'lockout'),
                        default='status')
    args = parser.parse_args(argv)
    if args.mode == 'plan':
        print(json.dumps(dict(plan=plan(), plan_sha256=plan_sha256()), sort_keys=True))
        return 0
    if args.mode == 'status':
        print(json.dumps(status(), sort_keys=True))
        return 0
    # Includes cleanup/lockout: never misrepresent a local latch as remote revoke.
    try:
        real_acceptance()
    except Refusal:
        print(json.dumps(dict(status(), requested_mode=args.mode, result='REFUSED'), sort_keys=True))
        return 2
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
