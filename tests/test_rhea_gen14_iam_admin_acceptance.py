"""Offline fakes only. No keys, credentials, SDK, network or live authorization.

Account pin patches below are explicit synthetic fixtures for a private check
algorithm. The public root gate stays disabled even under those patches.
"""
import ast
from contextlib import redirect_stdout
from dataclasses import FrozenInstanceError
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, sentinel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_gen14_iam_admin_acceptance as a
import rhea_multi_sst_marker_iam as iam

ACCOUNT = '123456789012'  # Synthetic identity only, never credentials.


class SDKError(Exception):
    def __init__(self, code='AccessDenied', status=403):
        super().__init__('sdk-body-must-not-be-echoed')
        self.response = dict(Error=dict(Code=code, SecretAccessKey=sentinel.private_material),
                             ResponseMetadata=dict(HTTPStatusCode=status))


class FakeSTS:
    def __init__(self, role):
        self.role = role
        self.identity = dict(Account=ACCOUNT, Arn=f'arn:aws:iam::{ACCOUNT}:user/' +
                             (a.WRITER if role == 'writer' else a.PUBLISHER), UserId='offline-' + role)
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return dict(self.identity)


class FakeS3:
    """Independent hand-written permissions, NOT a policy simulator/provider proof."""
    def __init__(self, role, objects, calls):
        self.role, self.objects, self.calls = role, objects, calls
        self.hook = lambda method, request, allowed: allowed
        self.error = lambda: SDKError()
        self.versioning = 'Enabled'
        self.response_hook = lambda response: response
        self.bodies = []

    def get_bucket_versioning(self, **request):
        self.calls.append((self.role, 'get_bucket_versioning', request))
        assert request == dict(Bucket=a.TEST_BUCKET, ExpectedBucketOwner=ACCOUNT)
        return dict(Status=self.versioning)

    def request(self, method, **request):
        self.calls.append((self.role, method, request))
        assert request['Bucket'] in (a.TEST_BUCKET, a.CONTROL_BUCKET)
        assert request['ExpectedBucketOwner'] == ACCOUNT
        key = request['Key']
        protected = key == a.PREFIX + 'CURRENT' or any(
            key == a.PREFIX + base or key.startswith(a.PREFIX + base + '.')
            for base in ('marker.manifest', 'marker.format-version'))
        in_scope = request['Bucket'] == a.TEST_BUCKET and key.startswith(a.PREFIX)
        if self.role == 'writer':
            allowed = in_scope and (method == 'get_object' or not protected) and 'VersionId' not in request
            if method == 'get_object':
                allowed = in_scope
        else:
            allowed = in_scope and ((method == 'put_object' and key == a.PREFIX + a.MARKER)
                                    or (method == 'get_object' and protected))
        allowed = self.hook(method, request, allowed)
        if not allowed:
            raise self.error()
        if method == 'put_object':
            assert len(request['Body']) <= 1024
            if request.get('IfNoneMatch') == '*' and key in self.objects:
                raise SDKError('PreconditionFailed', 412)
            version = str(len(self.objects) + 1)
            self.objects[key] = (request['Body'], version)
            return self.response_hook(dict(VersionId=version))
        if method == 'get_object':
            payload, version = self.objects[key]
            body = io.BytesIO(payload)
            self.bodies.append(body)
            return self.response_hook(dict(Body=body, VersionId=version))
        # Unexpected successful negative mutations must stop checks immediately.
        return {}

    def put_object(self, **request):
        return self.request('put_object', **request)

    def get_object(self, **request):
        return self.request('get_object', **request)

    def copy_object(self, **request):
        return self.request('copy_object', **request)

    def create_multipart_upload(self, **request):
        return self.request('create_multipart_upload', **request)

    def delete_object(self, **request):
        return self.request('delete_object', **request)


class FakeIAM:
    """Order/failure fake; returns opaque receipts, never generated secret strings."""
    def __init__(self, fail_at=None, ambiguous=False):
        self.calls = []
        self.fail_at, self.ambiguous = fail_at, ambiguous

    def perform(self, event, intent_records):
        # Explicit model intent is recorded before the fake sees an action.
        assert json.loads(intent_records[-1]) == event
        self.calls.append(event)
        if len(self.calls) - 1 == self.fail_at:
            return 'UNKNOWN' if self.ambiguous else 'FAILED'
        return 'CONFIRMED'


def rehearse(fake, *, save_key_receipt=True):
    model = a.ProvisioningModel()
    for _ in a._steps():
        model = model.intent()
        event = json.loads(model.events[-1])
        outcome = fake.perform(event, model.events)
        model = model.outcome(outcome, secret_durably_saved=(
            event['action'] == 'CreateAccessKey' and save_key_receipt))
        if model.halted:
            break
    return model


class PlanTests(unittest.TestCase):
    def test_published_policy_and_plan_hashes_match_reviewed_bytes(self):
        p = iam.build_policies(iam.Bindings(ACCOUNT, 'offline-writer', 'offline-publisher'), (a.MARKER,))
        expected = ('8828092941ce0c46eefd9169d0b887a4e6cbb54b9a9e865464c5d4a1e3002dd0',
                    'c05b027e08f63378f89e639b35d1506077df1edd3b57e83371cae2ca218ebb3f',
                    '7fe43a7eb3ba6e9ff84640e992580987b4e0a81a51802b4c7733c61547505c7c',
                    'b828fad32852d15e813a1f6b300093924e4c743f7e9b111c0dc938d0c7d24d23',
                    '4cdfa9fe6077be6ec3d37fc82e0c0b3bdd104c2ed5ef24cc6a66bede4ceb8415',
                    'eccbf72cab597f0733265f11ce3d7cce12be5b7bc7d1d03acd825e7967225764')
        actual = (iam.sha(p.writer_raw), iam.sha(p.publisher_raw), p.sha256,
                  a._test_documents()['writer']['sha256'], a._test_documents()['publisher']['sha256'],
                  a.plan_sha256())
        self.assertEqual(actual, expected)
        document = (ROOT / 'docs/rhea-gen14-marker-iam-20261111.md').read_text()
        for value in expected:
            self.assertIn(value, document)

    def test_plan_is_deterministic_and_hashes_are_exact_canonical_bytes(self):
        p = a.plan()
        self.assertEqual(p, a.plan())
        self.assertEqual(a.plan_sha256(), iam.digest(p))
        for item in p['policies'].values():
            self.assertEqual(item['sha256'], iam.sha(iam.canonical(item['document'])))
        self.assertFalse(p['live_enabled'])
        self.assertFalse(p['root_adapter_implemented'])
        self.assertIsNone(p['account'])

    def test_fixed_unique_disposable_names_and_no_certified_resources(self):
        self.assertNotEqual(a.TEST_BUCKET, a.CONTROL_BUCKET)
        for bucket in (a.TEST_BUCKET, a.CONTROL_BUCKET):
            self.assertTrue(bucket.startswith('rhea-gen14-iam-'))
            self.assertLessEqual(len(bucket), 63)
            self.assertNotEqual(bucket, iam.BUCKET)
        self.assertNotEqual(a.WRITER, a.PUBLISHER)
        for user in (a.WRITER, a.PUBLISHER):
            self.assertTrue(iam.NAME.fullmatch(user))
        for policy in a._test_documents().values():
            self.assertNotIn(iam.BUCKET, json.dumps(policy))

    def test_no_unsupported_conditions_principal_or_global_allow(self):
        for item in a._test_documents().values():
            for row in item['document']['Statement']:
                self.assertNotIn('Principal', row)
                for terms in row.get('Condition', {}).values():
                    self.assertLessEqual(set(terms), {'s3:prefix'})
                if row['Effect'] == 'Allow':
                    self.assertTrue(all(r.startswith('arn:aws:s3:::' + a.TEST_BUCKET)
                                        for r in row['Resource']))
                    self.assertNotIn('*', row['Action'])

    def test_original_certified_scope_and_current_are_unchanged(self):
        p = iam.build_policies(iam.Bindings(ACCOUNT, 'offline-writer', 'offline-publisher'), (a.MARKER,))
        self.assertEqual(p.binding['bucket'], 'rhea-pebble-lab-20261101-39037c6f01')
        self.assertEqual(p.binding['prefix'], 'rhea/pebbleds/')
        for role in ('writer', 'publisher'):
            self.assertEqual(iam.simulate(p.document(role), 's3:PutObject', iam.OBJECT_ARN + 'CURRENT',
                                          {}, inherited_allow=True), 'DENY')

    def test_test_policy_explicit_denies_override_inherited_allow(self):
        documents = a._test_documents()
        for role in ('writer', 'publisher'):
            doc = documents[role]['document']
            for bucket in (iam.BUCKET, a.CONTROL_BUCKET, 'unrelated-offline-bucket'):
                for action in ('s3:PutObject', 's3:GetObject', 's3:DeleteObject'):
                    self.assertEqual(iam.simulate(doc, action,
                        'arn:aws:s3:::' + bucket + '/' + a.PREFIX + a.MARKER,
                        {}, inherited_allow=True), 'DENY')
            for key in (*a.MARKERS, a.DATA, '../x', 'marker.manifest.extra/path'):
                resource = 'arn:aws:s3:::' + a.TEST_BUCKET + '/' + a.PREFIX + key
                for action in ('s3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion'):
                    expected = 'DENY'
                    if action == 's3:PutObject' and ((role == 'publisher' and key == a.MARKER)
                            or (role == 'writer' and key in (a.DATA, '../x'))):
                        expected = 'ALLOW'
                    if action == 's3:DeleteObject' and role == 'writer' and key in (a.DATA, '../x'):
                        expected = 'ALLOW'
                    self.assertEqual(iam.simulate(doc, action, resource, {}, inherited_allow=True), expected)

    def test_no_sdk_network_signer_or_credential_discovery_code(self):
        tree = ast.parse((ROOT / 'scripts/rhea_gen14_iam_admin_acceptance.py').read_bytes())
        imports = {n.name.split('.')[0] for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for n in node.names}
        imports |= {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse(imports & {'boto3', 'botocore', 'socket', 'requests', 'urllib', 'subprocess', 'os'})
        calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)}
        self.assertFalse(calls & {'client', 'Session', 'get_credentials', 'create_user', 'create_access_key',
                                  'put_user_policy', 'sign', 'delete_bucket', 'delete_user'})

    def test_status_default_is_read_only_and_plan_cli_has_no_credentials(self):
        for argv in ([], ['status'], ['plan']):
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(a.main(argv), 0)
            record = json.loads(stream.getvalue())
            self.assertNotIn('SecretAccessKey', stream.getvalue())
            self.assertNotIn('AccessKeyId', stream.getvalue())
            self.assertIsInstance(record, dict)

    def test_every_live_and_cleanup_mode_refuses_even_with_runtime_environment(self):
        with patch.dict('os.environ', {'RHEA_ROOT_APPROVED': '1', 'AWS_PROFILE': 'not-read'}):
            for mode in ('temporary-test-bucket', 'provision', 'accept', 'cleanup', 'lockout'):
                with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as stream:
                    self.assertEqual(a.main([mode]), 2)
                    self.assertEqual(json.loads(stream.getvalue())['result'], 'REFUSED')
        with self.assertRaises(a.Refusal):
            a.real_acceptance()

    def test_no_arbitrary_account_bucket_endpoint_policy_or_key_arguments(self):
        for option in ('--account', '--bucket', '--s3-endpoint', '--policy', '--profile', '--private-key'):
            with redirect_stdout(io.StringIO()), patch('sys.stderr', new=io.StringIO()):
                with self.assertRaises(SystemExit):
                    a.main(['plan', option, 'untrusted'])
        with self.assertRaises(TypeError):
            a._test_documents(bucket=iam.BUCKET)


class ProvisioningTests(unittest.TestCase):
    def test_exact_user_then_policy_then_key_order_with_recorded_intents(self):
        fake = FakeIAM()
        model = rehearse(fake)
        self.assertEqual([c['action'] for c in fake.calls],
                         ['CreateUser'] * 2 + ['PutUserPolicy'] * 2 + ['CreateAccessKey'] * 2)
        self.assertEqual([c['user'] for c in fake.calls], [a.WRITER, a.PUBLISHER] * 3)
        self.assertEqual(len(model.events), 12)
        self.assertFalse(model.halted)
        self.assertEqual(model.index, 6)
        with self.assertRaises(a.Refusal):
            model.intent()
        self.assertFalse(model.status()['actual_enforcement_proven'])

    def test_failed_create_first_or_second_leaves_prior_principals_no_rollback(self):
        for index in (0, 1):
            fake = FakeIAM(fail_at=index)
            model = rehearse(fake)
            self.assertTrue(model.halted)
            self.assertEqual(len(fake.calls), index + 1)
            self.assertEqual(model.index, index)
            self.assertTrue(all(c['action'] == 'CreateUser' for c in fake.calls))
            with self.assertRaises(a.Refusal):
                model.intent()

    def test_failed_or_ambiguous_iam_call_at_every_stage_never_retries(self):
        for index in range(6):
            for ambiguous in (False, True):
                fake = FakeIAM(fail_at=index, ambiguous=ambiguous)
                model = rehearse(fake)
                self.assertTrue(model.halted)
                self.assertEqual(len(fake.calls), index + 1)
                with self.assertRaises(a.Refusal):
                    model.intent()
                with self.assertRaises(a.Refusal):
                    model.outcome('CONFIRMED')

    def test_key_not_recorded_saved_stops_before_second_key(self):
        fake = FakeIAM()
        model = rehearse(fake, save_key_receipt=False)
        self.assertTrue(model.halted)
        self.assertEqual(len(fake.calls), 5)
        self.assertTrue(json.loads(model.events[-1])['reconciliation_required'])

    def test_pending_intent_cannot_be_replayed_or_skipped(self):
        model = a.ProvisioningModel().intent()
        with self.assertRaises(a.Refusal):
            model.intent()
        with self.assertRaises(a.Refusal):
            a.ProvisioningModel().outcome('CONFIRMED')
        with self.assertRaises(a.Refusal):
            model.outcome('unexpected')
        with self.assertRaises(FrozenInstanceError):
            model.index = 4

    def test_emergency_lockout_at_each_phase_is_local_stop_not_revocation_claim(self):
        model = a.ProvisioningModel()
        for _ in range(6):
            for state in (model, model.intent()):
                locked = state.emergency_lockout()
                self.assertTrue(locked.halted)
                with self.assertRaises(a.Refusal):
                    locked.intent()
                self.assertFalse(json.loads(locked.events[-1])['remote_revocation_proven'])
            model = model.intent().outcome('CONFIRMED', secret_durably_saved=True)

    def test_model_and_status_never_accept_or_expose_credential_values(self):
        model = rehearse(FakeIAM())
        self.assertEqual(model.status()['credentials'], 'MASKED')
        serialized = json.dumps(model.status()) + b''.join(model.events).decode()
        self.assertNotIn('SecretAccessKey', serialized)
        self.assertNotIn('AccessKeyId', serialized)
        with self.assertRaises(TypeError):
            model.outcome('CONFIRMED', credentials=sentinel.private_material)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.objects, self.calls = {}, []
        self.writer = FakeS3('writer', self.objects, self.calls)
        self.publisher = FakeS3('publisher', self.objects, self.calls)
        self.writer_sts, self.publisher_sts = FakeSTS('writer'), FakeSTS('publisher')

    def check(self):
        # Explicit fixture for the private algorithm, not root live authorization.
        with patch.object(a, 'ROOT_ACCOUNT', ACCOUNT):
            return a._quarantine_checks(writer_sts=self.writer_sts, publisher_sts=self.publisher_sts,
                                        writer_s3=self.writer, publisher_s3=self.publisher)

    def test_positive_data_and_marker_put_get_and_negative_matrix(self):
        result = self.check()
        self.assertEqual(result['status'], 'OFFLINE_CHECK_REHEARSAL_PASS')
        self.assertFalse(result['actual_enforcement_proven'])
        self.assertFalse(result['deployment_authorized'])
        self.assertEqual(set(self.objects), {a.PREFIX + a.DATA, a.PREFIX + a.MARKER})
        for role in ('writer', 'publisher'):
            rows = [(method, params) for r, method, params in self.calls if r == role]
            for method in ('put_object', 'copy_object', 'create_multipart_upload', 'delete_object'):
                self.assertTrue(any(m == method and p['Key'] == a.PREFIX + 'CURRENT' for m, p in rows))
            self.assertTrue(any(m == 'put_object' and p['Bucket'] == a.CONTROL_BUCKET for m, p in rows))
            self.assertEqual(sum(m == 'get_bucket_versioning' for m, _ in rows), 2)
        self.assertTrue(all(body.closed for body in self.writer.bodies + self.publisher.bodies))

    def test_only_disposable_buckets_and_maximum_one_kilobyte_public_objects(self):
        self.check()
        for _, _, request in self.calls:
            self.assertIn(request['Bucket'], (a.TEST_BUCKET, a.CONTROL_BUCKET))
            self.assertNotEqual(request['Bucket'], iam.BUCKET)
            if 'Key' in request:
                self.assertTrue(request['Key'].startswith(a.PREFIX))
            if 'Body' in request:
                self.assertLessEqual(len(request['Body']), 1024)
                self.assertEqual(request['Body'], a.PAYLOAD)
            if 'CopySource' in request:
                self.assertEqual(request['CopySource']['Bucket'], a.TEST_BUCKET)

    def test_every_marker_negative_operation_unexpected_allow_fails_closed(self):
        for method in ('put_object', 'copy_object', 'create_multipart_upload', 'delete_object'):
            self.setUp()
            self.writer.hook = lambda m, p, allowed, target=method: (
                True if m == target and p.get('Key') == a.PREFIX + 'CURRENT' else allowed)
            self.assertEqual(self.check()['status'], 'REFUSED')

    def test_publisher_arbitrary_marker_and_data_success_fail_closed(self):
        for key in ('CURRENT', a.DATA, 'marker.format-version'):
            self.setUp()
            self.publisher.hook = lambda m, p, allowed, key=key: (
                True if m == 'put_object' and p.get('Key') == a.PREFIX + key else allowed)
            self.assertEqual(self.check()['status'], 'REFUSED')

    def test_wrong_bucket_unexpected_allow_refuses_and_never_targets_real_buckets(self):
        for role in ('writer', 'publisher'):
            self.setUp()
            client = self.writer if role == 'writer' else self.publisher
            client.hook = lambda m, p, allowed: True if p['Bucket'] == a.CONTROL_BUCKET else allowed
            self.assertEqual(self.check()['status'], 'REFUSED')

    def test_version_delete_denied_with_real_fake_version_receipt(self):
        self.check()
        deletes = [params for _, method, params in self.calls
                   if method == 'delete_object' and 'VersionId' in params]
        self.assertEqual(len(deletes), 2)
        self.assertTrue(all(p['VersionId'] == self.objects[a.PREFIX + a.MARKER][1] for p in deletes))

    def test_non_access_denied_never_counts_as_enforcement(self):
        for code, status in (('NoSuchKey', 404), ('NoSuchBucket', 404), ('InvalidAccessKeyId', 403),
                             ('SignatureDoesNotMatch', 403), ('SlowDown', 503), ('AccessDenied', 500)):
            self.setUp()
            self.writer.error = lambda code=code, status=status: SDKError(code, status)
            self.assertEqual(self.check()['status'], 'REFUSED')

    def test_timeout_no_retry_and_sdk_exception_sanitized(self):
        def timeout(*args):
            raise TimeoutError('sdk-body-must-not-be-echoed')
        self.writer.hook = timeout
        with redirect_stdout(io.StringIO()) as stream:
            result = self.check()
        self.assertEqual(result['status'], 'REFUSED')
        puts = [c for c in self.calls if c[1] == 'put_object']
        self.assertEqual(len(puts), 1)
        self.assertEqual(stream.getvalue(), '')
        self.assertNotIn('sdk-body', json.dumps(result))

    def test_sdk_credentials_in_error_dictionary_do_not_leak(self):
        self.writer.error = lambda: SDKError('InvalidAccessKeyId', 403)
        with redirect_stdout(io.StringIO()) as stream:
            result = self.check()
        serialized = json.dumps(result) + stream.getvalue()
        for forbidden in ('SecretAccessKey', 'AccessKeyId', 'sentinel', 'sdk-body'):
            self.assertNotIn(forbidden, serialized)

    def test_sts_mismatch_missing_user_id_or_wrong_account_stops_before_s3(self):
        for field, value in (('Arn', f'arn:aws:iam::{ACCOUNT}:root'), ('Account', '999999999999'),
                             ('UserId', ''), ('Arn', self.publisher_sts.identity['Arn'])):
            self.setUp()
            self.writer_sts.identity[field] = value
            self.assertEqual(self.check()['status'], 'REFUSED')
            self.assertEqual(self.calls, [])

    def test_shared_clients_refused_before_calls(self):
        self.publisher = self.writer
        self.assertEqual(self.check()['status'], 'REFUSED')
        self.assertEqual(self.calls, [])

    def test_missing_suspended_versioning_or_changed_versioning_refused(self):
        for status in (None, 'Suspended', 'unknown'):
            self.setUp()
            self.writer.versioning = status
            self.assertEqual(self.check()['status'], 'REFUSED')
            self.assertFalse(any(c[1] == 'put_object' for c in self.calls))
        self.setUp()
        original = self.publisher.get_bucket_versioning
        def changing(**kwargs):
            if self.objects:
                self.publisher.versioning = 'Suspended'
            return original(**kwargs)
        self.publisher.get_bucket_versioning = changing
        self.assertEqual(self.check()['status'], 'REFUSED')

    def test_missing_null_or_mismatched_version_receipt_refuses(self):
        for version in (None, '', 'null'):
            self.setUp()
            self.writer.response_hook = lambda r, version=version: {**r, 'VersionId': version}
            self.assertEqual(self.check()['status'], 'REFUSED')
        self.setUp()
        self.writer.response_hook = lambda r: {**r, 'VersionId': 'mismatched'} if 'Body' in r else r
        self.assertEqual(self.check()['status'], 'REFUSED')
        self.assertTrue(self.writer.bodies[0].closed)

    def test_existing_object_and_positive_failure_not_automatically_retried(self):
        self.objects[a.PREFIX + a.DATA] = (a.PAYLOAD, 'existing')
        self.assertEqual(self.check()['status'], 'REFUSED')
        self.assertEqual(sum(c[1] == 'put_object' for c in self.calls), 1)

    def test_readback_mismatch_or_oversize_stops_and_closes_body(self):
        for payload in (b'wrong public test payload', b'x' * 1025):
            self.setUp()
            def response_hook(response):
                if 'Body' in response:
                    response['Body'].close()
                    response['Body'] = io.BytesIO(payload)
                    self.writer.bodies.append(response['Body'])
                return response
            self.writer.response_hook = response_hook
            self.assertEqual(self.check()['status'], 'REFUSED')
            self.assertTrue(all(body.closed for body in self.writer.bodies))

    def test_unprovisioned_private_algorithm_and_public_gate_make_no_calls(self):
        result = a._quarantine_checks(writer_sts=self.writer_sts, publisher_sts=self.publisher_sts,
                                     writer_s3=self.writer, publisher_s3=self.publisher)
        self.assertEqual(result['status'], 'REFUSED')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.writer_sts.calls, 0)
        with patch.object(a, 'ROOT_ACCOUNT', ACCOUNT):
            with self.assertRaises(a.Refusal):
                a.real_acceptance()
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
