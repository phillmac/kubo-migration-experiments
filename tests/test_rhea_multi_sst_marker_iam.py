"""Offline only: synthetic DI responses/signatures, no credentials or test keys.

Signature checking is mocked explicitly for pure transition tests. No private or
public signing keys are generated/shipped. Real verification fails unprovisioned.
These tests do not demonstrate Wasabi propagation or actual enforcement.
"""
import ast
from dataclasses import FrozenInstanceError, replace
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_marker_iam as m

KEY = 'marker.manifest.000017.MANIFEST-000123'
FORMAT = 'marker.format-version.000012.013'


def policies(keys=(KEY,), **kwargs):
    return m.build_policies(m.Bindings('123456789012', 'offline-writer', 'offline-publisher'), keys, **kwargs)


class FakeSTS:
    def __init__(self, p, role):
        self.identity = dict(Account=p.bindings.account, Arn=p.bindings.arn(role), UserId='offline-' + role)
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return dict(self.identity)


class FakeS3:
    def __init__(self):
        self.calls = []
        self.hook = lambda result: result

    def get_bucket_versioning(self, **request):
        self.calls.append(request)
        result = dict(Status='Enabled', ResponseMetadata=dict(RequestId=str(len(self.calls))))
        return self.hook(result)


class FakeIAM:
    """LOCAL SIMULATION ONLY; no remote service and no actual enforcement."""
    def __init__(self):
        self.calls = []
        self.hook = lambda result: result

    def validate_policy(self, **request):
        self.calls.append(request)
        document = json.loads(request['PolicyDocument'])
        rows = [dict(case_id=c['case_id'], request_sha256=c['request_sha256'],
                     decision=m.simulate(document, c['action'], c['resource'], c['context'], inherited_allow=True))
                for c in request['Cases']]
        result = dict(Status='COMPLETE', Semantics='SUPPLIED_IDENTITY_POLICY_DECISIONS',
                      Propagation='CONFIRMED', PolicySha256=request['PolicySha256'],
                      PrincipalArn=request['PrincipalArn'], Decisions=rows)
        return self.hook(result)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = policies()

    def decide(self, role, action, resource, **context):
        ctx = {'aws:PrincipalArn': self.p.bindings.arn(role), **context}
        return m.simulate(self.p.document(role), action, resource, ctx, inherited_allow=True)

    def test_canonical_and_deterministic(self):
        self.assertEqual(self.p, policies())
        self.assertEqual(policies((KEY, FORMAT)), policies((FORMAT, KEY)))
        for role in ('writer', 'publisher'):
            raw = getattr(self.p, role + '_raw')
            self.assertEqual(raw, m.canonical(json.loads(raw)))
            self.assertNotIn('Principal', self.p.document(role))
            for row in self.p.document(role)['Statement']:
                self.assertNotIn('Principal', row)

    def test_immutable_bytes_and_detached_document(self):
        with self.assertRaises(FrozenInstanceError):
            self.p.writer_raw = b'changed'
        copy = self.p.document('writer')
        copy['Statement'].clear()
        m.validate_bundle(self.p)
        self.assertGreater(len(self.p.document('writer')['Statement']), 0)

    def test_exact_resource_scope_and_no_bucket_argument(self):
        for role in ('writer', 'publisher'):
            for row in self.p.document(role)['Statement']:
                if row['Effect'] == 'Allow':
                    self.assertTrue(all(r == m.BUCKET_ARN or r.startswith(m.OBJECT_ARN)
                                        for r in row['Resource']))
        with self.assertRaises(TypeError):
            m.build_policies(self.p.bindings, (KEY,), bucket='production')

    def test_wrong_accounts_rejected(self):
        for account in ('*', '123', '12345678901?', '１２３４５６７８９０１２', 123456789012, '123456789012\n'):
            with self.subTest(account=account), self.assertRaises(m.Refusal):
                m.Bindings(account, 'writer', 'publisher')

    def test_principal_injection_rejected(self):
        for name in ('writer*', 'writer?', '../writer', 'path/writer', 'writer\n', '${aws:username}',
                     'arn:aws:iam::123456789012:user/x', '', 'x' * 65):
            with self.subTest(name=name), self.assertRaises(m.Refusal):
                m.Bindings('123456789012', name, 'publisher')
        with self.assertRaises(m.Refusal):
            m.Bindings('123456789012', 'same', 'same')

    def test_marker_key_injection_rejected(self):
        for key in ('*', KEY + '*', KEY + '/extra', '../' + KEY, 'rhea/pebbleds/' + KEY,
                    'marker.manifest', 'marker.format-version', 'CURRENT/child', '000123.sst',
                    '${aws:username}', KEY + '\n', FORMAT + '?'):
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                policies((key,))
        for keys in ([], [KEY], (), (KEY, KEY), (123,)):
            with self.subTest(keys=keys), self.assertRaises(m.Refusal):
                policies(keys)

    def test_writer_marker_deny_overrides_inherited_allow(self):
        for name in ('marker.manifest', KEY, 'marker.manifest.unexpected/path',
                     'marker.format-version', FORMAT, 'marker.format-version.extra/path', 'CURRENT'):
            for operation, action in m.DESTINATION_ACTIONS.items():
                with self.subTest(name=name, operation=operation):
                    self.assertEqual(self.decide('writer', action, m.OBJECT_ARN + name), 'DENY')

    def test_copy_and_multipart_destination_are_putobject(self):
        for op in ('CopyObject', 'CreateMultipartUpload', 'UploadPart', 'UploadPartCopy', 'CompleteMultipartUpload'):
            self.assertEqual(m.DESTINATION_ACTIONS[op], 's3:PutObject')
            cases = [c for c in m.acceptance_cases(self.p) if c.operation == op]
            self.assertTrue(cases)
            self.assertTrue(all(c.action == 's3:PutObject' for c in cases))

    def test_current_never_allowed_for_n2_publisher(self):
        self.assertEqual(self.decide('publisher', 's3:PutObject', m.OBJECT_ARN + 'CURRENT'), 'DENY')
        self.assertEqual(self.decide('publisher', 's3:GetObjectVersion', m.OBJECT_ARN + 'CURRENT'), 'ALLOW')
        with self.assertRaises(m.Refusal):
            policies(('CURRENT',))
        changed = policies(('CURRENT',), current_change_sha256=m.sha(b'offline separate artifact'))
        self.assertEqual(changed.binding['current_change_sha256'], m.sha(b'offline separate artifact'))
        with self.assertRaises(m.Refusal):
            policies(current_change_sha256=m.sha(b'extraneous'))

    def test_publisher_exact_marker_set_only(self):
        self.assertEqual(self.decide('publisher', 's3:PutObject', m.OBJECT_ARN + KEY), 'ALLOW')
        for name in (FORMAT, KEY + '0', 'marker.manifest.000018.MANIFEST-000124', '000123.sst', 'MANIFEST-000123'):
            self.assertEqual(self.decide('publisher', 's3:PutObject', m.OBJECT_ARN + name), 'DENY')

    def test_publisher_cannot_delete_markers_data_or_versions(self):
        for name in (KEY, FORMAT, 'CURRENT', '000123.sst'):
            for action in ('s3:DeleteObject', 's3:DeleteObjectVersion', 's3:AbortMultipartUpload'):
                self.assertEqual(self.decide('publisher', action, m.OBJECT_ARN + name), 'DENY')

    def test_necessary_writer_data_ops(self):
        for action in ('s3:GetObject', 's3:GetObjectVersion', 's3:PutObject', 's3:DeleteObject',
                       's3:AbortMultipartUpload', 's3:ListMultipartUploadParts'):
            self.assertEqual(self.decide('writer', action, m.OBJECT_ARN + '000123.sst'), 'ALLOW')
        self.assertEqual(self.decide('writer', 's3:DeleteObjectVersion', m.OBJECT_ARN + '000123.sst'), 'DENY')

    def test_lateral_buckets_and_project_prefixes_explicitly_denied(self):
        for role in ('writer', 'publisher'):
            for resource in ('arn:aws:s3:::production/x', m.BUCKET_ARN + '/rhea/other/x',
                             m.BUCKET_ARN + '/rhea/pebbleds-evil/x', m.BUCKET_ARN + '/x'):
                for action in ('s3:GetObject', 's3:PutObject', 's3:DeleteObject'):
                    self.assertEqual(self.decide(role, action, resource), 'DENY')

    def test_iam_bucket_policy_and_versioning_manipulation_denied(self):
        for role in ('writer', 'publisher'):
            for action in ('iam:*', 'iam:PutUserPolicy', 'iam:CreateAccessKey', 'sts:AssumeRole',
                           's3:PutBucketPolicy', 's3:PutBucketVersioning', 's3:PutObjectAcl',
                           's3:PutLifecycleConfiguration', 's3:DeleteBucket'):
                self.assertEqual(self.decide(role, action, m.BUCKET_ARN), 'DENY')

    def test_listing_requires_exact_prefix_and_scopes_publisher(self):
        for role in ('writer', 'publisher'):
            for action in ('s3:ListBucket', 's3:ListBucketVersions'):
                for prefix in (None, '', 'rhea/', 'other/', m.PREFIX[:-1]):
                    ctx = {} if prefix is None else {'s3:prefix': prefix}
                    self.assertEqual(self.decide(role, action, m.BUCKET_ARN, **ctx), 'DENY')
        self.assertEqual(self.decide('writer', 's3:ListBucketVersions', m.BUCKET_ARN,
                                     **{'s3:prefix': m.PREFIX}), 'ALLOW')
        self.assertEqual(self.decide('publisher', 's3:ListBucketVersions', m.BUCKET_ARN,
                                     **{'s3:prefix': m.PREFIX}), 'DENY')
        self.assertEqual(self.decide('publisher', 's3:ListBucketVersions', m.BUCKET_ARN,
                                     **{'s3:prefix': m.PREFIX + 'marker.manifest.'}), 'ALLOW')

    def test_wrong_and_missing_principal_denied_even_with_inherited_allow(self):
        for role in ('writer', 'publisher'):
            for context in ({}, {'aws:PrincipalArn': 'arn:aws:iam::999999999999:user/alien'},
                            {'aws:PrincipalArn': self.p.bindings.arn('publisher' if role == 'writer' else 'writer')}):
                self.assertEqual(m.simulate(self.p.document(role), 's3:GetObject', m.OBJECT_ARN + KEY,
                                             context, inherited_allow=True), 'DENY')

    def test_all_cases_locally_agree_under_inherited_allow(self):
        for c in m.acceptance_cases(self.p):
            with self.subTest(case=c.case_id):
                self.assertEqual(m.simulate(self.p.document(c.role), c.action, c.resource,
                                             dict(c.context), inherited_allow=True), c.expected)

    def test_mutated_policy_bytes_or_added_allow_refused(self):
        document = self.p.document('writer')
        document['Statement'].append(dict(Effect='Allow', Action='*', Resource='*'))
        bad = replace(self.p, writer_raw=m.canonical(document))
        self.assertNotEqual(bad.sha256, self.p.sha256)
        with self.assertRaisesRegex(m.Refusal, 'policy bytes'):
            m.validate_bundle(bad)


class ReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.p = policies()
        self.writer = FakeSTS(self.p, 'writer')
        self.publisher = FakeSTS(self.p, 'publisher')
        self.iam, self.s3 = FakeIAM(), FakeS3()

    def run_validation(self):
        return m.validate_read_only(self.p, writer_sts=self.writer, publisher_sts=self.publisher,
                                    iam=self.iam, s3=self.s3)

    def test_success_is_only_simulated_evidence(self):
        result = self.run_validation()
        self.assertEqual(result.status, 'POLICY_EVALUATOR_SIMULATED')
        self.assertEqual(result.decisions, len(m.acceptance_cases(self.p)))
        self.assertFalse(result.actual_enforcement_proven)
        self.assertFalse(result.deployment_authorized)
        self.assertEqual(len(self.iam.calls), 2)
        self.assertEqual(self.writer.calls, 1)
        self.assertEqual(self.publisher.calls, 1)

    def test_exact_bucket_owner_and_no_mutating_methods(self):
        self.run_validation()
        self.assertEqual(self.s3.calls, [dict(Bucket=m.BUCKET, ExpectedBucketOwner='123456789012')] * 2)
        for request in self.iam.calls:
            self.assertEqual(request['PolicySha256'], m.sha(request['PolicyDocument'].encode()))
            self.assertIn(request['PrincipalArn'], (self.p.bindings.arn('writer'), self.p.bindings.arn('publisher')))

    def test_wrong_sts_account_and_username_fail_before_evaluator(self):
        for field, value in (('Account', '999999999999'), ('Arn', self.p.bindings.arn('publisher')), ('UserId', '')):
            with self.subTest(field=field):
                original = self.writer.identity.copy()
                self.writer.identity[field] = value
                self.assertEqual(self.run_validation().status, 'REFUSED')
                self.assertEqual(self.iam.calls, [])
                self.writer.identity = original

    def test_iam_unsupported_denied_and_timeout_no_retry(self):
        for error in (NotImplementedError(), PermissionError(), TimeoutError(), ConnectionError()):
            with self.subTest(error=type(error).__name__):
                self.iam.calls.clear()
                def fail(result):
                    raise error
                self.iam.hook = fail
                result = self.run_validation()
                self.assertEqual(result.status, 'REFUSED')
                self.assertEqual(len(self.iam.calls), 1)
                self.assertFalse(result.actual_enforcement_proven)

    def test_syntax_only_validate_policy_success_is_not_acceptance(self):
        for response in ({'IsValid': True}, {'Status': 'COMPLETE'}, {'success': True}, True, None):
            with self.subTest(response=response):
                self.iam.hook = lambda _, r=response: r
                self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_unknown_or_omitted_status_and_propagation_refused(self):
        for field in ('Status', 'Semantics', 'Propagation', 'PolicySha256', 'PrincipalArn'):
            for value in (None, 'UNKNOWN', True, ''):
                with self.subTest(field=field, value=value):
                    self.iam.hook = lambda r, f=field, v=value: {**r, f: v}
                    self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_missing_duplicate_and_unknown_decisions_refused(self):
        hooks = [lambda r: {**r, 'Decisions': r['Decisions'][:-1]},
                 lambda r: {**r, 'Decisions': [r['Decisions'][0]] * len(r['Decisions'])},
                 lambda r: {**r, 'Decisions': [{**c, 'decision': 'UNKNOWN'} for c in r['Decisions']]},
                 lambda r: {**r, 'Decisions': [{**c, 'request_sha256': '0' * 64} for c in r['Decisions']]}]
        for hook in hooks:
            self.iam.hook = hook
            self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_marker_preopen_unexpectedly_allowed(self):
        def lie(r):
            r['Decisions'][0]['decision'] = 'ALLOW'
            return r
        self.iam.hook = lie
        self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_unexpected_other_bucket_allowed(self):
        def lie(r):
            cases = self.iam.calls[-1]['Cases']
            case_id = next(c['case_id'] for c in cases if 'unrelated-bucket' in c['resource'])
            for row in r['Decisions']:
                if row['case_id'] == case_id:
                    row['decision'] = 'ALLOW'
            return r
        self.iam.hook = lie
        self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_writer_data_denial_rejected(self):
        def lie(r):
            case_id = next(c['case_id'] for c in self.iam.calls[-1]['Cases']
                           if c['resource'] == m.OBJECT_ARN + '000123.sst' and c['action'] == 's3:PutObject')
            for row in r['Decisions']:
                if row['case_id'] == case_id:
                    row['decision'] = 'DENY'
            return r
        self.iam.hook = lie
        self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_versioning_suspended_unknown_or_changes_refused(self):
        for status in ('Suspended', 'UNKNOWN', None, True):
            self.s3.hook = lambda r, s=status: {**r, 'Status': s}
            self.assertEqual(self.run_validation().status, 'REFUSED')
        self.s3.calls.clear()
        self.s3.hook = lambda r: {**r, 'Status': 'Enabled' if len(self.s3.calls) == 1 else 'Suspended'}
        self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_exception_bodies_do_not_leak_credentials(self):
        def fail(_):
            raise RuntimeError('Authorization: SECRET CREDENTIAL MATERIAL')
        self.iam.hook = fail
        result = self.run_validation()
        self.assertEqual(result.reason, 'RuntimeError')
        self.assertNotIn('SECRET', repr(result))

    def test_mutable_hash_refused_before_any_requests(self):
        self.p = replace(self.p, publisher_raw=self.p.publisher_raw + b' ')
        self.assertEqual(self.run_validation().status, 'REFUSED')
        self.assertEqual(self.writer.calls, 0)
        self.assertEqual(self.iam.calls, [])


def signed(value):
    return m.SignedRecord(m.canonical(value), b'S' * 64)


class WasabiBridgeTests(unittest.TestCase):
    def setUp(self):
        self.p = policies()
        self.calls = []
        self.hook = lambda result: result
        owner = self

        class FakeEndpoint:
            # A synthetic decoder/transport, not a service enforcement proof.
            def evaluate_read_only(self, query, *, expected_context):
                owner.calls.append((query, expected_context))
                decision = m.simulate(json.loads(query['PolicyDocument']), query['UseAction'],
                                      query['UseResource'], expected_context, inherited_allow=True)
                return owner.hook(dict(Decision=decision, RequestSha256=m.digest(query),
                            PrincipalArn=expected_context['aws:PrincipalArn'], EvaluatedContext=expected_context,
                            Propagation='CONFIRMED', Source='WASABI_VALIDATE_POLICY'))

        self.bridge = m.WasabiValidatePolicyDI(FakeEndpoint(), FakeEndpoint(), self.p.bindings)

    def run_validation(self):
        return m.validate_read_only(self.p, writer_sts=FakeSTS(self.p, 'writer'),
                                   publisher_sts=FakeSTS(self.p, 'publisher'), iam=self.bridge, s3=FakeS3())

    def test_exact_documented_wasabi_query_and_signing_principal(self):
        self.assertEqual(self.run_validation().status, 'POLICY_EVALUATOR_SIMULATED')
        self.assertEqual(len(self.calls), len(m.acceptance_cases(self.p)))
        for query, context in self.calls:
            self.assertEqual(set(query), {'Action', 'Version', 'PolicyDocument', 'IsPrincipal',
                                         'UseAction', 'UseResource', 'UseService'})
            self.assertEqual(query['Action'], 'ValidatePolicy')
            self.assertEqual(query['Version'], '2010-05-08')
            self.assertEqual(query['IsPrincipal'], 'true')
            self.assertEqual(query['UseService'], query['UseAction'].split(':')[0])
            self.assertNotIn('s3:prefix', query)
            self.assertIn(context['aws:PrincipalArn'], (self.p.bindings.arn('writer'), self.p.bindings.arn('publisher')))

    def test_no_return_status_unknown_and_syntax_success_fail_closed(self):
        for response in ({}, {'IsValid': True}, None, {'Decision': 'UNKNOWN'}):
            self.hook = lambda _, r=response: r
            self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_actual_context_and_independent_propagation_required(self):
        for field, value in (('EvaluatedContext', {}), ('Propagation', 'UNKNOWN'), ('Source', 'LOCAL_SIMULATOR'),
                             ('PrincipalArn', self.p.bindings.arn('publisher')), ('RequestSha256', '0' * 64)):
            with self.subTest(field=field):
                self.hook = lambda r, f=field, v=value: {**r, f: v}
                self.assertEqual(self.run_validation().status, 'REFUSED')

    def test_unsupported_condition_context_does_not_fallback_to_local_simulation(self):
        def unsupported(result):
            if 's3:prefix' in result['EvaluatedContext']:
                raise NotImplementedError('no documented way to inject listing prefix')
            return result
        self.hook = unsupported
        self.assertEqual(self.run_validation().status, 'REFUSED')


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        # NO keys; explicit synthetic verification stub for the offline model.
        self.verifier = patch.object(m.admission, 'verify_detached', return_value=None)
        self.mock_verify = self.verifier.start()
        self.addCleanup(self.verifier.stop)
        self.p = policies()
        self.trust = m.OfflineTrust(b'offline authorization placeholder', m.sha(b'offline authorization placeholder'),
                                   b'offline independent witness placeholder', m.sha(b'offline independent witness placeholder'))
        self.auth = dict(domain=m.DOMAIN, kind='external-authorization', policy=self.p.binding,
                         epoch=m.sha(b'one epoch'), batch_sha256=m.sha(b'immutable N2 batch'),
                         issued=100, expires=800, generation=13, cap=9, pending=None,
                         current_sha256=m.sha(b'MANIFEST-000000\n'), maximum_units=2)
        self.pre_details = dict(writer_opened=False, writer_marker_decision='DENY', publisher_released=False,
                                propagation='CONFIRMED', enforcement='ACTUAL_ENFORCEMENT_PROVEN',
                                cases_sha256=m.digest([vars(c) for c in m.acceptance_cases(self.p)]),
                                versioning='Enabled', bucket=m.BUCKET, prefix=m.PREFIX)
        self.puts = ((KEY, m.sha(b''), 0, 'IfNoneMatch', '*'),)
        self.publication = m.canonical({'puts': [dict(Bucket=m.BUCKET, ExpectedBucketOwner=self.p.bindings.account,
                                      Key=m.PREFIX + KEY, SHA256=m.sha(b''), Size=0, IfNoneMatch='*')]})
        self.first_details = dict(workers=4, complete=True, version_history=True, writer_closed=True,
                                  rc_markers_validated=True, dirty_markers=0, queued_markers=0, uploading_markers=0,
                                  writer_mount_stopped=True, cache_disposition_sha256=m.sha(b'preserved isolated cache'),
                                  s3_proof_sha256=m.sha(b'complete S3 proof'), rc_proof_sha256=m.sha(b'authenticated RC'),
                                  publication_sha256=m.sha(self.publication))

    def receipt(self, kind, details, *, model=None, observed=110, **changes):
        value = dict(domain=m.DOMAIN, kind=kind, epoch=self.auth['epoch'], policy_sha256=self.p.sha256,
                     batch_sha256=self.auth['batch_sha256'], proof_id=m.sha(kind.encode()), observed=observed,
                     previous_sha256=model.chain_sha256 if model else m.sha(m.canonical(self.auth)), details=details)
        value.update(changes)
        return signed(value)

    def start(self, **kwargs):
        args = dict(policies=self.p, trust=self.trust, authorization=signed(self.auth),
                    preopen=self.receipt('preopen-denial', self.pre_details), now=110)
        args.update(kwargs)
        return m.ReleaseModel.start(**args)

    def proven(self):
        model = self.start()
        return model.first_proof(self.receipt('first-four-worker-proof', self.first_details,
                                            model=model, observed=120), now=120)

    def pending(self):
        return self.proven().release_intent(self.puts, now=130)

    def propagation(self, model, **changes):
        details = dict(status='CONFIRMED', enforcement='ACTUAL_ENFORCEMENT_PROVEN',
                       writer_marker_decision='DENY', publisher_exact_keys='ALLOW',
                       publisher_other_keys='DENY', intent_sha256=model.chain_sha256)
        details.update(changes)
        return self.receipt('publisher-propagation', details, model=model, observed=140)

    def test_complete_two_principal_one_shot_model(self):
        pending = self.pending()
        self.assertEqual(pending.phase, 'PENDING_RELEASE')
        ready = pending.propagation(self.propagation(pending), now=140)
        attempted = ready.release_once(now=150)
        receipt = self.receipt('release-result', dict(status='CONFIRMED',
                              version_receipts_sha256=m.sha(b'remote version receipts'),
                              publication_sha256=m.sha(self.publication)), model=attempted, observed=160)
        result = attempted.result(receipt, now=160)
        self.assertEqual(result.phase, 'RELEASE_RECORDED')
        self.assertIn(self.auth['epoch'], result.used_epochs)
        self.assertEqual(len(result.proof_ids), 4)
        self.assertTrue(self.mock_verify.called)
        domains = [call.kwargs['domain'] for call in self.mock_verify.call_args_list]
        self.assertEqual(set(domains), {m.admission.DEPLOYMENT_DOMAIN})

    def test_external_signature_required(self):
        self.mock_verify.side_effect = m.admission.Refusal('invalid')
        with self.assertRaisesRegex(m.Refusal, 'signature'):
            self.start()

    def test_signature_bytes_required_not_unsigned_boolean(self):
        with self.assertRaises(m.Refusal):
            self.start(authorization=m.SignedRecord(m.canonical(self.auth), b''))
        with self.assertRaises(m.Refusal):
            self.start(authorization=True)

    def test_independent_witness_pin_required(self):
        bad = replace(self.trust, witness_public=self.trust.authorization_public,
                      witness_sha256=self.trust.authorization_sha256)
        with self.assertRaisesRegex(m.Refusal, 'independent'):
            self.start(trust=bad)

    def test_reused_epoch_rejected(self):
        with self.assertRaisesRegex(m.Refusal, 'reused epoch'):
            self.start(used_epochs=(self.auth['epoch'],))

    def test_expired_future_or_unbounded_authorization_rejected(self):
        for change in ({'expires': 110}, {'issued': 111}, {'expires': 1001}, {'issued': True}):
            with self.subTest(change=change):
                original = self.auth.copy()
                self.auth.update(change)
                with self.assertRaises(m.Refusal):
                    self.start()
                self.auth = original

    def test_anchor_cap_pending_or_current_changes_rejected(self):
        for change in ({'generation': 14}, {'cap': 10}, {'pending': {}}, {'maximum_units': 1},
                       {'current_sha256': m.sha(b'MANIFEST-000123\n')}):
            with self.subTest(change=change):
                original = self.auth.copy()
                self.auth.update(change)
                with self.assertRaises(m.Refusal):
                    self.start()
                self.auth = original

    def test_separately_hashed_current_builder_still_cannot_admit_n2(self):
        self.p = policies(('CURRENT',), current_change_sha256=m.sha(b'independent change artifact'))
        self.auth['policy'] = self.p.binding
        with self.assertRaisesRegex(m.Refusal, 'N2/gen13'):
            self.start()

    def test_preopen_actual_denial_required_and_simulation_rejected(self):
        for change in ({'writer_marker_decision': 'ALLOW'}, {'writer_opened': True},
                       {'writer_opened': 0}, {'publisher_released': 0},
                       {'publisher_released': True}, {'propagation': 'UNKNOWN'},
                       {'enforcement': 'POLICY_EVALUATOR_SIMULATED'}, {'versioning': 'Suspended'},
                       {'bucket': 'production'}, {'prefix': 'rhea/'}, {'cases_sha256': '0' * 64}):
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                self.start(preopen=self.receipt('preopen-denial', {**self.pre_details, **change}))

    def test_simulation_report_cannot_be_an_enforcement_receipt(self):
        report = m.validate_read_only(self.p, writer_sts=FakeSTS(self.p, 'writer'),
                                     publisher_sts=FakeSTS(self.p, 'publisher'), iam=FakeIAM(), s3=FakeS3())
        with self.assertRaises(m.Refusal):
            self.start(preopen=report)

    def test_missing_first_proof_or_out_of_order_release_rejected(self):
        model = self.start()
        for call in (lambda: model.release_intent(self.puts, now=120), lambda: model.release_once(now=120),
                     lambda: model.propagation(self.propagation(model), now=140)):
            with self.assertRaises(m.Refusal):
                call()

    def test_first_proof_full_four_worker_and_rc_evidence_required(self):
        model = self.start()
        for change in ({'workers': 1}, {'workers': True}, {'complete': False}, {'version_history': False},
                       {'writer_closed': False}, {'rc_markers_validated': False}, {'writer_mount_stopped': False},
                       {'s3_proof_sha256': ''}, {'rc_proof_sha256': ''}, {'cache_disposition_sha256': ''}):
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                model.first_proof(self.receipt('first-four-worker-proof', {**self.first_details, **change},
                                               model=model, observed=120), now=120)

    def test_dirty_queued_or_uploading_marker_blocks_release(self):
        model = self.start()
        for field in ('dirty_markers', 'queued_markers', 'uploading_markers'):
            for value in (1, True, -1, '0', None):
                with self.subTest(field=field, value=value), self.assertRaises(m.Refusal):
                    model.first_proof(self.receipt('first-four-worker-proof',
                                      {**self.first_details, field: value}, model=model, observed=120), now=120)

    def test_wrong_proof_ids_epoch_batch_policy_or_chain_rejected(self):
        model = self.start()
        for change in ({'proof_id': model.proof_ids[0]}, {'proof_id': ''}, {'epoch': m.sha(b'other epoch')},
                       {'batch_sha256': m.sha(b'other batch')}, {'policy_sha256': m.sha(b'other policy')},
                       {'previous_sha256': m.sha(b'other chain')}):
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                model.first_proof(self.receipt('first-four-worker-proof', self.first_details, model=model,
                                               observed=120, **change), now=120)

    def test_receipt_time_order_and_expiry_rejected(self):
        model = self.start()
        for observed, now in ((109, 120), (110, 120), (121, 120), (801, 801), (True, 120)):
            with self.subTest(observed=observed), self.assertRaises(m.Refusal):
                model.first_proof(self.receipt('first-four-worker-proof', self.first_details, model=model,
                                               observed=observed), now=now)

    def test_mutated_policy_hash_or_bindings_rejected_after_signature(self):
        bad = policies((FORMAT,))
        with self.assertRaisesRegex(m.Refusal, 'policy'):
            self.start(policies=bad)
        model = self.start()
        model = replace(model, policies=bad)
        with self.assertRaisesRegex(m.Refusal, 'binding'):
            model.first_proof(self.receipt('first-four-worker-proof', self.first_details,
                                          model=model, observed=120), now=120)

    def test_release_conditional_params_and_exact_payload_hash_required(self):
        model = self.proven()
        for puts in (((KEY, m.sha(b''), 0, 'unconditional', ''),),
                     ((KEY, m.sha(b''), 0, 'IfMatch', '*'),),
                     ((KEY, m.sha(b'changed'), 0, 'IfNoneMatch', '*'),),
                     ((FORMAT, m.sha(b''), 0, 'IfNoneMatch', '*'),),
                     ((KEY, m.sha(b''), True, 'IfNoneMatch', '*'),), self.puts * 2, []):
            with self.subTest(puts=puts), self.assertRaises(m.Refusal):
                model.release_intent(puts, now=130)

    def test_ifmatch_supported_only_with_bound_exact_etag(self):
        puts = ((KEY, m.sha(b''), 0, 'IfMatch', '"' + 'a' * 32 + '"'),)
        self.publication = m.canonical({'puts': [dict(Bucket=m.BUCKET, ExpectedBucketOwner='123456789012',
                     Key=m.PREFIX + KEY, SHA256=m.sha(b''), Size=0, IfMatch='"' + 'a' * 32 + '"')]})
        self.first_details['publication_sha256'] = m.sha(self.publication)
        self.assertEqual(self.proven().release_intent(puts, now=130).phase, 'PENDING_RELEASE')

    def test_no_automatic_iam_or_rc_retry_on_unknown_transition(self):
        model = self.pending()
        for change in ({'status': 'UNKNOWN'}, {'status': None}, {'enforcement': 'POLICY_EVALUATOR_SIMULATED'},
                       {'writer_marker_decision': 'ALLOW'}, {'publisher_other_keys': 'ALLOW'}):
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                model.propagation(self.propagation(model, **change), now=140)
        with self.assertRaises(m.Refusal):
            model.release_once(now=150)

    def test_release_requires_separate_one_shot_and_propagation_proof(self):
        pending = self.pending()
        with self.assertRaises(m.Refusal):
            pending.release_once(now=150)
        ready = pending.propagation(self.propagation(pending), now=140)
        attempted = ready.release_once(now=150)
        for call in (lambda: attempted.release_once(now=151),
                     lambda: attempted.release_intent(self.puts, now=151),
                     lambda: ready.release_intent(self.puts, now=151)):
            with self.assertRaises(m.Refusal):
                call()

    def test_unknown_result_after_intent_cannot_record_success_or_retry(self):
        pending = self.pending()
        attempted = pending.propagation(self.propagation(pending), now=140).release_once(now=150)
        record = self.receipt('release-result', dict(status='UNKNOWN', version_receipts_sha256=m.sha(b'?'),
                              publication_sha256=m.sha(self.publication)), model=attempted, observed=160)
        with self.assertRaisesRegex(m.Refusal, 'no retry'):
            attempted.result(record, now=160)
        with self.assertRaises(m.Refusal):
            attempted.release_once(now=161)

    def test_publication_or_version_receipt_hash_missing_refused(self):
        pending = self.pending()
        attempted = pending.propagation(self.propagation(pending), now=140).release_once(now=150)
        for change in ({'version_receipts_sha256': ''}, {'publication_sha256': m.sha(b'wrong')}):
            details = dict(status='CONFIRMED', version_receipts_sha256=m.sha(b'versions'),
                           publication_sha256=m.sha(self.publication))
            details.update(change)
            with self.assertRaises(m.Refusal):
                attempted.result(self.receipt('release-result', details, model=attempted, observed=160), now=160)


class StaticTests(unittest.TestCase):
    def test_no_sdk_network_credential_or_mutating_entrypoint(self):
        tree = ast.parse((ROOT / 'scripts/rhea_multi_sst_marker_iam.py').read_bytes())
        imports = {node.name.split('.')[0] for n in ast.walk(tree)
                   if isinstance(n, ast.Import) for node in n.names}
        imports |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertFalse(imports & {'boto3', 'botocore', 'socket', 'requests', 'urllib', 'subprocess', 'os'})
        sdk_like_calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Attribute) and not n.func.attr.startswith('_')}
        self.assertFalse(sdk_like_calls & {'client', 'Session', 'put_object', 'delete_object', 'put_user_policy',
                                          'attach_user_policy', 'create_access_key', 'sign'})
        self.assertIsNone(m.PRODUCTION_TRUST_SHA256)

    def test_root_and_environment_cannot_supply_dynamic_signer(self):
        with patch.dict('os.environ', {'RHEA_SIGNER': 'caller-key', 'AWS_ACCESS_KEY_ID': 'bogus'}):
            self.assertEqual(m.status(), dict(status='OFFLINE_ONLY', live_mutation=False,
                             deployment_authorized=False, actual_enforcement_proven=False,
                             production_trust_provisioned=False))
            with patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(m.main(), 2)

    def test_real_signature_verifier_rejects_placeholder_without_key_creation(self):
        trust = m.OfflineTrust(b'invalid auth', m.sha(b'invalid auth'), b'invalid witness', m.sha(b'invalid witness'))
        with self.assertRaisesRegex(m.Refusal, 'signature'):
            trust.verify(signed({'domain': m.DOMAIN}))

    def test_duplicate_or_noncanonical_json_rejected(self):
        for raw in (b'{"a":1,"a":1}\n', b'{"a": NaN}\n', b'{ "a": 1 }', b'[]\n', b''):
            with self.subTest(raw=raw), self.assertRaises(m.Refusal):
                m.parse(raw)


if __name__ == '__main__':
    unittest.main()
