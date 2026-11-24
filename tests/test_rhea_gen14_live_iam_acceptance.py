"""Offline provider fakes for the bounded live S3 acceptance adapter."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_iam_admin_acceptance as plan
import rhea_gen14_live_iam_acceptance as a

ACCOUNT = '123456789012'
SECRET = 'OFFLINE-S3-SECRET-MUST-NOT-APPEAR'
BUCKETS = {plan.TEST_BUCKET, plan.CONTROL_BUCKET}
META = {'HTTPStatusCode': 200, 'RetryAttempts': 0}


class S3Error(Exception):
    def __init__(self, code='AccessDenied', status=403):
        super().__init__(SECRET)
        self.response = {'Error': {'Code': code, 'Message': SECRET},
                         'ResponseMetadata': {'HTTPStatusCode': status}}


class Store:
    def __init__(self):
        self.buckets = {}
        self.uploads = {}
        self.calls = []
        self.serial = 0
        self.denial = lambda: S3Error()
        self.denial_by_method = {}
        self.conditional_error = lambda: S3Error('PreconditionFailed', 412)
        self.denied_indices = []
        self.unexpected_success = None
        self.corrupt_positive = None
        self.bulk_override = None
        self.bulk_denial = None
        self.before_call = lambda role, method, params: None
        self.bodies = []

    def identifier(self, prefix):
        self.serial += 1
        return prefix + str(self.serial).zfill(12)

    def client(self, role):
        return S3(self, role)


class S3:
    """Independent explicit role matrix plus real version/body/upload bookkeeping."""
    def __init__(self, store, role):
        self.store, self.role = store, role

    def close(self):
        pass

    def __getattr__(self, method):
        return lambda **params: self.call(method, params)

    def allowed(self, method, params):
        if self.role in ('root', 'admin'):
            return True
        if params.get('Bucket') != plan.TEST_BUCKET:
            return False
        if method in ('get_bucket_location', 'get_bucket_versioning'):
            return True
        prefix = params.get('Prefix')
        if method in ('list_objects_v2', 'list_object_versions'):
            if not isinstance(prefix, str) or not prefix.startswith(plan.PREFIX):
                return False
            tail = prefix[len(plan.PREFIX):]
            return self.role == 'writer' or self.is_marker(tail)
        key = params.get('Key', '')
        if not key.startswith(plan.PREFIX):
            return False
        if method in ('copy_object', 'upload_part_copy') and isinstance(params.get('CopySource'), dict):
            source = params['CopySource']
            if not self.allowed('get_object', dict(Bucket=source['Bucket'], Key=source['Key'])):
                return False
        tail = key[len(plan.PREFIX):]
        marker = self.is_marker(tail)
        if method in ('get_object', 'head_object'):
            return self.role == 'writer' or marker
        if method == 'list_parts':
            return self.role == 'writer'
        if method in ('put_object', 'copy_object', 'create_multipart_upload',
                      'upload_part', 'upload_part_copy', 'complete_multipart_upload'):
            return (self.role == 'writer' and not marker) or (
                self.role == 'publisher' and tail == plan.MARKER)
        if method in ('delete_object', 'abort_multipart_upload'):
            return self.role == 'writer' and not marker and 'VersionId' not in params
        return False

    @staticmethod
    def is_marker(tail):
        return tail == 'CURRENT' or any(tail == stem or tail.startswith(stem + '.')
                                       for stem in ('marker.manifest', 'marker.format-version'))

    def call(self, method, params):
        self.store.before_call(self.role, method, params)
        self.store.calls.append((self.role, method, copy.deepcopy(params)))
        bucket = params.get('Bucket')
        assert bucket in BUCKETS, ('request escaped two fixed buckets', method, bucket)
        if 'ExpectedBucketOwner' in params:
            assert params['ExpectedBucketOwner'] == ACCOUNT
        if params.get('VersionId'):
            assert self.object(bucket, params['Key'], params['VersionId'])['version'] == params['VersionId']
        if method in ('copy_object', 'upload_part_copy'):
            source = params['CopySource']
            assert isinstance(source, dict) and source['Bucket'] in BUCKETS
            self.object(source['Bucket'], source['Key'], source.get('VersionId'))
        if method in ('upload_part', 'upload_part_copy', 'list_parts',
                      'complete_multipart_upload', 'abort_multipart_upload'):
            upload = self.store.uploads.get(params.get('UploadId'))
            assert upload is not None, 'invalid UploadId used as authorization evidence'
            assert (bucket, params.get('Key')) == (upload['bucket'], upload['key'])
            if method == 'complete_multipart_upload':
                parts = params['MultipartUpload']['Parts']
                assert parts and all(upload['parts'][part['PartNumber']]['etag'] == part['ETag'] for part in parts)
        if method == 'delete_objects':
            return self.bulk_delete(params)
        if not self.allowed(method, params):
            self.store.denied_indices.append(len(self.store.calls) - 1)
            if self.store.unexpected_success == method:
                return dict(ResponseMetadata=META)
            raise self.store.denial_by_method.get(method, self.store.denial)()
        if method == 'head_bucket':
            if bucket not in self.store.buckets:
                raise S3Error('NoSuchBucket', 404)
            return dict(ResponseMetadata=META)
        if method == 'create_bucket':
            if bucket in self.store.buckets:
                raise S3Error('BucketAlreadyOwnedByYou', 409)
            self.store.buckets[bucket] = dict(versioning=None, objects={})
            return dict(ResponseMetadata=META, Location='/' + bucket)
        if bucket not in self.store.buckets:
            raise S3Error('NoSuchBucket', 404)
        state = self.store.buckets[bucket]
        if method == 'put_bucket_versioning':
            state['versioning'] = params['VersioningConfiguration']['Status']
            return dict(ResponseMetadata=META)
        if method == 'get_bucket_versioning':
            return dict(ResponseMetadata=META, Status=state['versioning'])
        if method == 'get_bucket_location':
            return dict(ResponseMetadata=META, LocationConstraint='ca-central-1')
        key = params.get('Key')
        if method in ('put_object', 'copy_object'):
            if method == 'copy_object':
                source = params['CopySource']
                assert isinstance(source, dict) and source['Bucket'] in BUCKETS
                source_params = dict(Bucket=source['Bucket'], Key=source['Key'])
                assert self.allowed('get_object', source_params)
                body = self.object(source['Bucket'], source['Key'], source.get('VersionId'))['body']
            else:
                body = params['Body']
                current = state['objects'].get(key, [])
                current = current[-1] if current and not current[-1].get('deleted') else None
                if params.get('IfNoneMatch') == '*' and current is not None:
                    raise self.store.conditional_error()
                if 'IfMatch' in params and (current is None or params['IfMatch'] != current['etag']):
                    raise self.store.conditional_error()
            result = self.put(bucket, key, body)
            if method == 'copy_object':
                result['CopyObjectResult'] = {'ETag': result.pop('ETag')}
                result['CopySourceVersionId'] = self.object(source['Bucket'], source['Key'], source.get('VersionId'))['version']
            return self.corrupt(method, result)
        if method in ('get_object', 'head_object'):
            row = self.object(bucket, key, params.get('VersionId'))
            result = dict(ResponseMetadata=META, VersionId=row['version'],
                          ETag=row['etag'], ContentLength=len(row['body']))
            if method == 'get_object':
                stream = io.BytesIO(row['body'])
                self.store.bodies.append(stream)
                result['Body'] = stream
            return self.corrupt(method, result)
        if method in ('list_objects_v2', 'list_object_versions'):
            rows = []
            for object_key, versions in state['objects'].items():
                if object_key.startswith(params.get('Prefix', '')):
                    rows.extend(dict(Key=object_key, VersionId=v['version'], IsLatest=i == len(versions)-1,
                                     Size=len(v['body']), ETag=v['etag'])
                                for i, v in enumerate(versions) if not v.get('deleted'))
            field = 'Contents' if method == 'list_objects_v2' else 'Versions'
            markers = [dict(Key=k, VersionId=v['version'], IsLatest=i == len(vs)-1)
                       for k, vs in state['objects'].items() if k.startswith(params.get('Prefix', ''))
                       for i, v in enumerate(vs) if v.get('deleted')]
            result = dict(ResponseMetadata=META, IsTruncated=False, **{field: rows})
            if method == 'list_object_versions':
                result['DeleteMarkers'] = markers
            return result
        if method == 'delete_object':
            if 'VersionId' in params:
                versions = state['objects'].get(key, [])
                state['objects'][key] = [v for v in versions if v['version'] != params['VersionId']]
                return dict(ResponseMetadata={'HTTPStatusCode': 204, 'RetryAttempts': 0},
                            VersionId=params['VersionId'])
            result = self.put(bucket, key, b'')
            state['objects'][key][-1]['deleted'] = True
            return dict(ResponseMetadata={'HTTPStatusCode': 204, 'RetryAttempts': 0},
                        VersionId=result['VersionId'], DeleteMarker=True)
        if method == 'create_multipart_upload':
            upload = self.store.identifier('upload-')
            self.store.uploads[upload] = dict(bucket=bucket, key=key, parts={})
            return self.corrupt(method, dict(ResponseMetadata=META, Bucket=bucket, Key=key, UploadId=upload))
        if method in ('upload_part', 'upload_part_copy', 'list_parts', 'complete_multipart_upload', 'abort_multipart_upload'):
            upload = self.store.uploads.get(params['UploadId'])
            assert upload is not None, 'invalid UploadId used as authorization evidence'
            assert (bucket, key) == (upload['bucket'], upload['key'])
            if method in ('upload_part', 'upload_part_copy'):
                if method == 'upload_part_copy':
                    source = params['CopySource']
                    assert isinstance(source, dict) and source['Bucket'] in BUCKETS
                    body = self.object(source['Bucket'], source['Key'], source.get('VersionId'))['body']
                else:
                    body = params['Body']
                etag = '"' + hashlib.md5(body).hexdigest() + '"'
                upload['parts'][params['PartNumber']] = dict(body=body, etag=etag)
                result = dict(ResponseMetadata=META, ETag=etag)
                if method == 'upload_part_copy':
                    result['CopyPartResult'] = dict(ETag=result.pop('ETag'))
                    result['CopySourceVersionId'] = self.object(source['Bucket'], source['Key'], source.get('VersionId'))['version']
                return self.corrupt(method, result)
            if method == 'list_parts':
                return dict(ResponseMetadata=META, IsTruncated=False,
                            Parts=[dict(PartNumber=n, ETag=v['etag'], Size=len(v['body']))
                                   for n, v in upload['parts'].items()])
            if method == 'abort_multipart_upload':
                del self.store.uploads[params['UploadId']]
                return dict(ResponseMetadata={'HTTPStatusCode': 204, 'RetryAttempts': 0})
            parts = params['MultipartUpload']['Parts']
            assert all(upload['parts'][part['PartNumber']]['etag'] == part['ETag'] for part in parts)
            body = b''.join(upload['parts'][part['PartNumber']]['body'] for part in parts)
            del self.store.uploads[params['UploadId']]
            result = self.put(bucket, key, body)
            result.update(Bucket=bucket, Key=key)
            return result
        raise AssertionError('unexpected fake S3 method: ' + method)

    def object(self, bucket, key, version=None):
        rows = self.store.buckets[bucket]['objects'].get(key, [])
        row = next((v for v in rows if v['version'] == version), None) if version else (rows[-1] if rows else None)
        if row is None or row.get('deleted'):
            raise S3Error('NoSuchKey', 404)
        return row

    def put(self, bucket, key, body):
        assert isinstance(body, bytes) and len(body) <= 1024, 'unbounded test payload'
        assert self.store.buckets[bucket]['versioning'] == 'Enabled', 'mutation before versioning confirmed'
        row = dict(version=self.store.identifier('version-'), body=body,
                   etag='"' + hashlib.md5(body).hexdigest() + '"')
        self.store.buckets[bucket]['objects'].setdefault(key, []).append(row)
        return dict(ResponseMetadata=META, VersionId=row['version'], ETag=row['etag'])

    def bulk_delete(self, params):
        if self.store.bulk_denial:
            raise self.store.bulk_denial()
        deleted, errors = [], []
        for obj in params['Delete']['Objects']:
            single = dict(Bucket=params['Bucket'], **obj)
            if not self.allowed('delete_object', single):
                errors.append(dict(Key=obj['Key'], Code='AccessDenied', Message=SECRET))
                if 'VersionId' in obj:
                    errors[-1]['VersionId'] = obj['VersionId']
            else:
                deleted.append(dict(Key=obj['Key']))
        response = dict(ResponseMetadata=META, Deleted=deleted, Errors=errors)
        if self.store.bulk_override:
            self.store.bulk_override(params, response)
        return response

    def corrupt(self, method, response):
        if self.store.corrupt_positive:
            self.store.corrupt_positive(method, response)
        return response


class Journal:
    def __init__(self):
        self.entries = {}

    def write(self, name, value):
        assert name not in self.entries, 'journal record overwritten'
        assert SECRET not in repr(value), 'raw provider error leaked into journal'
        self.entries[name] = copy.deepcopy(value)
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def exists(self, name):
        return name in self.entries

    def read(self, name):
        return copy.deepcopy(self.entries[name])

    def before_call(self, role, method, params):
        assert self.entries, ('unlogged provider call', role, method)
        name = next(reversed(self.entries))
        assert name.endswith('.intent.json'), ('request lacked fresh intent', role, method, name)
        assert name.replace('.intent.', '.receipt.') not in self.entries


class STS:
    def __init__(self, store, role):
        self.store, self.role = store, role
        self.value = dict(ResponseMetadata=META, Account=ACCOUNT,
                          Arn=f"arn:aws:iam::{ACCOUNT}:user/{plan.plan()['users'][role]}",
                          UserId='offline-uid-' + role)

    def get_caller_identity(self):
        self.store.before_call(self.role, 'get_caller_identity', {})
        self.store.calls.append((self.role, 'get_caller_identity', {}))
        return self.value.copy()

    def close(self):
        pass


class LiveAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.enterContext(patch.object(socket, 'create_connection', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.reset_fixture()

    def reset_fixture(self):
        self.store, self.journal = Store(), Journal()
        self.store.before_call = self.journal.before_call
        self.clients = {role: self.store.client(role) for role in ('admin', 'writer', 'publisher')}
        self.clients.update({role + '_sts': STS(self.store, role) for role in ('writer', 'publisher')})
        self.clients['user_id_sha256'] = {
            role: hashlib.sha256(('offline-uid-' + role).encode()).hexdigest()
            for role in ('writer', 'publisher')}
        self.clients['credential_plan_sha256'] = '0' * 64

    def exercise(self):
        return a.run_checks(self.clients, self.journal, ACCOUNT)

    def assert_no_matrix_calls_after(self, index):
        for role, method, params in self.store.calls[index + 1:]:
            self.assertEqual((role, method), ('admin', 'abort_multipart_upload'))
            self.assertIn(params['Bucket'], BUCKETS)

    def test_complete_matrix_uses_fixed_fresh_buckets_and_valid_version_evidence(self):
        result = self.exercise()
        self.assertEqual(result['result'], 'PASS')
        self.assertTrue(result['actual_s3_enforcement_proven'])
        self.assertEqual(result['checks'], result['passed'])
        self.assertEqual(result['scope'], 'DISPOSABLE_BUCKETS_ONLY')
        self.assertTrue(result['conditional_publication_proven'])
        self.assertEqual(set(self.store.buckets), BUCKETS)
        self.assertTrue(all(body.closed for body in self.store.bodies))
        for _, method, params in self.store.calls:
            if method != 'get_caller_identity':
                self.assertIn(params['Bucket'], BUCKETS)
        for name in self.journal.entries:
            if name.endswith('.intent.json'):
                self.assertIn(name.replace('.intent.', '.receipt.'), self.journal.entries)

    def test_failed_run_persists_false_report_and_never_replays(self):
        self.store.denial = lambda: S3Error('NoSuchKey', 404)
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        self.enterContext(patch.dict(os.environ))
        with patch.object(a, 'Journal', return_value=self.journal), \
             patch.object(a, 'load_clients', return_value=(self.clients, ACCOUNT)), \
             patch.object(a.os, 'getuid', return_value=0), \
             patch.object(a.os, 'geteuid', return_value=0):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(a.main(['run']), 2)
            report = json.loads(output.getvalue())
            self.assertEqual(report['result'], 'REFUSED')
            self.assertFalse(report['actual_s3_enforcement_proven'])
            self.assertNotIn(SECRET, output.getvalue())
            self.assertEqual(self.journal.entries['result.json'], report)
            calls = len(self.store.calls)
            repeated = a.run('run')
            self.assertEqual(repeated, report)
            self.assertEqual(len(self.store.calls), calls)

    def test_existing_either_bucket_stops_before_any_bucket_creation(self):
        for bucket in BUCKETS:
            with self.subTest(bucket=bucket):
                self.store.buckets[bucket] = dict(versioning='Enabled', objects={})
                with self.assertRaises(Exception):
                    self.exercise()
                self.assertNotIn('create_bucket', [method for _, method, _ in self.store.calls])
                self.reset_fixture()

    def test_scope_identity_account_arn_and_user_id_must_match(self):
        for field, bad in (('Account', '210987654321'), ('Arn', f'arn:aws:iam::{ACCOUNT}:root'),
                           ('UserId', 'some-other-principal'), ('UserId', '')):
            with self.subTest(field=field, bad=bad):
                self.clients['writer_sts'].value[field] = bad
                with self.assertRaises(Exception):
                    self.exercise()
                self.assertFalse(any(method == 'create_bucket' for _, method, _ in self.store.calls))
                self.reset_fixture()

    def test_negative_evidence_requires_access_denied_403(self):
        variants = (lambda: S3Error('NoSuchKey', 404), lambda: S3Error('NoSuchBucket', 404),
                    lambda: S3Error('AccessDenied', 404), lambda: S3Error('InvalidAccessKeyId', 403),
                    lambda: TimeoutError(SECRET))
        for failure in variants:
            with self.subTest(failure=failure):
                self.store.denial = failure
                with self.assertRaises(Exception):
                    self.exercise()
                self.assertTrue(self.store.denied_indices)
                self.assert_no_matrix_calls_after(self.store.denied_indices[0])
                self.reset_fixture()

    def test_unexpected_negative_success_stops_further_matrix_mutations(self):
        self.store.unexpected_success = 'put_object'
        with self.assertRaises(Exception):
            self.exercise()
        self.assertTrue(self.store.denied_indices)
        target = next(i for i in self.store.denied_indices if self.store.calls[i][1] == 'put_object')
        self.assert_no_matrix_calls_after(target)

    def test_missing_null_or_mismatched_versions_cannot_count_as_positive(self):
        for version in (None, '', 'null'):
            with self.subTest(version=version):
                self.store.corrupt_positive = lambda method, response: (
                    response.update(VersionId=version) if method == 'put_object' else None)
                with self.assertRaises(Exception):
                    self.exercise()
                puts = [call for call in self.store.calls if call[1] == 'put_object']
                self.assertEqual(len(puts), 1)
                self.reset_fixture()
        self.store.corrupt_positive = lambda method, response: (
            response.update(VersionId='different-existing-version') if method == 'get_object' else None)
        with self.assertRaises(Exception):
            self.exercise()

    def test_wrong_or_oversized_readback_fails_and_closes_body(self):
        for body in (b'wrong bytes', b'x' * 1025):
            with self.subTest(size=len(body)):
                def corrupt(method, response):
                    if method == 'get_object':
                        response['Body'].close()
                        stream = io.BytesIO(body)
                        self.store.bodies.append(stream)
                        response['Body'] = stream
                self.store.corrupt_positive = corrupt
                with self.assertRaises(Exception):
                    self.exercise()
                self.assertTrue(all(stream.closed for stream in self.store.bodies))
                self.reset_fixture()

    def test_missing_upload_id_stops_before_any_part_request(self):
        self.store.corrupt_positive = lambda method, response: (
            response.update(UploadId='') if method == 'create_multipart_upload' else None)
        with self.assertRaises(Exception):
            self.exercise()
        self.assertFalse(any(method in ('upload_part', 'upload_part_copy', 'complete_multipart_upload')
                             for _, method, _ in self.store.calls))

    def test_missing_part_etag_stops_before_multipart_completion(self):
        self.store.corrupt_positive = lambda method, response: (
            response.update(ETag='') if method == 'upload_part' else None)
        with self.assertRaises(Exception):
            self.exercise()
        self.assertFalse(any(method == 'complete_multipart_upload' for _, method, _ in self.store.calls))

    def test_invalid_upload_error_is_not_authorization_evidence(self):
        self.store.denial_by_method['complete_multipart_upload'] = lambda: S3Error('NoSuchUpload', 404)
        with self.assertRaises(Exception):
            self.exercise()
        target = next(i for i in self.store.denied_indices
                      if self.store.calls[i][1] == 'complete_multipart_upload')
        self.assert_no_matrix_calls_after(target)

    def test_conditional_rejection_requires_precondition_failed_412(self):
        for failure in (lambda: S3Error('AccessDenied', 403),
                        lambda: S3Error('PreconditionFailed', 403),
                        lambda: S3Error('NoSuchKey', 404)):
            with self.subTest(failure=failure):
                self.store.conditional_error = failure
                with self.assertRaises(Exception):
                    self.exercise()
                self.reset_fixture()

    def test_bulk_delete_denials_require_exact_entries_and_no_deleted_objects(self):
        def wrong_code(params, value):
            value['Errors'][0]['Code'] = 'NoSuchKey'
        def wrong_key(params, value):
            value['Errors'][0]['Key'] = 'unrelated-key'
        def wrong_version(params, value):
            value['Errors'][0]['VersionId'] = 'not-requested'
        variants = (lambda params, value: value.update(Errors=[]),
                    lambda params, value: value.update(Deleted=[{'Key': params['Delete']['Objects'][0]['Key']}]),
                    wrong_code, wrong_key, wrong_version)
        for corrupt in variants:
            with self.subTest(corrupt=corrupt):
                self.store.bulk_override = corrupt
                with self.assertRaises(Exception):
                    self.exercise()
                target = next(i for i, (_, method, _) in enumerate(self.store.calls) if method == 'delete_objects')
                self.assert_no_matrix_calls_after(target)
                self.reset_fixture()

    def test_whole_bulk_delete_access_denied_403_is_valid_evidence(self):
        self.store.bulk_denial = lambda: S3Error('AccessDenied', 403)
        result = self.exercise()
        self.assertEqual(result['result'], 'PASS')
        self.assertTrue(result['actual_s3_enforcement_proven'])

    def test_control_seed_payloads_are_verified_before_negative_cases(self):
        for control in ('outside-prefix', 'outside-bucket'):
            with self.subTest(control=control):
                self.reset_fixture()
                altered = []
                def corrupt(method, response):
                    role, _, params = self.store.calls[-1]
                    matches = (params.get('Key') in a.OUTSIDE if control == 'outside-prefix'
                               else params.get('Bucket') == plan.CONTROL_BUCKET)
                    if role == 'admin' and method == 'put_object' and matches:
                        self.store.buckets[params['Bucket']]['objects'][params['Key']][-1]['body'] = b'wrong seed'
                        altered.append(params['Key'])
                self.store.corrupt_positive = corrupt
                with self.assertRaises(Exception):
                    self.exercise()
                self.assertTrue(altered)
                self.assertFalse(self.store.denied_indices)
                self.reset_fixture()


class Events:
    def __init__(self):
        self.handlers = []

    def register(self, name, handler, **kwargs):
        self.handlers.append((name, handler, kwargs.get('unique_id')))

    def unregister(self, name, handler=None, unique_id=None):
        self.handlers = [row for row in self.handlers
                         if not (row[0] == name and (row[1] == handler or row[2] == unique_id))]


class ConditionalClient:
    def __init__(self):
        self.meta = types.SimpleNamespace(events=Events())
        self.captured = []
        self.fail = False

    def put_object(self, **params):
        self.assert_no_sdk_conditionals(params)
        request = {'headers': {}}
        for _, handler, _ in list(self.meta.events.handlers):
            handler(params=request)
        self.captured.append((params, request))
        if self.fail:
            raise S3Error('PreconditionFailed', 412)
        return dict(ResponseMetadata=META, VersionId='offline-version')

    @staticmethod
    def assert_no_sdk_conditionals(params):
        assert 'IfMatch' not in params and 'IfNoneMatch' not in params


class ConditionalAdapterTests(unittest.TestCase):
    def test_conditional_header_injection_is_temporary(self):
        for argument, header, value in (('IfNoneMatch', 'If-None-Match', '*'),
                                        ('IfMatch', 'If-Match', '"expected-etag"')):
            with self.subTest(argument=argument):
                raw = ConditionalClient()
                wrapped = a.ConditionalS3(raw)
                wrapped.put_object(Bucket=plan.TEST_BUCKET, Key=plan.PREFIX + plan.MARKER,
                                   Body=b'x', **{argument: value})
                self.assertEqual(raw.captured[0][1]['headers'].get(header), value)
                self.assertFalse(raw.meta.events.handlers)
                wrapped.put_object(Bucket=plan.TEST_BUCKET, Key=plan.PREFIX + plan.MARKER, Body=b'x')
                self.assertEqual(raw.captured[1][1]['headers'], {})

    def test_conditional_header_hook_removed_when_provider_raises(self):
        raw = ConditionalClient()
        raw.fail = True
        wrapped = a.ConditionalS3(raw)
        with self.assertRaises(S3Error):
            wrapped.put_object(Bucket=plan.TEST_BUCKET, Key=plan.PREFIX + plan.MARKER,
                               Body=b'x', IfMatch='"wrong-etag"')
        self.assertFalse(raw.meta.events.handlers)


if __name__ == '__main__':
    unittest.main()
