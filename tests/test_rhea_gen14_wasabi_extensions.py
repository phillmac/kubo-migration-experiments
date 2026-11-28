"""No-network extension transport/permission/history acceptance fakes."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_wasabi_extensions as e
import test_rhea_gen14_live_iam_acceptance as f


class Transport:
    def __init__(self, store, journal):
        self.store, self.journal = store, journal
        self.calls = []
        self.deny_status, self.deny_code = 403, 'AccessDenied'
        self.put_status = 200
        self.before = lambda *args: None
        self.corrupt = lambda *args: None
        self.fail_once = False

    def __call__(self, client, spec):
        self.journal.before_call(client.role, 'raw', {})
        split = urlsplit(spec['url'])
        bucket, key = split.path[1:].split('/', 1)
        op = 'move' if spec['method'] == 'MOVE' else split.query
        self.calls.append((client.role, op, bucket, key, copy.deepcopy(spec)))
        self.before(client.role, op, bucket, key, spec)
        assert spec['headers']['x-amz-expected-bucket-owner'] == f.ACCOUNT
        assert bucket in e.BUCKETS and key in e.KEYS
        source = destination = None
        components = ()
        if op == 'move':
            assert spec['headers']['X-Wasabi-Prefix'] == 'false'
            assert spec['headers']['Overwrite'] == 'true'
            source, destination = key, spec['headers']['Destination']
            assert destination in e.KEYS
            self.store.client('admin').object(bucket, source)
            allowed = all(client.allowed('put_object', dict(Bucket=bucket, Key=k)) for k in (source, destination))
        elif op == 'compose':
            root = ET.fromstring(spec['body'])
            assert root.tag == 'ComposeRequest'
            components = tuple(x.findtext('Key') for x in root)
            assert all(k in e.KEYS for k in components)
            for k in components:
                self.store.client('admin').object(bucket, k)
            allowed = client.allowed('put_object', dict(Bucket=bucket, Key=key)) and all(
                client.allowed('get_object', dict(Bucket=bucket, Key=k)) for k in components)
        elif op == 'append':
            self.store.client('admin').object(bucket, key)
            allowed = client.allowed('put_object', dict(Bucket=bucket, Key=key))
        else:
            raise AssertionError(op)
        if self.fail_once:
            self.fail_once = False
            raise f.S3Error('InvalidRequest', 400)
        headers = {'x-amz-request-id': 'OFFLINE-REQUEST-123'}
        if not allowed:
            self.corrupt(client.role, op, bucket, key, False)
            return self.deny_status, headers, (
                '<Error><Code>' + self.deny_code + '</Code><Message>' + f.SECRET + '</Message></Error>').encode()
        if op == 'move':
            objects = self.store.buckets[bucket]['objects']
            assert destination not in objects
            objects[destination] = objects.pop(source)
            body = ('<MoveObjectResult><MoveObject><SourceKey>' + source + '</SourceKey><DestinationKey>'
                    + destination + '</DestinationKey></MoveObject><MoveCount>1</MoveCount></MoveObjectResult>').encode()
        elif op == 'compose':
            data = b''.join(self.store.client('admin').object(bucket, k)['body'] for k in components)
            self.store.client('admin').put(bucket, key, data)
            body = b''
        else:
            data = self.store.client('admin').object(bucket, key)['body'] + spec['body']
            self.store.client('admin').put(bucket, key, data)
            body = b''
        self.corrupt(client.role, op, bucket, key, True)
        return (200 if op == 'move' else self.put_status), headers, body


class ExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.enterContext(patch.object(socket, 'create_connection', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.store, self.journal = f.Store(), f.Journal()
        for bucket in e.BUCKETS:
            self.store.buckets[bucket] = dict(versioning='Enabled', objects={})
        for key in e.PROTECTED:
            self.store.client('admin').put(e.BUCKET, key, f.a.PAYLOAD)
        self.store.before_call = self.journal.before_call
        self.clients = {r: self.store.client(r) for r in ('admin', 'writer', 'publisher')}
        self.clients.update({r + '_sts': f.STS(self.store, r) for r in ('writer', 'publisher')})
        self.clients['user_id_sha256'] = {r: hashlib.sha256(('offline-uid-' + r).encode()).hexdigest()
                                         for r in ('writer', 'publisher')}
        self.clients['credential_plan_sha256'] = '0' * 64
        self.clients['closers'] = []
        self.transport = Transport(self.store, self.journal)

    def exercise(self):
        return e.run_checks(self.clients, f.ACCOUNT, self.journal, transport=self.transport)

    def test_full_matrix_preserves_history_and_requires_source_destination_denials(self):
        initial = copy.deepcopy(self.store.buckets[e.BUCKET]['objects'])
        result = self.exercise()
        self.assertEqual(result['result'], 'PASS')
        self.assertGreaterEqual(result['explicit_denials'], 40)
        for key, rows in initial.items():
            current = self.store.buckets[e.BUCKET]['objects'][key]
            self.assertEqual(current[:len(rows)], rows)
            self.assertEqual(len(current), len(rows) + (2 if key == e.APPROVED else 0))
        self.assertTrue(all(body.closed for body in self.store.bodies))
        serialized = repr(self.journal.entries)
        self.assertNotIn(f.SECRET, serialized)
        self.assertTrue(any(role == 'publisher' and op == 'compose' and key == e.APPROVED
                            for role, op, _, key, _ in self.transport.calls))
        self.assertTrue(any(role == 'writer' and op == 'move' and e.protected(key)
                            for role, op, _, key, _ in self.transport.calls))

    def test_404_does_not_count_as_denial(self):
        self.transport.deny_status, self.transport.deny_code = 404, 'NoSuchKey'
        with self.assertRaisesRegex(e.p.Refusal, 'not explicitly denied'):
            self.exercise()
        self.assertEqual(len(self.transport.calls), 7)
        failed = [value for name, value in self.journal.entries.items()
                  if name.endswith('.receipt.json') and value.get('result') == 'FAIL']
        self.assertEqual(failed[-1]['evidence']['http_status'], 404)
        self.assertEqual(failed[-1]['evidence']['error_code'], 'NoSuchKey')
        self.assertEqual(failed[-1]['evidence']['request_id'], 'OFFLINE-REQUEST-123')
        self.assertNotIn(f.SECRET, repr(failed))

    def test_move_negatives_allow_existing_destination_without_prefix_expansion(self):
        self.exercise()
        negatives = [spec for role, op, bucket, _, spec in self.transport.calls
                     if role == 'writer' and op == 'move'
                     and spec['headers']['Destination'] in e.PROTECTED]
        self.assertEqual(len(negatives), len(e.PROTECTED))
        for spec in negatives:
            self.assertEqual(spec['headers']['Overwrite'], 'true')
            self.assertEqual(spec['headers']['X-Wasabi-Prefix'], 'false')

    def test_signature_failure_does_not_count_as_denial(self):
        self.transport.deny_code = 'SignatureDoesNotMatch'
        with self.assertRaisesRegex(e.p.Refusal, 'not explicitly denied'):
            self.exercise()

    def test_failure_evidence_keeps_only_allowlisted_error_code(self):
        for code, expected in (('MissingSecurityHeader', 'MissingSecurityHeader'),
                               ('XAmzContentSHA256Mismatch', 'XAmzContentSHA256Mismatch'),
                               (f.SECRET, None)):
            with self.subTest(code=expected):
                body = ('<Error xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                        '<Code>' + code + '</Code><Message>' + f.SECRET + '</Message></Error>').encode()
                evidence = e.response_evidence(400, {}, body)
                self.assertEqual(evidence['error_code'], expected)
                self.assertNotIn(f.SECRET, repr(evidence))

    def test_denied_request_with_hidden_write_fails_history_check(self):
        def corrupt(role, op, bucket, key, allowed):
            if not allowed:
                self.store.client('admin').put(bucket, key, b'hidden mutation')
        self.transport.corrupt = corrupt
        with self.assertRaisesRegex(e.p.Refusal, 'denied extension changed'):
            self.exercise()

    def test_denied_request_with_deleted_history_fails(self):
        def corrupt(role, op, bucket, key, allowed):
            if not allowed:
                self.store.buckets[bucket]['objects'][key].clear()
        self.transport.corrupt = corrupt
        with self.assertRaisesRegex(e.p.Refusal, 'denied extension changed'):
            self.exercise()

    def test_bad_positive_body_stops_before_denials(self):
        def corrupt(role, op, bucket, key, allowed):
            if allowed and op == 'append':
                row = self.store.buckets[bucket]['objects'][key][-1]
                row['body'] = b'wrong append'
                row['etag'] = '"' + hashlib.md5(row['body']).hexdigest() + '"'
        self.transport.corrupt = corrupt
        with self.assertRaisesRegex(e.p.Refusal, 'publication version/body differs'):
            self.exercise()
        self.assertEqual(len(self.transport.calls), 1)

    def test_move_that_loses_an_old_version_is_rejected(self):
        def corrupt(role, op, bucket, key, allowed):
            if allowed and op == 'move':
                self.store.buckets[bucket]['objects'][e.FIXTURES[role + '-move-dest']].pop(0)
        self.transport.corrupt = corrupt
        with self.assertRaisesRegex(e.p.Refusal, 'exactly the recorded versions'):
            self.exercise()

    def test_wrong_identity_prevents_all_fixture_mutations(self):
        self.clients['writer_sts'].value['Account'] = '000000000000'
        with self.assertRaisesRegex(e.p.Refusal, 'identity differs'):
            self.exercise()
        self.assertFalse(self.transport.calls)
        self.assertFalse(any(row[1] == 'put_object' for row in self.store.calls))

    def test_existing_extension_fixture_prevents_run(self):
        self.store.client('admin').put(e.BUCKET, e.FIXTURES['a'], e.BASE)
        with self.assertRaisesRegex(e.p.Refusal, 'already exist'):
            self.exercise()
        self.assertFalse(self.transport.calls)

    def test_xml_mixed_move_results_never_pass_denial(self):
        body = b'<MoveObjectResult><MoveObject/><Error><Code>AccessDenied</Code></Error><MoveCount>1</MoveCount></MoveObjectResult>'
        with self.assertRaises(e.p.Refusal):
            e.xml_result(200, {}, body, 'move', 'deny', e.FIXTURES['a'], e.FIXTURES['b'])

    def test_204_requires_a_successful_empty_put_and_still_checks_versions(self):
        self.transport.put_status = 204
        self.assertEqual(self.exercise()['result'], 'PASS')
        for op, expected, body in (('move', 'ok', b''), ('append', 'deny', b''),
                                   ('compose', 'ok', b' '), ('append', 'ok', b'<Error/>')):
            with self.subTest(op=op, expected=expected, body=body), self.assertRaises(e.p.Refusal):
                e.xml_result(204, {}, body, op, expected, e.FIXTURES['a'])

    def test_xml_explicit_per_object_failure_with_zero_success_is_accepted(self):
        body = b'<MoveObjectResult><Error><Code>AccessDenied</Code></Error><MoveCount>0</MoveCount></MoveObjectResult>'
        result = e.xml_result(200, {}, body, 'move', 'deny', e.FIXTURES['a'], e.FIXTURES['b'])
        self.assertEqual(result['error_code'], 'AccessDenied')

    def test_xml_entities_and_oversized_response_are_rejected(self):
        for body in (b'<!DOCTYPE x><Error><Code>AccessDenied</Code></Error>', b'x' * (e.MAX_XML + 1)):
            with self.subTest(body=body[:20]), self.assertRaises(e.p.Refusal):
                e.xml_result(403, {}, body, 'append', 'deny', e.FIXTURES['a'])

    def test_scope_and_payload_limits(self):
        with self.assertRaises(e.p.Refusal):
            e.request_spec('append', 'production', e.FIXTURES['a'], f.ACCOUNT, data=e.APPEND)
        with self.assertRaises(e.p.Refusal):
            e.request_spec('move', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, destination='rhea/')
        with self.assertRaises(e.p.Refusal):
            e.request_spec('compose', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, components=('production/key',))
        with self.assertRaises(e.p.Refusal):
            e.request_spec('append', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, data=b'x' * 1025)

    def test_run_failure_is_saved_and_never_automatically_retried(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(e, 'STATE', Path(directory) / 'state'), \
             patch.object(e, 'Journal', return_value=self.journal), \
             patch.object(e.acceptance, 'load_clients', return_value=(self.clients, f.ACCOUNT)), \
             patch.object(e, 'run_checks', side_effect=f.S3Error('InvalidRequest', 400)) as run, \
             patch.object(e.os, 'getuid', return_value=0), patch.object(e.os, 'geteuid', return_value=0), \
             patch.dict(os.environ):
            old_mask = os.umask(0o077)
            try:
                result = e.run('run')
                self.assertEqual(result['result'], 'REFUSED')
                self.assertEqual(e.run('run'), result)
                self.assertEqual(run.call_count, 1)
                self.assertNotIn(f.SECRET, json.dumps(result))
            finally:
                os.umask(old_mask)


class RawTransportTests(unittest.TestCase):
    def make(self, body=b'', status=200):
        self.signed, self.sent = [], []
        class Request:
            def __init__(self, **kw):
                self.method, self.url, self.body, self.headers = kw['method'], kw['url'], kw['data'], kw['headers']
                self.stream_output = kw['stream_output']
            def prepare(self):
                return self
        stream = io.BytesIO(body)
        def sign(operation, request, **kw):
            assert request.headers['X-Amz-Content-Sha256'] == e.p.sha(request.body), 'payload hash absent before signing'
            self.signed.append((operation, request, kw))
            request.headers['Authorization'] = f.SECRET
        def send(request):
            self.sent.append(request)
            return types.SimpleNamespace(status_code=status, headers={'x-amz-request-id': 'offline-id'}, raw=stream)
        client = types.SimpleNamespace(meta=types.SimpleNamespace(endpoint_url=e.p.S3_ENDPOINT),
            _request_signer=types.SimpleNamespace(sign=sign),
            _endpoint=types.SimpleNamespace(http_session=types.SimpleNamespace(send=send)))
        fake = types.ModuleType('botocore.awsrequest')
        fake.AWSRequest = Request
        return client, stream, fake

    def test_actual_method_query_headers_are_signed_once_with_streaming_response(self):
        client, stream, fake = self.make()
        spec = e.request_spec('append', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, data=e.APPEND)
        with patch.dict(sys.modules, {'botocore.awsrequest': fake}):
            status, headers, body = e.raw_request(client, spec)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.signed), 1)
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(self.sent[0].stream_output)
        self.assertTrue(self.sent[0].url.endswith('?append'))
        self.assertEqual(self.sent[0].headers['X-Amz-Content-Sha256'], e.p.sha(e.APPEND))
        self.assertEqual(self.signed[0][2], dict(region_name='ca-central-1', signing_name='s3'))
        self.assertTrue(stream.closed)
        self.assertNotIn(f.SECRET, repr((status, headers, body)))

    def test_payload_hash_covers_compose_bytes_and_empty_move_body_before_signing(self):
        for operation, options in (('compose', dict(components=(e.FIXTURES['a'],))),
                                    ('move', dict(destination=e.FIXTURES['b']))):
            with self.subTest(operation=operation):
                client, stream, fake = self.make()
                spec = e.request_spec(operation, e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, **options)
                spec['headers']['x-amz-content-sha256'] = 'UNSIGNED-PAYLOAD'
                original = copy.deepcopy(spec)
                with patch.dict(sys.modules, {'botocore.awsrequest': fake}):
                    e.raw_request(client, spec)
                matching = [value for key, value in self.sent[0].headers.items()
                            if key.lower() == 'x-amz-content-sha256']
                self.assertEqual(matching, [e.p.sha(spec['body'])])
                self.assertEqual(spec, original, 'signing changed the journalable request specification')
                self.assertTrue(stream.closed)

    def test_transport_never_follows_redirect_or_repeats(self):
        client, stream, fake = self.make(status=307)
        spec = e.request_spec('append', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, data=e.APPEND)
        with patch.dict(sys.modules, {'botocore.awsrequest': fake}):
            status, _, _ = e.raw_request(client, spec)
        self.assertEqual(status, 307)
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(stream.closed)

    def test_transport_refuses_unbounded_body_and_closes_it(self):
        client, stream, fake = self.make(body=b'x' * (e.MAX_XML + 1))
        spec = e.request_spec('append', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, data=e.APPEND)
        with patch.dict(sys.modules, {'botocore.awsrequest': fake}), self.assertRaises(e.p.Refusal):
            e.raw_request(client, spec)
        self.assertTrue(stream.closed)

    def test_transport_rejects_redirected_destination_before_signing(self):
        client, stream, fake = self.make()
        spec = e.request_spec('append', e.BUCKET, e.FIXTURES['a'], f.ACCOUNT, data=e.APPEND)
        spec['url'] = 'https://example.invalid/credentials'
        with patch.dict(sys.modules, {'botocore.awsrequest': fake}), self.assertRaises(e.p.Refusal):
            e.raw_request(client, spec)
        self.assertFalse(self.signed)


class ResumeJournal(f.Journal):
    def raw(self, name):
        return e.p.canonical(self.read(name))


class ChecksumContinuationTests(unittest.TestCase):
    def setUp(self):
        ExtensionsTests.setUp(self)
        self.original = ResumeJournal()
        self.store.before_call = self.original.before_call
        # Match the real first-attempt sequence number without real provider data.
        for _ in range(3):
            self.store.client('admin').put(e.BUCKET, e.APPROVED, f.a.PAYLOAD)
        self.original.write('run.intent.json', dict(
            schema=1, domain='rhea-wasabi-extensions-v1', account=f.ACCOUNT,
            endpoint=e.p.S3_ENDPOINT, buckets=list(e.BUCKETS), policy_sha256=e.p.POLICY_SHAS,
            credential_plan_sha256=self.clients['credential_plan_sha256']))
        response = (b'<Error><Code>InvalidRequest</Code><Message>Missing required header for this request: '
                    b'X-Amz-Content-Sha256</Message></Error>')
        response = response.ljust(395, b' ')
        def missing_header(client, spec):
            self.original.before_call(client.role, 'raw', {})
            return 400, {'x-amz-request-id': 'OFFLINE-ORIGINAL-REQUEST'}, response
        trace = e.Trace()
        try:
            e.run_checks(self.clients, f.ACCOUNT, self.original, trace, transport=missing_header)
        except e.p.Refusal as exc:
            self.original.write('result.json', dict(
                result='REFUSED', stage=trace.stage, checks=trace.checks, explicit_denials=trace.denials,
                extension_response=exc.extension_response, reason=str(exc), **e.acceptance.error_details(exc)))
        else:
            raise AssertionError('missing-header control did not fail')
        self.assertEqual(trace.checks, 43)
        self.assertEqual(trace.stage, 'admin-append-positive')
        self.original.write('diagnostic-result.json', copy.deepcopy(e.CHECKSUM_DIAGNOSTIC))
        self.enterContext(patch.object(e, 'ORIGINAL_FAILURE_BODY_SHA', e.p.sha(response)))
        self.enterContext(patch.object(e, 'ORIGINAL_SNAPSHOT_SHA', e.p.sha(self.original.raw(e.ORIGINAL_SNAPSHOT))))
        self.corrected, self.reconciled = ResumeJournal(), ResumeJournal()
        self.store.before_call = self.corrected.before_call
        self.transport = Transport(self.store, self.corrected)
        directory = self.enterContext(tempfile.TemporaryDirectory(prefix='extension-FAKE-resume-'))
        self.state = Path(directory)
        self.enterContext(patch.object(e, 'STATE', self.state))
        def journals(continuation=None):
            if continuation:
                (self.state / continuation).mkdir(exist_ok=True)
            return {None: self.original, 'checksum-corrected': self.corrected,
                    'append-reconciled': self.reconciled}[continuation]
        self.enterContext(patch.object(e, 'Journal', side_effect=journals))
        self.clients_load = self.enterContext(patch.object(e.acceptance, 'load_clients', return_value=(self.clients, f.ACCOUNT)))
        checks = e.run_checks
        self.enterContext(patch.object(e, 'run_checks', side_effect=lambda *args, **kwargs:
                                     checks(*args, transport=self.transport, **kwargs)))
        self.enterContext(patch.object(e.os, 'getuid', return_value=0))
        self.enterContext(patch.object(e.os, 'geteuid', return_value=0))
        self.enterContext(patch.dict(os.environ))
        old_mask = os.umask(0o077)
        self.addCleanup(os.umask, old_mask)

    def invoke(self, mode='resume-checksum'):
        output = io.StringIO()
        with redirect_stdout(output):
            code = e.main([mode])
        self.assertNotIn(f.SECRET, output.getvalue())
        return code, json.loads(output.getvalue())

    def test_corrected_matrix_uses_existing_seeds_and_keeps_original_evidence(self):
        old = copy.deepcopy(self.original.entries)
        seeds = [row for row in self.store.calls if row[1] == 'put_object']
        code, value = self.invoke()
        self.assertEqual(code, 0, value)
        self.assertEqual(value['result'], 'PASS')
        self.assertEqual(value['continuation'], 'checksum-corrected')
        self.assertEqual(value['explicit_denials'], 49)
        self.assertEqual(len(self.transport.calls), 57)
        self.assertEqual(seeds, [row for row in self.store.calls if row[1] == 'put_object'])
        self.assertEqual(self.original.entries, old)
        self.assertEqual(value['source_evidence']['original_before_snapshot_sha256'], e.ORIGINAL_SNAPSHOT_SHA)
        self.assertEqual(value['source_evidence']['diagnostic_result_sha256'],
                         e.p.sha(self.original.raw('diagnostic-result.json')))
        self.assertEqual(self.invoke()[1], value)
        self.assertEqual(self.invoke('status-checksum')[1], value)
        self.assertEqual(self.invoke('run')[1], old['result.json'])
        self.assertEqual(len(self.transport.calls), 57)
        self.assertEqual(self.clients_load.call_count, 1)

    def test_history_change_prevents_every_custom_operation_and_reseed(self):
        self.store.client('admin').put(e.BUCKET, e.FIXTURES['admin-append'], b'unexpected version')
        old = copy.deepcopy(self.original.entries)
        seeds = [row for row in self.store.calls if row[1] == 'put_object']
        code, value = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn('history differs', value['reason'])
        self.assertFalse(self.transport.calls)
        self.assertEqual(seeds, [row for row in self.store.calls if row[1] == 'put_object'])
        self.assertEqual(old, self.original.entries)
        self.assertEqual(self.invoke()[1], value)
        self.assertEqual(self.clients_load.call_count, 1)

    def test_different_original_failure_stage_is_rejected_before_credentials(self):
        self.original.entries['result.json']['stage'] = 'writer-append-positive'
        self.assertEqual(self.invoke()[0], 2)
        self.clients_load.assert_not_called()
        self.assertFalse(self.corrected.entries)

    def test_missing_diagnostic_is_rejected_before_credentials(self):
        self.original.entries.pop('diagnostic-result.json')
        self.assertEqual(self.invoke()[0], 2)
        self.clients_load.assert_not_called()
        self.assertFalse(self.corrected.entries)

    def test_wrong_error_or_unproved_history_is_rejected_before_credentials(self):
        for name, value in (('error_code', 'AccessDenied'), ('http_status', 403),
                             ('history_unchanged', False), ('history_unchanged', 1),
                             ('message', 'another failure')):
            with self.subTest(name=name, value=value):
                self.original.entries['diagnostic-result.json'] = dict(e.CHECKSUM_DIAGNOSTIC, **{name: value})
                self.assertEqual(self.invoke()[0], 2)
                self.clients_load.assert_not_called()
                self.assertFalse(self.corrected.entries)

    def test_original_snapshot_edit_is_rejected_before_credentials(self):
        self.original.entries[e.ORIGINAL_SNAPSHOT][e.BUCKET][0]['latest'] = False
        self.assertEqual(self.invoke()[0], 2)
        self.clients_load.assert_not_called()
        self.assertFalse(self.corrected.entries)

    def test_changed_credential_account_refuses_before_continuation_intent(self):
        self.original.entries['run.intent.json']['account'] = '999999999999'
        self.assertEqual(self.invoke()[0], 2)
        self.assertFalse(self.corrected.entries)
        self.assertFalse(self.transport.calls)

    def test_corrected_failure_is_saved_and_never_replayed(self):
        self.transport.fail_once = True
        code, value = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(value['result'], 'REFUSED')
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.invoke()[1], value)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.original.read('result.json')['result'], 'REFUSED')

    def test_pending_continuation_does_not_retry_or_load_credentials(self):
        self.corrected.write('run.intent.json', {'result': 'interrupted'})
        self.assertEqual(self.invoke()[0], 2)
        self.clients_load.assert_not_called()
        self.assertFalse(self.transport.calls)

    def old_204_receipt(self):
        self.transport.put_status = 204
        parser = e.xml_result
        def old_parser(status, *args):
            if status == 204:
                raise e.p.Refusal('custom positive control failed')
            return parser(status, *args)
        with patch.object(e, 'xml_result', old_parser):
            code, result = self.invoke()
        self.assertEqual(code, 2, result)
        self.assertEqual(result['checks'], 30)
        self.assertEqual(len(self.transport.calls), 1)
        self.store.before_call = self.reconciled.before_call
        self.transport.journal = self.reconciled

    def test_reconcile_committed_append_then_execute_remaining_matrix_once(self):
        self.old_204_receipt()
        prior = copy.deepcopy(self.corrected.entries)
        code, result = self.invoke('resume-append')
        self.assertEqual(code, 0, result)
        self.assertEqual(result['explicit_denials'], 49)
        self.assertEqual(self.reconciled.read('admin-append-reconciliation.json')['result'], 'APPLIED_ONCE')
        self.assertEqual(self.invoke('status-append')[1], result)
        self.assertEqual(self.invoke('resume-append')[1], result)
        self.assertEqual(len(self.transport.calls), 57)
        self.assertEqual(self.transport.calls[1][0:2], ('admin', 'compose'))
        self.assertEqual(self.corrected.entries, prior)

    def test_extra_version_blocks_append_adoption_before_any_more_requests(self):
        self.old_204_receipt()
        self.store.client('admin').put(e.BUCKET, e.FIXTURES['admin-append'], e.BASE + e.APPEND)
        code, result = self.invoke('resume-append')
        self.assertEqual(code, 2, result)
        self.assertIn('version/body differs', result['reason'])
        self.assertEqual(len(self.transport.calls), 1)

    def test_receipt_mismatch_blocks_append_adoption_locally(self):
        self.old_204_receipt()
        self.corrected.entries['0030.receipt.json']['intent_sha256'] = '0' * 64
        code, result = self.invoke('resume-append')
        self.assertEqual(code, 2, result)
        self.assertEqual(result['stage'], 'validate_append_receipt')
        self.assertEqual(self.clients_load.call_count, 1)
        self.assertEqual(len(self.transport.calls), 1)


if __name__ == '__main__':
    unittest.main()
