#!/usr/bin/env python3
"""One recorded live IAM acceptance on two fixed disposable Wasabi buckets."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import time
import uuid

import rhea_gen14_create_iam_credentials as p
import rhea_gen14_recover_iam_policy as managed

STATE = Path('/root/.local/share/rhea-gen14-iam-live-acceptance-20261125')
TEST_BUCKET, CONTROL_BUCKET = p.admin.TEST_BUCKET, p.admin.CONTROL_BUCKET
PREFIX, MARKERS, MARKER, DATA = p.admin.PREFIX, p.admin.MARKERS, p.admin.MARKER, p.admin.DATA
PAYLOAD = b'rhea disposable IAM acceptance\n'
BUCKETS = (TEST_BUCKET, CONTROL_BUCKET)
OUTSIDE = ('other-project/000123.sst', 'rhea/pebbleds-evil/000123.sst')
DATA_KEYS = {name: PREFIX + 'acceptance-' + name + '.sst' for name in ('copy', 'multipart', 'delete', 'bulk', 'abort')}
KEYS = frozenset([PREFIX + k for k in MARKERS] + [PREFIX + DATA, *OUTSIDE, *DATA_KEYS.values()])
S3_CODES = frozenset(('AccessDenied', 'NoSuchBucket', 'NoSuchKey', 'NoSuchUpload', 'NoSuchVersion',
    'PreconditionFailed', 'ConditionalRequestConflict', 'BucketAlreadyExists', 'BucketAlreadyOwnedByYou',
    'InvalidBucketName', 'InvalidLocationConstraint', 'AuthorizationHeaderMalformed', 'InvalidRequest',
    'InvalidArgument', 'NotImplemented', 'MethodNotAllowed', 'InvalidPart', 'InvalidPartOrder',
    'EntityTooSmall', 'InvalidAccessKeyId', 'PermanentRedirect', 'SlowDown', '404'))


def error_details(exc):
    detail = managed.error_details(exc)
    response = getattr(exc, 'response', {})
    error = response.get('Error', {}) if type(response) is dict else {}
    code = error.get('Code') if type(error) is dict else None
    if type(code) is str and code in S3_CODES:
        detail['error_code'] = code
    return detail


class Trace:
    stage = 'validate_local_state'


class ConditionalS3:
    """Supply signed conditional PUT headers with the installed older SDK model."""
    def __init__(self, client):
        self.client = client

    def __getattr__(self, name):
        return getattr(self.client, name)

    def put_object(self, **kwargs):
        headers = {header: kwargs.pop(name) for name, header in
                   (('IfNoneMatch', 'If-None-Match'), ('IfMatch', 'If-Match')) if name in kwargs}
        if not headers:
            return self.client.put_object(**kwargs)
        event, token = 'before-call.s3.PutObject', 'rhea-conditional-' + uuid.uuid4().hex
        def inject(params, **_):
            params['headers'].update(headers)
        self.client.meta.events.register(event, inject, unique_id=token)
        try:
            return self.client.put_object(**kwargs)
        finally:
            self.client.meta.events.unregister(event, unique_id=token)


class Journal(p.Journal):
    def __enter__(self):
        self.fd, self.lock = p.directory(STATE, create=True, private=True), None
        try:
            try:
                self.lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=self.fd)
                os.fsync(self.lock)
                os.fsync(self.fd)
            except FileExistsError:
                self.lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            p.checked_file(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise


def load_clients(trace):
    trace.stage = 'verify_managed_credentials'
    verified = managed.run('verify')
    with p.Journal() as old, managed.Journal() as credentials:
        binding, legacy_receipts = managed.legacy_binding(old)
        receipts, pending = credentials.load_managed(binding)
        p.require(len(receipts) == 6 and pending is None
                  and verified['plan_sha256'] == p.admin.iam.digest(binding), 'credential verification changed')
        saved = {}
        for i, role in enumerate(('writer', 'publisher')):
            raw = credentials.raw(role + '.json')
            p.require(p.sha(raw) == receipts[4 + i]['result']['credential_file_sha256'], 'credential file changed')
            saved[role] = p.admin.iam.parse(raw)
    trace.stage = 'initialize_s3_clients'
    import boto3
    from botocore.config import Config
    config = Config(retries={'total_max_attempts': 1, 'mode': 'standard'}, connect_timeout=5,
                    read_timeout=10, signature_version='v4', proxies={}, s3={'addressing_style': 'path'})
    source_key, source_secret = p.source_credentials()
    clients = {'user_id_sha256': {r: legacy_receipts[i]['result']['user_id_sha256']
                                 for i, r in enumerate(('writer', 'publisher'))},
               'credential_plan_sha256': verified['plan_sha256'], 'closers': []}
    try:
        for role in ('admin', 'writer', 'publisher'):
            key, secret = (source_key, source_secret) if role == 'admin' else (
                saved[role]['AccessKeyId'], saved[role]['SecretAccessKey'])
            session = boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                                    aws_session_token=None, region_name='ca-central-1')
            client = session.client('s3', endpoint_url=p.S3_ENDPOINT, config=config)
            clients['closers'].append(client)
            p.require(callable(client.meta.events.register) and callable(client.meta.events.unregister),
                      'conditional PUT event adapter unavailable')
            clients[role] = ConditionalS3(client)
            if role != 'admin':
                client = session.client('sts', endpoint_url=p.admin.STS_ENDPOINT, region_name='us-east-1', config=config)
                clients['closers'].append(client)
                clients[role + '_sts'] = client
    except Exception:
        for client in clients['closers']:
            client.close()
        raise
    return clients, binding['identity']['account']


def opaque(value):
    return type(value) is str and 0 < len(value) <= 1024 and value != 'null'


class Checks:
    def __init__(self, clients, journal, account, trace):
        self.clients, self.journal, self.account, self.trace = clients, journal, account, trace
        self.count, self.passed, self.denials, self.uploads = 0, 0, 0, {}
        self.versions = {PREFIX + k: [] for k in MARKERS}
        self.etags, self.observations = {}, {}

    def params(self, key=None, bucket=TEST_BUCKET, **extra):
        return dict(Bucket=bucket, ExpectedBucketOwner=self.account, **({'Key': key} if key else {}), **extra)

    def boundary(self, params, method):
        if 'Bucket' in params:
            p.require(params['Bucket'] in BUCKETS and (method == 'create_bucket'
                      or params.get('ExpectedBucketOwner') == self.account),
                      'request outside disposable bucket boundary')
        if 'Key' in params:
            p.require(params['Key'] in KEYS, 'request outside fixed fixture keys')
        if 'CopySource' in params:
            source = params['CopySource']
            p.require(type(source) is dict and source.get('Bucket') in BUCKETS and source.get('Key') in KEYS,
                      'copy source outside disposable fixture boundary')
        if 'Delete' in params:
            p.require(all(row.get('Key') in KEYS for row in params['Delete']['Objects']), 'bulk delete outside fixtures')
        p.require('Body' not in params or type(params['Body']) is bytes and len(params['Body']) <= 1024,
                  'fixture exceeds 1024 bytes')

    def call(self, case, role, method, *, expect='ok', check=None, **params):
        self.boundary(params, method)
        self.trace.stage = case
        index, started = self.count, time.monotonic()
        self.count += 1
        intent = dict(case=case, role=role, method=method, expected=expect, sequence=index,
                      parameters={k: v for k, v in params.items() if k != 'Body'}, monotonic_start=started)
        self.journal.write(f'{index:04d}.intent.json', intent)
        response, evidence, writing_receipt = None, {}, False
        try:
            try:
                response = getattr(self.clients[role], method)(**params)
            except Exception as exc:
                detail = error_details(exc)
                accepted = ((expect in ('deny', 'bulk_deny') and detail['error_code'] == 'AccessDenied' and detail['http_status'] == 403)
                    or (expect == 'absent' and detail['error_code'] in ('NoSuchBucket', '404') and detail['http_status'] == 404)
                    or (expect == 'precondition' and detail['error_code'] == 'PreconditionFailed' and detail['http_status'] == 412))
                if not accepted:
                    raise
                evidence.update(detail)
            else:
                p.require(type(response) is dict, 'invalid S3 response')
                for name in ('VersionId', 'UploadId', 'ETag'):
                    if opaque(response.get(name)):
                        evidence[name] = response[name]
                if method == 'create_multipart_upload' and opaque(response.get('UploadId')):
                    self.uploads[response['UploadId']] = (params['Bucket'], params['Key'])
                p.require(expect in ('ok', 'bulk_deny'), 'request unexpectedly succeeded')
                meta = response.get('ResponseMetadata', {})
                p.require(meta.get('HTTPStatusCode') == (204 if method in ('delete_object', 'abort_multipart_upload') else 200)
                          and meta.get('RetryAttempts', 0) == 0 and 'Error' not in response,
                          'unexpected S3 status, retry or embedded error')
                if opaque(meta.get('RequestId')):
                    evidence['request_id'] = meta['RequestId']
                if method in ('put_object', 'copy_object', 'complete_multipart_upload'):
                    p.require(opaque(response.get('VersionId')) and opaque(response.get('ETag',
                              response.get('CopyObjectResult', {}).get('ETag'))), 'missing version or ETag receipt')
                if method == 'create_multipart_upload':
                    p.require(opaque(response.get('UploadId')), 'missing upload identifier')
                if method == 'upload_part':
                    p.require(opaque(response.get('ETag')), 'missing part ETag')
                if check:
                    extra = check(response)
                    if extra:
                        evidence.update(extra)
                if method in ('complete_multipart_upload', 'abort_multipart_upload'):
                    self.uploads.pop(params['UploadId'], None)
            writing_receipt = True
            self.journal.write(f'{index:04d}.receipt.json', dict(case=case, result='PASS', evidence=evidence,
                intent_sha256=p.admin.iam.digest(intent), monotonic_finish=time.monotonic()))
            self.passed += 1
            self.denials += expect in ('deny', 'bulk_deny')
            self.trace.checks, self.trace.passed, self.trace.denials = self.count, self.passed, self.denials
            if case in ('deny-writer-CURRENT-put_object', 'deny-publisher-data-put_object',
                        'late-writer-current-denial', 'late-publisher-data-denial'):
                self.observations[case] = time.monotonic()
            return response
        except Exception as exc:
            self.trace.checks, self.trace.passed, self.trace.denials = self.count, self.passed, self.denials
            if not writing_receipt:
                self.journal.write(f'{index:04d}.receipt.json', dict(case=case, result='FAIL', evidence=evidence,
                    intent_sha256=p.admin.iam.digest(intent), **error_details(exc), monotonic_finish=time.monotonic()))
            raise
        finally:
            if type(response) is dict and 'Body' in response:
                response['Body'].close()

    def version(self, key, response):
        version = response.get('VersionId')
        etag = response.get('ETag', response.get('CopyObjectResult', {}).get('ETag'))
        p.require(opaque(version) and opaque(etag), 'missing version or ETag receipt')
        if key in self.versions:
            self.versions[key].append(version)
            self.etags[key] = etag
        return version

    def get(self, role, key, version=None, bucket=TEST_BUCKET):
        def match(value):
            p.require(value['Body'].read(1025) == PAYLOAD and opaque(value.get('VersionId'))
                      and (version is None or value['VersionId'] == version), 'object readback differs')
        return self.call(f'get-{role}-{key}-{version or "current"}', role, 'get_object', check=match,
                         **self.params(key, bucket, **({'VersionId': version} if version else {})))

    def put(self, role, key, *, bucket=TEST_BUCKET, **extra):
        response = self.call(f'put-{role}-{bucket}-{key}', role, 'put_object', **self.params(key, bucket, Body=PAYLOAD, **extra))
        version = self.version(key, response)
        self.get(role, key, version, bucket)
        return version

    def lists(self, role, prefix=None, expected='ok', bucket=TEST_BUCKET, methods=('list_objects_v2', 'list_object_versions')):
        def complete(value):
            p.require(value.get('IsTruncated', False) is False, 'truncated fixture listing')
            rows = value.get('Contents', value.get('Versions', []))
            needed = {key for key in self.versions if key.startswith(prefix or '')}
            p.require(type(rows) is list and needed <= {row.get('Key') for row in rows}, 'listing omitted protected fixtures')
        for method in methods:
            self.call(f'{method}-{role}-{bucket}-{prefix!r}', role, method, expect=expected, check=complete,
                      **self.params(bucket=bucket, MaxKeys=1000, **({'Prefix': prefix} if prefix is not None else {})))

    def inventory(self):
        def match(value):
            p.require(value.get('IsTruncated', False) is False, 'truncated protected version inventory')
            versions = {key: [] for key in self.versions}
            latest = {}
            for row in value.get('Versions', []):
                if row.get('Key') in versions:
                    p.require(opaque(row.get('VersionId')), 'invalid protected object version')
                    versions[row['Key']].append(row['VersionId'])
                    if row.get('IsLatest'):
                        latest[row['Key']] = row['VersionId']
            p.require(not any(row.get('Key') in versions for row in value.get('DeleteMarkers', [])),
                      'protected delete marker appeared')
            p.require(all(sorted(versions[key]) == sorted(wanted) and latest.get(key) == wanted[-1]
                          for key, wanted in self.versions.items()), 'protected version inventory changed')
        self.call('verify-protected-version-inventory', 'admin', 'list_object_versions', check=match,
                  **self.params(Prefix=PREFIX, MaxKeys=1000))

    def multipart(self, role, key):
        created = self.call('create-multipart-' + role, role, 'create_multipart_upload', **self.params(key))
        upload = created.get('UploadId')
        p.require(opaque(upload), 'missing upload identifier')
        part = self.call('upload-part-' + role, role, 'upload_part', **self.params(key, UploadId=upload, PartNumber=1, Body=PAYLOAD))
        p.require(opaque(part.get('ETag')), 'missing part ETag')
        if role == 'writer':
            def match(value):
                p.require(value.get('IsTruncated', False) is False and any(
                    row.get('PartNumber') == 1 and row.get('ETag') == part['ETag'] for row in value.get('Parts', [])),
                    'multipart part readback differs')
            self.call('list-parts-writer', role, 'list_parts', check=match, **self.params(key, UploadId=upload))
        else:
            self.call('deny-publisher-abort-approved-upload', role, 'abort_multipart_upload', expect='deny',
                      **self.params(key, UploadId=upload))
        completed = self.call('complete-multipart-' + role, role, 'complete_multipart_upload',
            **self.params(key, UploadId=upload, MultipartUpload={'Parts': [{'PartNumber': 1, 'ETag': part['ETag']}]}))
        self.get(role, key, self.version(key, completed))

    def cleanup(self):
        errors = []
        for upload, (bucket, key) in list(self.uploads.items()):
            try:
                self.call('cleanup-own-upload', 'admin', 'abort_multipart_upload', **self.params(key, bucket, UploadId=upload))
            except Exception as exc:
                errors.append(error_details(exc))
        return errors


def run_checks(clients, journal, account, trace=None):
    trace = trace or Trace()
    c = Checks(clients, journal, account, trace)
    started_at = datetime.now(timezone.utc).isoformat()
    failure = None
    try:
        for role in ('writer', 'publisher'):
            def identity(value, r=role):
                p.require(value.get('Account') == account and value.get('Arn') ==
                    f"arn:aws:iam::{account}:user/{p.admin.plan()['users'][r]}"
                    and type(value.get('UserId')) is str and bool(value['UserId']), 'test credential identity differs')
                expected = clients.get('user_id_sha256', {}).get(r)
                p.require(expected is None or p.sha(value['UserId'].encode()) == expected, 'test credential user identity changed')
            c.call('identity-' + role, role + '_sts', 'get_caller_identity', check=identity)
        for bucket in BUCKETS:
            c.call('fresh-bucket-' + bucket, 'admin', 'head_bucket', expect='absent', **c.params(bucket=bucket))
        for bucket in BUCKETS:
            c.call('create-bucket-' + bucket, 'admin', 'create_bucket',
                   Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': 'ca-central-1'})
            c.call('enable-versioning-' + bucket, 'admin', 'put_bucket_versioning',
                   **c.params(bucket=bucket, VersioningConfiguration={'Status': 'Enabled'}))
            c.call('confirm-versioning-' + bucket, 'admin', 'get_bucket_versioning',
                   check=lambda v: p.require(v.get('Status') == 'Enabled', 'versioning not enabled'), **c.params(bucket=bucket))
        for marker in MARKERS:
            if marker != MARKER:
                c.put('admin', PREFIX + marker)
        c.put('admin', PREFIX + DATA)
        data_version = c.put('writer', PREFIX + DATA)
        for key in OUTSIDE:
            c.put('admin', key)
        c.put('admin', PREFIX + DATA, bucket=CONTROL_BUCKET)
        c.put('publisher', PREFIX + MARKER, IfNoneMatch='*')
        c.inventory()
        for role in ('writer', 'publisher'):
            c.call('read-versioning-' + role, role, 'get_bucket_versioning',
                   check=lambda v: p.require(v.get('Status') == 'Enabled', 'versioning not enabled'), **c.params())
            c.call('read-location-' + role, role, 'get_bucket_location',
                   check=lambda v: p.require(v.get('LocationConstraint') == 'ca-central-1', 'bucket location differs'), **c.params())
            for marker in MARKERS:
                c.get(role, PREFIX + marker, c.versions[PREFIX + marker][-1])
            c.lists(role, PREFIX if role == 'writer' else PREFIX + 'marker.manifest')
            for prefix in (None, '', *[key.rsplit('/', 1)[0] + '/' for key in OUTSIDE]):
                c.lists(role, prefix, 'deny')
            c.lists(role, PREFIX, 'deny', CONTROL_BUCKET)
            if role == 'publisher':
                c.lists(role, PREFIX, 'deny')
            for method in ('get_bucket_acl', 'get_bucket_policy', 'put_bucket_versioning'):
                c.call('deny-bucket-admin-' + role + '-' + method, role, method, expect='deny',
                    **c.params(**({'VersioningConfiguration': {'Status': 'Enabled'}} if method == 'put_bucket_versioning' else {})))
        for role in ('writer', 'publisher'):
            source = PREFIX + (DATA if role == 'writer' else MARKER)
            for marker in MARKERS:
                key = PREFIX + marker
                if role == 'writer' or marker != MARKER:
                    for method, extra in (('put_object', {'Body': PAYLOAD}),
                        ('copy_object', {'CopySource': {'Bucket': TEST_BUCKET, 'Key': source}}),
                        ('create_multipart_upload', {})):
                        c.call(f'deny-{role}-{marker}-{method}', role, method, expect='deny', **c.params(key, **extra))
                for extra in ({}, {'VersionId': c.versions[key][-1]}):
                    c.call(f'deny-{role}-{marker}-delete-{bool(extra)}', role, 'delete_object', expect='deny', **c.params(key, **extra))
            for bucket, key in ((CONTROL_BUCKET, PREFIX + DATA), *((TEST_BUCKET, k) for k in OUTSIDE)):
                for method, extra in (('get_object', {}), ('put_object', {'Body': PAYLOAD}), ('delete_object', {})):
                    c.call(f'deny-lateral-{role}-{bucket}-{key}-{method}', role, method, expect='deny', **c.params(key, bucket, **extra))
        for method, extra in (('get_object', {}), ('put_object', {'Body': PAYLOAD}),
            ('copy_object', {'CopySource': {'Bucket': TEST_BUCKET, 'Key': PREFIX + MARKER}}),
            ('delete_object', {}), ('create_multipart_upload', {})):
            c.call('deny-publisher-data-' + method, 'publisher', method, expect='deny', **c.params(PREFIX + DATA, **extra))
        c.call('deny-writer-delete-data-version', 'writer', 'delete_object', expect='deny',
               **c.params(PREFIX + DATA, VersionId=data_version))
        c.get('writer', PREFIX + DATA)
        for role, key, source in (('writer', DATA_KEYS['copy'], PREFIX + DATA),
                                   ('publisher', PREFIX + MARKER, PREFIX + 'marker.manifest')):
            response = c.call('copy-allowed-' + role, role, 'copy_object',
                             **c.params(key, CopySource={'Bucket': TEST_BUCKET, 'Key': source}))
            c.get(role, key, c.version(key, response))
        delete_version = c.put('writer', DATA_KEYS['delete'])
        c.call('writer-delete-current-data', 'writer', 'delete_object',
               check=lambda v: p.require(v.get('DeleteMarker') is True and opaque(v.get('VersionId')), 'missing delete marker'),
               **c.params(DATA_KEYS['delete']))
        c.get('admin', DATA_KEYS['delete'], delete_version)
        c.multipart('writer', DATA_KEYS['multipart'])
        c.multipart('publisher', PREFIX + MARKER)
        abort = c.call('writer-create-abortable-upload', 'writer', 'create_multipart_upload', **c.params(DATA_KEYS['abort']))
        c.call('writer-abort-data-upload', 'writer', 'abort_multipart_upload', **c.params(DATA_KEYS['abort'], UploadId=abort['UploadId']))
        key = PREFIX + 'CURRENT'
        upload = c.call('seed-protected-upload', 'admin', 'create_multipart_upload', **c.params(key))['UploadId']
        part = c.call('seed-protected-part', 'admin', 'upload_part', **c.params(key, UploadId=upload, PartNumber=1, Body=PAYLOAD))
        for role in ('writer', 'publisher'):
            source = PREFIX + (DATA if role == 'writer' else MARKER)
            for method, extra in (('upload_part', dict(PartNumber=1, Body=PAYLOAD)),
                ('upload_part_copy', dict(PartNumber=1, CopySource={'Bucket': TEST_BUCKET, 'Key': source})),
                ('complete_multipart_upload', dict(MultipartUpload={'Parts': [{'PartNumber': 1, 'ETag': part['ETag']}]})),
                ('abort_multipart_upload', {})):
                c.call('deny-protected-multipart-' + role + '-' + method, role, method, expect='deny', **c.params(key, UploadId=upload, **extra))
            c.call('protected-list-parts-' + role, role, 'list_parts', expect='ok' if role == 'writer' else 'deny', **c.params(key, UploadId=upload))
        # Multi-delete has per-object outcomes even when HTTP status is 200.
        for role in ('writer', 'publisher'):
            objects = [{'Key': PREFIX + 'CURRENT'}, {'Key': PREFIX + MARKER, 'VersionId': c.versions[PREFIX + MARKER][-1]}]
            def denied_rows(value, wanted=objects):
                rows = value.get('Errors', [])
                p.require(not value.get('Deleted') and len(rows) == len(wanted) and all(
                    any(row.get('Key') == item['Key'] and row.get('VersionId') == item.get('VersionId')
                        and row.get('Code') == 'AccessDenied' for row in rows) for item in wanted), 'bulk deletion was not denied per object')
            c.call('deny-bulk-marker-delete-' + role, role, 'delete_objects', expect='bulk_deny', check=denied_rows,
                   **c.params(Delete={'Objects': objects, 'Quiet': False}))
        c.call('late-writer-current-denial', 'writer', 'put_object', expect='deny', **c.params(PREFIX + 'CURRENT', Body=PAYLOAD))
        c.call('late-publisher-data-denial', 'publisher', 'put_object', expect='deny', **c.params(PREFIX + DATA, Body=PAYLOAD))
        for conditional in ({'IfNoneMatch': '*'}, {'IfMatch': '"00000000000000000000000000000000"'}):
            c.call('conditional-existing-marker-reject-' + next(iter(conditional)), 'publisher', 'put_object', expect='precondition',
                   **c.params(PREFIX + MARKER, Body=PAYLOAD, **conditional))
        c.put('publisher', PREFIX + MARKER, IfMatch=c.etags[PREFIX + MARKER])
        c.inventory()
        for bucket in BUCKETS:
            c.call('final-versioning-' + bucket, 'admin', 'get_bucket_versioning',
                   check=lambda v: p.require(v.get('Status') == 'Enabled', 'versioning changed'), **c.params(bucket=bucket))
        result = dict(result='PASS', checks=c.count, passed=c.passed, actual_s3_enforcement_proven=True,
                      scope='DISPOSABLE_BUCKETS_ONLY', buckets=list(BUCKETS), retained_objects=True,
                      conditional_publication_proven=True, explicit_denials=c.denials,
                      denial_observation_intervals_seconds={
                          'writer': c.observations['late-writer-current-denial'] - c.observations['deny-writer-CURRENT-put_object'],
                          'publisher': c.observations['late-publisher-data-denial'] - c.observations['deny-publisher-data-put_object']},
                      coverage_exclusions=['Wasabi custom MOVE', 'Wasabi compose', 'Wasabi append', 'production or clone resources'],
                      production_cutover_authorized=False)
    except Exception as exc:
        failure = (exc, trace.stage)
    cleanup_errors = c.cleanup()
    trace.cleanup_errors, trace.owned_uploads_remaining = cleanup_errors, len(c.uploads)
    if failure:
        trace.stage = failure[1]
        raise failure[0]
    p.require(not cleanup_errors, 'owned multipart upload cleanup unconfirmed')
    result.update(checks=c.count, passed=c.passed, owned_multipart_uploads_remaining=len(c.uploads))
    result.update(started_at_utc=started_at, completed_at_utc=datetime.now(timezone.utc).isoformat())
    return result


def run(mode, trace=None):
    trace = trace or Trace()
    p.require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LC_ALL='C', HOME='/nonexistent', AWS_EC2_METADATA_DISABLED='true')
    if not STATE.exists() and mode == 'status':
        return dict(result='NOT_STARTED', credentials='NOT_ACCESSED')
    with Journal() as journal:
        if journal.exists('result.json'):
            return journal.read('result.json')
        if mode == 'status':
            return dict(result='PENDING' if journal.exists('run.intent.json') else 'NOT_STARTED', credentials='NOT_ACCESSED')
        p.require(not journal.exists('run.intent.json'), 'acceptance already started; no mutation retries')
        clients, account = load_clients(trace)
        try:
            journal.write('run.intent.json', dict(schema=1, domain='rhea-gen14-live-iam-acceptance-v1',
                account=account, endpoint=p.S3_ENDPOINT, region='ca-central-1', buckets=list(BUCKETS),
                credential_plan_sha256=clients['credential_plan_sha256'], policy_sha256=p.POLICY_SHAS))
            try:
                result = run_checks(clients, journal, account, trace)
            except Exception as exc:
                result = dict(result='REFUSED', stage=trace.stage, actual_s3_enforcement_proven=False,
                              checks=getattr(trace, 'checks', 0), passed=getattr(trace, 'passed', 0),
                              explicit_denials=getattr(trace, 'denials', 0),
                              owned_multipart_uploads_remaining=getattr(trace, 'owned_uploads_remaining', 0),
                              cleanup_errors=getattr(trace, 'cleanup_errors', []), **error_details(exc))
                if type(exc) is p.Refusal:
                    result['reason'] = str(exc)
            journal.write('result.json', result)
            return result
        finally:
            for client in clients.get('closers', []):
                try:
                    client.close()
                except Exception:
                    pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('status', 'run'))
    args, trace = parser.parse_args(argv), Trace()
    try:
        result = run(args.mode, trace)
    except Exception as exc:
        result = dict(result='REFUSED', stage=trace.stage, actual_s3_enforcement_proven=False, **error_details(exc))
        if type(exc) is p.Refusal:
            result['reason'] = str(exc)
    print(json.dumps(result, sort_keys=True))
    return 2 if result['result'] == 'REFUSED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
