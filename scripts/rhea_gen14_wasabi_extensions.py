#!/usr/bin/env python3
"""One recorded MOVE/compose/append acceptance on fixed disposable buckets.

The original IAM policies are never edited. Raw custom requests use the existing
explicit-endpoint client's SigV4 signer and single-attempt HTTPS transport.
"""
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
from urllib.parse import quote
import xml.etree.ElementTree as ET

import rhea_gen14_create_iam_credentials as p
import rhea_gen14_live_iam_acceptance as acceptance

STATE = Path('/root/.local/share/rhea-gen14-wasabi-extensions-20261125')
BUCKETS = acceptance.BUCKETS
BUCKET = acceptance.TEST_BUCKET
PREFIX = acceptance.PREFIX
APPROVED = PREFIX + acceptance.MARKER
PROTECTED = frozenset(PREFIX + name for name in acceptance.MARKERS)
FIXTURE_PREFIX = PREFIX + 'wasabi-ext-20261125-'
FIXTURES = {name: FIXTURE_PREFIX + name + '.sst' for name in (
    'a', 'b', 'admin-append', 'admin-compose', 'admin-move-source', 'admin-move-dest',
    'writer-append', 'writer-compose', 'writer-move-source', 'writer-move-dest',
    'denied-move-source', 'denied-move-dest')}
OUTSIDE = 'other-project/wasabi-ext-20261125-outside.sst'
KEYS = PROTECTED | frozenset(FIXTURES.values()) | {OUTSIDE}
BASE = b'wasabi extension public fixture\n'
SECOND = b'wasabi extension second version\n'
APPEND = b'append\n'
MAX_BODY, MAX_XML, MAX_ROWS = 1024, 65536, 512
ERROR_CODES = acceptance.S3_CODES | frozenset((
    'BadDigest', 'BadRequest', 'IncompleteSignature', 'InvalidAction', 'InvalidDigest',
    'InvalidObjectState', 'MissingContentLength', 'MissingSecurityHeader',
    'AuthorizationQueryParametersError', 'SignatureDoesNotMatch', 'RequestTimeTooSkewed',
    'XAmzContentSHA256Mismatch'))
ORIGINAL_SNAPSHOT = '0043-admin-append-positive-before-snapshot.json'
ORIGINAL_SNAPSHOT_SHA = '7630439dc515d0269a59959c2924f346c844fab70c88605e8db1e55eeee7ca2a'
ORIGINAL_FAILURE_BODY_SHA = '3084292c927f88df1a55bd1a45bbb660e2e3e963ee080524f207f6a453ab9afa'
CHECKSUM_DIAGNOSTIC = dict(
    error_code='InvalidRequest', history_unchanged=True, http_status=400,
    message='Missing required header for this request: X-Amz-Content-Sha256',
    response_bytes=395,
    response_sha256='0b78fc105ff3b581fb4a1ab83602f3d4945597bedbef69aecb299b6f5f249197')


class Journal(p.Journal):
    def __init__(self, continuation=None):
        p.require(continuation in (None, 'checksum-corrected', 'append-reconciled'),
                  'invalid extension journal selection')
        self.path = STATE / continuation if continuation else STATE

    def __enter__(self):
        self.fd, self.lock = p.directory(self.path, create=True, private=True), None
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


class Trace:
    stage = 'validate_local_state'
    checks = 0
    denials = 0


def protected(key):
    if not key.startswith(PREFIX):
        return False
    tail = key[len(PREFIX):]
    return tail == 'CURRENT' or any(tail == stem or tail.startswith(stem + '.')
                                  for stem in ('marker.manifest', 'marker.format-version'))


def request_spec(operation, bucket, key, account, *, destination=None, components=(), data=b''):
    p.require(operation in ('move', 'compose', 'append') and bucket in BUCKETS
              and key in KEYS and re.fullmatch(r'[0-9]{12}', account), 'custom request outside fixed scope')
    p.require(type(data) is bytes and len(data) <= MAX_BODY, 'oversized extension payload')
    headers = {'x-amz-expected-bucket-owner': account}
    url = p.S3_ENDPOINT + '/' + bucket + '/' + quote(key, safe='/')
    if operation == 'move':
        p.require(destination in KEYS and destination != key and not components and not data,
                  'invalid exact-object MOVE')
        headers.update(Destination=destination, Overwrite='true',
                       **{'X-Wasabi-Prefix': 'false', 'X-Wasabi-Quiet': 'false'})
        return dict(method='MOVE', url=url, headers=headers, body=b'')
    p.require(destination is None, 'unexpected MOVE destination')
    if operation == 'compose':
        p.require(not data and type(components) is tuple and 0 < len(components) <= 2
                  and all(k in KEYS for k in components), 'invalid compose components')
        root = ET.Element('ComposeRequest')
        for component in components:
            ET.SubElement(ET.SubElement(root, 'Component'), 'Key').text = component
        data = ET.tostring(root, encoding='utf-8')
        p.require(len(data) <= MAX_BODY, 'oversized compose request')
        headers['Content-Type'] = 'text/xml'
    else:
        p.require(not components and bool(data), 'invalid append body')
        headers['Content-Type'] = 'application/octet-stream'
    return dict(method='PUT', url=url + '?' + operation, headers=headers, body=data)


def raw_request(client, spec):
    """No SDK operation-model edits, retries, redirects, logging, or secret export."""
    from botocore.awsrequest import AWSRequest
    raw = client.client if isinstance(client, acceptance.ConditionalS3) else client
    p.require(raw.meta.endpoint_url == p.S3_ENDPOINT, 'unexpected extension endpoint')
    allowed = {p.S3_ENDPOINT + '/' + bucket + '/' + quote(key, safe='/') + suffix
               for bucket in BUCKETS for key in KEYS for suffix in ('', '?compose', '?append')}
    p.require(spec['url'] in allowed and spec['method'] in ('MOVE', 'PUT'), 'raw request outside fixed scope')
    p.require(type(spec['body']) is bytes and len(spec['body']) <= MAX_BODY, 'invalid signed request payload')
    headers = {key: value for key, value in spec['headers'].items() if key.lower() != 'x-amz-content-sha256'}
    headers['X-Amz-Content-Sha256'] = p.sha(spec['body'])
    request = AWSRequest(method=spec['method'], url=spec['url'], data=spec['body'],
                         headers=headers, stream_output=True)
    raw._request_signer.sign('PutObject', request, region_name='ca-central-1', signing_name='s3')
    prepared = request.prepare()
    p.require(prepared.url == spec['url'] and prepared.method == spec['method'], 'signed request scope changed')
    response = raw._endpoint.http_session.send(prepared)
    try:
        body = response.raw.read(MAX_XML + 1)
        p.require(type(body) is bytes and len(body) <= MAX_XML, 'oversized extension response')
        return response.status_code, dict(response.headers), body
    finally:
        response.raw.close()


def xml_result(status, headers, body, operation, expected, source, destination=None):
    p.require(type(status) is int and type(body) is bytes and len(body) <= MAX_XML,
              'invalid extension response')
    p.require(b'<!DOCTYPE' not in body.upper() and b'<!ENTITY' not in body.upper(), 'unsafe XML response')
    root = ET.fromstring(body) if body.strip() else None
    if root is not None:
        for element in root.iter():
            element.tag = element.tag.rsplit('}', 1)[-1]
    codes = [e.text for e in root.iter('Code')] if root is not None else []
    errors = list(root.iter('Error')) if root is not None else []
    if expected == 'deny':
        explicit = status == 403 and root is not None and root.tag == 'Error' and codes == ['AccessDenied']
        # MOVE may report per-object failure with HTTP 200. Do not accept a
        # mixed-success response or an undocumented empty/no-op result.
        per_object = (operation == 'move' and status == 200 and root is not None
                      and root.tag == 'MoveObjectResult' and bool(errors)
                      and all(e.findtext('Code') == 'AccessDenied' for e in errors)
                      and not list(root.iter('MoveObject')) and root.findtext('MoveCount') in (None, '0'))
        p.require(explicit or per_object, 'custom operation was not explicitly denied')
    else:
        empty_put = status == 204 and operation in ('append', 'compose') and body == b''
        p.require(expected == 'ok' and (status == 200 or empty_put) and not codes and not errors,
                  'custom positive control failed')
        if operation == 'move':
            p.require(root is not None and root.tag == 'MoveObjectResult', 'unexpected MOVE result')
            sources = [e.text for e in root.iter('SourceKey')]
            destinations = [e.text for e in root.iter('DestinationKey')]
            p.require(bool(sources) and len(sources) == len(destinations)
                      and set(sources) == {source} and set(destinations) == {destination},
                      'MOVE response scope differs')
    request_id = next((v for k, v in headers.items() if k.lower() == 'x-amz-request-id'), None)
    return dict(http_status=status, response_sha256=p.sha(body), response_bytes=len(body),
                request_id=request_id if type(request_id) is str
                and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', request_id) else None,
                error_code='AccessDenied' if expected == 'deny' else None,
                xml_root=root.tag if root is not None and root.tag in ('Error', 'MoveObjectResult',
                'PutObjectResult', 'ComposeObjectResult', 'AppendObjectResult') else None)


def response_evidence(status, headers, body):
    """Retain diagnostics even for a rejected response, without its raw content."""
    request_id = next((v for k, v in headers.items() if k.lower() == 'x-amz-request-id'), None)
    codes = []
    if len(body) <= MAX_XML and b'<!DOCTYPE' not in body.upper() and b'<!ENTITY' not in body.upper():
        try:
            root = ET.fromstring(body)
            codes = [element.text for element in root.iter() if element.tag.rsplit('}', 1)[-1] == 'Code']
        except ET.ParseError:
            pass
    code = codes[0] if codes and len(set(codes)) == 1 and codes[0] in ERROR_CODES else None
    return dict(http_status=status if type(status) is int else None,
                response_sha256=p.sha(body), response_bytes=len(body),
                error_code=code,
                request_id=request_id if type(request_id) is str
                and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', request_id) else None)


class Checks:
    def __init__(self, clients, account, journal, trace, transport=raw_request):
        self.clients, self.account, self.journal, self.trace = clients, account, journal, trace
        self.transport, self.index, self.denials, self.body_cache = transport, 0, 0, {}

    def record(self, case, role, operation, parameters, fn):
        self.trace.stage = case
        i, self.index = self.index, self.index + 1
        intent = dict(sequence=i, case=case, role=role, operation=operation, parameters=parameters,
                      started_at_utc=datetime.now(timezone.utc).isoformat())
        self.journal.write(f'{i:04d}.intent.json', intent)
        try:
            result, evidence = fn()
        except Exception as exc:
            self.journal.write(f'{i:04d}.receipt.json', dict(result='FAIL',
                intent_sha256=p.admin.iam.digest(intent),
                evidence=getattr(exc, 'extension_response', None),
                completed_at_utc=datetime.now(timezone.utc).isoformat(),
                **acceptance.error_details(exc)))
            raise
        self.journal.write(f'{i:04d}.receipt.json', dict(result='PASS',
            intent_sha256=p.admin.iam.digest(intent), evidence=evidence,
            completed_at_utc=datetime.now(timezone.utc).isoformat()))
        self.trace.checks = self.index
        return result

    def sdk(self, case, role, operation, *, key=None, bucket=BUCKET, body=None, **extra):
        p.require(bucket in BUCKETS and (key is None or key in KEYS or protected(key)), 'SDK fixture scope differs')
        p.require(body is None or type(body) is bytes and len(body) <= MAX_BODY, 'SDK fixture body too large')
        params = dict(Bucket=bucket, ExpectedBucketOwner=self.account, **extra)
        if key is not None:
            params['Key'] = key
        if body is not None:
            params['Body'] = body
        def invoke():
            value = getattr(self.clients[role], operation)(**params)
            p.response_ok(value)
            if operation == 'get_object':
                stream = value['Body']
                try:
                    content = stream.read(MAX_BODY + 1)
                    p.require(len(content) <= MAX_BODY and value.get('VersionId') == extra.get('VersionId'),
                              'version-addressed body differs')
                    value = {**value, 'Body': content}
                finally:
                    stream.close()
            evidence = dict(version_id=value.get('VersionId'),
                            request_id=value.get('ResponseMetadata', {}).get('RequestId'))
            return value, evidence
        return self.record(case, role, operation, {k: v for k, v in params.items() if k != 'Body'}, invoke)

    def custom(self, case, role, operation, key, *, expected='ok', bucket=BUCKET, **options):
        spec = request_spec(operation, bucket, key, self.account, **options)
        before = self.snapshot(case + '-before')
        def invoke():
            status, headers, body = self.transport(self.clients[role], spec)
            try:
                evidence = xml_result(status, headers, body, operation, expected, key, options.get('destination'))
            except Exception as exc:
                exc.extension_response = response_evidence(status, headers, body)
                raise
            return evidence, evidence
        self.record(case, role, operation, dict(bucket=bucket, key=key, expected=expected,
                    **{k: (p.sha(v) if type(v) is bytes else v) for k, v in options.items()}), invoke)
        after = self.snapshot(case + '-after')
        if expected == 'deny':
            p.require(after == before, 'denied extension changed object/version history')
            self.denials += 1
            self.trace.denials = self.denials
        return before, after

    def snapshot(self, case, *, refresh=False):
        result = {}
        for bucket in BUCKETS:
            value = self.sdk(case + '-versions-' + bucket, 'admin', 'list_object_versions', bucket=bucket, MaxKeys=1000)
            p.require(value.get('IsTruncated', False) is False, 'extension history truncated')
            p.require(all(type(value.get(k, [])) is list for k in ('Versions', 'DeleteMarkers'))
                      and sum(len(value.get(k, [])) for k in ('Versions', 'DeleteMarkers')) <= MAX_ROWS,
                      'extension version inventory too large or malformed')
            rows = []
            for kind in ('Versions', 'DeleteMarkers'):
                p.require(type(value.get(kind, [])) is list, 'invalid version inventory')
                for row in value.get(kind, []):
                    key, version = row.get('Key'), row.get('VersionId')
                    p.require(type(key) is str and acceptance.opaque(version) and type(row.get('IsLatest')) is bool,
                              'invalid object version identity')
                    item = dict(key=key, version=version, latest=row['IsLatest'], delete=kind == 'DeleteMarkers')
                    if kind == 'Versions':
                        p.require(type(row.get('Size')) is int and row['Size'] >= 0
                                  and acceptance.opaque(row.get('ETag')), 'invalid version size or ETag')
                        item.update(size=row.get('Size'), etag=row.get('ETag'))
                        if key in KEYS or protected(key):
                            cache_key = (bucket, key, version, row.get('ETag'), row.get('Size'))
                            if refresh or cache_key not in self.body_cache:
                                fetched = self.sdk(case + '-body', 'admin', 'get_object', key=key, bucket=bucket, VersionId=version)
                                p.require(len(fetched['Body']) == row.get('Size') and fetched.get('ETag') == row.get('ETag'),
                                          'object body disagrees with version listing')
                                self.body_cache[cache_key] = p.sha(fetched['Body'])
                            item['sha256'] = self.body_cache[cache_key]
                    rows.append(item)
            p.require(len(rows) <= MAX_ROWS, 'extension version inventory too large')
            result[bucket] = sorted(rows, key=lambda row: (row['key'], row['version'], row['delete']))
        self.journal.write(f'{self.index:04d}-{case}-snapshot.json', result)
        return result

    def seed(self, name, *, bucket=BUCKET, body=BASE):
        key = FIXTURES[name] if name in FIXTURES else name
        value = self.sdk('seed-' + name, 'admin', 'put_object', key=key, bucket=bucket, body=body)
        p.require(acceptance.opaque(value.get('VersionId')), 'fixture creation omitted version ID')


def same_except(before, after, bucket, keys):
    trim = lambda value: {b: [row for row in rows if b != bucket or row['key'] not in keys]
                          for b, rows in value.items()}
    p.require(trim(before) == trim(after), 'custom positive changed unrelated history')


def added_version(before, after, bucket, key, body):
    same_except(before, after, bucket, {key})
    old = [r for r in before[bucket] if r['key'] == key]
    new = [r for r in after[bucket] if r['key'] == key]
    ids = {r['version'] for r in old}
    added = [r for r in new if r['version'] not in ids]
    p.require(len(new) == len(old) + 1 and len(added) == 1 and added[0]['latest']
              and not added[0]['delete'] and added[0].get('sha256') == p.sha(body)
              and all(dict(r, latest=False) in new for r in old), 'custom publication version/body differs')


def moved_versions(before, after, bucket, source, destination):
    same_except(before, after, bucket, {source, destination})
    old = [r for r in before[bucket] if r['key'] == source]
    new = [r for r in after[bucket] if r['key'] == destination]
    p.require(old and not any(r['key'] == destination for r in before[bucket])
              and not any(r['key'] == source for r in after[bucket]) and len(old) == len(new)
              and all(not r['delete'] for r in old + new)
              and sorted((r['sha256'], r['latest']) for r in old) == sorted((r['sha256'], r['latest']) for r in new),
              'MOVE did not move exactly the recorded versions')


def run_checks(clients, account, journal, trace=None, transport=raw_request, *,
               reconciled_snapshot=None, adopt_admin_append=False):
    trace = trace or Trace()
    c = Checks(clients, account, journal, trace, transport)
    for role in ('writer', 'publisher'):
        def identity(r=role):
            value = clients[r + '_sts'].get_caller_identity()
            p.response_ok(value)
            p.require(value.get('Account') == account and value.get('Arn') ==
                      f"arn:aws:iam::{account}:user/{p.admin.plan()['users'][r]}"
                      and type(value.get('UserId')) is str
                      and p.sha(value['UserId'].encode()) == clients['user_id_sha256'][r],
                      'extension signing identity differs')
            return None, dict(identity_verified=True)
        c.record('identify-' + role, role + '_sts', 'get_caller_identity', {}, identity)
    before = c.snapshot('initial', refresh=True)
    if adopt_admin_append:
        trace.stage = 'reconcile-admin-append'
        p.require(reconciled_snapshot is not None, 'missing pre-append history')
        added_version(reconciled_snapshot, before, BUCKET, FIXTURES['admin-append'], BASE + APPEND)
        journal.write('admin-append-reconciliation.json', dict(
            result='APPLIED_ONCE', case='admin-append-positive',
            before_sha256=p.sha(p.canonical(reconciled_snapshot)), after_sha256=p.sha(p.canonical(before))))
    elif reconciled_snapshot is None:
        p.require(all(not row['key'].startswith(FIXTURE_PREFIX) and row['key'] != OUTSIDE
                      for rows in before.values() for row in rows), 'extension fixtures already exist; no replay')
    else:
        p.require(type(reconciled_snapshot) is dict and set(reconciled_snapshot) == set(BUCKETS)
                  and before == reconciled_snapshot, 'checksum continuation history differs from original baseline')
    for bucket in BUCKETS:
        versioning = c.sdk('versioning-initial', 'admin', 'get_bucket_versioning', bucket=bucket)
        p.require(versioning.get('Status') == 'Enabled', 'versioning must remain enabled')
    p.require(PROTECTED <= {row['key'] for row in before[BUCKET] if not row['delete'] and row['latest']},
              'accepted marker fixtures missing')
    if reconciled_snapshot is None:
        for name in ('a', 'b', 'admin-append', 'writer-append', 'admin-move-source',
                     'writer-move-source', 'denied-move-source'):
            c.seed(name)
        for name in ('admin-move-source', 'writer-move-source'):
            c.seed(name, body=SECOND)
        c.seed(OUTSIDE)
        for name in ('a', 'b', 'denied-move-source'):
            c.seed(name, bucket=BUCKETS[1])

    # Positive controls prove custom requests are syntactically valid under
    # admin and writer before a 403 can be counted as a policy denial.
    for role in ('admin', 'writer'):
        if role != 'admin' or not adopt_admin_append:
            key = FIXTURES[role + '-append']
            old, new = c.custom(role + '-append-positive', role, 'append', key, data=APPEND)
            added_version(old, new, BUCKET, key, BASE + APPEND)
        key = FIXTURES[role + '-compose']
        old, new = c.custom(role + '-compose-positive', role, 'compose', key,
                            components=(FIXTURES['a'], FIXTURES['b']))
        added_version(old, new, BUCKET, key, BASE + BASE)
        source, destination = FIXTURES[role + '-move-source'], FIXTURES[role + '-move-dest']
        old, new = c.custom(role + '-move-positive', role, 'move', source, destination=destination)
        moved_versions(old, new, BUCKET, source, destination)

    for key in sorted(PROTECTED):
        for operation, options in (('append', dict(data=APPEND)),
                                   ('compose', dict(components=(FIXTURES['a'], FIXTURES['b'])))):
            c.custom('deny-writer-' + operation + '-' + key.rsplit('/', 1)[-1], 'writer', operation,
                     key, expected='deny', **options)
        c.custom('deny-writer-move-destination-' + key.rsplit('/', 1)[-1], 'writer', 'move',
                 FIXTURES['denied-move-source'], destination=key, expected='deny')
        c.custom('deny-writer-move-source-' + key.rsplit('/', 1)[-1], 'writer', 'move',
                 key, destination=FIXTURES['denied-move-dest'], expected='deny')
    for key in sorted((PROTECTED - {APPROVED}) | {FIXTURES['a']}):
        for operation, options in (('append', dict(data=APPEND)),
                                   ('compose', dict(components=(PREFIX + 'marker.manifest',)))):
            c.custom('deny-publisher-' + operation + '-' + key.rsplit('/', 1)[-1], 'publisher', operation,
                     key, expected='deny', **options)
    c.custom('deny-publisher-compose-data-source', 'publisher', 'compose', APPROVED,
             components=(FIXTURES['a'],), expected='deny')
    c.custom('deny-publisher-move-source', 'publisher', 'move', PREFIX + 'CURRENT',
             destination=APPROVED, expected='deny')
    c.custom('deny-publisher-move-destination', 'publisher', 'move', APPROVED,
             destination=FIXTURES['denied-move-dest'], expected='deny')
    for role in ('writer', 'publisher'):
        for bucket, key in ((BUCKET, OUTSIDE), (BUCKETS[1], FIXTURES['a'])):
            c.custom('deny-' + role + '-append-lateral-' + bucket, role, 'append', key,
                     bucket=bucket, data=APPEND, expected='deny')
            components = (FIXTURES['a'],) if role == 'writer' or bucket != BUCKET else (PREFIX + 'CURRENT',)
            c.custom('deny-' + role + '-compose-lateral-' + bucket, role, 'compose', key,
                     bucket=bucket, components=components, expected='deny')
        c.custom('deny-' + role + '-move-outside', role, 'move',
                 FIXTURES['denied-move-source'] if role == 'writer' else APPROVED,
                 destination=OUTSIDE, expected='deny')

    # Publisher positive append and compose preserve all prior marker versions.
    current = next(row for row in c.snapshot('publisher-positive-baseline')[BUCKET]
                   if row['key'] == APPROVED and row['latest'] and not row['delete'])
    body = c.sdk('read-publisher-append-base', 'admin', 'get_object', key=APPROVED,
                 VersionId=current['version'])['Body']
    p.require(len(body + APPEND) <= MAX_BODY, 'publisher append would exceed fixture bound')
    old, new = c.custom('publisher-append-positive', 'publisher', 'append', APPROVED, data=APPEND)
    added_version(old, new, BUCKET, APPROVED, body + APPEND)
    source = PREFIX + 'marker.manifest'
    current = next(row for row in new[BUCKET] if row['key'] == source and row['latest'] and not row['delete'])
    body = c.sdk('read-publisher-compose-base', 'admin', 'get_object', key=source,
                 VersionId=current['version'])['Body']
    old, new = c.custom('publisher-compose-positive', 'publisher', 'compose', APPROVED, components=(source,))
    added_version(old, new, BUCKET, APPROVED, body)
    p.require(c.snapshot('final-full-body-proof', refresh=True) == new, 'final version/body proof changed')
    for bucket in BUCKETS:
        value = c.sdk('versioning-final', 'admin', 'get_bucket_versioning', bucket=bucket)
        p.require(value.get('Status') == 'Enabled', 'versioning changed')
    return dict(result='PASS', scope='FIXED_DISPOSABLE_BUCKETS_ONLY', checks=c.index,
                explicit_denials=c.denials, extension_operations=['MOVE', 'compose', 'append'],
                protected_history_verified=True, source_and_destination_move_denials_verified=True,
                production_cutover_authorized=False, retained_objects=True,
                coverage_exclusions=['MOVE with X-Wasabi-Prefix:true', 'cross-bucket compose (unsupported by Wasabi)',
                                     'production or full-clone resources'])


def checksum_resume_evidence(original):
    """Authorize only the reviewed, unchanged first-append checksum failure."""
    raw_result = original.raw('result.json')
    result = p.admin.iam.parse(raw_result)
    response = result.get('extension_response', {})
    p.require(result.get('result') == 'REFUSED' and result.get('stage') == 'admin-append-positive'
              and result.get('checks') == 43 and result.get('explicit_denials') == 0
              and type(response) is dict and response.get('http_status') == 400
              and response.get('response_bytes') == 395
              and response.get('response_sha256') == ORIGINAL_FAILURE_BODY_SHA,
              'original failure is not the reviewed checksum failure')
    raw_diagnostic = original.raw('diagnostic-result.json')
    diagnostic = p.admin.iam.parse(raw_diagnostic)
    p.require(diagnostic == CHECKSUM_DIAGNOSTIC and raw_diagnostic == p.canonical(CHECKSUM_DIAGNOSTIC),
              'checksum diagnostic is missing, changed, or does not prove unchanged history')
    raw_before = original.raw(ORIGINAL_SNAPSHOT)
    p.require(p.sha(raw_before) == ORIGINAL_SNAPSHOT_SHA, 'original before-snapshot changed')
    before = p.admin.iam.parse(raw_before)
    p.require(set(before) == set(BUCKETS) and all(type(rows) is list for rows in before.values()),
              'original before-snapshot scope differs')
    source_run = original.read('run.intent.json')
    p.require(source_run.get('schema') == 1 and source_run.get('domain') == 'rhea-wasabi-extensions-v1'
              and source_run.get('endpoint') == p.S3_ENDPOINT and source_run.get('buckets') == list(BUCKETS)
              and source_run.get('policy_sha256') == p.POLICY_SHAS,
              'original extension run binding differs')
    failed_intent = original.read('0043.intent.json')
    p.require(failed_intent.get('sequence') == 43 and failed_intent.get('case') == 'admin-append-positive'
              and failed_intent.get('role') == 'admin' and failed_intent.get('operation') == 'append'
              and failed_intent.get('parameters') == dict(bucket=BUCKET, key=FIXTURES['admin-append'],
                                                          expected='ok', data=p.sha(APPEND)),
              'original failed request is not the reviewed append')
    failed_receipt = original.read('0043.receipt.json')
    p.require(failed_receipt.get('result') == 'FAIL'
              and failed_receipt.get('intent_sha256') == p.admin.iam.digest(failed_intent)
              and failed_receipt.get('evidence') == response, 'original failed request receipt differs')
    provenance = dict(original_result_sha256=p.sha(raw_result),
                      diagnostic_result_sha256=p.sha(raw_diagnostic),
                      original_before_snapshot_sha256=p.sha(raw_before),
                      original_run_sha256=p.admin.iam.digest(source_run),
                      original_failed_intent_sha256=p.admin.iam.digest(failed_intent),
                      original_failed_receipt_sha256=p.admin.iam.digest(failed_receipt))
    return before, source_run, provenance


def confirmed_append_evidence(checksum, before, source_run, provenance):
    """Bind the observed 204 to the intended append before inspecting the live versions."""
    binding = checksum.read('run.intent.json')
    expected = dict(source_run, domain='rhea-wasabi-extensions-checksum-corrected-v1',
                    corrected_header='X-Amz-Content-Sha256', source_evidence=provenance)
    p.require(binding == expected, 'checksum run binding differs')
    result = checksum.read('result.json')
    response = result.get('extension_response', {})
    p.require(result.get('result') == 'REFUSED' and result.get('continuation') == 'checksum-corrected'
              and result.get('source_evidence') == provenance and result.get('stage') == 'admin-append-positive'
              and result.get('reason') == 'custom positive control failed' and result.get('checks') == 30
              and result.get('explicit_denials') == 0 and type(response) is dict and response.get('http_status') == 204
              and response.get('response_bytes') == 0 and response.get('response_sha256') == p.sha(b'')
              and response.get('error_code') is None, 'checksum run did not stop on the empty 204 append')
    intent = checksum.read('0030.intent.json')
    receipt = checksum.read('0030.receipt.json')
    p.require(intent.get('case') == 'admin-append-positive' and intent.get('role') == 'admin'
              and intent.get('sequence') == 30 and intent.get('operation') == 'append'
              and intent.get('parameters') == dict(bucket=BUCKET, key=FIXTURES['admin-append'],
                                                    data=p.sha(APPEND), expected='ok')
              and receipt.get('result') == 'FAIL' and receipt.get('intent_sha256') == p.admin.iam.digest(intent)
              and receipt.get('evidence') == response and not checksum.exists('0031.intent.json')
              and checksum.read('0030-admin-append-positive-before-snapshot.json') == before,
              'checksum append intent, receipt or baseline differs')
    return dict(provenance, checksum_result_sha256=p.sha(checksum.raw('result.json')),
                checksum_run_sha256=p.admin.iam.digest(binding), append_intent_sha256=p.admin.iam.digest(intent),
                append_receipt_sha256=p.admin.iam.digest(receipt))


def continue_checks(mode, trace):
    """Continue in a new journal only from a reconciled predecessor."""
    adopt_append = mode in ('resume-append', 'status-append')
    name = 'append-reconciled' if adopt_append else 'checksum-corrected'
    if mode.startswith('status-'):
        if not (STATE / name).exists():
            return dict(result='NOT_STARTED', continuation=name, credentials='NOT_ACCESSED')
        with Journal(name) as journal:
            if journal.exists('result.json'):
                return journal.read('result.json')
            return dict(result='PENDING' if journal.exists('run.intent.json') else 'NOT_STARTED',
                        continuation=name, credentials='NOT_ACCESSED')
    p.require(STATE.is_dir(), 'original extension journal is missing')
    with Journal() as original, ExitStack() as parents:
        trace.stage = 'validate_checksum_resume_evidence'
        before, source_run, provenance = checksum_resume_evidence(original)
        if adopt_append:
            trace.stage = 'validate_append_receipt'
            p.require((STATE / 'checksum-corrected').is_dir(), 'checksum journal is missing')
            checksum = parents.enter_context(Journal('checksum-corrected'))
            provenance = confirmed_append_evidence(checksum, before, source_run, provenance)
        with Journal(name) as journal:
            if journal.exists('result.json'):
                return journal.read('result.json')
            p.require(not journal.exists('run.intent.json'), 'continuation already started; no retries')
            clients, account = acceptance.load_clients(trace)
            try:
                p.require(source_run.get('account') == account
                          and source_run.get('credential_plan_sha256') == clients['credential_plan_sha256'],
                          'checksum continuation credential binding differs')
                journal.write('run.intent.json', dict(
                    schema=1, domain='rhea-wasabi-extensions-' + name + '-v1',
                    account=account, endpoint=p.S3_ENDPOINT, buckets=list(BUCKETS),
                    credential_plan_sha256=clients['credential_plan_sha256'], policy_sha256=p.POLICY_SHAS,
                    corrected_header='X-Amz-Content-Sha256', source_evidence=provenance))
                try:
                    result = run_checks(clients, account, journal, trace, reconciled_snapshot=before,
                                        adopt_admin_append=adopt_append)
                except Exception as exc:
                    result = dict(result='REFUSED', stage=trace.stage, checks=trace.checks,
                                  explicit_denials=trace.denials, **acceptance.error_details(exc))
                    if getattr(exc, 'extension_response', None) is not None:
                        result['extension_response'] = exc.extension_response
                    if type(exc) is p.Refusal:
                        result['reason'] = str(exc)
                result.update(continuation=name, source_evidence=provenance)
                journal.write('result.json', result)
                return result
            finally:
                for client in clients.get('closers', []):
                    try:
                        client.close()
                    except Exception:
                        pass


def run(mode, trace=None):
    trace = trace or Trace()
    p.require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LC_ALL='C', HOME='/nonexistent', AWS_EC2_METADATA_DISABLED='true')
    if mode in ('resume-checksum', 'status-checksum', 'resume-append', 'status-append'):
        return continue_checks(mode, trace)
    if mode == 'status' and not STATE.exists():
        return dict(result='NOT_STARTED', credentials='NOT_ACCESSED')
    with Journal() as journal:
        if journal.exists('result.json'):
            return journal.read('result.json')
        if mode == 'status':
            return dict(result='PENDING' if journal.exists('run.intent.json') else 'NOT_STARTED', credentials='NOT_ACCESSED')
        p.require(not journal.exists('run.intent.json'), 'extension run already started; no retries')
        clients, account = acceptance.load_clients(trace)
        try:
            journal.write('run.intent.json', dict(schema=1, domain='rhea-wasabi-extensions-v1',
                account=account, endpoint=p.S3_ENDPOINT, buckets=list(BUCKETS),
                credential_plan_sha256=clients['credential_plan_sha256'], policy_sha256=p.POLICY_SHAS))
            try:
                result = run_checks(clients, account, journal, trace)
            except Exception as exc:
                result = dict(result='REFUSED', stage=trace.stage, checks=trace.checks,
                              explicit_denials=trace.denials, **acceptance.error_details(exc))
                if getattr(exc, 'extension_response', None) is not None:
                    result['extension_response'] = exc.extension_response
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
    parser.add_argument('mode', choices=('status', 'run', 'resume-checksum', 'status-checksum',
                                         'resume-append', 'status-append'))
    args, trace = parser.parse_args(argv), Trace()
    try:
        result = run(args.mode, trace)
    except Exception as exc:
        result = dict(result='REFUSED', stage=trace.stage, **acceptance.error_details(exc))
        if type(exc) is p.Refusal:
            result['reason'] = str(exc)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] != 'REFUSED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
