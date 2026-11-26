"""Test conditional versioned deletion on one empty, disposable ordinary object on Wasabi."""
import fcntl
import json
import logging
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

INSTALL = Path('/root/.local/share/rhea-gen14-signed-handoff-20261127')
if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('root required for the fixed test credential store')
    sys.path.insert(0, str(INSTALL))

import rhea_gen14_rclone_rehearsal as rehearsal

p = rehearsal.p
BUCKET = 'rhea-gen14-iam-test-20261111-48be1ecd7cc848fb'
KEY = 'rhea/pebbleds/retirement-signed-if-match-20261127.sst'
STATE = Path('/root/.local/share/rhea-gen14-marker-retirement-wire-20261127')
EMPTY_ETAG = '"d41d8cd98f00b204e9800998ecf8427e"'


def history(client, params):
    reply = client.list_object_versions(**params, Prefix=KEY, MaxKeys=32)
    p.response_ok(reply)
    p.require(reply['IsTruncated'] is False, 'incomplete fixture history')
    rows = []
    for field, deleted in [('Versions', False), ('DeleteMarkers', True)]:
        for row in reply.get(field, []):
            p.require(row['Key'] == KEY and row['VersionId'] and row['VersionId'] != 'null', 'unexpected version')
            rows.append(dict(version=row['VersionId'], deleted=deleted, latest=row['IsLatest'], etag=row.get('ETag')))
    return rows


def conditional(client, method, params, header, condition):
    from botocore.exceptions import ClientError
    operation = 'PutObject' if method == 'put_object' else 'DeleteObject'
    event = 'before-sign.s3.' + operation
    wire_event = 'before-send.s3.' + operation
    observed = []
    def witness(request, **kwargs):
        url = urlsplit(request.url)
        value = request.headers.get(header)
        auth = request.headers.get('Authorization', b'')
        if isinstance(auth, bytes):
            auth = auth.decode('ascii')
        if isinstance(value, bytes):
            value = value.decode('ascii')
        signed = auth.partition('SignedHeaders=')[2].partition(',')[0].split(';')
        p.require(not observed and url.scheme == 'https' and url.netloc == urlsplit(p.S3_ENDPOINT).netloc
                  and url.path == '/' + BUCKET + '/' + KEY and not url.query
                  and value == condition and header.lower() in signed, 'signed wire condition or target differs')
        observed.append(True)
    def bind(request, **kwargs):
        request.headers[header] = condition
    client.meta.events.register(event, bind, unique_id='exact-retirement-fixture')
    client.meta.events.register(wire_event, witness, unique_id='verify-signed-fixture')
    try:
        reply = getattr(client, method)(**params, Key=KEY, **({'Body': b''} if method == 'put_object' else {}))
        p.require(observed == [True], 'missing signed request observation')
        return dict(signed_header=header, http=reply['ResponseMetadata']['HTTPStatusCode'], version=reply.get('VersionId'),
                    tombstone=reply.get('DeleteMarker', False), etag=reply.get('ETag'))
    except ClientError as exc:
        p.require(observed == [True], 'missing signed request observation')
        return dict(signed_header=header, http=exc.response['ResponseMetadata']['HTTPStatusCode'], code=exc.response['Error']['Code'])
    finally:
        client.meta.events.unregister(event, unique_id='exact-retirement-fixture')
        client.meta.events.unregister(wire_event, unique_id='verify-signed-fixture')


def run():
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    p.require(BUCKET == p.admin.TEST_BUCKET and KEY.startswith(p.admin.PREFIX) and KEY.endswith('.sst'),
              'fixed disposable fixture scope differs')
    fd = p.directory(STATE, create=True, private=True)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def write(name, value):
            rehearsal.private_write(STATE / (name + '.json'), p.canonical(value))
        if (STATE / 'result.json').exists():
            return p.admin.iam.parse(p.read_private(fd, 'result.json'))
        p.require(not os.listdir(fd), 'unresolved fixture intent; inspect object history')
        saved, cloud, binding = rehearsal.load_context()
        client = rehearsal.s3_client(saved['AccessKeyId'], saved['SecretAccessKey'])
        try:
            params = {'Bucket': BUCKET, 'ExpectedBucketOwner': cloud.account}
            enabled = cloud.admin.get_bucket_versioning(**params)
            p.response_ok(enabled)
            p.require(enabled['Status'] == 'Enabled' and history(cloud.admin, params) == [], 'fixture already used')
            write('01-create-intent', dict(bucket=BUCKET, key=KEY, condition='If-None-Match: *', binding=binding))
            created = conditional(client, 'put_object', params, 'If-None-Match', '*')
            write('02-created', created)
            p.require(created['http'] == 200 and created['etag'] == EMPTY_ETAG and created['version'], 'empty create failed')
            old = dict(version=created['version'], latest=True, deleted=False, etag=EMPTY_ETAG)
            p.require(history(cloud.admin, params) == [old], 'create history differs')
            write('03-stale-delete-intent', dict(expected_version=old['version'], etag='"00000000000000000000000000000000"'))
            wrong = conditional(client, 'delete_object', params, 'If-Match', '"00000000000000000000000000000000"')
            write('04-stale-delete-response', wrong)
            records = history(cloud.admin, params)
            if wrong.get('http') == 412 and wrong.get('code') == 'PreconditionFailed':
                p.require(records == [old], 'rejected conditional delete changed history')
                write('05-matching-delete-intent', dict(expected_version=old['version'], etag=EMPTY_ETAG))
                deleted = conditional(client, 'delete_object', params, 'If-Match', EMPTY_ETAG)
                write('06-matching-delete-response', deleted)
                result = 'MATCH_ENFORCED'
            elif wrong.get('http') == 204:
                deleted = wrong
                result = 'STALE_ETAG_ACCEPTED'
            else:
                p.require(records == [old], 'unexpected conditional response changed the fixture')
                deleted = None
                result = 'CONDITIONAL_DELETE_UNPROVEN'
            rows = history(cloud.admin, params)
            if deleted is not None:
                p.require(deleted.get('http') == 204 and deleted.get('tombstone') is True and deleted.get('version')
                          and rows == [dict(old, latest=False), dict(version=deleted['version'], deleted=True,
                          latest=True, etag=None)], 'exactly one version-preserving tombstone required')
            response = cloud.admin.get_object(**params, Key=KEY, VersionId=old['version'])
            try:
                p.response_ok(response)
                p.require(response['ETag'] == EMPTY_ETAG and response['Body'].read(1) == b'', 'historical body changed')
            finally:
                response['Body'].close()
            report = dict(result=result, scope='disposable ordinary empty object', bucket=BUCKET, key=KEY,
                          stale=wrong, matching=deleted if result == 'MATCH_ENFORCED' else None,
                          version_history=rows, initial_version_readable=True)
            write('result', report)
            return report
        finally:
            client.close()
            cloud.admin.close()
    finally:
        os.close(fd)


if __name__ == '__main__':
    print(json.dumps(run(), sort_keys=True))
