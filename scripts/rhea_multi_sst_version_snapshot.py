#!/usr/bin/env python3
"""Exact version-addressed metadata retention; no cloud writes or completion claim.

Library only. The caller owns an immutable Store lock and supplies reviewed
version pins from a full proof. GETs here cannot replace either full enumeration
proof. No SDK/client construction, credentials, live CLI or recovery execution.
"""
from __future__ import annotations

import hashlib

import rhea_multi_sst_checkpoint_controller as c

CHUNK = 1024**2
BUCKET = c.verifier.BUCKET
PREFIX = c.verifier.PREFIX


def validate_pins(pins):
    base = c.verifier.proof.base
    c.require(type(pins) is dict and 0 < len(pins) <= base.MAX_METADATA_FILES, 'complete metadata pins required')
    total = 0
    for name, pin in pins.items():
        c.require(type(name) is str and base.META_NAME.fullmatch(name)
                  and type(pin) is dict and set(pin) == {'version_id', 'etag', 'size', 'sha256'}
                  and type(pin['version_id']) is str and pin['version_id'] not in ('', 'null')
                  and type(pin['etag']) is str and pin['etag'] and '"' not in pin['etag']
                  and type(pin['size']) is int and 0 <= pin['size'] <= base.MAX_METADATA_BYTES
                  and type(pin['sha256']) is str and c.HEX.fullmatch(pin['sha256']), 'invalid exact metadata version pin')
        total += pin['size']
    c.require(total <= base.MAX_METADATA_TOTAL, 'snapshot metadata total exceeds bound')


def _get(client, name, pin):
    response = client.get_object(Bucket=BUCKET, Key=PREFIX + name, VersionId=pin['version_id'])
    body = response.get('Body')
    try:
        c.require(response.get('VersionId') == pin['version_id']
                  and type(response.get('ContentLength')) is int and response['ContentLength'] == pin['size']
                  and response.get('ETag') == '"' + pin['etag'] + '"'
                  and response.get('DeleteMarker', False) is False,
                  'version GET identity/size/delete marker differs')
    except BaseException:
        if body is not None:
            body.close()
        raise
    return body


def _pieces(body, size):
    remaining = size
    while remaining:
        needed = min(CHUNK, remaining)
        parts = []
        while needed:
            part = body.read(needed)
            c.require(type(part) is bytes and 0 < len(part) <= needed, 'truncated/invalid version body')
            parts.append(part)
            needed -= len(part)
        data = b''.join(parts)
        remaining -= len(data)
        yield data
    c.require(body.read(1) == b'', 'version body longer than signed pin')


def capture(store, client, pins):
    """Write-ahead intent then exact raw chunks then completion reference.

    O_EXCL intent makes every interrupted capture non-replayable. Never repair
    or delete orphan chunks. Preserve the entire attempt for manual inspection.
    """
    c.require(store.locked, 'immutable evidence store lock required')
    validate_pins(pins)
    c.require({path.name for path in store.path.iterdir()} == {'lock'},
              'dedicated empty snapshot store required; existing attempt must be preserved')
    # Freeze against caller mutation, including callbacks from client/body code.
    pins = c.parse(c.canonical(pins))
    store.put('version-snapshot-intent.json', dict(schema=1, bucket=BUCKET, prefix=PREFIX, pins=pins))
    result = {}
    for index, (name, pin) in enumerate(sorted(pins.items())):
        body = _get(client, name, pin)
        digest, chunks = hashlib.sha256(), []
        try:
            for part, data in enumerate(_pieces(body, pin['size'])):
                digest.update(data)
                leaf = f'version-{index:04d}-{part:06d}.bin'
                store.put_raw(leaf, data)
                chunks.append(dict(file=leaf, size=len(data), sha256=c.raw_sha(data)))
        finally:
            body.close()
        c.require(digest.hexdigest() == pin['sha256'], 'exact version body hash differs')
        result[name] = dict(pin, chunks=chunks)
    value = dict(schema=1, bucket=BUCKET, prefix=PREFIX, objects=result, cloud_completion_proven=False)
    store.put('version-snapshot.json', value)
    return value


def audit(store, pins):
    """Independently read retained bytes; preserve original encoding and ordering."""
    validate_pins(pins)
    intent = c.parse(store.read('version-snapshot-intent.json'))
    c.require(c.canonical(intent) == c.canonical(dict(schema=1, bucket=BUCKET, prefix=PREFIX, pins=pins)),
              'snapshot intent differs from independently supplied version pins')
    value = c.parse(store.read('version-snapshot.json'))
    c.require(set(value) == {'schema', 'bucket', 'prefix', 'objects', 'cloud_completion_proven'}
              and type(value['schema']) is int and value['schema'] == 1 and value['bucket'] == BUCKET
              and value['prefix'] == PREFIX and value['cloud_completion_proven'] is False
              and type(value['objects']) is dict and set(value['objects']) == set(pins), 'snapshot schema differs')
    retained = {}
    for index, (name, pin) in enumerate(sorted(pins.items())):
        ref = value['objects'][name]
        c.require(type(ref) is dict and set(ref) == set(pin) | {'chunks'}
                  and c.canonical({k: ref[k] for k in pin}) == c.canonical(pin)
                  and type(ref['chunks']) is list and len(ref['chunks']) == (pin['size'] + CHUNK - 1) // CHUNK,
                  'snapshot pin/chunk references differ')
        pieces = []
        for part, chunk in enumerate(ref['chunks']):
            leaf = f'version-{index:04d}-{part:06d}.bin'
            c.require(type(chunk) is dict and set(chunk) == {'file', 'size', 'sha256'} and chunk['file'] == leaf,
                      'unexpected snapshot chunk name/schema')
            data = store.read(leaf)
            c.require(type(chunk['size']) is int and len(data) == chunk['size'] == min(CHUNK, pin['size'] - part * CHUNK)
                      and c.raw_sha(data) == chunk['sha256'], 'retained version chunk changed')
            pieces.append(data)
        raw = b''.join(pieces)
        c.require(len(raw) == pin['size'] and c.raw_sha(raw) == pin['sha256'], 'retained version body changed')
        retained[name] = raw
    return retained


def reconcile(store, client, pins):
    """Fresh version GETs vs independent pins AND retained exact bytes; no writes."""
    pins = c.parse(c.canonical(pins))
    retained = audit(store, pins)
    for name, pin in sorted(pins.items()):
        body = _get(client, name, pin)
        try:
            offset = 0
            for data in _pieces(body, pin['size']):
                c.require(retained[name][offset:offset + len(data)] == data, 'fresh version body differs')
                offset += len(data)
        finally:
            body.close()
    return dict(exact_version_bodies_verified=True, full_enumeration_proven=False,
                writer_replay_allowed=False, mutations_performed=False, controller_ready=False)
