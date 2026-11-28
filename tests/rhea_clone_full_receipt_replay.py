"""Replay the sealed generation-24 batch in private Rhea mount and network namespaces.

The caller binds an empty tmpfs journal at the runner's usual path, the original journal at
WORK/recorded read-only, the payload staging tree read-only, and a private writer lock.
The setup, interrupt and recover invocations must be separate processes.
"""
import argparse
import base64
from collections import Counter
import contextlib
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

INSTALL = Path('/root/.local/share/rhea-clone-batch-runner-4g-v1')
sys.path.insert(0, str(INSTALL / 'scripts'))
import rhea_clone_batch_runner as r

SOURCE_SHA = '653bd9c3add43fb74a24fefaa3d2661ea8e7e9ff214f26adf4212091d249d834'
CHILD = '000024'
PARENT = '000023'
STATE = r.ROOT / CHILD


def check_isolation(work):
    assert os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode
    for ns in ('net', 'mnt'):
        assert not os.path.samefile('/proc/self/ns/' + ns, '/proc/1/ns/' + ns)
    assert {name for _, name in socket.if_nameindex()} == {'lo'}
    assert work.parent == Path('/run') and work.stat().st_mode & 0o777 == 0o700
    assert (work / 'journal').samefile(r.ROOT) and (work / 'locks').samefile(r.a.WRITER_LOCK.parent)
    for path in (work / 'recorded', r.host.BATCH_DATA, INSTALL):
        assert os.statvfs(path).f_flag & os.ST_RDONLY
    assert not (work / 'recorded').samefile(r.ROOT)


def saved(work, name):
    return r.host.read(work / 'recorded' / CHILD / name)


def add_history(receipt, sample):
    # Model one input and one output per remaining mark using real eight-digit names and pin shapes.
    current = receipt['sst_lineage']
    pins = list(sample['created_sst_versions'].values())
    retired = [u['sst_diff']['retired'][0]['name'] for u in sample['unit_evidence']]
    for index in range(sample['marked_after']):
        old = retired[index % len(retired)]
        new_name, old_name = f'{70000000 + index}.sst', f'{80000000 + index}.sst'
        assert new_name not in current['created'] and old_name not in current['retired']
        current['created'][new_name] = pins[index % len(pins)]
        current['retired'][old_name] = sample['sst_lineage']['retired'][old]
        receipt['retired_sst_states'][old_name] = sample['retired_sst_states'][old]
    current['rewrite_operations'] += sample['marked_after']
    receipt['physical_rewrite_total'] += sample['marked_after']
    return receipt


def fixture_admission(work, source, parent_sha):
    keys = work / 'keys'
    keys.mkdir(mode=0o700)
    shutil.copy(r.h.TRANSACTION_INSTALL / 'release.pub', keys / 'release.pub')
    key = keys / 'ephemeral.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', key], check=True)
    subprocess.run(['openssl', 'pkey', '-in', key, '-pubout', '-out', keys / 'handoff.pub'], check=True)
    nonce = secrets.token_hex(32)
    binding = dict(source['binding'], previous_checkpoint_sha256=parent_sha, release_sha256=r.release()[0])
    now = int(time.time())
    raw = r.a.canonical(dict(binding=binding, issued=now, expires=now + 600, nonce=nonce))
    msg = keys / 'message'
    msg.write_bytes(r.a.DOMAIN + raw)
    sig = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', msg])
    key.unlink()
    r.host.mkdir(STATE / 'admissions')
    r.host.mkdir(r.ROOT / 'consumed-nonces')
    r.host.put(STATE / 'admissions' / (nonce + '.json'),
               dict(claims=base64.b64encode(raw).decode(), signature=base64.b64encode(sig).decode()))
    r.host.put(r.ROOT / 'consumed-nonces' / (nonce + '.json'),
               dict(schema=1, claims_sha256=r.a.sha(raw), signature_sha256=r.a.sha(sig), nonce=nonce))
    r.host.put(STATE / 'intent.json', dict(binding=binding, nonce=nonce))
    return r.a.sha(raw)


def setup(work):
    sample = saved(work, 'checkpoint.json')
    assert r.c.digest(sample) == SOURCE_SHA
    source = work / 'recorded' / CHILD
    parent = r.host.read(source.parent / PARENT / 'checkpoint.json')
    assert r.c.digest(parent) == sample['previous_checkpoint_sha256']
    for name in (PARENT, CHILD):
        r.host.mkdir(r.ROOT / name)
    parent = add_history(parent, sample)
    parent_sha = r.c.digest(parent)
    r.host.put(r.ROOT / PARENT / 'checkpoint.json', parent)
    row = dict(generation=23, sha256=parent_sha, previous_checkpoint_sha256=parent['previous_checkpoint_sha256'],
               certified_rewrites=parent['physical_rewrite_total'])
    r.host.put(r.ROOT / PARENT / 'completed.json', row)
    r.host.put(r.ROOT / 'HEAD.json', row)
    del parent
    for name in ('previous-metadata', 'closed-metadata'):
        shutil.copytree(source / name, STATE / name)
    for name in ('quarantine.json', 'opening.json', 'closed-queue.json', 'snapshot.json', 'writer-closed.json'):
        shutil.copy2(source / name, STATE / name)
    for path in source.glob('put-*.json'):
        shutil.copy2(path, STATE / path.name)
    claims_sha = fixture_admission(work, saved(work, 'intent.json'), parent_sha)
    r.host.put(STATE / 'writer-launch.json', dict(saved(work, 'writer-launch.json'), admission_sha256=claims_sha))
    proofs = {}
    for name in ('before-publication', 'final-remote'):
        receipt = add_history(saved(work, name + '.json'), sample)
        receipt['previous_checkpoint_sha256'] = parent_sha
        r.host.put(STATE / (name + '.json'), receipt)
        proofs[name] = r.c.digest(receipt)
        del receipt
    expected = add_history(saved(work, 'checkpoint.json'), sample)
    expected.update(previous_checkpoint_sha256=parent_sha, before_markers_proof_sha256=proofs['before-publication'],
                    final_remote_proof_sha256=proofs['final-remote'])
    r.host.put(work / 'expected.json', dict(parent_sha256=parent_sha, successor_sha256=r.c.digest(expected),
               created=len(expected['sst_lineage']['created']), retired=len(expected['retired_sst_states'])))
    db = work / 'reader'
    shutil.copytree(STATE / 'closed-metadata', db)
    for name in sample['retained_remote_metadata']:
        (db / name).touch(exist_ok=False)


class RecordedStore:
    """Serve the recorded version identities and stream the actual sealed output bytes. No PUT API."""
    def __init__(self, cert, opening):
        self.pins = {**cert['remote_metadata'], **cert['created_sst_versions']}
        self.marker_rows = [*opening['marker_history'],
                            r.bulk.markers.latest_row(cert['manifest_marker'], self.pins[cert['manifest_marker']])]
        self.ssts = cert['created_sst_versions']
        self.gets = Counter()
        self.lock = threading.Lock()

    def close(self):
        pass

    def name(self, Bucket, Key):
        assert Bucket == r.iam.BUCKET and Key.startswith(r.iam.PREFIX)
        return Key[len(r.iam.PREFIX):]

    def head_object(self, *, Bucket, Key):
        pin = self.pins[self.name(Bucket, Key)]
        return dict(VersionId=pin['version_id'], ContentLength=pin['size'], ETag=pin['etag'])

    def list_object_versions(self, *, Bucket, Prefix, MaxKeys):
        assert MaxKeys == 100
        pin = self.pins[self.name(Bucket, Prefix)]
        return dict(Versions=[dict(Key=Prefix, VersionId=pin['version_id'], Size=pin['size'],
                                   ETag=pin['etag'], IsLatest=True)])

    def get_object(self, *, Bucket, Key, VersionId):
        name = self.name(Bucket, Key)
        result = self.head_object(Bucket=Bucket, Key=Key)
        assert result['VersionId'] == VersionId
        path = (r.host.BATCH_DATA / CHILD / 'closed-payloads' if name in self.ssts else STATE / 'closed-metadata') / name
        with self.lock:
            self.gets[name] += 1
        return dict(result, Body=path.open('rb'))

    def get_paginator(self, operation):
        assert operation == 'list_object_versions'
        return self

    def paginate(self, *, Bucket, Prefix, PaginationConfig):
        assert self.name(Bucket, Prefix) == 'marker.' and PaginationConfig == {'PageSize': 1000}
        page = {'Versions': [], 'DeleteMarkers': []}
        for row in self.marker_rows:
            item = dict(Key=r.iam.PREFIX + row['name'], VersionId=row['version_id'], IsLatest=row['latest'])
            if not row['delete']:
                item.update(Size=row['size'], ETag=row['etag'])
            page['DeleteMarkers' if row['delete'] else 'Versions'].append(item)
        yield page


def retained_files():
    files = sorted([*STATE.glob('put-*.json'), *STATE.glob('admissions/*.json'),
                    *(r.ROOT / 'consumed-nonces').glob('*.json'),
                    *(STATE / n for n in ('before-publication.json', 'final-remote.json', 'checkpoint.json', 'completed.json'))])
    digest = hashlib.sha256()
    for path in files:
        st = path.stat()
        digest.update(r.c.canonical([str(path.relative_to(r.ROOT)), st.st_ino, st.st_size, st.st_mtime_ns]))
    return dict(count=len(files), identity_sha256=digest.hexdigest())


def run_attempt(work, interrupt):
    sample = saved(work, 'checkpoint.json')
    expected = r.host.read(work / 'expected.json')
    binding = r.host.read(STATE / 'intent.json')['binding']
    store = RecordedStore(sample, saved(work, 'opening.json'))
    keys = work / 'keys'
    reader = binding['reader']
    running = False
    def start_reader():
        nonlocal running
        running = True
        return reader

    def observations():
        assert set(store.gets) == {p.name[4:-len('.receipt.json')] for p in STATE.glob('put-*.receipt.json')}
        assert set(store.ssts) <= store.gets.keys() and set(store.gets.values()) == {1}
        return dict(retained=retained_files(), version_reads=len(store.gets), sst_count=len(store.ssts),
                    sst_bytes=sum(store.pins[n]['size'] for n in store.ssts), puts=0)

    def interrupt_commit(parent, successor):
        assert r.read_head()[0] == parent and parent['sha256'] == expected['parent_sha256']
        assert r.host.read(STATE / 'completed.json') == successor and successor['sha256'] == expected['successor_sha256']
        r.host.put(work / 'interrupted.json', observations())
        os._exit(75)

    # System services and cloud responses come from the sealed run. All journal, claim verification,
    # inventory decoding, payload hashing, proof comparison, cold-report checks and CAS code is real.
    credentials = ({'AccessKeyId': 'offline', 'SecretAccessKey': 'offline'}, 'offline')
    replacements = [
        (r.h, 'HANDOFF_KEY', r.a.sha((keys / 'handoff.pub').read_bytes())),
        (r.h, 'TRANSACTION_INSTALL', keys),
        (r.h, 'production', lambda: binding['production']),
        (r.h, 'reader', lambda required: reader),
        (r.h, 'main_pid', lambda unit: reader['process']['pid'] if running and unit == r.h.READER else 0),
        (r.h, 'mount_row', lambda path: None), (r.h.preflight, '_open_users', lambda pid: []),
        (r.host, 'start_reader', start_reader), (r.host, 'inspector', lambda binary, mode: sample['reopen']),
        (r.prep, 'DB', work / 'reader'), (r, 'admin_reader', lambda: contextlib.nullcontext(store)),
        (r, 'fixed_writer', lambda: credentials), (r.publisher, 'credentials', lambda *args: credentials),
        (r.host.r, 's3_client', lambda *args: store),
    ]
    if interrupt:
        replacements.append((r, 'commit_head', interrupt_commit))
    else:
        assert retained_files() == r.host.read(work / 'interrupted.json')['retained']
    with contextlib.ExitStack() as patches:
        for target, name, value in replacements:
            patches.enter_context(patch.object(target, name, value))
        result = r.main(['resume', '24'])
    assert not interrupt and result['sha256'] == expected['successor_sha256']
    assert r.read_head()[0]['sha256'] == result['sha256']
    obs = observations()
    assert obs == r.host.read(work / 'interrupted.json')
    r.host.put(work / 'recovered.json', dict(head=result, **obs))


def limits(work):
    # Exercise exact real limits without building a 128 MiB Python string.
    target = r.ROOT / '999999'
    r.host.mkdir(target)
    result = {}
    for name, limit in (('checkpoint.json', r.host.BATCH_PROOF_BYTES), ('completed.json', r.host.TRIAL_RECEIPT_BYTES)):
        path = target / name
        with path.open('xb') as f:
            f.write(b'{}')
            chunk = b' ' * (1 << 20)
            while f.tell() < limit:
                f.write(chunk[:min(len(chunk), limit - f.tell())])
        assert r.host.read(path) == {}
        with path.open('ab') as f:
            f.write(b' ')
        try:
            r.host.read(path)
        except r.c.Refusal as error:
            assert str(error) == 'invalid trial receipt'
        else:
            raise AssertionError('limit+1 accepted')
        result[name] = dict(accepted=limit, refused=limit + 1)
        path.unlink()
    r.host.put(work / 'boundaries.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('setup', 'interrupt', 'recover', 'limits'))
    parser.add_argument('work', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    check_isolation(args.work)
    if args.mode == 'setup':
        setup(args.work)
    elif args.mode == 'limits':
        limits(args.work)
    else:
        run_attempt(args.work, args.mode == 'interrupt')


if __name__ == '__main__':
    main()
