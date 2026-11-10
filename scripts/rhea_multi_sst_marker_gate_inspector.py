#!/usr/bin/env python3
"""Independent read-only gate audit. Never replay/repair/retry a writer or marker.

Only OFFLINE evidence classification is implemented. A certifiable candidate is
not a committed certificate and cannot authorize any live action.
"""
from __future__ import annotations

import rhea_multi_sst_marker_gate as g

c, v, require = g.c, g.v, g.require


def _read(store, name):
    return c.parse(store.read(name))


def audit_evidence(store):
    """No writes, even for missing receipts; reject every unreferenced artifact."""
    require(store.locked, 'read evidence under existing exclusive store lock')
    names = {path.name for path in store.path.iterdir()}
    expected = {'lock', 'gate-attempt-intent.json', 'gate-batch.json', 'gate-prepublication.json',
                'gate-before-proof.json', 'gate-publication.json', 'gate-final-proof.json', 'gate-drained-observation.json'}
    require(expected <= names, 'partial stage: required immutable evidence absent')
    retained, blobs = store.unpack_receipt('snapshot', _read(store, 'gate-batch.json'))
    batch = g.ClosedBatch.build(c.decode_metadata(retained['metadata']), c.decode_metadata(retained['previous_metadata']),
                               retained['report'], retained['hashes'], retained['previous'])
    require(retained['binding'] == batch.binding, 'retained batch binding differs')
    intent = _read(store, 'gate-attempt-intent.json')
    require(set(intent) == {'schema', 'batch_sha256', 'identity', 'isolation', 'timing', 'preopen_history'}
            and type(intent['schema']) is int and intent['schema'] == 1
            and intent['batch_sha256'] == batch.sha256, 'attempt intent differs')
    g.validate_identity(intent['identity'])
    g.validate_isolation(intent['isolation'], intent['identity'], batch)
    g.TimingPolicy(**intent['timing'])
    before, final = _read(store, 'gate-before-proof.json'), _read(store, 'gate-final-proof.json')
    drained = _read(store, 'gate-drained-observation.json')
    guard = g.QueueGuard(batch, intent['identity'], intent['isolation'], g.TimingPolicy(**intent['timing']))
    rows = guard.sample(drained, drained['finished'])
    state = g.GateState(batch.sha256).advance(batch, 'data-drained', rows)
    state = state.advance(batch, 'before-proved', before)
    prepublication = _read(store, 'gate-prepublication.json')
    require(prepublication['batch_sha256'] == batch.sha256, 'prepublication snapshot batch differs')
    g.check_marker_history(batch, intent['preopen_history'], prepublication['history'], {})
    publication = _read(store, 'gate-publication.json')
    require(set(publication) == {'batch_sha256', 'before_sha256', 'published'}
            and publication['batch_sha256'] == batch.sha256 and publication['before_sha256'] == c.digest(before)
            and set(publication['published']) == set(batch.changed), 'publication receipt differs')
    numbers = sorted({int(name.split('-')[2]) for name in names if name.startswith('gate-mutation-')})
    require(numbers == list(range(1, len(numbers) + 1)), 'mutation intent sequence gap')
    priorities, markers = [], {}
    for number in numbers:
        stem = f'gate-mutation-{number:04d}'
        expected.update({stem + '-intent.json', stem + '-receipt.json', stem + '-observation.json'})
        mutation, receipt = _read(store, stem + '-intent.json'), _read(store, stem + '-receipt.json')
        observed = _read(store, stem + '-observation.json')
        selected = mutation['selected']
        selected_guard = g.QueueGuard(batch, intent['identity'], intent['isolation'], g.TimingPolicy(**intent['timing']))
        selected_rows = selected_guard.sample(observed, observed['finished'])
        require(any((row.item_id, row.name, row.size, row.uploading, row.tries)
                    == (selected['id'], selected['name'], selected['size'], False, 0) for row in selected_rows),
                'selected tuple differs from retained authenticated observation')
        name = selected['name']
        priority = g.historical.upload_priority(name)
        basename = name[len('pebbleds/'):]
        require(set(mutation) == {'schema', 'generation', 'batch_sha256', 'before_sha256', 'identity_sha256',
                    'selected', 'method', 'parameters', 'automatic_retry', 'observation_sha256'}
                and type(mutation['schema']) is int and mutation['schema'] == 1 and mutation['generation'] == 14
                and mutation['batch_sha256'] == batch.sha256
                and mutation['observation_sha256'] == c.digest(observed)
                and mutation['identity_sha256'] == c.digest(intent['identity'])
                and mutation['automatic_retry'] is False and mutation['method'] == 'vfs/queue-set-expiry'
                and mutation['parameters'] == {'id': selected['id'], 'expiry': g.w.QUEUE_EXPIRIES['expedite']}
                and set(selected) == {'id', 'name', 'size'}
                and type(selected['id']) is int and 0 < selected['id'] < 2**63
                and type(selected['size']) is int and selected['size'] == batch.allowed[basename],
                'mutation not bound to generation/process/closed batch')
        require(set(receipt) == {'intent_sha256', 'rc', 'marker'}
                and receipt['intent_sha256'] == c.digest(mutation) and receipt['rc'] == {},
                'missing/ambiguous mutation receipt; never retry')
        priorities.append((priority, name))
        if priority >= 5:
            require(basename in batch.changed and basename not in markers
                    and mutation['before_sha256'] == c.digest(before)
                    and receipt['marker'] == publication['published'][basename], 'marker receipt differs')
            markers[basename] = receipt['marker']
        else:
            require(mutation['before_sha256'] is None and receipt['marker'] is None, 'data release out of phase')
    state = state.advance(batch, 'published', markers)
    state.advance(batch, 'remote-proved', final)
    require(priorities == sorted(priorities) and len(set(name for _, name in priorities)) == len(priorities)
            and set(markers) == set(batch.changed), 'data-first order or one-shot marker publication differs')
    require(names == expected | blobs, 'orphan/partial/unknown evidence; preserve all artifacts')
    require(before['proof_pass_id'] != final['proof_pass_id'], 'independent proof ID reused')
    for proof, mode in ((before, 'before-markers'), (final, 'final')):
        require(proof['mode'] == mode and proof['generation'] == 14
                and proof['previous_checkpoint_sha256'] == c.raw_sha(batch.previous_raw)
                and proof['go_report_sha256'] == c.raw_sha(batch.report_raw)
                and proof['closed_output_hashes_sha256'] == c.raw_sha(batch.hashes_raw)
                and proof['changed_markers'] == list(batch.changed), 'proof not bound to closed batch')
    for name, pin in markers.items():
        require(final['remote_metadata'][name] == pin, 'final proof differs from publication receipt')
    return batch, intent, publication, before, final


def inspect_attempt(store, client, ledger, *, observe_restored, reopen, reopened_metadata):
    """Read-only offline classifier with fresh full cloud proof and restoration recheck.

    observe_restored is an independent offline witness, NOT a signed authority.
    Production adaptation requires protected installed sources and actual reader
    tuple/boot/mount/service observations; no live certification path is shipped.
    """
    result = dict(decision='preserve/manual-inspection', writer_replay_allowed=False,
                  marker_retry_allowed=False, rollback_allowed=False, mutations_performed=False,
                  live_certification_allowed=False)
    try:
        batch, intent, publication, before, final = audit_evidence(store)
        restored = observe_restored()
        def check_restored():
            current = observe_restored()
            require(current == restored, 'restored reader changed during independent proof')
            require(set(current) == {'writer_stopped', 'queue_clean', 'reader_identity', 'reader_mount_read_only', 'stop'}
                    and current['writer_stopped'] is True and current['queue_clean'] is True
                    and current['reader_mount_read_only'] is True and current['stop'] is False,
                    'writer stop/clean queue/actually read-only reader/stop witness missing')
            c.process_tuple(current['reader_identity'])
            require(current['reader_identity']['boot_id'] == intent['identity']['process']['boot_id'], 'restored boot differs')
        check_restored()
        # Validate retained independent proof pair and read-only reopen first.
        v.finalize_checkpoint(before, final, reopen, reopened_metadata)
        class Stop:
            def is_set(self):
                check_restored()
                return False
        fresh = v.verify_generation(client, ledger, batch.previous, batch.report, batch.metadata, batch.hashes,
            'final', c.raw_sha(batch.previous_raw), enumeration_workers=4, enumeration_stop=Stop())
        require(fresh['proof_pass_id'] not in {before['proof_pass_id'], final['proof_pass_id']},
                'inspector proof pass ID reused')
        v.finalize_checkpoint(before, fresh, reopen, reopened_metadata)
        history = g.marker_history(client, stop=Stop())
        g.check_marker_history(batch, intent['preopen_history'], history, publication['published'])
        for name, pin in fresh['remote_metadata'].items():
            g.exact_latest(client, name, pin, batch.metadata[name], checkpoint=check_restored)
        check_restored()
        # Deliberately returns classification, never writes a certificate/journal.
        result.update(decision='certifiable-offline-candidate', batch_sha256=batch.sha256,
                      reason='closed batch, one-shot publication, independent proofs and read-only reopen agree')
    except Exception as exc:
        result['reason'] = str(exc)
    return result


def main():
    print('REFUSED: read-only offline inspector library; no live certification or recovery CLI')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
