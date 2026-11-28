"""Verification for successors of the certified generation-14 disposable clone."""
import base64
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import os
from pathlib import Path
import time

import rhea_gen14_create_only_checkpoint as original
import rhea_gen14_retained_manifest_proof as markers

c, v, p = original.c, original.v, original.p
require = c.require
ANCHOR = '7c83ebd87b1194c1624f7455a2e330af686ca9a1421e58e00051ebe5473bd09c'
SCOPE = 'rhea-disposable-clone-byte-capped-batch-v1'
LIMITS = dict(v.LIMITS, maximum_units=8, input_bytes=512 << 20)
FOUR_GIB_LIMITS = dict(LIMITS, maximum_units=64, input_bytes=4 << 30,
                       sst_output_bytes=4 << 30, backlog_bytes=5 << 30)
SCHEMA = 3


def sst_worker_count(value):
    require(type(value) is int and 1 <= value <= 4, 'select between one and four SST workers')
    return value


def map_ssts(items, clients, operation):
    """Use each client for one SST at a time. Drain active work before propagating an error."""
    sst_worker_count(len(clients))
    require(items and all(p.base.SST_NAME.fullmatch(name) for name in items), 'expected exact SST names')
    if len(clients) == 1:
        return {name: operation(clients[0], name, item) for name, item in items.items()}

    remaining = iter(items.items())
    results = {}
    with ThreadPoolExecutor(max_workers=len(clients), thread_name_prefix='clone-sst') as pool:
        active = {}

        def submit_next(client):
            item = next(remaining, None)
            if item is not None:
                name, value = item
                active[pool.submit(operation, client, name, value)] = (client, name)

        for client in clients:
            submit_next(client)
        while active:
            completed, _ = wait(active, return_when=FIRST_COMPLETED)
            for future in completed:
                _, name = active[future]
                results[name] = future.result()
            for future in completed:
                client, _ = active.pop(future)
                submit_next(client)
    return results


def hash_proof_ssts(readers, created, latest, hashes):
    """Fetch and hash every new version afresh for this pass, with monotonic timing per SST."""
    require(created.keys() == hashes.keys(), 'proof SST set differs from sealed outputs')
    start = time.monotonic_ns()

    def read_one(client, name, expected):
        begin = time.monotonic_ns() - start
        pin = p._hash_new_sst(client, name, latest[p.PREFIX + name], expected)
        return pin, [begin, time.monotonic_ns() - start]

    results = map_ssts(hashes, readers, read_one)
    elapsed = time.monotonic_ns() - start
    return ({n: pin for n, (pin, _) in results.items()},
            dict(workers=len(readers), elapsed_ns=elapsed, intervals_ns={n: span for n, (_, span) in results.items()}))


def check_read_metrics(report, workers):
    sst_worker_count(workers)
    metrics = report['sst_read_metrics']
    spans = metrics['intervals_ns']
    elapsed = metrics['elapsed_ns']
    require(sst_worker_count(metrics['workers']) == workers and spans.keys() == report['created_sst_versions'].keys()
            and spans and type(elapsed) is int and elapsed > 0, 'proof read coverage or width differs')
    events = []
    for begin, end in spans.values():
        require(type(begin) is type(end) is int and 0 <= begin < end <= elapsed, 'invalid SST read interval')
        events.extend(((begin, 1), (end, -1)))
    active = 0
    for _, delta in sorted(events):
        active += delta
        require(0 <= active <= workers, 'proof read concurrency exceeds admission')


def limits_for(generation):
    require(type(generation) is int and generation >= 15, 'invalid successor generation')
    return FOUR_GIB_LIMITS if generation >= 17 else LIMITS


def validate_io(io, limits):
    require(isinstance(io, dict) and not io.get('blocked_budget_error'), 'missing or failed write budget')
    for kind, cap in [('sst', limits['sst_output_bytes']), ('metadata', limits['metadata_write_bytes'])]:
        actual = io.get(kind + '_write_bytes')
        maximum = io.get('max_' + kind + '_write_bytes')
        require(type(maximum) is int and maximum == cap and type(actual) is int and 0 <= actual <= cap,
                'cumulative write counter or budget differs')


def validate_health(value, limits):
    names = ('cache_bytes', 'free_bytes', 'queue_bytes', 'queue_files', 'errors', 'transferring')
    require(all(type(value.get(n)) is int and value[n] >= 0 for n in names), 'invalid clone resource sample')
    require(value['cache_bytes'] <= limits['cache_bytes'] and value['free_bytes'] >= limits['minimum_free_bytes']
            and value['queue_bytes'] <= limits['backlog_bytes'] and value['queue_files'] <= limits['backlog_files']
            and value['errors'] == value['transferring'] == 0, 'clone queue or free-space limit exceeded')


def validate_closed(writer, intent, limits):
    """Bind the signed large-batch request to the child exit and every durable Go record."""
    validate_health(writer['health'], limits)
    identity = c.process_tuple(writer['source_process'])
    require(identity['exe_sha256'] == writer['binary_sha256'] == intent['go_binary_sha256']
            and identity['boot_id'] == intent['reader_identity']['boot_id']
            and type(writer['exit_code']) is int and writer['exit_code'] == 0
            and writer['stopped'] is True and writer['monitor_complete'] is True, 'clone writer exit differs')
    report = writer['report']
    request = intent['request']
    units = report['units']
    require(report['closed'] is True and not report.get('error') and not report.get('attempted_unit')
            and report['stop_reason'] in ('unit-limit', 'no-marked-files', 'next-unit-budget')
            and c.digest(report['request']) == c.digest(request)
            and type(report['physical_compactions']) is int and 1 <= len(units) == report['physical_compactions']
            <= intent['unit_count'] == request['maximum_units'] == limits['maximum_units'], 'unclosed or partial batch')
    expected = {'pending.json': dict(schema=v.WRITER_SCHEMA, phase='executing', request=request), 'closed.json': report}
    for index, unit in enumerate(units, 1):
        prefix = f'unit-{index:03d}'
        before = dict(format=unit['before_format'], marked=unit['marked_before'], files=unit['sst_files_before'],
                      bytes=unit['sst_bytes_before'], inventory_sha256=unit['sst_inventory_sha256_before'])
        expected[prefix+'-intent.json'] = dict(index=index, before=before, picker_plan=unit['picker_plan'])
        expected[prefix+'-receipt.json'] = unit
    files = writer['go_files']
    require(files.keys() == expected.keys(), 'missing or extra clone writer record')
    for name, record in expected.items():
        raw = base64.b64decode(files[name], validate=True)
        require(c.digest(c.parse(raw)) == c.digest(record), 'clone writer journal differs: '+name)


def predecessor(cert, sha):
    require(c.digest(cert) == sha and cert.get('pebble_reopen_verified') is True
            and cert.get('remote_generation_verified') is True, 'uncertified predecessor')
    if cert['generation'] == 14:
        require(sha == ANCHOR and v._predecessor(cert, sha) == 2, 'wrong generation-14 anchor')
    else:
        require(type(cert['generation']) is int and cert['generation'] > 14 and cert['schema'] == SCHEMA
                and cert['scope'] == SCOPE and cert['anchor_checkpoint_sha256'] == ANCHOR
                and cert['batch_checkpoint_count'] == cert['generation'] - 13
                and cert['limits'] == limits_for(cert['generation']) and cert['physical_rewrite_total'] == cert['sst_lineage']['rewrite_operations'],
                'successor certificate ancestry or limits differ')
    p._validate_previous(cert, sha, p._metadata_pins(cert))


def logical_metadata(db, cert):
    """Read active metadata. Retained, version-pinned files can grow across checkpoints."""
    active = cert['remote_metadata']
    retained = cert['retained_remote_metadata']
    require(active.keys().isdisjoint(retained), 'duplicate logical and retained metadata')
    with os.scandir(db) as entries:
        actual = {e.name for e in entries if not p.base.SST_NAME.fullmatch(e.name)}
    require(actual == active.keys() | retained.keys(), 'physical metadata names differ from certificate')
    data = {}
    for name, pin in active.items():
        path = db / name
        require(p.base.META_NAME.fullmatch(name) and not path.is_symlink()
                and path.is_file() and path.stat().st_size == pin['size'] <= p.base.MAX_METADATA_BYTES,
                'invalid active metadata leaf')
        body = path.read_bytes()
        require(c.raw_sha(body) == pin['sha256'], 'active metadata bytes differ: '+name)
        data[name] = body
    c.metadata_bounds(data)
    return data


def marker_view(cert, history, fresh, successor=None, pin=None):
    """All existing versions and tombstones stay exact across a monotonic marker creation."""
    baseline = markers.version_rows(history)
    require(c.digest(history) == cert['marker_history_sha256'], 'predecessor marker history differs')
    names = {n: v for n,v in {**cert['remote_metadata'], **cert['retained_remote_metadata']}.items()
             if n.startswith('marker.')}
    heads = {r['name']: r for r in baseline.values() if r['latest'] and not r['delete']}
    require(heads == {n: markers.latest_row(n, v) for n,v in names.items()}, 'certified marker heads differ')
    old = cert['manifest_marker']
    fmt = cert['format_marker']
    manifests = {n: tuple(map(int, markers.MANIFEST.fullmatch(n).groups()))
                 for n in names if markers.MANIFEST.fullmatch(n)}
    require(set(names) == {fmt} | manifests.keys() and markers.FORMAT.fullmatch(fmt) and fmt.endswith('.013')
            and old in manifests and all(a < manifests[old][0] and b < manifests[old][1]
                for n,(a,b) in manifests.items() if n != old), 'ambiguous active manifest marker')
    prior = dict(active=old,retained=sorted(manifests.keys()-{old}),format=fmt)
    require(cert['manifest_view'] == prior, 'predecessor retained marker selection differs')
    expected = dict(baseline)
    if successor is not None:
        m = markers.MANIFEST.fullmatch(successor)
        require(m and all(int(x)>y for x,y in zip(m.groups(),manifests[old]))
                and all(n!=successor for n,_ in baseline), 'successor marker was used or did not advance')
        if pin is not None:
            expected[successor,pin['version_id']] = markers.latest_row(successor,pin)
    else:
        require(pin is None, 'marker pin without a successor')
    require(markers.version_rows(fresh)==expected, 'marker history changed outside admitted publication')
    return prior if pin is None else dict(active=successor,retained=sorted(manifests),format=fmt)


def check_opening(cert, latest, deleted):
    if cert['generation'] == 14:
        gen13 = c.parse((c.source_root()/'docs/evidence/rhea-batch2-000013-certificate-20261107.json').read_bytes())
        added = (cert['remote_metadata'].keys() - gen13['remote_metadata'].keys()) | cert['created_sst_versions'].keys()
        digest = original.baseline_digest(latest,deleted,{p.PREFIX+n for n in added})
        require(digest == cert['physical_baseline_sha256'], 'generation-14 physical baseline differs')
    else:
        require(original.baseline_digest(latest,deleted,set()) == cert['sealed_physical_sha256'],
                'current version or tombstone differs from certified successor')


def validate_batch(report, before, after, bs, ats, hashes, *, limits=LIMITS):
    """Reconstruct every intermediate MANIFEST state and compare it to actual picker and Pebble events."""
    current = {n:dict(row,name=n) for n,row in before.items()}
    expected_after = {n:dict(row,name=n) for n,row in after.items()}
    request = report['request']
    units = report['units']
    require(report['schema']==v.WRITER_SCHEMA and report['action']=='multi-step' and report['closed'] is True
            and not report.get('error') and not report.get('attempted_unit') and set(request)==
            {'maximum_units','before','initial_plan_sha256'} and type(request['maximum_units']) is int
            and request['maximum_units']==limits['maximum_units'] and type(report['physical_compactions']) is int
            and 1<=len(units)==report['physical_compactions']<=request['maximum_units'], 'unexpected closed batch')
    v._equal_json(request['before'],v._state(current),'admitted prestate differs')
    v._equal_json(report['before'],request['before'],'writer prestate differs')
    require(v._stats(before)['marked_files']==bs['marked_files'] and v._stats(after)['marked_files']==ats['marked_files'],
            'decoded MANIFEST statistics differ')
    validate_io(report['io'], limits)
    created, retired = v._delta(report['sst_diff'])
    require(set(hashes)==set(created),'closed SST hashes incomplete')
    all_new, all_retired, touched, jobs, events = {}, {}, set(), set(), []
    input_bytes, last_sst, last_meta = 0, 0, 0
    for index,unit in enumerate(units):
        new, gone = v._delta(unit['sst_diff'])
        require(unit['action']=='step' and not unit.get('error') and new and gone and
                not touched.intersection(new.keys()|gone.keys()) and new.keys().isdisjoint(current)
                and gone.keys()<=current.keys(), 'non-disjoint or unrelated unit')
        plan = v._plan(unit['picker_plan'],current)
        require(index or plan['plan_sha256']==request['initial_plan_sha256'], 'first picker differs')
        nxt = {n:row for n,row in current.items() if n not in gone}
        nxt.update({n:dict(row,marked=False) for n,row in new.items()})
        validate_io(unit['io'], limits)
        sst, meta = unit['io']['sst_write_bytes'], unit['io']['metadata_write_bytes']
        # The pinned single-unit proof checks writes for one compaction. The
        # native worker reports cumulative counters from one open Pebble DB.
        unit_io = dict(unit['io'], sst_write_bytes=sst-last_sst, metadata_write_bytes=meta-last_meta,
                       max_sst_write_bytes=v.MAX_OUTPUT)
        p._validate_stage(dict(unit, io=unit_io), current, nxt, v._stats(current), v._stats(nxt),
                          '013', '013', {n: hashes[n] for n in new})
        require(last_sst + sum(row['size'] for row in new.values()) <= sst <= report['io']['sst_write_bytes']
                and last_meta <= meta <= report['io']['metadata_write_bytes'],'cumulative writes differ')
        begin,end = unit['compactions']
        require(end['job'] not in jobs and not begin.get('error'), 'compaction job differs or was repeated')
        jobs.add(end['job']); events.extend((begin,end))
        touched.update(new.keys()|gone.keys()); all_new.update(new); all_retired.update(gone)
        input_bytes += plan['input_bytes']
        last_sst,last_meta,current = sst,meta,nxt
    require(current==expected_after and created==all_new and retired==all_retired and events==report['compactions'],
            'aggregate MANIFEST or event delta differs')
    v._equal_json(report['after'],v._state(current),'writer final state differs')
    require(type(report['input_bytes']) is int and report['input_bytes']==input_bytes<=limits['input_bytes']
            and sum(x['size'] for x in created.values())<=report['io']['sst_write_bytes']<=limits['sst_output_bytes'],
            'aggregate byte limit exceeded')
    reason = report['stop_reason']
    if reason=='next-unit-budget':
        stop = v._plan(report['stopped_plan'],current)
        require(len(units)<request['maximum_units'] and not touched.intersection(stop['input_files'])
                and (input_bytes+stop['input_bytes']>limits['input_bytes'] or
                     stop['input_bytes']>(limits['sst_output_bytes']-report['io']['sst_write_bytes'])//2 or
                     report['io']['metadata_write_bytes']>=limits['metadata_write_bytes']), 'next unit fits budget')
    else:
        require(not report.get('stopped_plan') and (reason=='unit-limit' and len(units)==request['maximum_units']
                or reason=='no-marked-files' and len(units)<request['maximum_units'] and ats['marked_files']==0),
                'false bounded stop')
    return created,retired


def finalize(cert, before, final, reopen, logical):
    from rhea_gen14_checkpoint_prepare import verify_inspection
    require(before['proof_pass_id']!=final['proof_pass_id'] and before['mode']=='before-markers' and final['mode']=='final'
            and before['remote_generation_verified'] is False and final['remote_generation_verified'] is True
            and final['previous_checkpoint_sha256']==c.digest(cert) and final['generation']==cert['generation']+1,
            'checkpoint proofs or predecessor differ')
    variable={'mode','remote_generation_verified','proof_pass_id','verified_unix','enumeration_metrics','manifest_view',
              'remote_metadata','marker_history_sha256','sealed_physical_sha256'}
    if final['generation'] >= 19:
        workers = before['sst_read_metrics']['workers']
        check_read_metrics(before, workers)
        check_read_metrics(final, workers)
        variable.add('sst_read_metrics')
    require({k:w for k,w in before.items() if k not in variable}=={k:w for k,w in final.items() if k not in variable}
            and final['scope']==SCOPE and final['schema']==SCHEMA and final['limits']==limits_for(final['generation'])
            and before['manifest_view']==cert['manifest_view'] and final['manifest_view']['active']==final['manifest_marker']
            and final['manifest_view']['retained']==sorted([*cert['manifest_view']['retained'],cert['manifest_marker']]),
            'independent proofs differ')
    marker=final['manifest_marker']
    require(final['remote_metadata'].keys()-before['remote_metadata'].keys()=={marker}
            and all(final['remote_metadata'].get(n)==v for n,v in before['remote_metadata'].items())
            and not before['pebble_reopen_verified'] and not final['pebble_reopen_verified']
            and logical.keys()==final['remote_metadata'].keys(), 'publication or logical metadata differs')
    for name,body in logical.items():
        pin=final['remote_metadata'][name]
        require(len(body)==pin['size'] and c.raw_sha(body)==pin['sha256'], 'cold metadata differs')
    verify_inspection(reopen,final)
    validate_io(reopen['io'], final['limits'])
    return dict(final,pebble_reopen_verified=True,reopen=reopen,before_markers_proof_sha256=c.digest(before),
                final_remote_proof_sha256=c.digest(final))
