"""Full-clone proofs for a two-SST checkpoint that only creates Wasabi objects."""
from pathlib import Path

import rhea_gen14_retained_manifest_proof as markers
import rhea_multi_sst_checkpoint_controller as c
import rhea_wasabi_lab_mount as lab

v = c.verifier
p = v.proof
require = c.require
PREFIX = v.PREFIX


def physical_metadata(db):
    """Read every non-SST leaf from the actual directory, including retained originals."""
    names = [f for f in db.iterdir() if not p.base.SST_NAME.fullmatch(f.name)]
    require(len(names) <= p.base.MAX_METADATA_FILES, 'too many metadata leaves')
    result = {}
    for path in names:
        require(p.base.META_NAME.fullmatch(path.name) and not path.is_symlink() and path.is_file()
                and path.stat().st_size <= p.base.MAX_METADATA_BYTES, 'unexpected metadata leaf: ' + path.name)
        result[path.name] = path.read_bytes()
    c.metadata_bounds(result)
    return result


def writer_metadata(certificate, physical):
    """The writer sees only independently pinned logical metadata. Audit raw names first."""
    logical = certificate['remote_metadata']
    retained = certificate.get('retained_remote_metadata', {})
    require(not (logical.keys() & retained.keys()) and physical.keys() == (logical.keys() | retained.keys()),
            'physical metadata inventory differs from certificate')
    for name, pin in {**logical, **retained}.items():
        require(len(physical[name]) == pin['size'] and c.raw_sha(physical[name]) == pin['sha256'],
                'physical metadata differs from certified bytes: ' + name)
    selection = certificate.get('manifest_view')
    if retained:
        require(selection is not None and selection['active'] == certificate['manifest_marker']
                and set(selection['retained']) == {name for name in retained if markers.MANIFEST.fullmatch(name)},
                'retained names do not identify a proved successor')
    return {name: physical[name] for name in logical}


def enumerate_markers(client):
    rows = []
    pages = client.get_paginator('list_object_versions').paginate(
        Bucket=v.BUCKET, Prefix=PREFIX + 'marker.', PaginationConfig={'PageSize': 1000})
    for index, page in enumerate(pages):
        require(index < 16, 'marker history exceeded bound')
        for field, deleted in (('Versions', False), ('DeleteMarkers', True)):
            for item in page.get(field, []):
                key = item['Key']
                require(key.startswith(PREFIX + 'marker.'), 'unexpected marker prefix')
                row = dict(name=key[len(PREFIX):], version_id=item['VersionId'], delete=deleted, latest=item['IsLatest'])
                if not deleted:
                    row.update(size=item['Size'], etag=item['ETag'])
                rows.append(row)
    rows.sort(key=lambda row: (row['name'], row['version_id']))
    markers.version_rows(rows)
    return rows


def baseline_digest(latest, deleted, additions):
    require(additions <= latest.keys() and additions.isdisjoint(deleted), 'expected new object missing or tombstoned')
    return c.digest(dict(objects=sorted((k, row['VersionId'], row['ETag'], row['Size'])
                                        for k, row in latest.items() if k not in additions),
                         tombstones=sorted((k, row['VersionId']) for k, row in deleted.items())))


def ledger_context(cert, previous_sha=v.GENERATION13_SHA256):
    ledger = lab.load_ledger(lab.LEDGER.read_bytes())
    baseline = p._baseline_pins(ledger)
    current, lineage = p._lineage(cert, baseline)
    if previous_sha == v.GENERATION13_SHA256:
        require(v._predecessor(cert, previous_sha) == 1 and lineage['rewrite_operations'] == 9,
                'expected the generation-13 certificate and nine rewrites')
    else:
        from rhea_clone_batch_proof import predecessor
        predecessor(cert, previous_sha)
    return ledger, baseline, current, lineage


def scan(client, baseline):
    metrics = {}
    latest, deleted = p._collect_latest(client, baseline, enumeration_workers=4, enumeration_metrics=metrics)
    return latest, deleted, metrics


def anchored_inventory(client, cert, previous_sha=v.GENERATION13_SHA256):
    ledger, baseline, current, lineage = ledger_context(cert, previous_sha)
    latest, deleted, metrics = scan(client, baseline)
    pins = {**cert.get('retained_remote_metadata', {}), **cert['remote_metadata']}
    expected = {PREFIX+name: pin for name, pin in {**current, **pins}.items()}
    for key, entry in ledger.items():
        if not key.startswith(PREFIX):
            expected[key] = dict(size=entry.size, version_id=entry.version_id, etag=entry.etag)
    for name, pin in lineage['retired'].items():
        key = PREFIX + name
        p._head_matches(client, name, pin, historical=True)
        old = cert['retired_sst_states'][name]
        if old['state'] == 'unchanged-unreferenced-latest':
            require(old['version_id'] == pin['version_id'], 'retired version differs')
            expected[key] = pin
        else:
            require(old['state'] == 'latest-delete-marker' and key in deleted
                    and deleted[key]['VersionId'] == old['delete_marker_version_id'], 'retired SST tombstone differs')
    require(latest.keys() == expected.keys() and all(p._same_version(latest[k], pin) for k, pin in expected.items()),
            'full current object inventory differs from certified generation 13')
    require(all(not key.endswith('.sst') or key.startswith(PREFIX) and key[len(PREFIX):] in lineage['retired']
                for key in deleted), 'unexpected SST tombstone')
    history = enumerate_markers(client)
    if previous_sha == v.GENERATION13_SHA256:
        markers.certified_baseline(pins, history)
    else:
        from rhea_clone_batch_proof import check_opening, marker_view
        marker_view(cert, history, history)
        check_opening(cert, latest, deleted)
    return dict(baseline_sha256=baseline_digest(latest, deleted, set()), latest=len(latest), deleted=len(deleted),
                marker_history=history, enumeration_metrics=metrics)


def closed_metadata(cert, old, new):
    require(old.keys() == cert['remote_metadata'].keys() and all(
        len(body) == cert['remote_metadata'][name]['size'] and c.raw_sha(body) == cert['remote_metadata'][name]['sha256']
        for name, body in old.items()), 'initial logical metadata incomplete')
    require(new.keys().isdisjoint(cert.get('retained_remote_metadata', {})), 'retired metadata name reused')
    c.metadata_bounds(new)
    for key in old.keys() & new.keys():
        require(new[key] == old[key], 'existing metadata would require replacement: ' + key)
    info = p._marker_info(new)
    changed = p.changed_marker_names(cert, new)
    require(new.get('CURRENT') == old['CURRENT'] == b'MANIFEST-000000\n' and
            info['after_format'] == cert['after_format'] == '013' and new.get('LOCK') == b''
            and changed == [info['manifest_marker']] and info['manifest'] in new
            and any(name.startswith('OPTIONS-') for name in new), 'closed staged activation differs')
    _, stats = p._decode_tables(new[info['manifest']])
    require(stats['min_unflushed_log'] > 0 and f"{stats['min_unflushed_log']:06d}.log" in new, 'closed WAL missing')
    return info


def verify(client, opening, cert, old, new, writer, hashes, published=None, *, previous_sha=v.GENERATION13_SHA256):
    """Each invocation enumerates the full physical prefix, checks historical pins and hashes new SSTs."""
    import secrets
    import time
    info = closed_metadata(cert, old, new)
    _, baseline, current, lineage = ledger_context(cert, previous_sha)
    prior = p._metadata_pins(cert)
    p._validate_previous(cert, previous_sha, prior)
    old_data = p._get_bytes(client, cert['manifest'], prior[cert['manifest']])
    require(old_data == old[cert['manifest']], 'predecessor manifest differs')
    before, bs = p._decode_tables(old_data)
    after, ats = p._decode_tables(new[info['manifest']])
    require({name: row['size'] for name, row in before.items()} == {name: pin['size'] for name, pin in current.items()}
            and p.base.inventory_digest(p._inventory(before)) == cert['sst_inventory_sha256']
            and bs['marked_files'] == cert['marked_after'], 'prior manifest differs from certified SST lineage')
    successor = previous_sha != v.GENERATION13_SHA256
    if successor:
        import rhea_clone_batch_proof as bulk
        created, retired = bulk.validate_batch(writer, before, after, bs, ats, hashes)
    else:
        created, retired = v.validate_batch(writer, before, after, bs, ats, '013', '013', hashes)
        require(writer['physical_compactions'] == len(writer['units']) == 2, 'expected two pilot rewrites')
    count = len(writer['units'])
    require(not created.keys() & (baseline.keys() | lineage['created'].keys()), 'reused SST name')
    marker = info['manifest_marker']
    expected_new = (new.keys() - old.keys()) | created.keys()
    if published is None:
        expected_new.remove(marker)
    marker_before = enumerate_markers(client)
    view = (bulk.marker_view(cert, opening['marker_history'], marker_before, marker, published) if successor else
            markers.retained_manifest_view(prior, marker, opening['marker_history'], marker_before, published))
    latest, deleted, metrics = scan(client, baseline)
    require(baseline_digest(latest, deleted, {PREFIX+n for n in expected_new}) == opening['baseline_sha256'],
            'an existing physical object or tombstone changed during the trial')
    logical, retained_meta = {}, dict(cert.get('retained_remote_metadata', {}))
    for name, pin in retained_meta.items():
        require(p._same_version(latest[PREFIX+name], pin), 'retained metadata version changed')
    for name in sorted(old.keys() | new.keys()):
        if name == marker and published is None:
            continue
        data = new[name] if name in new else old[name]
        pin = p._row_pin(latest[PREFIX+name], c.raw_sha(data))
        require(pin['size'] == len(data) and p._get_bytes(client, name, pin) == data, 'closed metadata mismatch')
        p._head_matches(client, name, pin)
        require(name not in prior or pin == prior[name], 'existing metadata version changed')
        if name == marker:
            require(pin == published, 'published marker version differs')
        (logical if name in new else retained_meta)[name] = pin
    created_versions = {name: p._hash_new_sst(client, name, latest[PREFIX+name], hashes[name]) for name in created}
    retired_states = dict(cert['retired_sst_states'])
    for name in retired:
        pin = current[name]
        p._head_matches(client, name, pin, historical=True)
        require(p._same_version(latest[PREFIX+name], pin), 'retired predecessor payload changed')
        lineage['retired'][name] = pin
        retired_states[name] = dict(state='unchanged-unreferenced-latest', version_id=pin['version_id'])
    lineage['created'].update(created_versions)
    lineage['rewrite_operations'] += count
    require(enumerate_markers(client) == marker_before, 'marker history changed during proof')
    return dict(info, schema=bulk.SCHEMA if successor else v.CERTIFICATE_SCHEMA, scope=bulk.SCOPE if successor else v.SCOPE,
                generation=cert['generation']+1, batch_checkpoint_count=cert.get('batch_checkpoint_count',0)+1,
                anchor_checkpoint_sha256=bulk.ANCHOR if successor else v.GENERATION13_SHA256, physical_compactions=count,
                physical_rewrite_total=lineage['rewrite_operations'], unit_evidence=writer['units'],
                limits=dict(bulk.LIMITS if successor else v.LIMITS), historical_verifier_sha256=v.HISTORICAL_VERIFIER_SHA256,
                scanner_sha256=p.SCANNER_SHA256, enumeration_workers=4, proof_pass_id=secrets.token_hex(16),
                bucket=v.BUCKET, prefix='rhea/', mode='final' if published else 'before-markers', action=writer['action'],
                verified_unix=time.time(), previous_checkpoint_sha256=previous_sha, go_report_sha256=c.digest(writer),
                closed_output_hashes_sha256=c.digest(hashes), decoder_sha256=p.DECODER_SHA256, ledger_sha256=p.LEDGER_SHA256,
                remote_generation_verified=published is not None, pebble_reopen_verified=False, changed_markers=[marker],
                marked_after=ats['marked_files'], manifest_stats=ats, sst_count=len(after),
                sst_bytes=sum(row['size'] for row in after.values()), sst_inventory_sha256=p.base.inventory_digest(p._inventory(after)),
                sst_lineage=lineage, unchanged_sst_versions=len(current)-len(retired),
                new_sst_payload_bytes_downloaded=sum(pin['size'] for pin in created_versions.values()),
                unchanged_sst_payload_bytes_downloaded=0, retired_sst_states=retired_states,
                created_sst_versions=created_versions, remote_metadata=logical, retained_remote_metadata=retained_meta,
                latest_delete_markers=len(deleted), physical_baseline_sha256=opening['baseline_sha256'],
                marker_history_sha256=c.digest(marker_before), manifest_view=view, enumeration_metrics=metrics,
                **({'sealed_physical_sha256': baseline_digest(latest,deleted,set())} if successor else {}))


def finalize(before, final, reopen, physical):
    require(before['physical_baseline_sha256'] == final['physical_baseline_sha256']
            and before['retained_remote_metadata'] == final['retained_remote_metadata']
            and before['manifest_view']['active'] in final['manifest_view']['retained']
            and final['manifest_view']['active'] == final['manifest_marker'], 'retained publication evidence differs')
    return v.finalize_checkpoint(before, final, reopen, writer_metadata(final, physical))
