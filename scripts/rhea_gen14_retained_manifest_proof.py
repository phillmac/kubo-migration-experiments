"""Verify the protected marker portion of a generation-14 create-only transition.

Inputs are independent, complete physical marker-version enumerations from
rhea_multi_sst_marker_gate.marker_history. CURRENT, MANIFEST closure, SSTs,
quarantine and the read-only reopen still require their own proofs.
"""
import hashlib
import re

from rhea_multi_sst_signed_admission import require

MANIFEST = re.compile(r'marker\.manifest\.([0-9]{6,})\.MANIFEST-([0-9]{6,})\Z')
FORMAT = re.compile(r'marker\.format-version\.[0-9]{6,}\.[0-9]{3,}\Z')
EMPTY_SHA = hashlib.sha256(b'').hexdigest()


def version_rows(rows):
    require(type(rows) is list, 'complete marker history required')
    result, latest = {}, {}
    for row in rows:
        require(type(row) is dict, 'invalid marker row')
        name = row.get('name')
        require(type(name) is str and (MANIFEST.fullmatch(name) or FORMAT.fullmatch(name)), 'unknown marker class')
        deleted = row.get('delete')
        fields = {'name', 'version_id', 'latest', 'delete'}
        require(type(deleted) is bool and type(row.get('latest')) is bool
                and set(row) == (fields if deleted else fields | {'size', 'etag'}), 'invalid history fields')
        require(deleted or (type(row['size']) is int and row['size'] == 0 and type(row['etag']) is str
                            and bool(row['etag'])), 'invalid empty marker metadata')
        vid = row['version_id']
        require(type(vid) is str and vid not in ('', 'null') and (name, vid) not in result, 'duplicate/invalid version')
        result[name, vid] = row
        latest[name] = latest.get(name, 0) + int(row['latest'])
    require(all(count == 1 for count in latest.values()), 'ambiguous latest protected version')
    return result


def latest_row(name, pin):
    require(set(pin) == {'version_id', 'etag', 'size', 'sha256'} and pin['sha256'] == EMPTY_SHA
            and type(pin['size']) is int and pin['size'] == 0, 'empty version-pinned marker required')
    return dict(name=name, version_id=pin['version_id'], etag=pin['etag'], size=0, delete=False, latest=True)


def certified_baseline(previous_metadata, preopen):
    names = [name for name in previous_metadata if name.startswith('marker.')]
    manifests = [name for name in names if MANIFEST.fullmatch(name)]
    formats = [name for name in names if FORMAT.fullmatch(name)]
    require(len(names) == 2 and len(manifests) == len(formats) == 1 and formats[0].endswith('.013'),
            'expected certified format-013 predecessor with one active manifest')
    old = manifests[0]
    baseline = version_rows(preopen)
    active = {row['name']: row for row in baseline.values() if row['latest'] and not row['delete']}
    require(active == {name: latest_row(name, previous_metadata[name]) for name in names},
            'pre-open history differs from certified markers')
    return old, formats[0], baseline


def retained_manifest_view(previous_metadata, new_marker, preopen, fresh, published_pin=None):
    """Return the logical marker selection only when raw history proves the exact transition."""
    old, format_marker, baseline = certified_baseline(previous_metadata, preopen)
    new = MANIFEST.fullmatch(new_marker)
    require(new is not None and all(int(n) > int(o) for n, o in zip(new.groups(), MANIFEST.fullmatch(old).groups()))
            and all(name != new_marker for name, _ in baseline),
            'manifest generation, file number, or prior key history differs')
    observed = version_rows(fresh)
    expected = dict(baseline)
    if published_pin is not None:
        row = latest_row(new_marker, published_pin)
        expected[new_marker, row['version_id']] = row
    require(observed == expected, 'physical marker versions, latest flags, or publication differ')
    return dict(active=new_marker if published_pin is not None else old,
                retained=[old] if published_pin is not None else [], format=format_marker)
