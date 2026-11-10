#!/usr/bin/env python3
"""Fixed read-only health for the explicitly restored generation-nine host.

Historical adoption guards remain immutable. This helper validates their saved
proofs, then checks only the new identities sealed by the root restoration
receipt. It never accepts a later restart automatically, starts a service,
opens Pebble, changes a queue, or writes migration state.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.request

sys.dont_write_bytecode = True
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'post-reboot-20261106'
INSTALL = OPS / 'health.py'
VERIFY = OPS / 'verify.py'
IDENTITY = OPS / 'identity.json'
ADOPTION = TRUST / 'bounded-adoption-20261106'
ADOPTION_HEALTH = ADOPTION / 'health.py'
ADOPTION_HEALTH_SHA = '27ef8e7ae0e1b70eaef02b9b37828af2d44d54dc1f703efd9d54a8a42eb32b6f'
ADOPTION_INTENT_SHA = '07b55f1af37ad35fee0d9486975f83664c7b77782a830e91328a92384a8ec13c'
ADOPTION_COMPLETED_SHA = 'ee3613fadce8c80d8f4294958130d85ca88401803229f0e611a7479fd9785208'
PARK = TRUST / 'reboot-prep-20261106T0918Z'
PARK_SHA = '74f8b07349487df8e32c10c1998de399d3977d83138e95148b1e2de6f1d2c791'
SAVED_INSPECT = PARK / 'production-container.inspect.json'
SAVED_INSPECT_SHA = 'e8bd84f8fbd3dc4126c459f802d6f40dd249f5c840b597c159d77a1251cabecc'
STATE_SHA = '22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2'
CERT_SHA = '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'
PINS_SHA = '684fbaed2cc696c0f29de500c8f1224c2569c6cfd761f7498a750223daaa455c'
BOOT_ID = '6fc54ca7-d64a-4125-98fa-d0a728485237'
OLD_BOOT_ID = '727cc0aa-6827-403b-b97c-3f7ad839528e'
KERNEL = '6.8.0-149-generic'
SCOPE = 'rhea-post-reboot-generation-nine-identities'
HEALTH_SCOPE = 'rhea-post-reboot-generation-nine-health'
VERIFICATION_SCOPE = 'rhea-post-reboot-generation-nine-verification-completed'
PRODUCTION_UNIT = 'rhea-ipfs-wasabi-rclone-mount.service'
WALKER = 'rhea-broken-pin-walk-20261026.service'
PRODUCTION_MOUNT = Path('/home/ubuntu/.ipfs-wasabi')
PRODUCTION_CACHE = Path('/data/ipfs-wasabi-cache')
LAUNCHER = Path('/home/ubuntu/source/repos/phill/Dotfiles/scripts/ipfs/rhea_wasabi_mount_start.sh')
ALIASES = Path('/home/ubuntu/.bashrc.d/020aliases.bashrc')
IPFS_ALIASES = Path('/home/ubuntu/.bashrc.d/rhea.bashrc.d/ipfs.bashrc')
ALIAS_LINK = Path('/home/ubuntu/.bashrc.d')
ALIAS_DIRECTORY = Path('/home/ubuntu/source/repos/phill/Dotfiles/.bashrc.d')
PUBLIC_INPUT_POLICY = {
    LAUNCHER: (LAUNCHER, 1000, 1000, 0o755),
    ALIASES: (ALIAS_DIRECTORY / '020aliases.bashrc', 1000, 1000, 0o664),
    IPFS_ALIASES: (ALIAS_DIRECTORY / 'rhea.bashrc.d/ipfs.bashrc', 1000, 1000, 0o644),
    Path('/usr/bin/rclone'): (Path('/usr/bin/rclone'), 0, 0, 0o755),
}
READER_CONFIG = Path('/root/.config/rclone/rhea-pebble-lab-reader-20261102.conf')
PRIVATE_INPUTS = {
    READER_CONFIG, Path('/root/.config/rclone/rclone.conf'),
    Path('/root/.config/rclone/rc-auth/wasabi-ipfs-rc.htpasswd'),
    Path('/root/.config/rclone/rc-auth/wasabi-ipfs-rc-client.json'),
    SAVED_INSPECT, INSTALL, VERIFY,
}
INPUTS = PRIVATE_INPUTS | {LAUNCHER, ALIASES, IPFS_ALIASES, Path('/usr/bin/rclone')}
SOURCE_INPUT_PINS = {
    LAUNCHER: '3ecbed1303159faf384bb1d0f55c08956fa067c7345577cecb9c3c6cba4b6bb2',
    ALIASES: '3f4aa1d09e7d2e9baecb6cd166bd153223e1e32b2a8eeb65b417f23ce600bbfc',
    IPFS_ALIASES: '637868a30f7b0dab7bedc18ce65817b3c08946730f00775fd147a561c798cc69',
    SAVED_INSPECT: SAVED_INSPECT_SHA,
    Path('/usr/bin/rclone'): 'dc1ec3109000e4d36c8d14efac6d4c4158d1b860853cb75c09dcc9f6dded420b',
}
PRODUCTION_PROPERTIES = {
    'Description': 'Rhea Wasabi IPFS rclone VFS mount with authenticated loopback RC',
    'User': 'ubuntu', 'WorkingDirectory': '/home/ubuntu', 'Restart': 'no',
    'StandardOutput': 'null', 'StandardError': 'null', 'KillMode': 'control-group',
    'TimeoutStopSec': '10min',
}
RECEIPTS = ('intent.json', 'production-start-intent.json', 'production-restored.json',
            'reader-start-intent.json', 'reader-restored.json', 'reader-metadata.json')
IDENTITY_KEYS = {
    'schema', 'scope', 'observed_unix', 'boot_id', 'kernel', 'generation', 'rewrites',
    'pending', 'state_sha256', 'checkpoint_sha256', 'pins_sha256',
    'adoption_completed_sha256', 'parking_completed_sha256', 'reader', 'production',
    'receipts', 'protected_inputs',
}
HOST_CONFIG_KEYS = ('NetworkMode', 'Privileged', 'CapAdd', 'CapDrop', 'SecurityOpt',
                    'Devices', 'RestartPolicy', 'AutoRemove')
CONFIG_KEYS = ('Image', 'Cmd', 'Entrypoint', 'User', 'WorkingDir', 'Env')
HEX = re.compile(r'[0-9a-f]{64}')
CONTAINER_GROUP = re.compile(r'/system.slice/docker-([0-9a-f]{64})\.scope')
MAX_JSON = 16 * 1024**2
MAX_INPUT = 512 * 1024**2


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def valid_pin(value):
    return (type(value) is dict and set(value) == {'bytes', 'sha256'}
            and type(value['bytes']) is int and 0 <= value['bytes'] <= MAX_INPUT
            and type(value['sha256']) is str and HEX.fullmatch(value['sha256']) is not None)


def process_identity(value):
    require(type(value) is dict and set(value) == {'pid', 'start_ticks', 'boot_id'}
            and type(value['pid']) is int and value['pid'] > 1
            and type(value['start_ticks']) is str and value['start_ticks'].isdigit()
            and int(value['start_ticks']) > 0 and value['boot_id'] == BOOT_ID,
            'restored process identity is not from the fixed new boot')
    return value


def start_command(unit, properties, argv):
    return ['/usr/bin/systemd-run', '--unit=' + unit,
            *['--property=' + key + '=' + value for key, value in properties.items()], '--', *argv]


def validate_identity(ctx, value, receipts):
    """Pure shape and launch-link validation; current processes are checked later."""
    c, old = ctx['c'], ctx['old']
    require(type(value) is dict and set(value) == IDENTITY_KEYS, 'identity receipt schema differs')
    expected = {'schema': 1, 'scope': SCOPE, 'boot_id': BOOT_ID, 'kernel': KERNEL,
                'generation': 9, 'rewrites': 5, 'pending': None, 'state_sha256': STATE_SHA,
                'checkpoint_sha256': CERT_SHA, 'pins_sha256': PINS_SHA,
                'adoption_completed_sha256': ADOPTION_COMPLETED_SHA, 'parking_completed_sha256': PARK_SHA}
    require(all(type(value.get(k)) is type(v) and value[k] == v for k, v in expected.items()),
            'identity receipt changes boot, checkpoint or policy')
    require(type(value['observed_unix']) in (int, float) and math.isfinite(value['observed_unix'])
            and value['observed_unix'] > 0, 'invalid restoration observation time')
    require(type(value['receipts']) is dict and set(value['receipts']) == set(RECEIPTS)
            and set(receipts) == set(RECEIPTS), 'restoration receipt set differs')
    for name, raw in receipts.items():
        pin = value['receipts'][name]
        require(valid_pin(pin) and len(raw) == pin['bytes'] and sha(raw) == pin['sha256'],
                'restoration receipt bytes differ: ' + name)
    inputs = value['protected_inputs']
    require(type(inputs) is dict and set(inputs) == {str(p) for p in INPUTS}
            and all(valid_pin(pin) for pin in inputs.values()), 'protected restoration input set differs')
    require(all(inputs[str(path)]['sha256'] == digest for path, digest in SOURCE_INPUT_PINS.items()),
            'preserved launcher, aliases or container snapshot differs')
    reader, production = value['reader'], value['production']
    require(type(reader) is dict and set(reader) == {'service', 'properties', 'mount', 'process'},
            'reader identity shape differs')
    process_identity(reader['process'])
    require(type(production) is dict and set(production) == {
        *ctx['w'].PROD_OFF, PRODUCTION_UNIT, 'production_process', 'service_leader_executable',
        'walker_unit_file_state', 'rc_server'}, 'production identity shape differs')
    leader = process_identity(production['production_process'])
    server = production['rc_server']
    require(type(server) is dict and set(server) == {'process', 'executable', 'cgroup', 'listener'},
            'production RC identity shape differs')
    process_identity(server['process'])
    require(len({reader['process']['pid'], leader['pid'], server['process']['pid']}) == 3,
            'restored process roles are not distinct')
    require(production['service_leader_executable'] == '/usr/bin/bash'
            and production['walker_unit_file_state'] == 'disabled'
            and server['executable'] == '/usr/bin/rclone'
            and type(server['cgroup']) is str and CONTAINER_GROUP.fullmatch(server['cgroup']),
            'restored production executable, container or walker differs')
    listener = server['listener']
    require(type(listener) is dict and set(listener) == {'address', 'port', 'pid', 'inode'}
            and listener['address'] == '127.0.0.1' and type(listener['port']) is int and listener['port'] == 5572
            and type(listener['pid']) is int and listener['pid'] == server['process']['pid']
            and type(listener['inode']) is str and listener['inode'].isdigit() and int(listener['inode']) > 0,
            'restored RC listener identity differs')
    records = {name: c.json_object(raw) for name, raw in receipts.items()}
    require(records['production-restored.json'].get('production') == production
            and records['reader-restored.json'].get('reader') == reader,
            'identity is not the recorded restoration observation')
    production_argv = start_command(PRODUCTION_UNIT, PRODUCTION_PROPERTIES, ['/usr/bin/bash', str(LAUNCHER)])
    reader_argv = start_command(old.READER_UNIT, old.READER_PROPERTIES, old.READER_ARGV)
    require(records['production-start-intent.json'].get('argv') == production_argv
            and records['reader-start-intent.json'].get('argv') == reader_argv,
            'recorded launch command differs from the original fixed command')
    metadata = records['reader-metadata.json']
    expected_metadata = {name: {key: pin[key] for key in ('size', 'sha256')}
                         for name, pin in ctx['cert']['remote_metadata'].items()}
    require(metadata.get('state') == c.checkpoint_state(ctx['cert'])
            and metadata.get('metadata') == expected_metadata
            and metadata.get('db') == str(old.READER_DB)
            and metadata.get('manifest') == ctx['cert']['manifest']
            and metadata.get('manifest_sha256') == expected_metadata[ctx['cert']['manifest']]['sha256']
            and type(metadata.get('listed_sst_files')) is int
            and metadata['listed_sst_files'] >= ctx['cert']['sst_count'],
            'restored reader metadata is not the certified generation')
    return value


def read_input(path, pin):
    """Hash a fixed input without exposing bytes; preserve private-file ownership."""
    require(path in INPUTS and valid_pin(pin), 'unscoped protected input')
    private = path in PRIVATE_INPUTS
    resolved, uid, gid, mode = (path, 0, 0, 0o600) if private else PUBLIC_INPUT_POLICY[path]
    if path in (ALIASES, IPFS_ALIASES):
        link = ALIAS_LINK.lstat()
        require(stat.S_ISLNK(link.st_mode) and link.st_uid == link.st_gid == 1000
                and Path(os.readlink(ALIAS_LINK)) == ALIAS_DIRECTORY,
                'managed alias directory link changed')
    require(path.resolve(strict=True) == resolved and resolved.resolve(strict=True) == resolved,
            'protected input resolved path changed')
    for part in (*reversed(resolved.parents), resolved):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'protected input contains an unexpected symlink')
        if private:
            require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                    'private input ancestor is not root protected')
        else:
            require(info.st_uid in (0, 1000) and info.st_gid in (0, 1000)
                    and not info.st_mode & 0o002
                    and (not info.st_mode & 0o020 or info.st_uid == info.st_gid == 1000),
                    'managed source ownership or permissions changed')
        if part != resolved:
            require(stat.S_ISDIR(info.st_mode), 'protected input ancestor is not a directory')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == pin['bytes'],
            'protected input type or size differs')
    require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode),
            'protected input leaf ownership or mode differs')
    original = (info.st_dev, info.st_ino, info.st_size, info.st_uid, info.st_gid, info.st_mode)
    digest = hashlib.sha256()
    with os.fdopen(os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_uid, opened.st_gid, opened.st_mode) == original,
                'protected input changed during open')
        remaining = pin['bytes']
        while remaining:
            chunk = stream.read(min(1024**2, remaining))
            require(bool(chunk), 'protected input became shorter')
            digest.update(chunk)
            remaining -= len(chunk)
        require(stream.read(1) == b'', 'protected input became longer')
    current = resolved.lstat()
    require((current.st_dev, current.st_ino, current.st_size, current.st_uid, current.st_gid, current.st_mode) == original
            and path.resolve(strict=True) == resolved
            and digest.hexdigest() == pin['sha256'], 'protected input changed')


def validate_docker(saved, current, server):
    """Compare immutable launch settings, treating only documented lists as sets."""
    require(type(saved) is list and len(saved) == 1 and type(current) is list and len(current) == 1,
            'Docker inspect is absent or ambiguous')
    before, after = saved[0], current[0]
    require(type(before) is dict and type(after) is dict, 'invalid Docker inspect record')
    match = CONTAINER_GROUP.fullmatch(server['cgroup'])
    require(match is not None and after.get('Id') == match.group(1), 'Docker container is not the sealed RC scope')
    state = after.get('State', {})
    require(state.get('Running') is True and state.get('Paused') is False
            and state.get('Restarting') is False and state.get('Dead') is False
            and state.get('OOMKilled') is False and type(state.get('Pid')) is int
            and state['Pid'] == server['process']['pid'], 'Docker process is not the sealed running RC server')
    require(type(before.get('Image')) is str and before['Image'].startswith('sha256:')
            and after.get('Image') == before['Image'], 'production container image changed')
    for key in CONFIG_KEYS:
        require(key in before.get('Config', {}) and key in after.get('Config', {})
                and after['Config'][key] == before['Config'][key], 'production Docker Config changed: ' + key)
    for key in HOST_CONFIG_KEYS:
        require(key in before.get('HostConfig', {}) and key in after.get('HostConfig', {})
                and after['HostConfig'][key] == before['HostConfig'][key], 'production Docker HostConfig changed: ' + key)
    require(after['HostConfig']['RestartPolicy'].get('Name') == 'no'
            and after['HostConfig']['AutoRemove'] is True, 'production container restart/removal policy differs')
    binds = []
    for item in (before, after):
        rows = item.get('HostConfig', {}).get('Binds')
        require(type(rows) is list and all(type(row) is str for row in rows)
                and len(rows) == len(set(rows)), 'duplicate or invalid Docker bind')
        binds.append(sorted(rows))
    require(binds[0] == binds[1], 'production Docker bind set changed')
    mounts = []
    for item in (before, after):
        rows = item.get('Mounts')
        require(type(rows) is list and all(type(row) is dict and type(row.get('Destination')) is str for row in rows),
                'invalid Docker mount list')
        indexed = {row['Destination']: row for row in rows}
        require(len(indexed) == len(rows), 'duplicate Docker mount destination')
        mounts.append(indexed)
    require(mounts[0] == mounts[1], 'production Docker mount mapping changed')
    return {'container_id': after['Id'], 'image_id': after['Image'], 'configuration_matches_saved': True}


def listener_owner(server):
    expected = server['listener']
    rows = []
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) > 9 and fields[1] == '0100007F:15C4' and fields[3] == '0A':
            rows.append(fields[9])
    require(rows == [expected['inode']], 'production RC listener changed or is ambiguous')
    target = 'socket:[' + expected['inode'] + ']'
    found = False
    for fd in (Path('/proc') / str(server['process']['pid']) / 'fd').iterdir():
        try:
            found = found or os.readlink(fd) == target
        except FileNotFoundError:
            continue
    require(found, 'sealed rclone process does not own RC listener')
    return expected


def production_observation(ctx):
    rt, w, c = ctx['rt'], ctx['w'], ctx['c']
    expected = ctx['identity']['production']
    units = {unit: rt.host.service(unit) for unit in (*w.PROD_OFF, PRODUCTION_UNIT)}
    for unit in w.PROD_OFF:
        item = units[unit]
        require(item.get('ActiveState') == 'inactive' and item.get('MainPID') == '0'
                and item.get('LoadState') in (('loaded', 'not-found') if unit == w.PROD_OFF[0] else ('loaded',)),
                'production Kubo or walker is not inactive')
    rt.host.no_hidden_wasabi_kubo()
    service = units[PRODUCTION_UNIT]
    leader = expected['production_process']
    require(service.get('LoadState') == 'loaded' and service.get('ActiveState') == 'active'
            and service.get('SubState') == 'running' and service.get('MainPID') == str(leader['pid'])
            and service.get('User') == 'ubuntu' and service.get('Group') == ''
            and service.get('FragmentPath') == '/run/systemd/transient/' + PRODUCTION_UNIT
            and service.get('ControlGroup') == '/system.slice/' + PRODUCTION_UNIT
            and not service.get('DropInPaths') and service.get('NeedDaemonReload') == 'no',
            'production transient service differs from the restored service')
    require(rt._process_identity(leader['pid']) == leader
            and os.readlink(Path('/proc') / str(leader['pid']) / 'exe') == '/usr/bin/bash'
            and (Path('/proc') / str(leader['pid']) / 'cmdline').read_bytes().split(b'\0')[:-1]
            == [b'/usr/bin/bash', str(LAUNCHER).encode()], 'production launcher process changed')
    wanted = dict(PRODUCTION_PROPERTIES)
    wanted['TimeoutStopUSec'] = wanted.pop('TimeoutStopSec')
    raw = rt.host.run([rt.host.systemctl, 'show', PRODUCTION_UNIT, '--property=' + ','.join(wanted)])
    props = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    require(props == wanted, 'production transient properties changed')
    raw = rt.host.run([rt.host.systemctl, 'show', WALKER, '--property=Id,UnitFileState'])
    props = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    require(props == {'Id': WALKER, 'UnitFileState': 'disabled'}, 'walker boot policy changed')
    server = expected['rc_server']
    proc = Path('/proc') / str(server['process']['pid'])
    require(rt._process_identity(server['process']['pid']) == server['process']
            and os.readlink(proc / 'exe') == '/usr/bin/rclone'
            and (proc / 'cgroup').read_text().splitlines() == ['0::' + server['cgroup']],
            'production rclone process or Docker scope changed')
    listener_owner(server)
    container_id = CONTAINER_GROUP.fullmatch(server['cgroup']).group(1)
    docker = rt.host.run(['/usr/bin/docker', 'inspect', container_id])
    validate_docker(json.loads(ctx['saved_inspect']), json.loads(docker), server)
    rows = [row for row in w.mount_rows(Path('/proc/self/mountinfo').read_text())
            if row['target'] == str(PRODUCTION_MOUNT)]
    require(len(rows) == 1 and rows[0]['type'] == 'fuse.rclone' and rows[0]['root'] == '/'
            and 'rw' in rows[0]['options']
            and re.fullmatch(r'wasabi-ca-central-1(?:\{[A-Za-z0-9_-]{1,64}\})?:ipfs-remote-mount/rhea', rows[0]['source']),
            'production mount source or identity differs')
    result = dict(units, production_process=leader, service_leader_executable='/usr/bin/bash',
                  walker_unit_file_state='disabled', rc_server=server)
    require(result == expected, 'production observation changed from the restoration receipt')
    return result


def _retained_adoption(ctx):
    h, c, w = ctx['h'], ctx['c'], ctx['w']
    files, state, pins_sha = h._phase_files(ctx, 'after', ADOPTION_INTENT_SHA)
    require(sha(files[h.STATE]) == STATE_SHA and pins_sha == PINS_SHA
            and state['generation'] == 9 and state['rewrites'] == 5 and state['pending'] is None,
            'post-reboot state is not the exact adopted endpoint')
    path = ADOPTION / 'completed.json'
    raw = w.read_protected(path, mode=0o600, max_bytes=MAX_JSON)
    require(sha(raw) == ADOPTION_COMPLETED_SHA, 'adoption completion changed')
    files[path] = raw
    done = c.json_object(raw)
    intent = c.json_object(files[ADOPTION / 'intent.json'])
    verification = h.validate_completed(done, intent, ADOPTION_INTENT_SHA)
    blobs = {}
    for name in ('intent.json', 'result.json', 'metrics.json', 'completed.json'):
        path = ADOPTION / verification['path'] / name
        blobs[name] = w.read_protected(path, mode=0o600, max_bytes=MAX_JSON)
        files[path] = blobs[name]
    for field, name in (('result_sha256', 'result.json'), ('metrics_sha256', 'metrics.json'),
                        ('receipt_sha256', 'completed.json')):
        require(sha(blobs[name]) == verification[field], 'retained adoption proof changed')
    failure = ADOPTION / verification['path'] / 'failure.json'
    require(not failure.exists() and not failure.is_symlink(), 'accepted adoption proof has a failure receipt')
    measurement = h.validate_acceptance(ctx, blobs, intent, done, verification)
    comparison = h.exact_module(*h.HELPERS['comparison'], 'post_reboot_retained_adoption_metrics')
    comparison.validate_pass(measurement['metrics'], measurement['enumeration'], measurement['listing_guard'], candidate=True)
    return files, state


def load(*, manifest_sha256=None):
    require(os.geteuid() == 0 and Path(__file__).absolute() == INSTALL, 'fixed root health installation required')
    # Use the existing protected loader without executing its PID-bound observer.
    import types
    for part in (*reversed(ADOPTION_HEALTH.parents), ADOPTION_HEALTH):
        info = part.lstat()
        require(info.st_uid == info.st_gid == 0 and not stat.S_ISLNK(info.st_mode)
                and not info.st_mode & 0o022, 'historical health source is not protected')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            'historical health source mode differs')
    with os.fdopen(os.open(ADOPTION_HEALTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        source = stream.read(MAX_JSON + 1)
    require(len(source) <= MAX_JSON and sha(source) == ADOPTION_HEALTH_SHA, 'historical health source changed')
    h = types.ModuleType('post_reboot_adoption_health')
    h.__file__ = str(ADOPTION_HEALTH)
    sys.modules[h.__name__] = h
    exec(compile(source, str(ADOPTION_HEALTH), 'exec'), h.__dict__)
    ctx = dict(h.load(), h=h)
    c, w = ctx['c'], ctx['w']
    w.secure_path(INSTALL, leaf_mode=0o600)
    w.secure_path(OPS, leaf_mode=0o700)
    files, state = _retained_adoption(ctx)
    parking_raw = w.read_protected(PARK / 'completed.json', mode=0o600, max_bytes=MAX_JSON)
    require(sha(parking_raw) == PARK_SHA, 'parking completion changed')
    parking = c.json_object(parking_raw)
    require(parking.get('boot_id') == OLD_BOOT_ID and parking.get('generation') == 9
            and parking.get('rewrites') == 5 and parking.get('pending') is None
            and parking.get('rclone_processes') == []
            and parking.get('rclone_mounts_all_observed_namespaces') == [], 'parking endpoint differs')
    files[PARK / 'completed.json'] = parking_raw
    completed_raw = None
    if manifest_sha256 is None:
        completed_raw = w.read_protected(OPS / 'verification/completed.json', mode=0o600, max_bytes=MAX_JSON)
        completed = c.json_object(completed_raw)
        require(completed.get('scope') == VERIFICATION_SCOPE and completed.get('verified') is True,
                'post-reboot final verification is incomplete')
        manifest_sha256 = completed.get('identity_sha256')
    require(type(manifest_sha256) is str and HEX.fullmatch(manifest_sha256), 'exact identity receipt hash required')
    raw = w.read_protected(IDENTITY, mode=0o600, max_bytes=MAX_JSON)
    require(sha(raw) == manifest_sha256, 'identity receipt changed')
    files[IDENTITY] = raw
    receipts = {name: w.read_protected(OPS / name, mode=0o600, max_bytes=MAX_JSON) for name in RECEIPTS}
    files.update({OPS / name: blob for name, blob in receipts.items()})
    identity = validate_identity(ctx, c.json_object(raw), receipts)
    for path in INPUTS:
        read_input(path, identity['protected_inputs'][str(path)])
    saved = w.read_protected(SAVED_INSPECT, mode=0o600, max_bytes=MAX_JSON)
    require(sha(saved) == SAVED_INSPECT_SHA, 'saved production Docker configuration changed')
    files[SAVED_INSPECT] = saved
    ctx.update(static_files=files, adopted_state=state, identity=identity, identity_raw=raw,
               identity_sha256=manifest_sha256, saved_inspect=saved)
    if completed_raw is not None:
        blobs = {name: w.read_protected(OPS / 'verification' / name, mode=0o600, max_bytes=MAX_JSON)
                 for name in ('intent.json', 'result.json', 'metrics.json', 'completed.json')}
        require(blobs['completed.json'] == completed_raw, 'verification completion changed during load')
        failure = OPS / 'verification/failure.json'
        require(not failure.exists() and not failure.is_symlink(), 'post-reboot proof has a failure receipt')
        runner = h.exact_module(VERIFY, identity['protected_inputs'][str(VERIFY)]['sha256'], 'post_reboot_retained_verifier')
        comparison = h.exact_module(*h.HELPERS['comparison'], 'post_reboot_retained_comparison')
        equivalence = h.exact_module(*h.HELPERS['equivalence'], 'post_reboot_retained_equivalence')
        runner.validate_retained(ctx, blobs, comparison=comparison, equivalence=equivalence)
        files.update({OPS / 'verification' / name: blob for name, blob in blobs.items()})
    return ctx


def _unchanged(ctx):
    ctx['h']._unchanged(ctx, ctx['static_files'])
    for path in INPUTS:
        read_input(path, ctx['identity']['protected_inputs'][str(path)])


def observe(ctx, *, authenticated_rc=True):
    rt, w, old, rc, c = (ctx[k] for k in ('rt', 'w', 'old', 'rc', 'c'))
    require(rt.host.locked and not rt.stop_present(), 'post-reboot observation requires the protected idle lock')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT_ID
            and os.uname().release == KERNEL, 'host rebooted or kernel changed after identity reconciliation')
    _unchanged(ctx)
    writer = old.writer_absent(rt)
    expected_reader = ctx['identity']['reader']
    reader = old.reader_observation(rt, expected_reader['process']['pid'])
    require(reader == expected_reader, 'reader changed from the restored identity')
    old.no_other_lab_users(rt, reader['process']['pid'])
    before = production_observation(ctx)
    disk = None
    if authenticated_rc:
        helper = rc.exact_module(rc.HELPER, rc.HELPER_SHA256, 'post_reboot_authenticated_rc', protected=False)
        require(helper.API == rc.API and helper.CLIENT == rc.CLIENT, 'authenticated RC helper scope differs')
        w.secure_path(rc.CLIENT, leaf_mode=0o600)
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}), rc.NoRedirect()))
        stats = helper.call_rc('vfs/stats', {'fs': rc.FS}, client=rc.CLIENT)
        queue = helper.call_rc('vfs/queue', {'fs': rc.FS}, client=rc.CLIENT)
        rc.validate_rc(stats, queue)
        w.clean_queue(stats, queue)
        disk = {key: stats['diskCache'][key] for key in
                ('bytesUsed', 'uploadsQueued', 'uploadsInProgress', 'erroredFiles', 'outOfSpace')}
    after = production_observation(ctx)
    require(before == after and old.reader_observation(rt, reader['process']['pid']) == reader,
            'restored process changed during health observation')
    old.writer_absent(rt)
    require(all(path.is_dir() for path in (rt.profile.cache, old.READER_CACHE, PRODUCTION_CACHE)),
            'retained cache directory missing')
    require(not rt.stop_present() and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT_ID,
            'stop sentinel or boot changed during observation')
    _unchanged(ctx)
    return {'schema': 1, 'scope': HEALTH_SCOPE, 'observed_unix': time.time(), 'boot_id': BOOT_ID,
            'kernel': KERNEL, 'identity_sha256': ctx['identity_sha256'], 'state_sha256': STATE_SHA,
            'pins_sha256': PINS_SHA, 'checkpoint_sha256': CERT_SHA, 'generation': 9, 'rewrites': 5,
            'pending': None, 'state': c.checkpoint_state(ctx['cert']), 'reader_process': reader['process'],
            'production_service_process': after['production_process'], 'production_rc_process': after['rc_server']['process'],
            'production_rc_checked': authenticated_rc, 'production_disk_cache': disk,
            'production_identity_sha256': sha(canonical(after)), 'production_rc_identity_sha256': sha(canonical(after['rc_server'])),
            'writer': {key: writer[key] for key in ('ActiveState', 'SubState', 'MainPID', 'Result', 'ExecMainStatus')},
            'writer_mount_and_socket_absent': True, 'reader_and_writer_caches_retained': True,
            'kubo_and_walker_inactive': True, 'walker_unit_file_state': 'disabled',
            'free_bytes': rt.free_bytes(), 'protected_anchors_unchanged': True}


def main():
    require(sys.argv[1:] == ['--check'], 'explicit completed post-reboot check required')
    ctx = load()
    with ctx['rt'].lock():
        result = observe(ctx)
    try:
        print(json.dumps(result), flush=True)
    except OSError:
        pass


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        try:
            print('Post-reboot health check did not complete (' + type(exc).__name__ + ').', file=sys.stderr)
        except OSError:
            pass
        raise SystemExit(1) from None
