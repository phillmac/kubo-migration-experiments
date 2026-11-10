#!/usr/bin/env python3
"""Reader-restored evidence and dry-run planning. NOT DEPLOYED / NOT LIVE TESTED.

No authorization, signer, nonce consumption, handoff or mutation is provided.
Only probe_reader_restored() can execute a child: the fixed historical health
witness, which takes the historical lock itself. Never call it while locked.
Offline APIs accept evidence and a clock explicitly; the root probe does not.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import socket
import stat
import subprocess
import time

import rhea_multi_sst_signed_admission as a

require = a.require
Refusal = a.Refusal
sha = a.sha
canonical = a.canonical
TRUST = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101')
OPS = TRUST / 'pacing-batch2-20261107'
HEALTH = OPS / 'health.py'
HEALTH_SHA256 = '2781718c06389a0753cc23b6ff39d97bac388f492399dbb1bb637d57dbf4db1e'
RESTORED = OPS / 'finalization/reader-restored.json'
RESTORED_SHA256 = 'a306a23027ccaf1fd7f6c3a130af6723dea51f382ba780d0676d4435d5ab4b7f'
FINALIZATION = OPS / 'finalization/completed.json'
FINALIZATION_SHA256 = '4803afbd28b0e9bf6d2e0de4213b809735c1d1d4b743dd4e6489fb29e7ef6fd3'
STATE = TRUST / 'full-clone-steps/state.json'
PINS = TRUST / 'full-clone-batch2-step-pins.json'
CLOSE = TRUST / 'full-clone-steps/checkpoints/000004-failed-step-close-01.json'
CLOSE_SHA256 = '066cd75f6af19b51bbbbd647589203b26e9fb03e41b240b878401c405451152d'
LOCK = Path('/run/rhea-wasabi-lab/writer.lock')
STOP = Path('/run/rhea-wasabi-lab/full-clone-step-budget-stop')
READER_UNIT = 'rhea-pebble-lab-reader-fast-mount-20261102.service'
READER_MOUNT = '/mnt/rhea-pebble-lab-reader-20261102'
WRITER_MOUNT = '/mnt/rhea-pebble-lab-writable-20261102'
WRITER_SOCKET = Path('/run/rhea-wasabi-lab/full-clone.sock')
CACHES = ('/data/rhea-pebble-lab-reader-cache-fast-20261102',
          '/data/rhea-pebble-lab-real-cache-20261102', '/data/ipfs-wasabi-cache')
MAX_AGE = 120
MAX_BYTES = 16 * 1024**2

# Immutable historical pins below are literal review inputs, never loaded from
# caller documents at runtime. The health report itself contains ONLY gen10-13.
BASELINE_CHECKPOINT_SHA256 = 'bb367de3908fd0c59984a4ce55410f9e88340a038d8d1d357bac404d5d88489c'
CERTIFICATES = (('rhea-full-clone-000001-ratchet6-20261103.json',
  'full-clone-steps/checkpoints/000001-ratchet6.json',
  '4ae193b3c8d88b3be8405c90b1beb1a70aba41c3057c9127dd40f254d19ce809'),
 ('rhea-full-clone-000002-ratchet7-20261103.json',
  'full-clone-steps/checkpoints/000002-ratchet7.json',
  '65d72c8c2c30f644613d39d193a285b2a7007f914ed05cca1262705cb5b53d46'),
 ('rhea-full-clone-000003-ratchet10-20261103.json',
  'full-clone-steps/checkpoints/000003-ratchet10.json',
  'd0febdcfc77d8ec92456ca429e1768e67677b12ca91bfb0db49447622b5dab00'),
 ('rhea-full-clone-000004-ratchet13-20261103.json',
  'full-clone-steps/checkpoints/000004-ratchet13.json',
  '62a288014d932a0272a0083e6ccf02ab640f2d6cca2822d661987b03b1c03ad5'),
 ('rhea-full-clone-000005-step-20261103.json',
  'full-clone-steps/checkpoints/000005-step.json',
  '53295fea8edf8abb35c89b9eefa864bc8b044f5ede6eeabfcba5ca3ee540925b'),
 ('rhea-full-clone-000006-step-20261104.json',
  'full-clone-steps/checkpoints/000006-step.json',
  'd45cf581915bcf8e6047eae5c7d2d0fb5afea2d9cd13ddc5c927073c48c4b16f'),
 ('rhea-full-clone-000007-step-20261104.json',
  'full-clone-steps/checkpoints/000007-step.json',
  '46350c4b120ac5e4661a83e49fbaa8296ad8986b5f7a3d1f62fd4d1fa4411a32'),
 ('rhea-full-clone-000008-step-20261104.json',
  'full-clone-steps/checkpoints/000008-step.json',
  '5b5740422c3f50cd52bf5190b64c8d4b6a1c6473ebdc3569a26ecdf302a21aa1'),
 ('rhea-full-clone-000009-step-20261104.json',
  'full-clone-steps/checkpoints/000009-step.json',
  '220f2daf2018a9944885403bc0bab27f25dcdb0dec8b8e895e3d182738caecd2'),
 ('rhea-batch2-000010-certificate-20261107.json',
  'full-clone-steps/checkpoints/000010-step.json',
  '6a8d7fbbd46fa26102eafe3d803b1a65286d5331c9eaaa2a3656c3e51907c0fc'),
 ('rhea-batch2-000011-certificate-20261107.json',
  'full-clone-steps/checkpoints/000011-step.json',
  'c4cbad183a4646a148fe74275c4fab6dbfbf4abaf1501e814725913e80158b9a'),
 ('rhea-batch2-000012-certificate-20261107.json',
  'full-clone-steps/checkpoints/000012-step.json',
  '10d0b19e80d9b449b9d8f6334414e5fd7a83bfb25117432a3d12acfa9d801fbe'),
 ('rhea-batch2-000013-certificate-20261107.json',
  'full-clone-steps/checkpoints/000013-step.json',
  '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774'))
IMMUTABLE_REPORT = {'schema': 1,
 'scope': 'rhea-batch2-closed-generation-health',
 'phase': 'reader-restored',
 'boot_id': '6fc54ca7-d64a-4125-98fa-d0a728485237',
 'kernel': '6.8.0-149-generic',
 'identity_sha256': '3821f719ebc3b31df7cb77b02e516e3da2f11db5044df040f6be1129a9a14e67',
 'post_reboot_verification_sha256': '64c805f7b51950853303c7de4b39ae75c449243913af5f083f98ece9fbda0ade',
 'baseline_state_sha256': '22a05d67b860491e2475069851b568bad49c6136c17ffe354cee169fb9596af2',
 'state_sha256': 'c1563e322c496ca479c26501ef3f8ae2b71091565ee8fa227e24b4292f2cd90c',
 'pins_sha256': '1c5e844a4252a63133ed32c78dc119064150510d517c5cbc7d75cf739cf83363',
 'checkpoint_sha256': '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774',
 'generation': 13,
 'rewrites': 9,
 'pending': None,
 'state': {'format': '013',
           'marked': 93686,
           'count': 93697,
           'bytes': 7786594079552,
           'inventory': '78ac0bf93a22dc0e0606c6a2c00f59e2381207ec5e63b4cdf06bdf2f61f11f49'},
 'maximum_rewrites': 9,
 'certified_stages': [{'generation': 10,
                       'checkpoint_sha256': '6a8d7fbbd46fa26102eafe3d803b1a65286d5331c9eaaa2a3656c3e51907c0fc',
                       'writer_sha256': '20225918550963a3be285b367ec7265981a5a6c26d5d77cafcd8f51bd1d75c97',
                       'created_files': 1,
                       'retired_files': 1},
                      {'generation': 11,
                       'checkpoint_sha256': 'c4cbad183a4646a148fe74275c4fab6dbfbf4abaf1501e814725913e80158b9a',
                       'writer_sha256': '5fb9950010b8a510f26e2b38ccb299acef6934a0eed00600364293244870ff42',
                       'created_files': 1,
                       'retired_files': 1},
                      {'generation': 12,
                       'checkpoint_sha256': '10d0b19e80d9b449b9d8f6334414e5fd7a83bfb25117432a3d12acfa9d801fbe',
                       'writer_sha256': '67c8c352591f93da7b4127f3cae2f9bcb09358b55dc52978bc1a5bfe1262dde7',
                       'created_files': 1,
                       'retired_files': 1},
                      {'generation': 13,
                       'checkpoint_sha256': '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774',
                       'writer_sha256': 'bcb5b956eb2342bbcf05a9ee67de1d87a1111aedb2440a1d153bbb6e2c555b4e',
                       'created_files': 1,
                       'retired_files': 1}],
 'reader_process': {'pid': 78502,
                    'start_ticks': '5054051',
                    'boot_id': '6fc54ca7-d64a-4125-98fa-d0a728485237'},
 'writer_process': None,
 'production_service_process': {'boot_id': '6fc54ca7-d64a-4125-98fa-d0a728485237',
                                'pid': 3786,
                                'start_ticks': '93876'},
 'production_rc_process': {'boot_id': '6fc54ca7-d64a-4125-98fa-d0a728485237',
                           'pid': 3905,
                           'start_ticks': '94049'},
 'production_rc_checked': True,
 'production_disk_cache': {'bytesUsed': 0,
                           'uploadsQueued': 0,
                           'uploadsInProgress': 0,
                           'erroredFiles': 0,
                           'outOfSpace': False},
 'production_identity_sha256': '6fa73023985ded9935814949b2d0e1f95c274c9a4d15285a7b11932166c143ea',
 'production_rc_identity_sha256': 'a141321d968de5c66b7577ab4de47f7311dbc52783527003090b1cb5b819731e',
 'writer': {'ActiveState': 'inactive',
            'SubState': 'dead',
            'MainPID': '0',
            'Result': 'success',
            'ExecMainStatus': '0'},
 'writer_mount_and_socket_absent': True,
 'lab_disk_cache': None,
 'reader_and_writer_caches_retained': True,
 'kubo_and_walker_inactive': True,
 'walker_unit_file_state': 'disabled',
 'protected_anchors_unchanged': True}
PROTECTED_PINS = {str(HEALTH): HEALTH_SHA256, str(RESTORED): RESTORED_SHA256,
                  str(FINALIZATION): FINALIZATION_SHA256, str(CLOSE): CLOSE_SHA256,
                  str(STATE): IMMUTABLE_REPORT['state_sha256'],
                  str(PINS): IMMUTABLE_REPORT['pins_sha256']}
PROTECTED_PINS.update({str(TRUST / path): pin for _, path, pin in CERTIFICATES})


def object_json(raw):
    """Historical JSON permits whitespace, but never duplicate/nonfinite values."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'invalid evidence bytes')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate evidence key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False, 'nonfinite evidence'))
        require(type(value) is dict, 'evidence object required')
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise Refusal('malformed evidence JSON') from exc


def exact(value, expected, message):
    # Canonical bytes distinguish JSON true from 1, including nested fields.
    require(canonical(value) == canonical(expected), message)


def fresh(observed, now):
    require(type(now) in (int, float) and math.isfinite(now)
            and type(observed) in (int, float) and math.isfinite(observed)
            and 0 <= now - observed <= MAX_AGE, 'future/stale health evidence')


def validate_chain(certificates, close_raw):
    """Exactly thirteen generations plus the explicit gen4 failed-close bridge."""
    require(type(certificates) in (list, tuple) and len(certificates) == 13,
            'thirteen ordered certificates required')
    require(sha(close_raw) == CLOSE_SHA256, 'failed-close bridge changed')
    close = object_json(close_raw)
    previous = BASELINE_CHECKPOINT_SHA256
    values = []
    for index, (raw, (_, _, pin)) in enumerate(zip(certificates, CERTIFICATES), 1):
        require(sha(raw) == pin, 'certificate bytes/order changed')
        value = object_json(raw)
        exact(value.get('generation'), index, 'certificate generation changed')
        if index == 5:
            require(close.get('generation') == 4 and close.get('previous_checkpoint_sha256') == previous,
                    'failed-close bridge predecessor changed')
            previous = CLOSE_SHA256
        require(value.get('previous_checkpoint_sha256') == previous,
                'certificate predecessor changed')
        require(value.get('mode') == 'final' and value.get('remote_generation_verified') is True
                and value.get('pebble_reopen_verified') is True,
                'certificate lacks final remote/reopen proof')
        values.append(value)
        previous = pin
    require(previous == a.ANCHOR and values[-1]['sst_lineage']['rewrite_operations'] == 9,
            'terminal gen13/rewrite proof changed')
    exact({k: values[-1][v] for k, v in
           (('format', 'after_format'), ('marked', 'marked_after'), ('count', 'sst_count'),
            ('bytes', 'sst_bytes'), ('inventory', 'sst_inventory_sha256'))},
          IMMUTABLE_REPORT['state'], 'terminal state changed')
    return values


def validate_report(raw, *, now, source_path, source_raw, restored_raw,
                    finalization_raw, certificates, close_raw, prior_report_raw=None):
    """Pure evidence validation; supplied source bytes DO NOT authenticate origin.

    No success flag from a caller is an admission. Actual provenance additionally
    requires the root probe's protected-file and independent /proc observations.
    """
    require(str(source_path) == str(HEALTH) and sha(source_raw) == HEALTH_SHA256,
            'exact historical health source/path mismatch')
    require(sha(restored_raw) == RESTORED_SHA256
            and sha(finalization_raw) == FINALIZATION_SHA256, 'certified restoration changed')
    restored, done = object_json(restored_raw), object_json(finalization_raw)
    require(done.get('reader_restored_sha256') == RESTORED_SHA256
            and done.get('checkpoint_sha256') == a.ANCHOR
            and done.get('reader') == restored, 'restoration linkage changed')
    chain = validate_chain(certificates, close_raw)
    value = object_json(raw)
    require(set(value) == set(IMMUTABLE_REPORT) | {'observed_unix', 'free_bytes'},
            'health schema missing/unknown fields')
    for key, expected in IMMUTABLE_REPORT.items():
        exact(value[key], expected, 'historical health mismatch: ' + key)
    exact(value['reader_process'], restored['process'], 'reader differs from certified restoration')
    expected_stages = [dict(generation=i, checkpoint_sha256=CERTIFICATES[i-1][2],
                            writer_sha256=chain[i-1]['go_report_sha256'],
                            created_files=1, retired_files=1) for i in range(10, 14)]
    exact(value['certified_stages'], expected_stages, 'certified stage suffix changed')
    fresh(value['observed_unix'], now)
    require(type(value['free_bytes']) is int and value['free_bytes'] >= 2 * 1024**4,
            'two TiB free reserve required')
    if prior_report_raw is not None:
        prior = validate_report(prior_report_raw, now=now, source_path=source_path,
            source_raw=source_raw, restored_raw=restored_raw, finalization_raw=finalization_raw,
            certificates=certificates, close_raw=close_raw)
        require(prior['observed_unix'] <= value['observed_unix'], 'witness time regressed')
    return value


def _mount_row(line):
    fields = line.split()
    require(len(fields) >= 10 and fields.count('-') == 1, 'malformed mountinfo')
    split = fields.index('-')
    require(split >= 6 and len(fields) == split + 4
            and all(v.isdigit() for v in fields[:2]), 'mountinfo identity missing')
    return dict(root=fields[3], target=fields[4], options=fields[5].split(','),
                type=fields[split+1], source=fields[split+2])


def validate_witness(witness, report, restored):
    """Validate independent /proc observations. This is still an unsigned seal."""
    require(type(witness) is dict and set(witness) == {
        'boot_id', 'kernel', 'processes', 'reader_cgroup', 'reader_cmdline',
        'reader_exe', 'reader_exe_sha256', 'mountinfo', 'open_users',
        'cache_identities', 'protected_files', 'file_identities', 'stop_present', 'writer_socket_present'},
        'incomplete independent reader witness')
    exact(witness['boot_id'], report['boot_id'], 'independent boot mismatch')
    exact(witness['kernel'], report['kernel'], 'independent kernel mismatch')
    expected_processes = {k: report[k] for k in
                         ('reader_process', 'production_service_process', 'production_rc_process')}
    exact(witness['processes'], expected_processes, 'independent process mismatch')
    groups = witness['reader_cgroup'].splitlines()
    require(groups and any(row.split(':', 2)[-1] == '/system.slice/' + READER_UNIT for row in groups),
            'separate reader service cgroup missing')
    command = witness['reader_cmdline']
    def option(name, value):
        return (command.count(name) == 1 and command.index(name) + 1 < len(command)
                and command[command.index(name)+1] == value)
    require(type(command) is list and command and command[0] == '/usr/bin/rclone'
            and '--read-only' in command and command.count('mount') == 1
            and command.count(READER_MOUNT) == 1
            and 'rhea_pebble_lab_reader:' + a.BUCKET + '/rhea' in command
            and option('--config', '/root/.config/rclone/rhea-pebble-lab-reader-20261102.conf')
            and option('--cache-dir', CACHES[0]),
            'reader command is not the separate read-only mount')
    require(witness['reader_exe'] == '/usr/bin/rclone'
            and type(witness['reader_exe_sha256']) is str
            and a.HEX.fullmatch(witness['reader_exe_sha256']), 'reader executable identity missing')
    lines = witness['mountinfo']
    require(type(lines) is list and all(type(line) is str for line in lines), 'mountinfo missing')
    rows = [_mount_row(line) for line in lines]
    require(len(rows) == 1 and rows[0] == restored['mount'], 'unexpected/alternate lab mount')
    require(witness['open_users'] == [] and witness['stop_present'] is False
            and witness['writer_socket_present'] is False, 'open users, stop sentinel or writer socket')
    require(type(witness['cache_identities']) is dict
            and set(witness['cache_identities']) == set(CACHES), 'exact retained caches missing')
    for item in witness['cache_identities'].values():
        require(type(item) is dict and set(item) == {'device', 'inode'}
                and all(type(v) is int and v > 0 for v in item.values()), 'cache identity missing')
    exact(witness['protected_files'], PROTECTED_PINS, 'protected file identity changed')
    require(type(witness['file_identities']) is dict
            and set(witness['file_identities']) == set(PROTECTED_PINS), 'protected file metadata missing')
    for info in witness['file_identities'].values():
        require(type(info) is dict and set(info) == {'device', 'inode', 'size', 'mtime_ns', 'ctime_ns'}
                and all(type(v) is int and v >= 0 for v in info.values()) and info['inode'] > 0,
                'invalid protected file metadata')
    return witness


def validate_evidence(evidence, *, now):
    require(type(evidence) is dict and set(evidence) == {'raw', 'source_path', 'source_raw',
            'restored_raw', 'finalization_raw', 'certificates', 'close_raw', 'witness'},
            'complete evidence bundle required')
    report = validate_report(**{k: v for k, v in evidence.items() if k != 'witness'}, now=now)
    witness = validate_witness(evidence['witness'], report, object_json(evidence['restored_raw']))
    binding = dict(schema=1, scope='rhea-reader-restored-evidence-only-v1',
                   report_sha256=sha(evidence['raw']), health_source_sha256=HEALTH_SHA256,
                   health_source_path=str(HEALTH), restored_sha256=RESTORED_SHA256,
                   boot_id=report['boot_id'], kernel=report['kernel'],
                   reader_process=report['reader_process'], mountinfo=witness['mountinfo'],
                   independent_witness_sha256=sha(canonical(witness)),
                   generation=13, rewrites=9, cap=9, pending=None,
                   state_sha256=report['state_sha256'], checkpoint_sha256=a.ANCHOR,
                   observed_unix=report['observed_unix'], admission=False)
    return dict(binding=binding, evidence_seal_sha256=sha(canonical(binding)),
                controller_ready=False, admission=False)


def plan_handoff(before, after, *, now):
    """Pure two-observation state machine. Produces proposals, never executes them.

    No retained nonce or signed claims are accepted by this API. Both unsigned
    bundles are revalidated; a caller's previous seal/success value is insufficient.
    """
    phases = ['unobserved']
    try:
        first = validate_evidence(before, now=now)
        phases.append('before-validated')
        second = validate_evidence(after, now=now)
        phases.append('after-validated')
        require(object_json(before['raw'])['observed_unix'] < object_json(after['raw'])['observed_unix']
                and sha(before['raw']) != sha(after['raw']),
                'two distinct ordered health observations required; replay/time regression')
        exact(before['witness'], after['witness'], 'reader/mount/production/cache/open-user identities changed')
        phases.append('stable-reader-restored')
    except (Refusal, KeyError, IndexError, TypeError, ValueError) as exc:
        return dict(schema=1, state='blocked', phases=phases + ['blocked'], dry_run_go=False,
                    execution_allowed=False, admission=False, controller_ready=False,
                    mutations_performed=False, reasons=[str(exc)])
    intent = dict(scope='rhea-reader-restored-transition-intent-only-v1',
                  before=first, after=second, preserved_caches=after['witness']['cache_identities'],
                  cap=9, checkpoint_sha256=a.ANCHOR, source_and_markers='preserve exact bytes')
    steps = [
        ('review-and-admit', 'Separately review full protected-source byte guards and signed admission integration.',
         'Fresh identities revalidated under exclusive writer.lock; independently signed exact intent; durable nonce consumed.'),
        ('retain-handoff-intent', 'Retain reviewed immutable intent before any separately implemented handoff.',
         'Exact old reader PID/start/boot, mount and caches bound; cap9 and historical journal preserved.'),
        ('reader-stop-proposal', 'A future authorized operator stops only the sealed reader.',
         'Original PID gone, reader mount absent, no new open users; caches retained; production frozen.'),
        ('writer-start-proposal', 'A future reviewed integration admits one lab writer with markers withheld.',
         'Separate writer PID/mount/RC peer authenticated, clean queue, 2 TiB reserve; original reader absent.'),
        ('n2-pilot-review', 'Separately authorize at most two units using a new journal and physical rewrite accounting.',
         'Historical cap9 stays unchanged; full before/final cloud proofs and fresh reopen required.'),
        ('reader-return-proposal', 'A future reviewed integration drains/stops writer and restores read-only reader.',
         'Writer/socket/mount absent; new reader explicitly certified; caches retained; source and production unchanged.'),
    ]
    return dict(schema=1, state='plan-only-ready', phases=phases + ['plan-only-ready'],
                dry_run_go=True, execution_allowed=False, admission=False, controller_ready=False,
                mutations_performed=False, transition_intent=intent,
                transition_intent_sha256=sha(canonical(intent)), preserved_caches=list(CACHES),
                steps=[dict(stage=k, proposal=v, expected_postconditions=p, executable=False)
                       for k, v, p in steps],
                blockers=['full protected-source byte guard review', 'signed admission under exclusive lock',
                          'independent keys and installation absent', 'live handoff/monitor/recovery qualification'])


def _process(pid, boot):
    require(type(pid) is int and pid > 1, 'invalid live PID')
    proc = Path('/proc') / str(pid)
    def read():
        fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        require(fields[0] not in ('Z', 'X'), 'dead reader/production process')
        return dict(pid=pid, start_ticks=fields[19], boot_id=boot)
    before = read()
    require(read() == before, 'live PID changed')
    return before


def _unlocked_identity():
    """Inspect kernel lock evidence, without taking ANY flock (even shared).

    The child has its own lock. Lock absence here is NOT a reservation; child
    contention must refuse, and there is no admission spanning the observations.
    """
    with a.protected_directory(LOCK.parent) as fd:
        lock_fd = os.open(LOCK.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(lock_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    'unprotected historical lock')
            device = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
            for line in Path('/proc/locks').read_text().splitlines():
                for field in line.split():
                    parts = field.split(':')
                    if len(parts) == 3:
                        try:
                            row = (int(parts[0], 16), int(parts[1], 16), int(parts[2]))
                        except ValueError:
                            continue
                        require(row != device, 'historical writer.lock already held; probe forbidden')
            current = os.stat(LOCK.name, dir_fd=fd, follow_symlinks=False)
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'lock replaced')
            return dict(device=info.st_dev, inode=info.st_ino)
        finally:
            os.close(lock_fd)


def _lab_mounts():
    lines = Path('/proc/self/mountinfo').read_text().splitlines()
    # Include any bind/alternate mount of the same lab remote, as well as exact
    # reader/writer paths and children. The historical witness checks namespaces.
    return [line for line in lines if a.BUCKET in line or any(
        len(line.split()) > 4 and (line.split()[4] == target or line.split()[4].startswith(target + '/'))
        for target in (READER_MOUNT, WRITER_MOUNT))]


def _open_users(reader_pid):
    users = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == reader_pid:
            continue
        try:
            paths = [proc / 'cwd', proc / 'root', proc / 'exe', *(proc / 'fd').iterdir()]
            for path in paths:
                try:
                    target = os.readlink(path)
                except FileNotFoundError:
                    continue
                if any(target == mount or target.startswith(mount + '/')
                       for mount in (READER_MOUNT, WRITER_MOUNT)):
                    users.append(dict(pid=int(proc.name), reference=str(path), target=target))
            for row in (proc / 'maps').read_text().splitlines():
                fields = row.split(maxsplit=5)
                if len(fields) == 6 and any(fields[5] == mount or fields[5].startswith(mount + '/')
                                            for mount in (READER_MOUNT, WRITER_MOUNT)):
                    users.append(dict(pid=int(proc.name), reference=str(proc / 'maps'), target=fields[5]))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(users, key=lambda row: (row['pid'], row['reference']))


def _snapshot():
    """Read fixed files and /proc only. No historical module is imported."""
    files, identities = {}, {}
    for path, pin in PROTECTED_PINS.items():
        path_object = Path(path)
        with a.protected_directory(path_object.parent) as fd:
            first = os.stat(path_object.name, dir_fd=fd, follow_symlinks=False)
            raw = a.read_at(fd, path_object.name, limit=MAX_BYTES)
            last = os.stat(path_object.name, dir_fd=fd, follow_symlinks=False)
            def identity(info):
                return dict(device=info.st_dev, inode=info.st_ino, size=info.st_size,
                            mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
            require(identity(first) == identity(last), 'protected file replaced during read')
            identities[path] = identity(last)
        require(sha(raw) == pin, 'protected source/production anchor changed: ' + path)
        files[path] = raw
    restored = object_json(files[str(RESTORED)])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    report = IMMUTABLE_REPORT
    processes = {k: _process(report[k]['pid'], boot) for k in
                 ('reader_process', 'production_service_process', 'production_rc_process')}
    proc = Path('/proc') / str(restored['process']['pid'])
    exe = str((proc / 'exe').resolve(strict=True))
    require(exe == '/usr/bin/rclone', 'reader executable changed')
    exe_raw = a.protected_read(Path(exe), mode=0o755, limit=32 * 1024**2)
    caches = {}
    for path in CACHES:
        with a.protected_directory(Path(path)) as fd:
            info = os.fstat(fd)
            caches[path] = dict(device=info.st_dev, inode=info.st_ino)
    witness = dict(boot_id=boot, kernel=os.uname().release, processes=processes,
        reader_cgroup=(proc / 'cgroup').read_text(),
        reader_cmdline=(proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
        reader_exe=exe, reader_exe_sha256=sha(exe_raw), mountinfo=_lab_mounts(),
        open_users=_open_users(restored['process']['pid']), cache_identities=caches,
        protected_files={path: sha(raw) for path, raw in files.items()},
        file_identities=identities,
        stop_present=os.path.lexists(STOP), writer_socket_present=os.path.lexists(WRITER_SOCKET))
    validate_witness(witness, report, restored)
    require({k: _process(v['pid'], boot) for k, v in processes.items()} == processes
            and _lab_mounts() == witness['mountinfo'], 'process/mount changed during snapshot')
    lock = _unlocked_identity()
    return dict(files=files, witness=witness, lock=lock)


def _validate_interpreter():
    with a.protected_directory(Path('/usr/bin')) as fd:
        info = os.stat('python3', dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            interpreter = Path('/usr/bin/python3').resolve(strict=True)
            require(interpreter.parent == Path('/usr/bin'), 'untrusted interpreter symlink')
        else:
            interpreter = Path('/usr/bin/python3')
        a.protected_read(interpreter, mode=0o755, limit=32 * 1024**2)


def probe_reader_restored():
    """Root-only read-only witness. No caller paths/clock/env, no installed handoff.

    Never invoke inside RootHostAdapter.exclusive(): health takes writer.lock.
    The time gap after the child's lock release precludes using this as admission.
    A later signed admission MUST revalidate independently under its own lock.
    """
    require(os.geteuid() == 0 and socket.gethostname().split('.')[0].lower() == 'rhea',
            'root on Rhea required for historical read-only probe')
    _unlocked_identity()  # Refuse self-held/other-held lock BEFORE any child.
    before = _snapshot()
    # Validate the absolute interpreter (standard-library-only child, isolated
    # Python import path). No ambient AWS/rclone/Python/proxy credentials survive.
    _validate_interpreter()
    started, tick = time.time(), time.monotonic()
    try:
        child = subprocess.run(['/usr/bin/python3', '-I', '-B', str(HEALTH),
            '--phase', 'reader-restored', '--reader-sha256', RESTORED_SHA256],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
                          'LANG': 'C', 'LC_ALL': 'C'}, timeout=MAX_AGE, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal('historical health witness failed/timed out') from exc
    require(child.returncode == 0 and not child.stderr and 0 < len(child.stdout) <= MAX_BYTES,
            'historical health witness refused')
    after = _snapshot()
    require(before == after, 'protected source/process/mount/lock identity changed during probe')
    now = time.time()
    require(0 <= time.monotonic() - tick <= MAX_AGE
            and abs((now - started) - (time.monotonic() - tick)) <= 1,
            'probe deadline or host clock changed')
    raw = child.stdout
    require(started <= object_json(raw)['observed_unix'] <= now, 'replayed health child output')
    files = after['files']
    evidence = dict(raw=raw, source_path=str(HEALTH), source_raw=files[str(HEALTH)],
        restored_raw=files[str(RESTORED)], finalization_raw=files[str(FINALIZATION)],
        certificates=[files[str(TRUST / path)] for _, path, _ in CERTIFICATES],
        close_raw=files[str(CLOSE)], witness=after['witness'])
    seal = validate_evidence(evidence, now=now)
    return dict(evidence=evidence, seal=seal, mode='reader-restored', admission=False,
                controller_ready=False, protected_source_bytes_proven=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-report', type=Path, help='offline report; never admission')
    parser.add_argument('--evidence-dir', type=Path, help='offline docs/evidence directory')
    args = parser.parse_args(argv)
    if args.verify_report is None or args.evidence_dir is None:
        print(json.dumps(dict(admission=False, controller_ready=False,
                              reason='live CLI disabled; offline --verify-report and --evidence-dir required')))
        return 2
    try:
        directory = args.evidence_dir
        done_raw = (directory / 'rhea-batch2-reader-finalization-20261107.json').read_bytes()
        # CLI uses the checked-out source as an offline comparison only, without
        # executing/importing historical code or asserting actual root provenance.
        source = Path(__file__).resolve().with_name('rhea_batch2_health.py').read_bytes()
        validate_report(args.verify_report.read_bytes(), now=time.time(), source_path=str(HEALTH),
            source_raw=source, restored_raw=canonical(object_json(done_raw)['reader']),
            finalization_raw=done_raw, certificates=[(directory / name).read_bytes()
                for name, _, _ in CERTIFICATES],
            close_raw=(directory / 'rhea-full-clone-failed-close-certified-20261103.json').read_bytes())
    except (Refusal, OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps(dict(valid=False, admission=False, reason=str(exc))))
        return 2
    print(json.dumps(dict(valid=True, admission=False, controller_ready=False,
                          provenance='offline source comparison only', decision='not admission')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
