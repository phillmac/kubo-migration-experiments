"""Read-only observations and native rehearsal for the two-SST clone checkpoint."""
import contextlib
import fcntl
import os
from pathlib import Path
import re
import secrets

import rhea_gen14_create_only_checkpoint as proof
import rhea_gen14_staged_host as host

h, iam, c, a = host.h, host.iam, host.c, host.h.admission
require, STATE, INSTALL = c.require, host.STATE, host.INSTALL
SCOPE = 'rhea-gen14-create-only-two-sst-checkpoint-warm-v1'
HANDOFF = '7ef9fe34aafd20beaadbf3728b10d93e9b949a17e5b2caef6f8daa431466c7f8'
DB = Path(h.reopen.MOUNT) / 'pebbleds'


@contextlib.contextmanager
def writer_lock():
    with a.protected_directory(a.WRITER_LOCK.parent, private=True) as parent:
        a.read_at(parent, a.WRITER_LOCK.name)
        fd = os.open(a.WRITER_LOCK.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    with os.fdopen(fd, 'rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def release(install=INSTALL, scope=SCOPE, required=()):
    raw = a.protected_read(install / 'release.json')
    a.verify_detached(raw, a.protected_read(install / 'release.sig'), a.protected_read(h.TRANSACTION_INSTALL / 'release.pub'),
                      domain=a.DEPLOYMENT_DOMAIN, key_sha256=h.RELEASE_KEY)
    manifest = a.parse(raw)
    require(set(manifest) == {'scope','files'} and manifest['scope'] == scope and
            {'worker','scripts/rhea_gen14_checkpoint_prepare.py','scripts/rhea_gen14_staged_host.py',
             'scripts/rhea_gen14_create_only_checkpoint.py'} | set(c.SOURCE_PINS) | set(required) <= manifest['files'].keys(),
            'release omits a controller dependency')
    for name, sha in manifest['files'].items():
        path = install / name
        require(re.fullmatch(r'[A-Za-z0-9_./-]+', name) and not name.startswith('/') and '..' not in path.parts
                and path.is_file() and not path.is_symlink() and h.reopen.digest_file(path) == sha, 'release differs: '+name)
    require({p.relative_to(install).as_posix() for p in (install/'scripts').glob('*.py')} <= manifest['files'].keys(),
            'unlisted Python module')
    return c.raw_sha(raw), manifest['files']['worker']


def save(path, obj):
    if path.exists():
        require(host.read(path) == obj, 'retained record differs: '+path.name)
    else:
        host.put(path, obj)


def save_metadata(path, values):
    host.mkdir(path)
    require({p.name for p in path.iterdir()} <= values.keys(), 'metadata snapshot has extra leaves')
    for name, value in values.items():
        if not (path/name).exists():
            host.r.private_write(path/name, value)
    require(proof.physical_metadata(path) == values, 'retained metadata bytes differ')


def recovered_reader(cert, prior):
    # The pinned Go implementation requires a durable pending.json acknowledgement
    # before its first writable Open. Re-admission is limited to that boundary.
    legacy = iam.TRIAL / 'checkpoint-000014'
    first_install = Path('/root/.local/share/rhea-gen14-live-checkpoint-20261127')
    raw = a.protected_read(first_install/'admission.json')
    sig = a.protected_read(first_install/'admission.sig')
    require(a.sha(raw)=='d1769f15898998a6a4e942b85286f12e2b22a4245de3e09e797374b314b024ff', 'first admission differs')
    a.verify_detached(raw,sig,a.protected_read(h.TRANSACTION_INSTALL/'handoff.pub'),key_sha256=h.HANDOFF_KEY,domain=a.DOMAIN)
    admitted = a.parse(raw)
    binding = admitted['binding']
    launch = host.read(legacy/'writer-launch.json')
    nonce = host.read(legacy/'nonces'/(admitted['nonce']+'.json'))
    require(nonce==dict(schema=1,claims_sha256=a.sha(raw),signature_sha256=a.sha(sig),nonce=admitted['nonce'])
            and host.read(legacy/'intent.json')==binding and launch['admission_sha256']==a.sha(raw)
            and binding['reader']==prior['restored_reader'] and binding['production']==prior['production']
            and launch['intent']['go_binary_sha256']==binding['worker_sha256']
            and binding['request']['maximum_units']==2, 'original admitted launch differs')
    require({p.name for p in (legacy/'go').iterdir()}=={'lock'} and
            all(not (legacy/name).exists() for name in ('writer-closed.json','snapshot.json','before-publication.json',
                'final-remote.json','checkpoint-000014.json','completed.json')) and not list(legacy.glob('put-*'))
            and not (iam.TRIAL/'publisher-plan.json').exists(), 'first attempt passed the no-replay boundary')
    work=Path('/data/rhea-gen14-checkpoint-000014-20261127/writer')
    require(host.read(legacy/'quarantine.json')==dict(cache=str(work/'quarantined-cache'),no_rc_socket=True,stopped=True)
            and (work/'cache').is_file() and not (work/'runtime/rc.sock').exists()
            and not any(f.is_file() or f.is_symlink() for f in (work/'quarantined-cache').rglob('*')),
            'first cache contains data or is not quarantined')
    old=proof.physical_metadata(legacy/'previous-metadata')
    require(proof.writer_metadata(cert,old)==old==proof.physical_metadata(work/'metadata'),
            'first attempt modified metadata')
    reader=h.reader(True)
    require(reader['process']!=binding['reader']['process'] and reader['process']['boot_id']==binding['reader']['process']['boot_id'],
            'expected a freshly restored reader on the admitted boot')
    return reader, binding


def baseline():
    cert = iam.anchored_checkpoint()
    handoff = iam.read_path(h.TRIAL/'complete.json')
    require(c.raw_sha(handoff) == HANDOFF and c.raw_sha(iam.read_path(iam.TRIAL/'prepared-writer-request.json')) == h.PREPARED,
            'signed handoff or prepared anchor changed')
    prior = c.parse(handoff)
    current, aborted = recovered_reader(cert,prior)
    prior = dict(prior,restored_reader=current,aborted_admission_sha256='d1769f15898998a6a4e942b85286f12e2b22a4245de3e09e797374b314b024ff',
                 aborted_baseline=aborted['physical_baseline_sha256'])
    require(h.production() == prior['production']
            and not any(h.main_pid(u) for u in (host.UNIT,host.PROBE,h.WRITER)) and not h.mount_row(h.DB)
            and not h.preflight._open_users(prior['restored_reader']['process']['pid']), 'clone or production state changed')
    return cert, prior


def verify_inspection(report, cert):
    fields = dict(format='after_format',marked='marked_after',files='sst_count',bytes='sst_bytes',
                  inventory_sha256='sst_inventory_sha256')
    expected = {k:cert[v] for k,v in fields.items()}
    for side in ('before','after'):
        require({k:report[key] for k,key in zip(fields,(side+'_format','marked_'+side,'sst_files_'+side,
                'sst_bytes_'+side,'sst_inventory_sha256_'+side))} == expected, 'cold staged reopen differs')
    require(report['action']=='inspect' and not report.get('error') and report['compactions']==[]
            and not any(proof.v._delta(report['sst_diff'])) and report['io']['sst_write_bytes']==0
            and report['io']['metadata_write_bytes']==0, 'staged inspection wrote or compacted')


def native_inspection(mount,cert,old):
    # Populate the real writer VFS directory cache before supervised RC polling.
    # The first 93k-object listing holds the directory mutex in rclone 1.68.
    with mount.launch('inspect-staged') as (proc, sock):
        raw, _ = proc.communicate(timeout=240)
        require(proc.returncode==0, 'staged inspector failed; inspect '+str(mount.work/'inspect-staged.stderr'))
    report=c.parse(raw)
    verify_inspection(report,cert)
    rows,health=mount.sample()
    require(not rows and proof.physical_metadata(mount.meta)==old,'native inspection changed clone')
    return dict(report=report,health=health)


def prepare():
    _, worker_sha = release()
    cert, prior = baseline()
    host.mkdir(STATE)
    host.mkdir(host.DATA)
    proposal = host.inspector(INSTALL/'worker','plan')
    old_request = c.parse(iam.read_path(iam.TRIAL/'prepared-writer-request.json'))
    require(proposal == old_request['proposal'], 'initial picker changed in new binary')
    request = host.supervisor.verified_request(proposal, iam.read_path(iam.LEGACY/'checkpoints/000013-step.json'))
    link = dict(worker_sha256=worker_sha, prepared_sha256=h.PREPARED, handoff_sha256=HANDOFF, proposal=proposal)
    save(STATE/'linked-preparation.json', link)
    old = proof.physical_metadata(DB)
    require(proof.writer_metadata(cert, old)==old, 'certified predecessor metadata differs')
    save_metadata(STATE/'previous-metadata',old)
    with contextlib.closing(host.r.s3_client(*iam.p.source_credentials())) as client:
        opening = proof.anchored_inventory(client,cert)
    former=host.read(iam.TRIAL/'checkpoint-000014/opening.json')
    require(opening['baseline_sha256']==prior['aborted_baseline']==former['baseline_sha256']
            and opening['marker_history']==former['marker_history'], 'cloud changed since the refused first launch')
    if (STATE/'opening.json').exists():
        kept = host.read(STATE/'opening.json')
        require({k:v for k,v in kept.items() if k!='enumeration_metrics'} ==
                {k:v for k,v in opening.items() if k!='enumeration_metrics'}, 'physical baseline changed')
    else:
        host.put(STATE/'opening.json',opening)
    native = STATE/('probe-'+worker_sha+'.json')
    if not native.exists():
        mount = host.WriterMount(host.DATA/('probe-'+secrets.token_hex(8)),host.PROBE)
        credential, _ = host.role_credentials('writer',cert)
        mount.prepare(old)
        try:
            identity = mount.start(credential)
            check = native_inspection(mount,cert,old)
        finally:
            quarantine = mount.quarantine()
        host.put(native,dict(identity=identity,**check,quarantine=quarantine,worker_sha256=worker_sha))
    verify_inspection(host.read(native)['report'],cert)
    require(baseline()==(cert,prior), 'state changed across preparation')
    return dict(phase='ready', baseline=opening['baseline_sha256'], latest=opening['latest'], tombstones=opening['deleted'],
                request=request, worker_sha256=worker_sha)


def observation():
    release_sha, worker_sha = release()
    cert, prior = baseline()
    link = host.read(STATE/'linked-preparation.json')
    require(link['worker_sha256']==worker_sha and link['prepared_sha256']==h.PREPARED and link['handoff_sha256']==HANDOFF,
            'linked preparation differs')
    probe = host.read(STATE/('probe-'+worker_sha+'.json'))
    verify_inspection(probe['report'],cert)
    opening = host.read(STATE/'opening.json')
    return dict(scope=SCOPE, release_sha256=release_sha, worker_sha256=worker_sha, previous_checkpoint_sha256=iam.CHECKPOINT_SHA,
                linked_preparation_sha256=c.digest(link), native_probe_sha256=c.digest(probe), signed_handoff_sha256=HANDOFF,
                physical_baseline_sha256=opening['baseline_sha256'], marker_history_sha256=c.digest(opening['marker_history']),
                reader=prior['restored_reader'], production=prior['production'], target=iam.BUCKET+'/'+iam.PREFIX,
                aborted_admission_sha256=prior['aborted_admission_sha256'],
                request=host.supervisor.verified_request(link['proposal'],iam.read_path(iam.LEGACY/'checkpoints/000013-step.json')))


if __name__ == '__main__':
    raise SystemExit('use the installed checkpoint entry point')
