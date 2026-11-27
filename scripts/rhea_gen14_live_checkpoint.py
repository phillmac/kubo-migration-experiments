"""Run one admitted two-SST rewrite on the disposable full clone and certify its cold reopen."""
import contextlib
import json
import logging
import os
from pathlib import Path
import sys
import time

if __name__ == '__main__':
    fixed = Path('/root/.local/share/rhea-gen14-live-checkpoint-warm-20261127/scripts')
    if Path(__file__).parent != fixed or os.geteuid() != 0:
        raise SystemExit('fixed root installation required')
    sys.path.insert(0, str(fixed))

import rhea_gen14_checkpoint_prepare as prep

host, proof, h, iam, c, a = prep.host, prep.proof, prep.h, prep.iam, prep.c, prep.a
STATE, INSTALL, require = host.STATE, host.INSTALL, c.require
PAYLOADS = host.DATA / 'closed-payloads'
WORK = host.DATA / 'writer'
CHECKPOINT = STATE/'checkpoint-000014.json'


def evidence(name):
    return host.read(STATE/name)


def claims(binding, *, historical=False):
    raw = a.protected_read(INSTALL/'admission.json')
    sig = a.protected_read(INSTALL/'admission.sig')
    obj = a.parse(raw)
    require(set(obj)=={'binding','issued','expires','nonce'} and a.canonical(obj['binding'])==a.canonical(binding)
            and binding['scope']==prep.SCOPE and binding['release_sha256']==prep.release()[0]
            and binding['target']==iam.BUCKET+'/'+iam.PREFIX and binding['request']['maximum_units']==2,
            'admission binding differs')
    now = obj['issued'] if historical else int(time.time())
    require(all(type(obj[k]) is int for k in ('issued','expires')) and obj['issued']<=now<obj['expires']<=obj['issued']+a.MAX_LIFETIME
            and type(obj['nonce']) is str and a.HEX.fullmatch(obj['nonce']) and len(set(bytes.fromhex(obj['nonce'])))>=8,
            'admission validity or nonce differs')
    a.verify_detached(raw,sig,a.protected_read(h.TRANSACTION_INSTALL/'handoff.pub'),key_sha256=h.HANDOFF_KEY,domain=a.DOMAIN)
    verified = a.VerifiedAdmission(raw,sig,obj['nonce'],obj['expires'])
    if historical:
        consumed = host.read(STATE/'nonces'/(obj['nonce']+'.json'))
        require(consumed==dict(schema=1,claims_sha256=a.sha(raw),signature_sha256=a.sha(sig),nonce=obj['nonce']),
                'consumed admission differs')
    return verified


def stopped_reader(original):
    require(h.reader(True)==original and not h.preflight._open_users(original['process']['pid']), 'reader in use or replaced')
    h.output(['/usr/bin/systemctl','stop',h.READER],timeout=110)
    require(not h.main_pid(h.READER) and not Path('/proc',str(original['process']['pid'])).exists()
            and not h.mount_row(h.reopen.MOUNT),'reader did not stop')
    return host.collect_reader(original)


def park():
    mount = host.WriterMount(WORK,host.UNIT)
    if (WORK/'cache').exists():
        mount.quarantine()
    require(not h.main_pid(host.UNIT) and not h.main_pid(host.PROBE), 'private writer still active')
    if not h.main_pid(h.READER) and (STATE/'intent.json').exists():
        host.collect_reader(evidence('intent.json')['reader'])
    return host.start_reader()


def decode_batch(cert,old,new,report,hashes):
    info = proof.closed_metadata(cert,old,new)
    previous, bs = proof.p._decode_tables(old[cert['manifest']])
    current, cs = proof.p._decode_tables(new[info['manifest']])
    created, retired = proof.v.validate_batch(report,previous,current,bs,cs,'013','013',hashes)
    require(report['stop_reason']=='unit-limit' and len(report['units'])==len(created)==len(retired)==2,
            'pilot did not produce two disjoint single-SST rewrites')
    return info


def hash_files(report):
    result = {}
    for row in report['sst_diff']['created']:
        name = row['name']
        require(proof.p.base.SST_NAME.fullmatch(name) and name not in result, 'invalid output name')
        path = PAYLOADS/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size==row['size'], 'closed payload differs')
        result[name] = dict(sha256=h.reopen.digest_file(path),size=row['size'])
    require({p.name for p in PAYLOADS.iterdir()}==result.keys(), 'unexpected closed payload')
    return result


def run_writer():
    binding = prep.observation()
    verified = claims(binding)
    cert = iam.anchored_checkpoint()
    opening = evidence('opening.json')
    with contextlib.closing(host.r.s3_client(*iam.p.source_credentials())) as admin:
        fresh = proof.anchored_inventory(admin,cert)
    require(fresh['baseline_sha256']==binding['physical_baseline_sha256'] and fresh['marker_history']==opening['marker_history'],
            'pre-open cloud differs from signed evidence')
    credential, _ = host.role_credentials('writer',cert)
    prior = prep.DB
    old = proof.physical_metadata(STATE/'previous-metadata')
    require(old==proof.physical_metadata(prior) and proof.writer_metadata(cert,old)==old and h.production()==binding['production'],
            'admitted reader or production changed')
    require(not (STATE/'intent.json').exists() and not WORK.exists(), 'existing admitted trial requires reconciliation')
    host.mkdir(STATE/'nonces')
    with a.protected_directory(STATE/'nonces',private=True) as fd:
        a._consume_at(fd,verified,lock_path=a.WRITER_LOCK,uid=0)
    host.put(STATE/'intent.json',binding)
    mount = host.WriterMount(WORK,host.UNIT)
    try:
        host.put(STATE/'reader-stopped.json',stopped_reader(binding['reader']))
        mount.prepare(old)
        ident = mount.start(credential)
        warm = prep.native_inspection(mount,cert,old)
        host.put(STATE/'warm-reader.json',warm)
        last_guard = 0
        def monitor():
            nonlocal last_guard
            mount.sample()
            if time.monotonic()-last_guard>=8:
                require(h.production()==binding['production'] and not h.main_pid(h.READER) and
                        not h.main_pid(h.WRITER) and not h.main_pid(host.PROBE), 'production or clone lifecycle changed')
                last_guard = time.monotonic()
        monitor()
        require(time.time()<verified.expires, 'admission expired before launch')
        journal_path = STATE/'go'
        host.mkdir(journal_path)
        store = c.Store(journal_path)
        intent = dict(unit_count=2,request=binding['request'],go_binary_sha256=binding['worker_sha256'],
                      reader_identity=binding['reader']['process'])
        host.put(STATE/'writer-launch.json',dict(admission_sha256=a.sha(verified.raw),mount=ident,intent=intent))
        with store.lock(), mount.launch('worker') as (process,sock):
            writer = host.supervisor.supervise(process,sock,intent,store,monitor,lambda:mount.sample()[1])
        host.put(STATE/'writer-closed.json',writer)
        report = writer['report']
        new = proof.physical_metadata(mount.meta)
        prep.save_metadata(STATE/'closed-metadata',new)
        host.mkdir(PAYLOADS)
        hashes = {}
        for row in report['sst_diff']['created']:
            name = row['name']
            require(proof.p.base.SST_NAME.fullmatch(name) and name not in hashes, 'invalid output name')
            hashes[name] = host.copy_closed(mount.database/name,PAYLOADS/name,row['size'])
        require(hashes==hash_files(report), 'closed SST readback differs')
        decode_batch(cert,old,new,report,hashes)
        rows, health = mount.sample()
        require({row['name']:row['size'] for row in rows}=={k:p['size'] for k,p in hashes.items()},
                'deferred queue differs from closed SSTs')
        host.put(STATE/'snapshot.json',dict(hashes=hashes,queue=rows,health=health,writer_sha256=c.digest(report),
                 metadata={n:c.raw_sha(b) for n,b in new.items()}))
    finally:
        if (WORK/'cache').exists():
            prep.save(STATE/'quarantine.json',mount.quarantine())


def history(admin, name):
    args = dict(Bucket=iam.BUCKET,Prefix=iam.PREFIX+name,MaxKeys=100)
    result = admin.list_object_versions(**args)
    require(not result.get('IsTruncated') and all(x['Key']!=args['Prefix'] for x in result.get('DeleteMarkers',[])),
            'ambiguous exact-key history or deletion: '+name)
    return [x for x in result.get('Versions',[]) if x['Key']==args['Prefix']]


def conditional_upload(admin, signer, account, role, path, expected):
    name = path.name
    require((role=='publisher')==bool(proof.markers.MANIFEST.fullmatch(name)) and
            (role=='publisher' or not name.startswith('marker.')), 'upload credential class differs')
    intent = STATE/('put-'+name+'.intent.json')
    done = STATE/('put-'+name+'.receipt.json')
    record = dict(role=role,bucket=iam.BUCKET,name=name,size=expected['size'],sha256=expected['sha256'])
    versions = history(admin,name)
    if not intent.exists():
        require(not versions, 'object name already used: '+name)
        prep.save(intent,record)
        require(path.stat().st_size==expected['size'] and h.reopen.digest_file(path)==expected['sha256'],
                'local upload payload changed')
        with path.open('rb') as body:
            result = signer.put_object(Bucket=iam.BUCKET,Key=iam.PREFIX+name,Body=body,ContentLength=expected['size'],
                                       ExpectedBucketOwner=account,IfNoneMatch='*')
        host.r.response_ok(result)
        require(host.r.live.opaque(result.get('VersionId')), 'PUT has no version')
        versions = history(admin,name)
        require(len(versions)==1 and versions[0]['VersionId']==result['VersionId'], 'PUT version not visible')
    else:
        require(host.read(intent)==record, 'prior exact PUT intent differs')
    require(len(versions)==1 and versions[0]['IsLatest'] is True, 'unresolved PUT intent or conflicting versions: '+name)
    pin = proof.p._hash_new_sst(admin,name,versions[0],expected)
    prep.save(done,pin)
    return pin


@contextlib.contextmanager
def scoped(role,cert):
    creds,account = host.role_credentials(role,cert)
    with contextlib.closing(host.r.s3_client(creds['AccessKeyId'],creds['SecretAccessKey'])) as client:
        yield host.r.live.ConditionalS3(client),account


def finish():
    cert = iam.anchored_checkpoint()
    binding = evidence('intent.json')
    verified = claims(binding,historical=True)
    launch, writer = evidence('writer-launch.json'),evidence('writer-closed.json')
    require(launch['admission_sha256']==a.sha(verified.raw) and launch['intent']['request']==binding['request']
            and launch['intent']['go_binary_sha256']==binding['worker_sha256'], 'closed writer admission differs')
    c.validate_closed(writer,launch['intent'])
    require(not h.main_pid(host.UNIT) and not h.main_pid(host.PROBE) and not h.mount_row(h.DB) and
            h.production()==binding['production'], 'writer not stopped or production changed')
    quarantine = evidence('quarantine.json')
    require(host.WriterMount(WORK,host.UNIT).quarantine()==quarantine,'quarantined cache differs')
    report, snapshot = writer['report'],evidence('snapshot.json')
    hashes = hash_files(report)
    old = proof.physical_metadata(STATE/'previous-metadata')
    newdir = STATE/'closed-metadata'
    new = proof.physical_metadata(newdir)
    info = decode_batch(cert,old,new,report,hashes)
    require(hashes==snapshot['hashes'] and snapshot['writer_sha256']==c.digest(report) and
            snapshot['metadata']=={n:c.raw_sha(b) for n,b in new.items()},'durable snapshot differs')
    opening = evidence('opening.json')
    require(opening['baseline_sha256']==binding['physical_baseline_sha256'] and
            c.digest(opening['marker_history'])==binding['marker_history_sha256'], 'opening changed')
    marker = info['manifest_marker']
    with contextlib.closing(host.r.s3_client(*iam.p.source_credentials())) as admin:
        with scoped('writer',cert) as (client,account):
            for name, pin in hashes.items():
                conditional_upload(admin,client,account,'writer',PAYLOADS/name,pin)
            for name in sorted(new.keys()-old.keys()-{marker}):
                conditional_upload(admin,client,account,'writer',newdir/name,dict(size=len(new[name]),sha256=c.raw_sha(new[name])))
        if not (STATE/'before-publication.json').exists():
            host.put(STATE/'before-publication.json',proof.verify(admin,opening,cert,old,new,report,hashes))
        before = evidence('before-publication.json')
        require(before['go_report_sha256']==c.digest(report) and before['physical_baseline_sha256']==opening['baseline_sha256']
                and before['changed_markers']==[marker], 'prepublication proof differs')
        proof.v.recheck_publication_inputs(admin,before,c.digest(before))
        empty = dict(size=0,sha256=c.raw_sha(b''))
        if not (STATE/('put-'+marker+'.intent.json')).exists():
            proof.markers.retained_manifest_view(cert['remote_metadata'],marker,opening['marker_history'],
                                                 proof.enumerate_markers(admin))
        require(h.production()==binding['production'], 'production changed before publication')
        plan = dict(schema=1,bucket=iam.BUCKET,prefix=iam.PREFIX,generation=14,previous_checkpoint_sha256=iam.CHECKPOINT_SHA,
                    closed_writer_sha256=c.digest(report),before_proof_sha256=c.digest(before),
                    quarantine_sha256=c.digest(quarantine),markers=[dict(name=marker,**empty)])
        prep.save(iam.TRIAL/'publisher-plan.json',plan)
        iam.run('publisher')
        with scoped('publisher',cert) as (client,account):
            published = conditional_upload(admin,client,account,'publisher',newdir/marker,empty)
        if not (STATE/'final-remote.json').exists():
            host.put(STATE/'final-remote.json',proof.verify(admin,opening,cert,old,new,report,hashes,published))
        final = evidence('final-remote.json')
        proof.markers.retained_manifest_view(cert['remote_metadata'],marker,opening['marker_history'],
                                             proof.enumerate_markers(admin),published)
    if h.main_pid(h.READER):
        stopped_reader(h.reader(True))
    reader = host.start_reader()
    raw = proof.physical_metadata(prep.DB)
    reopen = host.inspector(INSTALL/'worker','inspect')
    require(proof.physical_metadata(prep.DB)==raw and h.reader(True)==reader and h.production()==binding['production']
            and iam.anchored_checkpoint()==cert,'cold reopen or production changed')
    checkpoint = proof.finalize(before,final,reopen,raw)
    if CHECKPOINT.exists():
        recorded = host.read(CHECKPOINT)
        require(recorded==checkpoint,'durable checkpoint differs')
    else:
        host.put(CHECKPOINT,checkpoint)
    complete = dict(scope=prep.SCOPE,generation=14,certified_rewrites=11,marked_after=checkpoint['marked_after'],
                    checkpoint_sha256=c.digest(checkpoint), predecessor_sha256=iam.CHECKPOINT_SHA,
                    reader_sha256=c.digest(reader),production_sha256=c.digest(binding['production']),
                    marker=marker,retained=checkpoint['manifest_view']['retained'],completed_unix=int(time.time()))
    if (STATE/'completed.json').exists():
        kept = evidence('completed.json')
        require(kept['checkpoint_sha256']==complete['checkpoint_sha256'], 'completion differs')
        return kept
    host.put(STATE/'completed.json',complete)
    return complete


def main(mode):
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    with prep.writer_lock():
        prep.release()
        if mode=='prepare':
            return prep.prepare()
        if mode=='observe':
            return prep.observation()
        if mode=='park':
            return park()
        require(mode in ('run','finish'), 'unknown checkpoint mode')
        try:
            if mode=='run':
                run_writer()
            return finish()
        finally:
            if (STATE/'intent.json').exists():
                park()


if __name__=='__main__':
    print(c.canonical(main(sys.argv[1])).decode(),end='')
