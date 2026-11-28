"""Run or resume one explicitly selected byte-capped checkpoint on the disposable Rhea clone."""
import argparse
import base64
import contextlib
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import time

if __name__=='__main__':
    fixed=Path(__file__).parent
    allowed={Path('/root/.local/share')/name/'scripts' for name in
             ('rhea-clone-batch-runner-v1','rhea-clone-batch-runner-4g-v1')}
    if fixed not in allowed or os.geteuid()!=0:
        raise SystemExit('fixed root clone-batch installation required')
    sys.path.insert(0,str(fixed))

import rhea_clone_batch_proof as bulk
from rhea_clone_batch_proof import map_ssts as transfer_ssts, sst_worker_count
import rhea_clone_batch_publisher as publisher
import rhea_gen14_live_checkpoint as pilot

prep,host,h,iam,c,a,proof = pilot.prep,pilot.host,pilot.h,pilot.iam,pilot.c,pilot.a,pilot.proof
require=c.require
ROOT=host.BATCH_JOURNAL
INSTALL=host.BATCH_INSTALL if Path(__file__).parent.parent==host.BATCH_INSTALL else host.FOUR_GIB_INSTALL
ANCHOR_FILE=host.STATE/'checkpoint-000014.json'
REQUIRED={'scripts/rhea_clone_batch_runner.py','scripts/rhea_clone_batch_proof.py','scripts/rhea_clone_batch_publisher.py'}


def release():
    return prep.release(INSTALL,bulk.SCOPE,REQUIRED)


def read_head():
    anchor=host.read(ANCHOR_FILE)
    bulk.predecessor(anchor,bulk.ANCHOR)
    initial=dict(generation=14,sha256=bulk.ANCHOR,previous_checkpoint_sha256=iam.CHECKPOINT_SHA,
                 certified_rewrites=anchor['physical_rewrite_total'])
    if not (ROOT/'HEAD.json').exists():
        return initial,anchor
    head=host.read(ROOT/'HEAD.json')
    gen=head['generation']
    require(type(gen) is int and 15<=gen<=999999,'invalid head generation')
    state=ROOT/f'{gen:06d}'
    cert=host.read(state/'checkpoint.json')
    bulk.predecessor(cert,head['sha256'])
    require(host.read(state/'completed.json')==head and cert['generation']==gen and
            cert['physical_rewrite_total']==head['certified_rewrites'] and
            cert['previous_checkpoint_sha256']==head['previous_checkpoint_sha256'], 'head receipt differs')
    return head,cert


def commit_head(parent, successor):
    current,_=read_head()
    if current==successor:
        return
    require(current==parent and successor['generation']==parent['generation']+1
            and successor['previous_checkpoint_sha256']==parent['sha256'],'checkpoint head moved')
    fd,tmp=tempfile.mkstemp(dir=ROOT,prefix='.head-')
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(c.canonical(successor))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp,ROOT/'HEAD.json')
        with host.c_dir(ROOT) as directory:
            os.fsync(directory)
    finally:
        Path(tmp).unlink(missing_ok=True)
    require(read_head()[0]==successor,'head readback differs')


def guard(parent_reader=None):
    prod=h.production()
    require(c.digest(prod)==host.read(host.STATE/'completed.json')['production_sha256']
            and not h.main_pid(h.WRITER) and not h.main_pid(host.PROBE),'production or competing clone service changed')
    if parent_reader is not None:
        require(h.reader(True)==parent_reader and not h.main_pid(host.UNIT)
                and not h.mount_row(h.DB) and not h.preflight._open_users(parent_reader['process']['pid']),
                'clone reader changed or has an open user')
    return prod


def check_claims(raw,signature,binding,*,historical=False):
    claims=a.parse(raw)
    require(set(claims)=={'binding','issued','expires','nonce'} and a.canonical(claims['binding'])==a.canonical(binding)
            and binding['scope']==bulk.SCOPE and binding['release_sha256']==release()[0]
            and binding['target']==iam.BUCKET+'/'+iam.PREFIX and binding['limits']==bulk.limits_for(binding['generation'])
            and binding['request']['maximum_units']==binding['limits']['maximum_units'], 'admission binding differs')
    if binding['generation'] >= 18:
        sst_worker_count(binding['sst_workers'])
    if binding['generation'] >= 19:
        sst_worker_count(binding['proof_workers'])
    now=claims['issued'] if historical else int(time.time())
    require(all(type(claims[k]) is int for k in ('issued','expires')) and claims['issued']<=now<claims['expires']
            <=claims['issued']+a.MAX_LIFETIME and isinstance(claims['nonce'],str) and a.HEX.fullmatch(claims['nonce'])
            and len(set(bytes.fromhex(claims['nonce'])))>=8,'admission nonce or lifetime differs')
    a.verify_detached(raw,signature,a.protected_read(h.TRANSACTION_INSTALL/'handoff.pub'),
                      key_sha256=h.HANDOFF_KEY,domain=a.DOMAIN)
    return a.VerifiedAdmission(raw,signature,claims['nonce'],claims['expires'])


@contextlib.contextmanager
def admin_reader():
    with contextlib.closing(host.r.s3_client(*iam.p.source_credentials())) as client:
        yield client


def fixed_writer():
    return host.role_credentials('writer',iam.anchored_checkpoint())


def publish_after_policy_change(put, verify_empty, record, *, resume=False, wait=time.sleep):
    """Retry only an explicitly denied conditional PUT after rechecking the closed generation."""
    delays = (25, 65)
    for attempt in range(len(delays) + 1):
        try:
            return put(resume or attempt > 0)
        except Exception as error:
            response = getattr(error, 'response', {})
            if (attempt == len(delays) or getattr(error, 'operation_name', None) != 'PutObject'
                    or response.get('Error', {}).get('Code') != 'AccessDenied'
                    or response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 403):
                raise
            record(attempt + 1, delays[attempt])
        wait(delays[attempt])
        verify_empty()


def verify_plan(plan,cert,metadata):
    tables,stats=proof.p._decode_tables(metadata[cert['manifest']])
    before=proof.v._state(tables)
    require(before==dict(format=cert['after_format'],marked=cert['marked_after'],files=cert['sst_count'],
                         bytes=cert['sst_bytes'],inventory_sha256=cert['sst_inventory_sha256'])
            and stats['marked_files']==cert['marked_after'],'predecessor MANIFEST inventory differs')
    picker=proof.v._plan(plan['first_picker_plan'],tables)
    require(plan['request']==dict(maximum_units=bulk.limits_for(cert['generation']+1)['maximum_units'],before=before,
                                  initial_plan_sha256=picker['plan_sha256'])
            and plan['first_inputs']==sorted((dict(name=n,number=tables[n]['number'],size=tables[n]['size'],level=tables[n]['level'])
                       for n in picker['input_files']),key=lambda row:row['number']), 'picker request differs from MANIFEST')


class Batch:
    def __init__(self,generation):
        self.parent,self.cert=read_head()
        require(type(generation) is int and 15<=generation==self.parent['generation']+1<=999999,'select the next generation')
        require(INSTALL==(host.FOUR_GIB_INSTALL if generation>=17 else host.BATCH_INSTALL),
                'use the signed worker profile for this generation')
        self.generation=generation
        self.limits=bulk.limits_for(generation)
        name=f'{generation:06d}'
        self.state=ROOT/name
        self.data=host.BATCH_DATA/name
        self.mount=host.WriterMount(self.data/'writer',host.UNIT)
        self.payloads=self.data/'closed-payloads'

    def read(self,name):
        return host.read(self.state/name)

    def save(self,name,value):
        prep.save(self.state/name,value)

    def verify_remote(self, admin, binding, args, published=None):
        if self.generation < 19:
            return proof.verify(admin, *args, published, previous_sha=self.parent['sha256'])
        with contextlib.ExitStack() as stack:
            readers = [admin]
            for _ in range(1, sst_worker_count(binding['proof_workers'])):
                readers.append(stack.enter_context(admin_reader()))
            return proof.verify(admin, *args, published, previous_sha=self.parent['sha256'], sst_readers=readers)

    def opening(self):
        with admin_reader() as client:
            return proof.anchored_inventory(client,self.cert,self.parent['sha256'])

    def prepare(self, sst_workers=1, proof_workers=1):
        sst_worker_count(sst_workers)
        sst_worker_count(proof_workers)
        require(self.generation >= 19 or proof_workers == 1, 'earlier generation requires serial proof reads')
        require(self.generation >= 18 or sst_workers == 1, 'earlier generation requires serial transfers')
        require(not (self.state/'intent.json').exists(),'existing admitted batch requires resume')
        host.mkdir(self.state)
        host.mkdir(self.data)
        reader=h.reader(True)
        production=guard(reader)
        if self.generation >= 18:
            transfers = dict(workers=sst_workers, parent_sha256=self.parent['sha256'])
            if self.generation >= 19:
                transfers['proof_workers'] = proof_workers
            self.save('sst-transfer-plan.json', transfers)
        old=bulk.logical_metadata(prep.DB,self.cert)
        prep.save_metadata(self.state/'previous-metadata',old)
        proposal=host.inspector(INSTALL/'worker','plan')
        verify_plan(proposal,self.cert,old)
        if self.generation==15:
            saved=host.read(host.STATE/'readback-and-next-picker.json')['next_read_only_picker']
            require(saved['inputs']==proposal['first_inputs'] and saved['plan_sha256']==proposal['request']['initial_plan_sha256'],
                    'first successor picker differs from generation-14 readback')
        if self.generation==17:
            acceptance=host.read(ROOT/'acceptance-000015-000016.json')
            require(c.digest(acceptance)=='fd63640875568a4cce9e4b5f6a6a4f3995509a20100fb349a9996fac3d178c3a'
                    and acceptance['head']==self.parent, 'generation-16 readback differs')
            saved=acceptance['independent_readback']['next_read_only_picker']
            require(saved['inputs']==proposal['first_inputs'] and saved['plan_sha256']==proposal['request']['initial_plan_sha256'],
                    'first large picker differs from generation-16 readback')
        opening=self.opening()
        require(guard(reader)==production and read_head()[0]==self.parent,'state changed during preparation')
        if (self.state/'opening.json').exists():
            kept=self.read('opening.json')
            require(all(kept[k]==opening[k] for k in opening if k!='enumeration_metrics'),'stored opening differs')
        else:
            self.save('opening.json',opening)
        self.save('plan.json',proposal)
        return self.observation()

    def observation(self):
        reader=h.reader(True)
        production=guard(reader)
        release_sha,worker=release()
        plan=self.read('plan.json')
        opening=self.read('opening.json')
        binding=dict(scope=bulk.SCOPE,release_sha256=release_sha,worker_sha256=worker,generation=self.generation,
                    previous_checkpoint_sha256=self.parent['sha256'],anchor_sha256=bulk.ANCHOR,target=iam.BUCKET+'/'+iam.PREFIX,
                    limits=self.limits,request=plan['request'],first_inputs=plan['first_inputs'],
                    plan_sha256=c.digest(plan),physical_baseline_sha256=opening['baseline_sha256'],
                    marker_history_sha256=c.digest(opening['marker_history']),reader=reader,production=production)
        if self.generation >= 18:
            transfers = self.read('sst-transfer-plan.json')
            require(transfers['parent_sha256'] == self.parent['sha256'], 'transfer plan predecessor changed')
            binding['sst_workers'] = sst_worker_count(transfers['workers'])
            if self.generation >= 19:
                binding['proof_workers'] = sst_worker_count(transfers['proof_workers'])
        return binding

    def accept(self,envelope):
        raw=base64.b64decode(envelope['claims'],validate=True)
        sig=base64.b64decode(envelope['signature'],validate=True)
        binding=self.observation()
        verified=check_claims(raw,sig,binding)
        require(not (self.state/'intent.json').exists(), 'admitted batch cannot receive a new launch')
        directory=self.state/'admissions'
        host.mkdir(directory)
        path=directory/(verified.nonce+'.json')
        prep.save(path,envelope)
        return dict(nonce=verified.nonce,expires=verified.expires)

    def admitted(self,nonce,binding,historical=False):
        require(isinstance(nonce,str) and a.HEX.fullmatch(nonce), 'invalid admission identifier')
        envelope=host.read(self.state/'admissions'/(nonce+'.json'))
        raw=base64.b64decode(envelope['claims'],validate=True)
        sig=base64.b64decode(envelope['signature'],validate=True)
        verified=check_claims(raw,sig,binding,historical=historical)
        require(verified.nonce==nonce,'admission filename differs')
        if historical:
            require(host.read(ROOT/'consumed-nonces'/(nonce+'.json'))==dict(schema=1,claims_sha256=a.sha(raw),
                    signature_sha256=a.sha(sig),nonce=nonce),'consumed admission receipt differs')
        return verified

    def quarantine(self):
        if h.main_pid(host.UNIT):
            proc=Path('/proc')/str(h.main_pid(host.UNIT))
            args=(proc/'cmdline').read_bytes().split(b'\0')
            require(os.fsencode(self.mount.cache) in args,'active writer belongs to another transaction')
        return self.mount.quarantine()

    def park(self):
        if not (self.state/'intent.json').exists():
            return
        if self.mount.cache.exists():
            self.save('quarantine.json',self.quarantine())
        require(not h.main_pid(host.UNIT) and not h.main_pid(host.PROBE),'writer still running')
        if not h.main_pid(h.READER):
            host.collect_reader(self.read('intent.json')['binding']['reader'])
        host.start_reader()

    def write(self,nonce):
        require(not (self.state/'intent.json').exists() and not self.mount.work.exists(),'existing writer cannot be replayed')
        binding=self.observation()
        verified=self.admitted(nonce,binding)
        opening=self.opening()
        require(opening['baseline_sha256']==binding['physical_baseline_sha256'] and
                c.digest(opening['marker_history'])==binding['marker_history_sha256'],'signed physical baseline changed')
        old=proof.physical_metadata(self.state/'previous-metadata')
        require(old==bulk.logical_metadata(prep.DB,self.cert) and guard(binding['reader'])==binding['production'],
                'old metadata or production changed')
        verify_plan(self.read('plan.json'),self.cert,old)
        credential,_=fixed_writer()
        host.mkdir(ROOT/'consumed-nonces')
        with a.protected_directory(ROOT/'consumed-nonces',private=True) as fd:
            a._consume_at(fd,verified,lock_path=a.WRITER_LOCK,uid=0)
        self.save('intent.json',dict(nonce=nonce,binding=binding))
        self.save('reader-stopped.json',pilot.stopped_reader(binding['reader']))
        self.mount.prepare(old)
        ident=self.mount.start(credential)
        self.save('warm-reader.json',prep.native_inspection(self.mount,self.cert,old))
        last_guard=0
        def monitor():
            nonlocal last_guard
            self.mount.sample()
            if time.monotonic()-last_guard>=8:
                require(guard()==binding['production'] and not h.main_pid(h.READER),'reader or production changed')
                last_guard=time.monotonic()
        monitor()
        require(time.time()<verified.expires,'expired before writer launch')
        go=self.state/'go'
        host.mkdir(go)
        journal=c.Store(go)
        intent=dict(unit_count=binding['request']['maximum_units'],request=binding['request'],
                    go_binary_sha256=binding['worker_sha256'],reader_identity=binding['reader']['process'])
        self.save('writer-launch.json',dict(admission_sha256=a.sha(verified.raw),mount=ident,intent=intent))
        with journal.lock(),self.mount.launch('worker') as (proc,sock):
            receipt=host.supervisor.supervise(proc,sock,intent,journal,monitor,lambda:self.mount.sample()[1],limits=self.limits)
        self.save('writer-closed.json',receipt)
        rows,health=self.mount.sample()
        expected={row['name']:row['size'] for row in receipt['report']['sst_diff']['created']}
        require({r['name']:r['size'] for r in rows}==expected and len(rows)==len(expected),'closed queue differs')
        self.save('closed-queue.json',dict(queue=rows,health=health))
        self.save('quarantine.json',self.quarantine())

    def snapshot(self,report):
        old=proof.physical_metadata(self.state/'previous-metadata')
        new=proof.physical_metadata(self.mount.meta)
        prep.save_metadata(self.state/'closed-metadata',new)
        info=proof.closed_metadata(self.cert,old,new)
        queue=self.read('closed-queue.json')
        sizes={r['name']:r['size'] for r in report['sst_diff']['created']}
        require({r['name']:r['size'] for r in queue['queue']}==sizes and len(queue['queue'])==len(sizes),
                'closed queue differs from writer')
        host.mkdir(self.payloads)
        cache=self.mount.work/'quarantined-cache'
        fs=self.read('writer-launch.json')['mount']['fs']
        label,remote=fs.rstrip('/').split(':')
        require(remote==iam.BUCKET+'/'+iam.PREFIX.rstrip('/') and '/' not in label and label.startswith('iam_writer'),
                'quarantined backend differs')
        for name,size in sizes.items():
            require(proof.p.base.SST_NAME.fullmatch(name), 'unexpected SST name')
            relative=Path(label)/remote/name
            data=cache/'vfs'/relative
            meta=json.loads((cache/'vfsMeta'/relative).read_bytes())
            require(meta['Dirty'] is True and meta['Size']==size and meta['Rs']==[dict(Pos=0,Size=size)]
                    and data.stat().st_size==size and not data.is_symlink(),'quarantined output is incomplete')
            dest=self.payloads/name
            if not dest.exists():
                # The sealed native cache and payloads are on the same filesystem.
                os.link(data,dest,follow_symlinks=False)
                with dest.open('rb') as f:
                    os.fsync(f.fileno())
                with host.c_dir(self.payloads) as fd:
                    os.fsync(fd)
            require(os.path.samefile(data,dest),'payload does not refer to the sealed inode')
        hashes=pilot.hash_files(report,self.payloads)
        before,bs=proof.p._decode_tables(old[self.cert['manifest']])
        after,ats=proof.p._decode_tables(new[info['manifest']])
        bulk.validate_batch(report,before,after,bs,ats,hashes,limits=self.limits)
        self.save('snapshot.json',dict(hashes=hashes,writer_sha256=c.digest(report),metadata={n:c.raw_sha(b) for n,b in new.items()}))
        return old,new,hashes,info

    def finish(self,*,reconcile=False):
        claim=self.read('intent.json')
        binding=claim['binding']
        verified=self.admitted(claim['nonce'],binding,historical=True)
        launch=self.read('writer-launch.json')
        require(launch['admission_sha256']==a.sha(verified.raw) and launch['intent']['request']==binding['request']
                and launch['intent']['go_binary_sha256']==binding['worker_sha256'],'launch receipt differs')
        writer=self.read('writer-closed.json')
        bulk.validate_closed(writer,launch['intent'],self.limits)
        require(not h.main_pid(host.UNIT) and not h.main_pid(host.PROBE) and guard()==binding['production'],
                'writer not parked or production changed')
        self.save('quarantine.json',self.quarantine())
        report=writer['report']
        old,new,hashes,info=self.snapshot(report)
        opening=self.read('opening.json')
        require(opening['baseline_sha256']==binding['physical_baseline_sha256'] and
                c.digest(opening['marker_history'])==binding['marker_history_sha256'] and read_head()[0]==self.parent,
                'retained opening or parent differs')
        marker=info['manifest_marker']
        args=(opening,self.cert,old,new,report,hashes)
        with admin_reader() as admin:
            creds,account=fixed_writer()
            with contextlib.closing(host.r.s3_client(creds['AccessKeyId'],creds['SecretAccessKey'])) as raw:
                signer=host.r.live.ConditionalS3(raw)
                # Each signer installs a per-request conditional-header hook on its own SDK client.
                # Construct the clients on this thread and join every transfer before closing them.
                with contextlib.ExitStack() as extra:
                    clients = [(admin, signer)]
                    workers = binding['sst_workers'] if self.generation >= 18 else 1
                    for _ in range(1, min(sst_worker_count(workers), len(hashes))):
                        reader = extra.enter_context(admin_reader())
                        raw_writer = extra.enter_context(contextlib.closing(
                            host.r.s3_client(creds['AccessKeyId'], creds['SecretAccessKey'])))
                        clients.append((reader, host.r.live.ConditionalS3(raw_writer)))

                    def upload(pair, name, pin):
                        reader, writer = pair
                        pilot.conditional_upload(reader, writer, account, 'writer', self.payloads/name, pin,
                                                 state=self.state, reconcile_missing=reconcile)

                    transfer_ssts(hashes, clients, upload)
                for name in sorted(new.keys()-old.keys()-{marker}):
                    pilot.conditional_upload(admin,signer,account,'writer',self.state/'closed-metadata'/name,
                        dict(size=len(new[name]),sha256=c.raw_sha(new[name])),state=self.state,reconcile_missing=reconcile)
            if not (self.state/'before-publication.json').exists():
                self.save('before-publication.json',self.verify_remote(admin, binding, args))
            before=self.read('before-publication.json')
            if self.generation >= 19:
                bulk.check_read_metrics(before, binding['proof_workers'])
            require(before['physical_baseline_sha256']==binding['physical_baseline_sha256'] and before['go_report_sha256']==c.digest(report)
                    and before['previous_checkpoint_sha256']==self.parent['sha256'] and before['changed_markers']==[marker]
                    and before['mode']=='before-markers' and before['remote_generation_verified'] is False,'prepublication evidence differs')
            for name,pin in {**before['remote_metadata'],**before['created_sst_versions']}.items():
                proof.p._head_matches(admin,name,pin)
            if not (self.state/('put-'+marker+'.intent.json')).exists():
                bulk.marker_view(self.cert,opening['marker_history'],proof.enumerate_markers(admin),marker)
            require(guard()==binding['production'],'production changed before publication')
            plan=dict(bucket=iam.BUCKET,prefix=iam.PREFIX,generation=self.generation,marker=marker,
                      previous_checkpoint_sha256=self.parent['sha256'],closed_writer_sha256=c.digest(report),
                      before_proof_sha256=c.digest(before),quarantine_sha256=c.digest(self.read('quarantine.json')))
            self.save('publisher-plan.json',plan)
            creds,account=publisher.credentials(ROOT,self.state,plan)
            with contextlib.closing(host.r.s3_client(creds['AccessKeyId'],creds['SecretAccessKey'])) as raw:
                signer=host.r.live.ConditionalS3(raw)
                def put_marker(reconcile_empty):
                    return pilot.conditional_upload(admin,signer,account,'publisher',self.state/'closed-metadata'/marker,
                        dict(size=0,sha256=c.raw_sha(b'')),state=self.state,reconcile_missing=reconcile_empty)
                def verify_empty():
                    require(guard()==binding['production'] and read_head()[0]==self.parent
                            and not pilot.history(admin,marker), 'marker or generation changed during policy wait')
                    bulk.marker_view(self.cert,opening['marker_history'],proof.enumerate_markers(admin),marker)
                    for n,pin in {**before['remote_metadata'],**before['created_sst_versions']}.items():
                        proof.p._head_matches(admin,n,pin)
                def record_denial(attempt,delay):
                    self.save(f'publisher-denial-{attempt}.json',dict(marker=marker,wait_seconds=delay,
                              code='AccessDenied',policy_sha256=self.read('publisher-version.json')['sha256']))
                published=publish_after_policy_change(put_marker,verify_empty,record_denial,resume=reconcile)
            if not (self.state/'final-remote.json').exists():
                self.save('final-remote.json',self.verify_remote(admin, binding, args, published))
            final=self.read('final-remote.json')
            if self.generation >= 19:
                bulk.check_read_metrics(final, binding['proof_workers'])
            bulk.marker_view(self.cert,opening['marker_history'],proof.enumerate_markers(admin),marker,published)
        if h.main_pid(h.READER):
            pilot.stopped_reader(h.reader(True))
        reader=host.start_reader()
        logical=bulk.logical_metadata(prep.DB,final)
        reopen=host.inspector(INSTALL/'worker','inspect')
        require(bulk.logical_metadata(prep.DB,final)==logical and h.reader(True)==reader and guard(reader)==binding['production'],
                'cold reader or production changed')
        cert=bulk.finalize(self.cert,before,final,reopen,logical)
        self.save('checkpoint.json',cert)
        successor=dict(generation=self.generation,sha256=c.digest(cert),previous_checkpoint_sha256=self.parent['sha256'],
                       certified_rewrites=cert['physical_rewrite_total'])
        self.save('completed.json',successor)
        commit_head(self.parent,successor)
        return dict(successor,marked_after=cert['marked_after'],stop_reason=report['stop_reason'])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('status','prepare','observe','accept','run','resume','park'))
    parser.add_argument('generation',nargs='?',type=int)
    parser.add_argument('nonce',nargs='?')
    parser.add_argument('--sst-workers', type=int, choices=range(1,5),
                        help='concurrent sealed SST transfers for a new admission (default 1)')
    parser.add_argument('--proof-workers', type=int, choices=range(1,5),
                        help='concurrent version-pinned SST reads within each proof (default 1)')
    args=parser.parse_args(argv)
    if args.sst_workers is not None and args.mode != 'prepare':
        parser.error('--sst-workers applies to prepare only')
    if args.proof_workers is not None and args.mode != 'prepare':
        parser.error('--proof-workers applies to prepare only')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    with prep.writer_lock():
        release()
        host.mkdir(ROOT)
        head,cert=read_head()
        if args.mode=='status':
            return dict(head=head,marked=cert['marked_after'],next_generation=head['generation']+1)
        if args.generation==head['generation'] and args.mode in ('run','resume','park'):
            return dict(head,phase='already certified')
        require(args.generation is not None or args.mode=='prepare','an explicit generation is required')
        batch=Batch(args.generation if args.generation is not None else head['generation']+1)
        if args.mode=='prepare':
            return batch.prepare(args.sst_workers or 1, args.proof_workers or 1)
        if args.mode=='observe':
            return batch.observation()
        if args.mode=='accept':
            return batch.accept(c.parse(sys.stdin.buffer.read(65537)))
        if args.mode=='park':
            batch.park()
            return dict(parked=True)
        try:
            if args.mode=='run':
                batch.write(args.nonce)
            return batch.finish(reconcile=args.mode=='resume')
        finally:
            batch.park()


if __name__=='__main__':
    print(c.canonical(main()).decode(),end='')
