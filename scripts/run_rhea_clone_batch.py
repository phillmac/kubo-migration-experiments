"""On the jump host, admit or resume one numbered disposable clone checkpoint."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import tempfile
import time

TARGET='rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/'
ANCHOR='7c83ebd87b1194c1624f7455a2e330af686ca9a1421e58e00051ebe5473bd09c'
SCOPE='rhea-disposable-clone-byte-capped-batch-v1'
CTL='/root/.local/share/rhea-clone-batch-runner-v1/scripts/rhea_clone_batch_runner.py'
LARGE_CTL='/root/.local/share/rhea-clone-batch-runner-4g-v1/scripts/rhea_clone_batch_runner.py'
KEYS=Path.home()/'.local/share/rhea-gen14-handoff-signing-20261127'
RELEASE_PUB='1e795ba5e4727de5c5ad7d3500afeb0c0bc5bb4f0510195a1333b18ed1f13e6f'
ADMISSION_PUB='8ae285df7e903cad9b2806f1f96d53060b4d968863a2436d062a8a45ef7a9102'


def require(condition,message):
    if not condition:
        raise RuntimeError(message)


def canonical(obj):
    return (json.dumps(obj,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def remote(args,data=None):
    connection=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=12',
                '-i',str(Path.home()/'.ssh/id_ed25519_rhea'),'ubuntu@192.99.21.37']
    return subprocess.check_output([*connection,shlex.join(['sudo','-n',*args])],input=data,timeout=900)


def verify_release(path,tmp):
    raw=path.read_bytes()
    public=subprocess.check_output(['openssl','pkey','-in',str(KEYS/'release.pem'),'-pubout'])
    require(digest(public)==RELEASE_PUB,'release identity differs')
    (tmp/'release.pub').write_bytes(public)
    (tmp/'message').write_bytes(b'RHEA-MULTI-SST-DEPLOYMENT-v1\0'+raw)
    subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(tmp/'release.pub'),'-rawin','-in',
                    str(tmp/'message'),'-sigfile',str(path.with_suffix('.sig'))],stdout=subprocess.DEVNULL,check=True)
    manifest=json.loads(raw)
    require(manifest['scope']==SCOPE and re.fullmatch('[a-f0-9]{64}',manifest['files']['worker']),'wrong release')
    return digest(raw),manifest['files']['worker']


def validate(binding,head,gen,release,worker,*,sst_workers=1,proof_workers=1):
    require(binding['scope']==SCOPE and binding['target']==TARGET and binding['anchor_sha256']==ANCHOR
            and binding['generation']==gen==head['generation']+1 and binding['previous_checkpoint_sha256']==head['sha256']
            and binding['release_sha256']==release and binding['worker_sha256']==worker,'requested generation, signer or target differs')
    limits=dict(maximum_units=8,input_bytes=512<<20,sst_output_bytes=512<<20,metadata_write_bytes=64<<20,
                cache_bytes=96<<30,minimum_free_bytes=2<<40,backlog_bytes=768<<20,backlog_files=256)
    if gen >= 17:
        limits.update(maximum_units=64,input_bytes=4<<30,sst_output_bytes=4<<30,backlog_bytes=5<<30)
    if gen >= 18:
        received = binding.get('sst_workers')
        require(type(received) is int and type(sst_workers) is int and 1 <= received == sst_workers <= 4,
                'requested concurrent SST count differs')
    else:
        require(sst_workers == 1, 'earlier generation requires serial transfers')
    if gen >= 19:
        received = binding.get('proof_workers')
        require(type(received) is int and type(proof_workers) is int and 1 <= received == proof_workers <= 4,
                'requested proof read count differs')
    else:
        require(proof_workers == 1, 'earlier generation requires serial proof reads')
    req=binding['request']
    require(binding['limits']==limits and req['maximum_units']==limits['maximum_units'] and req['before']['format']=='013'
            and req['before']['marked']>0 and binding['first_inputs'] and binding['production']['queue']==0
            and binding['production']['uploadsInProgress']==0 and binding['production']['erroredFiles']==0,
            'unexpected byte limits, picker state or production activity')
    if gen==15:
        require(head['sha256']==ANCHOR and req['initial_plan_sha256']=='3938d034fbbd929ff5c9095015fcaad668b1f4ee832ef53d4d9928dceb6fc210',
                'first batch differs from the independently retained next picker')
    if gen == 17:
        require(head['sha256']=='7fb1712a6d08b8a9744472a3e9ee8d7bcda8dfcf0fcacfd1d4f23da54b26f445'
                and req['initial_plan_sha256']=='4fd51080c5a17e199061dd88b37104b1a31988881d793aa92a94d5a9f8e9b08c',
                'large batch differs from the certified generation-16 picker')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('generation',type=int)
    parser.add_argument('--release',required=True,type=Path,help='signed local release manifest with adjacent .sig')
    parser.add_argument('--resume',action='store_true',help='reconcile closed output and finish certification')
    parser.add_argument('--sst-workers', type=int, choices=range(1,5),
                        help='concurrent sealed SST transfers for a new admission (default 1)')
    parser.add_argument('--proof-workers', type=int, choices=range(1,5),
                        help='concurrent version-pinned SST reads per proof (default 1)')
    args=parser.parse_args()
    if args.proof_workers is not None and (args.resume or args.generation < 19):
        parser.error('--proof-workers applies to new admissions from generation 19 onward')
    if args.sst_workers is not None and (args.resume or args.generation < 18):
        parser.error('--sst-workers applies to new admissions from generation 18 onward')
    os.umask(0o077)
    cmd=['/usr/bin/python3','-I','-B',LARGE_CTL if args.generation>=17 else CTL]
    with tempfile.TemporaryDirectory(dir=KEYS,prefix='batch-admission.') as temp:
        tmp=Path(temp)
        sha,worker=verify_release(args.release,tmp)
        status=json.loads(remote([*cmd,'status']))
        head=status['head']
        if head['generation']==args.generation:
            print(json.dumps(dict(head,phase='already certified')))
            return
        require(head['generation']+1==args.generation,'select the current successor')
        number=str(args.generation)
        run_args=['resume',number]
        if not args.resume:
            workers = args.sst_workers or 1
            options = ['--sst-workers', str(workers)] if args.generation >= 18 else []
            proof_workers = args.proof_workers or 1
            if args.generation >= 19:
                options.extend(['--proof-workers', str(proof_workers)])
            binding=json.loads(remote([*cmd,'prepare',number,*options]))
            validate(binding,head,args.generation,sha,worker,sst_workers=workers,proof_workers=proof_workers)
            now=int(time.time())
            nonce=secrets.token_hex(32)
            raw=canonical(dict(binding=binding,issued=now,expires=now+895,nonce=nonce))
            public=subprocess.check_output(['openssl','pkey','-in',str(KEYS/'handoff.pem'),'-pubout'])
            require(digest(public)==ADMISSION_PUB,'batch signer differs')
            message=tmp/'message'
            message.write_bytes(b'RHEA-MULTI-SST-ADMISSION-v1\0'+raw)
            sig=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',str(KEYS/'handoff.pem'),'-in',str(message)])
            envelope=canonical(dict(claims=base64.b64encode(raw).decode(),signature=base64.b64encode(sig).decode()))
            accepted=json.loads(remote([*cmd,'accept',number],envelope))
            require(accepted['nonce']==nonce,'accepted admission differs')
            run_args=['run',number,nonce]
        unit=f'rhea-clone-batch-{args.generation:06d}'
        remote(['/usr/bin/systemd-run','--quiet','--collect','--no-block','--service-type=exec','--unit='+unit,
                '-p','RuntimeMaxSec=7200','-p','MemoryMax=8G','-p','UMask=0077','-p',
                'ExecStopPost='+shlex.join([*cmd,'park',number]),*cmd,*run_args])
        print(json.dumps(dict(generation=args.generation,unit=unit,mode=run_args[0],phase='started')))


if __name__=='__main__':
    main()
