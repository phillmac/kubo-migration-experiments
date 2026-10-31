#!/usr/bin/env python3
"""Prove Pebble v1 format-13 ratchet without a Kubo daemon, synthetic repos only.

Runs in isolated, loopback-only GitHub runner namespace; nothing connects to Rhea.
It tests whether Kubo v0.43.1/Pebble v2 can then open a schema-18 repository
with the format explicitly pinned to 13. Does not claim production acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from kubo_migration_lab import Lab, Refusal, migrate_schema, require_isolation, verify_binary

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--base',required=True)
    for name in ('old','target','standalone'):
        p.add_argument('--'+name,required=True)
        p.add_argument('--'+name+'-sha256',required=True)
    args=p.parse_args()
    require_isolation()
    binaries={name:verify_binary(getattr(args,name),getattr(args,name+'_sha256'))
              for name in ('old','target','standalone')}
    lab=Lab(args.base)
    report={'scope':'synthetic-clone-only','uses_kubo_daemon':False,
            'standalone_pebble_migration':False,'target_kubo_opens':False,
            'production_approved':False,'lab_path':str(lab.root)}
    print('EVIDENCE='+str(lab.evidence),flush=True)
    try:
        repo=lab.root/'seed'
        repo.mkdir()
        for name,expected in [('old','0.31.0'),('target','0.43.1')]:
            version=lab.run(binaries[name],repo,'version','--number')[1].decode().strip()
            if version!=expected:raise Refusal('Wrong binary version '+name+': '+version)
        lab.run(binaries['old'],repo,'init','--profile=pebbleds')
        data=hashlib.shake_256(b'standalone-format13-synthetic').digest(8*1024*1024)
        file=lab.root/'sample.bin'
        file.write_bytes(data)
        root=lab.run(binaries['old'],repo,'add','-Q','--cid-version=0','--raw-leaves=false',str(file))[1].decode().strip()
        raw_data=b'Unpinned synthetic direct Pebble verification block.'
        raw_file=lab.root/'raw.bin'
        raw_file.write_bytes(raw_data)
        raw=lab.run(binaries['old'],repo,'block','put','--cid-codec=raw','--mhtype=sha2-256',str(raw_file))[1].decode().strip()
        lab.run(binaries['old'],repo,'files','cp','/ipfs/'+root,'/sample.bin')
        baseline=lab.fingerprint(binaries['old'],repo,root,raw,data,raw_data)
        sealed=lab.clone(repo,'rollback-control')
        clone=lab.clone(repo,'stage13')
        done=subprocess.run([str(binaries['standalone']),'--lab-root',str(lab.root),
                             '--db',str(clone/'pebbleds'),'--target-format=13'],
                             capture_output=True,text=True,timeout=180)
        report['standalone_exit_code']=done.returncode
        report['standalone_stdout']=done.stdout[-2500:]
        report['standalone_stderr']=done.stderr[-2500:]
        if done.returncode:raise Refusal('Standalone v1 format-13 stage failed: '+done.stderr[-1200:])
        evidence=json.loads(done.stdout)
        if evidence['format_after']!='013':raise Refusal('Unexpected format major '+str(evidence))
        report['standalone_pebble_migration']=True
        # Pin format before target Kubo runs: its default upgrades to newest.
        conf=clone/'config'
        cfg=json.loads(conf.read_text())
        spec=cfg['Datastore']['Spec']
        if spec['type']!='pebbleds' or spec['path']!='pebbleds':
            raise Refusal('Unexpected datastore layout')
        if 'formatMajorVersion' in spec:raise Refusal('Synthetic baseline unexpectedly pinned a format')
        spec['formatMajorVersion']=13
        conf.write_text(json.dumps(cfg,indent=2)+'\n')
        report['format_pinned_in_new_kubo_config']=13
        report['schema_migration']=migrate_schema(lab,binaries['target'],clone)
        actual=lab.fingerprint(binaries['target'],clone,root,raw,data,raw_data)
        if actual!=baseline:raise Refusal('Logical data changed across independent Pebble format migration')
        report['target_kubo_opens']=True
        report['target_repo_version']=(clone/'version').read_text().strip()
        report['target_format_markers']=[p.name for p in (clone/'pebbleds').glob('*format-version*')]
        if lab.fingerprint(binaries['old'],sealed,root,raw,data,raw_data)!=baseline:
            raise Refusal('Frozen old-version restore failed')
        report['rollback_restored']=True
        report['status']='synthetic-standalone-format13-then-kubo-v2-success'
        print('STANDALONE_FORMAT13_SUCCESS',json.dumps({k:v for k,v in report.items() if k not in ('lab_path','standalone_stdout','standalone_stderr')}),flush=True)
    except Exception as exc:
        report['status']='failed'
        report['error']=str(exc)
        print('STANDALONE_FORMAT13_FAILURE',str(exc),flush=True)
        raise
    finally:
        (lab.evidence/'standalone-format13-result.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
