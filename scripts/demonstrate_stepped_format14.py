#!/usr/bin/env python3
"""Independent Pebble v1 SST compaction demonstration with closed checkpoints.

Synthetic only. Each action opens and closes Pebble through a standalone
Go utility, then this harness reopens a distinct invocation and checks
marked-file counts, SST changes and app-level pin/MFS integrity.

Invoked inside a loopback-only network namespace on a throwaway GitHub runner.
No Kubo daemon, production repository, rclone cache or real Wasabi prefix.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from kubo_migration_lab import Lab, Refusal, migrate_schema, require_isolation, verify_binary
from test_standalone_pebble_format13 import fingerprint_with_pinned_format

MIB=1024**2
IO_OPS="read,readv,pread64,write,writev,pwrite64,fsync,fdatasync,openat,unlinkat,renameat,renameat2,close"
RE = re.compile(r"^(read|readv|pread64|write|writev|pwrite64)\(\d+<([^>]+)>.*\)\s+=\s+(\d+)")
RE_TID = re.compile(r"^\[pid \d+\] ")
def trace_byte_totals(prefix,repo):
    totals={}
    files={}
    for path in sorted(prefix.parent.glob(prefix.name+".*")):
        for line in path.read_text(errors="replace").splitlines():
            line=RE_TID.sub("",line).strip()
            match=RE.match(line)
            if not match:continue
            op,source,count=match.groups()
            if not source.startswith(str(repo)+"/"):
                continue
            if not source.endswith(".sst"):
                continue
            which="read" if op in ("read","readv","pread64") else "write"
            amount=int(count)
            totals[which]=totals.get(which,0)+amount
            name=Path(source).name
            entry=files.setdefault(name,{"read":0,"write":0})
            entry[which]+=amount
    return {"sst_syscall_bytes":totals,
            "sst_files_touched":len(files),
            "sst_file_IO":files,
            "trace_file_count":len(list(prefix.parent.glob(prefix.name+".*")))}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base",required=True)
    p.add_argument("--old",required=True)
    p.add_argument("--old-sha256",required=True)
    p.add_argument("--target",required=True)
    p.add_argument("--target-sha256",required=True)
    p.add_argument("--demo",required=True)
    p.add_argument("--demo-sha256",required=True)
    p.add_argument("--groups",type=int,default=4)
    p.add_argument("--keys-per-group",type=int,default=2048)
    args=p.parse_args()
    require_isolation()
    if not 2<=args.groups<=6 or not 256<=args.keys_per_group<=4096:
        raise Refusal("fixture bounds outside supported synthetic range")
    binary={key:verify_binary(getattr(args,key),getattr(args,key+"_sha256"))
            for key in ("old","target","demo")}
    lab=Lab(args.base)
    report={"scope":"isolated-synthetic-standalone-Pebble-v1",
            "production_approved":False,"kubo_daemon_used":False,
            "lab_path":str(lab.root),"steps":[]}
    print("EVIDENCE="+str(lab.evidence),flush=True)
    trace_dir=lab.root/"trace-capture"
    trace_dir.mkdir()
    def demo(repo,action,group=0,measure=False,limit=16*MIB):
        c=[str(binary["demo"]),"--lab-root",str(lab.root),"--db",str(repo/"pebbleds"),
           "--action",action,"--groups",str(args.groups),
           "--keys-per-group",str(args.keys_per_group),
           "--value-bytes","1536","--group",str(group),
           "--max-overlap-bytes",str(limit)]
        trace_prefix=trace_dir/("step-%02d" % group)
        if measure:
            c=["strace","-ff","-yy","-s","0",
               "-e","trace="+IO_OPS,"-o",str(trace_prefix)]+c
        result=subprocess.run(c,capture_output=True,text=True,timeout=180)
        if result.returncode:
            raise Refusal("standalone Pebble %s failed: %s %s" %
                          (action,result.stdout[-2000:],result.stderr[-1000:]))
        if len(result.stdout)>4*MIB:
            raise Refusal("unexpected demo output size")
        output=json.loads(result.stdout)
        if output.get("error"):
            raise Refusal("%s error %s" % (action,output["error"]))
        if measure:
            output["measured_SST_IO"]=trace_byte_totals(trace_prefix,repo)
        print("STEP_RESULT",json.dumps({"action":action,"group":group,
            "marked_before":output["marked_before"],
            "marked_after":output["marked_after"],
            "format_before":output["format_before"],
            "format_after":output["format_after"],
            "sst_diff":output["sst_diff"],
            "measured_SST_IO":output.get("measured_SST_IO")},sort_keys=True),flush=True)
        return output
    try:
        repo=lab.root/"seed"
        repo.mkdir()
        if lab.run(binary["old"],repo,"version","--number")[1].decode().strip()!="0.31.0":
            raise Refusal("wrong baseline Kubo")
        if lab.run(binary["target"],repo,"version","--number")[1].decode().strip()!="0.43.1":
            raise Refusal("wrong target Kubo")
        lab.run(binary["old"],repo,"init","--profile=pebbleds")
        payload=hashlib.shake_256(b"stepped-format14-demo").digest(2*MIB)
        source=lab.root/"fixture.bin"
        source.write_bytes(payload)
        raw_payload=b"unique standalone-compaction demonstration raw block"
        raw_source=lab.root/"raw.bin"
        raw_source.write_bytes(raw_payload)
        root=lab.run(binary["old"],repo,"add","-Q","--cid-version=0",
                     "--raw-leaves=false",str(source))[1].decode().strip()
        raw=lab.run(binary["old"],repo,"block","put","--cid-codec=raw",
                    "--mhtype=sha2-256",str(raw_source))[1].decode().strip()
        lab.run(binary["old"],repo,"files","cp","/ipfs/"+root,"/fixture.bin")
        baseline=lab.fingerprint(binary["old"],repo,root,raw,payload,raw_payload)
        rollback=lab.clone(repo,"rollback-control")
        working=lab.clone(repo,"working")
        seeded=demo(working,"seed")
        report["seed"]={"count":seeded["keys_after"],"sha256":seeded["keys_sha256_after"],
                        "sst_count":seeded["sst_count_after"]}
        if seeded["keys_after"]!=args.groups*args.keys_per_group:
            raise Refusal("seed key count mismatch")
        prepared=demo(working,"prepare")
        report["prepare"]={"marked":prepared["marked_after"],"format":prepared["format_after"]}
        if prepared["format_after"]!="013" or prepared["marked_after"]<2:
            raise Refusal("insufficient marked files for a stepped rewrite")
        expected_sha=prepared["keys_sha256_after"]
        expected_keys=prepared["keys_after"]
        prior=prepared["marked_after"]
        for group in range(args.groups):
            if prior==0:break
            step=demo(working,"step",group=group,measure=True)
            if step["marked_before"]!=prior or step["marked_after"]>=prior:
                raise Refusal("manual step did not monotonically reduce marked SST count")
            if step["sst_diff"]["created_count"]<1 or step["sst_diff"]["retired_count"]<1:
                raise Refusal("manual compaction did not retire and create SSTs")
            if step["sst_diff"]["created_bytes"]>64*MIB:
                raise Refusal("synthetic step output exceeded bound")
            if step["keys_sha256_after"]!=expected_sha or step["keys_after"]!=expected_keys:
                raise Refusal("synthetic payload altered")
            record={k:step[k] for k in ("group","marked_before","marked_after",
                        "sst_diff","preflight_overlap_bytes","measured_SST_IO",
                        "elapsed_seconds")}
            report["steps"].append(record)
            # A separate fresh process must re-open the closed database and
            # observe exactly the same durable marked count and key checksum.
            reopened=demo(working,"inspect")
            if (reopened["marked_after"]!=step["marked_after"] or
                reopened["keys_sha256_after"]!=expected_sha):
                raise Refusal("closed Pebble checkpoint lost its progress")
            prior=step["marked_after"]
        if len(report["steps"])<2:
            raise Refusal("fewer than two independently closed manual compactions")
        if prior!=0:
            raise Refusal("not all marked files were cleared by bounded test ranges: %d" % prior)
        finish=demo(working,"finish",measure=False)
        if finish["format_after"]!="014":
            raise Refusal("final format14 ratchet failed")
        if finish["sst_diff"]["created_count"] or finish["sst_diff"]["retired_count"]:
            raise Refusal("final ratchet unexpectedly rewrote SSTs")
        report["finish"]=finish
        # Kubo 0.43.1 must be configured to pin format 14 before opening;
        # otherwise its default is to ratchet to the newest version.
        config_path=working/"config"
        config=json.loads(config_path.read_text())
        spec=config["Datastore"]["Spec"]
        if spec.get("type")=="measure" and spec.get("prefix")=="pebble.datastore":
            spec=spec["child"]
        if spec.get("type")!="pebbleds":
            raise Refusal("unexpected new Kubo datastore type")
        spec["formatMajorVersion"]=14
        config_path.write_text(json.dumps(config,indent=2)+"\n")
        report["schema_migration"]=migrate_schema(lab,binary["target"],working)
        target=fingerprint_with_pinned_format(lab,binary["target"],working,root,
                                               raw,payload,raw_payload)
        if target!=baseline:raise Refusal("target Kubo content, pins or MFS changed")
        report["target_verified"]=True
        if lab.fingerprint(binary["old"],rollback,root,raw,payload,raw_payload)!=baseline:
            raise Refusal("old-generation rollback failed")
        report["old_rollback_verified"]=True
        report["result"]="success: bounded SST rewrites + independent closes + final fmt14 + Kubo0.43"
        print("DEMO_VERIFIED",json.dumps({"steps":len(report["steps"]),
            "marked_at_start":prepared["marked_after"],"marked_at_finish":prior,
            "target_verified":True,"old_rollback_verified":True}),flush=True)
    except Exception as exc:
        report["result"]="failed"
        report["error"]=str(exc)
        print("DEMO_FAILED",str(exc),flush=True)
        raise
    finally:
        report_path=lab.evidence/"stepped-format14-result.json"
        report_path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        print("RESULT_REPORT",report_path,flush=True)

if __name__=="__main__":
    main()
