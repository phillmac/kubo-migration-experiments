// Copyright 2026. Experimental synthetic-only Pebble v1.1.3 adapter.
// This file is copied into a temporary, exact-version Pebble module checkout
// on an isolated GitHub-hosted runner. Never patch the live Rhea installation.
//
// Unlike RatchetFormatMajorVersion(14), this schedules precisely one internally
// picked marked-file rewrite and returns only when it has completed.
package pebble

import (
 "errors"
 "fmt"
)

type DemoRewritePlan struct {
 InputLevel int
 InputFiles []string
 InputBytes uint64
}

// DemoRewriteOneMarkedFile is intentionally NOT a supported upstream API.
// It is a code-reviewed experiment to demonstrate Pebble's own marked-file
// picker as a bounded atomic unit. It requires automatic compactions disabled.
func (d *DB) DemoRewriteOneMarkedFile(maxInputBytes uint64) (DemoRewritePlan,error) {
 result:=DemoRewritePlan{}
 if maxInputBytes==0 {return result,errors.New("nonzero input limit is required")}
 if err:=d.closed.Load();err!=nil{return result,err.(error)}
 d.mu.Lock()
 if !d.opts.DisableAutomaticCompactions {
  d.mu.Unlock()
  return result,errors.New("demo requires automatic compactions disabled")
 }
 if d.mu.compact.compactingCount!=0 {
  d.mu.Unlock()
  return result,errors.New("demo requires no other compactions in progress")
 }
 if d.mu.versions.currentVersion().Stats.MarkedForCompaction==0 {
  d.mu.Unlock()
  return result,errors.New("no marked files remain")
 }
 // Follow the same versionSet locking and environment fields used by
 // maybeScheduleCompactionPicker. Do not call that helper: it could loop.
 d.mu.versions.logLock()
 env:=compactionEnv{
  diskAvailBytes:d.diskAvailBytes.Load(),
  earliestSnapshotSeqNum:d.mu.snapshots.earliest(),
  earliestUnflushedSeqNum:d.getEarliestUnflushedSeqNumLocked(),
  inProgressCompactions:d.getInProgressCompactionInfoLocked(nil),
 }
 pc:=d.mu.versions.picker.pickRewriteCompaction(env)
 d.mu.versions.logUnlock()
 if pc==nil {
  d.mu.Unlock()
  return result,errors.New("marked rewrite picker returned no compaction")
 }
 result.InputLevel=pc.startLevel.level
 it:=pc.startLevel.files.Iter()
 for f:=it.First();f!=nil;f=it.Next() {
  result.InputFiles=append(result.InputFiles,f.FileNum.String())
  result.InputBytes+=f.Size
 }
 if result.InputBytes==0 || result.InputBytes>maxInputBytes {
  d.mu.Unlock()
  return result,fmt.Errorf("chosen atomic unit %d bytes exceeds maximum %d",result.InputBytes,maxInputBytes)
 }
 // Schedule exactly one compaction using the original internal rewrite
 // picker/constructor. The standard completion path respects our disabled
 // automatic compactions option and will not chain a second rewrite.
 c:=newCompaction(pc,d.opts,d.timeNow(),d.ObjProvider())
 d.mu.compact.compactingCount++
 d.addInProgressCompaction(c)
 done:=make(chan error,1)
 go d.compact(c,done)
 d.mu.Unlock()
 err:=<-done
 d.mu.Lock()
 for d.mu.compact.compactingCount>0 {
  d.mu.compact.cond.Wait()
 }
 d.mu.Unlock()
 return result,err
}
