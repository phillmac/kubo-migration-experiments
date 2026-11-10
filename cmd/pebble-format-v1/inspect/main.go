// Command inspect is a read-only preflight for the disposable Rhea Wasabi clone.
// It never starts Kubo, never writes Pebble, and refuses non-laboratory paths.
package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/cockroachdb/pebble"
)

const (
 labMount = "/mnt/rhea-pebble-lab-reader-20261102"
 labDB = labMount + "/pebbleds"
)

type SST struct {
 Number string `json:"number"`
 Bytes uint64 `json:"bytes"`
}
type AtomicUnits struct {
 UnitCount int `json:"unit_count"`
 MultiFileUnits int `json:"multi_file_units"`
 MaxFilesPerUnit int `json:"max_files_per_unit"`
 MaxUnitBytes uint64 `json:"max_unit_bytes"`
 UnitsAbove128MiB int `json:"units_above_128mib"`
 UnitsAbove256MiB int `json:"units_above_256mib"`
}
type Level struct {
 Level int `json:"level"`
 Count int `json:"count"`
 Bytes uint64 `json:"bytes"`
 MinSize uint64 `json:"min_sst_bytes"`
 MaxSize uint64 `json:"max_sst_bytes"`
 VirtualFiles int `json:"virtual_files"`
 Largest []SST `json:"largest_files"`
 Atomic AtomicUnits `json:"atomic_units"`
}
type Report struct {
 Scope string `json:"scope"`
 ReadOnly bool `json:"read_only"`
 FormatMajorVersion string `json:"format_major_version"`
 MarkedFiles int `json:"marked_files"`
 SSTCount int `json:"sst_count"`
 SSTBytes uint64 `json:"sst_bytes"`
 EstimatedMaxAtomicInputBytes uint64 `json:"estimated_max_atomic_input_bytes"`
 Levels []Level `json:"levels"`
 ElapsedSeconds float64 `json:"elapsed_seconds"`
}

func validate(path string) error {
 if path != labDB { return errors.New("refusing a path outside the exact disposable reader mount") }
 for _, p := range []string{labMount,labDB} {
  fi,err:=os.Lstat(p)
  if err!=nil {return err}
  if !fi.IsDir() || fi.Mode()&os.ModeSymlink!=0 {return errors.New("path is not a real lab directory")}
  real,err:=filepath.EvalSymlinks(p)
  if err!=nil || real!=p {return errors.New("symlinks not permitted")}
 }
 b,err:=os.ReadFile("/proc/self/mountinfo")
 if err!=nil{return err}
 var matched bool
 for _,line:=range strings.Split(string(b),"\n") {
  parts:=strings.SplitN(line," - ",2)
  if len(parts)!=2 {continue}
  left:=strings.Fields(parts[0]);right:=strings.Fields(parts[1])
  if len(left)<5 || len(right)<2 || left[4]!=labMount {continue}
  if right[0]!="fuse.rclone" || !strings.Contains(right[1],"rhea_pebble_lab_reader") {
   return errors.New("lab mount is not the read-only IAM rclone identity")
  }
  matched=true
 }
 if !matched{return errors.New("required disposable FUSE mount was not found")}
 return nil
}

func main() {
 dbPath:=flag.String("db","","exact lab Pebble directory")
 flag.Parse()
 if flag.NArg()!=0 || *dbPath=="" {fmt.Fprintln(os.Stderr,"usage: inspect --db "+labDB);os.Exit(2)}
 if err:=validate(*dbPath);err!=nil {fmt.Fprintln(os.Stderr,"safety gate:",err);os.Exit(2)}
 start:=time.Now()
 db,err:=pebble.Open(*dbPath,&pebble.Options{
  ErrorIfNotExists:true,ReadOnly:true,FormatMajorVersion:pebble.FormatMostCompatible,
 })
 if err!=nil {fmt.Fprintln(os.Stderr,"read-only Pebble open failed:",err);os.Exit(1)}
 format:=db.FormatMajorVersion()
 metrics:=db.Metrics()
 tables,err:=db.SSTables()
 if err!=nil {_=db.Close();fmt.Fprintln(os.Stderr,"SSTables:",err);os.Exit(1)}
 result:=Report{
  Scope:"lab-reader-only",ReadOnly:true,FormatMajorVersion:format.String(),
  MarkedFiles:metrics.Compact.MarkedFiles,Levels:make([]Level,0,len(tables)),
 }
 for i,level:=range tables {
  l:=Level{Level:i,Count:len(level),Largest:[]SST{}}
  for _,entry:=range level {
   size:=entry.Size
   l.Bytes+=size
   if l.MinSize==0 || size<l.MinSize {l.MinSize=size}
   if size>l.MaxSize {l.MaxSize=size}
   if entry.Virtual {l.VirtualFiles++}
   s:=SST{Number:entry.FileNum.String(),Bytes:size}
   inserted:=false
   for j,old:=range l.Largest {
    if s.Bytes>old.Bytes {
     l.Largest=append(l.Largest,SST{})
     copy(l.Largest[j+1:],l.Largest[j:])
     l.Largest[j]=s
     inserted=true;break
    }
   }
   if !inserted && len(l.Largest)<5 {l.Largest=append(l.Largest,s)}
   if len(l.Largest)>5 {l.Largest=l.Largest[:5]}
  }
  // Mirrors the v1.1.3 expandToAtomicUnit user-key boundary rule for
  // non-overlapping L1-L6. This is a preflight estimate, not Pebble's
  // authoritative compaction picker or a durable marked-file count.
  var unitBytes uint64
  var unitCount int
  closeUnit:=func() {
   if unitCount==0{return}
   l.Atomic.UnitCount++
   if unitCount>1{l.Atomic.MultiFileUnits++}
   if unitCount>l.Atomic.MaxFilesPerUnit{l.Atomic.MaxFilesPerUnit=unitCount}
   if unitBytes>l.Atomic.MaxUnitBytes{l.Atomic.MaxUnitBytes=unitBytes}
   if unitBytes>128*1024*1024{l.Atomic.UnitsAbove128MiB++}
   if unitBytes>256*1024*1024{l.Atomic.UnitsAbove256MiB++}
  }
  for j,entry:=range level {
   joined:=false
   if i>0 && j>0 {
    prev:=level[j-1]
    joined= !prev.Largest.IsExclusiveSentinel() && bytes.Equal(prev.Largest.UserKey,entry.Smallest.UserKey)
   }
   if !joined{closeUnit();unitBytes=0;unitCount=0}
   unitBytes+=entry.Size
   unitCount++
  }
  closeUnit()
  if l.Atomic.MaxUnitBytes>result.EstimatedMaxAtomicInputBytes{
   result.EstimatedMaxAtomicInputBytes=l.Atomic.MaxUnitBytes
  }
  result.Levels=append(result.Levels,l)
  result.SSTCount+=l.Count
  result.SSTBytes+=l.Bytes
 }
 if err:=db.Close();err!=nil {fmt.Fprintln(os.Stderr,"close:",err);os.Exit(1)}
 result.ElapsedSeconds=time.Since(start).Seconds()
 if err:=json.NewEncoder(os.Stdout).Encode(result);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
