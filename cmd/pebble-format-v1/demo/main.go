// Command stepped-demo proves bounded, resumable *manual* Pebble rewrites.
// It only accepts disposable kubo-lab-* repositories, never production paths.
// Each invocation opens and closes Pebble; no Kubo daemon is involved.
package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "hash"
 "math/rand"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "sync"
 "time"

 "github.com/cockroachdb/pebble"
)

type table struct {
 Number string
 Level int
 Size uint64
 First string
 Last string
}

type result map[string]interface{}

func guard(root, db string) error {
 if !filepath.IsAbs(root) || !filepath.IsAbs(db) { return errors.New("paths must be absolute") }
 root=filepath.Clean(root);db=filepath.Clean(db)
 if !strings.HasPrefix(filepath.Base(root),"kubo-lab-") || filepath.Base(db)!="pebbleds" || filepath.Dir(filepath.Dir(db))!=root {
  return errors.New("only <kubo-lab-*>/<synthetic-child>/pebbleds allowed")
 }
 for _, p:=range []string{root,filepath.Dir(db),db} {
  fi,err:=os.Lstat(p);if err!=nil{return err}
  if !fi.IsDir() || fi.Mode()&os.ModeSymlink!=0{return fmt.Errorf("not a real directory: %s",p)}
  real,err:=filepath.EvalSymlinks(p);if err!=nil||real!=p{return errors.New("symlink path denied")}
 }
 if _,err:=os.Stat(filepath.Join(filepath.Dir(db),"api"));err==nil{return errors.New("synthetic repo has API file")}else if !errors.Is(err,os.ErrNotExist){return err}
 if _,err:=os.Stat(filepath.Join(db,"CURRENT"));err!=nil{return fmt.Errorf("missing old Pebble CURRENT: %w",err)}
 return nil
}

func tables(db *pebble.DB) (map[string]table,error) {
 levels,err:=db.SSTables();if err!=nil{return nil,err}
 out:=make(map[string]table)
 for level,entries:=range levels {
  for _,entry:=range entries {
   num:=entry.FileNum.String()
   out[num]=table{Number:num,Level:level,Size:entry.Size,
    First:string(entry.Smallest.UserKey),Last:string(entry.Largest.UserKey)}
  }
 }
 return out,nil
}
func diff(a,b map[string]table) result {
 added,retired:=make([]table,0),make([]table,0)
 var newBytes,oldBytes uint64
 for id,t:=range b {if _,ok:=a[id];!ok {added=append(added,t);newBytes+=t.Size}}
 for id,t:=range a {if _,ok:=b[id];!ok {retired=append(retired,t);oldBytes+=t.Size}}
 sort.Slice(added,func(i,j int)bool{return added[i].Number<added[j].Number})
 sort.Slice(retired,func(i,j int)bool{return retired[i].Number<retired[j].Number})
 return result{"created":added,"retired":retired,"created_bytes":newBytes,
  "retired_bytes":oldBytes,"created_count":len(added),"retired_count":len(retired)}
}
func scan(db *pebble.DB) (int,string,error) {
 it,err:=db.NewIter(&pebble.IterOptions{LowerBound:[]byte("demo/"),UpperBound:[]byte("demo0")})
 if err!=nil{return 0,"",err}
 var h hash.Hash=sha256.New()
 count:=0
 for it.First();it.Valid();it.Next() {
  count++
  h.Write(it.Key());h.Write([]byte{0})
  h.Write(it.Value());h.Write([]byte{0})
 }
 if err=it.Error();err!=nil{_ = it.Close();return 0,"",err}
 if err=it.Close();err!=nil{return 0,"",err}
 return count,hex.EncodeToString(h.Sum(nil)),nil
}
func groupRange(g int) ([]byte,[]byte){
 return []byte(fmt.Sprintf("demo/%02d/",g)),[]byte(fmt.Sprintf("demo/%02d/",g+1))
}
func main(){
 action:=flag.String("action","inspect","seed, prepare, inspect, step, finish")
 root:=flag.String("lab-root","","absolute disposable lab root")
 dir:=flag.String("db","","absolute direct child Pebble database")
 group:=flag.Int("group",0,"bounded group index for step")
 groups:=flag.Int("groups",4,"seed groups, 2-6")
 keys:=flag.Int("keys-per-group",2048,"seed keys per group, <=4096")
 bytesPerValue:=flag.Int("value-bytes",1536,"seed bytes per value, <=2048")
 plannedLimit:=flag.Uint64("max-overlap-bytes",16777216,"refuse manual step if preflight SST overlap bytes exceed limit")
 flag.Parse()
 if flag.NArg()>0 || *root=="" || *dir=="" {fmt.Fprintln(os.Stderr,"unexpected args or missing paths");os.Exit(2)}
 if err:=guard(*root,*dir);err!=nil{fmt.Fprintln(os.Stderr,"path refusal:",err);os.Exit(2)}
 if *groups<2||*groups>6||*keys<=0||*keys>4096||*bytesPerValue<128||*bytesPerValue>2048 {
  fmt.Fprintln(os.Stderr,"fixture size guard refused");os.Exit(2)
 }
 if *group<0 || (*action!="step" && *group>=*groups) || (*action=="step" && *group>=*groups+8) {fmt.Fprintln(os.Stderr,"invalid phase ordinal");os.Exit(2)}
 if *action!="seed"&&*action!="prepare"&&*action!="inspect"&&*action!="step"&&*action!="finish" {
  fmt.Fprintln(os.Stderr,"unknown action");os.Exit(2)
 }
 if *plannedLimit<1000000||*plannedLimit>128*1024*1024{fmt.Fprintln(os.Stderr,"bounded budget required");os.Exit(2)}
 var mu sync.Mutex
 events:=make([]result,0)
 listener:=&pebble.EventListener{
  CompactionBegin:func(info pebble.CompactionInfo){
   mu.Lock();defer mu.Unlock()
   events=append(events,result{"type":"begin","job":info.JobID,"reason":info.Reason})
  },
  CompactionEnd:func(info pebble.CompactionInfo){
   mu.Lock();defer mu.Unlock()
   in:=make([]result,0);out:=make([]result,0)
   for _,l:=range info.Input {for _,t:=range l.Tables {
    in=append(in,result{"level":l.Level,"sst":t.FileNum.String(),"bytes":t.Size})
   }}
   for _,t:=range info.Output.Tables {out=append(out,result{"level":info.Output.Level,"sst":t.FileNum.String(),"bytes":t.Size})}
   errorText:="";if info.Err!=nil{errorText=info.Err.Error()}
   events=append(events,result{"type":"end","job":info.JobID,"reason":info.Reason,"input":in,"output":out,"error":errorText,"milliseconds":info.Duration.Milliseconds()})
  },
 }
 options:=&pebble.Options{ErrorIfNotExists:true,FormatMajorVersion:pebble.FormatMostCompatible,
  DisableAutomaticCompactions:true,MaxConcurrentCompactions:func()int{return 1},EventListener:listener}
 opened:=time.Now()
 db,err:=pebble.Open(*dir,options)
 if err!=nil{fmt.Fprintln(os.Stderr,"open:",err);os.Exit(1)}
 beforeFormat:=db.FormatMajorVersion()
 beforeMarked:=db.Metrics().Compact.MarkedFiles
 beforeTables,err:=tables(db)
 if err!=nil{_ = db.Close();fmt.Fprintln(os.Stderr,"tables:",err);os.Exit(1)}
 // The mutation-only step is traced independently. Full integrity scans
 // run in a fresh process immediately after the clean close. Including them
 // here would overcount SST reads during a single rewrite.
 beforeCount,beforeHash:=0,"deferred-to-closed-reopen"
 if *action!="step" {
  var err error
  beforeCount,beforeHash,err=scan(db)
  if err!=nil{_ = db.Close();fmt.Fprintln(os.Stderr,"scan:",err);os.Exit(1)}
 }
 output:=result{"action":*action,"group":*group,"format_before":beforeFormat.String(),
  "marked_before":beforeMarked,"sst_count_before":len(beforeTables),"keys_before":beforeCount,
  "keys_sha256_before":beforeHash,"disabled_auto_compactions":true,"max_concurrency":1}
 doErr:=func()error{
  switch *action{
  case "seed":
   if beforeFormat!=pebble.FormatMostCompatible{return errors.New("seed requires format 1")}
   if beforeCount!=0{return errors.New("seed requires unseeded demonstration keys")}
   var value=[]byte{}
   for g:=0;g<*groups;g++ {
    rng:=rand.New(rand.NewSource(int64(123456+g)))
    start,end:=groupRange(g)
    for n:=0;n<*keys;n++ {
     value=make([]byte,*bytesPerValue)
     if _,err:=rng.Read(value);err!=nil{return err}
     key:=[]byte(fmt.Sprintf("demo/%02d/%08d",g,n))
     if err:=db.Set(key,value,pebble.NoSync);err!=nil{return err}
    }
    if err:=db.Flush();err!=nil{return err}
    if err:=db.Compact(start,end,false);err!=nil{return err}
   }
   output["groups"]=*groups;output["keys_per_group"]=*keys;output["value_bytes"]=*bytesPerValue
  case "prepare":
   if beforeFormat>13{return errors.New("already newer than format 13")}
   if err:=db.RatchetFormatMajorVersion(13);err!=nil{return err}
   if db.Metrics().Compact.MarkedFiles==0{return errors.New("demonstration lacks marked legacy lower-level SSTs")}
  case "step":
   if beforeFormat!=13{return errors.New("single-marked-rewrite requires format 13")}
   if beforeMarked==0{return errors.New("no marked SSTs to rewrite")}
   plan,err:=db.DemoRewriteOneMarkedFile(*plannedLimit)
   output["preflight_overlap_bytes"]=plan.InputBytes
   output["preflight_overlap_ssts"]=plan.InputFiles
   output["picked_input_level"]=plan.InputLevel
   if err!=nil{return err}
   if db.Metrics().Compact.MarkedFiles>=beforeMarked {
    return errors.New("single marked rewrite did not reduce marked-file count")
   }
  case "finish":
   if beforeFormat!=13{return errors.New("finish requires format 13")}
   if beforeMarked!=0{return fmt.Errorf("refuse ratchet14 with %d marked files",beforeMarked)}
   if err:=db.RatchetFormatMajorVersion(14);err!=nil{return err}
   if db.FormatMajorVersion()!=14{return errors.New("final ratchet did not reach format 14")}
  case "inspect":
  }
  return nil
 }()
 afterFormat:=db.FormatMajorVersion()
 afterMarked:=db.Metrics().Compact.MarkedFiles
 afterTables,tableErr:=tables(db)
 afterCount,afterHash:=0,"deferred-to-closed-reopen"
 var scanErr error
 if *action!="step" {afterCount,afterHash,scanErr=scan(db)}
 closeErr:=db.Close()
 if doErr==nil{doErr=tableErr}
 if doErr==nil{doErr=scanErr}
 if doErr==nil{doErr=closeErr}
 mu.Lock();eventsCopy:=append([]result(nil),events...);mu.Unlock()
 output["format_after"]=afterFormat.String();output["marked_after"]=afterMarked
 output["sst_count_after"]=len(afterTables);output["keys_after"]=afterCount;output["keys_sha256_after"]=afterHash
 output["sst_diff"]=diff(beforeTables,afterTables);output["compactions"]=eventsCopy
 output["elapsed_seconds"]=time.Since(opened).Seconds()
 if *action!="seed" && (beforeCount!=afterCount||beforeHash!=afterHash){doErr=errors.New("demonstration key/value digest mismatch")}
 if doErr!=nil{output["error"]=doErr.Error()}
 enc:=json.NewEncoder(os.Stdout)
 if err:=enc.Encode(output);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 if doErr!=nil{os.Exit(1)}
}
