// Command checkpoint3 demonstrates real Pebble v1.1.3 format-1 -> format-3
// marker semantics on a disposable local scratch repo only. No Kubo daemon.
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
 "strings"
 "time"

 "github.com/cockroachdb/pebble"
)

const root = "/home/ubuntu/pebble-recovery-analysis/pebble-format3-checkpoint-20261102"

type Result struct {
 Action string `json:"action"`
 DbPath string `json:"db_path"`
 Format string `json:"format"`
 Keys int `json:"keys"`
 DigestSHA256 string `json:"digest_sha256"`
 MarkedFiles int `json:"marked_files"`
 SSTFiles int `json:"sst_files"`
 SSTBytes uint64 `json:"sst_bytes"`
 ElapsedSeconds float64 `json:"elapsed_seconds"`
}

func ensure(path,action string) error {
 if !filepath.IsAbs(path) || filepath.Clean(path)!=path {return errors.New("absolute normalized path required")}
 if !strings.HasPrefix(path,root+"/") || filepath.Base(path)!="pebbleds" {return errors.New("synthetic scratch root only")}
 parent:=filepath.Dir(path)
 if filepath.Dir(parent)!=root || filepath.Base(parent)=="rhea" {return errors.New("immediate synthetic scratch child only")}
 for _,p:=range []string{root,parent} {
  fi,err:=os.Lstat(p);if err!=nil{return err}
  if !fi.IsDir() || fi.Mode()&os.ModeSymlink!=0{return fmt.Errorf("symlink or non-directory: %s",p)}
 }
 if action=="seed"{
  _,err:=os.Lstat(path)
  if !errors.Is(err,os.ErrNotExist){return errors.New("seed DB path must not already exist")}
 } else {
  fi,err:=os.Lstat(path)
  if err!=nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink!=0{return errors.New("existing real DB dir required")}
 }
 return nil
}
func digest(db *pebble.DB) (int,string,error) {
 it,err:=db.NewIter(&pebble.IterOptions{LowerBound:[]byte("probe/"),UpperBound:[]byte("probe0")})
 if err!=nil{return 0,"",err}
 var h hash.Hash=sha256.New()
 n:=0
 for it.First();it.Valid();it.Next() {
  n++
  h.Write(it.Key());h.Write([]byte{0})
  h.Write(it.Value());h.Write([]byte{0})
 }
 if e:=it.Error();e!=nil{_ = it.Close();return 0,"",e}
 if e:=it.Close();e!=nil{return 0,"",e}
 return n,hex.EncodeToString(h.Sum(nil)),nil
}
func main(){
 action:=flag.String("action","","seed, ratchet3, or inspect")
 path:=flag.String("db","","synthetic local scratch pebbleds path")
 flag.Parse()
 if flag.NArg()!=0 || !(*action=="seed" || *action=="ratchet3" || *action=="inspect"){
  fmt.Fprintln(os.Stderr,"action=seed|ratchet3|inspect required");os.Exit(2)
 }
 if e:=ensure(*path,*action);e!=nil{fmt.Fprintln(os.Stderr,"scratch-only refusal:",e);os.Exit(2)}
 start:=time.Now()
 opts:=&pebble.Options{FormatMajorVersion:pebble.FormatMostCompatible,MaxConcurrentCompactions:func()int{return 1},
  DisableAutomaticCompactions:true,ReadOnly:*action=="inspect",ErrorIfNotExists:*action!="seed"}
 db,err:=pebble.Open(*path,opts)
 if err!=nil{fmt.Fprintln(os.Stderr,"open:",err);os.Exit(1)}
 var opErr error
 switch *action {
 case "seed":
  if db.FormatMajorVersion()!=pebble.FormatMostCompatible{opErr=errors.New("unexpected initial format");break}
  for group:=0;group<4 && opErr==nil;group++{
   rng:=rand.New(rand.NewSource(int64(20261102+group)))
   for i:=0;i<1024;i++{
    key:=[]byte(fmt.Sprintf("probe/%02d/%08d",group,i))
    value:=make([]byte,1024)
    _,opErr=rng.Read(value);if opErr!=nil{break}
    opErr=db.Set(key,value,pebble.NoSync);if opErr!=nil{break}
   }
   if opErr==nil{opErr=db.Flush()}
  }
 case "ratchet3":
  if db.FormatMajorVersion()!=pebble.FormatMostCompatible{opErr=errors.New("must start at format1");break}
  opErr=db.RatchetFormatMajorVersion(3)
 case "inspect":
 }
 r:=Result{Action:*action,DbPath:*path,Format:db.FormatMajorVersion().String(),
  MarkedFiles:db.Metrics().Compact.MarkedFiles}
 if opErr==nil{r.Keys,r.DigestSHA256,opErr=digest(db)}
 if opErr==nil {
  var levels [][]pebble.SSTableInfo
  levels,opErr=db.SSTables()
  if opErr==nil{for _,level:=range levels{for _,f:=range level{r.SSTFiles++;r.SSTBytes+=f.Size}}}
 }
 if e:=db.Close();opErr==nil{opErr=e}
 r.ElapsedSeconds=time.Since(start).Seconds()
 if opErr!=nil{fmt.Fprintln(os.Stderr,"operation:",opErr);os.Exit(1)}
 if r.Keys!=4096{fmt.Fprintln(os.Stderr,"expected exactly 4096 immutable test keys, got",r.Keys);os.Exit(1)}
 if *action=="ratchet3" && r.Format!="003"{fmt.Fprintln(os.Stderr,"did not reach format 003");os.Exit(1)}
 if e:=json.NewEncoder(os.Stdout).Encode(r);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
}
