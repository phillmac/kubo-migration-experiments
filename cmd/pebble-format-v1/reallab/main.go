// Command reallab only opens the independently verified, disposable Rhea Wasabi lab.
// It is intentionally incapable of opening production. No Kubo daemon is used.
// The ratchet3 action is a single, explicit format-001 -> format-003 experiment.
// No format 7/10/13/14 upgrades or table rewrites are exposed by this command.
package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "time"

 "github.com/cockroachdb/pebble"
)

const (
 labMount = "/mnt/rhea-pebble-lab-writable-20261102"
 labDB = labMount + "/pebbleds"
 labBucket = "rhea-pebble-lab-20261101-39037c6f01"
 sourcePointer = "MANIFEST-47475278\n"
 baselineFiles = 93697
 baselineBytes uint64 = 7786594080785
)

type report struct {
 Action string `json:"action"`
 BeforeFormat string `json:"before_format"`
 AfterFormat string `json:"after_format"`
 SSTFilesBefore int `json:"sst_files_before"`
 SSTFilesAfter int `json:"sst_files_after"`
 SSTBytesBefore uint64 `json:"sst_bytes_before"`
 SSTBytesAfter uint64 `json:"sst_bytes_after"`
 MarkedBefore int `json:"marked_before"`
 MarkedAfter int `json:"marked_after"`
 Seconds float64 `json:"seconds"`
}

func gate(action string) error {
 if action!="plan" && action!="ratchet3" && action!="inspect" {return errors.New("action must be plan, ratchet3 or inspect")}
 if b,e:=exec.Command("systemctl","show","rhea-ipfs-wasabi-kubo.service","-p","ActiveState","--value").Output();e!=nil || strings.TrimSpace(string(b))!="inactive" {return errors.New("production Kubo must remain stopped")}
 if b,e:=exec.Command("systemctl","show","rhea-broken-pin-walk-20261026.service","-p","ActiveState","--value").Output();e!=nil || strings.TrimSpace(string(b))!="inactive" {return errors.New("production walker must remain stopped")}
 for _,path:=range []string{labMount,labDB} {
  fi,err:=os.Lstat(path)
  if err!=nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink!=0{return errors.New("lab path not a real directory: "+path)}
  real,err:=filepath.EvalSymlinks(path)
  if err!=nil || real!=path{return errors.New("lab path symlink not allowed")}
 }
 b,err:=os.ReadFile("/proc/self/mountinfo");if err!=nil{return err}
 valid:=false
 for _,line:=range strings.Split(string(b),"\n") {
  pair:=strings.SplitN(line," - ",2);if len(pair)!=2{continue}
  lhs:=strings.Fields(pair[0]);rhs:=strings.Fields(pair[1])
  if len(lhs)<5 || len(rhs)<2 || lhs[4]!=labMount {continue}
  if rhs[0]=="fuse.rclone" && strings.Contains(rhs[1],"rhea_pebble_lab") &&
   strings.Contains(rhs[1],labBucket+"/rhea"){valid=true}
 }
 if !valid{return errors.New("refusing unverified lab FUSE mount or production object source")}
 if action=="ratchet3" || action=="plan" {
  content,err:=os.ReadFile(filepath.Join(labDB,"CURRENT"))
  if err!=nil{return err}
  if string(content)!=sourcePointer{return errors.New("original frozen lab CURRENT checkpoint has changed; refusing ratchet")}
 }
 return nil
}

func sst(db *pebble.DB) (int,uint64,error) {
 levels,err:=db.SSTables();if err!=nil{return 0,0,err}
 var count int
 var total uint64
 for _,level:=range levels {for _,x:=range level{count++;total+=x.Size}}
 return count,total,nil
}

func main(){
 if len(os.Args)!=2 {fmt.Fprintln(os.Stderr,"usage: reallab plan|ratchet3|inspect");os.Exit(2)}
 action:=os.Args[1]
 if err:=gate(action);err!=nil{fmt.Fprintln(os.Stderr,"fail-closed gate:",err);os.Exit(2)}
 t:=time.Now()
 opts:=&pebble.Options{
  ReadOnly:action!="ratchet3",ErrorIfNotExists:true,
  FormatMajorVersion:pebble.FormatMostCompatible,
  DisableAutomaticCompactions:true,
  MaxConcurrentCompactions:func()int{return 1},
 }
 db,err:=pebble.Open(labDB,opts)
 if err!=nil{fmt.Fprintln(os.Stderr,"opening lab failed:",err);os.Exit(1)}
 r:=report{Action:action,BeforeFormat:db.FormatMajorVersion().String(),MarkedBefore:db.Metrics().Compact.MarkedFiles}
 r.SSTFilesBefore,r.SSTBytesBefore,err=sst(db)
 if err==nil && action!="inspect" && (r.BeforeFormat!="001" || r.MarkedBefore!=0 ||
  r.SSTFilesBefore!=baselineFiles || r.SSTBytesBefore!=baselineBytes) {
  err=errors.New("unexpected lab manifest, file count, byte sum, marks or format; no ratchet attempted")
 }
 if err==nil && action=="ratchet3" {err=db.RatchetFormatMajorVersion(3)}
 r.AfterFormat=db.FormatMajorVersion().String()
 r.MarkedAfter=db.Metrics().Compact.MarkedFiles
 if err==nil {r.SSTFilesAfter,r.SSTBytesAfter,err=sst(db)}
 if err==nil && action=="ratchet3" {
  if r.AfterFormat!="003" || r.SSTFilesAfter!=baselineFiles || r.SSTBytesAfter!=baselineBytes || r.MarkedAfter!=0 {
   err=errors.New("unexpected SST changes during format3 ratchet")
  }
 }
 closeErr:=db.Close()
 if err==nil {err=closeErr}
 r.Seconds=time.Since(t).Seconds()
 if err!=nil{fmt.Fprintln(os.Stderr,"lab operation error:",err);os.Exit(1)}
 if e:=json.NewEncoder(os.Stdout).Encode(r);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
}
