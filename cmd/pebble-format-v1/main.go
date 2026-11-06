// Command pebble-format-v1 is a synthetic-only standalone Pebble format migration probe.
// It never starts Kubo, does not read Kubo config, and refuses non-lab paths.
package main

import (
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

type evidence struct {
	Tool string `json:"tool"`
	Before string `json:"format_before"`
	After string `json:"format_after"`
	Started string `json:"started_utc"`
	Finished string `json:"finished_utc"`
	Database string `json:"database_kind"`
}

func validateLabPath(labRoot, dbPath string) (string, error) {
	if !filepath.IsAbs(labRoot) || !filepath.IsAbs(dbPath) {
		return "", errors.New("paths must be absolute")
	}
	labRoot = filepath.Clean(labRoot)
	dbPath = filepath.Clean(dbPath)
	if !strings.HasPrefix(filepath.Base(labRoot), "kubo-lab-") {
		return "", errors.New("requires a kubo-lab-* disposable root")
	}
	if filepath.Base(dbPath) != "pebbleds" || filepath.Dir(filepath.Dir(dbPath)) != labRoot {
		return "", errors.New("database must be a direct child of a direct lab repo")
	}
	repo := filepath.Dir(dbPath)
	for _, path := range []string{labRoot, repo, dbPath} {
		fi, err := os.Lstat(path)
		if err != nil { return "", err }
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("directory is not a real local directory: %s", path)
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil || real != path { return "", errors.New("symlink traversal forbidden") }
	}
	if _, err := os.Stat(filepath.Join(repo, "api")); err == nil {
		return "", errors.New("lab repo contains an API file")
	} else if !errors.Is(err, os.ErrNotExist) { return "", err }
	for _, name := range []string{"CURRENT", "OPTIONS-"} {
		if name == "CURRENT" {
			if _, err := os.Stat(filepath.Join(dbPath,name)); err != nil { return "", fmt.Errorf("missing existing Pebble CURRENT: %w",err) }
		}
	}
	for _, prefix := range []string{"/home/ubuntu/.ipfs-wasabi","/data/ipfs-wasabi-cache"} {
		if strings.HasPrefix(dbPath,prefix) { return "", errors.New("production paths are forbidden") }
	}
	return dbPath,nil
}

func main() {
	lab := flag.String("lab-root", "", "Absolute disposable kubo-lab-* root")
	dbdir := flag.String("db", "", "Absolute direct child <lab>/<clone>/pebbleds")
	target := flag.Int("target-format", 0, "Explicit format; synthetic test supports only 13")
	flag.Parse()
	if flag.NArg()!=0 || *target!=13 { fmt.Fprintln(os.Stderr,"requires --target-format=13 and no extra arguments");os.Exit(2) }
	path,err := validateLabPath(*lab,*dbdir)
	if err!=nil { fmt.Fprintln(os.Stderr,"path guard:",err);os.Exit(2) }
	started:=time.Now().UTC()
	// Do not select FormatNewest, which could silently trigger a full
	// SST format rewrite. Explicitly ratchet after recording initial format.
	db,err := pebble.Open(path,&pebble.Options{
		ErrorIfNotExists:true,
		FormatMajorVersion:pebble.FormatMostCompatible,
		MaxConcurrentCompactions:func()int{return 1},
	})
	if err!=nil { fmt.Fprintln(os.Stderr,"open:",err);os.Exit(1) }
	before:=db.FormatMajorVersion()
	if before>pebble.FormatMajorVersion(*target) {
		_ = db.Close()
		fmt.Fprintln(os.Stderr,"refusing to downgrade format",before)
		os.Exit(2)
	}
	if before<pebble.FormatMajorVersion(*target) {
		if err=db.RatchetFormatMajorVersion(pebble.FormatMajorVersion(*target));err!=nil {
			_ = db.Close()
			fmt.Fprintln(os.Stderr,"ratchet:",err)
			os.Exit(1)
		}
	}
	after:=db.FormatMajorVersion()
	if err=db.Close();err!=nil { fmt.Fprintln(os.Stderr,"close:",err);os.Exit(1) }
	if after!=pebble.FormatMajorVersion(*target) {fmt.Fprintln(os.Stderr,"format mismatch");os.Exit(1)}
	value:=evidence{Tool:"standalone-Pebble-v1-no-Kubo",Before:before.String(),After:after.String(),
		Started:started.Format(time.RFC3339),Finished:time.Now().UTC().Format(time.RFC3339),Database:"synthetic-clone"}
	_ = json.NewEncoder(os.Stdout).Encode(value)
}
