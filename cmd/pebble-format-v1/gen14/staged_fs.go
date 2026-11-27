// Pebble metadata is staged locally until a closed batch has passed verification.
// SST payload reads and new immutable SST writes go through the scoped clone mount.
package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

const stageDir = "/run/rhea-gen14-two-sst-metadata"

var sstFile = regexp.MustCompile(`^[0-9]{6,20}\.sst$`)
var metadataFile = regexp.MustCompile(`^(CURRENT|LOCK|[0-9]{6,20}\.log|(MANIFEST|OPTIONS)-[0-9]{6,20}|marker\.manifest\.[0-9]{6,20}\.MANIFEST-[0-9]{6,20}|marker\.format-version\.[0-9]{6,20}\.[0-9]{3}|temporary\.[0-9]{6,20}\.dbtmp|[0-9]{6,20}\.dbtmp)$`)

type stagedFS struct {
	vfs.FS
	db, stage string
	mu        sync.RWMutex
	retired   map[string]bool
}

func stageFS(raw vfs.FS, dir, stage string) *stagedFS {
	return &stagedFS{FS: raw, db: dir, stage: stage, retired: make(map[string]bool)}
}

func (fs *stagedFS) path(name string) (string, error) {
	if filepath.Clean(name) != name || filepath.Dir(name) != fs.db {
		return "", errors.New("name outside clone database")
	}
	base := filepath.Base(name)
	if sstFile.MatchString(base) {
		fs.mu.RLock()
		gone := fs.retired[base]
		fs.mu.RUnlock()
		if gone {
			return "", os.ErrNotExist
		}
		return name, nil
	}
	if !metadataFile.MatchString(base) {
		return "", errors.New("unknown Pebble metadata name: " + base)
	}
	return filepath.Join(fs.stage, base), nil
}

func (fs *stagedFS) Create(name string) (vfs.File, error) {
	p, err := fs.path(name)
	if err != nil {
		return nil, err
	}
	if sstFile.MatchString(filepath.Base(name)) {
		// A retired physical name can never be allocated again.
		if _, err := fs.FS.Stat(name); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("immutable SST name already present or unavailable")
		}
	}
	return fs.FS.Create(p)
}
func (fs *stagedFS) Open(name string, opts ...vfs.OpenOption) (vfs.File, error) {
	p, err := fs.path(name)
	if err != nil {
		return nil, err
	}
	return fs.FS.Open(p, opts...)
}
func (fs *stagedFS) OpenReadWrite(name string, opts ...vfs.OpenOption) (vfs.File, error) {
	p, err := fs.path(name)
	if err != nil {
		return nil, err
	}
	if p == name {
		return nil, errors.New("immutable SST may only be created")
	}
	return fs.FS.OpenReadWrite(p, opts...)
}
func (fs *stagedFS) Stat(name string) (os.FileInfo, error) {
	if name == fs.db {
		return fs.FS.Stat(fs.stage)
	}
	p, err := fs.path(name)
	if err != nil {
		return nil, err
	}
	return fs.FS.Stat(p)
}
func (fs *stagedFS) List(dir string) ([]string, error) {
	if dir != fs.db {
		return nil, errors.New("unexpected list directory")
	}
	data, err := fs.FS.List(dir)
	if err != nil {
		return nil, err
	}
	local, err := fs.FS.List(fs.stage)
	if err != nil {
		return nil, err
	}
	for _, name := range local {
		if !metadataFile.MatchString(name) {
			return nil, errors.New("unexpected staged metadata: " + name)
		}
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	for _, name := range data {
		if sstFile.MatchString(name) {
			if !fs.retired[name] {
				local = append(local, name)
			}
		} else if !metadataFile.MatchString(name) {
			return nil, errors.New("unknown physical clone file: " + name)
		}
	}
	return local, nil
}
func (fs *stagedFS) Remove(name string) error {
	p, err := fs.path(name)
	if err != nil {
		return err
	}
	if name != p {
		return fs.FS.Remove(p)
	}
	// Keep all predecessor SST versions readable even after compaction.
	if _, err := fs.FS.Stat(p); err != nil {
		return err
	}
	fs.mu.Lock()
	fs.retired[filepath.Base(p)] = true
	fs.mu.Unlock()
	return nil
}
func (fs *stagedFS) RemoveAll(string) error    { return errors.New("recursive removal forbidden") }
func (fs *stagedFS) Link(string, string) error { return errors.New("hard links forbidden") }
func (fs *stagedFS) metadataPair(a, b string) (string, string, error) {
	x, err := fs.path(a)
	if err != nil {
		return "", "", err
	}
	y, err := fs.path(b)
	if err != nil {
		return "", "", err
	}
	if x == a || y == b {
		return "", "", errors.New("SST move forbidden")
	}
	return x, y, nil
}
func (fs *stagedFS) Rename(a, b string) error {
	x, y, err := fs.metadataPair(a, b)
	if err != nil {
		return err
	}
	return fs.FS.Rename(x, y)
}
func (fs *stagedFS) ReuseForWrite(a, b string) (vfs.File, error) {
	x, y, err := fs.metadataPair(a, b)
	if err != nil {
		return nil, err
	}
	return fs.FS.ReuseForWrite(x, y)
}
func (fs *stagedFS) Lock(name string) (io.Closer, error) {
	if name != filepath.Join(fs.db, "LOCK") {
		return nil, errors.New("unexpected lock path")
	}
	return fs.FS.Lock(filepath.Join(fs.stage, "LOCK"))
}
func (fs *stagedFS) MkdirAll(dir string, mode os.FileMode) error {
	if dir != fs.db {
		return errors.New("unexpected database subdirectory")
	}
	return nil
}

type stagedDir struct {
	vfs.File
	remote vfs.File
}

func (d *stagedDir) Sync() error  { return errors.Join(d.File.Sync(), d.remote.Sync()) }
func (d *stagedDir) Close() error { return errors.Join(d.File.Close(), d.remote.Close()) }
func (fs *stagedFS) OpenDir(dir string) (vfs.File, error) {
	if dir != fs.db {
		return nil, errors.New("unexpected directory handle")
	}
	local, err := fs.FS.OpenDir(fs.stage)
	if err != nil {
		return nil, err
	}
	remote, err := fs.FS.OpenDir(fs.db)
	if err != nil {
		local.Close()
		return nil, err
	}
	return &stagedDir{local, remote}, nil
}

func inspectClosed(fs vfs.FS, dir string) (report, error) {
	result := report{Action: "inspect", Compactions: []compactionEvent{}}
	guard := newBudgetFS(fs, dir, false, func(uint64) error { return nil })
	db, err := pebble.Open(dir, options(guard, true, nil))
	if err != nil {
		return result, err
	}
	before, e1 := readState(db)
	after, e2 := readState(db)
	e3 := db.Close()
	result.states(before, after)
	result.Diff, err = difference(before.Tables, after.Tables)
	result.IO = guard.report()
	return result, errors.Join(e1, e2, e3, err)
}

func stagedWorkerFS() (*stagedFS, error) {
	p, err := filepath.EvalSymlinks(stageDir)
	if err != nil || p != stageDir {
		return nil, errors.New("metadata stage absent or indirect")
	}
	info, err := os.Lstat(stageDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("metadata stage identity differs")
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	found := false
	for _, line := range strings.Split(string(mounts), "\n") {
		left, right, ok := strings.Cut(line, " - ")
		f := strings.Fields(left)
		r := strings.Fields(right)
		if !ok || len(f) < 6 || len(r) < 2 {
			continue
		}
		if strings.HasPrefix(f[4], stageDir+"/") {
			return nil, errors.New("unexpected metadata submount")
		}
		if f[4] == stageDir {
			if found || !(r[0] == "ext4" || r[0] == "xfs") || !strings.Contains(","+f[5]+",", ",rw,") {
				return nil, errors.New("metadata stage must be a dedicated writable local bind")
			}
			found = true
		}
	}
	if !found {
		return nil, errors.New("dedicated metadata mount missing")
	}
	return stageFS(vfs.Default, writerDB, stageDir), nil
}
