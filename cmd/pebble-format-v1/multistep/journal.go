package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// Receipts are append-only observations, NOT a remote checkpoint. pending.json
// is never removed by this engine, even after a successful close. No recovery
// entrypoint invokes the writer. A crash between a commit and receipt creation
// leaves the intent and demands independent exact recovery or baseline restore.
type evidenceSink interface {
	put(string, interface{}) error
}

type diskJournal struct {
	dir   string
	owner uint32
}

// A future live adapter must use this constructor. Tests explicitly choose
// their own UID through the private constructor; there is no CLI bypass.
func newRootJournal(dir string) (*diskJournal, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root required for durable live evidence")
	}
	for path := dir; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("live journal ancestry must be root-owned directories without group/world write")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	return newDiskJournal(dir, 0)
}

func newDiskJournal(dir string, owner uint32) (*diskJournal, error) {
	j := &diskJournal{dir: dir, owner: owner}
	if err := j.check(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *diskJournal) check() error {
	if !filepath.IsAbs(j.dir) || filepath.Clean(j.dir) != j.dir {
		return errors.New("journal must be an absolute clean protected directory")
	}
	resolved, err := filepath.EvalSymlinks(j.dir)
	if err != nil || resolved != j.dir {
		return errors.New("journal path contains symlink")
	}
	info, err := os.Lstat(j.dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != j.owner || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("journal owner/mode must be trusted UID and 0700")
	}
	return nil
}

var evidenceName = regexp.MustCompile(`^(pending|closed|unit-[0-9]{3}-(intent|receipt|failed))\.json$`)

func (j *diskJournal) put(name string, value interface{}) error {
	if !evidenceName.MatchString(name) {
		return errors.New("invalid evidence basename")
	}
	if err := j.check(); err != nil {
		return err
	}
	if name == "pending.json" {
		entries, err := os.ReadDir(j.dir)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return errors.New("existing evidence directory forbids a new writer invocation")
		}
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// O_EXCL also refuses a symlink and an unfinished prior invocation. A short
	// write/fsync failure leaves evidence in place and never authorizes replay.
	f, err := os.OpenFile(filepath.Join(j.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(body, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	d, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	dirErr := d.Sync()
	dirCloseErr := d.Close()
	return errors.Join(writeErr, syncErr, closeErr, dirErr, dirCloseErr)
}
