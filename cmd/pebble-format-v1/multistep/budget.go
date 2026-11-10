// Isolated copy of realstep/budget.go at e9abee5; historical source preserved.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cockroachdb/pebble/vfs"
)

const (
	maxInputBytes         uint64 = 256 * 1024 * 1024
	maxSSTWriteBytes      uint64 = 512 * 1024 * 1024
	maxMetadataWriteBytes uint64 = 64 * 1024 * 1024
	minCacheFreeBytes     uint64 = 2 * 1024 * 1024 * 1024 * 1024
)

type ioReport struct {
	SSTWriteBytes         uint64 `json:"sst_write_bytes"`
	MetadataWriteBytes    uint64 `json:"metadata_write_bytes"`
	MaxSSTWriteBytes      uint64 `json:"max_sst_write_bytes"`
	MaxMetadataWriteBytes uint64 `json:"max_metadata_write_bytes"`
	BlockedBudgetError    string `json:"blocked_budget_error,omitempty"`
}

// budgetFS intercepts actual Pebble file writes. Counts are cumulative bytes
// submitted successfully, including rewrites of the same metadata bytes. A
// failed or deleted output never replenishes the allowance. It does not claim
// to measure remote traffic or replace the controller's VFS cache/queue limits.
type budgetFS struct {
	vfs.FS
	root      string
	allowSST  bool
	freeCheck func(uint64) error
	mu        sync.Mutex
	used      ioReport
}

func newBudgetFS(fs vfs.FS, root string, allowSST bool, freeCheck func(uint64) error) *budgetFS {
	return &budgetFS{FS: fs, root: root, allowSST: allowSST, freeCheck: freeCheck,
		used: ioReport{MaxSSTWriteBytes: maxSSTWriteBytes, MaxMetadataWriteBytes: maxMetadataWriteBytes}}
}

func (b *budgetFS) report() ioReport { b.mu.Lock(); defer b.mu.Unlock(); return b.used }

func (b *budgetFS) scoped(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || filepath.Dir(name) != b.root {
		return errors.New("file operation outside fixed lab database")
	}
	return nil
}

func (b *budgetFS) writable(name string) error {
	if err := b.scoped(name); err != nil {
		return err
	}
	if strings.HasSuffix(name, ".sst") && !b.allowSST {
		return errors.New("metadata stage forbids SST creation or writes")
	}
	return b.freeCheck(0)
}

func (b *budgetFS) wrap(name string, f vfs.File, err error) (vfs.File, error) {
	if err != nil {
		return nil, err
	}
	return &budgetFile{File: f, owner: b, sst: strings.HasSuffix(name, ".sst")}, nil
}

func (b *budgetFS) Create(name string) (vfs.File, error) {
	if err := b.writable(name); err != nil {
		return nil, err
	}
	if strings.HasSuffix(name, ".sst") {
		if _, err := b.FS.Stat(name); err == nil {
			return nil, errors.New("refuse replacing an existing immutable SST")
		} else if !errors.Is(err, os.ErrNotExist) {
			// vfs.Default adds a stack wrapper to os.Stat errors. Only an
			// actual not-exist cause permits creation; retain every other error.
			return nil, err
		}
	}
	f, err := b.FS.Create(name)
	return b.wrap(name, f, err)
}

func (b *budgetFS) Open(name string, opts ...vfs.OpenOption) (vfs.File, error) {
	if err := b.scoped(name); err != nil {
		return nil, err
	}
	if err := b.freeCheck(0); err != nil {
		return nil, err
	}
	f, err := b.FS.Open(name, opts...)
	return b.wrap(name, f, err)
}

func (b *budgetFS) OpenReadWrite(name string, opts ...vfs.OpenOption) (vfs.File, error) {
	if err := b.writable(name); err != nil {
		return nil, err
	}
	if strings.HasSuffix(name, ".sst") {
		return nil, errors.New("read-write open of an immutable SST is forbidden")
	}
	fs, ok := b.FS.(interface {
		OpenReadWrite(string, ...vfs.OpenOption) (vfs.File, error)
	})
	if !ok {
		return nil, errors.New("filesystem lacks guarded read-write open")
	}
	f, err := fs.OpenReadWrite(name, opts...)
	return b.wrap(name, f, err)
}

func (b *budgetFS) ReuseForWrite(oldname, newname string) (vfs.File, error) {
	if err := b.writable(oldname); err != nil {
		return nil, err
	}
	if err := b.writable(newname); err != nil {
		return nil, err
	}
	if strings.HasSuffix(oldname, ".sst") || strings.HasSuffix(newname, ".sst") {
		return nil, errors.New("immutable SST reuse forbidden")
	}
	f, err := b.FS.ReuseForWrite(oldname, newname)
	return b.wrap(newname, f, err)
}

func (b *budgetFS) Rename(oldname, newname string) error {
	if err := b.scoped(oldname); err != nil {
		return err
	}
	if err := b.scoped(newname); err != nil {
		return err
	}
	if strings.HasSuffix(oldname, ".sst") || strings.HasSuffix(newname, ".sst") {
		return errors.New("SST rename is outside the single-rewrite budget model")
	}
	return b.FS.Rename(oldname, newname)
}

func (b *budgetFS) Link(oldname, newname string) error {
	return errors.New("filesystem hard links are outside the single-rewrite budget model")
}

func (b *budgetFS) Remove(name string) error {
	if err := b.scoped(name); err != nil {
		return err
	}
	return b.FS.Remove(name)
}

func (b *budgetFS) RemoveAll(name string) error {
	return errors.New("recursive removal is forbidden for full-clone operations")
}

type budgetFile struct {
	vfs.File
	owner *budgetFS
	sst   bool
}

func (f *budgetFile) write(data []byte, offset int64, at bool) (int, error) {
	b := f.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	used, limit := &b.used.MetadataWriteBytes, b.used.MaxMetadataWriteBytes
	if f.sst {
		used, limit = &b.used.SSTWriteBytes, b.used.MaxSSTWriteBytes
	}
	var err error
	if f.sst && !b.allowSST {
		err = errors.New("metadata stage forbids SST writes")
	} else if uint64(len(data)) > limit-*used {
		err = fmt.Errorf("write budget would exceed %d bytes", limit)
	} else if at && (offset < 0 || uint64(offset) > limit || uint64(len(data)) > limit-uint64(offset)) {
		err = errors.New("write offset exceeds output extent budget")
	} else {
		err = b.freeCheck(uint64(len(data)))
	}
	if err != nil {
		b.used.BlockedBudgetError = err.Error()
		return 0, err
	}
	var n int
	if at {
		writer, ok := f.File.(io.WriterAt)
		if !ok {
			return 0, errors.New("filesystem file lacks guarded WriteAt")
		}
		n, err = writer.WriteAt(data, offset)
	} else {
		n, err = f.File.Write(data)
	}
	if n > 0 {
		*used += uint64(n)
	}
	return n, err
}

func (f *budgetFile) Write(data []byte) (int, error) { return f.write(data, 0, false) }
func (f *budgetFile) WriteAt(data []byte, offset int64) (int, error) {
	return f.write(data, offset, true)
}

func (f *budgetFile) Read(data []byte) (int, error) {
	if err := f.owner.freeCheck(0); err != nil {
		return 0, err
	}
	return f.File.Read(data)
}
func (f *budgetFile) ReadAt(data []byte, offset int64) (int, error) {
	if err := f.owner.freeCheck(0); err != nil {
		return 0, err
	}
	return f.File.ReadAt(data, offset)
}

func (f *budgetFile) Prefetch(offset, length int64) error {
	if err := f.owner.freeCheck(0); err != nil {
		return err
	}
	if p, ok := f.File.(interface{ Prefetch(int64, int64) error }); ok {
		return p.Prefetch(offset, length)
	}
	return nil
}

// Preallocation is an optional filesystem optimization. Do not forward it:
// only the guarded writes may consume output disk space. Checking the requested
// extent also prevents a malformed writer from reserving an unbounded file.
func (f *budgetFile) Preallocate(offset, length int64) error {
	limit := f.owner.used.MaxMetadataWriteBytes
	if f.sst {
		limit = f.owner.used.MaxSSTWriteBytes
	}
	if offset < 0 || length < 0 || uint64(offset) > limit || uint64(length) > limit-uint64(offset) {
		return errors.New("preallocation exceeds output extent budget")
	}
	return f.owner.freeCheck(0)
}
