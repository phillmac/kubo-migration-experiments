// Isolated copy of realstep/budget_test.go at e9abee5; historical source preserved.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble/vfs"
)

func testBudgetFS(t *testing.T, allowSST bool) *budgetFS {
	t.Helper()
	mem := vfs.NewMem()
	if err := mem.MkdirAll("/lab/pebbleds", 0700); err != nil {
		t.Fatal(err)
	}
	b := newBudgetFS(mem, "/lab/pebbleds", allowSST, func(uint64) error { return nil })
	b.used.MaxSSTWriteBytes = 8
	b.used.MaxMetadataWriteBytes = 12
	return b
}

func TestSSTCreateOnDefaultFSHandlesWrappedNotExist(t *testing.T) {
	// vfs.Default adds errors.WithStack to Stat errors. Exercise the same
	// filesystem adapter as the real command so an absent
	// output is accepted without allowing replacement or bypassing the budget.
	dir := t.TempDir()
	b := newBudgetFS(vfs.Default, dir, true, func(uint64) error { return nil })
	b.used.MaxSSTWriteBytes = 8
	name := filepath.Join(dir, "000001.sst")
	f, err := b.Create(name)
	if err != nil {
		t.Fatalf("new SST rejected by default filesystem: %v", err)
	}
	if n, err := f.Write([]byte("original")); err != nil || n != 8 {
		_ = f.Close()
		t.Fatalf("new SST write: %d %v", n, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if replacement, err := b.Create(name); err == nil {
		_ = replacement.Close()
		t.Fatal("existing immutable SST replacement allowed")
	}
	if contents, err := os.ReadFile(name); err != nil || string(contents) != "original" {
		t.Fatalf("immutable SST contents changed: %q %v", contents, err)
	}
	second, err := b.Create(filepath.Join(dir, "000002.sst"))
	if err != nil {
		t.Fatalf("second new SST rejected by default filesystem: %v", err)
	}
	defer second.Close()
	if n, err := second.Write([]byte("x")); err == nil || n != 0 {
		t.Fatalf("new file bypassed exhausted SST budget: %d %v", n, err)
	}
	if info, err := second.Stat(); err != nil || info.Size() != 0 {
		t.Fatalf("blocked write reached default filesystem: %v %v", info, err)
	}
	if got := b.report(); got.SSTWriteBytes != 8 || got.MetadataWriteBytes != 0 {
		t.Fatalf("incorrect default-filesystem accounting: %+v", got)
	}
}

type createStatFailureFS struct {
	vfs.FS
	statErr     error
	createCalls int
}

func (f *createStatFailureFS) Stat(string) (os.FileInfo, error) { return nil, f.statErr }

func (f *createStatFailureFS) Create(name string) (vfs.File, error) {
	f.createCalls++
	return f.FS.Create(name)
}

func TestSSTCreatePreservesWrappedStatFailures(t *testing.T) {
	b := testBudgetFS(t, true)
	name := "/lab/pebbleds/000001.sst"
	blocked := fmt.Errorf("wrapped stat failure: %w", &os.PathError{Op: "stat", Path: name, Err: os.ErrPermission})
	fs := &createStatFailureFS{FS: b.FS, statErr: blocked}
	b.FS = fs
	if f, err := b.Create(name); f != nil || !errors.Is(err, os.ErrPermission) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("non-ENOENT stat failure was not preserved: %v", err)
	}
	if fs.createCalls != 0 {
		t.Fatal("stat failure reached underlying Create")
	}
	if got := b.report(); got.SSTWriteBytes != 0 || got.MetadataWriteBytes != 0 {
		t.Fatalf("rejected creation consumed a write allowance: %+v", got)
	}
}

func TestWriteBudgetsPreventOvershootAcrossFiles(t *testing.T) {
	b := testBudgetFS(t, true)
	first, err := b.Create("/lab/pebbleds/000001.sst")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := first.Write([]byte("123456")); err != nil || n != 6 {
		t.Fatalf("first write: %d %v", n, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := b.Create("/lab/pebbleds/000002.sst")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if n, err := second.Write([]byte("789")); err == nil || n != 0 {
		t.Fatalf("overshoot allowed: %d %v", n, err)
	}
	if fi, err := second.Stat(); err != nil || fi.Size() != 0 {
		t.Fatalf("rejected write reached filesystem: %v %v", fi, err)
	}
	if n, err := second.Write([]byte("78")); err != nil || n != 2 {
		t.Fatalf("remaining allowance: %d %v", n, err)
	}
	meta, err := b.Create("/lab/pebbleds/MANIFEST-000003")
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	if n, err := meta.Write([]byte("123456789012")); err != nil || n != 12 {
		t.Fatalf("independent metadata limit: %d %v", n, err)
	}
	if n, err := meta.Write([]byte("x")); err == nil || n != 0 {
		t.Fatalf("metadata overshoot allowed: %d %v", n, err)
	}
	got := b.report()
	if got.SSTWriteBytes != 8 || got.MetadataWriteBytes != 12 {
		t.Fatalf("wrong write counters: %+v", got)
	}
}

func TestMetadataStageRefusesSSTCreation(t *testing.T) {
	b := testBudgetFS(t, false)
	if _, err := b.Create("/lab/pebbleds/000001.sst"); err == nil {
		t.Fatal("preliminary metadata stage created an SST")
	}
	if _, err := b.FS.Stat("/lab/pebbleds/000001.sst"); err == nil {
		t.Fatal("rejected creation reached filesystem")
	}
}

func TestBudgetDoesNotRefillWhenOutputDeleted(t *testing.T) {
	b := testBudgetFS(t, true)
	f, err := b.Create("/lab/pebbleds/000001.sst")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = b.Remove("/lab/pebbleds/000001.sst"); err != nil {
		t.Fatal(err)
	}
	f, err = b.Create("/lab/pebbleds/000002.sst")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if n, err := f.Write([]byte("x")); err == nil || n != 0 {
		t.Fatal("deleted output restored spent budget")
	}
}

func TestGuardFailureBlocksReadsAndWrites(t *testing.T) {
	b := testBudgetFS(t, true)
	f, err := b.Create("/lab/pebbleds/000001.sst")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	blocked := errors.New("cache reserve or monitor sentinel")
	b.freeCheck = func(uint64) error { return blocked }
	if n, err := f.Write([]byte("x")); !errors.Is(err, blocked) || n != 0 {
		t.Fatal("guard did not block write")
	}
	if n, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, blocked) || n != 0 {
		t.Fatal("guard did not block read")
	}
}

func TestExtentAndImmutableFileGuards(t *testing.T) {
	b := testBudgetFS(t, true)
	f, err := b.Create("/lab/pebbleds/000001.sst")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.(io.WriterAt).WriteAt([]byte("x"), 8); err == nil {
		t.Fatal("sparse write beyond extent cap allowed")
	}
	if err := f.Preallocate(0, 9); err == nil {
		t.Fatal("oversize preallocation allowed")
	}
	if _, err := b.Create("/lab/pebbleds/000001.sst"); err == nil {
		t.Fatal("existing immutable SST was truncated")
	}
	if _, err := b.Create("/lab/pebbleds/../production/MANIFEST-1"); err == nil {
		t.Fatal("path escape allowed")
	}
}
