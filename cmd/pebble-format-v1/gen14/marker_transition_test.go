package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// Model a VFS that can create a local dirty marker but cannot retire the old
// protected object. Ordinary database IO goes to a fresh real disk fixture.
type retainManifest struct {
	vfs.FS
	blocked int
}

func (f *retainManifest) Remove(name string) error {
	if strings.HasPrefix(filepath.Base(name), "marker.manifest.") {
		f.blocked++
		return os.ErrPermission
	}
	return f.FS.Remove(name)
}

func TestGeneration14RetainedManifest(t *testing.T) {
	dir, request, _ := seedDisk(t)
	markers := func() []string {
		files, err := filepath.Glob(filepath.Join(dir, "marker.manifest.*"))
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	before := markers()
	if len(before) != 1 {
		t.Fatalf("initial markers: %v", before)
	}
	fs := &retainManifest{FS: vfs.Default}
	report, err := runBatch(fs, dir, request, journal(), func(uint64) error { return nil })
	if err != nil || !report.Closed || report.PhysicalCompactions != 2 || fs.blocked == 0 {
		t.Fatalf("expected two closed rewrites and a blocked retirement: %+v, %v", report, err)
	}
	after := markers()
	if len(after) != 2 || after[0] != before[0] {
		t.Fatalf("unexpected retained marker inventory: %v", after)
	}
	ro, err := pebble.Open(dir, options(fs, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	s, err := readState(ro)
	if err != nil || !equalState(s, report.After) || ro.Close() != nil {
		t.Fatalf("read-only reopen with both markers: %+v, %v", s, err)
	}
	rw, err := pebble.Open(dir, options(fs, false, nil))
	if err == nil {
		rw.Close()
		t.Fatal("writable reopen unexpectedly passed with the old protected marker")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unexpected cause of refused writable reopen: %v", err)
	}
	// The actual publisher must first prove the new version, and the retirement
	// authority may tombstone only the exact old key. This OS fixture models that ordering.
	if err := os.Remove(before[0]); err != nil {
		t.Fatal(err)
	}
	left := markers()
	if len(left) != 1 || left[0] != after[1] {
		t.Fatalf("retirement removed an unexpected marker: %v", left)
	}
	rw, err = pebble.Open(dir, options(vfs.Default, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	s, err = readState(rw)
	if err != nil || !equalState(s, report.After) || rw.Close() != nil {
		t.Fatalf("writable reopen after exact retirement: %+v, %v", s, err)
	}
	t.Logf("two rewrites; retained %s and %s; read-only reopen passed, writable reopen refused; exact retirement restored writable reopen",
		filepath.Base(before[0]), filepath.Base(after[1]))
}

// This fixture represents the namespace presented to a subsequent writer only
// after independent object-version proof. The cloud observer always lists raw FS.
type publishedMarkerListing struct {
	vfs.FS
	db, old, published string
}

func (v publishedMarkerListing) List(dir string) ([]string, error) {
	names, err := v.FS.List(dir)
	if err != nil || dir != v.db {
		return names, err
	}
	found := false
	visible := make([]string, 0, len(names))
	for _, name := range names {
		if name == v.published {
			found = true
		}
		if name != v.old {
			visible = append(visible, name)
		}
	}
	if !found {
		return nil, errors.New("previously published marker absent")
	}
	return visible, nil
}

func TestGeneration14RetainedManifestWithoutDelete(t *testing.T) {
	dir, request, _ := seedDisk(t)
	old, err := filepath.Glob(filepath.Join(dir, "marker.manifest.*"))
	if err != nil || len(old) != 1 {
		t.Fatalf("missing initial marker: %v, %v", old, err)
	}
	denied := &retainManifest{FS: vfs.Default}
	closed, err := runBatch(denied, dir, request, journal(), func(uint64) error { return nil })
	if err != nil || !closed.Closed || closed.PhysicalCompactions != 2 {
		t.Fatalf("initial two rewrites: %v", err)
	}
	both, err := filepath.Glob(filepath.Join(dir, "marker.manifest.*"))
	if err != nil || len(both) != 2 || both[0] != old[0] {
		t.Fatalf("unexpected published pair: %v, %v", both, err)
	}
	pins := make([]os.FileInfo, 0, 2)
	for _, name := range both {
		fi, err := os.Stat(name)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
			t.Fatalf("invalid marker: %s %v", name, err)
		}
		pins = append(pins, fi)
	}
	view := publishedMarkerListing{FS: denied, db: dir, old: filepath.Base(both[0]), published: filepath.Base(both[1])}
	missing := view
	missing.published = "marker.manifest.999999.MANIFEST-999999"
	if _, err := missing.List(dir); err == nil {
		t.Fatal("hid the old marker without the named published successor")
	}
	db, err := pebble.Open(dir, options(view, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	s, err := readState(db)
	if err != nil || !equalState(s, closed.After) || db.Close() != nil {
		t.Fatalf("writable reopen through retained-marker listing: %+v, %v", s, err)
	}
	for i, name := range both {
		fi, err := os.Stat(name)
		if err != nil || !os.SameFile(fi, pins[i]) || fi.Size() != 0 || fi.ModTime() != pins[i].ModTime() {
			t.Fatalf("raw physical marker changed: %s", name)
		}
	}
	t.Log("subsequent writable open passed with both physical marker files intact and all manifest deletes denied")
}
