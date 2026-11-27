package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

func TestGeneration14StagedManifest(t *testing.T) {
	dir, req, _ := seedDisk(t)
	stage := t.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = raw
		if !strings.HasSuffix(path, ".sst") {
			if err := os.WriteFile(filepath.Join(stage, e.Name()), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	fs := stageFS(vfs.Default, dir, stage)
	batch, err := runBatch(fs, dir, req, journal(), func(uint64) error { return nil })
	if err != nil || !batch.Closed || batch.PhysicalCompactions != 2 {
		t.Fatalf("staged run: %v (%s)", err, batch.Error)
	}
	// Every predecessor object is still byte-for-byte available at its original path.
	for name, body := range before {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(raw, body) {
			t.Fatalf("baseline changed: %s %v", name, err)
		}
	}
	rawReport, err := inspectClosed(vfs.Default, dir)
	if err != nil || rawReport.InventoryAfter != req.Before.InventorySHA256 {
		t.Fatalf("old generation no longer opens: %v", err)
	}
	meta, err := os.ReadDir(stage)
	if err != nil {
		t.Fatal(err)
	}
	newMarker := ""
	for _, e := range meta {
		name := e.Name()
		body, err := os.ReadFile(filepath.Join(stage, name))
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := before[name]; ok {
			if !bytes.Equal(prev, body) {
				t.Fatalf("non-create metadata change: %s", name)
			}
			continue
		}
		if strings.HasPrefix(name, "marker.manifest.") {
			newMarker = name
			continue
		}
		if !metadataFile.MatchString(name) {
			t.Fatalf("invalid metadata: %s", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if newMarker == "" {
		t.Fatal("new manifest marker missing")
	}
	beforePub, err := inspectClosed(vfs.Default, dir)
	if err != nil || beforePub.InventoryAfter != req.Before.InventorySHA256 {
		t.Fatalf("before-publication reopen: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, newMarker), nil, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := inspectClosed(vfs.Default, dir)
	if err != nil || after.InventoryAfter != batch.After.InventorySHA256 || after.MarkedAfter != 0 {
		t.Fatalf("published physical reopen: %v", err)
	}
	next := t.TempDir()
	for _, e := range meta {
		raw, err := os.ReadFile(filepath.Join(stage, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(next, e.Name()), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// The next writable open sees precisely the proved logical metadata kept by the controller.
	nextFS := stageFS(vfs.Default, dir, next)
	db, err := pebble.Open(dir, options(nextFS, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("two staged rewrites, old and prepublication reopens, raw published reopen, subsequent staged writable reopen")
}
