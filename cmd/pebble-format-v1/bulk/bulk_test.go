package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

type bulkJournal map[string]bool

func (j bulkJournal) put(name string, _ interface{}) error {
	if j[name] {
		return fmt.Errorf("duplicate record %s", name)
	}
	j[name] = true
	return nil
}

func stagedManifest(t *testing.T, stage string) []byte {
	t.Helper()
	entries, err := os.ReadDir(stage)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), "marker.manifest.") {
			parts := strings.Split(ent.Name(), ".")
			data, err := os.ReadFile(filepath.Join(stage, parts[len(parts)-1]))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
	t.Fatal("no staged manifest")
	return nil
}

func TestBulkByteCapAndSuccessor(t *testing.T) {
	dir := t.TempDir()
	opts := options(vfs.Default, false, nil)
	opts.ErrorIfNotExists = false
	db, err := pebble.Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	groups := 10
	if maxBatchUnits > 8 {
		groups = 22
	}
	for group := 0; group < groups; group++ {
		begin := fmt.Sprintf("range-%02d/", group)
		for i := 0; i < 100; i++ {
			if err := db.Set([]byte(fmt.Sprintf("%s%04d", begin, i)), []byte(strings.Repeat("v1", 100)), pebble.NoSync); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := db.Compact([]byte(begin), []byte(fmt.Sprintf("range-%02d/", group+1)), false); err != nil {
			t.Fatal(err)
		}
	}
	for _, ver := range []pebble.FormatMajorVersion{3, 6, 7, 10, 13} {
		if err := db.RatchetFormatMajorVersion(ver); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sst") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, e.Name()), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fs := stageFS(vfs.Default, dir, stage)
	plan, err := prepareBatch(fs, dir)
	if err != nil || plan.Request.Before.Marked != groups {
		t.Fatalf("initial plan %+v %v", plan.Request.Before, err)
	}
	plan.Request.Units = maxBatchUnits
	cap := plan.Picker.InputBytes * 5
	first, err := runBatchWithInputCap(fs, dir, plan.Request, bulkJournal{}, func(uint64) error { return nil }, cap)
	if err != nil || !first.Closed || first.PhysicalCompactions <= 2 || first.StopReason != "next-unit-budget" ||
		first.InputBytes > cap || first.InputBytes+first.StoppedPlan.InputBytes <= cap {
		t.Fatalf("byte-capped run %+v %v", first, err)
	}
	next, err := prepareBatch(fs, dir)
	if err != nil || !equalState(next.Request.Before, first.After) {
		t.Fatalf("next state %v", err)
	}
	next.Request.Units = maxBatchUnits
	beforeManifest := stagedManifest(t, stage)
	second, err := runBatch(fs, dir, next.Request, bulkJournal{}, func(uint64) error { return nil })
	if err != nil || !second.Closed || second.After.Marked != 0 || second.PhysicalCompactions+first.PhysicalCompactions != groups {
		t.Fatalf("successor %v %+v", err, second.After)
	}
	if output := os.Getenv("RHEA_BULK_FIXTURE"); output != "" {
		hashes := map[string]interface{}{}
		for _, row := range second.Diff.Created {
			raw, err := os.ReadFile(filepath.Join(dir, row.Name))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			hashes[row.Name] = map[string]interface{}{"size": len(raw), "sha256": hex.EncodeToString(sum[:])}
		}
		fixture, err := json.Marshal(map[string]interface{}{"before": beforeManifest,
			"after": stagedManifest(t, stage), "report": second, "hashes": hashes})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, fixture, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("first closed with %d rewrites, next closed with %d", first.PhysicalCompactions, second.PhysicalCompactions)
}
