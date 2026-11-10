package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// This narrowly scoped in-memory fixture checks the new read-only picker API,
// stale-plan rejection and exactly-one execution path. It has no host, network,
// production path or remote credential access.
func TestAuthoritativeReadOnlyPlanAndOneRewrite(t *testing.T) {
	fs := vfs.NewMem()
	const dir = "/lab/pebbleds"
	if err := fs.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	seedOpts := options(fs, false, nil)
	seedOpts.ErrorIfNotExists = false
	db, err := pebble.Open(dir, seedOpts)
	if err != nil {
		t.Fatal(err)
	}
	for group := 0; group < 2; group++ {
		for i := 0; i < 128; i++ {
			if err := db.Set([]byte(fmt.Sprintf("probe/%02d/%06d", group, i)), []byte(strings.Repeat(fmt.Sprintf("value-%06d", i), 16)), pebble.NoSync); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := db.Compact([]byte(fmt.Sprintf("probe/%02d/", group)), []byte(fmt.Sprintf("probe/%02d/", group+1)), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RatchetFormatMajorVersion(3); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Exercise actual Pebble directory/marker/WAL paths through the guarded FS,
	// not just individual File.Write unit tests. Every preliminary stage is a
	// separate writable open/close with SST writes prohibited.
	for _, target := range []pebble.FormatMajorVersion{6, 7, 10, 13} {
		guarded := newBudgetFS(fs, dir, false, func(uint64) error { return nil })
		op := options(guarded, false, nil)
		db, err = pebble.Open(dir, op)
		if err != nil {
			t.Fatal(err)
		}
		initial, err := readState(db)
		if err != nil {
			t.Fatal(err)
		}
		if target == 7 && initial.Marked != 0 {
			t.Fatal("fixture unexpectedly needs split-key compaction")
		}
		if err := db.RatchetFormatMajorVersion(target); err != nil {
			t.Fatal(err)
		}
		final, err := readState(db)
		if err != nil {
			t.Fatal(err)
		}
		if initial.InventorySHA256 != final.InventorySHA256 {
			t.Fatal("preliminary stage changed SST inventory")
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if guarded.report().SSTWriteBytes != 0 {
			t.Fatal("preliminary stage wrote SST data")
		}
	}

	readonlyGuard := newBudgetFS(fs, dir, false, func(uint64) error { return nil })
	roOpts := options(readonlyGuard, true, nil)
	ro, err := pebble.Open(dir, roOpts)
	if err != nil {
		t.Fatal(err)
	}
	before, err := readState(ro)
	if err != nil {
		t.Fatal(err)
	}
	if before.Marked != 2 {
		t.Fatalf("expected two marked fixture tables, got %d", before.Marked)
	}
	plan, err := ro.LabPlanOneMarkedFile(maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if plan.InputBytes == 0 || plan.InputLevel != plan.OutputLevel || len(plan.InputFiles) != 1 {
		t.Fatalf("unexpected picker result: %+v", plan)
	}
	if _, err := ro.LabRewriteOneMarkedFile(maxInputBytes, plan.PlanSHA256); err == nil {
		t.Fatal("read-only DB allowed rewrite")
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}

	stepGuard := newBudgetFS(fs, dir, true, func(uint64) error { return nil })
	stepOpts := options(stepGuard, false, nil)
	db, err = pebble.Open(dir, stepOpts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.LabRewriteOneMarkedFile(maxInputBytes, strings.Repeat("0", 64)); err == nil {
		t.Fatal("stale candidate digest accepted")
	}
	if _, err := db.LabRewriteOneMarkedFile(1, plan.PlanSHA256); err == nil {
		t.Fatal("over-budget candidate was scheduled")
	}
	unchanged, err := readState(db)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Marked != before.Marked || unchanged.InventorySHA256 != before.InventorySHA256 {
		t.Fatal("negative admission mutated SST state")
	}
	if _, err := db.LabRewriteOneMarkedFile(maxInputBytes, plan.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	after, err := readState(db)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := difference(before.Tables, after.Tables)
	if err != nil {
		t.Fatal(err)
	}
	if after.Marked != 1 || after.Format != "013" || delta.CreatedCount != 1 || delta.RetiredCount != 1 {
		t.Fatalf("wrong single-rewrite result: %+v %+v", after, delta)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if stepGuard.report().SSTWriteBytes == 0 {
		t.Fatal("real rewrite bypassed SST write guard")
	}
	reopenedGuard := newBudgetFS(fs, dir, false, func(uint64) error { return nil })
	ro, err = pebble.Open(dir, options(reopenedGuard, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := readState(ro)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Marked != 1 || reopened.InventorySHA256 != after.InventorySHA256 {
		t.Fatal("closed rewrite progress was not durable or a second rewrite chained")
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
}
