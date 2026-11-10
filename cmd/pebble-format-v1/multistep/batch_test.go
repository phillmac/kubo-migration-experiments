package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

const fixtureDir = "/fixture/pebbleds"

type memoryJournal struct {
	entries map[string]interface{}
	fail    string
}

func (j *memoryJournal) put(name string, value interface{}) error {
	if name == j.fail {
		return errors.New("injected evidence failure")
	}
	if _, exists := j.entries[name]; exists {
		return errors.New("existing pending evidence forbids replay")
	}
	j.entries[name] = value
	return nil
}

func journal() *memoryJournal { return &memoryJournal{entries: map[string]interface{}{}} }

func seed(t *testing.T) (vfs.FS, batchRequest) {
	t.Helper()
	fs := vfs.NewMem()
	if err := fs.MkdirAll(fixtureDir, 0700); err != nil {
		t.Fatal(err)
	}
	opts := options(fs, false, nil)
	opts.ErrorIfNotExists = false
	db, err := pebble.Open(fixtureDir, opts)
	if err != nil {
		t.Fatal(err)
	}
	for group := 0; group < 2; group++ {
		for i := 0; i < 128; i++ {
			key := []byte(fmt.Sprintf("probe/%02d/%06d", group, i))
			if err := db.Set(key, []byte(strings.Repeat(fmt.Sprintf("v%06d", i), 16)), pebble.NoSync); err != nil {
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
	for _, version := range []pebble.FormatMajorVersion{3, 6, 7, 10, 13} {
		if err := db.RatchetFormatMajorVersion(version); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := pebble.Open(fixtureDir, options(fs, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	before, err := readState(ro)
	if err != nil || before.Marked != 2 {
		t.Fatalf("need two marked SSTs: %+v %v", before, err)
	}
	p, err := ro.LabPlanOneMarkedFile(maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	return fs, batchRequest{Units: 2, Before: before, InitialPlanSHA256: bindPlan(before, p).PlanSHA256}
}

func readFile(t *testing.T, fs vfs.FS, name string) []byte {
	t.Helper()
	f, err := fs.Open(fixtureDir + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}

func manifestBytes(t *testing.T, fs vfs.FS) []byte {
	t.Helper()
	names, err := fs.List(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.HasPrefix(name, "marker.manifest.") {
			return readFile(t, fs, name[strings.Index(name, ".MANIFEST-")+1:])
		}
	}
	t.Fatal("manifest marker missing")
	return nil
}

func TestTwoGenuineSequentialRewritesAndClosedReopen(t *testing.T) {
	fs, req := seed(t)
	beforeManifest := manifestBytes(t, fs)
	j := journal()
	r, err := runBatch(fs, fixtureDir, req, j, func(uint64) error { return nil })
	if err != nil || !r.Closed || r.PhysicalCompactions != 2 || len(r.Units) != 2 || r.After.Marked != 0 || len(r.Compactions) != 4 {
		t.Fatalf("two-unit result: %+v %v", r, err)
	}
	if len(j.entries) != 6 || r.InputBytes != r.Diff.RetiredBytes || r.IO.SSTWriteBytes == 0 || r.IO.SSTWriteBytes > maxSSTWriteBytes || !equalState(req.Before, r.Before) {
		t.Fatalf("missing durable evidence/aggregate accounting: %+v %+v", r, j.entries)
	}
	ro, err := pebble.Open(fixtureDir, options(fs, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	after, err := readState(ro)
	if err != nil || !equalState(after, r.After) {
		t.Fatalf("closed state not durable: %+v %v", after, err)
	}
	for group := 0; group < 2; group++ {
		value, closer, err := ro.Get([]byte(fmt.Sprintf("probe/%02d/%06d", group, 17)))
		if err != nil || string(value) != strings.Repeat("v000017", 16) {
			t.Fatalf("rewritten data mismatch: %q %v", value, err)
		}
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	// The harness feeds ACTUAL Pebble manifests/output hashes and this report
	// to the independent Python stage validator, without S3 or credentials.
	if output := os.Getenv("RHEA_MULTI_FIXTURE_OUTPUT"); output != "" {
		hashes := map[string]interface{}{}
		for _, row := range r.Diff.Created {
			data := readFile(t, fs, row.Name)
			hash := sha256.Sum256(data)
			hashes[row.Name] = map[string]interface{}{"size": len(data), "sha256": hex.EncodeToString(hash[:])}
		}
		data, err := json.Marshal(map[string]interface{}{"report": r, "before_manifest": beforeManifest,
			"after_manifest": manifestBytes(t, fs), "hashes": hashes})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMismatchedInitialPlanOrStateNeverWrites(t *testing.T) {
	for _, change := range []func(*batchRequest){
		func(r *batchRequest) { r.InitialPlanSHA256 = strings.Repeat("0", 64) },
		func(r *batchRequest) { r.Before.Bytes++ },
		func(r *batchRequest) { r.Before.Marked++ },
		func(r *batchRequest) { r.Units = 3 },
	} {
		fs, req := seed(t)
		change(&req)
		j := journal()
		r, err := runBatch(fs, fixtureDir, req, j, func(uint64) error { return nil })
		if err == nil || r.IO.SSTWriteBytes != 0 || r.IO.MetadataWriteBytes != 0 || len(j.entries) != 0 {
			t.Fatalf("bad expectation reached writable open: %+v %v", r, err)
		}
	}
}

func TestNextCandidateOverAggregateInputStopsBeforeItsWrite(t *testing.T) {
	fs, req := seed(t)
	ro, err := pebble.Open(fixtureDir, options(fs, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ro.LabPlanOneMarkedFile(maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	j := journal()
	r, err := runBatchWithInputCap(fs, fixtureDir, req, j, func(uint64) error { return nil }, p.InputBytes)
	if err != nil || !r.Closed || r.PhysicalCompactions != 1 || len(r.Units) != 1 || r.After.Marked != 1 || r.StoppedPlan == nil || r.StopReason != "next-unit-budget" {
		t.Fatalf("over-budget second unit was not stopped: %+v %v", r, err)
	}
	if j.entries["unit-002-intent.json"] != nil || r.InputBytes != p.InputBytes {
		t.Fatal("over-budget unit was admitted")
	}
}

type failingOutputFS struct {
	vfs.FS
	outputs int
}

func (f *failingOutputFS) Create(name string) (vfs.File, error) {
	if strings.HasSuffix(name, ".sst") {
		f.outputs++
		if f.outputs == 2 {
			return nil, errors.New("injected second-compaction output failure")
		}
	}
	return f.FS.Create(name)
}

func TestSecondCompactionFailurePreservesFirstCommitBeforeClose(t *testing.T) {
	fs, req := seed(t)
	j := journal()
	r, err := runBatch(&failingOutputFS{FS: fs}, fixtureDir, req, j, func(uint64) error { return nil })
	if err == nil || !r.Closed || r.PhysicalCompactions != 1 || len(r.Units) != 1 || r.After.Marked != 1 || r.AttemptedUnit == nil || r.StopReason != "recovery-required" {
		t.Fatalf("second failure lost first commit: %+v %v", r, err)
	}
	if j.entries["unit-001-receipt.json"] == nil || j.entries["unit-002-intent.json"] == nil || j.entries["unit-002-failed.json"] == nil || j.entries["closed.json"] == nil {
		t.Fatal("failed compaction evidence missing")
	}
}

func TestFirstCommitThenSecondIntentFailureClosesAndNeverReplays(t *testing.T) {
	fs, req := seed(t)
	j := journal()
	j.fail = "unit-002-intent.json"
	r, err := runBatch(fs, fixtureDir, req, j, func(uint64) error { return nil })
	if err == nil || !r.Closed || r.After.Marked != 1 || r.PhysicalCompactions != 1 || len(r.Units) != 1 || r.StopReason != "recovery-required" {
		t.Fatalf("partial commit mislabeled: %+v %v", r, err)
	}
	if j.entries["pending.json"] == nil || j.entries["unit-001-receipt.json"] == nil || j.entries["closed.json"] == nil {
		t.Fatal("partial evidence lost")
	}
	// Even an explicit request with a newly inspected exact remaining state
	// cannot reuse the pending journal to replay a writer.
	ro, err := pebble.Open(fixtureDir, options(fs, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ro.LabPlanOneMarkedFile(maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	req.Before, req.InitialPlanSHA256 = r.After, bindPlan(r.After, p).PlanSHA256
	retry, err := runBatch(fs, fixtureDir, req, j, func(uint64) error { return nil })
	if err == nil || retry.IO.MetadataWriteBytes != 0 || retry.IO.SSTWriteBytes != 0 {
		t.Fatalf("pending journal permitted replay: %+v %v", retry, err)
	}
}

func TestProtectedJournalExclusiveDurability(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := newDiskJournal(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.put("pending.json", map[string]int{"units": 2}); err != nil {
		t.Fatal(err)
	}
	if err := j.put("pending.json", "overwrite"); err == nil {
		t.Fatal("journal evidence replaced")
	}
	if err := j.put("../escape.json", nil); err == nil {
		t.Fatal("journal path escape")
	}
	info, err := os.Stat(filepath.Join(dir, "pending.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("wrong evidence mode: %v %v", info, err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := j.put("closed.json", nil); err == nil {
		t.Fatal("unprotected journal accepted")
	}
}
