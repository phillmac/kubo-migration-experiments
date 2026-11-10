//go:build ignore

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// This embeds a recipe, never saved SST/MANIFEST bytes.
//go:embed offline-case.json
var diskRecipeJSON []byte

type diskRecipe struct {
	Schema string `json:"schema"`
	Groups int `json:"groups"`
	Records int `json:"records_per_group"`
	Repetitions int `json:"value_repetitions"`
	Steps []pebble.FormatMajorVersion `json:"format_steps"`
	Units int `json:"maximum_units"`
	Marked int `json:"expected_marked_before"`
}

// Every call creates new OS files. No DB fixture, SST or MANIFEST is reused.
func seedDisk(t *testing.T) (string, batchRequest, []byte) {
	t.Helper()
	var recipe diskRecipe
	if err := json.Unmarshal(diskRecipeJSON, &recipe); err != nil { t.Fatal(err) }
	if recipe.Schema != "rhea-pilot-offline-case-v1" || recipe.Groups != 2 || recipe.Records != 128 || recipe.Repetitions != 16 || recipe.Units != 2 || recipe.Marked != 2 { t.Fatal("unreviewed fixture recipe") }
	dir := filepath.Join(t.TempDir(), "pebbleds")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	opts := options(vfs.Default, false, nil)
	opts.ErrorIfNotExists = false
	db, err := pebble.Open(dir, opts)
	if err != nil { t.Fatal(err) }
	for group := 0; group < recipe.Groups; group++ {
		for i := 0; i < recipe.Records; i++ {
			key := []byte(fmt.Sprintf("probe/%02d/%06d", group, i))
			if err := db.Set(key, []byte(strings.Repeat(fmt.Sprintf("v%06d", i), recipe.Repetitions)), pebble.NoSync); err != nil { t.Fatal(err) }
		}
		if err := db.Flush(); err != nil { t.Fatal(err) }
		if err := db.Compact([]byte(fmt.Sprintf("probe/%02d/", group)), []byte(fmt.Sprintf("probe/%02d/", group+1)), false); err != nil { t.Fatal(err) }
	}
	for _, version := range recipe.Steps {
		if err := db.RatchetFormatMajorVersion(version); err != nil { t.Fatal(err) }
	}
	if err := db.Close(); err != nil { t.Fatal(err) }
	s, plan := inspectDisk(t, dir)
	if s.Marked != recipe.Marked || s.Files != 2 { t.Fatalf("need two genuine marked SSTs: %+v", s) }
	return dir, batchRequest{Units: recipe.Units, Before: s, InitialPlanSHA256: plan.PlanSHA256}, diskManifest(t, dir)
}

func inspectDisk(t *testing.T, dir string) (state, pickerPlan) {
	t.Helper()
	db, err := pebble.Open(dir, options(vfs.Default, true, nil))
	if err != nil { t.Fatal(err) }
	s, err := readState(db)
	if err != nil { t.Fatal(err) }
	var plan pickerPlan
	if s.Marked > 0 {
		p, err := db.LabPlanOneMarkedFile(maxInputBytes)
		if err != nil { t.Fatal(err) }
		plan = bindPlan(s, p)
	}
	// Check every original value after close, including after a failed rewrite.
	for group := 0; group < 2; group++ {
		for i := 0; i < 128; i++ {
			value, closer, err := db.Get([]byte(fmt.Sprintf("probe/%02d/%06d", group, i)))
			if err != nil { t.Fatal(err) }
			matches := string(value) == strings.Repeat(fmt.Sprintf("v%06d", i), 16)
			if err := closer.Close(); err != nil { t.Fatal(err) }
			if !matches { t.Fatal("original value changed") }
		}
	}
	if err := db.Close(); err != nil { t.Fatal(err) }
	return s, plan
}

func diskManifest(t *testing.T, dir string) []byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil { t.Fatal(err) }
	var manifest string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "marker.manifest.") {
			if manifest != "" { t.Fatal("ambiguous manifest marker") }
			pos := strings.Index(e.Name(), ".MANIFEST-")
			if pos < 0 { t.Fatal("invalid manifest marker") }
			manifest = e.Name()[pos+1:]
		}
	}
	if manifest == "" { t.Fatal("manifest marker missing") }
	data, err := os.ReadFile(filepath.Join(dir, manifest))
	if err != nil { t.Fatal(err) }
	return data
}

// Count successful OS sync operations under the unchanged shared budget guard.
// SyncTo is counted separately: a queued range sync is not durable fsync proof.
type syncFS struct {
	vfs.FS
	syncs atomic.Int64
	dataSyncs atomic.Int64
	rangeSyncs atomic.Int64
	outputs atomic.Int64
	failSecond bool
}
type syncFile struct { vfs.File; fs *syncFS }
func (f *syncFile) Sync() error { err := f.File.Sync(); if err == nil { f.fs.syncs.Add(1) }; return err }
func (f *syncFile) SyncData() error { err := f.File.SyncData(); if err == nil { f.fs.dataSyncs.Add(1) }; return err }
func (f *syncFile) SyncTo(n int64) (bool, error) { full, err := f.File.SyncTo(n); if err == nil { f.fs.rangeSyncs.Add(1) }; return full, err }
func (f *syncFS) wrap(file vfs.File, err error) (vfs.File, error) { if err != nil { return nil, err }; return &syncFile{file, f}, nil }
func (f *syncFS) Create(name string) (vfs.File, error) {
	if strings.HasSuffix(name, ".sst") && f.outputs.Add(1) == 2 && f.failSecond { return nil, errors.New("offline injected second output interruption") }
	return f.wrap(f.FS.Create(name))
}
func (f *syncFS) Open(name string, opts ...vfs.OpenOption) (vfs.File, error) { return f.wrap(f.FS.Open(name, opts...)) }
func (f *syncFS) OpenReadWrite(name string, opts ...vfs.OpenOption) (vfs.File, error) { return f.wrap(f.FS.OpenReadWrite(name, opts...)) }
func (f *syncFS) OpenDir(name string) (vfs.File, error) { return f.wrap(f.FS.OpenDir(name)) }
func (f *syncFS) ReuseForWrite(a, b string) (vfs.File, error) { return f.wrap(f.FS.ReuseForWrite(a, b)) }

type observedJournal struct {
	*diskJournal
	mode string
	second atomic.Bool
	records int
	bytes int
}
func (j *observedJournal) put(name string, value interface{}) error {
	if err := j.diskJournal.put(name, value); err != nil { return err }
	body, err := os.ReadFile(filepath.Join(j.dir, name))
	if err != nil { return err }
	j.records++
	j.bytes += len(body)
	if name == "unit-002-intent.json" {
		j.second.Store(true)
		if j.mode == "exit-second-intent" { os.Exit(73) }
	}
	return nil
}

// Only the Go test executable accepts these paths/faults. pilot_main has no
// reference to this function, no env switch, and no test flag or writable ABI.
func TestOfflineChild(t *testing.T) {
	if os.Getenv("RHEA_PILOT_TEST_CHILD") != "1" { return }
	dir := os.Getenv("RHEA_PILOT_TEST_DB")
	jdir := os.Getenv("RHEA_PILOT_TEST_JOURNAL")
	var req batchRequest
	if err := json.Unmarshal([]byte(os.Getenv("RHEA_PILOT_TEST_REQUEST")), &req); err != nil { t.Fatal(err) }
	j, err := newDiskJournal(jdir, uint32(os.Geteuid()))
	if err != nil { t.Fatal(err) }
	mode := os.Getenv("RHEA_PILOT_TEST_MODE")
	sink := &observedJournal{diskJournal: j, mode: mode}
	fs := &syncFS{FS: vfs.Default, failSecond: mode == "fail-second-output"}
	var checks, writeChecks atomic.Int64
	monitor := func(n uint64) error {
		checks.Add(1)
		if n > 0 {
			writeChecks.Add(1)
			if mode == "monitor-second" && sink.second.Load() { return errors.New("offline monitor revoked during second unit write") }
		}
		return nil
	}
	r, batchErr := runBatch(fs, dir, req, sink, monitor)
	output := map[string]interface{}{"report": r, "db_sync": fs.syncs.Load(), "db_sync_data": fs.dataSyncs.Load(),
		"db_sync_to": fs.rangeSyncs.Load(), "monitor_checks": checks.Load(), "write_checks": writeChecks.Load(),
		"evidence_records": sink.records, "evidence_bytes": sink.bytes}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil { os.Exit(79) }
	if batchErr != nil { os.Exit(23) }
	os.Exit(0)
}

type childObservation struct {
	Report batchReport `json:"report"`
	DBSync int64 `json:"db_sync"`
	DBSyncData int64 `json:"db_sync_data"`
	MonitorChecks int64 `json:"monitor_checks"`
	WriteChecks int64 `json:"write_checks"`
	Records int `json:"evidence_records"`
	Bytes int `json:"evidence_bytes"`
}

func diskChild(t *testing.T, dir, jdir, mode string, req batchRequest) (childObservation, int) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil { t.Fatal(err) }
	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestOfflineChild$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "RHEA_PILOT_TEST_CHILD=1", "RHEA_PILOT_TEST_DB="+dir,
		"RHEA_PILOT_TEST_JOURNAL="+jdir, "RHEA_PILOT_TEST_MODE="+mode, "RHEA_PILOT_TEST_REQUEST="+string(body)}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil { t.Fatal("child timed out: ", stderr.String()) }
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) { t.Fatal(err) }
		code = exit.ExitCode()
	}
	var observation childObservation
	if code != 73 {
		if err := json.Unmarshal(stdout.Bytes(), &observation); err != nil { t.Fatalf("child exit %d, stdout=%s stderr=%s: %v", code, stdout.String(), stderr.String(), err) }
	}
	return observation, code
}

func assertJournal(t *testing.T, jdir string, observation childObservation, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(jdir)
	if err != nil || len(entries) != len(names) { t.Fatalf("evidence entries %v: %v", entries, err) }
	bytes := 0
	for _, name := range names {
		p := filepath.Join(jdir, name)
		body, err := os.ReadFile(p)
		if err != nil || len(body) == 0 || body[len(body)-1] != '\n' || !json.Valid(body) { t.Fatalf("invalid durable evidence %s: %v", name, err) }
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0600 { t.Fatal("evidence mode") }
		bytes += len(body)
	}
	if observation.Records != 0 && (observation.Records != len(names) || observation.Bytes != bytes) { t.Fatal("evidence accounting differs from disk bytes") }
}

func TestPilotDiskTwoSequentialSubprocessRewrites(t *testing.T) {
	dir, req, beforeManifest := seedDisk(t)
	jdir := t.TempDir()
	o, code := diskChild(t, dir, jdir, "success", req)
	r := o.Report
	if code != 0 || !r.Closed || r.After.Marked != 0 || len(r.Units) != 2 || r.PhysicalCompactions != 2 || r.Error != "" { t.Fatalf("subprocess %d: %+v", code, r) }
	if o.DBSync+o.DBSyncData == 0 || o.WriteChecks < 2 || o.MonitorChecks <= o.WriteChecks { t.Fatalf("missing actual sync/continuous monitor calls: %+v", o) }
	assertJournal(t, jdir, o, "pending.json", "unit-001-intent.json", "unit-001-receipt.json", "unit-002-intent.json", "unit-002-receipt.json", "closed.json")
	closed, err := os.ReadFile(filepath.Join(jdir, "closed.json"))
	if err != nil { t.Fatal(err) }
	expected, err := json.Marshal(r)
	if err != nil || string(closed) != string(expected)+"\n" { t.Fatal("stdout differs from durable close observation") }
	after, _ := inspectDisk(t, dir)
	if !equalState(r.After, after) { t.Fatal("closed on-disk state differs") }
	seen := map[string]bool{}
	for _, unit := range r.Units {
		if err := validateUnit(unit); err != nil { t.Fatal(err) }
		for _, rows := range [][]table{unit.Diff.Retired, unit.Diff.Created} {
			for _, row := range rows { if seen[row.Name] { t.Fatal("reused SST") }; seen[row.Name] = true }
		}
	}
	// Actual disk MANIFESTs/output hashes feed the unchanged Python verifier.
	if output := os.Getenv("RHEA_PILOT_FIXTURE_OUTPUT"); output != "" {
		hashes := map[string]interface{}{}
		evidenceHashes := map[string]string{}
		entries, err := os.ReadDir(jdir)
		if err != nil { t.Fatal(err) }
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(jdir, entry.Name()))
			if err != nil { t.Fatal(err) }
			hash := sha256.Sum256(data)
			evidenceHashes[entry.Name()] = hex.EncodeToString(hash[:])
		}
		for _, row := range r.Diff.Created {
			data, err := os.ReadFile(filepath.Join(dir, row.Name))
			if err != nil { t.Fatal(err) }
			hash := sha256.Sum256(data)
			hashes[row.Name] = map[string]interface{}{"size": len(data), "sha256": hex.EncodeToString(hash[:])}
		}
		data, err := json.Marshal(map[string]interface{}{"report": r, "before_manifest": beforeManifest, "after_manifest": diskManifest(t, dir), "hashes": hashes,
			"offline_observation": map[string]interface{}{"deployable": false, "db_sync": o.DBSync, "db_sync_data": o.DBSyncData,
				"monitor_checks": o.MonitorChecks, "write_checks": o.WriteChecks, "evidence_records": o.Records,
				"evidence_bytes": o.Bytes, "evidence_sha256": evidenceHashes,
				"journal_syncs_implied_by_successful_put": 2*o.Records}})
		if err != nil { t.Fatal(err) }
		if err := os.WriteFile(output, data, 0600); err != nil { t.Fatal(err) }
	}
}

func TestPilotDiskSecondInterruptionAndClose(t *testing.T) {
	for _, mode := range []string{"fail-second-output", "monitor-second"} {
		t.Run(mode, func(t *testing.T) {
			dir, req, _ := seedDisk(t)
			jdir := t.TempDir()
			o, code := diskChild(t, dir, jdir, mode, req)
			r := o.Report
			if code != 23 || !r.Closed || r.After.Marked != 1 || len(r.Units) != 1 || r.PhysicalCompactions != 1 || r.AttemptedUnit == nil || r.StopReason != "recovery-required" { t.Fatalf("interrupted subprocess %d: %+v", code, r) }
			assertJournal(t, jdir, o, "pending.json", "unit-001-intent.json", "unit-001-receipt.json", "unit-002-intent.json", "unit-002-failed.json", "closed.json")
			after, plan := inspectDisk(t, dir)
			if !equalState(after, r.After) { t.Fatal("failed rewrite state not durable") }
			// Even a newly inspected exact request cannot replay retained evidence.
			req.Before, req.InitialPlanSHA256 = after, plan.PlanSHA256
			retry, code := diskChild(t, dir, jdir, "success", req)
			if code != 23 || retry.Report.IO.SSTWriteBytes != 0 || retry.Report.IO.MetadataWriteBytes != 0 { t.Fatalf("replayed retained evidence: %+v", retry) }
		})
	}
}

func TestPilotDiskProcessExitAfterSecondIntent(t *testing.T) {
	dir, req, _ := seedDisk(t)
	jdir := t.TempDir()
	o, code := diskChild(t, dir, jdir, "exit-second-intent", req)
	if code != 73 { t.Fatalf("expected interrupted process, got %d", code) }
	assertJournal(t, jdir, o, "pending.json", "unit-001-intent.json", "unit-001-receipt.json", "unit-002-intent.json")
	after, _ := inspectDisk(t, dir)
	if after.Marked != 1 { t.Fatalf("first rewrite not preserved after process exit: %+v", after) }
	if _, err := os.Stat(filepath.Join(jdir, "closed.json")); !os.IsNotExist(err) { t.Fatal("abrupt exit fabricated clean close evidence") }
}

func TestPilotCLIAlwaysRefusesWriterArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--db", cloneDB}, {"--offline"}, {"--live"}, {"--abi", "--write"}, {"-test.run=TestOfflineChild"}} {
		var out, stderr bytes.Buffer
		if pilotCLI(args, &out, &stderr) != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), "NON-DEPLOYABLE") { t.Fatal("writable CLI bypass") }
	}
}
