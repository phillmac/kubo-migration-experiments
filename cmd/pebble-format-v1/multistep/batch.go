package main

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

const batchSchema = "rhea-multi-sst-writer-v1"

type batchRequest struct {
	Units             int    `json:"maximum_units"`
	Before            state  `json:"before"`
	InitialPlanSHA256 string `json:"initial_plan_sha256"`
}

type batchReport struct {
	Schema              string            `json:"schema"`
	Action              string            `json:"action"`
	Request             batchRequest      `json:"request"`
	Before              state             `json:"before"`
	After               state             `json:"after"`
	Units               []report          `json:"units"`
	AttemptedUnit       *report           `json:"attempted_unit,omitempty"`
	PhysicalCompactions int               `json:"physical_compactions"`
	Compactions         []compactionEvent `json:"compactions"`
	InputBytes          uint64            `json:"input_bytes"`
	Diff                tableDiff         `json:"sst_diff"`
	IO                  ioReport          `json:"io"`
	Closed              bool              `json:"closed"`
	StopReason          string            `json:"stop_reason"`
	StoppedPlan         *pickerPlan       `json:"stopped_plan,omitempty"`
	Error               string            `json:"error,omitempty"`
}

func equalState(a, b state) bool {
	return a.Format == b.Format && a.Marked == b.Marked && a.Files == b.Files &&
		a.Bytes == b.Bytes && a.InventorySHA256 == b.InventorySHA256
}

// runBatch never snapshots, enumerates S3, drains rclone, or publishes markers.
// One shared FS guard counts EVERY write across open, all units, and close.
// freeCheck must be a continuously enforced monitor in any future live adapter;
// the offline fixture deliberately supplies a no-op. No live adapter is exposed.
func runBatch(raw vfs.FS, dir string, req batchRequest, sink evidenceSink, freeCheck func(uint64) error) (result batchReport, err error) {
	return runBatchWithInputCap(raw, dir, req, sink, freeCheck, maxInputBytes)
}

// Only tests lower this cap to exercise real picker refusal without a large
// fixture. No caller can raise the pilot maximum and no CLI exposes this knob.
func runBatchWithInputCap(raw vfs.FS, dir string, req batchRequest, sink evidenceSink, freeCheck func(uint64) error, inputCap uint64) (result batchReport, err error) {
	result = batchReport{Schema: batchSchema, Action: "multi-step", Request: req,
		Units: []report{}, Compactions: []compactionEvent{},
		Diff: tableDiff{Created: []table{}, Retired: []table{}}}
	guard := newBudgetFS(raw, dir, true, freeCheck)
	var db *pebble.DB
	var mu sync.Mutex
	events := []compactionEvent{}
	defer func() {
		if db != nil {
			// Even a rewrite/receipt failure must close, never retry the writer.
			final, stateErr := readState(db)
			closeErr := db.Close()
			result.Closed = closeErr == nil
			result.After = final
			var diffErr error
			result.Diff, diffErr = difference(result.Before.Tables, final.Tables)
			err = errors.Join(err, stateErr, closeErr, diffErr)
		}
		mu.Lock()
		result.Compactions = append(result.Compactions, events...)
		mu.Unlock()
		for _, e := range result.Compactions {
			if e.Type == "end" && e.Error == "" {
				result.PhysicalCompactions++
			}
		}
		result.IO = guard.report()
		if db != nil && err == nil {
			created, retired := []table{}, []table{}
			for _, unit := range result.Units {
				created = append(created, unit.Diff.Created...)
				retired = append(retired, unit.Diff.Retired...)
			}
			if result.PhysicalCompactions != len(result.Units) || len(result.Compactions) != 2*len(result.Units) || !sameTables(created, result.Diff.Created) || !sameTables(retired, result.Diff.Retired) {
				err = errors.New("aggregate compaction/delta differs from completed units")
			}
		}
		if result.IO.BlockedBudgetError != "" {
			err = errors.Join(err, errors.New(result.IO.BlockedBudgetError))
		}
		if err != nil {
			result.Error = err.Error()
			result.StopReason = "recovery-required"
		}
		if db != nil {
			// This is a close observation, never a certificate or replay token.
			if journalErr := sink.put("closed.json", result); journalErr != nil {
				err = errors.Join(err, journalErr)
				result.Error = err.Error()
				result.StopReason = "recovery-required"
			}
		}
	}()
	if inputCap == 0 || inputCap > maxInputBytes || sink == nil || freeCheck == nil || req.Units < 1 || req.Units > 2 || req.Before.Format != "013" || req.Before.Marked < 1 || req.Before.Files < 1 || req.Before.Bytes == 0 || !shaPattern.MatchString(req.Before.InventorySHA256) || !shaPattern.MatchString(req.InitialPlanSHA256) {
		return result, errors.New("explicit exact format-013 state, first plan and one/two-unit admission required")
	}
	// Digest and exact prestate checked before writable Open can create metadata.
	ro, openErr := pebble.Open(dir, options(guard, true, nil))
	if openErr != nil {
		return result, openErr
	}
	before, stateErr := readState(ro)
	result.Before, result.After = before, before
	candidate, planErr := ro.LabPlanOneMarkedFile(maxInputBytes)
	closeErr := ro.Close()
	if err = errors.Join(stateErr, planErr, closeErr); err != nil {
		return result, err
	}
	if !equalState(req.Before, before) || bindPlan(before, candidate).PlanSHA256 != req.InitialPlanSHA256 {
		return result, errors.New("initial exact state or inspected first plan differs")
	}
	if candidate.InputBytes > inputCap {
		return result, errors.New("first candidate exceeds aggregate input allowance before writable open")
	}
	pending := struct {
		Schema  string       `json:"schema"`
		Phase   string       `json:"phase"`
		Request batchRequest `json:"request"`
	}{batchSchema, "executing", req}
	if err = sink.put("pending.json", pending); err != nil {
		return result, err
	}
	listener := &pebble.EventListener{
		CompactionBegin: func(info pebble.CompactionInfo) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, compactionEvent{Type: "begin", Job: info.JobID, Reason: info.Reason})
		},
		CompactionEnd: func(info pebble.CompactionInfo) {
			e := compactionEvent{Type: "end", Job: info.JobID, Reason: info.Reason, Input: []table{}, Output: []table{}}
			if info.Err != nil {
				e.Error = info.Err.Error()
			}
			for _, level := range info.Input {
				for _, f := range level.Tables {
					e.Input = append(e.Input, table{Name: f.FileNum.String() + ".sst", Number: uint64(f.FileNum), Size: f.Size, Level: level.Level})
				}
			}
			for _, f := range info.Output.Tables {
				e.Output = append(e.Output, table{Name: f.FileNum.String() + ".sst", Number: uint64(f.FileNum), Size: f.Size, Level: info.Output.Level})
			}
			mu.Lock()
			defer mu.Unlock()
			events = append(events, e)
		},
	}
	db, err = pebble.Open(dir, options(guard, false, listener))
	if err != nil {
		return result, err
	}
	current, err := readState(db)
	if err != nil || !equalState(current, before) {
		return result, errors.Join(err, errors.New("writable prestate changed"))
	}
	seen := map[string]bool{}
	for index := 0; index < req.Units; index++ {
		if current.Marked == 0 {
			result.StopReason = "no-marked-files"
			return result, nil
		}
		candidate, err = db.LabPlanOneMarkedFile(maxInputBytes)
		if err != nil {
			return result, err
		}
		plan := bindPlan(current, candidate)
		if index == 0 && plan.PlanSHA256 != req.InitialPlanSHA256 {
			return result, errors.New("first picker plan changed after writable open")
		}
		used := guard.report()
		// Output sizes are known only while Pebble writes. Reserve 2x input at
		// admission; the shared byte guard is the hard bound even if actual
		// expansion is larger. A runtime budget failure requires recovery.
		if candidate.InputBytes > inputCap-result.InputBytes || candidate.InputBytes > (maxSSTWriteBytes-used.SSTWriteBytes)/2 || used.MetadataWriteBytes >= maxMetadataWriteBytes {
			result.StoppedPlan = &plan
			result.StopReason = "next-unit-budget"
			return result, nil
		}
		for _, name := range plan.InputFiles {
			if seen[name] {
				return result, errors.New("picker reused earlier batch input/output")
			}
		}
		intent := struct {
			Index  int        `json:"index"`
			Before state      `json:"before"`
			Plan   pickerPlan `json:"picker_plan"`
		}{index + 1, current, plan}
		if err = sink.put(fmt.Sprintf("unit-%03d-intent.json", index+1), intent); err != nil {
			return result, err
		}
		mu.Lock()
		start := len(events)
		mu.Unlock()
		u := report{Action: "step", PickerPlan: &plan, ExpectedPlanSHA256: plan.PlanSHA256}
		result.InputBytes += candidate.InputBytes
		_, rewriteErr := db.LabRewriteOneMarkedFile(inputCap-result.InputBytes+candidate.InputBytes, candidate.PlanSHA256)
		after, readErr := readState(db)
		u.states(current, after)
		u.Diff, err = difference(current.Tables, after.Tables)
		mu.Lock()
		u.Compactions = append([]compactionEvent{}, events[start:]...)
		mu.Unlock()
		// Unit I/O is cumulative within this one writable session, not reset.
		u.IO = guard.report()
		err = errors.Join(err, rewriteErr, readErr)
		if err == nil {
			err = validateUnit(u)
		}
		if err != nil {
			u.Error = err.Error()
			result.AttemptedUnit = &u
			err = errors.Join(err, sink.put(fmt.Sprintf("unit-%03d-failed.json", index+1), u))
			return result, err
		}
		for _, rows := range [][]table{u.Diff.Retired, u.Diff.Created} {
			for _, row := range rows {
				if seen[row.Name] {
					return result, errors.New("non-disjoint batch delta")
				}
				seen[row.Name] = true
			}
		}
		result.Units = append(result.Units, u)
		if err = sink.put(fmt.Sprintf("unit-%03d-receipt.json", index+1), u); err != nil {
			return result, err
		}
		current = after
	}
	result.StopReason = "unit-limit"
	return result, nil
}
