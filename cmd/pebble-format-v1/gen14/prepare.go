package main

import (
	"errors"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

type preparedBatch struct {
	Request batchRequest `json:"request"`
	Picker  pickerPlan   `json:"first_picker_plan"`
	Inputs  []table      `json:"first_inputs"`
}

func prepareBatch(fs vfs.FS, dir string) (preparedBatch, error) {
	var result preparedBatch
	db, err := pebble.Open(dir, options(fs, true, nil))
	if err != nil {
		return result, err
	}
	before, stateErr := readState(db)
	candidate, planErr := db.LabPlanOneMarkedFile(maxInputBytes)
	if err := errors.Join(stateErr, planErr, db.Close()); err != nil {
		return result, err
	}
	plan := bindPlan(before, candidate)
	selected := make(map[string]bool, len(plan.InputFiles))
	for _, name := range plan.InputFiles {
		selected[name] = true
	}
	var total uint64
	for _, row := range before.Tables {
		if selected[row.Name] {
			if row.Level != plan.InputLevel || row.Size > maxInputBytes-total {
				return result, errors.New("picker input differs from the bounded inventory")
			}
			total += row.Size
			result.Inputs = append(result.Inputs, row)
		}
	}
	if len(result.Inputs) != len(plan.InputFiles) || total == 0 || total != plan.InputBytes {
		return result, errors.New("picker input closure differs from the observed inventory")
	}
	result.Picker = plan
	result.Request = batchRequest{Units: 2, Before: before, InitialPlanSHA256: plan.PlanSHA256}
	return result, nil
}
