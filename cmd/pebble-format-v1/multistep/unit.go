// Picker binding and single-unit validation copied from realstep at e9abee5.
// The historical command and its report schema remain unchanged.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type pickerPlan struct {
	InputLevel      int      `json:"input_level"`
	OutputLevel     int      `json:"output_level"`
	InputFiles      []string `json:"input_files"`
	InputBytes      uint64   `json:"input_bytes"`
	CandidateSHA256 string   `json:"candidate_sha256"`
	PlanSHA256      string   `json:"plan_sha256"`
}

func bindPlan(s state, p pebble.LabRewritePlan) pickerPlan {
	files := make([]string, len(p.InputFiles))
	for i, name := range p.InputFiles {
		files[i] = name + ".sst"
	}
	sort.Strings(files)
	h := sha256.New()
	fmt.Fprintf(h, "fullclone-plan-v1\nformat\t%s\nmarked\t%d\ninventory\t%s\ncandidate\t%s\n", s.Format, s.Marked, s.InventorySHA256, p.PlanSHA256)
	return pickerPlan{InputLevel: p.InputLevel, OutputLevel: p.OutputLevel, InputFiles: files, InputBytes: p.InputBytes, CandidateSHA256: p.PlanSHA256, PlanSHA256: hex.EncodeToString(h.Sum(nil))}
}

func options(fs vfs.FS, readOnly bool, listener *pebble.EventListener) *pebble.Options {
	opts := &pebble.Options{FS: fs, ReadOnly: readOnly, ErrorIfNotExists: true,
		FormatMajorVersion: pebble.FormatMostCompatible, DisableAutomaticCompactions: true,
		MaxConcurrentCompactions: func() int { return 1 }, EventListener: listener}
	pebble.LabDisableTableStats(opts)
	return opts
}

func sameTables(a, b []table) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]table(nil), a...), append([]table(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i].Number < x[j].Number })
	sort.Slice(y, func(i, j int) bool { return y[i].Number < y[j].Number })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func validateUnit(r report) error {
	if r.AfterFormat != "013" || r.MarkedAfter >= r.MarkedBefore || r.MarkedBefore-r.MarkedAfter > r.Diff.RetiredCount || r.Diff.CreatedCount < 1 || r.Diff.RetiredCount < 1 || r.Diff.CreatedBytes > maxSSTWriteBytes {
		return errors.New("single rewrite did not satisfy format, progress, or output bounds")
	}
	if len(r.Compactions) != 2 || r.Compactions[0].Type != "begin" || r.Compactions[1].Type != "end" || r.Compactions[0].Job != r.Compactions[1].Job || r.Compactions[0].Reason != "rewrite" || r.Compactions[1].Reason != "rewrite" || r.Compactions[1].Error != "" {
		return errors.New("expected exactly one successful rewrite compaction")
	}
	if !sameTables(r.Compactions[1].Input, r.Diff.Retired) || !sameTables(r.Compactions[1].Output, r.Diff.Created) {
		return errors.New("compaction events disagree with actual SST inventory delta")
	}
	if r.PickerPlan == nil || r.PickerPlan.InputBytes != r.Diff.RetiredBytes || len(r.PickerPlan.InputFiles) != r.Diff.RetiredCount {
		return errors.New("authoritative picker inputs disagree with retired SSTs")
	}
	names := make([]string, len(r.Diff.Retired))
	for i, entry := range r.Diff.Retired {
		names[i] = entry.Name
	}
	sort.Strings(names)
	if strings.Join(names, "\n") != strings.Join(r.PickerPlan.InputFiles, "\n") {
		return errors.New("retired SST set differs from authoritative picker")
	}
	return nil
}
