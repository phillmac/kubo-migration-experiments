// Command realstep performs one explicitly selected operation on the fixed
// disposable full clone. It never starts Kubo or exposes format 14. Build only
// against the reviewed, additive exact-version Pebble picker adapter.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

type stage struct {
	from string
	to   pebble.FormatMajorVersion
}

// Format 6 marks split-user-key units; format 7 can perform a blocking rewrite.
// Keep that boundary explicit and refuse format 7 unless no marked work remains.
// Format 10 marks legacy table formats; stop at 13 for one manual rewrite.
var preliminary = map[string]stage{
	"ratchet6":  {from: "003", to: 6},
	"ratchet7":  {from: "006", to: 7},
	"ratchet10": {from: "007", to: 10},
	"ratchet13": {from: "010", to: 13},
}

type arguments struct {
	action    string
	format    string
	marked    int
	inventory string
	plan      string
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func parseArgs(argv []string) (arguments, error) {
	a := arguments{marked: -1}
	if len(argv) < 1 {
		return a, errors.New("usage: realstep inspect|plan|ratchet6|ratchet7|ratchet10|ratchet13|step [expected-state flags]")
	}
	a.action = argv[0]
	_, ratchet := preliminary[a.action]
	if !ratchet && a.action != "inspect" && a.action != "plan" && a.action != "step" {
		return a, errors.New("unknown or forbidden action")
	}
	f := flag.NewFlagSet("realstep", flag.ContinueOnError)
	f.StringVar(&a.format, "expected-format", "", "certified three-digit format before mutation")
	f.IntVar(&a.marked, "expected-marked", -1, "certified marked-file count before mutation")
	f.StringVar(&a.inventory, "expected-inventory-sha256", "", "certified exact SST inventory digest")
	f.StringVar(&a.plan, "expected-plan-sha256", "", "read-only picker plan required by step")
	if err := f.Parse(argv[1:]); err != nil {
		return a, err
	}
	if f.NArg() != 0 {
		return a, errors.New("unexpected positional arguments")
	}
	if ratchet || a.action == "step" {
		if !regexp.MustCompile(`^0[0-1][0-9]$`).MatchString(a.format) || a.marked < 0 || !shaPattern.MatchString(a.inventory) {
			return a, errors.New("all mutations require expected-format, expected-marked and expected-inventory-sha256")
		}
	} else if a.format != "" || a.marked != -1 || a.inventory != "" || a.plan != "" {
		return a, errors.New("read-only actions do not accept mutation expectation flags")
	}
	if a.action == "step" && !shaPattern.MatchString(a.plan) {
		return a, errors.New("step requires expected-plan-sha256")
	}
	if a.action != "step" && a.plan != "" {
		return a, errors.New("expected-plan-sha256 applies only to step")
	}
	return a, nil
}

func matchesExpected(a arguments, s state) error {
	if s.Format != a.format || s.Marked != a.marked || s.InventorySHA256 != a.inventory {
		return errors.New("database state differs from explicit certified expectation")
	}
	if st, ok := preliminary[a.action]; ok {
		if s.Format != st.from {
			return errors.New("preliminary stage must start at its explicit preceding format")
		}
		if (a.action == "ratchet6" || a.action == "ratchet7" || a.action == "ratchet10") && s.Marked != 0 {
			return errors.New("preliminary stage would cross an uncompleted marked-file migration")
		}
	}
	if a.action == "step" && (s.Format != "013" || s.Marked <= 0) {
		return errors.New("single rewrite requires format 013 with marked files")
	}
	return nil
}

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

func run(a arguments) (r report, err error) {
	started := time.Now()
	r = report{Action: a.action, ExpectedPlanSHA256: a.plan, Compactions: []compactionEvent{}, Diff: tableDiff{Created: []table{}, Retired: []table{}}}
	fs := newBudgetFS(vfs.Default, labDB, a.action == "step", cacheReserve)
	defer func() {
		r.IO = fs.report()
		r.Seconds = time.Since(started).Seconds()
		if err != nil {
			r.Error = err.Error()
		}
	}()
	if err = hostGate(); err != nil {
		return
	}

	// Every mutation first checks the certified state through a read-only open.
	// A later writable open may create metadata even if its own recheck refuses.
	ro, openErr := pebble.Open(labDB, options(fs, true, nil))
	if openErr != nil {
		err = openErr
		return
	}
	before, stateErr := readState(ro)
	r.states(before, before)
	if stateErr == nil && a.action == "plan" {
		if before.Format != "013" || before.Marked <= 0 {
			stateErr = errors.New("picker plan requires format 013 with marked files")
		} else {
			var candidate pebble.LabRewritePlan
			candidate, stateErr = ro.LabPlanOneMarkedFile(maxInputBytes)
			if stateErr == nil {
				p := bindPlan(before, candidate)
				r.PickerPlan = &p
			}
		}
	}
	closeErr := ro.Close()
	if stateErr != nil {
		err = stateErr
		return
	}
	if closeErr != nil {
		err = closeErr
		return
	}
	if a.action == "inspect" || a.action == "plan" {
		return
	}
	if err = matchesExpected(a, before); err != nil {
		return
	}

	var mu sync.Mutex
	events := []compactionEvent{}
	listener := &pebble.EventListener{
		CompactionBegin: func(info pebble.CompactionInfo) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, compactionEvent{Type: "begin", Job: info.JobID, Reason: info.Reason})
		},
		CompactionEnd: func(info pebble.CompactionInfo) {
			event := compactionEvent{Type: "end", Job: info.JobID, Reason: info.Reason, Input: []table{}, Output: []table{}, Milliseconds: info.Duration.Milliseconds()}
			if info.Err != nil {
				event.Error = info.Err.Error()
			}
			for _, level := range info.Input {
				for _, entry := range level.Tables {
					event.Input = append(event.Input, table{Name: entry.FileNum.String() + ".sst", Number: uint64(entry.FileNum), Size: entry.Size, Level: level.Level})
				}
			}
			for _, entry := range info.Output.Tables {
				event.Output = append(event.Output, table{Name: entry.FileNum.String() + ".sst", Number: uint64(entry.FileNum), Size: entry.Size, Level: info.Output.Level})
			}
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		},
	}
	db, openErr := pebble.Open(labDB, options(fs, false, listener))
	if openErr != nil {
		err = openErr
		return
	}
	current, stateErr := readState(db)
	if stateErr == nil {
		stateErr = matchesExpected(a, current)
	}
	if stateErr == nil {
		if st, ok := preliminary[a.action]; ok {
			stateErr = db.RatchetFormatMajorVersion(st.to)
		} else {
			candidate, planErr := db.LabPlanOneMarkedFile(maxInputBytes)
			if planErr != nil {
				stateErr = planErr
			} else {
				plan := bindPlan(current, candidate)
				r.PickerPlan = &plan
				if plan.PlanSHA256 != a.plan {
					stateErr = errors.New("authoritative picker plan changed before rewrite")
				} else {
					_, stateErr = db.LabRewriteOneMarkedFile(maxInputBytes, candidate.PlanSHA256)
				}
			}
		}
	}
	after, afterErr := readState(db)
	closeErr = db.Close()
	mu.Lock()
	r.Compactions = append(r.Compactions, events...)
	mu.Unlock()
	r.states(before, after)
	diff, diffErr := difference(before.Tables, after.Tables)
	r.Diff = diff
	for _, candidateErr := range []error{stateErr, afterErr, closeErr, diffErr} {
		if candidateErr != nil {
			err = candidateErr
			return
		}
	}
	err = validateResult(a, r)
	return
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

func validateResult(a arguments, r report) error {
	if st, ok := preliminary[a.action]; ok {
		if r.AfterFormat != st.to.String() || r.InventoryBefore != r.InventoryAfter || r.Diff.CreatedCount != 0 || r.Diff.RetiredCount != 0 || len(r.Compactions) != 0 {
			return errors.New("preliminary metadata stage unexpectedly changed SSTs or ran compaction")
		}
		if a.action == "ratchet7" && r.MarkedAfter != 0 {
			return errors.New("format7 left marked migration work")
		}
		if a.action == "ratchet13" && r.MarkedAfter != r.MarkedBefore {
			return errors.New("format13 unexpectedly changed the marked-file count")
		}
		return nil
	}
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

func main() {
	args, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := run(args)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
