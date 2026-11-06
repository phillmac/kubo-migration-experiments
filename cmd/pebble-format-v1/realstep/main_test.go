package main

import (
	"strings"
	"testing"
)

func TestMutationExpectationsAreMandatory(t *testing.T) {
	for _, action := range []string{"ratchet6", "ratchet7", "ratchet10", "ratchet13", "step"} {
		if _, err := parseArgs([]string{action}); err == nil {
			t.Fatalf("%s accepted missing expected state", action)
		}
	}
	if _, err := parseArgs([]string{"ratchet14"}); err == nil {
		t.Fatal("format14 is exposed")
	}
	if _, err := parseArgs([]string{"step", "--expected-format", "013", "--expected-marked", "1", "--expected-inventory-sha256", strings.Repeat("a", 64)}); err == nil {
		t.Fatal("step accepted no expected picker plan")
	}
}

func TestPreliminaryStagesDoNotSkipOrEnterBlockingMarkedWork(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, action := range []string{"ratchet6", "ratchet7", "ratchet10"} {
		st := preliminary[action]
		a := arguments{action: action, format: st.from, marked: 1, inventory: digest}
		s := state{Format: st.from, Marked: 1, InventorySHA256: digest}
		if err := matchesExpected(a, s); err == nil {
			t.Fatalf("%s accepted pending marked work", action)
		}
	}
	a := arguments{action: "ratchet13", format: "003", marked: 0, inventory: digest}
	if err := matchesExpected(a, state{Format: "003", Marked: 0, InventorySHA256: digest}); err == nil {
		t.Fatal("ratchet13 skipped preceding stages")
	}
	a = arguments{action: "ratchet13", format: "010", marked: 93697, inventory: digest}
	if err := matchesExpected(a, state{Format: "010", Marked: 93697, InventorySHA256: digest}); err != nil {
		t.Fatalf("metadata13 should preserve pending rewrite marks: %v", err)
	}
}

func TestExactSourceAndInventoryIdentity(t *testing.T) {
	for _, source := range []string{
		"rhea_pebble_lab:rhea-pebble-lab-20261101-39037c6f01/rhea",
		"rhea_pebble_lab{Dn7qA}:rhea-pebble-lab-20261101-39037c6f01/rhea",
		"rhea_pebble_lab{_9Ic9}:rhea-pebble-lab-20261101-39037c6f01/rhea",
	} {
		if !exactRemote.MatchString(source) {
			t.Fatalf("valid exact lab source refused: %s", source)
		}
	}
	for _, source := range []string{
		"rhea_pebble_lab:ipfs-remote-mount/rhea",
		"rhea_pebble_lab:rhea-pebble-lab-20261101-39037c6f01/rhea-extra",
		"evil_rhea_pebble_lab:rhea-pebble-lab-20261101-39037c6f01/rhea",
		"rhea_pebble_lab{../}:rhea-pebble-lab-20261101-39037c6f01/rhea",
	} {
		if exactRemote.MatchString(source) {
			t.Fatalf("substituted source accepted: %s", source)
		}
	}
	before := []table{{Name: "000001.sst", Number: 1, Size: 40}, {Name: "000002.sst", Number: 2, Size: 60}}
	after := []table{{Name: "000001.sst", Number: 1, Size: 41}, {Name: "000002.sst", Number: 2, Size: 59}}
	if _, err := difference(before, after); err == nil {
		t.Fatal("same-total immutable object mutation accepted")
	}
}

func TestSuccessfulStepMustBeExactlyOneMatchingRewrite(t *testing.T) {
	old := table{Name: "000001.sst", Number: 1, Size: 40, Level: 6}
	fresh := table{Name: "000002.sst", Number: 2, Size: 39, Level: 6}
	r := report{AfterFormat: "013", MarkedBefore: 2, MarkedAfter: 1,
		Diff:        tableDiff{Created: []table{fresh}, Retired: []table{old}, CreatedCount: 1, RetiredCount: 1, CreatedBytes: 39, RetiredBytes: 40},
		PickerPlan:  &pickerPlan{InputBytes: 40, InputFiles: []string{"000001.sst"}},
		Compactions: []compactionEvent{{Type: "begin", Job: 3, Reason: "rewrite"}, {Type: "end", Job: 3, Reason: "rewrite", Input: []table{old}, Output: []table{fresh}}}}
	if err := validateResult(arguments{action: "step"}, r); err != nil {
		t.Fatal(err)
	}
	r.Compactions = append(r.Compactions, compactionEvent{Type: "begin", Job: 4, Reason: "rewrite"})
	if err := validateResult(arguments{action: "step"}, r); err == nil {
		t.Fatal("chained second compaction accepted")
	}
}
