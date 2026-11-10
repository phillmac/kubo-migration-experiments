package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/cockroachdb/pebble"
)

type table struct {
	Name   string `json:"name"`
	Number uint64 `json:"number"`
	Size   uint64 `json:"size"`
	Level  int    `json:"level"`
}

type state struct {
	Format          string  `json:"format"`
	Marked          int     `json:"marked"`
	Files           int     `json:"files"`
	Bytes           uint64  `json:"bytes"`
	InventorySHA256 string  `json:"inventory_sha256"`
	Tables          []table `json:"-"`
}

type tableDiff struct {
	Created      []table `json:"created"`
	Retired      []table `json:"retired"`
	CreatedBytes uint64  `json:"created_bytes"`
	RetiredBytes uint64  `json:"retired_bytes"`
	CreatedCount int     `json:"created_count"`
	RetiredCount int     `json:"retired_count"`
}

func inventoryDigest(entries []table) (string, error) {
	ordered := append([]table(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Number < ordered[j].Number })
	h := sha256.New()
	for i, entry := range ordered {
		if i > 0 && ordered[i-1].Number == entry.Number {
			return "", errors.New("duplicate referenced SST file number")
		}
		fmt.Fprintf(h, "%d\t%d\n", entry.Number, entry.Size)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readState(db *pebble.DB) (state, error) {
	out := state{Format: db.FormatMajorVersion().String(), Marked: db.Metrics().Compact.MarkedFiles, Tables: []table{}}
	levels, err := db.SSTables()
	if err != nil {
		return out, err
	}
	for level, entries := range levels {
		for _, entry := range entries {
			out.Tables = append(out.Tables, table{Name: entry.FileNum.String() + ".sst", Number: uint64(entry.FileNum), Size: entry.Size, Level: level})
			out.Bytes += entry.Size
		}
	}
	sort.Slice(out.Tables, func(i, j int) bool { return out.Tables[i].Number < out.Tables[j].Number })
	out.Files = len(out.Tables)
	out.InventorySHA256, err = inventoryDigest(out.Tables)
	return out, err
}

func difference(before, after []table) (tableDiff, error) {
	out := tableDiff{Created: []table{}, Retired: []table{}}
	a, b := map[uint64]table{}, map[uint64]table{}
	for _, entry := range before {
		a[entry.Number] = entry
	}
	for _, entry := range after {
		b[entry.Number] = entry
	}
	for number, entry := range a {
		if other, ok := b[number]; !ok {
			out.Retired = append(out.Retired, entry)
			out.RetiredBytes += entry.Size
		} else if other.Size != entry.Size || other.Name != entry.Name {
			return out, errors.New("existing immutable SST identity changed")
		}
	}
	for number, entry := range b {
		if _, ok := a[number]; !ok {
			out.Created = append(out.Created, entry)
			out.CreatedBytes += entry.Size
		}
	}
	sort.Slice(out.Created, func(i, j int) bool { return out.Created[i].Number < out.Created[j].Number })
	sort.Slice(out.Retired, func(i, j int) bool { return out.Retired[i].Number < out.Retired[j].Number })
	out.CreatedCount = len(out.Created)
	out.RetiredCount = len(out.Retired)
	return out, nil
}

type compactionEvent struct {
	Type         string  `json:"type"`
	Job          int     `json:"job"`
	Reason       string  `json:"reason"`
	Input        []table `json:"input,omitempty"`
	Output       []table `json:"output,omitempty"`
	Error        string  `json:"error"`
	Milliseconds int64   `json:"milliseconds,omitempty"`
}

type report struct {
	Action             string            `json:"action"`
	BeforeFormat       string            `json:"before_format"`
	AfterFormat        string            `json:"after_format"`
	MarkedBefore       int               `json:"marked_before"`
	MarkedAfter        int               `json:"marked_after"`
	SSTFilesBefore     int               `json:"sst_files_before"`
	SSTFilesAfter      int               `json:"sst_files_after"`
	SSTBytesBefore     uint64            `json:"sst_bytes_before"`
	SSTBytesAfter      uint64            `json:"sst_bytes_after"`
	InventoryBefore    string            `json:"sst_inventory_sha256_before"`
	InventoryAfter     string            `json:"sst_inventory_sha256_after"`
	Diff               tableDiff         `json:"sst_diff"`
	Compactions        []compactionEvent `json:"compactions"`
	PickerPlan         *pickerPlan       `json:"picker_plan,omitempty"`
	ExpectedPlanSHA256 string            `json:"expected_plan_sha256,omitempty"`
	IO                 ioReport          `json:"io"`
	Seconds            float64           `json:"seconds"`
	Error              string            `json:"error,omitempty"`
}

func (r *report) states(before, after state) {
	r.BeforeFormat = before.Format
	r.AfterFormat = after.Format
	r.MarkedBefore = before.Marked
	r.MarkedAfter = after.Marked
	r.SSTFilesBefore = before.Files
	r.SSTFilesAfter = after.Files
	r.SSTBytesBefore = before.Bytes
	r.SSTBytesAfter = after.Bytes
	r.InventoryBefore = before.InventorySHA256
	r.InventoryAfter = after.InventorySHA256
}
