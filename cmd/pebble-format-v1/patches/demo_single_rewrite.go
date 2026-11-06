// Copyright 2026. Experimental disposable-lab Pebble v1.1.3 adapter.
// This file is copied into a temporary, exact-version Pebble module checkout
// for isolated fixture or guarded full-clone binaries. Never patch the installed
// production Kubo/Pebble implementation.
//
// Unlike RatchetFormatMajorVersion(14), this schedules precisely one internally
// picked marked-file rewrite and returns only when it has completed.
package pebble

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

type DemoRewritePlan struct {
	InputLevel int
	InputFiles []string
	InputBytes uint64
}

// LabRewritePlan is the authoritative marked-file picker result used by the
// fixed disposable full-clone command. PlanSHA256 describes the exact candidate;
// the command additionally binds it to format, marked count and inventory hash.
type LabRewritePlan struct {
	InputLevel  int
	OutputLevel int
	InputFiles  []string
	InputBytes  uint64
	PlanSHA256  string
}

// LabDisableTableStats suppresses the unrelated background table-stat scan
// started by writable Open even when automatic compactions are disabled. The
// marked-file rewrite picker does not need these statistics. Call before Open
// on every realstep Options value; this is an experimental, non-upstream API.
func LabDisableTableStats(opts *Options) {
	opts.private.disableTableStats = true
}

// LabPlanOneMarkedFile only inspects the existing picker. It schedules no work
// and is valid on a read-only DB. This is an experimental, non-upstream API.
func (d *DB) LabPlanOneMarkedFile(maxInputBytes uint64) (LabRewritePlan, error) {
	return d.labMarkedRewrite(maxInputBytes, "", false)
}

// LabRewriteOneMarkedFile re-picks under the original version-set locks and
// schedules exactly one unit only if its digest matches the reviewed plan.
func (d *DB) LabRewriteOneMarkedFile(maxInputBytes uint64, expectedPlanSHA256 string) (LabRewritePlan, error) {
	if len(expectedPlanSHA256) != 64 {
		return LabRewritePlan{}, errors.New("exact candidate digest required")
	}
	return d.labMarkedRewrite(maxInputBytes, expectedPlanSHA256, true)
}

func (d *DB) labMarkedRewrite(maxInputBytes uint64, expectedPlanSHA256 string, execute bool) (LabRewritePlan, error) {
	result := LabRewritePlan{InputFiles: []string{}}
	if maxInputBytes == 0 || maxInputBytes > 256*1024*1024 {
		return result, errors.New("input cap must be nonzero and at most 256 MiB")
	}
	if err := d.closed.Load(); err != nil {
		return result, err.(error)
	}
	if d.FormatMajorVersion() != 13 {
		return result, errors.New("full-clone marked rewrite requires format 13")
	}
	if execute && d.opts.ReadOnly {
		return result, errors.New("cannot rewrite a read-only DB")
	}
	d.mu.Lock()
	if !d.opts.DisableAutomaticCompactions || d.mu.compact.compactingCount != 0 || d.mu.compact.flushing || len(d.mu.compact.manual) != 0 {
		d.mu.Unlock()
		return result, errors.New("automatic compactions must be disabled; active/manual compaction or flush is forbidden")
	}
	if d.mu.versions.currentVersion().Stats.MarkedForCompaction == 0 {
		d.mu.Unlock()
		return result, errors.New("no marked files remain")
	}
	d.mu.versions.logLock()
	env := compactionEnv{
		diskAvailBytes:          d.diskAvailBytes.Load(),
		earliestSnapshotSeqNum:  d.mu.snapshots.earliest(),
		earliestUnflushedSeqNum: d.getEarliestUnflushedSeqNumLocked(),
		inProgressCompactions:   d.getInProgressCompactionInfoLocked(nil),
	}
	pc := d.mu.versions.picker.pickRewriteCompaction(env)
	d.mu.versions.logUnlock()
	if pc == nil {
		d.mu.Unlock()
		return result, errors.New("marked rewrite picker returned no compaction")
	}
	result.InputLevel = pc.startLevel.level
	result.OutputLevel = pc.outputLevel.level
	if result.InputLevel != result.OutputLevel || pc.kind != compactionKindRewrite || len(pc.inputs) != 2 || len(pc.extraLevels) != 0 || !pc.outputLevel.files.Empty() {
		d.mu.Unlock()
		return result, errors.New("marked rewrite unexpectedly crosses levels or contains unbudgeted input sets")
	}
	type entry struct {
		number uint64
		size   uint64
	}
	entries := []entry{}
	it := pc.startLevel.files.Iter()
	for f := it.First(); f != nil; f = it.Next() {
		result.InputFiles = append(result.InputFiles, f.FileNum.String())
		if f.Size > ^uint64(0)-result.InputBytes {
			d.mu.Unlock()
			return result, errors.New("candidate size overflow")
		}
		result.InputBytes += f.Size
		entries = append(entries, entry{uint64(f.FileNum), f.Size})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].number < entries[j].number })
	h := sha256.New()
	fmt.Fprintf(h, "pebble-lab-candidate-v1\ninput-level\t%d\noutput-level\t%d\n", result.InputLevel, result.OutputLevel)
	for _, f := range entries {
		fmt.Fprintf(h, "%d\t%d\n", f.number, f.size)
	}
	result.PlanSHA256 = hex.EncodeToString(h.Sum(nil))
	if result.InputBytes == 0 || result.InputBytes > maxInputBytes {
		d.mu.Unlock()
		return result, fmt.Errorf("chosen atomic unit %d bytes exceeds maximum %d", result.InputBytes, maxInputBytes)
	}
	if !execute {
		d.mu.Unlock()
		return result, nil
	}
	if result.PlanSHA256 != expectedPlanSHA256 {
		d.mu.Unlock()
		return result, errors.New("authoritative candidate changed before scheduling")
	}
	c := newCompaction(pc, d.opts, d.timeNow(), d.ObjProvider())
	d.mu.compact.compactingCount++
	d.addInProgressCompaction(c)
	done := make(chan error, 1)
	go d.compact(c, done)
	d.mu.Unlock()
	err := <-done
	d.mu.Lock()
	for d.mu.compact.compactingCount > 0 {
		d.mu.compact.cond.Wait()
	}
	d.mu.Unlock()
	return result, err
}

// DemoRewriteOneMarkedFile is intentionally NOT a supported upstream API.
// It is a code-reviewed experiment to demonstrate Pebble's own marked-file
// picker as a bounded atomic unit. It requires automatic compactions disabled.
func (d *DB) DemoRewriteOneMarkedFile(maxInputBytes uint64) (DemoRewritePlan, error) {
	result := DemoRewritePlan{}
	if maxInputBytes == 0 {
		return result, errors.New("nonzero input limit is required")
	}
	if err := d.closed.Load(); err != nil {
		return result, err.(error)
	}
	d.mu.Lock()
	if !d.opts.DisableAutomaticCompactions {
		d.mu.Unlock()
		return result, errors.New("demo requires automatic compactions disabled")
	}
	if d.mu.compact.compactingCount != 0 {
		d.mu.Unlock()
		return result, errors.New("demo requires no other compactions in progress")
	}
	if d.mu.versions.currentVersion().Stats.MarkedForCompaction == 0 {
		d.mu.Unlock()
		return result, errors.New("no marked files remain")
	}
	// Follow the same versionSet locking and environment fields used by
	// maybeScheduleCompactionPicker. Do not call that helper: it could loop.
	d.mu.versions.logLock()
	env := compactionEnv{
		diskAvailBytes:          d.diskAvailBytes.Load(),
		earliestSnapshotSeqNum:  d.mu.snapshots.earliest(),
		earliestUnflushedSeqNum: d.getEarliestUnflushedSeqNumLocked(),
		inProgressCompactions:   d.getInProgressCompactionInfoLocked(nil),
	}
	pc := d.mu.versions.picker.pickRewriteCompaction(env)
	d.mu.versions.logUnlock()
	if pc == nil {
		d.mu.Unlock()
		return result, errors.New("marked rewrite picker returned no compaction")
	}
	result.InputLevel = pc.startLevel.level
	it := pc.startLevel.files.Iter()
	for f := it.First(); f != nil; f = it.Next() {
		result.InputFiles = append(result.InputFiles, f.FileNum.String())
		result.InputBytes += f.Size
	}
	if result.InputBytes == 0 || result.InputBytes > maxInputBytes {
		d.mu.Unlock()
		return result, fmt.Errorf("chosen atomic unit %d bytes exceeds maximum %d", result.InputBytes, maxInputBytes)
	}
	// Schedule exactly one compaction using the original internal rewrite
	// picker/constructor. The standard completion path respects our disabled
	// automatic compactions option and will not chain a second rewrite.
	c := newCompaction(pc, d.opts, d.timeNow(), d.ObjProvider())
	d.mu.compact.compactingCount++
	d.addInProgressCompaction(c)
	done := make(chan error, 1)
	go d.compact(c, done)
	d.mu.Unlock()
	err := <-done
	d.mu.Lock()
	for d.mu.compact.compactingCount > 0 {
		d.mu.compact.cond.Wait()
	}
	d.mu.Unlock()
	return result, err
}
