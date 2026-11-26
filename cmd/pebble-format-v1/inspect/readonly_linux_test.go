package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble/vfs"
	"golang.org/x/sys/unix"
)

func TestReaderConflictsWithPebblePOSIXWriterWithoutChangingLOCK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LOCK")
	fs := readOnlyLockFS{FS: vfs.Default, lockPath: path}
	if _, err := fs.Lock(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent lock: %v", err)
	}
	if err := os.WriteFile(path, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writeLock := func(kind int16) error {
		lock := unix.Flock_t{Type: kind}
		return unix.FcntlFlock(writer.Fd(), unix.F_SETLK, &lock)
	}
	reader, err := fs.Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLock(unix.F_WRLCK); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("reader did not exclude writer: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	// A separate process owns a POSIX lock in practice. Use an OFD write
	// lock here as well so closing a rejected reader FD cannot release it.
	lock := unix.Flock_t{Type: unix.F_WRLCK}
	if err := unix.FcntlFlock(writer.Fd(), unix.F_OFD_SETLK, &lock); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lock(path); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("writer did not exclude reader: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "retained" {
		t.Fatalf("LOCK changed: %q, %v", body, err)
	}
}

func TestReaderRejectsForeignWritableOrNestedMounts(t *testing.T) {
	row := "77 4 0:80 / " + labMount + " ro,nodev - fuse.rclone rhea_pebble_lab_reader{abc}:rhea-pebble-lab-20261101-39037c6f01/rhea rw"
	if err := verifyCloneMount(row, 77); err != nil {
		t.Fatal(err)
	}
	covered := "64 4 0:65 /private " + labMount + " rw - tmpfs tmpfs rw"
	if err := verifyCloneMount(covered+"\n"+row, 77); err != nil {
		t.Fatalf("rejected visible read-only clone above a private staging directory: %v", err)
	}
	if err := verifyCloneMount(covered+"\n"+row, 64); err == nil {
		t.Fatal("accepted a covered clone with a different visible mount ID")
	}
	for _, altered := range []string{
		strings.Replace(row, " ro,nodev", " rw,nodev", 1),
		strings.Replace(row, "39037c6f01", "different", 1),
		strings.Replace(row, "fuse.rclone", "ext4", 1),
		row + "\n78 77 0:81 / " + labDB + "/LOCK rw - tmpfs tmpfs rw",
	} {
		if err := verifyCloneMount(altered, 77); err == nil {
			t.Fatalf("accepted altered mount: %s", altered)
		}
	}
	if err := verifyCloneMount(row, 78); err == nil {
		t.Fatal("accepted stale mount ID")
	}
	if _, _, err := inspectionFS(t.TempDir(), true); err == nil {
		t.Fatal("accepted a writable temporary directory")
	}
}

func TestReaderRefusesSubstitutedLOCK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "LOCK")
	fs := readOnlyLockFS{FS: vfs.Default, lockPath: path}
	target := filepath.Join(dir, "other")
	if err := os.WriteFile(target, []byte("other file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lock(target); err == nil {
		t.Fatal("accepted another lock path")
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lock(path); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("accepted or followed a symlink: %v", err)
	}
}
