package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cockroachdb/pebble/vfs"
	"golang.org/x/sys/unix"
)

var cloneSource = regexp.MustCompile(`^rhea_pebble_lab_reader(\{[A-Za-z0-9_-]+\})?:rhea-pebble-lab-20261101-39037c6f01/rhea$`)

// Pebble v1 normally creates/truncates LOCK even with Options.ReadOnly.
// An OFD read lock on the existing inode conflicts with Pebble's POSIX write
// lock and stays held until this specific file description is closed.
type readOnlyLockFS struct {
	vfs.FS
	lockPath string
}

func (fs readOnlyLockFS) Lock(name string) (io.Closer, error) {
	if name != fs.lockPath {
		return nil, errors.New("unexpected Pebble lock path")
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("Pebble LOCK is not a regular file")
	}
	if err == nil {
		lock := unix.Flock_t{Type: unix.F_RDLCK, Whence: io.SeekStart}
		err = unix.FcntlFlock(file.Fd(), unix.F_OFD_SETLK, &lock)
	}
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("lock existing Pebble LOCK for reading: %w", err)
	}
	return file, nil
}

func verifyCloneMount(mountinfo string, mountID uint64) error {
	want := strconv.FormatUint(mountID, 10)
	found := false
	for _, line := range strings.Split(mountinfo, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		fields, fs := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 6 || len(fs) < 3 {
			continue
		}
		if strings.HasPrefix(fields[4], labMount+"/") {
			return errors.New("unexpected submount in the clone reader")
		}
		if fields[0] == want {
			if found || fields[3] != "/" || fields[4] != labMount ||
				fs[0] != "fuse.rclone" || !cloneSource.MatchString(fs[1]) ||
				!strings.Contains(","+fields[5]+",", ",ro,") {
				return errors.New("active mount does not identify the read-only clone")
			}
			found = true
		}
	}
	if !found {
		return errors.New("active clone mount ID missing")
	}
	return nil
}

func inspectionFS(path string, requireRO bool) (vfs.FS, bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return nil, false, err
	}
	if st.Flags&unix.ST_RDONLY == 0 {
		if requireRO {
			return nil, false, errors.New("kernel mount is writable")
		}
		return vfs.Default, false, nil
	}
	var sx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &sx); err != nil {
		return nil, false, err
	}
	if sx.Mask&unix.STATX_MNT_ID == 0 {
		return nil, false, errors.New("kernel did not return a mount ID")
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, false, err
	}
	if err := verifyCloneMount(string(data), sx.Mnt_id); err != nil {
		return nil, false, err
	}
	return readOnlyLockFS{FS: vfs.Default, lockPath: filepath.Join(path, "LOCK")}, true, nil
}
