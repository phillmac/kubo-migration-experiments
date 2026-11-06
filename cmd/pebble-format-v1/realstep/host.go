package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	labMount   = "/mnt/rhea-pebble-lab-writable-20261102"
	labDB      = labMount + "/pebbleds"
	labCache   = "/data/rhea-pebble-lab-real-cache-20261102"
	budgetStop = "/run/rhea-wasabi-lab/full-clone-step-budget-stop"
)

var exactRemote = regexp.MustCompile(`^rhea_pebble_lab(?:\{[A-Za-z0-9_-]+\})?:rhea-pebble-lab-20261101-39037c6f01/rhea$`)

func monitorAllowsIO() error {
	if _, err := os.Lstat(budgetStop); err == nil {
		return errors.New("controller budget-stop sentinel present; interrupted generation requires reconciliation")
	} else if !os.IsNotExist(err) {
		return errors.New("cannot establish absence of controller budget-stop sentinel")
	}
	return nil
}

func cacheReserve(extra uint64) error {
	if err := monitorAllowsIO(); err != nil {
		return err
	}
	var info syscall.Statfs_t
	if err := syscall.Statfs(labCache, &info); err != nil {
		return errors.New("cannot read actual cache-filesystem free space")
	}
	if info.Bsize <= 0 {
		return errors.New("invalid cache-filesystem block size")
	}
	free := info.Bavail * uint64(info.Bsize)
	if free < minCacheFreeBytes || extra > free-minCacheFreeBytes {
		return fmt.Errorf("cache filesystem lacks %d-byte free reserve plus pending I/O", minCacheFreeBytes)
	}
	return nil
}

func serviceValue(name, property string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", name, "--property="+property, "--value").Output()
	if err != nil {
		return "", errors.New("required service-state observation failed")
	}
	return strings.TrimSpace(string(out)), nil
}

// The Python controller additionally verifies the complete root-owned unit,
// Unix RC peer, IAM scope, admission journal, cloud checkpoint and open users.
// These independent command-level checks never start or stop a service.
func hostGate() error {
	if os.Geteuid() != 0 {
		return errors.New("root required for fixed full-clone operation")
	}
	host, err := os.Hostname()
	if err != nil || strings.ToLower(strings.Split(host, ".")[0]) != "rhea" {
		return errors.New("Rhea host required")
	}
	for _, unit := range []string{"rhea-ipfs-wasabi-kubo.service", "rhea-broken-pin-walk-20261026.service", "rhea-pebble-lab-reader-fast-mount-20261102.service"} {
		value, err := serviceValue(unit, "ActiveState")
		if err != nil || value != "inactive" {
			return errors.New("production Kubo/walker and lab reader must remain inactive")
		}
	}
	for _, unit := range []string{"rhea-ipfs-wasabi-rclone-mount.service", "rhea-pebble-lab-full-clone-20261102.service"} {
		value, err := serviceValue(unit, "ActiveState")
		if err != nil || value != "active" {
			return errors.New("required production/lab rclone service is not active")
		}
	}
	for _, path := range []string{labMount, labDB, labCache} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fixed lab path is not a real directory")
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return errors.New("fixed lab path contains symlink")
		}
	}
	body, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	matches := 0
	for _, line := range strings.Split(string(body), "\n") {
		pair := strings.SplitN(line, " - ", 2)
		if len(pair) != 2 {
			continue
		}
		left, right := strings.Fields(pair[0]), strings.Fields(pair[1])
		if len(left) < 6 || len(right) < 2 || left[4] != labMount {
			continue
		}
		if left[3] != "/" || right[0] != "fuse.rclone" || !exactRemote.MatchString(right[1]) {
			return errors.New("fixed lab FUSE source does not match exact disposable prefix")
		}
		rw := false
		for _, option := range strings.Split(left[5], ",") {
			if option == "rw" {
				rw = true
			}
		}
		if !rw {
			return errors.New("lab mount is not writable")
		}
		matches++
	}
	if matches != 1 {
		return errors.New("exactly one host-visible full-clone FUSE mount required")
	}
	return cacheReserve(0)
}
