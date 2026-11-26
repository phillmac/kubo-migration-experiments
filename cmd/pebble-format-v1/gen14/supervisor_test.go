package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/vfs"
)

// The test-only subprocess can target seeded disk fixtures. The shipped
// executable only accepts the fixed scoped clone and authenticated root peer.
func TestGeneration14SocketChild(t *testing.T) {
	dir := os.Getenv("RHEA_GEN14_FIXTURE_DB")
	if dir == "" {
		t.Skip("supervisor child only")
	}
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := serveBatch(conn, vfs.Default, dir); err != nil {
		t.Fatal(err)
	}
}

func TestGeneration14PythonSupervisor(t *testing.T) {
	for _, mode := range []string{"complete", "revoke-second", "stale-request", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			dir, req, _ := seedDisk(t)
			plan, err := prepareBatch(vfs.Default, dir)
			if err != nil || !equalState(req.Before, plan.Request.Before) ||
				req.InitialPlanSHA256 != plan.Request.InitialPlanSHA256 {
				t.Fatalf("picker mismatch: %+v %v", plan, err)
			}
			if mode == "stale-request" {
				plan.Request.InitialPlanSHA256 = strings.Repeat("0", 64)
			}
			data, err := json.Marshal(plan.Request)
			if err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(t.TempDir(), "records")
			if err := os.Mkdir(journal, 0700); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-B", os.Getenv("RHEA_GEN14_DRIVER"), mode, binary, dir, journal, string(data))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("supervisor fixture: %v %s", err, out)
			}
			after, _ := inspectDisk(t, dir)
			want := map[string]int{"complete": 0, "revoke-second": 1, "stale-request": 2, "disconnect": 1}
			if after.Marked != want[mode] {
				t.Fatalf("reopened fixture has %d marked, wanted %d", after.Marked, want[mode])
			}
			t.Log(strings.TrimSpace(string(out)))
		})
	}
}

func TestGeneration14WriterMountBinding(t *testing.T) {
	row := "43 20 0:4 / " + writerDB + " rw,nodev - fuse.rclone iam_writer{abc}:rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds rw"
	if err := workerMount(row, 43); err != nil {
		t.Fatal(err)
	}
	for _, altered := range []string{
		strings.Replace(row, "iam_writer", "wasabi-ca-central-1", 1),
		strings.Replace(row, "39037c6f01", "other", 1),
		strings.Replace(row, " rw,nodev", " ro,nodev", 1),
		strings.Replace(row, " / "+writerDB, " /subtree "+writerDB, 1),
		row + "\n45 43 0:5 / " + writerDB + "/CURRENT rw - tmpfs tmpfs rw",
	} {
		if workerMount(altered, 43) == nil {
			t.Fatalf("unexpectedly accepted %s", altered)
		}
	}
	if workerMount(row, 42) == nil {
		t.Fatal("accepted stale mount")
	}
}
