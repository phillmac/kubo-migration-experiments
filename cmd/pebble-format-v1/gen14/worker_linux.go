package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/pebble/vfs"
	"golang.org/x/sys/unix"
)

const writerDB = "/mnt/rhea-pebble-lab-writable-20261102/pebbleds"
const maxFrame = 1 << 20

var writerSource = regexp.MustCompile(`^iam_writer(\{[A-Za-z0-9_-]+\})?:rhea-pebble-lab-20261101-39037c6f01/rhea/pebbleds/?$`)

type controlLink struct {
	conn    net.Conn
	in      *bufio.Reader
	mu      sync.Mutex
	seq     uint64
	failed  bool
	revoked bool
}

type event struct {
	Seq   uint64      `json:"seq"`
	Kind  string      `json:"kind"`
	Name  string      `json:"name,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

type reply struct {
	Seq     uint64        `json:"seq"`
	Allow   bool          `json:"allow"`
	Request *batchRequest `json:"request,omitempty"`
}

func (c *controlLink) exchange(kind, name string, value interface{}) (reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ack reply
	if c.failed || (kind == "check" && c.revoked) {
		return ack, errors.New("controller connection revoked")
	}
	// Once any acknowledgement is uncertain no operation is repeated.
	c.failed = true
	c.seq++
	if err := c.conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return ack, err
	}
	data, err := json.Marshal(event{c.seq, kind, name, value})
	if err != nil || len(data)+1 > maxFrame {
		return ack, errors.New("invalid controller event")
	}
	if _, err := io.Copy(c.conn, bytes.NewReader(append(data, '\n'))); err != nil {
		return ack, err
	}
	line, err := c.in.ReadSlice('\n')
	if err != nil {
		return ack, err
	}
	if err := json.Unmarshal(line, &ack); err != nil || ack.Seq != c.seq ||
		(kind == "ready" && ack.Allow) != (ack.Request != nil) {
		return ack, errors.New("controller refused or returned an invalid acknowledgement")
	}
	c.failed = false
	if !ack.Allow {
		c.revoked = true
		return ack, errors.New("controller revoked batch")
	}
	return ack, nil
}

func (c *controlLink) put(name string, value interface{}) error {
	_, err := c.exchange("record", name, value)
	return err
}

func (c *controlLink) monitor(n uint64) error {
	_, err := c.exchange("check", "", n)
	return err
}

func serveBatch(conn net.Conn, fs vfs.FS, dir string) error {
	link := &controlLink{conn: conn, in: bufio.NewReaderSize(conn, 8192)}
	ack, err := link.exchange("ready", "", nil)
	if err != nil {
		return err
	}
	if ack.Request.Units != 2 {
		return errors.New("generation 14 requires a two-unit request")
	}
	report, err := runBatch(fs, dir, *ack.Request, link, link.monitor)
	_, finish := link.exchange("finished", "", report)
	return errors.Join(err, finish)
}

func workerMount(rows string, id uint64) error {
	active := false
	for _, raw := range strings.Split(rows, "\n") {
		left, right, ok := strings.Cut(raw, " - ")
		fields, fs := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 6 || len(fs) < 3 {
			continue
		}
		if strings.HasPrefix(fields[4], writerDB+"/") {
			return errors.New("unexpected writer submount")
		}
		if fields[0] != strconv.FormatUint(id, 10) {
			continue
		}
		if active || fields[3] != "/" || fields[4] != writerDB || fs[0] != "fuse.rclone" ||
			!writerSource.MatchString(fs[1]) || !strings.Contains(","+fields[5]+",", ",rw,") {
			return errors.New("unexpected active writer mount")
		}
		active = true
	}
	if !active {
		return errors.New("scoped writer mount unavailable")
	}
	return nil
}

func worker(inspectOnly bool) error {
	peer, err := unix.GetsockoptUcred(0, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peer.Uid != 0 || int(peer.Pid) != os.Getppid() || os.Geteuid() == 0 {
		return errors.New("dedicated unprivileged child of the root controller required")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, field := range []string{"CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1"} {
		if !strings.Contains("\n"+string(status), "\n"+field+"\n") {
			return errors.New("writer sandbox privileges differ")
		}
	}
	path, err := filepath.EvalSymlinks(writerDB)
	if err != nil || path != writerDB {
		return errors.New("invalid scoped clone directory")
	}
	var sx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, writerDB, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &sx); err != nil {
		return err
	}
	rows, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || sx.Mask&unix.STATX_MNT_ID == 0 {
		return errors.New("cannot identify active mount")
	}
	if err := workerMount(string(rows), sx.Mnt_id); err != nil {
		return err
	}
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		return fmt.Errorf("controller socket: %w", err)
	}
	defer conn.Close()
	fs, err := stagedWorkerFS()
	if err != nil {
		return err
	}
	if inspectOnly {
		report, err := inspectClosed(fs, writerDB)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	return serveBatch(conn, fs, writerDB)
}
