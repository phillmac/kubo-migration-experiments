// The generation-14 controller obtains its initial request from the same
// Pebble picker and inventory code used when the writer rechecks admission.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const labMount = "/mnt/rhea-pebble-lab-reader-20261102"
const labDB = labMount + "/pebbleds"

func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "worker" || os.Args[1] == "inspect-staged") {
		return worker(os.Args[1] == "inspect-staged")
	}
	if len(os.Args) != 2 || (os.Args[1] != "plan" && os.Args[1] != "inspect") {
		return errors.New("usage: rhea-gen14 plan | inspect | inspect-staged | worker")
	}
	path, err := filepath.EvalSymlinks(labDB)
	if err != nil || path != labDB {
		return errors.New("clone reader path is absent or indirect")
	}
	fs, _, err := inspectionFS(labDB, true)
	if err != nil {
		return err
	}
	if os.Args[1] == "inspect" {
		report, err := inspectClosed(fs, labDB)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	result, err := prepareBatch(fs, labDB)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
