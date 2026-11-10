//go:build ignore

// Source-only artifact. The offline builder removes the build constraint in
// its temporary assembly. This command has NO writable entrypoint.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const pilotABI = "rhea-pilot-offline-abi-v1"

// These describe the eventual admission scope, never configurable paths.
const cloneDB = "/mnt/rhea-pebble-lab-writable-20261102/pebbleds"
const rootEvidence = "/root/.local/share/rhea-multi-sst-controller-v2"

func abiReport() map[string]interface{} {
	return map[string]interface{}{
		"schema": pilotABI, "deployable": false, "writer_schema": batchSchema,
		"request_fields": []string{"maximum_units", "before", "initial_plan_sha256"},
		"maximum_units": 2, "format": "013",
		"limits": map[string]uint64{"max_input_bytes": maxInputBytes,
			"max_sst_write_bytes": maxSSTWriteBytes, "max_metadata_write_bytes": maxMetadataWriteBytes,
			"min_cache_free_bytes": minCacheFreeBytes, "max_cache_bytes": 96 << 30},
		"future_fixed_db": cloneDB, "future_fixed_evidence_root": rootEvidence,
		"live_gate": "unimplemented-unconditionally-refused",
	}
}

func pilotCLI(args []string, out, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--abi" {
		if err := json.NewEncoder(out).Encode(abiReport()); err != nil {
			return 2
		}
		return 0
	}
	fmt.Fprintln(stderr, "NON-DEPLOYABLE / OFFLINE ONLY: signed root admission and continuous host monitor are not implemented; no writable command is exposed")
	return 2
}

func main() { os.Exit(pilotCLI(os.Args[1:], os.Stdout, os.Stderr)) }
