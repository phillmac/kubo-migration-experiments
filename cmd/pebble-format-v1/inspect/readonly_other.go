//go:build !linux

package main

import (
	"errors"

	"github.com/cockroachdb/pebble/vfs"
)

func inspectionFS(_ string, requireRO bool) (vfs.FS, bool, error) {
	if requireRO {
		return nil, false, errors.New("strict clone inspection requires Linux mount and lock verification")
	}
	return vfs.Default, false, nil
}
