//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockServerInstance(_ string) (*os.File, error) {
	// The smart-card reader, Wintun adapter and IPsec policy store are host
	// resources rather than database resources. Use one lock per Windows user
	// even when diagnostic instances point at different database paths.
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("locate Windows user cache for server instance lock: %w", err)
	}
	directory := filepath.Join(base, "VoCat")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create server instance lock directory: %w", err)
	}
	path := filepath.Join(directory, "vocat-server.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open server instance lock: %w", err)
	}
	overlapped := new(windows.Overlapped)
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	)
	if err == nil {
		return file, nil
	}
	_ = file.Close()
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return nil, errors.New("another vocat server already controls this host's modem and smart-card resources")
	}
	return nil, fmt.Errorf("lock server instance: %w", err)
}
