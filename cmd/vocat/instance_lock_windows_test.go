//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsServerInstanceLockRejectsSecondProcess(t *testing.T) {
	first, err := lockServerInstance(filepath.Join(t.TempDir(), "vocat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := lockServerInstance(filepath.Join(t.TempDir(), "other.db"))
	if second != nil {
		second.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "already controls this host") {
		t.Fatalf("second lock error = %v", err)
	}
}
