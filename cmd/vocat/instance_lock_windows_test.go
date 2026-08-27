//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowsServerInstanceLockRejectsSecondProcess(t *testing.T) {
	name := fmt.Sprintf(`Global\VoCat.Server.Instance.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	first, err := lockWindowsServerInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := lockWindowsServerInstance(name)
	if second != nil {
		second.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "already controls this host") {
		t.Fatalf("second lock error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := lockWindowsServerInstance(name)
	if err != nil {
		t.Fatalf("reacquire released mutex: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsServerInstanceMutexUsesRestrictedGlobalNamespace(t *testing.T) {
	if !strings.HasPrefix(windowsServerInstanceMutexName, `Global\`) {
		t.Fatalf("mutex name = %q, want Global namespace", windowsServerInstanceMutexName)
	}
	sddl := windowsServerInstanceMutexSDDL("S-1-5-21-1-2-3-1001")
	for _, required := range []string{";;;SY)", ";;;BA)", ";;;LS)", ";;;NS)", ";;;S-1-5-21-1-2-3-1001)"} {
		if !strings.Contains(sddl, required) {
			t.Fatalf("security descriptor %q omits %q", sddl, required)
		}
	}
	for _, forbidden := range []string{";;;WD)", ";;;AU)"} {
		if strings.Contains(sddl, forbidden) {
			t.Fatalf("security descriptor %q grants unrelated principal %q", sddl, forbidden)
		}
	}
}
