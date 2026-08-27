//go:build linux

package ims

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunIPCommandExplainsMissingKernelXFRM(t *testing.T) {
	directory := t.TempDir()
	command := directory + "/ip"
	script := "#!/bin/sh\necho 'Cannot open netlink socket: Protocol not supported' >&2\nexit 1\n"
	if err := os.WriteFile(command, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runIPCommand(context.Background(), command, xfrmOperation{description: "test state"})
	if err == nil || !strings.Contains(err.Error(), "kmod-ipsec") || !strings.Contains(err.Error(), "CONFIG_XFRM_USER") {
		t.Fatalf("error = %v", err)
	}
}

func TestLinuxIPSecCloseRetriesUntilDeletesAreConfirmedAbsent(t *testing.T) {
	directory := t.TempDir()
	command := directory + "/ip"
	countFile := directory + "/count"
	script := "#!/bin/sh\n" +
		"count_file=" + strconv.Quote(countFile) + "\n" +
		"count=0\n" +
		"[ ! -f \"$count_file\" ] || count=$(cat \"$count_file\")\n" +
		"count=$((count + 1))\n" +
		"printf '%s\\n' \"$count\" > \"$count_file\"\n" +
		"if [ \"$count\" -eq 1 ]; then\n" +
		"  echo 'injected transient XFRM delete failure' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"echo 'RTNETLINK answers: No such file or directory' >&2\n" +
		"exit 2\n"
	if err := os.WriteFile(command, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	cleanup := buildXFRMCleanupPlan(testIPSecSAConfig())
	handle := &linuxIPSecHandle{
		ipCommand: command,
		cleanup:   append([]xfrmOperation(nil), cleanup...),
	}
	if err := handle.Close(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "injected transient") {
		t.Fatalf("first Close() error = %v, want injected transient failure", err)
	}
	if handle.closed || len(handle.cleanup) != len(cleanup) {
		t.Fatalf(
			"failed Close state: closed=%v pending=%d, want pending=%d",
			handle.closed,
			len(handle.cleanup),
			len(cleanup),
		)
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() with confirmed-absent objects: %v", err)
	}
	if !handle.closed || len(handle.cleanup) != 0 {
		t.Fatalf("completed Close state: closed=%v pending=%d", handle.closed, len(handle.cleanup))
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close(): %v", err)
	}
	wantCalls := 1 + len(cleanup)
	count, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(count)); got != strconv.Itoa(wantCalls) {
		t.Fatalf("ip command calls = %s, want %d", got, wantCalls)
	}
}

func TestLinuxIPSecPartialInstallRollsBackOnlyOwnedObjects(t *testing.T) {
	directory := t.TempDir()
	command := directory + "/ip"
	countFile := directory + "/count"
	logFile := directory + "/operations"
	script := "#!/bin/sh\n" +
		"count_file=" + strconv.Quote(countFile) + "\n" +
		"log_file=" + strconv.Quote(logFile) + "\n" +
		"printf '%s\\n' \"$*\" >> \"$log_file\"\n" +
		"count=0\n" +
		"[ ! -f \"$count_file\" ] || count=$(cat \"$count_file\")\n" +
		"count=$((count + 1))\n" +
		"printf '%s\\n' \"$count\" > \"$count_file\"\n" +
		"if [ \"$count\" -eq 2 ]; then\n" +
		"  echo 'injected add collision' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(command, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := (linuxIPSecInstaller{ipCommand: command}).Install(
		context.Background(),
		testIPSecSAConfig(),
	)
	if !errors.Is(err, ErrIPSecInstall) {
		t.Fatalf("Install() error = %v, want ErrIPSecInstall", err)
	}
	logged, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	operations := strings.Split(strings.TrimSpace(string(logged)), "\n")
	if len(operations) != 3 {
		t.Fatalf("ip operations = %v, want two adds and one owned rollback", operations)
	}
	if !strings.Contains(operations[0], "xfrm state add") ||
		!strings.Contains(operations[0], "spi 0x20000002") {
		t.Fatalf("first install operation = %q", operations[0])
	}
	if !strings.Contains(operations[1], "xfrm state add") ||
		!strings.Contains(operations[1], "spi 0x10000002") {
		t.Fatalf("failed install operation = %q", operations[1])
	}
	if !strings.Contains(operations[2], "xfrm state delete") ||
		!strings.Contains(operations[2], "spi 0x20000002") {
		t.Fatalf("rollback operation = %q", operations[2])
	}
}

func TestLinuxIPSecInstallerLifecycle(t *testing.T) {
	if os.Getenv("VOCAT_NETNS_TEST") != "1" {
		t.Skip("set VOCAT_NETNS_TEST=1 inside an isolated Linux network namespace")
	}
	handle, err := (linuxIPSecInstaller{ipCommand: "ip"}).Install(
		context.Background(),
		testIPSecSAConfig(),
	)
	if err != nil {
		t.Fatalf("install ipsec-3gpp XFRM set: %v", err)
	}
	states, err := exec.Command("ip", "xfrm", "state").CombinedOutput()
	if err != nil {
		t.Fatalf("list XFRM states: %v: %s", err, states)
	}
	if count := strings.Count(string(states), "src 10.0.0.2 dst 10.0.0.3"); count != 2 {
		t.Fatalf("outbound XFRM state count = %d: %s", count, states)
	}
	if count := strings.Count(string(states), "src 10.0.0.3 dst 10.0.0.2"); count != 2 {
		t.Fatalf("inbound XFRM state count = %d: %s", count, states)
	}
	policies, err := exec.Command("ip", "xfrm", "policy").CombinedOutput()
	if err != nil {
		t.Fatalf("list XFRM policies: %v: %s", err, policies)
	}
	if count := strings.Count(string(policies), "sport 40666 dport 50600"); count != 2 {
		t.Fatalf("UE-client policy count = %d: %s", count, policies)
	}

	closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := handle.Close(closeContext); err != nil {
		t.Fatalf("close ipsec-3gpp XFRM set: %v", err)
	}
	states, err = exec.Command("ip", "xfrm", "state").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(states)) != "" {
		t.Fatalf("XFRM states survived Close: %s", states)
	}
	policies, err = exec.Command("ip", "xfrm", "policy").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(policies)) != "" {
		t.Fatalf("XFRM policies survived Close: %s", policies)
	}
}
