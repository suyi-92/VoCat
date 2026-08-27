//go:build linux

package ike

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateUserspaceRoutesAllowsOnlyNegotiatedEndpoints(t *testing.T) {
	t.Parallel()
	config := userspaceRouteTestConfig()
	if err := validateUserspaceRoutes(config); err != nil {
		t.Fatalf("valid negotiated route: %v", err)
	}

	config.PCSCF = []net.IP{net.IPv4(203, 0, 113, 10)}
	if err := validateUserspaceRoutes(config); err == nil {
		t.Fatal("P-CSCF outside responder selector was accepted")
	}
}

func TestValidateUserspaceRoutesRequiresMatchingAddressFamily(t *testing.T) {
	t.Parallel()
	config := userspaceRouteTestConfig()
	config.PCSCF = []net.IP{net.ParseIP("2001:db8::20")}
	config.ResponderSelectors = []trafficSelector{{
		StartPort: 0,
		EndPort:   65535,
		StartIP:   net.ParseIP("2001:db8::"),
		EndIP:     net.ParseIP("2001:db8::ffff"),
	}}
	if err := validateUserspaceRoutes(config); err == nil {
		t.Fatal("IPv6 P-CSCF without an assigned inner IPv6 address was accepted")
	}
}

func TestUserspaceRulePriorityAlwaysPrecedesMainRoute(t *testing.T) {
	t.Parallel()
	for _, spi := range []uint32{
		0,
		1,
		32767,
		0x01020304,
		0x80000000,
		0xffffffff,
	} {
		table, priority := userspaceRoutingIdentifiers(spi)
		if table <= 255 {
			t.Fatalf("SPI %08x produced reserved routing table %d", spi, table)
		}
		if priority < 10000 || priority >= 30000 || priority >= 32766 {
			t.Fatalf(
				"SPI %08x produced unsafe rule priority %d",
				spi,
				priority,
			)
		}
	}
}

func userspaceRouteTestConfig() ChildSAConfig {
	return ChildSAConfig{
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
		PCSCF:          []net.IP{net.IPv4(10, 127, 192, 82)},
		InitiatorSelectors: []trafficSelector{{
			StartPort: 0,
			EndPort:   65535,
			StartIP:   net.IPv4(10, 132, 116, 34),
			EndIP:     net.IPv4(10, 132, 116, 34),
		}},
		ResponderSelectors: []trafficSelector{{
			StartPort: 0,
			EndPort:   65535,
			StartIP:   net.IPv4(10, 0, 0, 0),
			EndIP:     net.IPv4(10, 255, 255, 255),
		}},
	}
}

func TestLinuxUserspaceCloseRetriesNetworkCleanup(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "ip.log")
	scriptPath := filepath.Join(directory, "ip")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$VOCAT_USERSPACE_TEST_LOG\"\nif [ \"$VOCAT_USERSPACE_TEST_FAIL\" = 1 ]; then\n  echo 'transient delete failure' >&2\n  exit 1\nfi\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOCAT_USERSPACE_TEST_LOG", logPath)
	t.Setenv("VOCAT_USERSPACE_TEST_FAIL", "1")
	handle := newLinuxUserspaceCleanupTestHandle(t, scriptPath)
	handle.cleanup = []ipCleanupCommand{
		{operation: "remove source rule", arguments: []string{"delete-rule"}},
		{operation: "remove unreachable route", arguments: []string{"delete-unreachable"}},
	}

	if err := handle.Close(context.Background()); err == nil {
		t.Fatal("transient network cleanup failure unexpectedly returned nil")
	}
	handle.mu.Lock()
	closed, cleaned := handle.closed, handle.networkCleaned
	handle.mu.Unlock()
	if !closed || cleaned || len(handle.cleanup) != 2 {
		t.Fatalf("failed cleanup state = closed:%v cleaned:%v cleanup:%#v", closed, cleaned, handle.cleanup)
	}
	t.Setenv("VOCAT_USERSPACE_TEST_FAIL", "0")
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close failed: %v", err)
	}
	handle.mu.Lock()
	cleaned = handle.networkCleaned
	handle.mu.Unlock()
	if !cleaned || len(handle.cleanup) != 0 {
		t.Fatalf("successful retry did not finalize cleanup: cleaned=%v cleanup=%#v", cleaned, handle.cleanup)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "delete-unreachable\ndelete-unreachable\ndelete-rule"
	if got := strings.TrimSpace(string(logData)); got != want {
		t.Fatalf("cleanup commands = %q, want %q", got, want)
	}
}

func TestLinuxUserspaceCloseAcceptsAlreadyAbsentCleanup(t *testing.T) {
	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "ip")
	script := "#!/bin/sh\necho 'RTNETLINK answers: No such process' >&2\nexit 2\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	handle := newLinuxUserspaceCleanupTestHandle(t, scriptPath)
	handle.dynamicRoutes["10.0.0.3"] = ipCleanupCommand{
		operation: "remove dynamic route",
		arguments: []string{"delete-dynamic"},
	}
	handle.cleanup = []ipCleanupCommand{
		{operation: "remove source rule", arguments: []string{"delete-rule"}},
		{operation: "remove unreachable route", arguments: []string{"delete-unreachable"}},
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("already absent cleanup failed: %v", err)
	}
	handle.mu.Lock()
	cleaned := handle.networkCleaned
	handle.mu.Unlock()
	if !cleaned || len(handle.dynamicRoutes) != 0 || len(handle.cleanup) != 0 {
		t.Fatalf("absent cleanup was retained: cleaned=%v dynamic=%#v cleanup=%#v", cleaned, handle.dynamicRoutes, handle.cleanup)
	}
}

func TestLinuxUserspaceInstallRollbackRetriesTransientCleanup(t *testing.T) {
	directory := t.TempDir()
	countPath := filepath.Join(directory, "count")
	scriptPath := filepath.Join(directory, "ip")
	script := "#!/bin/sh\n" +
		"count_file=" + strconv.Quote(countPath) + "\n" +
		"count=0\n" +
		"[ ! -f \"$count_file\" ] || count=$(cat \"$count_file\")\n" +
		"count=$((count + 1))\n" +
		"printf '%s\\n' \"$count\" > \"$count_file\"\n" +
		"if [ \"$count\" -eq 1 ]; then\n" +
		"  echo 'transient rollback failure' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	handle := newLinuxUserspaceCleanupTestHandle(t, scriptPath)
	handle.cleanup = []ipCleanupCommand{
		{operation: "remove source rule", arguments: []string{"delete-rule"}},
		{operation: "remove unreachable route", arguments: []string{"delete-unreachable"}},
	}

	if err := handle.rollbackInstall(); err != nil {
		t.Fatalf("rollbackInstall() error = %v", err)
	}
	handle.mu.Lock()
	cleaned := handle.networkCleaned
	handle.mu.Unlock()
	if !cleaned || len(handle.cleanup) != 0 {
		t.Fatalf("rollback state: cleaned=%v cleanup=%#v", cleaned, handle.cleanup)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(count)); got != "3" {
		t.Fatalf("ip command calls = %s, want 3", got)
	}
}

func TestLinuxUserspaceInstallRollbackBoundsPersistentCleanupFailure(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "ip.log")
	scriptPath := filepath.Join(directory, "ip")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$VOCAT_USERSPACE_TEST_LOG\"\necho 'persistent rollback failure' >&2\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOCAT_USERSPACE_TEST_LOG", logPath)
	handle := newLinuxUserspaceCleanupTestHandle(t, scriptPath)
	handle.cleanup = []ipCleanupCommand{
		{operation: "remove source rule", arguments: []string{"delete-rule"}},
	}

	err := handle.rollbackInstall()
	if err == nil || !strings.Contains(err.Error(), "after 3 bounded attempts") ||
		!strings.Contains(err.Error(), "persistent rollback failure") {
		t.Fatalf("rollbackInstall() error = %v", err)
	}
	handle.mu.Lock()
	cleaned := handle.networkCleaned
	handle.mu.Unlock()
	if cleaned || len(handle.cleanup) != 1 {
		t.Fatalf("failed rollback state: cleaned=%v cleanup=%#v", cleaned, handle.cleanup)
	}
	logged, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if calls := len(strings.Fields(string(logged))); calls != linuxUserspaceRollbackAttempts {
		t.Fatalf("ip command calls = %d, want %d", calls, linuxUserspaceRollbackAttempts)
	}
}

func newLinuxUserspaceCleanupTestHandle(t *testing.T, ipCommand string) *linuxUserspaceHandle {
	t.Helper()
	tun, err := os.CreateTemp(t.TempDir(), "vocat-tun-test")
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	return &linuxUserspaceHandle{
		ipCommand:     ipCommand,
		tun:           tun,
		cancel:        cancel,
		failures:      make(chan error, 1),
		dynamicRoutes: make(map[string]ipCleanupCommand),
	}
}

type blockingNATTRelay struct{}

func (blockingNATTRelay) SendESP(ctx context.Context, _ []byte) error {
	return ctx.Err()
}

func (blockingNATTRelay) ReceiveESP(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestLinuxUserspaceInstallerLifecycle(t *testing.T) {
	if os.Getenv("VOCAT_NETNS_TEST") != "1" {
		t.Skip("set VOCAT_NETNS_TEST=1 inside an isolated Linux network namespace")
	}
	config := userspaceRouteTestConfig()
	config.Name = "vocat-swu-test"
	config.InboundSPI = 0x01020304
	config.OutboundSPI = 0x05060708
	config.Encryption = "aes-cbc-128"
	config.Integrity = "hmac-sha1-96"
	config.InboundEncKey = make([]byte, 16)
	config.InboundAuthKey = make([]byte, 20)
	config.OutboundEncKey = make([]byte, 16)
	config.OutboundAuthKey = make([]byte, 20)
	config.UDPEncapsulation = true
	config.Relay = blockingNATTRelay{}

	tableID, _ := userspaceRoutingIdentifiers(config.InboundSPI)
	table := strconv.FormatUint(uint64(tableID), 10)
	if output, err := exec.Command(
		"ip", "-4", "route", "add",
		"table", table, "unreachable", "default",
	).CombinedOutput(); err != nil {
		t.Fatalf("preoccupy route table: %v: %s", err, output)
	}
	if conflicting, err := (linuxUserspaceInstaller{ipCommand: "ip"}).Install(
		context.Background(),
		config,
	); err == nil {
		_ = conflicting.Close(context.Background())
		t.Fatal("installer accepted a preoccupied routing table")
	}
	if output, err := exec.Command(
		"ip", "-4", "route", "delete",
		"table", table, "unreachable", "default",
	).CombinedOutput(); err != nil {
		t.Fatalf("release preoccupied route table: %v: %s", err, output)
	}

	handle, err := (linuxUserspaceInstaller{ipCommand: "ip"}).Install(
		context.Background(),
		config,
	)
	if err != nil {
		t.Fatalf("install user-space CHILD_SA: %v", err)
	}
	if mode := handle.(DataplaneEvidence).DataplaneMode(); mode != "userspace" {
		t.Fatalf("dataplane mode = %q", mode)
	}
	if output, err := exec.Command("ip", "link", "show", "dev", config.Name).CombinedOutput(); err != nil {
		t.Fatalf("TUN interface was not created: %v: %s", err, output)
	}
	if output, err := exec.Command(
		"ip", "-4", "route", "show", "table", table,
	).CombinedOutput(); err != nil ||
		!strings.Contains(string(output), "10.127.192.82") ||
		!strings.Contains(string(output), "unreachable default") {
		t.Fatalf("isolated P-CSCF routes are missing: %v: %s", err, output)
	}
	if output, err := exec.Command(
		"ip", "-4", "route", "get", "10.127.192.82",
		"from", "10.132.116.34",
	).CombinedOutput(); err != nil ||
		!strings.Contains(string(output), "dev "+config.Name) ||
		!strings.Contains(string(output), "table "+table) {
		t.Fatalf(
			"P-CSCF route did not win before the main table: %v: %s",
			err,
			output,
		)
	}
	if output, err := exec.Command(
		"ip", "-4", "route", "get", "198.51.100.1",
		"from", "10.132.116.34",
	).CombinedOutput(); err == nil {
		t.Fatalf(
			"non-P-CSCF inner traffic escaped the unreachable default: %s",
			output,
		)
	}

	expectedFailure := errors.New("test relay stopped")
	concrete := handle.(*linuxUserspaceHandle)
	concrete.fail(expectedFailure)
	select {
	case failure := <-concrete.Failures():
		if !errors.Is(failure, expectedFailure) {
			t.Fatalf("runtime failure = %v", failure)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal failure was not published")
	}

	closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := handle.Close(closeContext); err != nil {
		t.Fatalf("close user-space CHILD_SA: %v", err)
	}
	if err := exec.Command("ip", "link", "show", "dev", config.Name).Run(); err == nil {
		t.Fatal("TUN interface survived Close")
	}
	output, err := exec.Command("ip", "-4", "rule", "show").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "from 10.132.116.34") {
		t.Fatalf("source rule survived Close: %s", output)
	}
}

var _ NATTPacketRelay = blockingNATTRelay{}
