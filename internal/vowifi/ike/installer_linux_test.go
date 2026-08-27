//go:build linux

package ike

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestLinuxXFRMPolicyPlacesUPSpecBeforeDirectionAndDeletesExactSelector(t *testing.T) {
	handle := linuxXFRMHandle{
		config: ChildSAConfig{
			OuterLocal:  net.ParseIP("192.0.2.10"),
			OuterRemote: net.ParseIP("192.0.2.20"),
		},
		reqid: "1234",
	}
	initiator := trafficSelector{
		IPProtocol: 17,
		StartPort:  4000,
		EndPort:    4000,
		StartIP:    net.ParseIP("10.0.0.2"),
		EndIP:      net.ParseIP("10.0.0.2"),
	}
	responder := trafficSelector{
		IPProtocol: 17,
		StartPort:  5000,
		EndPort:    5000,
		StartIP:    net.ParseIP("10.0.0.3"),
		EndIP:      net.ParseIP("10.0.0.3"),
	}

	commands, err := handle.policyPairCommands(initiator, responder)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 {
		t.Fatalf("policy command count = %d, want 2", len(commands))
	}
	outbound := commands[0]
	for _, fields := range [][]string{outbound.add, outbound.remove} {
		proto := slices.Index(fields, "proto")
		sport := slices.Index(fields, "sport")
		dport := slices.Index(fields, "dport")
		direction := slices.Index(fields, "dir")
		if proto < 0 || sport < proto || dport < sport || direction < dport {
			t.Fatalf("invalid XFRM selector ordering: %q", strings.Join(fields, " "))
		}
	}
	remove := strings.Join(outbound.remove, " ")
	for _, want := range []string{
		"xfrm policy delete",
		"proto 17",
		"sport 4000",
		"dport 5000",
		"dir out",
	} {
		if !strings.Contains(remove, want) {
			t.Fatalf("delete command %q does not contain %q", remove, want)
		}
	}
	if strings.Contains(remove, "tmpl") || strings.Contains(remove, "priority") {
		t.Fatalf("delete command contains non-selector fields: %q", remove)
	}
}

func TestLinuxXFRMPolicyRejectsPortsWithoutProtocol(t *testing.T) {
	handle := linuxXFRMHandle{config: ChildSAConfig{
		OuterLocal:  net.ParseIP("192.0.2.10"),
		OuterRemote: net.ParseIP("192.0.2.20"),
	}}
	initiator := trafficSelector{
		StartPort: 4000,
		EndPort:   4000,
		StartIP:   net.ParseIP("10.0.0.2"),
		EndIP:     net.ParseIP("10.0.0.2"),
	}
	responder := trafficSelector{
		StartPort: 0,
		EndPort:   65535,
		StartIP:   net.ParseIP("10.0.0.3"),
		EndIP:     net.ParseIP("10.0.0.3"),
	}
	if _, err := handle.policyPairCommands(initiator, responder); err == nil {
		t.Fatal("port-restricted selector without protocol unexpectedly succeeded")
	}
}

func TestLinuxXFRMPolicyInstallationDeduplicatesEquivalentSelectors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux executable path required")
	}
	handle := linuxXFRMHandle{
		ipCommand:           "/bin/true",
		installedPolicyKeys: make(map[string]bool),
	}
	command := linuxXFRMPolicyCommand{
		add:    []string{"-4", "xfrm", "policy", "add", "src", "10.0.0.2/32", "dir", "out"},
		remove: []string{"-4", "xfrm", "policy", "delete", "src", "10.0.0.2/32", "dir", "out"},
	}
	if err := handle.installPolicyCommand(context.Background(), "install test policy", command); err != nil {
		t.Fatal(err)
	}
	if err := handle.installPolicyCommand(context.Background(), "install test policy", command); err != nil {
		t.Fatal(err)
	}
	if len(handle.cleanup) != 1 {
		t.Fatalf("cleanup command count = %d, want one deduplicated policy", len(handle.cleanup))
	}
}

func TestLinuxXFRMOutboundGuardsCoverNarrowIPv4AndIPv6Selectors(t *testing.T) {
	config := ChildSAConfig{
		InnerLocalIPv4: net.ParseIP("10.0.0.2"),
		InnerLocalIPv6: net.ParseIP("2001:db8::2"),
		InitiatorSelectors: []trafficSelector{
			udpHostSelector("10.0.0.2", 4000),
			udpHostSelector("2001:db8::2", 4000),
		},
		ResponderSelectors: []trafficSelector{
			udpHostSelector("10.0.0.3", 5000),
			udpHostSelector("2001:db8::3", 5000),
		},
	}
	commands := linuxXFRMOutboundGuardCommands(config)
	if len(commands) != 2 {
		t.Fatalf("guard count = %d, want IPv4 and IPv6 guards", len(commands))
	}
	want := []string{
		"-4 xfrm policy add src 10.0.0.2/32 dir out action block priority 30000",
		"-6 xfrm policy add src 2001:db8::2/128 dir out action block priority 30000",
	}
	for index, command := range commands {
		if got := strings.Join(command.add, " "); got != want[index] {
			t.Fatalf("guard %d = %q, want %q", index, got, want[index])
		}
		remove := strings.Join(command.remove, " ")
		if strings.Contains(remove, "action") || strings.Contains(remove, "priority") {
			t.Fatalf("guard delete contains non-selector fields: %q", remove)
		}
	}
}

func TestLinuxXFRMOutboundGuardSkipsFullyCoveringPolicies(t *testing.T) {
	config := ChildSAConfig{
		InnerLocalIPv4: net.ParseIP("10.0.0.2"),
		InnerLocalIPv6: net.ParseIP("2001:db8::2"),
		InitiatorSelectors: []trafficSelector{
			anyPortHostSelector("10.0.0.2"),
			anyPortHostSelector("2001:db8::2"),
		},
		ResponderSelectors: []trafficSelector{
			anyIPv4Selector(),
			anyIPv6Selector(),
		},
	}
	if commands := linuxXFRMOutboundGuardCommands(config); len(commands) != 0 {
		t.Fatalf("fully covering policies generated guards: %#v", commands)
	}
}

func TestLinuxXFRMCloseRetainsFailedCleanupForRetry(t *testing.T) {
	handle := linuxXFRMHandle{
		ipCommand: "/bin/false",
		cleanup: []ipCleanupCommand{{
			operation: "delete test policy",
			arguments: []string{"-4", "xfrm", "policy", "delete"},
		}},
	}
	if err := handle.Close(context.Background()); err == nil {
		t.Fatal("failed cleanup unexpectedly returned nil")
	}
	if handle.closed || len(handle.cleanup) != 1 {
		t.Fatalf("failed cleanup was not retained: closed=%v cleanup=%#v", handle.closed, handle.cleanup)
	}
	handle.ipCommand = "/bin/true"
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !handle.closed || len(handle.cleanup) != 0 {
		t.Fatalf("successful retry did not close handle: closed=%v cleanup=%#v", handle.closed, handle.cleanup)
	}
}

func TestLinuxXFRMCloseTreatsConfirmedMissingObjectsAsCleaned(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*linuxXFRMHandle)
		retained  func(*linuxXFRMHandle) bool
	}{
		{
			name: "interface",
			configure: func(handle *linuxXFRMHandle) {
				handle.config.Name = "vocat-test"
				handle.interfaceCreated = true
			},
			retained: func(handle *linuxXFRMHandle) bool { return handle.interfaceCreated },
		},
		{
			name: "policy or state",
			configure: func(handle *linuxXFRMHandle) {
				handle.cleanup = []ipCleanupCommand{{
					operation: "delete XFRM object",
					arguments: []string{"xfrm", "policy", "delete"},
				}}
			},
			retained: func(handle *linuxXFRMHandle) bool { return len(handle.cleanup) == 1 },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			statePath := filepath.Join(directory, "deleted")
			scriptPath := filepath.Join(directory, "ip")
			script := "#!/bin/sh\nif [ ! -e \"$VOCAT_XFRM_DELETE_STATE\" ]; then\n  : > \"$VOCAT_XFRM_DELETE_STATE\"\n  echo 'simulated error after delete side effect' >&2\n  exit 1\nfi\necho 'RTNETLINK answers: No such file or directory' >&2\nexit 2\n"
			if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("VOCAT_XFRM_DELETE_STATE", statePath)
			handle := linuxXFRMHandle{ipCommand: scriptPath}
			test.configure(&handle)
			if err := handle.Close(context.Background()); err == nil {
				t.Fatal("post-delete execution error unexpectedly returned nil")
			}
			if handle.closed || !test.retained(&handle) {
				t.Fatalf("ambiguous delete was not retained: closed=%v interface=%v cleanup=%#v", handle.closed, handle.interfaceCreated, handle.cleanup)
			}
			if err := handle.Close(context.Background()); err != nil {
				t.Fatalf("retry did not accept confirmed missing object: %v", err)
			}
			if !handle.closed || handle.interfaceCreated || len(handle.cleanup) != 0 {
				t.Fatalf("retry did not finish cleanup: closed=%v interface=%v cleanup=%#v", handle.closed, handle.interfaceCreated, handle.cleanup)
			}
		})
	}
}

func TestLinuxXFRMCloseDoesNotRemovePoliciesWhenInterfaceCannotBeDeleted(t *testing.T) {
	handle := linuxXFRMHandle{
		ipCommand:        "/bin/false",
		config:           ChildSAConfig{Name: "vocat-test"},
		interfaceCreated: true,
		cleanup: []ipCleanupCommand{{
			operation: "delete test policy",
			arguments: []string{"-4", "xfrm", "policy", "delete"},
		}},
	}
	if err := handle.Close(context.Background()); err == nil {
		t.Fatal("link-down failure unexpectedly returned nil")
	}
	if len(handle.cleanup) != 1 {
		t.Fatalf("policy cleanup ran after link-delete failure: %#v", handle.cleanup)
	}
}

func TestLinuxXFRMCloseKeepsGuardAfterPolicyCleanupFailure(t *testing.T) {
	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "ip")
	script := "#!/bin/sh\ncase \"$*:$VOCAT_XFRM_TEST_FAIL\" in *fail-policy:1*) exit 1;; esac\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOCAT_XFRM_TEST_FAIL", "1")
	handle := linuxXFRMHandle{
		ipCommand: scriptPath,
		cleanup: []ipCleanupCommand{
			{operation: "delete source guard", arguments: []string{"delete-guard"}},
			{operation: "delete protect policy", arguments: []string{"fail-policy"}},
		},
	}
	if err := handle.Close(context.Background()); err == nil {
		t.Fatal("policy cleanup failure unexpectedly returned nil")
	}
	if len(handle.cleanup) != 2 || handle.cleanup[0].arguments[0] != "delete-guard" {
		t.Fatalf("guard was removed after policy cleanup failure: %#v", handle.cleanup)
	}
	t.Setenv("VOCAT_XFRM_TEST_FAIL", "0")
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !handle.closed || len(handle.cleanup) != 0 {
		t.Fatalf("cleanup retry did not finish: closed=%v cleanup=%#v", handle.closed, handle.cleanup)
	}
}

func TestLinuxXFRMInstallerBoundsRollbackAfterInstallFailure(t *testing.T) {
	for _, test := range []struct {
		name           string
		mode           string
		wantCalls      string
		wantBoundedErr bool
	}{
		{name: "transient cleanup", mode: "transient", wantCalls: "4"},
		{name: "persistent cleanup", mode: "persistent", wantCalls: "5", wantBoundedErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			countPath := filepath.Join(directory, "count")
			scriptPath := filepath.Join(directory, "ip")
			script := "#!/bin/sh\n" +
				"count=0\n" +
				"[ ! -f \"$VOCAT_XFRM_ROLLBACK_COUNT\" ] || count=$(cat \"$VOCAT_XFRM_ROLLBACK_COUNT\")\n" +
				"count=$((count + 1))\n" +
				"printf '%s\\n' \"$count\" > \"$VOCAT_XFRM_ROLLBACK_COUNT\"\n" +
				"if [ \"$count\" -eq 2 ]; then\n" +
				"  echo 'injected XFRM install failure' >&2\n" +
				"  exit 1\n" +
				"fi\n" +
				"if [ \"$count\" -ge 3 ]; then\n" +
				"  case \"$VOCAT_XFRM_ROLLBACK_MODE:$count\" in\n" +
				"    transient:3|persistent:*)\n" +
				"      echo 'injected XFRM rollback failure' >&2\n" +
				"      exit 1\n" +
				"      ;;\n" +
				"  esac\n" +
				"fi\n" +
				"exit 0\n"
			if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("VOCAT_XFRM_ROLLBACK_COUNT", countPath)
			t.Setenv("VOCAT_XFRM_ROLLBACK_MODE", test.mode)
			config := ChildSAConfig{
				Name:           "vocat-rollback-test",
				OuterLocal:     net.ParseIP("192.0.2.10"),
				OuterRemote:    net.ParseIP("192.0.2.20"),
				InnerLocalIPv4: net.ParseIP("10.0.0.2"),
				InboundSPI:     1001,
				OutboundSPI:    1002,
				InitiatorSelectors: []trafficSelector{
					udpHostSelector("10.0.0.2", 4000),
				},
				ResponderSelectors: []trafficSelector{
					udpHostSelector("10.0.0.3", 5000),
				},
			}
			handle, err := (linuxXFRMInstaller{ipCommand: scriptPath}).Install(
				context.Background(),
				config,
			)
			if handle != nil || err == nil || !strings.Contains(err.Error(), "injected XFRM install failure") {
				t.Fatalf("Install() handle=%#v error=%v", handle, err)
			}
			if test.wantBoundedErr != strings.Contains(err.Error(), "after 3 bounded attempts") {
				t.Fatalf("Install() bounded rollback error = %v, want bounded=%v", err, test.wantBoundedErr)
			}
			count, readErr := os.ReadFile(countPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if got := strings.TrimSpace(string(count)); got != test.wantCalls {
				t.Fatalf("ip command calls = %s, want %s", got, test.wantCalls)
			}
		})
	}
}

func TestLinuxXFRMInstallAndCloseKeepInnerAddressFailClosed(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "ip.log")
	scriptPath := filepath.Join(directory, "ip")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$VOCAT_XFRM_TEST_LOG\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOCAT_XFRM_TEST_LOG", logPath)
	config := ChildSAConfig{
		Name:           "vocat-test",
		OuterLocal:     net.ParseIP("192.0.2.10"),
		OuterRemote:    net.ParseIP("192.0.2.20"),
		InnerLocalIPv4: net.ParseIP("10.0.0.2"),
		InboundSPI:     1001,
		OutboundSPI:    1002,
		Encryption:     "aes-cbc-128",
		Integrity:      "hmac-sha1-96",
		InitiatorSelectors: []trafficSelector{
			udpHostSelector("10.0.0.2", 4000),
		},
		ResponderSelectors: []trafficSelector{
			udpHostSelector("10.0.0.3", 5000),
		},
	}
	handle := linuxXFRMHandle{
		ipCommand:           scriptPath,
		config:              config,
		reqid:               "1001",
		installedPolicyKeys: make(map[string]bool),
	}
	if err := handle.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	installLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	installLines := strings.Split(strings.TrimSpace(string(installLog)), "\n")
	guard := indexContaining(installLines, "action block")
	protect := indexContaining(installLines, "tmpl src")
	address := indexContaining(installLines, "address add 10.0.0.2/32")
	linkUp := indexContaining(installLines, "link set dev vocat-test up")
	if guard < 0 || protect < guard || address < protect || linkUp < address {
		t.Fatalf("unsafe install order:\n%s", installLog)
	}

	beforeClose := len(installLines)
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	allLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	allLines := strings.Split(strings.TrimSpace(string(allLog)), "\n")
	closeLines := allLines[beforeClose:]
	if len(closeLines) == 0 || closeLines[0] != "link delete vocat-test" {
		t.Fatalf("Close did not delete interface before XFRM teardown: %#v", closeLines)
	}
}

func indexContaining(lines []string, fragment string) int {
	for index, line := range lines {
		if strings.Contains(line, fragment) {
			return index
		}
	}
	return -1
}

func udpHostSelector(address string, port uint16) trafficSelector {
	ip := net.ParseIP(address)
	return trafficSelector{
		IPProtocol: 17,
		StartPort:  port,
		EndPort:    port,
		StartIP:    ip,
		EndIP:      ip,
	}
}

func anyPortHostSelector(address string) trafficSelector {
	ip := net.ParseIP(address)
	return trafficSelector{
		StartPort: 0,
		EndPort:   65535,
		StartIP:   ip,
		EndIP:     ip,
	}
}

func anyIPv4Selector() trafficSelector {
	return trafficSelector{
		StartPort: 0,
		EndPort:   65535,
		StartIP:   net.IPv4zero,
		EndIP:     net.IPv4bcast,
	}
}

func anyIPv6Selector() trafficSelector {
	end := make(net.IP, net.IPv6len)
	for index := range end {
		end[index] = 0xff
	}
	return trafficSelector{
		StartPort: 0,
		EndPort:   65535,
		StartIP:   net.IPv6zero,
		EndIP:     end,
	}
}
