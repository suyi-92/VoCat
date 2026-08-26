//go:build windows

package ike

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type windowsTestRelay struct{}

func (windowsTestRelay) SendESP(context.Context, []byte) error { return nil }
func (windowsTestRelay) ReceiveESP(context.Context, []byte) (int, error) {
	return 0, context.Canceled
}

func TestWindowsTunnelNetworkPlanUsesHostRoutes(t *testing.T) {
	config := ChildSAConfig{
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
		InnerLocalIPv6: net.ParseIP("2001:db8::10"),
		PCSCF: []net.IP{
			net.IPv4(10, 127, 192, 82),
			net.IPv4(10, 127, 192, 82),
			net.ParseIP("2001:db8::20"),
		},
	}
	addresses, routes, families, err := windowsTunnelNetworkPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0].Bits() != 32 || addresses[1].Bits() != 128 {
		t.Fatalf("addresses = %#v", addresses)
	}
	if len(routes) != 2 || routes[0].Destination.Bits() != 32 || routes[1].Destination.Bits() != 128 {
		t.Fatalf("routes = %#v", routes)
	}
	if len(families) != 2 || families[0] != windows.AF_INET || families[1] != windows.AF_INET6 {
		t.Fatalf("families = %#v", families)
	}
}

func TestWindowsInstallerRejectsNonNATTBeforeLoadingDLL(t *testing.T) {
	_, err := (windowsUserspaceInstaller{}).Install(nil, ChildSAConfig{Relay: windowsTestRelay{}})
	if err == nil {
		t.Fatal("Windows installer accepted a CHILD_SA without UDP encapsulation")
	}
}

func TestNormalizeWintunCloseErrorAcceptsBoxedSuccess(t *testing.T) {
	var boxedSuccess error = syscall.Errno(0)
	if err := normalizeWintunCloseError(boxedSuccess); err != nil {
		t.Fatalf("normalizeWintunCloseError(Errno(0)) = %v", err)
	}
	want := syscall.Errno(5)
	if err := normalizeWintunCloseError(want); err != want {
		t.Fatalf("normalizeWintunCloseError(%v) = %v", want, err)
	}
}
