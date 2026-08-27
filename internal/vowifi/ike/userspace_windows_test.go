//go:build windows

package ike

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type windowsTestRelay struct{}

func (windowsTestRelay) SendESP(context.Context, []byte) error { return nil }
func (windowsTestRelay) ReceiveESP(context.Context, []byte) (int, error) {
	return 0, context.Canceled
}

type fakeWindowsInterfaceAddressAPI struct {
	lists        [][]windowsInterfaceAddress
	listErrors   []error
	listCall     int
	deleteErrors map[netip.Prefix]error
	deleted      []windowsInterfaceAddress
}

func (api *fakeWindowsInterfaceAddressAPI) List() ([]windowsInterfaceAddress, error) {
	call := api.listCall
	api.listCall++
	if call < len(api.listErrors) && api.listErrors[call] != nil {
		return nil, api.listErrors[call]
	}
	if len(api.lists) == 0 {
		return nil, nil
	}
	if call >= len(api.lists) {
		call = len(api.lists) - 1
	}
	return append([]windowsInterfaceAddress(nil), api.lists[call]...), nil
}

func (api *fakeWindowsInterfaceAddressAPI) Delete(address windowsInterfaceAddress) error {
	api.deleted = append(api.deleted, address)
	return api.deleteErrors[address.prefix]
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

type fakeWindowsWintunAdapterCloser struct {
	closeCount int
	err        error
}

func (adapter *fakeWindowsWintunAdapterCloser) Close() error {
	adapter.closeCount++
	return adapter.err
}

func TestWindowsUserspaceHandleConsumesAdapterAfterVoidClose(t *testing.T) {
	adapter := &fakeWindowsWintunAdapterCloser{err: syscall.Errno(5)}
	handle := &windowsUserspaceHandle{
		adapter:      adapter,
		sessionEnded: true,
		networkClean: true,
	}
	if err := handle.closeResources(context.Background()); err != nil {
		t.Fatalf("closeResources() treated undefined Wintun return state as an error: %v", err)
	}
	if adapter.closeCount != 1 || handle.adapter != nil {
		t.Fatalf("adapter ownership after close: count=%d owner=%#v", adapter.closeCount, handle.adapter)
	}
	if err := handle.closeResources(context.Background()); err != nil {
		t.Fatalf("idempotent closeResources(): %v", err)
	}
	if adapter.closeCount != 1 {
		t.Fatalf("consumed Wintun adapter was closed %d times", adapter.closeCount)
	}
}

func TestWindowsWintunAdapterGUIDIsStableAndIdentityScoped(t *testing.T) {
	first, err := windowsWintunAdapterGUID("  USB\\VID_2C7C&PID_0125\\DEVICE-A  ")
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := windowsWintunAdapterGUID("usb\\vid_2c7c&pid_0125\\device-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := windowsWintunAdapterGUID("usb\\vid_2c7c&pid_0125\\device-b")
	if err != nil {
		t.Fatal(err)
	}
	if first != repeated {
		t.Fatalf("stable device identity produced changing GUIDs: %v != %v", first, repeated)
	}
	if first == second {
		t.Fatalf("different complete device identities produced one GUID: %v", first)
	}
	if first.Data3>>12 != 8 || first.Data4[0]&0xc0 != 0x80 {
		t.Fatalf("deterministic GUID does not carry UUIDv8/RFC4122 bits: %v", first)
	}
	if _, err := windowsWintunAdapterGUID(" "); err == nil {
		t.Fatal("empty stable device identity was accepted")
	}
}

func TestWintunSendRingOverflowIsTransient(t *testing.T) {
	if !transientWintunSendError(fmt.Errorf("wrapped: %w", windows.ERROR_BUFFER_OVERFLOW)) {
		t.Fatal("Wintun ring overflow was classified as terminal")
	}
	if transientWintunSendError(windows.ERROR_INVALID_HANDLE) {
		t.Fatal("invalid Wintun handle was classified as transient")
	}
}

func TestRemoveAndVerifyWindowsInterfaceAddressesRequiresEmptyRecheck(t *testing.T) {
	luid := windowsInterfaceAddress{luid: 7, prefix: netip.MustParsePrefix("10.0.0.2/32")}
	api := &fakeWindowsInterfaceAddressAPI{lists: [][]windowsInterfaceAddress{{luid}, {luid}}}
	safe, err := removeAndVerifyWindowsInterfaceAddresses(api, luid.luid)
	if safe || err == nil {
		t.Fatalf("safe=%v err=%v; residual address was accepted after a successful delete call", safe, err)
	}
}

func TestRemoveAndVerifyWindowsInterfaceAddressesReportsDeleteErrorAfterSafeRecheck(t *testing.T) {
	address := windowsInterfaceAddress{luid: 9, prefix: netip.MustParsePrefix("2001:db8::2/128")}
	deleteErr := errors.New("delete failed")
	api := &fakeWindowsInterfaceAddressAPI{
		lists:        [][]windowsInterfaceAddress{{address}, nil},
		deleteErrors: map[netip.Prefix]error{address.prefix: deleteErr},
	}
	safe, err := removeAndVerifyWindowsInterfaceAddresses(api, address.luid)
	if !safe || !errors.Is(err, deleteErr) {
		t.Fatalf("safe=%v err=%v; verified removal must stay safe while preserving the delete diagnostic", safe, err)
	}
}

func TestRemoveAndVerifyWindowsInterfaceAddressesIgnoresOtherInterfaces(t *testing.T) {
	target := windowsInterfaceAddress{luid: 11, prefix: netip.MustParsePrefix("10.0.0.3/32")}
	other := windowsInterfaceAddress{luid: 12, prefix: netip.MustParsePrefix("10.0.0.4/32")}
	api := &fakeWindowsInterfaceAddressAPI{lists: [][]windowsInterfaceAddress{{target, other}, {other}}}
	safe, err := removeAndVerifyWindowsInterfaceAddresses(api, target.luid)
	if err != nil || !safe {
		t.Fatalf("safe=%v err=%v", safe, err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != target {
		t.Fatalf("deleted=%#v; expected only the target interface address", api.deleted)
	}
}

func TestRemoveAndVerifyWindowsInterfaceAddressesFailsClosedOnRecheckError(t *testing.T) {
	address := windowsInterfaceAddress{luid: 13, prefix: netip.MustParsePrefix("10.0.0.5/32")}
	verifyErr := errors.New("recheck failed")
	api := &fakeWindowsInterfaceAddressAPI{
		lists:      [][]windowsInterfaceAddress{{address}},
		listErrors: []error{nil, verifyErr},
	}
	safe, err := removeAndVerifyWindowsInterfaceAddresses(api, address.luid)
	if safe || !errors.Is(err, verifyErr) {
		t.Fatalf("safe=%v err=%v; verification failure must retain the source guard", safe, err)
	}
}

func TestWindowsDynamicHostRouteRequiresAssignedAddressFamily(t *testing.T) {
	config := ChildSAConfig{InnerLocalIPv4: net.IPv4(10, 132, 116, 34)}
	route, key, err := windowsDynamicHostRoute(config, net.IPv4(10, 20, 30, 40))
	if err != nil {
		t.Fatal(err)
	}
	if key != "10.20.30.40" || route.destination.Bits() != 32 || !route.nextHop.IsUnspecified() {
		t.Fatalf("dynamic route = %#v key=%q", route, key)
	}
	if _, _, err := windowsDynamicHostRoute(config, net.ParseIP("2001:db8::20")); err == nil {
		t.Fatal("IPv6 route without an assigned inner IPv6 address was accepted")
	}
}

type retryableWindowsSourceGuard struct {
	closeCount int
	failures   int
	err        error
}

func (guard *retryableWindowsSourceGuard) Close() error {
	guard.closeCount++
	if guard.failures > 0 {
		guard.failures--
		return guard.err
	}
	return nil
}

func TestWindowsUserspaceHandleRetriesSourceGuardCleanup(t *testing.T) {
	want := errors.New("transient source-guard close failure")
	guard := &retryableWindowsSourceGuard{failures: 1, err: want}
	handle := &windowsUserspaceHandle{
		sourceGuard:  guard,
		sessionEnded: true,
		networkClean: true,
	}
	if err := handle.closeResources(context.Background()); !errors.Is(err, want) {
		t.Fatalf("first closeResources() error = %v, want transient failure", err)
	}
	if guard.closeCount != 1 || handle.sourceGuard == nil {
		t.Fatalf("failed source guard was not retained: count=%d guard=%#v", guard.closeCount, handle.sourceGuard)
	}
	if err := handle.closeResources(context.Background()); err != nil {
		t.Fatalf("retry closeResources(): %v", err)
	}
	if guard.closeCount != 2 || handle.sourceGuard != nil {
		t.Fatalf("retry state: count=%d guard=%#v", guard.closeCount, handle.sourceGuard)
	}
	if err := handle.closeResources(context.Background()); err != nil {
		t.Fatalf("idempotent closeResources(): %v", err)
	}
	if guard.closeCount != 2 {
		t.Fatalf("completed source guard retried %d times", guard.closeCount)
	}
}

func TestCloseAbandonedWindowsUserspaceHandleRetriesTransientCleanup(t *testing.T) {
	want := errors.New("transient source-guard close failure")
	guard := &retryableWindowsSourceGuard{failures: 1, err: want}
	handle := &windowsUserspaceHandle{
		sourceGuard:  guard,
		sessionEnded: true,
		networkClean: true,
	}
	if err := closeAbandonedWindowsUserspaceHandle(handle); err != nil {
		t.Fatalf("bounded rollback did not recover: %v", err)
	}
	if guard.closeCount != 2 || handle.sourceGuard != nil {
		t.Fatalf("bounded rollback state: count=%d guard=%#v", guard.closeCount, handle.sourceGuard)
	}
}

func TestRollbackAbandonedWindowsUserspaceHandleIsBoundedAndJoinsErrors(t *testing.T) {
	cause := errors.New("injected Windows tunnel install failure")
	cleanupErr := errors.New("persistent source-guard close failure")
	guard := &retryableWindowsSourceGuard{
		failures: windowsUserspaceRollbackAttempts + 1,
		err:      cleanupErr,
	}
	handle := &windowsUserspaceHandle{
		sourceGuard:  guard,
		sessionEnded: true,
		networkClean: true,
	}
	err := rollbackAbandonedWindowsUserspaceHandle(cause, handle)
	if !errors.Is(err, cause) || !errors.Is(err, cleanupErr) {
		t.Fatalf("rollback error = %v; want install and cleanup causes", err)
	}
	if guard.closeCount != windowsUserspaceRollbackAttempts {
		t.Fatalf("persistent cleanup attempts = %d, want %d", guard.closeCount, windowsUserspaceRollbackAttempts)
	}
	if handle.sourceGuard == nil {
		t.Fatal("persistent rollback failure discarded the source-guard owner")
	}
}
