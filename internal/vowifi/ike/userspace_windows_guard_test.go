//go:build windows && (amd64 || arm64)

package ike

import (
	"errors"
	"net"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsSourceGuardABILayout(t *testing.T) {
	for _, test := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "value", got: unsafe.Sizeof(sourceGuardValue0{}), want: 16},
		{name: "condition", got: unsafe.Sizeof(sourceGuardFilterCondition0{}), want: 40},
		{name: "filter", got: unsafe.Sizeof(sourceGuardFilter0{}), want: 200},
		{name: "session", got: unsafe.Sizeof(sourceGuardSession0{}), want: 72},
		{name: "sublayer", got: unsafe.Sizeof(sourceGuardSubLayer0{}), want: 72},
	} {
		if test.got != test.want {
			t.Fatalf("%s ABI size = %d, want %d", test.name, test.got, test.want)
		}
	}
}

func TestWindowsSourceGuardFilterBlocksOnlyNonTunnelInterface(t *testing.T) {
	subLayer := windows.GUID{Data1: 0x1234}
	material, err := buildWindowsSourceGuardFilter(
		net.IPv4(10, 132, 116, 34),
		0x01020304,
		subLayer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.filter.layerKey != sourceGuardLayerOutboundIPv4 ||
		material.filter.subLayerKey != subLayer ||
		material.filter.action.typeID != sourceGuardActionBlock ||
		material.filter.flags&sourceGuardFilterClearAction == 0 {
		t.Fatalf("unexpected source guard filter: %#v", material.filter)
	}
	if len(material.conditions) != 2 {
		t.Fatalf("conditions = %#v", material.conditions)
	}
	address := material.conditions[0]
	if address.fieldKey != sourceGuardConditionLocalAddress ||
		address.matchType != sourceGuardMatchEqual ||
		address.conditionValue.typeID != sourceGuardUint32 ||
		address.conditionValue.value != 0x0a847422 {
		t.Fatalf("local-address condition = %#v", address)
	}
	iface := material.conditions[1]
	if iface.fieldKey != sourceGuardConditionInterfaceIndex ||
		iface.matchType != sourceGuardMatchNotEqual ||
		iface.conditionValue.typeID != sourceGuardUint32 ||
		material.interfaceIndex != 0x01020304 ||
		iface.conditionValue.value != uintptr(material.interfaceIndex) {
		t.Fatalf("outbound-interface condition = %#v", iface)
	}
	if material.filter.weight.typeID != sourceGuardUint64 ||
		material.weight != ^uint64(0) ||
		material.filter.weight.value != uintptr(unsafe.Pointer(&material.weight)) {
		t.Fatalf("filter weight = %#v", material.filter.weight)
	}
}

func TestWindowsSourceGuardFilterUsesIPv6PacketLayer(t *testing.T) {
	inner := net.ParseIP("2001:db8::1234")
	material, err := buildWindowsSourceGuardFilter(inner, 0x1234, windows.GUID{Data1: 1})
	if err != nil {
		t.Fatal(err)
	}
	if material.filter.layerKey != sourceGuardLayerOutboundIPv6 ||
		material.conditions[0].conditionValue.typeID != sourceGuardByteArray16Type ||
		material.addressV6 == nil ||
		!net.IP(material.addressV6.bytes[:]).Equal(inner) {
		t.Fatalf("IPv6 source guard material = %#v", material)
	}
}

type fakeWindowsSourceGuardAPI struct {
	opened           bool
	dynamic          bool
	closed           bool
	subLayerAdded    bool
	subLayerDeleted  bool
	subLayerWeight   uint16
	filterCount      int
	deletedFilters   []uint64
	filterError      error
	cleanupError     error
	deleteFailures   map[uint64]int
	subLayerFailures int
	closeFailures    int
}

func (api *fakeWindowsSourceGuardAPI) openEngine(
	session *sourceGuardSession0,
) (windows.Handle, error) {
	api.opened = true
	api.dynamic = session.flags&sourceGuardSessionFlagDynamic != 0
	return windows.Handle(1), nil
}

func (api *fakeWindowsSourceGuardAPI) closeEngine(windows.Handle) error {
	if api.closeFailures > 0 {
		api.closeFailures--
		return api.cleanupError
	}
	api.closed = true
	return nil
}

func (api *fakeWindowsSourceGuardAPI) addSubLayer(
	_ windows.Handle,
	subLayer *sourceGuardSubLayer0,
) error {
	api.subLayerAdded = true
	api.subLayerWeight = subLayer.weight
	return nil
}

func (api *fakeWindowsSourceGuardAPI) deleteSubLayer(
	_ windows.Handle,
	_ *windows.GUID,
) error {
	if api.subLayerFailures > 0 {
		api.subLayerFailures--
		return api.cleanupError
	}
	api.subLayerDeleted = true
	return nil
}

func (api *fakeWindowsSourceGuardAPI) addFilter(
	_ windows.Handle,
	filter *sourceGuardFilter0,
) (uint64, error) {
	if filter.action.typeID != sourceGuardActionBlock {
		return 0, errors.New("test: source guard filter does not block")
	}
	api.filterCount++
	if api.filterError != nil {
		return 0, api.filterError
	}
	return uint64(100 + api.filterCount), nil
}

func (api *fakeWindowsSourceGuardAPI) deleteFilter(_ windows.Handle, id uint64) error {
	api.deletedFilters = append(api.deletedFilters, id)
	if api.deleteFailures[id] > 0 {
		api.deleteFailures[id]--
		return api.cleanupError
	}
	return nil
}

func TestWindowsSourceGuardUsesDynamicSessionAndCleansInReverse(t *testing.T) {
	api := &fakeWindowsSourceGuardAPI{}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "complete-device-identity",
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
		InnerLocalIPv6: net.ParseIP("2001:db8::10"),
	}, 0x1234, api)
	if err != nil {
		t.Fatal(err)
	}
	if !api.opened || !api.dynamic || !api.subLayerAdded ||
		api.subLayerWeight != sourceGuardSubLayerWeight || api.filterCount != 2 {
		t.Fatalf("install state = %#v", api)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if !api.subLayerDeleted || !api.closed ||
		len(api.deletedFilters) != 2 ||
		api.deletedFilters[0] != 102 || api.deletedFilters[1] != 101 {
		t.Fatalf("cleanup state = %#v", api)
	}
}

func TestWindowsSourceGuardFailsClosedWhenFilterInstallFails(t *testing.T) {
	want := errors.New("test: BFE rejected filter")
	api := &fakeWindowsSourceGuardAPI{filterError: want}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "complete-device-identity",
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
	}, 0x1234, api)
	if guard != nil || !errors.Is(err, want) {
		t.Fatalf("install result guard=%#v err=%v", guard, err)
	}
	if !api.dynamic || !api.subLayerDeleted || !api.closed {
		t.Fatalf("failed install did not remove dynamic policy: %#v", api)
	}
}

func TestWindowsSourceGuardInstallRetriesTransientRollbackFailure(t *testing.T) {
	installErr := errors.New("test: BFE rejected filter")
	cleanupErr := errors.New("test: transient engine close failure")
	api := &fakeWindowsSourceGuardAPI{
		filterError:   installErr,
		cleanupError:  cleanupErr,
		closeFailures: 1,
	}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "retry-install-source-guard-cleanup",
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
	}, 0x1234, api)
	if guard != nil || !errors.Is(err, installErr) {
		t.Fatalf("install result guard=%#v err=%v", guard, err)
	}
	if !api.subLayerDeleted || !api.closed || api.closeFailures != 0 {
		t.Fatalf("bounded install rollback state = %#v", api)
	}
}

func TestWindowsSourceGuardInstallBoundsPersistentRollbackFailure(t *testing.T) {
	installErr := errors.New("test: BFE rejected filter")
	cleanupErr := errors.New("test: persistent engine close failure")
	api := &fakeWindowsSourceGuardAPI{
		filterError:   installErr,
		cleanupError:  cleanupErr,
		closeFailures: sourceGuardRollbackAttempts + 1,
	}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "bounded-install-source-guard-cleanup",
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
	}, 0x1234, api)
	if guard != nil || !errors.Is(err, installErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("install result guard=%#v err=%v", guard, err)
	}
	if api.closed || api.closeFailures != 1 {
		t.Fatalf("persistent rollback exceeded its strict attempt bound: %#v", api)
	}
}

func TestWindowsSourceGuardCloseRetriesUnfinishedCleanup(t *testing.T) {
	want := errors.New("test: transient WFP cleanup failure")
	api := &fakeWindowsSourceGuardAPI{}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "retryable-source-guard-cleanup",
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
		InnerLocalIPv6: net.ParseIP("2001:db8::10"),
	}, 0x1234, api)
	if err != nil {
		t.Fatal(err)
	}
	api.cleanupError = want
	api.deleteFailures = map[uint64]int{102: 1}
	api.subLayerFailures = 1
	api.closeFailures = 1
	if err := guard.Close(); !errors.Is(err, want) {
		t.Fatalf("first close error = %v, want transient failure", err)
	}
	if guard.closed || guard.engine == 0 || !guard.subLayer ||
		len(guard.filterIDs) != 1 || guard.filterIDs[0] != 102 {
		t.Fatalf("failed cleanup state = %#v", guard)
	}
	deletedBeforeRetry := len(api.deletedFilters)
	if err := guard.Close(); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if got := api.deletedFilters[deletedBeforeRetry:]; len(got) != 1 || got[0] != 102 {
		t.Fatalf("retry deleted filters = %v, want [102]", got)
	}
	if !guard.closed || guard.engine != 0 || guard.subLayer || len(guard.filterIDs) != 0 {
		t.Fatalf("successful retry retained WFP state = %#v", guard)
	}
}

func TestWindowsSourceGuardCloseUsesDynamicSessionAsCleanupFallback(t *testing.T) {
	want := errors.New("test: explicit filter deletion failed")
	api := &fakeWindowsSourceGuardAPI{}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "dynamic-source-guard-cleanup",
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
	}, 0x1234, api)
	if err != nil {
		t.Fatal(err)
	}
	api.cleanupError = want
	api.deleteFailures = map[uint64]int{101: 1}
	if err := guard.Close(); err != nil {
		t.Fatalf("dynamic engine close should finish cleanup: %v", err)
	}
	if !guard.closed || guard.engine != 0 || len(guard.filterIDs) != 0 {
		t.Fatalf("dynamic-session cleanup state = %#v", guard)
	}
}

func TestWindowsSourceGuardSystemAPIIntegration(t *testing.T) {
	if os.Getenv("VOCAT_WINDOWS_WFP_TEST") != "1" {
		t.Skip("set VOCAT_WINDOWS_WFP_TEST=1 in an elevated Windows test process")
	}
	guard, err := installWindowsSourceGuardWithAPI(ChildSAConfig{
		DeviceID:       "vocat-source-guard-integration-test",
		InnerLocalIPv4: net.IPv4(192, 0, 2, 254),
		InnerLocalIPv6: net.ParseIP("2001:db8:ffff::254"),
	}, 0xfffffffe, windowsSourceGuardSystemAPI{})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
}

var _ windowsSourceGuardAPI = (*fakeWindowsSourceGuardAPI)(nil)
