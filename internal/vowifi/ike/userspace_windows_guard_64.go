//go:build windows && (amd64 || arm64)

package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These minimal declarations mirror the Windows SDK 10.0.26100.0 ABI used by
// fwpuclnt.dll. The source guard is deliberately independent of IMS transport
// IPsec: it protects the SWu inner address at the outbound IP-packet layer.
type sourceGuardDataType uint32
type sourceGuardMatchType uint32

const (
	sourceGuardEmpty           sourceGuardDataType = 0
	sourceGuardUint32          sourceGuardDataType = 3
	sourceGuardUint64          sourceGuardDataType = 4
	sourceGuardByteArray16Type sourceGuardDataType = 11

	sourceGuardMatchEqual    sourceGuardMatchType = 0
	sourceGuardMatchNotEqual sourceGuardMatchType = 10

	sourceGuardActionBlock         uint32 = 0x00001001
	sourceGuardSessionFlagDynamic  uint32 = 0x00000001
	sourceGuardFilterClearAction   uint32 = 0x00000008
	sourceGuardRPCAuthenticationNT uint32 = 10
	sourceGuardSubLayerWeight      uint16 = 0xffff

	sourceGuardRollbackAttempts   = 3
	sourceGuardRollbackRetryDelay = 25 * time.Millisecond
)

type sourceGuardByteArray16 struct {
	bytes [16]byte
}

type sourceGuardByteBlob struct {
	size uint32
	data *byte
}

type sourceGuardValue0 struct {
	typeID sourceGuardDataType
	value  uintptr
}

type sourceGuardDisplayData0 struct {
	name        *uint16
	description *uint16
}

type sourceGuardAction0 struct {
	typeID     uint32
	calloutKey windows.GUID
}

type sourceGuardFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      sourceGuardMatchType
	conditionValue sourceGuardValue0
}

type sourceGuardFilter0 struct {
	filterKey           windows.GUID
	displayData         sourceGuardDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        sourceGuardByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              sourceGuardValue0
	numFilterConditions uint32
	filterCondition     *sourceGuardFilterCondition0
	action              sourceGuardAction0
	_actionPadding      [4]byte
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     sourceGuardValue0
}

type sourceGuardSession0 struct {
	sessionKey           windows.GUID
	displayData          sourceGuardDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type sourceGuardSubLayer0 struct {
	subLayerKey  windows.GUID
	displayData  sourceGuardDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData sourceGuardByteBlob
	weight       uint16
}

var (
	sourceGuardLayerOutboundIPv4 = windows.GUID{
		Data1: 0x1e5c9fae, Data2: 0x8a84, Data3: 0x4135,
		Data4: [8]byte{0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd},
	}
	sourceGuardLayerOutboundIPv6 = windows.GUID{
		Data1: 0xa3b3ab6b, Data2: 0x3564, Data3: 0x488c,
		Data4: [8]byte{0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63},
	}
	sourceGuardConditionLocalAddress = windows.GUID{
		Data1: 0xd9ee00de, Data2: 0xc1ef, Data3: 0x4617,
		Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57},
	}
	sourceGuardConditionInterfaceIndex = windows.GUID{
		Data1: 0x667fd755, Data2: 0xd695, Data3: 0x434a,
		Data4: [8]byte{0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc},
	}
)

type windowsSourceGuardAPI interface {
	openEngine(*sourceGuardSession0) (windows.Handle, error)
	closeEngine(windows.Handle) error
	addSubLayer(windows.Handle, *sourceGuardSubLayer0) error
	deleteSubLayer(windows.Handle, *windows.GUID) error
	addFilter(windows.Handle, *sourceGuardFilter0) (uint64, error)
	deleteFilter(windows.Handle, uint64) error
}

type windowsSourceGuardSystemAPI struct{}

var (
	sourceGuardFWPDLL                   = windows.NewLazySystemDLL("fwpuclnt.dll")
	sourceGuardProcEngineOpen0          = sourceGuardFWPDLL.NewProc("FwpmEngineOpen0")
	sourceGuardProcEngineClose0         = sourceGuardFWPDLL.NewProc("FwpmEngineClose0")
	sourceGuardProcSubLayerAdd0         = sourceGuardFWPDLL.NewProc("FwpmSubLayerAdd0")
	sourceGuardProcSubLayerDeleteByKey0 = sourceGuardFWPDLL.NewProc("FwpmSubLayerDeleteByKey0")
	sourceGuardProcFilterAdd0           = sourceGuardFWPDLL.NewProc("FwpmFilterAdd0")
	sourceGuardProcFilterDeleteByID0    = sourceGuardFWPDLL.NewProc("FwpmFilterDeleteById0")
)

func (windowsSourceGuardSystemAPI) openEngine(
	session *sourceGuardSession0,
) (windows.Handle, error) {
	var engine windows.Handle
	status, _, _ := sourceGuardProcEngineOpen0.Call(
		0,
		uintptr(sourceGuardRPCAuthenticationNT),
		0,
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&engine)),
	)
	runtime.KeepAlive(session)
	return engine, sourceGuardStatus("open filtering engine", status)
}

func (windowsSourceGuardSystemAPI) closeEngine(engine windows.Handle) error {
	status, _, _ := sourceGuardProcEngineClose0.Call(uintptr(engine))
	return sourceGuardStatus("close filtering engine", status)
}

func (windowsSourceGuardSystemAPI) addSubLayer(
	engine windows.Handle,
	subLayer *sourceGuardSubLayer0,
) error {
	status, _, _ := sourceGuardProcSubLayerAdd0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(subLayer)),
		0,
	)
	runtime.KeepAlive(subLayer)
	return sourceGuardStatus("add fail-closed filtering sublayer", status)
}

func (windowsSourceGuardSystemAPI) deleteSubLayer(
	engine windows.Handle,
	key *windows.GUID,
) error {
	status, _, _ := sourceGuardProcSubLayerDeleteByKey0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(key)),
	)
	runtime.KeepAlive(key)
	return sourceGuardStatus("delete fail-closed filtering sublayer", status)
}

func (windowsSourceGuardSystemAPI) addFilter(
	engine windows.Handle,
	filter *sourceGuardFilter0,
) (uint64, error) {
	var id uint64
	status, _, _ := sourceGuardProcFilterAdd0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(filter)),
		0,
		uintptr(unsafe.Pointer(&id)),
	)
	runtime.KeepAlive(filter)
	return id, sourceGuardStatus("add fail-closed source filter", status)
}

func (windowsSourceGuardSystemAPI) deleteFilter(engine windows.Handle, id uint64) error {
	status, _, _ := sourceGuardProcFilterDeleteByID0.Call(uintptr(engine), uintptr(id))
	return sourceGuardStatus("delete fail-closed source filter", status)
}

func sourceGuardStatus(operation string, status uintptr) error {
	if status == 0 {
		return nil
	}
	code := uint32(status)
	return fmt.Errorf("%s: WFP status 0x%08X: %w", operation, code, windows.Errno(code))
}

type windowsSourceGuard struct {
	mu          sync.Mutex
	api         windowsSourceGuardAPI
	engine      windows.Handle
	subLayerKey windows.GUID
	subLayer    bool
	filterIDs   []uint64
	closed      bool
}

func installWindowsSourceGuard(
	config ChildSAConfig,
	interfaceIndex uint32,
) (windowsSourceGuardHandle, error) {
	return installWindowsSourceGuardWithAPI(
		config,
		interfaceIndex,
		windowsSourceGuardSystemAPI{},
	)
}

func installWindowsSourceGuardWithAPI(
	config ChildSAConfig,
	interfaceIndex uint32,
	api windowsSourceGuardAPI,
) (result *windowsSourceGuard, resultErr error) {
	if interfaceIndex == 0 {
		return nil, errors.New("Wintun interface index is zero")
	}
	if innerIPv4 := canonicalRouteIP(config.InnerLocalIPv4); innerIPv4 == nil &&
		canonicalRouteIP(config.InnerLocalIPv6) == nil {
		return nil, errors.New("no assigned inner address for source guard")
	}
	subLayerKey, err := windowsDeterministicGUID("wintun-source-guard", config.DeviceID)
	if err != nil {
		return nil, err
	}
	handle := &windowsSourceGuard{api: api, subLayerKey: subLayerKey}
	session := sourceGuardSession0{flags: sourceGuardSessionFlagDynamic}
	handle.engine, err = api.openEngine(&session)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			if cleanupErr := closeAbandonedWindowsSourceGuard(handle); cleanupErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("roll back Windows source guard: %w", cleanupErr),
				)
			}
		}
	}()

	name, err := windows.UTF16FromString("VoCat Wintun source guard")
	if err != nil {
		return nil, err
	}
	description, err := windows.UTF16FromString(
		"Blocks SWu inner-source traffic unless it exits through the owning Wintun interface",
	)
	if err != nil {
		return nil, err
	}
	subLayer := sourceGuardSubLayer0{
		subLayerKey: subLayerKey,
		displayData: sourceGuardDisplayData0{
			name:        &name[0],
			description: &description[0],
		},
		weight: sourceGuardSubLayerWeight,
	}
	if err := api.addSubLayer(handle.engine, &subLayer); err != nil {
		return nil, err
	}
	runtime.KeepAlive(name)
	runtime.KeepAlive(description)
	handle.subLayer = true

	for _, address := range []net.IP{config.InnerLocalIPv4, config.InnerLocalIPv6} {
		if canonicalRouteIP(address) == nil {
			continue
		}
		material, buildErr := buildWindowsSourceGuardFilter(
			address,
			interfaceIndex,
			subLayerKey,
		)
		if buildErr != nil {
			return nil, buildErr
		}
		filterID, addErr := api.addFilter(handle.engine, &material.filter)
		runtime.KeepAlive(material)
		if addErr != nil {
			return nil, addErr
		}
		handle.filterIDs = append(handle.filterIDs, filterID)
	}
	cleanup = false
	return handle, nil
}

func closeAbandonedWindowsSourceGuard(guard *windowsSourceGuard) error {
	if guard == nil {
		return nil
	}
	var lastErr error
	for attempt := 1; attempt <= sourceGuardRollbackAttempts; attempt++ {
		lastErr = guard.Close()
		if lastErr == nil {
			return nil
		}
		if attempt < sourceGuardRollbackAttempts {
			time.Sleep(sourceGuardRollbackRetryDelay)
		}
	}
	return fmt.Errorf(
		"source-guard cleanup did not complete after %d bounded attempts: %w",
		sourceGuardRollbackAttempts,
		lastErr,
	)
}

type windowsSourceGuardFilterMaterial struct {
	filter         sourceGuardFilter0
	conditions     []sourceGuardFilterCondition0
	addressV6      *sourceGuardByteArray16
	interfaceIndex uint32
	weight         uint64
	name           []uint16
	description    []uint16
}

func buildWindowsSourceGuardFilter(
	innerIP net.IP,
	interfaceIndex uint32,
	subLayerKey windows.GUID,
) (*windowsSourceGuardFilterMaterial, error) {
	innerIP = canonicalRouteIP(innerIP)
	if innerIP == nil || interfaceIndex == 0 {
		return nil, errors.New("ike: invalid Windows source-guard endpoint")
	}
	material := &windowsSourceGuardFilterMaterial{
		interfaceIndex: interfaceIndex,
		weight:         ^uint64(0),
	}
	name, err := windows.UTF16FromString("VoCat block inner-source route escape")
	if err != nil {
		return nil, err
	}
	description, err := windows.UTF16FromString(
		"Fail closed when an SWu inner address is routed through a non-Wintun interface",
	)
	if err != nil {
		return nil, err
	}
	material.name = name
	material.description = description
	layer := sourceGuardLayerOutboundIPv6
	if ipv4 := innerIP.To4(); ipv4 != nil {
		layer = sourceGuardLayerOutboundIPv4
		material.conditions = append(material.conditions, sourceGuardFilterCondition0{
			fieldKey:  sourceGuardConditionLocalAddress,
			matchType: sourceGuardMatchEqual,
			conditionValue: sourceGuardValue0{
				typeID: sourceGuardUint32,
				value:  uintptr(binary.BigEndian.Uint32(ipv4)),
			},
		})
	} else {
		material.addressV6 = &sourceGuardByteArray16{}
		copy(material.addressV6.bytes[:], innerIP.To16())
		material.conditions = append(material.conditions, sourceGuardFilterCondition0{
			fieldKey:  sourceGuardConditionLocalAddress,
			matchType: sourceGuardMatchEqual,
			conditionValue: sourceGuardValue0{
				typeID: sourceGuardByteArray16Type,
				value:  uintptr(unsafe.Pointer(material.addressV6)),
			},
		})
	}
	material.conditions = append(material.conditions, sourceGuardFilterCondition0{
		fieldKey:  sourceGuardConditionInterfaceIndex,
		matchType: sourceGuardMatchNotEqual,
		conditionValue: sourceGuardValue0{
			typeID: sourceGuardUint32,
			value:  uintptr(material.interfaceIndex),
		},
	})
	material.filter = sourceGuardFilter0{
		displayData: sourceGuardDisplayData0{
			name:        &material.name[0],
			description: &material.description[0],
		},
		flags:       sourceGuardFilterClearAction,
		layerKey:    layer,
		subLayerKey: subLayerKey,
		weight: sourceGuardValue0{
			typeID: sourceGuardUint64,
			value:  uintptr(unsafe.Pointer(&material.weight)),
		},
		numFilterConditions: uint32(len(material.conditions)),
		filterCondition:     &material.conditions[0],
		action: sourceGuardAction0{
			typeID: sourceGuardActionBlock,
		},
	}
	return material, nil
}

func (guard *windowsSourceGuard) Close() error {
	if guard == nil {
		return nil
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.closed {
		return nil
	}
	var errs []error
	for index := len(guard.filterIDs) - 1; index >= 0; index-- {
		if err := guard.api.deleteFilter(guard.engine, guard.filterIDs[index]); err != nil {
			errs = append(errs, err)
			continue
		}
		guard.filterIDs = append(guard.filterIDs[:index], guard.filterIDs[index+1:]...)
	}
	if guard.subLayer {
		if err := guard.api.deleteSubLayer(guard.engine, &guard.subLayerKey); err != nil {
			errs = append(errs, err)
		} else {
			guard.subLayer = false
		}
	}
	if guard.engine != 0 {
		if err := guard.api.closeEngine(guard.engine); err != nil {
			errs = append(errs, err)
			return errors.Join(errs...)
		}
		// The dynamic WFP session removes every object still associated with
		// it. A successful engine close therefore completes cleanup even when
		// an earlier explicit delete reported a transient error.
		guard.engine = 0
		guard.filterIDs = nil
		guard.subLayer = false
	}
	guard.closed = true
	return nil
}
