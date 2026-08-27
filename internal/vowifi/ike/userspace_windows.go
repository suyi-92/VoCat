//go:build windows

package ike

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"vocat/internal/wintunsecure"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	windowsWintunRingCapacity        = 4 << 20
	windowsUserspaceRollbackAttempts = 3
	windowsUserspaceRollbackDelay    = 25 * time.Millisecond
)

type windowsUserspaceInstaller struct{}

func defaultChildSAInstaller() ChildSAInstaller {
	return windowsUserspaceInstaller{}
}

type windowsUserspaceHandle struct {
	config      ChildSAConfig
	tunnel      *espTunnel
	relay       NATTPacketRelay
	adapter     windowsWintunAdapterCloser
	session     wintun.Session
	luid        winipcfg.LUID
	sourceGuard windowsSourceGuardHandle

	runContext  context.Context
	cancel      context.CancelFunc
	cancelEvent windows.Handle
	wait        sync.WaitGroup
	cancelOnce  sync.Once
	cleanupMu   sync.Mutex

	mu            sync.Mutex
	closed        bool
	terminalErr   error
	failures      chan error
	dynamicRoutes map[string]windowsHostRoute
	sessionEnded  bool
	networkClean  bool
}

// windowsWintunAdapterCloser deliberately exposes only Close. The upstream
// wrapper declares the void WintunCloseAdapter export as BOOL and can return a
// synthetic error sourced from an undefined return register. Once Close has
// been called, the opaque handle must never be handed to the DLL again.
type windowsWintunAdapterCloser interface {
	Close() error
}

type windowsSourceGuardHandle interface {
	Close() error
}

type windowsHostRoute struct {
	destination netip.Prefix
	nextHop     netip.Addr
}

type windowsInterfaceAddress struct {
	luid   winipcfg.LUID
	prefix netip.Prefix
}

type windowsInterfaceAddressAPI interface {
	List() ([]windowsInterfaceAddress, error)
	Delete(windowsInterfaceAddress) error
}

type systemWindowsInterfaceAddressAPI struct{}

func (systemWindowsInterfaceAddressAPI) List() ([]windowsInterfaceAddress, error) {
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	addresses := make([]windowsInterfaceAddress, 0, len(rows))
	for i := range rows {
		address := rows[i].Address.Addr()
		if !address.IsValid() {
			return nil, errors.New("invalid address in Windows unicast address table")
		}
		addresses = append(addresses, windowsInterfaceAddress{
			luid:   rows[i].InterfaceLUID,
			prefix: netip.PrefixFrom(address, address.BitLen()),
		})
	}
	return addresses, nil
}

func (systemWindowsInterfaceAddressAPI) Delete(address windowsInterfaceAddress) error {
	return address.luid.DeleteIPAddress(address.prefix)
}

func (*windowsUserspaceHandle) DataplaneMode() string { return "userspace" }

func (windowsUserspaceInstaller) Install(ctx context.Context, config ChildSAConfig) (ChildSAHandle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if config.Relay == nil {
		return nil, errors.New("ike: Windows user-space ESP requires a NAT-T packet relay")
	}
	if !config.UDPEncapsulation {
		return nil, errors.New("ike: Windows user-space ESP currently requires negotiated UDP encapsulation")
	}
	if len(config.PCSCF) == 0 {
		return nil, errors.New("ike: Windows user-space ESP requires at least one negotiated P-CSCF address")
	}
	if err := validateUserspaceRoutes(config); err != nil {
		return nil, err
	}
	tunnel, err := newESPTunnel(config, nil)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(config.Name)
	if name == "" || len(name) > wintun.AdapterNameMax {
		return nil, errors.New("ike: Wintun adapter name is invalid")
	}
	adapter, err := openWindowsWintunAdapter(name, config.DeviceID)
	if err != nil {
		return nil, err
	}
	luid := winipcfg.LUID(adapter.LUID())
	// A named Wintun adapter is persistent and may retain addresses from an
	// interrupted prior run. Clear and verify them before StartSession brings
	// the adapter up; otherwise an old inner address would predate and evade the
	// source guard built for this CHILD_SA.
	addressesSafe, addressErr := removeAndVerifyWindowsInterfaceAddresses(
		systemWindowsInterfaceAddressAPI{},
		luid,
	)
	if addressErr != nil || !addressesSafe {
		if addressErr == nil {
			addressErr = errors.New("one or more stale Wintun addresses remain")
		}
		return nil, rollbackAbandonedWindowsUserspaceHandle(
			fmt.Errorf("ike: clear stale Wintun addresses before session start: %w", addressErr),
			&windowsUserspaceHandle{adapter: adapter, luid: luid, sessionEnded: true},
		)
	}
	interfaceRow, err := luid.Interface()
	if err != nil {
		return nil, rollbackAbandonedWindowsUserspaceHandle(
			fmt.Errorf("ike: read Wintun interface index: %w", err),
			&windowsUserspaceHandle{adapter: adapter, luid: luid, sessionEnded: true, networkClean: true},
		)
	}
	if interfaceRow.InterfaceIndex == 0 {
		return nil, rollbackAbandonedWindowsUserspaceHandle(
			errors.New("ike: Wintun interface index is zero"),
			&windowsUserspaceHandle{adapter: adapter, luid: luid, sessionEnded: true, networkClean: true},
		)
	}
	// Install the block policy before StartSession can bring the adapter up.
	// The interface-index condition observes the actual outbound interface;
	// IP_LOCAL_INTERFACE would only identify the source address owner.
	guard, err := installWindowsSourceGuard(config, interfaceRow.InterfaceIndex)
	if err != nil {
		return nil, rollbackAbandonedWindowsUserspaceHandle(
			fmt.Errorf("ike: install fail-closed Windows source guard: %w", err),
			&windowsUserspaceHandle{adapter: adapter, luid: luid, sessionEnded: true, networkClean: true},
		)
	}
	session, err := adapter.StartSession(windowsWintunRingCapacity)
	if err != nil {
		return nil, rollbackAbandonedWindowsUserspaceHandle(
			fmt.Errorf("ike: start Wintun packet session: %w", err),
			&windowsUserspaceHandle{
				adapter: adapter, luid: luid, sourceGuard: guard,
				sessionEnded: true, networkClean: true,
			},
		)
	}
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, rollbackAbandonedWindowsUserspaceHandle(
			fmt.Errorf("ike: create Wintun cancellation event: %w", err),
			&windowsUserspaceHandle{
				adapter: adapter, session: session, luid: luid, sourceGuard: guard,
				networkClean: true,
			},
		)
	}
	runContext, cancel := context.WithCancel(context.Background())
	handle := &windowsUserspaceHandle{
		config:        cloneChildSAConfig(config),
		tunnel:        tunnel,
		relay:         config.Relay,
		adapter:       adapter,
		session:       session,
		luid:          luid,
		sourceGuard:   guard,
		runContext:    runContext,
		cancel:        cancel,
		cancelEvent:   cancelEvent,
		failures:      make(chan error, 1),
		dynamicRoutes: make(map[string]windowsHostRoute),
	}
	if err := handle.configure(ctx); err != nil {
		handle.cancelRun()
		return nil, rollbackAbandonedWindowsUserspaceHandle(err, handle)
	}
	handle.wait.Add(2)
	go handle.copyWintunToRelay()
	go handle.copyRelayToWintun()
	return handle, nil
}

func openWindowsWintunAdapter(name string, deviceID string) (*wintun.Adapter, error) {
	if _, err := wintunsecure.EnsureLoaded(); err != nil {
		return nil, fmt.Errorf("ike: securely load wintun.dll: %w", err)
	}
	adapter, openErr := wintun.OpenAdapter(name)
	if openErr == nil {
		return adapter, nil
	}
	requestedGUID, guidErr := windowsWintunAdapterGUID(deviceID)
	if guidErr != nil {
		return nil, guidErr
	}
	adapter, createErr := wintun.CreateAdapter(name, "VoCat", &requestedGUID)
	if createErr == nil {
		return adapter, nil
	}
	return nil, fmt.Errorf(
		"ike: open or create Wintun adapter: %v; %w (place the official architecture-matched wintun.dll beside vocat.exe and run as Administrator)",
		openErr,
		createErr,
	)
}

func windowsWintunAdapterGUID(deviceID string) (windows.GUID, error) {
	return windowsDeterministicGUID("wintun-adapter", deviceID)
}

func windowsDeterministicGUID(namespace string, identity string) (windows.GUID, error) {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	identity = strings.ToLower(strings.TrimSpace(identity))
	if namespace == "" || identity == "" {
		return windows.GUID{}, errors.New("ike: stable identity is required for deterministic Windows GUID")
	}
	digest := sha256.Sum256([]byte("vocat:" + namespace + ":v1:" + identity))
	// UUIDv8 marks this as an application-defined deterministic UUID while the
	// RFC 4122 variant keeps it acceptable to Windows APIs expecting a GUID.
	digest[6] = digest[6]&0x0f | 0x80
	digest[8] = digest[8]&0x3f | 0x80
	result := windows.GUID{
		Data1: binary.BigEndian.Uint32(digest[0:4]),
		Data2: binary.BigEndian.Uint16(digest[4:6]),
		Data3: binary.BigEndian.Uint16(digest[6:8]),
	}
	copy(result.Data4[:], digest[8:16])
	return result, nil
}

func (handle *windowsUserspaceHandle) configure(ctx context.Context) error {
	addresses, routes, families, err := windowsTunnelNetworkPlan(handle.config)
	if err != nil {
		return err
	}
	for _, family := range families {
		row, rowErr := handle.luid.IPInterface(family)
		if rowErr != nil {
			return fmt.Errorf("ike: read Wintun IP interface settings: %w", rowErr)
		}
		row.NLMTU = userspaceTunnelMTU
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		row.DadTransmits = 0
		row.ManagedAddressConfigurationSupported = false
		row.OtherStatefulConfigurationSupported = false
		row.UseAutomaticMetric = false
		row.Metric = 0
		row.DisableDefaultRoutes = true
		if rowErr = row.Set(); rowErr != nil {
			return fmt.Errorf("ike: configure Wintun IP interface: %w", rowErr)
		}
	}
	if err := contextErrorForWindowsTunnel(ctx); err != nil {
		return err
	}
	if err := handle.luid.AddIPAddresses(addresses); err != nil {
		return fmt.Errorf("ike: assign Wintun inner addresses: %w", err)
	}
	if err := handle.luid.SetRoutes(routes); err != nil {
		return fmt.Errorf("ike: install Wintun P-CSCF host routes: %w", err)
	}
	return contextErrorForWindowsTunnel(ctx)
}

func windowsTunnelNetworkPlan(config ChildSAConfig) (
	addresses []netip.Prefix,
	routes []*winipcfg.RouteData,
	families []winipcfg.AddressFamily,
	err error,
) {
	seenFamilies := make(map[winipcfg.AddressFamily]bool)
	appendAddress := func(ip net.IP) error {
		address, convertErr := windowsNetIP(ip)
		if convertErr != nil {
			return convertErr
		}
		bits := 128
		family := winipcfg.AddressFamily(windows.AF_INET6)
		if address.Is4() {
			bits = 32
			family = windows.AF_INET
		}
		addresses = append(addresses, netip.PrefixFrom(address, bits))
		if !seenFamilies[family] {
			families = append(families, family)
			seenFamilies[family] = true
		}
		return nil
	}
	if config.InnerLocalIPv4 != nil {
		if err = appendAddress(config.InnerLocalIPv4); err != nil {
			return nil, nil, nil, fmt.Errorf("ike: convert assigned Windows IPv4 address: %w", err)
		}
	}
	if config.InnerLocalIPv6 != nil {
		if err = appendAddress(config.InnerLocalIPv6); err != nil {
			return nil, nil, nil, fmt.Errorf("ike: convert assigned Windows IPv6 address: %w", err)
		}
	}
	seenRoutes := make(map[string]bool)
	for _, ip := range config.PCSCF {
		address, convertErr := windowsNetIP(ip)
		if convertErr != nil {
			return nil, nil, nil, fmt.Errorf("ike: convert Windows P-CSCF route: %w", convertErr)
		}
		key := address.String()
		if seenRoutes[key] {
			continue
		}
		bits := 128
		nextHop := netip.IPv6Unspecified()
		family := winipcfg.AddressFamily(windows.AF_INET6)
		if address.Is4() {
			bits = 32
			nextHop = netip.IPv4Unspecified()
			family = windows.AF_INET
		}
		if !seenFamilies[family] {
			continue
		}
		seenRoutes[key] = true
		routes = append(routes, &winipcfg.RouteData{
			Destination: netip.PrefixFrom(address, bits),
			NextHop:     nextHop,
			Metric:      0,
		})
	}
	return addresses, routes, families, nil
}

func windowsNetIP(ip net.IP) (netip.Addr, error) {
	if ipv4 := ip.To4(); ipv4 != nil {
		var value [4]byte
		copy(value[:], ipv4)
		return netip.AddrFrom4(value), nil
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		var value [16]byte
		copy(value[:], ipv6)
		return netip.AddrFrom16(value), nil
	}
	return netip.Addr{}, errors.New("invalid IP address")
}

func (handle *windowsUserspaceHandle) AddRoute(ctx context.Context, destination net.IP) error {
	route, key, err := windowsDynamicHostRoute(handle.config, destination)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextErrorForWindowsTunnel(ctx); err != nil {
		return err
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return errors.New("ike: Windows user-space CHILD_SA is closed")
	}
	if isConfiguredPCSCF(handle.config, destination) {
		return nil
	}
	if _, exists := handle.dynamicRoutes[key]; exists {
		return nil
	}
	if err := handle.luid.AddRoute(route.destination, route.nextHop, 0); err != nil {
		return fmt.Errorf("ike: install dynamic Wintun media host route: %w", err)
	}
	handle.dynamicRoutes[key] = route
	return nil
}

func (handle *windowsUserspaceHandle) RemoveRoute(ctx context.Context, destination net.IP) error {
	destination = canonicalRouteIP(destination)
	if destination == nil {
		return errors.New("ike: dynamic Wintun route destination is invalid")
	}
	key := destination.String()
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil
	}
	if isConfiguredPCSCF(handle.config, destination) {
		return nil
	}
	route, exists := handle.dynamicRoutes[key]
	if !exists {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextErrorForWindowsTunnel(ctx); err != nil {
		return err
	}
	if err := normalizeWindowsRouteDeleteError(
		handle.luid.DeleteRoute(route.destination, route.nextHop),
	); err != nil {
		return fmt.Errorf("ike: remove dynamic Wintun media host route: %w", err)
	}
	delete(handle.dynamicRoutes, key)
	return nil
}

func windowsDynamicHostRoute(
	config ChildSAConfig,
	destination net.IP,
) (windowsHostRoute, string, error) {
	address, err := windowsNetIP(destination)
	if err != nil || address.IsUnspecified() || address.IsMulticast() {
		return windowsHostRoute{}, "", errors.New("ike: dynamic Wintun route destination is invalid")
	}
	bits := 128
	nextHop := netip.IPv6Unspecified()
	if address.Is4() {
		if canonicalRouteIP(config.InnerLocalIPv4) == nil {
			return windowsHostRoute{}, "", errors.New("ike: no assigned inner IPv4 address for Wintun media route")
		}
		bits = 32
		nextHop = netip.IPv4Unspecified()
	} else if canonicalRouteIP(config.InnerLocalIPv6) == nil {
		return windowsHostRoute{}, "", errors.New("ike: no assigned inner IPv6 address for Wintun media route")
	}
	return windowsHostRoute{
		destination: netip.PrefixFrom(address, bits),
		nextHop:     nextHop,
	}, address.String(), nil
}

func normalizeWindowsRouteDeleteError(err error) error {
	if err == nil || errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return err
}

func (handle *windowsUserspaceHandle) copyWintunToRelay() {
	defer handle.wait.Done()
	for {
		packet, err := handle.receiveWintunPacket()
		if err != nil {
			if handle.runContext.Err() == nil {
				handle.fail(fmt.Errorf("ike: read Wintun packet: %w", err))
			}
			return
		}
		protected, protectErr := handle.tunnel.seal(packet)
		handle.session.ReleaseReceivePacket(packet)
		if protectErr != nil {
			if errors.Is(protectErr, errESPPolicyDrop) {
				continue
			}
			handle.fail(protectErr)
			return
		}
		if err := handle.relay.SendESP(handle.runContext, protected); err != nil {
			if handle.runContext.Err() == nil {
				handle.fail(fmt.Errorf("ike: relay outbound ESP: %w", err))
			}
			return
		}
	}
}

func (handle *windowsUserspaceHandle) receiveWintunPacket() ([]byte, error) {
	for {
		if err := handle.runContext.Err(); err != nil {
			return nil, err
		}
		packet, err := handle.session.ReceivePacket()
		if err == nil {
			if len(packet) == 0 {
				return nil, errors.New("Wintun returned an empty packet")
			}
			return packet, nil
		}
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return nil, err
		}
		event, waitErr := windows.WaitForMultipleObjects(
			[]windows.Handle{handle.session.ReadWaitEvent(), handle.cancelEvent},
			false,
			windows.INFINITE,
		)
		if waitErr != nil {
			return nil, waitErr
		}
		switch event {
		case windows.WAIT_OBJECT_0:
			continue
		case windows.WAIT_OBJECT_0 + 1:
			return nil, handle.runContext.Err()
		default:
			return nil, fmt.Errorf("unexpected Wintun wait result 0x%08X", event)
		}
	}
}

func (handle *windowsUserspaceHandle) copyRelayToWintun() {
	defer handle.wait.Done()
	buffer := make([]byte, wintun.PacketSizeMax)
	for {
		count, err := handle.relay.ReceiveESP(handle.runContext, buffer)
		if err != nil {
			if handle.runContext.Err() == nil {
				handle.fail(fmt.Errorf("ike: relay inbound ESP: %w", err))
			}
			return
		}
		cleartext, err := handle.tunnel.open(buffer[:count])
		if err != nil {
			continue
		}
		packet, err := handle.session.AllocateSendPacket(len(cleartext))
		if err != nil {
			if transientWintunSendError(err) {
				// A full ring is bounded packet loss/backpressure, not a terminal
				// CHILD_SA failure. Drop this decrypted packet and keep receiving.
				continue
			}
			if handle.runContext.Err() == nil {
				handle.fail(fmt.Errorf("ike: allocate Wintun packet: %w", err))
			}
			return
		}
		copy(packet, cleartext)
		handle.session.SendPacket(packet)
	}
}

func transientWintunSendError(err error) bool {
	return errors.Is(err, windows.ERROR_BUFFER_OVERFLOW)
}

func (handle *windowsUserspaceHandle) fail(err error) {
	handle.mu.Lock()
	notify := false
	if handle.terminalErr == nil {
		handle.terminalErr = err
		notify = true
	}
	handle.mu.Unlock()
	if notify {
		select {
		case handle.failures <- err:
		default:
		}
	}
	handle.cancelRun()
}

func (handle *windowsUserspaceHandle) Failures() <-chan error {
	return handle.failures
}

func (handle *windowsUserspaceHandle) cancelRun() {
	handle.cancelOnce.Do(func() {
		handle.cancel()
		_ = windows.SetEvent(handle.cancelEvent)
	})
}

func (handle *windowsUserspaceHandle) Close(ctx context.Context) error {
	if handle == nil {
		return nil
	}
	handle.mu.Lock()
	handle.closed = true
	handle.mu.Unlock()

	handle.cancelRun()
	handle.wait.Wait()
	return handle.closeResources(ctx)
}

func (handle *windowsUserspaceHandle) closeResources(ctx context.Context) error {
	handle.cleanupMu.Lock()
	defer handle.cleanupMu.Unlock()

	var errs []error
	if !handle.sessionEnded {
		handle.session.End()
		handle.sessionEnded = true
	}
	innerAddressesSafe := handle.networkClean
	if !handle.networkClean {
		var networkErr error
		innerAddressesSafe, networkErr = handle.cleanupNetwork(ctx)
		if networkErr != nil {
			errs = append(errs, networkErr)
		} else if innerAddressesSafe {
			handle.networkClean = true
		}
	}
	if handle.cancelEvent != 0 {
		if err := windows.CloseHandle(handle.cancelEvent); err != nil {
			errs = append(errs, fmt.Errorf("ike: close Wintun cancellation event: %w", err))
		} else {
			handle.cancelEvent = 0
		}
	}
	if handle.adapter != nil {
		adapter := handle.adapter
		handle.adapter = nil
		// WintunCloseAdapter is void. The legacy wrapper's error is ABI noise,
		// and retrying with this already-consumed opaque handle risks a UAF.
		_ = adapter.Close()
	}
	// WintunCloseAdapter only releases the adapter handle, so filter teardown
	// must depend on confirmed address removal rather than wrapper return state. Retain a
	// guard whose close failed so a later Close call can finish cleanup.
	if handle.sourceGuard != nil && innerAddressesSafe {
		if err := handle.sourceGuard.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ike: remove fail-closed Windows source guard: %w", err))
		} else {
			handle.sourceGuard = nil
		}
	}
	return errors.Join(errs...)
}

func rollbackAbandonedWindowsUserspaceHandle(cause error, handle *windowsUserspaceHandle) error {
	cleanupErr := closeAbandonedWindowsUserspaceHandle(handle)
	if cleanupErr == nil {
		return cause
	}
	return errors.Join(cause, fmt.Errorf("ike: roll back abandoned Windows user-space tunnel: %w", cleanupErr))
}

func closeAbandonedWindowsUserspaceHandle(handle *windowsUserspaceHandle) error {
	if handle == nil {
		return nil
	}
	var lastErr error
	for attempt := 1; attempt <= windowsUserspaceRollbackAttempts; attempt++ {
		lastErr = handle.closeResources(context.Background())
		if lastErr == nil {
			return nil
		}
		if attempt < windowsUserspaceRollbackAttempts {
			time.Sleep(windowsUserspaceRollbackDelay)
		}
	}
	return fmt.Errorf(
		"cleanup did not complete after %d bounded attempts: %w",
		windowsUserspaceRollbackAttempts,
		lastErr,
	)
}

func (handle *windowsUserspaceHandle) cleanupNetwork(ctx context.Context) (bool, error) {
	if ctx == nil || ctx.Err() != nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := contextErrorForWindowsTunnel(ctx); err != nil {
		return false, err
	}
	var errs []error
	if err := handle.luid.FlushRoutes(windows.AF_UNSPEC); err != nil {
		errs = append(errs, fmt.Errorf("ike: remove Wintun routes: %w", err))
	}
	innerAddressesSafe, addressErr := removeAndVerifyWindowsInterfaceAddresses(
		systemWindowsInterfaceAddressAPI{},
		handle.luid,
	)
	if addressErr != nil {
		errs = append(errs, fmt.Errorf("ike: remove and verify Wintun addresses: %w", addressErr))
	}
	return innerAddressesSafe, errors.Join(errs...)
}

func removeAndVerifyWindowsInterfaceAddresses(
	api windowsInterfaceAddressAPI,
	luid winipcfg.LUID,
) (bool, error) {
	addresses, err := api.List()
	if err != nil {
		return false, fmt.Errorf("list Windows interface addresses before removal: %w", err)
	}

	var errs []error
	for _, address := range addresses {
		if address.luid != luid {
			continue
		}
		if err := api.Delete(address); err != nil {
			errs = append(errs, fmt.Errorf("delete Windows interface address %s: %w", address.prefix, err))
		}
	}

	remaining, err := api.List()
	if err != nil {
		errs = append(errs, fmt.Errorf("verify Windows interface addresses after removal: %w", err))
		return false, errors.Join(errs...)
	}
	var residual []netip.Prefix
	for _, address := range remaining {
		if address.luid == luid {
			residual = append(residual, address.prefix)
		}
	}
	if len(residual) != 0 {
		errs = append(errs, fmt.Errorf("Windows interface still has addresses after removal: %v", residual))
		return false, errors.Join(errs...)
	}
	return true, errors.Join(errs...)
}

func contextErrorForWindowsTunnel(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

var _ ChildSAInstaller = windowsUserspaceInstaller{}
var _ ChildSAHandle = (*windowsUserspaceHandle)(nil)
var _ DataplaneEvidence = (*windowsUserspaceHandle)(nil)
var _ DataplaneFailureNotifier = (*windowsUserspaceHandle)(nil)
var _ ChildSADynamicRouteManager = (*windowsUserspaceHandle)(nil)
