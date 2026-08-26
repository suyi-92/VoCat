//go:build windows

package ike

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const windowsWintunRingCapacity = 4 << 20

type windowsUserspaceInstaller struct{}

func defaultChildSAInstaller() ChildSAInstaller {
	return windowsUserspaceInstaller{}
}

type windowsUserspaceHandle struct {
	config  ChildSAConfig
	tunnel  *espTunnel
	relay   NATTPacketRelay
	adapter *wintun.Adapter
	session wintun.Session
	luid    winipcfg.LUID

	runContext  context.Context
	cancel      context.CancelFunc
	cancelEvent windows.Handle
	wait        sync.WaitGroup
	cancelOnce  sync.Once
	closeOnce   sync.Once

	mu          sync.Mutex
	closed      bool
	terminalErr error
	failures    chan error
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
	adapter, err := openWindowsWintunAdapter(name)
	if err != nil {
		return nil, err
	}
	session, err := adapter.StartSession(windowsWintunRingCapacity)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("ike: start Wintun packet session: %w", err)
	}
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		session.End()
		_ = adapter.Close()
		return nil, fmt.Errorf("ike: create Wintun cancellation event: %w", err)
	}
	runContext, cancel := context.WithCancel(context.Background())
	handle := &windowsUserspaceHandle{
		config:      cloneChildSAConfig(config),
		tunnel:      tunnel,
		relay:       config.Relay,
		adapter:     adapter,
		session:     session,
		luid:        winipcfg.LUID(adapter.LUID()),
		runContext:  runContext,
		cancel:      cancel,
		cancelEvent: cancelEvent,
		failures:    make(chan error, 1),
	}
	if err := handle.configure(ctx); err != nil {
		cancel()
		_ = windows.SetEvent(cancelEvent)
		_ = handle.cleanupNetwork(context.Background())
		session.End()
		_ = windows.CloseHandle(cancelEvent)
		_ = adapter.Close()
		return nil, err
	}
	handle.wait.Add(2)
	go handle.copyWintunToRelay()
	go handle.copyRelayToWintun()
	return handle, nil
}

func openWindowsWintunAdapter(name string) (*wintun.Adapter, error) {
	adapter, openErr := wintun.OpenAdapter(name)
	if openErr == nil {
		return adapter, nil
	}
	adapter, createErr := wintun.CreateAdapter(name, "VoCat", nil)
	if createErr == nil {
		return adapter, nil
	}
	return nil, fmt.Errorf(
		"ike: open or create Wintun adapter: %v; %w (place the official architecture-matched wintun.dll beside vocat.exe and run as Administrator)",
		openErr,
		createErr,
	)
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
	if err := handle.luid.SetIPAddresses(addresses); err != nil {
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
			if handle.runContext.Err() == nil {
				handle.fail(fmt.Errorf("ike: allocate Wintun packet: %w", err))
			}
			return
		}
		copy(packet, cleartext)
		handle.session.SendPacket(packet)
	}
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
	handle.mu.Lock()
	if handle.closed {
		handle.mu.Unlock()
		return nil
	}
	handle.closed = true
	handle.mu.Unlock()

	handle.cancelRun()
	handle.wait.Wait()
	return handle.closeResources(ctx)
}

func (handle *windowsUserspaceHandle) closeResources(ctx context.Context) error {
	var result error
	handle.closeOnce.Do(func() {
		var errs []error
		if err := handle.cleanupNetwork(ctx); err != nil {
			errs = append(errs, err)
		}
		handle.session.End()
		if handle.cancelEvent != 0 {
			if err := windows.CloseHandle(handle.cancelEvent); err != nil {
				errs = append(errs, fmt.Errorf("ike: close Wintun cancellation event: %w", err))
			}
			handle.cancelEvent = 0
		}
		if handle.adapter != nil {
			if err := normalizeWintunCloseError(handle.adapter.Close()); err != nil {
				errs = append(errs, fmt.Errorf("ike: close Wintun adapter: %w", err))
			}
			handle.adapter = nil
		}
		result = errors.Join(errs...)
	})
	return result
}

func normalizeWintunCloseError(err error) error {
	if err == nil {
		return nil
	}
	// The legacy official Go wrapper treats WintunCloseAdapter's void return
	// register as a BOOL. Some DLL/compiler combinations therefore surface a
	// boxed syscall.Errno(0) even though the close completed successfully.
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == windows.ERROR_SUCCESS {
		return nil
	}
	return err
}

func (handle *windowsUserspaceHandle) cleanupNetwork(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := contextErrorForWindowsTunnel(ctx); err != nil {
		return err
	}
	var errs []error
	if err := handle.luid.FlushRoutes(windows.AF_UNSPEC); err != nil {
		errs = append(errs, fmt.Errorf("ike: remove Wintun routes: %w", err))
	}
	if err := handle.luid.FlushIPAddresses(windows.AF_UNSPEC); err != nil {
		errs = append(errs, fmt.Errorf("ike: remove Wintun addresses: %w", err))
	}
	return errors.Join(errs...)
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
