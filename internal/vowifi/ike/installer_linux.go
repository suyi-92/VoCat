//go:build linux

package ike

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"vocat/internal/vowifi"
)

type linuxXFRMInstaller struct {
	ipCommand string
}

func defaultChildSAInstaller() ChildSAInstaller {
	return linuxChildSAInstallerRouter{ipCommand: "ip"}
}

type linuxChildSAInstallerRouter struct {
	ipCommand string
}

func (router linuxChildSAInstallerRouter) Install(ctx context.Context, config ChildSAConfig) (ChildSAHandle, error) {
	if config.ProxyMode == vowifi.ProxyModeSOCKS5 || config.UDPEncapsulation {
		return (linuxUserspaceInstaller{ipCommand: router.ipCommand}).Install(ctx, config)
	}
	return (linuxXFRMInstaller{ipCommand: router.ipCommand}).Install(ctx, config)
}

type linuxXFRMHandle struct {
	mu                  sync.Mutex
	ipCommand           string
	config              ChildSAConfig
	reqid               string
	closed              bool
	interfaceCreated    bool
	cleanup             []ipCleanupCommand
	installedPolicyKeys map[string]bool
}

const (
	linuxXFRMBlockPriority          = 30000
	linuxXFRMRollbackAttempts       = 3
	linuxXFRMRollbackAttemptTimeout = 2 * time.Second
	linuxXFRMRollbackRetryDelay     = 25 * time.Millisecond
)

type linuxXFRMPolicyCommand struct {
	add    []string
	remove []string
}

func (*linuxXFRMHandle) DataplaneMode() string { return "xfrm" }

func (installer linuxXFRMInstaller) Install(ctx context.Context, config ChildSAConfig) (ChildSAHandle, error) {
	if config.ProxyMode == vowifi.ProxyModeSOCKS5 || config.UDPEncapsulation {
		return nil, errors.New("NAT-T and SOCKS5 require a user-space ESP/TUN installer using NATTPacketRelay; kernel XFRM cannot own the user-space UDP association")
	}
	if config.OuterLocal == nil || config.OuterRemote == nil {
		return nil, errors.New("outer IP addresses are required")
	}
	if config.InboundSPI == 0 || config.OutboundSPI == 0 {
		return nil, errors.New("ESP SPIs must be nonzero")
	}
	command := installer.ipCommand
	if command == "" {
		command = "ip"
	}
	if _, err := exec.LookPath(command); err != nil {
		return nil, errors.New("Linux iproute2 is required to install the CHILD_SA")
	}
	handle := &linuxXFRMHandle{
		ipCommand:           command,
		config:              cloneChildSAConfig(config),
		reqid:               strconv.FormatUint(uint64(config.InboundSPI), 10),
		installedPolicyKeys: make(map[string]bool),
	}
	if err := handle.install(ctx); err != nil {
		return nil, errors.Join(err, handle.rollbackInstall())
	}
	return handle, nil
}

func (handle *linuxXFRMHandle) install(ctx context.Context) error {
	config := handle.config
	if err := handle.run(ctx, "create tunnel interface", "link", "add", config.Name, "type", "dummy"); err != nil {
		return err
	}
	handle.interfaceCreated = true
	// Kernel XFRM lets packets that miss every protect policy continue through
	// ordinary routing. Install an inner-source catch-all block before assigning
	// the address, so even an explicit bind cannot expose it during setup. A
	// fully broad protect policy already covers every packet from that address
	// and cannot coexist with an identical block selector, so no redundant guard
	// is installed for that family; the dummy interface remains down until the
	// broad policy is present.
	for _, guard := range linuxXFRMOutboundGuardCommands(config) {
		if err := handle.installPolicyCommand(ctx, "install outbound XFRM source guard", guard); err != nil {
			return err
		}
	}
	outboundState := handle.stateArguments(
		config.OuterLocal, config.OuterRemote, config.OutboundSPI,
		config.OutboundEncKey, config.OutboundAuthKey,
	)
	if err := handle.runAndRecord(
		ctx,
		"install outbound ESP state",
		append([]string{"xfrm", "state", "add"}, outboundState...),
		ipCleanupCommand{
			operation: "delete outbound ESP state",
			arguments: append([]string{"xfrm", "state", "delete"},
				handle.stateDeleteSelector(config.OuterLocal, config.OuterRemote, config.OutboundSPI)...),
		},
	); err != nil {
		return err
	}
	inboundState := handle.stateArguments(
		config.OuterRemote, config.OuterLocal, config.InboundSPI,
		config.InboundEncKey, config.InboundAuthKey,
	)
	if err := handle.runAndRecord(
		ctx,
		"install inbound ESP state",
		append([]string{"xfrm", "state", "add"}, inboundState...),
		ipCleanupCommand{
			operation: "delete inbound ESP state",
			arguments: append([]string{"xfrm", "state", "delete"},
				handle.stateDeleteSelector(config.OuterRemote, config.OuterLocal, config.InboundSPI)...),
		},
	); err != nil {
		return err
	}
	for _, initiator := range config.InitiatorSelectors {
		for _, responder := range config.ResponderSelectors {
			if (initiator.StartIP.To4() == nil) != (responder.StartIP.To4() == nil) {
				continue
			}
			if err := handle.installPolicyPair(ctx, initiator, responder); err != nil {
				return err
			}
		}
	}
	// Assign inner addresses only after every source is covered by either a
	// catch-all block or a fully broad protect policy. A down dummy still makes
	// an address locally bindable, so link state alone is not a sufficient guard.
	if config.InnerLocalIPv4 != nil {
		if err := handle.run(ctx, "assign tunnel IPv4 address", "address", "add", config.InnerLocalIPv4.String()+"/32", "dev", config.Name); err != nil {
			return err
		}
	}
	if config.InnerLocalIPv6 != nil {
		if err := handle.run(ctx, "assign tunnel IPv6 address", "-6", "address", "add", fmt.Sprintf("%s/%d", config.InnerLocalIPv6.String(), config.InnerIPv6Prefix), "dev", config.Name); err != nil {
			return err
		}
	}
	// The interface becomes usable only after both the catch-all guard and every
	// negotiated protect policy are present.
	return handle.run(ctx, "enable tunnel interface", "link", "set", "dev", config.Name, "up")
}

func (handle *linuxXFRMHandle) installPolicyPair(
	ctx context.Context,
	initiator trafficSelector,
	responder trafficSelector,
) error {
	commands, err := handle.policyPairCommands(initiator, responder)
	if err != nil {
		return err
	}
	operations := []string{
		"install outbound ESP policy",
		"install inbound ESP policy",
	}
	for index, command := range commands {
		if err := handle.installPolicyCommand(ctx, operations[index], command); err != nil {
			return err
		}
	}
	return nil
}

func (handle *linuxXFRMHandle) policyPairCommands(
	initiator trafficSelector,
	responder trafficSelector,
) ([]linuxXFRMPolicyCommand, error) {
	initiatorPrefix, err := selectorPrefix(initiator)
	if err != nil {
		return nil, err
	}
	responderPrefix, err := selectorPrefix(responder)
	if err != nil {
		return nil, err
	}
	if initiator.IPProtocol != responder.IPProtocol &&
		initiator.IPProtocol != 0 && responder.IPProtocol != 0 {
		return nil, errors.New("negotiated traffic selectors use conflicting IP protocols")
	}
	protocol := initiator.IPProtocol
	if protocol == 0 {
		protocol = responder.IPProtocol
	}
	if protocol == 0 && (!selectorUsesAllPorts(initiator) || !selectorUsesAllPorts(responder)) {
		return nil, errors.New("negotiated port selector requires a specific IP protocol")
	}
	family := "-4"
	if initiator.StartIP.To4() == nil {
		family = "-6"
	}
	outboundSelector := []string{
		family, "xfrm", "policy", "add",
		"src", initiatorPrefix, "dst", responderPrefix,
	}
	inboundSelector := []string{
		family, "xfrm", "policy", "add",
		"src", responderPrefix, "dst", initiatorPrefix,
	}
	if protocol != 0 {
		outboundSelector = append(outboundSelector, "proto", strconv.Itoa(int(protocol)))
		inboundSelector = append(inboundSelector, "proto", strconv.Itoa(int(protocol)))
	}
	outboundSelector, err = appendSelectorPorts(outboundSelector, initiator, responder)
	if err != nil {
		return nil, err
	}
	inboundSelector, err = appendSelectorPorts(inboundSelector, responder, initiator)
	if err != nil {
		return nil, err
	}
	outboundRemove := append(replacePolicyVerb(outboundSelector, "delete"), "dir", "out")
	inboundRemove := append(replacePolicyVerb(inboundSelector, "delete"), "dir", "in")
	outbound := append(append([]string(nil), outboundSelector...), "dir", "out", "priority", "0")
	inbound := append(append([]string(nil), inboundSelector...), "dir", "in", "priority", "0")
	outbound = append(outbound,
		"tmpl", "src", handle.config.OuterLocal.String(), "dst", handle.config.OuterRemote.String(),
		"proto", "esp", "mode", "tunnel", "reqid", handle.reqid,
	)
	inbound = append(inbound,
		"tmpl", "src", handle.config.OuterRemote.String(), "dst", handle.config.OuterLocal.String(),
		"proto", "esp", "mode", "tunnel", "reqid", handle.reqid,
	)
	return []linuxXFRMPolicyCommand{
		{add: outbound, remove: outboundRemove},
		{add: inbound, remove: inboundRemove},
	}, nil
}

func replacePolicyVerb(arguments []string, verb string) []string {
	result := append([]string(nil), arguments...)
	if len(result) >= 4 {
		result[3] = verb
	}
	return result
}

func selectorUsesAllPorts(selector trafficSelector) bool {
	return selector.StartPort == 0 && selector.EndPort == 65535
}

func appendSelectorPorts(
	arguments []string,
	source trafficSelector,
	destination trafficSelector,
) ([]string, error) {
	appendPort := func(label string, start uint16, end uint16) error {
		if start == 0 && end == 65535 {
			return nil
		}
		if start != end {
			return fmt.Errorf("negotiated %s port range %d-%d cannot be represented safely by XFRM", label, start, end)
		}
		arguments = append(arguments, label, strconv.Itoa(int(start)))
		return nil
	}
	if err := appendPort("sport", source.StartPort, source.EndPort); err != nil {
		return nil, err
	}
	if err := appendPort("dport", destination.StartPort, destination.EndPort); err != nil {
		return nil, err
	}
	return arguments, nil
}

func selectorPrefix(selector trafficSelector) (string, error) {
	start := selector.StartIP
	end := selector.EndIP
	bits := 128
	if start4 := start.To4(); start4 != nil {
		start = start4
		end = end.To4()
		bits = 32
	} else {
		start = start.To16()
		end = end.To16()
	}
	if start == nil || end == nil || len(start) != len(end) {
		return "", errors.New("negotiated traffic selector IP range is invalid")
	}
	prefix := 0
	different := false
	for index := 0; index < len(start); index++ {
		for bit := 7; bit >= 0; bit-- {
			startBit := start[index] & (1 << bit)
			endBit := end[index] & (1 << bit)
			if !different && startBit == endBit {
				prefix++
				continue
			}
			different = true
			if startBit != 0 || endBit == 0 {
				return "", errors.New("negotiated traffic selector range is not a CIDR prefix")
			}
		}
	}
	network := &net.IPNet{IP: start, Mask: net.CIDRMask(prefix, bits)}
	return network.String(), nil
}

func (handle *linuxXFRMHandle) stateArguments(
	source net.IP,
	destination net.IP,
	spi uint32,
	encryptionKey []byte,
	integrityKey []byte,
) []string {
	arguments := []string{
		"src", source.String(),
		"dst", destination.String(),
		"proto", "esp",
		"spi", fmt.Sprintf("0x%08x", spi),
		"reqid", handle.reqid,
		"mode", "tunnel",
	}
	switch handle.config.Integrity {
	case "hmac-sha1-96":
		arguments = append(arguments, "auth-trunc", "hmac(sha1)", "0x"+hex.EncodeToString(integrityKey), "96")
	case "hmac-sha2-256-128":
		arguments = append(arguments, "auth-trunc", "hmac(sha256)", "0x"+hex.EncodeToString(integrityKey), "128")
	}
	arguments = append(arguments, "enc", "cbc(aes)", "0x"+hex.EncodeToString(encryptionKey))
	if handle.config.UDPEncapsulation {
		arguments = append(arguments, "encap", "espinudp", "4500", "4500", "0.0.0.0")
	}
	return arguments
}

func (handle *linuxXFRMHandle) stateDeleteSelector(
	source net.IP,
	destination net.IP,
	spi uint32,
) []string {
	return []string{
		"src", source.String(),
		"dst", destination.String(),
		"proto", "esp",
		"spi", fmt.Sprintf("0x%08x", spi),
	}
}

func (handle *linuxXFRMHandle) runAndRecord(
	ctx context.Context,
	operation string,
	arguments []string,
	cleanup ipCleanupCommand,
) error {
	if err := handle.run(ctx, operation, arguments...); err != nil {
		return err
	}
	handle.cleanup = append(handle.cleanup, ipCleanupCommand{
		operation: cleanup.operation,
		arguments: append([]string(nil), cleanup.arguments...),
	})
	return nil
}

func (handle *linuxXFRMHandle) installPolicyCommand(
	ctx context.Context,
	operation string,
	command linuxXFRMPolicyCommand,
) error {
	key := strings.Join(command.remove, "\x00")
	if handle.installedPolicyKeys[key] {
		return nil
	}
	if err := handle.runAndRecord(ctx, operation, command.add, ipCleanupCommand{
		operation: strings.Replace(operation, "install", "delete", 1),
		arguments: command.remove,
	}); err != nil {
		return err
	}
	handle.installedPolicyKeys[key] = true
	return nil
}

func linuxXFRMOutboundGuardCommands(config ChildSAConfig) []linuxXFRMPolicyCommand {
	addresses := []struct {
		family  string
		address net.IP
		bits    int
	}{
		{family: "-4", address: config.InnerLocalIPv4, bits: 32},
		{family: "-6", address: config.InnerLocalIPv6, bits: 128},
	}
	var commands []linuxXFRMPolicyCommand
	for _, candidate := range addresses {
		address := canonicalRouteIP(candidate.address)
		if address == nil || linuxXFRMProtectsAllOutboundFrom(config, address) {
			continue
		}
		selector := []string{
			candidate.family, "xfrm", "policy", "add",
			"src", fmt.Sprintf("%s/%d", address.String(), candidate.bits),
		}
		remove := append(replacePolicyVerb(selector, "delete"), "dir", "out")
		add := append(selector,
			"dir", "out",
			"action", "block",
			"priority", strconv.Itoa(linuxXFRMBlockPriority),
		)
		commands = append(commands, linuxXFRMPolicyCommand{add: add, remove: remove})
	}
	return commands
}

func linuxXFRMProtectsAllOutboundFrom(config ChildSAConfig, inner net.IP) bool {
	inner = canonicalRouteIP(inner)
	if inner == nil {
		return false
	}
	for _, initiator := range config.InitiatorSelectors {
		if initiator.IPProtocol != 0 || !selectorUsesAllPorts(initiator) ||
			!trafficSelectorContainsIP(initiator, inner) {
			continue
		}
		for _, responder := range config.ResponderSelectors {
			if responder.IPProtocol == 0 && selectorUsesAllPorts(responder) &&
				trafficSelectorCoversAddressFamily(responder, inner) {
				return true
			}
		}
	}
	return false
}

func trafficSelectorContainsIP(selector trafficSelector, address net.IP) bool {
	address = canonicalRouteIP(address)
	start := canonicalRouteIP(selector.StartIP)
	end := canonicalRouteIP(selector.EndIP)
	if address == nil || start == nil || end == nil ||
		(address.To4() == nil) != (start.To4() == nil) || len(start) != len(end) {
		return false
	}
	return bytesCompare(address, start) >= 0 && bytesCompare(address, end) <= 0
}

func trafficSelectorCoversAddressFamily(selector trafficSelector, address net.IP) bool {
	address = canonicalRouteIP(address)
	start := canonicalRouteIP(selector.StartIP)
	end := canonicalRouteIP(selector.EndIP)
	if address == nil || start == nil || end == nil ||
		(address.To4() == nil) != (start.To4() == nil) {
		return false
	}
	if address.To4() != nil {
		return start.Equal(net.IPv4zero) && end.Equal(net.IPv4bcast)
	}
	return start.Equal(net.IPv6zero) && ipBytesAllEqual(end, 0xff)
}

func ipBytesAllEqual(address net.IP, value byte) bool {
	if len(address) == 0 {
		return false
	}
	for _, current := range address {
		if current != value {
			return false
		}
	}
	return true
}

func bytesCompare(left net.IP, right net.IP) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func (handle *linuxXFRMHandle) run(ctx context.Context, operation string, arguments ...string) error {
	command := exec.CommandContext(ctx, handle.ipCommand, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("%s: %s", operation, message)
	}
	return nil
}

func (handle *linuxXFRMHandle) Close(ctx context.Context) error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if handle.interfaceCreated {
		command := exec.CommandContext(ctx, handle.ipCommand,
			"link", "delete", handle.config.Name,
		)
		command.Env = linuxIPCommandEnvironment()
		output, err := command.CombinedOutput()
		if err != nil && !linuxIPDeleteReportsAbsent(output) {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			// Removing the interface also removes its assigned inner addresses.
			// Do not tear down guards or protect policies while that first step is
			// uncertain; a later Close can retry the exact same sequence.
			return fmt.Errorf("delete tunnel interface: %s", message)
		}
		handle.interfaceCreated = false
	}
	for len(handle.cleanup) > 0 {
		index := len(handle.cleanup) - 1
		item := handle.cleanup[index]
		command := exec.CommandContext(ctx, handle.ipCommand, item.arguments...)
		command.Env = linuxIPCommandEnvironment()
		output, err := command.CombinedOutput()
		if err != nil && !linuxIPDeleteReportsAbsent(output) {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			// Cleanup is intentionally ordered protect -> state -> guard. Stop at
			// the first failure so the source guard and all prerequisites remain
			// installed until a later Close can resume safely.
			return fmt.Errorf("%s: %s", item.operation, message)
		}
		handle.cleanup = handle.cleanup[:index]
	}
	handle.closed = true
	return nil
}

func (handle *linuxXFRMHandle) rollbackInstall() error {
	var lastErr error
	for attempt := 1; attempt <= linuxXFRMRollbackAttempts; attempt++ {
		cleanupContext, cleanupCancel := context.WithTimeout(
			context.Background(),
			linuxXFRMRollbackAttemptTimeout,
		)
		lastErr = handle.Close(cleanupContext)
		cleanupCancel()
		if lastErr == nil {
			return nil
		}
		if attempt < linuxXFRMRollbackAttempts {
			time.Sleep(linuxXFRMRollbackRetryDelay)
		}
	}
	return fmt.Errorf(
		"Linux XFRM rollback did not complete after %d bounded attempts: %w",
		linuxXFRMRollbackAttempts,
		lastErr,
	)
}

func linuxIPCommandEnvironment() []string {
	return append(os.Environ(), "LC_ALL=C", "LANG=C")
}

func linuxIPDeleteReportsAbsent(output []byte) bool {
	message := strings.ToLower(strings.TrimSpace(string(output)))
	return strings.Contains(message, "no such file or directory") ||
		strings.Contains(message, "cannot find device") ||
		strings.Contains(message, "no such process") ||
		strings.Contains(message, "does not exist")
}
