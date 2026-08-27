package ike

import (
	"errors"
	"fmt"
	"net"
)

const userspaceTunnelMTU = 1380

const mediaRouteUDPProtocol uint8 = 17

type mediaRoutePolicy struct {
	innerIPv4          net.IP
	innerIPv6          net.IP
	initiatorSelectors []trafficSelector
	responderSelectors []trafficSelector
}

func newMediaRoutePolicy(config ChildSAConfig) mediaRoutePolicy {
	return mediaRoutePolicy{
		innerIPv4:          append(net.IP(nil), config.InnerLocalIPv4...),
		innerIPv6:          append(net.IP(nil), config.InnerLocalIPv6...),
		initiatorSelectors: cloneTrafficSelectors(config.InitiatorSelectors),
		responderSelectors: cloneTrafficSelectors(config.ResponderSelectors),
	}
}

func (policy mediaRoutePolicy) validate(
	destination net.IP,
	sourcePort uint16,
	destinationPort uint16,
) (net.IP, error) {
	destination = canonicalRouteIP(destination)
	if destination == nil || destination.IsUnspecified() || destination.IsMulticast() {
		return nil, errors.New("ike: media route destination is invalid")
	}
	if sourcePort == 0 || destinationPort == 0 {
		return nil, errors.New("ike: media route requires nonzero UDP ports")
	}
	local := canonicalRouteIP(policy.innerIPv6)
	if destination.To4() != nil {
		local = canonicalRouteIP(policy.innerIPv4)
	}
	if local == nil {
		return nil, errors.New("ike: media route has no assigned inner address of the same family")
	}
	if !endpointAllowed(
		local,
		mediaRouteUDPProtocol,
		sourcePort,
		policy.initiatorSelectors,
	) {
		return nil, fmt.Errorf(
			"ike: local RTP endpoint %s:%d is outside initiator traffic selectors",
			local,
			sourcePort,
		)
	}
	if !endpointAllowed(
		destination,
		mediaRouteUDPProtocol,
		destinationPort,
		policy.responderSelectors,
	) {
		return nil, fmt.Errorf(
			"ike: remote RTP endpoint %s:%d is outside responder traffic selectors",
			destination,
			destinationPort,
		)
	}
	return destination, nil
}

func canonicalRouteIP(ip net.IP) net.IP {
	if ipv4 := ip.To4(); ipv4 != nil {
		return append(net.IP(nil), ipv4...)
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		return append(net.IP(nil), ipv6...)
	}
	return nil
}

func isConfiguredPCSCF(config ChildSAConfig, destination net.IP) bool {
	destination = canonicalRouteIP(destination)
	for _, candidate := range config.PCSCF {
		candidate = canonicalRouteIP(candidate)
		if candidate != nil && candidate.Equal(destination) {
			return true
		}
	}
	return false
}

func validateUserspaceRoutes(config ChildSAConfig) error {
	if config.InnerLocalIPv4 == nil && config.InnerLocalIPv6 == nil {
		return errors.New("ike: user-space ESP requires an assigned inner address")
	}
	validLocal := func(ip net.IP) bool {
		return ip != nil &&
			!ip.IsUnspecified() &&
			!ip.IsMulticast() &&
			ipAllowedBySelectors(ip, config.InitiatorSelectors)
	}
	if config.InnerLocalIPv4 != nil && !validLocal(config.InnerLocalIPv4) {
		return errors.New("ike: assigned inner IPv4 address is outside initiator traffic selectors")
	}
	if config.InnerLocalIPv6 != nil && !validLocal(config.InnerLocalIPv6) {
		return errors.New("ike: assigned inner IPv6 address is outside initiator traffic selectors")
	}
	matchingFamily := false
	for _, pcscf := range config.PCSCF {
		if pcscf == nil || pcscf.IsUnspecified() || pcscf.IsMulticast() {
			return errors.New("ike: P-CSCF address is invalid")
		}
		if !ipAllowedBySelectors(pcscf, config.ResponderSelectors) {
			return fmt.Errorf("ike: P-CSCF %s is outside responder traffic selectors", pcscf)
		}
		if (pcscf.To4() != nil && config.InnerLocalIPv4 != nil) ||
			(pcscf.To4() == nil && pcscf.To16() != nil && config.InnerLocalIPv6 != nil) {
			matchingFamily = true
		}
	}
	if !matchingFamily {
		return errors.New("ike: no P-CSCF address matches an assigned inner address family")
	}
	return nil
}

func ipAllowedBySelectors(ip net.IP, selectors []trafficSelector) bool {
	for _, selector := range selectors {
		if ipWithinRange(ip, selector.StartIP, selector.EndIP) {
			return true
		}
	}
	return false
}
