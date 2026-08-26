package ike

import "net"

func cloneChildSAConfig(config ChildSAConfig) ChildSAConfig {
	config.OuterLocal = append(net.IP(nil), config.OuterLocal...)
	config.OuterRemote = append(net.IP(nil), config.OuterRemote...)
	config.InnerLocalIPv4 = append(net.IP(nil), config.InnerLocalIPv4...)
	config.InnerLocalIPv6 = append(net.IP(nil), config.InnerLocalIPv6...)
	config.InboundEncKey = append([]byte(nil), config.InboundEncKey...)
	config.InboundAuthKey = append([]byte(nil), config.InboundAuthKey...)
	config.OutboundEncKey = append([]byte(nil), config.OutboundEncKey...)
	config.OutboundAuthKey = append([]byte(nil), config.OutboundAuthKey...)
	config.InitiatorSelectors = cloneTrafficSelectors(config.InitiatorSelectors)
	config.ResponderSelectors = cloneTrafficSelectors(config.ResponderSelectors)
	config.PCSCF = cloneIPs(config.PCSCF)
	config.DNS = cloneIPs(config.DNS)
	return config
}

func cloneTrafficSelectors(selectors []trafficSelector) []trafficSelector {
	result := append([]trafficSelector(nil), selectors...)
	for index := range result {
		result[index].StartIP = append(net.IP(nil), result[index].StartIP...)
		result[index].EndIP = append(net.IP(nil), result[index].EndIP...)
	}
	return result
}
