package i18n

// Keep feature-specific diagnostic strings together so additions to the proxy
// probe do not cause conflicts in the shared dictionary.
func init() {
	zhToEn["UDP ASSOCIATE 已建立，但实际 UDP 数据没有返回；检查节点 UDP 转发、路由和防火墙。"] = "UDP ASSOCIATE was established, but no UDP payload returned; check the node's UDP forwarding, routing, and firewall."
	zhToEn["TCP 握手、认证、UDP ASSOCIATE 与真实 UDP DNS 往返均通过。"] = "TCP handshake, authentication, UDP ASSOCIATE, and a real UDP DNS round trip all passed."
	zhToEn["代理已保存，SOCKS5 认证与真实 UDP 往返均通过。"] = "Proxy saved; SOCKS5 authentication and a real UDP round trip both passed."
	zhToEn["SOCKS5 认证与真实 UDP 往返探测通过。"] = "SOCKS5 authentication and a real UDP round-trip probe passed."
	zhToEn["Clash VLESS 代理已识别并保存。"] = "Clash VLESS proxy recognized and saved."
	zhToEn["Clash VLESS 代理已保存；该配置关闭了 UDP，不能用于 VoWiFi 绑定。"] = "Clash VLESS proxy saved. UDP is disabled, so it cannot be assigned to VoWiFi."
	zhToEn["Clash VLESS 代理已保存，启用后才会启动受管代理核心。"] = "Clash VLESS proxy saved. Its managed proxy core starts only after the proxy is enabled."
	zhToEn["Clash VLESS 代理已保存，受管核心与真实 UDP 往返均通过。"] = "Clash VLESS proxy saved; the managed core and real UDP round trip both passed."
	zhToEn["Clash VLESS 代理已保存；未找到 Xray 核心，使用前请将 xray 放到 VoCat 旁边。"] = "Clash VLESS proxy saved. Place Xray beside VoCat before using it."
	zhToEn["Clash VLESS 代理已保存；连通性探测未通过，请检查节点信息。"] = "Clash VLESS proxy saved, but its connectivity probe failed. Check the node settings."
}
