package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

const validVLESSYAML = `- name: 【Dmit-US-LA-PRO】AaITR-Frontier
  type: vless
  server: edge.example.com
  port: 443
  uuid: 11111111-2222-4333-8444-555555555555
  flow: xtls-rprx-vision
  network: tcp
  tls: true
  client-fingerprint: chrome
  udp: false
  reality-opts:
    public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    short-id: "0123456789abcdef"
  alpn:
    - h2
    - http/1.1
  servername: www.example.com`

func TestParseClashVLESSSequenceAndStoredRoundTrip(t *testing.T) {
	nodes, err := ParseClashVLESS(validVLESSYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(nodes))
	}
	node := nodes[0]
	if node.Name != "【Dmit-US-LA-PRO】AaITR-Frontier" || node.Server != "edge.example.com" || node.Port != 443 {
		t.Fatalf("identity fields = %+v", node)
	}
	if node.UDP || !node.TLS || node.Flow != "xtls-rprx-vision" || node.ClientFingerprint != "chrome" {
		t.Fatalf("transport fields = %+v", node)
	}
	if node.ServerAddress() != "edge.example.com:443" || !strings.HasPrefix(node.StableID(), "clash-") {
		t.Fatalf("derived fields = %q, %q", node.ServerAddress(), node.StableID())
	}
	extra, err := node.StoredExtra()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(extra), node.UUID) {
		t.Fatal("stored non-secret VLESS metadata contains the UUID")
	}
	restored, err := VLESSFromStored(node.Name, node.ServerAddress(), node.UUID, extra)
	if err != nil {
		t.Fatal(err)
	}
	if restored.UUID != node.UUID || restored.RealityOptions != node.RealityOptions || strings.Join(restored.ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("restored node = %+v", restored)
	}
	masked, err := restored.ClashYAML("********")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(masked, node.UUID) || !strings.Contains(masked, "uuid: '********'") {
		t.Fatalf("masked YAML = %s", masked)
	}
}

func TestParseClashVLESSInputShapes(t *testing.T) {
	direct := unindentSequenceEntry(validVLESSYAML)
	complete := "proxies:\n" + indentYAML(validVLESSYAML, "  ")
	fenced := "```yaml\n" + validVLESSYAML + "\n```"
	for name, input := range map[string]string{
		"direct mapping":  direct,
		"complete config": complete,
		"markdown fence":  fenced,
	} {
		t.Run(name, func(t *testing.T) {
			nodes, err := ParseClashVLESS(input)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("ParseClashVLESS() = %d, %v", len(nodes), err)
			}
		})
	}
}

func TestParseClashVLESSRejectsUnsafeOrUnsupportedValues(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"unsupported type": func(value string) string { return strings.Replace(value, "type: vless", "type: vmess", 1) },
		"invalid UUID": func(value string) string {
			return strings.Replace(value, "11111111-2222-4333-8444-555555555555", "123", 1)
		},
		"invalid public key": func(value string) string {
			return strings.Replace(value, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "123", 1)
		},
		"odd short ID":        func(value string) string { return strings.Replace(value, "0123456789abcdef", "123", 1) },
		"unsupported network": func(value string) string { return strings.Replace(value, "network: tcp", "network: ws", 1) },
		"TLS disabled":        func(value string) string { return strings.Replace(value, "tls: true", "tls: false", 1) },
		"YAML alias": func(value string) string {
			return "defaults: &node\n" + indentYAML(strings.TrimPrefix(value, "- "), "  ") + "\nproxies:\n  - *node"
		},
		"multiple documents": func(value string) string { return value + "\n---\n" + value },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClashVLESS(mutate(validVLESSYAML)); err == nil {
				t.Fatal("ParseClashVLESS() accepted invalid input")
			}
		})
	}
}

func TestParseClashVLESSUpdateAcceptsOnlyExactSecretMask(t *testing.T) {
	masked := strings.Replace(validVLESSYAML, "uuid: 11111111-2222-4333-8444-555555555555", "uuid: '********'", 1)
	if _, err := ParseClashVLESS(masked); err == nil {
		t.Fatal("create parser accepted a masked UUID")
	}
	nodes, err := ParseClashVLESSUpdate(masked, "********")
	if err != nil || len(nodes) != 1 || nodes[0].UUID != "********" {
		t.Fatalf("ParseClashVLESSUpdate() = %+v, %v", nodes, err)
	}
}

func TestBuildXrayConfigMapsRealityAndUDP(t *testing.T) {
	nodes, err := ParseClashVLESS(strings.Replace(validVLESSYAML, "udp: false", "udp: true", 1))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := buildXrayConfig(nodes[0], 39123)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	settings := inbound["settings"].(map[string]any)
	if inbound["listen"] != "127.0.0.1" || inbound["port"] != float64(39123) || settings["udp"] != true {
		t.Fatalf("inbound = %#v", inbound)
	}
	outbound := config["outbounds"].([]any)[0].(map[string]any)
	stream := outbound["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	if stream["security"] != "reality" || reality["fingerprint"] != "chrome" || reality["publicKey"] != nodes[0].RealityOptions.PublicKey {
		t.Fatalf("reality settings = %#v", reality)
	}
	vnext := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	user := vnext["users"].([]any)[0].(map[string]any)
	if user["id"] != nodes[0].UUID || user["flow"] != "xtls-rprx-vision" {
		t.Fatalf("VLESS user = %#v", user)
	}
}

func indentYAML(value, prefix string) string {
	return prefix + strings.ReplaceAll(value, "\n", "\n"+prefix)
}

func unindentSequenceEntry(value string) string {
	lines := strings.Split(value, "\n")
	lines[0] = strings.TrimPrefix(lines[0], "- ")
	for index := 1; index < len(lines); index++ {
		lines[index] = strings.TrimPrefix(lines[index], "  ")
	}
	return strings.Join(lines, "\n")
}
