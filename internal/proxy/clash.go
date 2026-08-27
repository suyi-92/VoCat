package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	ClashProxyTypeVLESS = "vless"
	MaxClashConfigBytes = 64 << 10
	maxClashProxyCount  = 32
	maxYAMLNodes        = 4096
	maxYAMLDepth        = 32
)

// RealityOptions contains the Clash Reality keys used by VLESS clients.
type RealityOptions struct {
	PublicKey string `json:"public_key" yaml:"public-key"`
	ShortID   string `json:"short_id" yaml:"short-id"`
}

// VLESSNode is the normalized subset of a standard Clash VLESS/Reality proxy
// entry that VoCat can execute through its managed Xray bridge.
type VLESSNode struct {
	Name              string         `json:"name" yaml:"name"`
	Type              string         `json:"type" yaml:"type"`
	Server            string         `json:"server" yaml:"server"`
	Port              int            `json:"port" yaml:"port"`
	UUID              string         `json:"uuid" yaml:"uuid"`
	Flow              string         `json:"flow,omitempty" yaml:"flow,omitempty"`
	Network           string         `json:"network" yaml:"network"`
	TLS               bool           `json:"tls" yaml:"tls"`
	ClientFingerprint string         `json:"client_fingerprint" yaml:"client-fingerprint"`
	UDP               bool           `json:"udp" yaml:"udp"`
	RealityOptions    RealityOptions `json:"reality_options" yaml:"reality-opts"`
	ALPN              []string       `json:"alpn,omitempty" yaml:"alpn,omitempty"`
	ServerName        string         `json:"server_name" yaml:"servername"`
}

type clashPort int

func (port *clashPort) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("port must be a number")
	}
	value, err := strconv.Atoi(strings.TrimSpace(node.Value))
	if err != nil {
		return errors.New("port must be a number")
	}
	*port = clashPort(value)
	return nil
}

type clashVLESSInput struct {
	Name              string         `yaml:"name"`
	Type              string         `yaml:"type"`
	Server            string         `yaml:"server"`
	Port              clashPort      `yaml:"port"`
	UUID              string         `yaml:"uuid"`
	Flow              string         `yaml:"flow"`
	Network           string         `yaml:"network"`
	TLS               *bool          `yaml:"tls"`
	ClientFingerprint string         `yaml:"client-fingerprint"`
	UDP               *bool          `yaml:"udp"`
	RealityOptions    RealityOptions `yaml:"reality-opts"`
	ALPN              []string       `yaml:"alpn"`
	ServerName        string         `yaml:"servername"`
}

type storedVLESS struct {
	Type              string         `json:"type"`
	Flow              string         `json:"flow,omitempty"`
	Network           string         `json:"network"`
	TLS               bool           `json:"tls"`
	ClientFingerprint string         `json:"client_fingerprint"`
	UDP               bool           `json:"udp"`
	RealityOptions    RealityOptions `json:"reality_options"`
	ALPN              []string       `json:"alpn,omitempty"`
	ServerName        string         `json:"server_name"`
}

// ParseClashVLESS accepts a single mapping, a YAML sequence, or a complete
// Clash document containing a proxies sequence. Markdown code fences are
// tolerated because operator input is frequently copied from documentation.
func ParseClashVLESS(input string) ([]VLESSNode, error) {
	return parseClashVLESS(input, "")
}

// ParseClashVLESSUpdate permits the caller's exact secret mask in place of a
// UUID. The API replaces that mask with the already stored UUID before the
// node can reach validation or execution.
func ParseClashVLESSUpdate(input, secretMask string) ([]VLESSNode, error) {
	if strings.TrimSpace(secretMask) == "" {
		return nil, errors.New("VLESS update secret mask is empty")
	}
	return parseClashVLESS(input, secretMask)
}

func parseClashVLESS(input, allowedUUIDMask string) ([]VLESSNode, error) {
	input = stripYAMLCodeFence(strings.TrimSpace(input))
	if input == "" {
		return nil, errors.New("Clash proxy configuration is empty")
	}
	if len(input) > MaxClashConfigBytes {
		return nil, fmt.Errorf("Clash proxy configuration exceeds %d bytes", MaxClashConfigBytes)
	}

	decoder := yaml.NewDecoder(bytes.NewBufferString(input))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse Clash YAML: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("Clash input must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("parse trailing Clash YAML: %w", err)
	}
	if len(document.Content) != 1 {
		return nil, errors.New("Clash input does not contain a proxy object")
	}
	count := 0
	if err := validateYAMLNode(document.Content[0], 0, &count); err != nil {
		return nil, err
	}

	entries, err := clashProxyEntries(document.Content[0])
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("Clash input does not contain any proxies")
	}
	if len(entries) > maxClashProxyCount {
		return nil, fmt.Errorf("Clash input contains %d proxies; the limit is %d", len(entries), maxClashProxyCount)
	}

	result := make([]VLESSNode, 0, len(entries))
	for index, entry := range entries {
		var value clashVLESSInput
		if err := entry.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode Clash proxy %d: %w", index+1, err)
		}
		node := normalizeClashVLESS(value)
		if err := node.validate(allowedUUIDMask); err != nil {
			return nil, fmt.Errorf("Clash proxy %d: %w", index+1, err)
		}
		result = append(result, node)
	}
	return result, nil
}

func stripYAMLCodeFence(value string) string {
	if !strings.HasPrefix(value, "```") {
		return value
	}
	firstNewline := strings.IndexByte(value, '\n')
	if firstNewline < 0 {
		return value
	}
	value = strings.TrimSpace(value[firstNewline+1:])
	if strings.HasSuffix(value, "```") {
		value = strings.TrimSpace(strings.TrimSuffix(value, "```"))
	}
	return value
}

func validateYAMLNode(node *yaml.Node, depth int, count *int) error {
	if node == nil {
		return nil
	}
	*count++
	if *count > maxYAMLNodes {
		return errors.New("Clash YAML is too complex")
	}
	if depth > maxYAMLDepth {
		return errors.New("Clash YAML nesting is too deep")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("Clash YAML anchors and aliases are not supported")
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func clashProxyEntries(root *yaml.Node) ([]*yaml.Node, error) {
	switch root.Kind {
	case yaml.SequenceNode:
		return root.Content, nil
	case yaml.MappingNode:
		for index := 0; index+1 < len(root.Content); index += 2 {
			if root.Content[index].Value != "proxies" {
				continue
			}
			value := root.Content[index+1]
			if value.Kind != yaml.SequenceNode {
				return nil, errors.New("Clash proxies field must be a YAML sequence")
			}
			return value.Content, nil
		}
		return []*yaml.Node{root}, nil
	default:
		return nil, errors.New("Clash proxy configuration must be a mapping or sequence")
	}
}

func normalizeClashVLESS(value clashVLESSInput) VLESSNode {
	network := strings.ToLower(strings.TrimSpace(value.Network))
	if network == "" {
		network = "tcp"
	}
	fingerprint := strings.ToLower(strings.TrimSpace(value.ClientFingerprint))
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	tlsEnabled := value.TLS != nil && *value.TLS
	udpEnabled := value.UDP != nil && *value.UDP
	alpn := make([]string, 0, len(value.ALPN))
	for _, protocol := range value.ALPN {
		if protocol = strings.TrimSpace(protocol); protocol != "" {
			alpn = append(alpn, protocol)
		}
	}
	return VLESSNode{
		Name:              strings.TrimSpace(value.Name),
		Type:              strings.ToLower(strings.TrimSpace(value.Type)),
		Server:            strings.TrimSpace(value.Server),
		Port:              int(value.Port),
		UUID:              strings.TrimSpace(value.UUID),
		Flow:              strings.ToLower(strings.TrimSpace(value.Flow)),
		Network:           network,
		TLS:               tlsEnabled,
		ClientFingerprint: fingerprint,
		UDP:               udpEnabled,
		RealityOptions: RealityOptions{
			PublicKey: strings.TrimSpace(value.RealityOptions.PublicKey),
			ShortID:   strings.TrimSpace(value.RealityOptions.ShortID),
		},
		ALPN:       alpn,
		ServerName: strings.TrimSpace(value.ServerName),
	}
}

func (node VLESSNode) Validate() error {
	return node.validate("")
}

func (node VLESSNode) validate(allowedUUIDMask string) error {
	if node.Name == "" || utf8.RuneCountInString(node.Name) > 200 {
		return errors.New("name is required and must not exceed 200 characters")
	}
	if strings.ToLower(strings.TrimSpace(node.Type)) != ClashProxyTypeVLESS {
		return fmt.Errorf("unsupported proxy type %q; this importer currently supports vless", node.Type)
	}
	if err := validateClashHost(node.Server, "server", true); err != nil {
		return err
	}
	if node.Port < 1 || node.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if allowedUUIDMask == "" || node.UUID != allowedUUIDMask {
		if !validUUID(node.UUID) {
			return errors.New("uuid must be a valid VLESS UUID")
		}
	}
	if node.Flow != "" && node.Flow != "xtls-rprx-vision" {
		return fmt.Errorf("unsupported VLESS flow %q", node.Flow)
	}
	if strings.ToLower(strings.TrimSpace(node.Network)) != "tcp" {
		return fmt.Errorf("unsupported VLESS network %q; Reality import currently requires tcp", node.Network)
	}
	if !node.TLS {
		return errors.New("tls must be true for a VLESS Reality proxy")
	}
	if !validFingerprint(node.ClientFingerprint) {
		return fmt.Errorf("unsupported client-fingerprint %q", node.ClientFingerprint)
	}
	if err := validateRealityPublicKey(node.RealityOptions.PublicKey); err != nil {
		return err
	}
	if err := validateRealityShortID(node.RealityOptions.ShortID); err != nil {
		return err
	}
	if err := validateClashHost(node.ServerName, "servername", false); err != nil {
		return err
	}
	if len(node.ALPN) > 8 {
		return errors.New("alpn may contain at most 8 protocols")
	}
	for _, protocol := range node.ALPN {
		if protocol == "" || len(protocol) > 32 || strings.IndexFunc(protocol, unicode.IsSpace) >= 0 || strings.IndexFunc(protocol, unicode.IsControl) >= 0 {
			return fmt.Errorf("invalid ALPN protocol %q", protocol)
		}
	}
	return nil
}

func validateClashHost(value, field string, allowIP bool) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 {
		return fmt.Errorf("%s is required and must not exceed 253 characters", field)
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/\\?#@") || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s must be a hostname%s", field, map[bool]string{true: " or IP address", false: ""}[allowIP])
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		if allowIP {
			return nil
		}
		return fmt.Errorf("%s must be a hostname", field)
	}
	if strings.Contains(value, ":") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return fmt.Errorf("%s must be a valid hostname", field)
	}
	return nil
}

func validUUID(value string) bool {
	compact := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(compact) != 32 {
		return false
	}
	if len(value) != 32 && !(len(value) == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-') {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}

func validFingerprint(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return true
	default:
		return false
	}
}

func validateRealityPublicKey(value string) error {
	value = strings.TrimSpace(value)
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	if err != nil || len(decoded) != 32 {
		return errors.New("reality-opts.public-key must be a 32-byte URL-safe base64 X25519 public key")
	}
	return nil
}

func validateRealityShortID(value string) error {
	value = strings.TrimSpace(value)
	if len(value) > 16 || len(value)%2 != 0 {
		return errors.New("reality-opts.short-id must contain an even number of at most 16 hexadecimal characters")
	}
	if value == "" {
		return nil
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("reality-opts.short-id must contain only hexadecimal characters")
	}
	return nil
}

func (node VLESSNode) ServerAddress() string {
	return net.JoinHostPort(strings.Trim(node.Server, "[]"), strconv.Itoa(node.Port))
}

func (node VLESSNode) StableID() string {
	encoded, _ := json.Marshal(node)
	digest := sha256.Sum256(encoded)
	return "clash-" + hex.EncodeToString(digest[:8])
}

func (node VLESSNode) StoredExtra() (json.RawMessage, error) {
	return json.Marshal(storedVLESS{
		Type:              ClashProxyTypeVLESS,
		Flow:              node.Flow,
		Network:           node.Network,
		TLS:               node.TLS,
		ClientFingerprint: node.ClientFingerprint,
		UDP:               node.UDP,
		RealityOptions:    node.RealityOptions,
		ALPN:              append([]string(nil), node.ALPN...),
		ServerName:        node.ServerName,
	})
}

func ProxyType(extra json.RawMessage) string {
	var metadata struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(extra, &metadata) == nil && strings.TrimSpace(metadata.Type) != "" {
		return strings.ToLower(strings.TrimSpace(metadata.Type))
	}
	return "socks5"
}

func VLESSFromStored(name, address, uuid string, extra json.RawMessage) (VLESSNode, error) {
	var stored storedVLESS
	if err := json.Unmarshal(extra, &stored); err != nil {
		return VLESSNode{}, fmt.Errorf("decode stored VLESS configuration: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(stored.Type)) != ClashProxyTypeVLESS {
		return VLESSNode{}, fmt.Errorf("stored proxy type is %q, not vless", stored.Type)
	}
	server, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return VLESSNode{}, fmt.Errorf("decode stored VLESS server address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return VLESSNode{}, fmt.Errorf("decode stored VLESS server port: %w", err)
	}
	return VLESSNode{
		Name:              name,
		Type:              ClashProxyTypeVLESS,
		Server:            strings.Trim(server, "[]"),
		Port:              port,
		UUID:              uuid,
		Flow:              stored.Flow,
		Network:           stored.Network,
		TLS:               stored.TLS,
		ClientFingerprint: stored.ClientFingerprint,
		UDP:               stored.UDP,
		RealityOptions:    stored.RealityOptions,
		ALPN:              append([]string(nil), stored.ALPN...),
		ServerName:        stored.ServerName,
	}, nil
}

func (node VLESSNode) ClashYAML(uuid string) (string, error) {
	copyNode := node
	copyNode.UUID = uuid
	encoded, err := yaml.Marshal([]VLESSNode{copyNode})
	if err != nil {
		return "", fmt.Errorf("encode Clash VLESS YAML: %w", err)
	}
	return strings.TrimSpace(string(encoded)), nil
}
