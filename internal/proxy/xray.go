package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	ErrVLESSCoreUnavailable = errors.New("vless proxy core is unavailable")
	ErrVLESSUDPDisabled     = errors.New("vless proxy has UDP disabled")
)

const XrayCoreVersion = "26.3.27"

// VLESSCore turns a validated Clash VLESS node into a private loopback
// SOCKS5 endpoint. The existing VoWiFi transport can then keep its hardened
// SOCKS5 and UDP Associate implementation unchanged.
type VLESSCore interface {
	Ensure(context.Context, string, VLESSNode) (string, error)
	Stop(string) error
}

type XrayOptions struct {
	CorePath       string
	RuntimeDir     string
	Logger         *slog.Logger
	StartupTimeout time.Duration
}

type XrayManager struct {
	options XrayOptions

	operations sync.Mutex
	mu         sync.Mutex
	closed     bool
	corePath   string
	instances  map[string]*xrayInstance
}

type xrayInstance struct {
	address     string
	fingerprint string
	command     *exec.Cmd
	done        chan struct{}
	mu          sync.Mutex
	err         error
	output      *tailBuffer
}

func NewXrayManager(options XrayOptions) *XrayManager {
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.StartupTimeout <= 0 {
		options.StartupTimeout = 8 * time.Second
	}
	if strings.TrimSpace(options.RuntimeDir) == "" {
		options.RuntimeDir = filepath.Join(os.TempDir(), "vocat-proxy-core")
	}
	return &XrayManager{options: options, instances: make(map[string]*xrayInstance)}
}

func (manager *XrayManager) Ensure(ctx context.Context, id string, node VLESSNode) (string, error) {
	if err := node.Validate(); err != nil {
		return "", fmt.Errorf("validate VLESS proxy: %w", err)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", errors.New("managed VLESS proxy ID is empty")
	}
	fingerprint := vlessFingerprint(node)

	manager.operations.Lock()
	defer manager.operations.Unlock()

	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return "", errors.New("managed VLESS proxy core is closed")
	}
	existing := manager.instances[id]
	manager.mu.Unlock()
	if existing != nil && existing.fingerprint == fingerprint && !existing.exited() {
		return existing.address, nil
	}
	if existing != nil {
		manager.removeInstance(id, existing)
		stopXrayInstance(existing)
	}

	corePath, err := manager.resolveCorePath()
	if err != nil {
		return "", err
	}
	instance, err := manager.start(ctx, corePath, id, node, fingerprint)
	if err != nil {
		return "", err
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		stopXrayInstance(instance)
		return "", errors.New("managed VLESS proxy core is closed")
	}
	manager.instances[id] = instance
	manager.mu.Unlock()
	manager.options.Logger.Info("managed VLESS proxy core started", "proxy_id", id, "listen", instance.address)
	return instance.address, nil
}

func (manager *XrayManager) Stop(id string) error {
	manager.operations.Lock()
	defer manager.operations.Unlock()

	manager.mu.Lock()
	instance := manager.instances[strings.TrimSpace(id)]
	delete(manager.instances, strings.TrimSpace(id))
	manager.mu.Unlock()
	if instance == nil {
		return nil
	}
	stopXrayInstance(instance)
	manager.options.Logger.Info("managed VLESS proxy core stopped", "proxy_id", strings.TrimSpace(id))
	return nil
}

func (manager *XrayManager) Close(ctx context.Context) error {
	manager.operations.Lock()
	defer manager.operations.Unlock()

	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return nil
	}
	manager.closed = true
	instances := make([]*xrayInstance, 0, len(manager.instances))
	for _, instance := range manager.instances {
		instances = append(instances, instance)
	}
	manager.instances = make(map[string]*xrayInstance)
	manager.mu.Unlock()

	for _, instance := range instances {
		if instance.command.Process != nil && !instance.exited() {
			_ = instance.command.Process.Kill()
		}
	}
	for _, instance := range instances {
		select {
		case <-instance.done:
		case <-ctx.Done():
			return fmt.Errorf("stop managed VLESS proxy cores: %w", ctx.Err())
		}
	}
	return nil
}

func (manager *XrayManager) removeInstance(id string, expected *xrayInstance) {
	manager.mu.Lock()
	if manager.instances[id] == expected {
		delete(manager.instances, id)
	}
	manager.mu.Unlock()
}

func (manager *XrayManager) start(
	ctx context.Context,
	corePath string,
	id string,
	node VLESSNode,
	fingerprint string,
) (*xrayInstance, error) {
	if err := os.MkdirAll(manager.options.RuntimeDir, 0o700); err != nil {
		return nil, fmt.Errorf("create managed proxy runtime directory: %w", err)
	}
	port, err := availableLoopbackPort()
	if err != nil {
		return nil, err
	}
	config, err := buildXrayConfig(node, port)
	if err != nil {
		return nil, err
	}
	configFile, err := os.CreateTemp(manager.options.RuntimeDir, "xray-*.json")
	if err != nil {
		return nil, fmt.Errorf("create managed VLESS proxy configuration: %w", err)
	}
	configPath := configFile.Name()
	defer os.Remove(configPath)
	if err := configFile.Chmod(0o600); err != nil {
		configFile.Close()
		return nil, fmt.Errorf("protect managed VLESS proxy configuration: %w", err)
	}
	if _, err := configFile.Write(config); err != nil {
		configFile.Close()
		return nil, fmt.Errorf("write managed VLESS proxy configuration: %w", err)
	}
	if err := configFile.Close(); err != nil {
		return nil, fmt.Errorf("close managed VLESS proxy configuration: %w", err)
	}

	output := newTailBuffer(16 << 10)
	coreLock, executablePath, err := lockAndValidateProxyCore(corePath)
	if err != nil {
		return nil, err
	}
	defer coreLock.Close()
	command := exec.Command(executablePath, "run", "-config", configPath)
	command.Dir = filepath.Dir(executablePath)
	command.Stdout = output
	command.Stderr = output
	configureProxyCoreCommand(command)
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start Xray proxy core: %w", err)
	}
	instance := &xrayInstance{
		address:     net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
		fingerprint: fingerprint,
		command:     command,
		done:        make(chan struct{}),
		output:      output,
	}
	go func() {
		err := command.Wait()
		instance.mu.Lock()
		instance.err = err
		instance.mu.Unlock()
		close(instance.done)
	}()

	deadline := time.NewTimer(manager.options.StartupTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, dialErr := net.DialTimeout("tcp", instance.address, 150*time.Millisecond)
		if dialErr == nil {
			connection.Close()
			return instance, nil
		}
		select {
		case <-ctx.Done():
			stopXrayInstance(instance)
			return nil, fmt.Errorf("start managed VLESS proxy: %w", ctx.Err())
		case <-instance.done:
			return nil, manager.startFailure(id, node.UUID, instance)
		case <-deadline.C:
			stopXrayInstance(instance)
			return nil, fmt.Errorf("managed VLESS proxy %q did not open its local SOCKS5 endpoint", id)
		case <-ticker.C:
		}
	}
}

func (manager *XrayManager) startFailure(id, secret string, instance *xrayInstance) error {
	instance.mu.Lock()
	err := instance.err
	instance.mu.Unlock()
	detail := strings.TrimSpace(instance.output.String())
	if secret != "" {
		detail = strings.ReplaceAll(detail, secret, "********")
	}
	if len(detail) > 1000 {
		detail = detail[len(detail)-1000:]
	}
	if detail != "" {
		return fmt.Errorf("managed VLESS proxy %q exited during startup: %v: %s", id, err, detail)
	}
	return fmt.Errorf("managed VLESS proxy %q exited during startup: %w", id, err)
}

func (manager *XrayManager) resolveCorePath() (string, error) {
	manager.mu.Lock()
	cached := manager.corePath
	manager.mu.Unlock()
	if cached != "" {
		if pathIsRegularFile(cached) {
			return cached, nil
		}
	}

	name := "xray"
	if runtime.GOOS == "windows" {
		name = "xray.exe"
	}
	candidates := make([]string, 0, 5)
	if configured := strings.TrimSpace(manager.options.CorePath); configured != "" {
		candidates = append(candidates, configured)
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		candidates = append(candidates, filepath.Join(directory, name), filepath.Join(directory, "tools", name))
	}
	if path, err := exec.LookPath(name); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		candidate, _ = filepath.Abs(candidate)
		if !pathIsRegularFile(candidate) {
			continue
		}
		manager.mu.Lock()
		manager.corePath = candidate
		manager.mu.Unlock()
		return candidate, nil
	}
	return "", fmt.Errorf("%w: place %s beside vocat or set VOCAT_XRAY_PATH", ErrVLESSCoreUnavailable, name)
}

func pathIsRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func availableLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve managed proxy loopback port: %w", err)
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port < 1 {
		return 0, errors.New("reserve managed proxy loopback port: invalid listener address")
	}
	return address.Port, nil
}

func buildXrayConfig(node VLESSNode, port int) ([]byte, error) {
	if err := node.Validate(); err != nil {
		return nil, err
	}
	reality := map[string]any{
		"show":        false,
		"fingerprint": node.ClientFingerprint,
		"serverName":  node.ServerName,
		"publicKey":   node.RealityOptions.PublicKey,
		"shortId":     node.RealityOptions.ShortID,
		"spiderX":     "/",
	}
	if len(node.ALPN) > 0 {
		reality["alpn"] = node.ALPN
	}
	user := map[string]any{
		"id":         node.UUID,
		"encryption": "none",
	}
	if node.Flow != "" {
		user["flow"] = node.Flow
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag":      "vocat-socks",
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": node.UDP, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{map[string]any{
			"tag":      "vocat-vless",
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": node.Server,
				"port":    node.Port,
				"users":   []any{user},
			}}},
			"streamSettings": map[string]any{
				"network":         node.Network,
				"security":        "reality",
				"realitySettings": reality,
			},
		}},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"type":        "field",
				"inboundTag":  []string{"vocat-socks"},
				"outboundTag": "vocat-vless",
			}},
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode Xray VLESS configuration: %w", err)
	}
	return encoded, nil
}

func vlessFingerprint(node VLESSNode) string {
	encoded, _ := json.Marshal(node)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func stopXrayInstance(instance *xrayInstance) {
	if instance == nil || instance.command == nil || instance.command.Process == nil || instance.exited() {
		return
	}
	_ = instance.command.Process.Kill()
	select {
	case <-instance.done:
	case <-time.After(3 * time.Second):
	}
}

func (instance *xrayInstance) exited() bool {
	select {
	case <-instance.done:
		return true
	default:
		return false
	}
}

type tailBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func newTailBuffer(limit int) *tailBuffer {
	return &tailBuffer{limit: limit}
}

func (buffer *tailBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	original := len(value)
	if len(value) >= buffer.limit {
		buffer.data = append(buffer.data[:0], value[len(value)-buffer.limit:]...)
		return original, nil
	}
	if excess := len(buffer.data) + len(value) - buffer.limit; excess > 0 {
		buffer.data = append(buffer.data[:0], buffer.data[excess:]...)
	}
	buffer.data = append(buffer.data, value...)
	return original, nil
}

func (buffer *tailBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return string(bytes.Clone(buffer.data))
}
