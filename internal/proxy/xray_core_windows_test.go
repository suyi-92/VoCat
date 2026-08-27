//go:build windows

package proxy

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBundledXrayExecutableIsApprovedAndArchitectureMatched(t *testing.T) {
	architecture := runtime.GOARCH
	if architecture != "amd64" && architecture != "arm64" {
		t.Skip("VoCat Windows bundles support amd64 and arm64")
	}
	path := filepath.Join("..", "..", "dist", "windows-"+architecture, "xray.exe")
	lock, finalPath, err := lockAndValidateProxyCore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if finalPath == "" {
		t.Fatal("validated Xray path is empty")
	}
}

func TestXrayManagerStartsPrivateSOCKSEndpointFromVLESSConfig(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("VoCat Windows bundles support amd64 and arm64")
	}
	corePath := filepath.Join("..", "..", "dist", "windows-"+runtime.GOARCH, "xray.exe")
	manager := NewXrayManager(XrayOptions{
		CorePath: corePath, RuntimeDir: t.TempDir(), StartupTimeout: 5 * time.Second,
	})
	node := VLESSNode{
		Name: "Managed", Type: "vless", Server: "edge.example.com", Port: 443,
		UUID: "11111111-2222-4333-8444-555555555555", Flow: "xtls-rprx-vision",
		Network: "tcp", TLS: true, ClientFingerprint: "chrome", UDP: true,
		RealityOptions: RealityOptions{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ShortID:   "0123456789abcdef",
		},
		ALPN: []string{"h2", "http/1.1"}, ServerName: "www.example.com",
	}
	address, err := manager.Ensure(context.Background(), "managed", node)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial managed SOCKS endpoint: %v", err)
	}
	connection.Close()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBundledXrayExecutableRejectsModifiedImage(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the test host validates its matching bundle")
	}
	source := filepath.Join("..", "..", "dist", "windows-amd64", "xray.exe")
	image, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	image[len(image)-1] ^= 0xff
	path := filepath.Join(t.TempDir(), "xray.exe")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if lock, _, err := lockAndValidateProxyCore(path); err == nil {
		lock.Close()
		t.Fatal("modified Xray executable passed pinned SHA256 validation")
	}
}
