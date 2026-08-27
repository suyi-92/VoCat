package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vocat/internal/store"
)

const clashVLESSAPIYAML = `- name: 【Dmit-US-LA-PRO】AaITR-Frontier
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

func newClashProxyTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	database, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return &Server{
		store:               database,
		logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		maxRequestBodyBytes: 1 << 20,
	}, database
}

func clashProxyRequest(t *testing.T, server *Server, method, id, content string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"content": content})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/upstream-proxies/import-clash"
	if id != "" {
		path = "/api/upstream-proxies/" + id + "/clash"
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.handleClashProxyImport(response, request, id)
	return response
}

func TestClashVLESSImportStoresSecretAndReturnsOnlyMaskedConfig(t *testing.T) {
	server, database := newClashProxyTestServer(t)
	response := clashProxyRequest(t, server, http.MethodPost, "", clashVLESSAPIYAML)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "11111111-2222-4333-8444-555555555555") {
		t.Fatal("API response exposed the VLESS UUID")
	}
	var envelope struct {
		Data struct {
			WarningCode string `json:"warning_code"`
			Proxy       struct {
				ID        string `json:"id"`
				Type      string `json:"type"`
				UDP       bool   `json:"udp"`
				ClashYAML string `json:"clash_yaml"`
			} `json:"proxy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.WarningCode != "vless_udp_disabled" || envelope.Data.Proxy.Type != "vless" || envelope.Data.Proxy.UDP {
		t.Fatalf("response = %+v", envelope.Data)
	}
	if envelope.Data.Proxy.ID == "" || !strings.Contains(envelope.Data.Proxy.ClashYAML, "********") {
		t.Fatalf("redacted proxy = %+v", envelope.Data.Proxy)
	}
	stored, err := database.UpstreamProxy(context.Background(), envelope.Data.Proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Password != "11111111-2222-4333-8444-555555555555" || stored.Protocol() != store.UpstreamProtocolVLESS {
		t.Fatalf("stored proxy = %+v", stored)
	}
	if strings.Contains(string(stored.Extra), stored.Password) {
		t.Fatal("VLESS UUID leaked into non-secret extra_json")
	}
}

func TestClashVLESSUpdatePreservesMaskedUUID(t *testing.T) {
	server, database := newClashProxyTestServer(t)
	created := clashProxyRequest(t, server, http.MethodPost, "", clashVLESSAPIYAML)
	if created.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var envelope struct {
		Data struct {
			Proxy struct {
				ID        string `json:"id"`
				ClashYAML string `json:"clash_yaml"`
			} `json:"proxy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	updatedYAML := strings.Replace(envelope.Data.Proxy.ClashYAML, "www.example.com", "cdn.example.com", 1)
	updated := clashProxyRequest(t, server, http.MethodPut, envelope.Data.Proxy.ID, updatedYAML)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", updated.Code, updated.Body.String())
	}
	stored, err := database.UpstreamProxy(context.Background(), envelope.Data.Proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Password != "11111111-2222-4333-8444-555555555555" || !strings.Contains(string(stored.Extra), "cdn.example.com") {
		t.Fatalf("stored update = %+v, extra = %s", stored, stored.Extra)
	}
}

func TestClashVLESSImportRejectsPlaceholderCredentialsWithoutPartialSave(t *testing.T) {
	server, database := newClashProxyTestServer(t)
	invalid := strings.Replace(clashVLESSAPIYAML, "11111111-2222-4333-8444-555555555555", "123", 1)
	response := clashProxyRequest(t, server, http.MethodPost, "", invalid)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", response.Code, response.Body.String())
	}
	values, err := database.ListUpstreamProxies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 0 {
		t.Fatalf("invalid import persisted %d proxies", len(values))
	}
}

func TestProfileBindingRejectsVLESSWithUDPDisabled(t *testing.T) {
	server, database, _ := newProfileBindingTestServer(t)
	imported := clashProxyRequest(t, server, http.MethodPost, "", clashVLESSAPIYAML)
	if imported.Code != http.StatusOK {
		t.Fatalf("import status = %d, body = %s", imported.Code, imported.Body.String())
	}
	values, err := database.ListUpstreamProxies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var importedID string
	for _, value := range values {
		if value.Protocol() == store.UpstreamProtocolVLESS {
			importedID = value.ID
		}
	}
	requestBody := `{"upstream_proxy_id":"` + importedID + `","bindings":[{"device_id":"ec20","iccid":"8944100000000000001","profile_name":"Profile"}]}`
	response := profileBindingRequest(t, server, http.MethodPost, requestBody)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "upstream_proxy_udp_disabled") {
		t.Fatalf("binding status = %d, body = %s", response.Code, response.Body.String())
	}
}
