package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"vocat/internal/device"
	managedproxy "vocat/internal/proxy"
	"vocat/internal/store"
	"vocat/internal/vowifi"
)

type fakeVLESSCore struct {
	address string
	calls   int
	node    managedproxy.VLESSNode
}

func (core *fakeVLESSCore) Ensure(_ context.Context, _ string, node managedproxy.VLESSNode) (string, error) {
	core.calls++
	core.node = node
	return core.address, nil
}

func (*fakeVLESSCore) Stop(string) error { return nil }

func testStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestProxyResolverUsesICCIDProfileBinding(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertUpstreamProxy(context.Background(), store.UpstreamProxy{
		ID:       "clash",
		Name:     "Clash",
		Addr:     "192.168.2.143:7897",
		Enabled:  true,
		Password: "must-not-be-lost",
		Username: "proxy-user",
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDeviceProxyBinding(context.Background(), store.DeviceProxyBinding{
		DeviceID:        "ec20",
		ICCID:           "8944100000000000001",
		ProfileName:     "Vodafone UK",
		UpstreamProxyID: "clash",
	}); err != nil {
		t.Fatal(err)
	}
	route, err := (ProxyResolver{Store: database}).Resolve(
		context.Background(),
		vowifi.ProxyRequest{DeviceID: "ec20", ICCID: "8944100000000000001", HomeMCC: "234", HomeMNC: "15"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != vowifi.ProxyModeSOCKS5 ||
		route.Address != "192.168.2.143:7897" ||
		route.Username != "proxy-user" ||
		route.Password != "must-not-be-lost" {
		t.Fatalf("route = %#v", route)
	}
}

func TestProxyResolverStartsManagedVLESSAndReturnsPrivateSOCKSRoute(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	node := managedproxy.VLESSNode{
		Name: "Managed", Type: "vless", Server: "edge.example.com", Port: 443,
		UUID: "11111111-2222-4333-8444-555555555555", Flow: "xtls-rprx-vision",
		Network: "tcp", TLS: true, ClientFingerprint: "chrome", UDP: true,
		RealityOptions: managedproxy.RealityOptions{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ShortID:   "0123456789abcdef",
		},
		ALPN: []string{"h2", "http/1.1"}, ServerName: "www.example.com",
	}
	extra, err := node.StoredExtra()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertUpstreamProxy(context.Background(), store.UpstreamProxy{
		ID: "managed", Name: node.Name, Addr: node.ServerAddress(), Password: node.UUID, Enabled: true, Extra: extra,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDeviceProxyBinding(context.Background(), store.DeviceProxyBinding{
		DeviceID: "ec20", ICCID: "8944100000000000001", ProfileName: "Profile", UpstreamProxyID: "managed",
	}); err != nil {
		t.Fatal(err)
	}
	core := &fakeVLESSCore{address: "127.0.0.1:39123"}
	route, err := (ProxyResolver{Store: database, VLESSCore: core}).Resolve(
		context.Background(),
		vowifi.ProxyRequest{DeviceID: "ec20", ICCID: "8944100000000000001"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != vowifi.ProxyModeSOCKS5 || route.Address != core.address || route.Username != "" || route.Password != "" {
		t.Fatalf("route = %#v", route)
	}
	if core.calls != 1 || core.node.UUID != node.UUID || core.node.RealityOptions != node.RealityOptions {
		t.Fatalf("core = %+v", core)
	}
}

func TestProxyResolverRejectsManagedVLESSWithUDPDisabled(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	node := managedproxy.VLESSNode{
		Name: "No UDP", Type: "vless", Server: "edge.example.com", Port: 443,
		UUID: "11111111-2222-4333-8444-555555555555", Network: "tcp", TLS: true,
		ClientFingerprint: "chrome", UDP: false,
		RealityOptions: managedproxy.RealityOptions{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		ServerName:     "www.example.com",
	}
	extra, err := node.StoredExtra()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertUpstreamProxy(context.Background(), store.UpstreamProxy{
		ID: "no-udp", Name: node.Name, Addr: node.ServerAddress(), Password: node.UUID, Enabled: true, Extra: extra,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDeviceProxyBinding(context.Background(), store.DeviceProxyBinding{
		DeviceID: "ec20", ICCID: "8944100000000000001", ProfileName: "Profile", UpstreamProxyID: "no-udp",
	}); err != nil {
		t.Fatal(err)
	}
	core := &fakeVLESSCore{address: "127.0.0.1:39123"}
	_, err = (ProxyResolver{Store: database, VLESSCore: core}).Resolve(
		context.Background(),
		vowifi.ProxyRequest{DeviceID: "ec20", ICCID: "8944100000000000001"},
	)
	if !errors.Is(err, managedproxy.ErrVLESSUDPDisabled) || core.calls != 0 {
		t.Fatalf("Resolve() error = %v, core calls = %d", err, core.calls)
	}
}

func TestProxyResolverDoesNotLeakBindingToAnotherProfileOnSameDevice(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertUpstreamProxy(context.Background(), store.UpstreamProxy{ID: "proxy", Name: "Proxy", Addr: "127.0.0.1:1080", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDeviceProxyBinding(context.Background(), store.DeviceProxyBinding{DeviceID: "ec20", ICCID: "8944100000000000001", ProfileName: "A", UpstreamProxyID: "proxy"}); err != nil {
		t.Fatal(err)
	}
	route, err := (ProxyResolver{Store: database}).Resolve(context.Background(), vowifi.ProxyRequest{DeviceID: "ec20", ICCID: "89104100000028106378"})
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != vowifi.ProxyModeDirect {
		t.Fatalf("route = %#v, want direct for unbound ICCID", route)
	}
}

func TestProxyResolverUsesCountryRuleWithoutICCIDBinding(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertUpstreamProxy(context.Background(), store.UpstreamProxy{
		ID: "legacy", Name: "Legacy", Addr: "127.0.0.1:1080", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCountryRule(context.Background(), store.CountryRule{
		CountryCode: "GB", CountryName: "United Kingdom", UpstreamProxyID: "legacy", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	route, err := (ProxyResolver{Store: database}).Resolve(
		context.Background(),
		vowifi.ProxyRequest{DeviceID: "ec20", HomeMCC: "234"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != vowifi.ProxyModeSOCKS5 || route.ID != "legacy" {
		t.Fatalf("route = %#v, want MCC country fallback", route)
	}
}

func TestProxyResolverCountryRuleWithDisabledProxyFallsBackDirect(t *testing.T) {
	database := testStore(t)
	ctx := context.Background()
	if err := database.UpsertUpstreamProxy(ctx, store.UpstreamProxy{
		ID: "disabled", Name: "Disabled", Addr: "127.0.0.1:1080", Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCountryRule(ctx, store.CountryRule{
		CountryCode: "GB", CountryName: "United Kingdom", UpstreamProxyID: "disabled", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	route, err := (ProxyResolver{Store: database}).Resolve(ctx, vowifi.ProxyRequest{DeviceID: "ec20", HomeMCC: "234"})
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != vowifi.ProxyModeDirect {
		t.Fatalf("route = %#v, want direct for a disabled country default", route)
	}
}

func TestProxyResolverICCIDBindingWithDisabledProxyFailsClosed(t *testing.T) {
	database := testStore(t)
	ctx := context.Background()
	if err := database.UpsertDevice(ctx, store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertUpstreamProxy(ctx, store.UpstreamProxy{
		ID: "disabled", Name: "Disabled", Addr: "127.0.0.1:1080", Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDeviceProxyBinding(ctx, store.DeviceProxyBinding{
		DeviceID: "ec20", ICCID: "8944100000000000001", ProfileName: "Manual", UpstreamProxyID: "disabled",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := (ProxyResolver{Store: database}).Resolve(ctx, vowifi.ProxyRequest{
		DeviceID: "ec20", ICCID: "8944100000000000001", HomeMCC: "234",
	})
	if err == nil {
		t.Fatal("disabled explicit ICCID binding unexpectedly fell back to another route")
	}
}

func TestProxyResolverMaterializesCountryRuleAsICCIDBinding(t *testing.T) {
	database := testStore(t)
	ctx := context.Background()
	if err := database.UpsertDevice(ctx, store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	for _, proxy := range []store.UpstreamProxy{
		{ID: "first", Name: "First", Addr: "127.0.0.1:1080", Enabled: true},
		{ID: "later", Name: "Later", Addr: "127.0.0.1:1081", Enabled: true},
	} {
		if err := database.UpsertUpstreamProxy(ctx, proxy); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.UpsertCountryRule(ctx, store.CountryRule{
		CountryCode: "GB", CountryName: "United Kingdom", UpstreamProxyID: "first", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	request := vowifi.ProxyRequest{
		DeviceID: "ec20", ICCID: "8944100000000000001", HomeMCC: "234",
	}
	resolver := ProxyResolver{Store: database}
	route, err := resolver.Resolve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if route.ID != "first" {
		t.Fatalf("first route = %#v, want MCC default", route)
	}
	binding, err := database.DeviceProxyBinding(ctx, request.ICCID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.DeviceID != request.DeviceID || binding.UpstreamProxyID != "first" {
		t.Fatalf("materialized binding = %#v", binding)
	}

	if err := database.UpsertCountryRule(ctx, store.CountryRule{
		CountryCode: "GB", CountryName: "United Kingdom", UpstreamProxyID: "later", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	route, err = resolver.Resolve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if route.ID != "first" {
		t.Fatalf("route after country rule edit = %#v, want durable ICCID binding", route)
	}
}

func TestInsertDeviceProxyBindingIfAbsentDoesNotReplaceExplicitBinding(t *testing.T) {
	database := testStore(t)
	ctx := context.Background()
	if err := database.UpsertDevice(ctx, store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	for _, proxyID := range []string{"explicit", "default"} {
		if err := database.UpsertUpstreamProxy(ctx, store.UpstreamProxy{
			ID: proxyID, Name: proxyID, Addr: "127.0.0.1:1080", Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	iccid := "8944100000000000001"
	if err := database.UpsertDeviceProxyBinding(ctx, store.DeviceProxyBinding{
		DeviceID: "ec20", ICCID: iccid, ProfileName: "Manual", UpstreamProxyID: "explicit",
	}); err != nil {
		t.Fatal(err)
	}
	created, err := database.InsertDeviceProxyBindingIfAbsent(ctx, store.DeviceProxyBinding{
		DeviceID: "ec20", ICCID: iccid, ProfileName: "Automatic", UpstreamProxyID: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("default binding unexpectedly replaced an explicit binding")
	}
	binding, err := database.DeviceProxyBinding(ctx, iccid)
	if err != nil {
		t.Fatal(err)
	}
	if binding.UpstreamProxyID != "explicit" || binding.ProfileName != "Manual" {
		t.Fatalf("binding = %#v, want explicit binding unchanged", binding)
	}
}

func TestProxyResolverPrefersICCIDBindingOverCountryRule(t *testing.T) {
	database := testStore(t)
	for _, proxy := range []store.UpstreamProxy{
		{ID: "profile", Name: "Profile", Addr: "127.0.0.1:1080", Enabled: true},
		{ID: "country", Name: "Country", Addr: "127.0.0.1:1081", Enabled: true},
	} {
		if err := database.UpsertUpstreamProxy(context.Background(), proxy); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.UpsertCountryRule(context.Background(), store.CountryRule{
		CountryCode: "GB", CountryName: "United Kingdom", UpstreamProxyID: "country", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDevice(context.Background(), store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDeviceProxyBinding(context.Background(), store.DeviceProxyBinding{
		DeviceID: "ec20", ICCID: "8944100000000000001", ProfileName: "Physical SIM", UpstreamProxyID: "profile",
	}); err != nil {
		t.Fatal(err)
	}
	route, err := (ProxyResolver{Store: database}).Resolve(context.Background(), vowifi.ProxyRequest{
		DeviceID: "ec20", ICCID: "8944100000000000001", HomeMCC: "234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if route.ID != "profile" {
		t.Fatalf("route = %#v, want ICCID binding", route)
	}
}

func TestPhoneStoreRejectsUntrustedSource(t *testing.T) {
	database := testStore(t)
	phones := PhoneStore{Store: database, DeviceID: "ec20"}
	record := vowifi.PhoneRecord{
		ICCID:     "89441000400311061404",
		Number:    "+447700900123",
		Source:    "imsi_guess",
		UpdatedAt: time.Now(),
	}
	if err := phones.SaveAssociatedNumber(context.Background(), record); err == nil {
		t.Fatal("untrusted source was accepted")
	}
	record.Source = vowifi.PhoneSourcePAssociatedURI
	if err := phones.SaveAssociatedNumber(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	got, err := database.PhoneAssociation(context.Background(), record.ICCID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Number != record.Number || got.Source != record.Source {
		t.Fatalf("association = %#v", got)
	}
}

func TestStateProjectorRestoresVerifiedNumber(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{
		ID:   "ec20",
		Name: "EC20",
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertPhoneAssociation(context.Background(), store.PhoneAssociation{
		ICCID:    "89441000400311061404",
		DeviceID: "ec20",
		Number:   "+447700900123",
		Source:   vowifi.PhoneSourcePAssociatedURI,
	}); err != nil {
		t.Fatal(err)
	}
	projector := StateProjector{
		Store: database,
		Devices: staticDeviceReader{
			iccid: "89441000400311061404",
			imsi:  "234159598901845",
		},
	}
	if err := projector.Save(context.Background(), vowifi.State{
		DeviceID:  "ec20",
		Phase:     vowifi.PhaseIdle,
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := database.VoWiFiRuntime(context.Background(), "ec20")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.LocalPhone != "+447700900123" ||
		runtime.PhoneNumberSource != vowifi.PhoneSourcePAssociatedURI {
		t.Fatalf("runtime phone = %q (%q)", runtime.LocalPhone, runtime.PhoneNumberSource)
	}
	var tunnel map[string]any
	if err := json.Unmarshal(runtime.Tunnel, &tunnel); err != nil {
		t.Fatal(err)
	}
}

func TestStateProjectorPreservesConcreteDataplaneMode(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{
		ID:   "ec25",
		Name: "EC25",
	}); err != nil {
		t.Fatal(err)
	}
	projector := StateProjector{Store: database}
	if err := projector.Save(context.Background(), vowifi.State{
		DeviceID:           "ec25",
		Phase:              vowifi.PhaseIMSReady,
		TunnelReady:        true,
		IMSReady:           true,
		TunnelName:         "vocat-swu-ec25",
		DataplaneMode:      "userspace",
		CarrierProfile:     "vodafone-uk",
		CarrierProfileFrom: "hplmn",
		UpdatedAt:          time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := database.VoWiFiRuntime(context.Background(), "ec25")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.DataplaneMode != "userspace" {
		t.Fatalf("dataplane mode = %q, want userspace", runtime.DataplaneMode)
	}
	var tunnel map[string]any
	if err := json.Unmarshal(runtime.Tunnel, &tunnel); err != nil {
		t.Fatal(err)
	}
	if tunnel["dataplane_mode"] != "userspace" {
		t.Fatalf("tunnel dataplane mode = %#v", tunnel["dataplane_mode"])
	}
	var extra map[string]any
	if err := json.Unmarshal(runtime.Extra, &extra); err != nil {
		t.Fatal(err)
	}
	if extra["carrier_profile"] != "vodafone-uk" || extra["carrier_profile_from"] != "hplmn" {
		t.Fatalf("carrier profile projection = %#v", extra)
	}
}

func TestStateProjectorDoesNotAttachOldSessionNumberToNewLiveSIM(t *testing.T) {
	database := testStore(t)
	if err := database.UpsertDevice(context.Background(), store.Device{ID: "ec20", Name: "EC20"}); err != nil {
		t.Fatal(err)
	}
	projector := StateProjector{
		Store: database,
		Devices: staticDeviceReader{
			iccid: "89104100000028106378",
			imsi:  "310380500712483",
		},
	}
	if err := projector.Save(context.Background(), vowifi.State{
		DeviceID:          "ec20",
		ICCID:             "8944100000000000001",
		IMSI:              "234150000000001",
		Phase:             vowifi.PhaseStopping,
		PhoneNumber:       "+447700900123",
		PhoneNumberSource: vowifi.PhoneSourcePAssociatedURI,
		UpdatedAt:         time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := database.VoWiFiRuntime(context.Background(), "ec20")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.ICCID != "8944100000000000001" || runtime.IMSI != "234150000000001" {
		t.Fatalf("runtime identity = %q/%q", runtime.ICCID, runtime.IMSI)
	}
	if runtime.LocalPhone != "+447700900123" {
		t.Fatalf("runtime phone = %q", runtime.LocalPhone)
	}
}

type staticDeviceReader struct {
	iccid string
	imsi  string
}

func (reader staticDeviceReader) Get(string) (device.Device, error) {
	return device.Device{
		Snapshot: &device.Snapshot{
			ICCID: reader.iccid,
			IMSI:  reader.imsi,
		},
	}, nil
}
