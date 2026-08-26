//go:build windows && (amd64 || arm64)

package ims

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var testWindowsIPSecSubLayer = windows.GUID{
	Data1: 0x3d53b459,
	Data2: 0x029f,
	Data3: 0x4ad1,
	Data4: [8]byte{0x8e, 0x84, 0xb0, 0x38, 0xe4, 0x76, 0x66, 0xf9},
}

func TestWindowsWFPLayoutsMatchSDK64(t *testing.T) {
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"FWP_BYTE_BLOB", unsafe.Sizeof(wfpByteBlob{}), 16},
		{"FWP_VALUE0", unsafe.Sizeof(wfpValue0{}), 16},
		{"FWPM_DISPLAY_DATA0", unsafe.Sizeof(wfpDisplayData0{}), 16},
		{"FWPM_ACTION0", unsafe.Sizeof(wfpAction0{}), 20},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(wfpFilterCondition0{}), 40},
		{"FWPM_FILTER0", unsafe.Sizeof(wfpFilter0{}), 200},
		{"FWPM_SESSION0", unsafe.Sizeof(wfpSession0{}), 72},
		{"FWPM_SUBLAYER0", unsafe.Sizeof(wfpSubLayer0{}), 72},
		{"IPSEC_AUTH_TRANSFORM_ID0", unsafe.Sizeof(wfpIPSecAuthTransformID0{}), 8},
		{"IPSEC_AUTH_TRANSFORM0", unsafe.Sizeof(wfpIPSecAuthTransform0{}), 16},
		{"IPSEC_CIPHER_TRANSFORM_ID0", unsafe.Sizeof(wfpIPSecCipherTransformID0{}), 8},
		{"IPSEC_CIPHER_TRANSFORM0", unsafe.Sizeof(wfpIPSecCipherTransform0{}), 16},
		{"IPSEC_SA_AUTH_INFORMATION0", unsafe.Sizeof(wfpIPSecSAAuthInformation0{}), 32},
		{"IPSEC_SA_CIPHER_INFORMATION0", unsafe.Sizeof(wfpIPSecSACipherInformation0{}), 32},
		{"IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0", unsafe.Sizeof(wfpIPSecSAAuthAndCipherInformation0{}), 64},
		{"IPSEC_SA0", unsafe.Sizeof(wfpIPSecSA0{}), 16},
		{"IPSEC_SA_BUNDLE1", unsafe.Sizeof(wfpIPSecSABundle1{}), 112},
		{"IPSEC_TRAFFIC1", unsafe.Sizeof(wfpIPSecTraffic1{}), 72},
		{"IPSEC_GETSPI1", unsafe.Sizeof(wfpIPSecGetSPI1{}), 96},
		{"FWPM_FILTER0.action", unsafe.Offsetof(wfpFilter0{}.action), 128},
		{"FWPM_FILTER0.filterID", unsafe.Offsetof(wfpFilter0{}.filterID), 176},
		{"IPSEC_SA_BUNDLE1.ipsecID", unsafe.Offsetof(wfpIPSecSABundle1{}.ipsecID), 24},
		{"IPSEC_SA_BUNDLE1.saList", unsafe.Offsetof(wfpIPSecSABundle1{}.saList), 48},
		{"IPSEC_SA_BUNDLE1.ipVersion", unsafe.Offsetof(wfpIPSecSABundle1{}.ipVersion), 64},
		{"IPSEC_SA_BUNDLE1.mmSAID", unsafe.Offsetof(wfpIPSecSABundle1{}.mmSAID), 72},
		{"IPSEC_SA_BUNDLE1.pfsGroup", unsafe.Offsetof(wfpIPSecSABundle1{}.pfsGroup), 80},
		{"IPSEC_SA_BUNDLE1.saLookupContext", unsafe.Offsetof(wfpIPSecSABundle1{}.saLookupContext), 84},
		{"IPSEC_SA_BUNDLE1.qmFilterID", unsafe.Offsetof(wfpIPSecSABundle1{}.qmFilterID), 104},
		{"IPSEC_TRAFFIC1.trafficType", unsafe.Offsetof(wfpIPSecTraffic1{}.trafficType), 36},
		{"IPSEC_TRAFFIC1.ipsecFilterID", unsafe.Offsetof(wfpIPSecTraffic1{}.ipsecFilterID), 40},
		{"IPSEC_TRAFFIC1.remotePort", unsafe.Offsetof(wfpIPSecTraffic1{}.remotePort), 48},
		{"IPSEC_TRAFFIC1.localPort", unsafe.Offsetof(wfpIPSecTraffic1{}.localPort), 50},
		{"IPSEC_TRAFFIC1.ipProtocol", unsafe.Offsetof(wfpIPSecTraffic1{}.ipProtocol), 52},
		{"IPSEC_TRAFFIC1.localIfLUID", unsafe.Offsetof(wfpIPSecTraffic1{}.localIfLUID), 56},
		{"IPSEC_TRAFFIC1.realIfProfileID", unsafe.Offsetof(wfpIPSecTraffic1{}.realIfProfileID), 64},
		{"IPSEC_GETSPI1.ipVersion", unsafe.Offsetof(wfpIPSecGetSPI1{}.ipVersion), 72},
		{"IPSEC_GETSPI1.inboundUDPEncapsulation", unsafe.Offsetof(wfpIPSecGetSPI1{}.inboundUDPEncapsulation), 80},
		{"IPSEC_GETSPI1.rngCryptoModuleID", unsafe.Offsetof(wfpIPSecGetSPI1{}.rngCryptoModuleID), 88},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("layout = %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestBuildWindowsIPSecPlanUsesTwoBidirectionalSAPairs(t *testing.T) {
	config := testIPSecSAConfig()
	plan, err := buildWindowsIPSecPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 {
		t.Fatalf("pair count = %d, want 2", len(plan))
	}
	if plan[0].inboundSPI != config.UEClientSPI || plan[0].outboundSPI != config.PCSCFServerSPI {
		t.Fatalf("client pair SPIs = %#v", plan[0])
	}
	if plan[0].inbound.localPort != uint16(config.UEClientPort) ||
		plan[0].inbound.remotePort != uint16(config.PCSCFServerPort) {
		t.Fatalf("client inbound ports = %#v", plan[0].inbound)
	}
	if plan[1].inboundSPI != config.UEServerSPI || plan[1].outboundSPI != config.PCSCFClientSPI {
		t.Fatalf("server pair SPIs = %#v", plan[1])
	}
	if plan[1].inbound.localPort != uint16(config.UEServerPort) || plan[1].inbound.remotePort != 0 {
		t.Fatalf("server inbound ports = %#v", plan[1].inbound)
	}
	if plan[0].qmSAID == 0 || plan[1].qmSAID == 0 || plan[0].qmSAID == plan[1].qmSAID {
		t.Fatalf("QM SA IDs = %d and %d", plan[0].qmSAID, plan[1].qmSAID)
	}
}

func TestBuildWindowsWFPFilterUsesExactIMSFlow(t *testing.T) {
	plan, err := buildWindowsIPSecPlan(testIPSecSAConfig())
	if err != nil {
		t.Fatal(err)
	}
	client, err := buildWindowsWFPFilter(plan[0].outbound, testWindowsIPSecSubLayer)
	if err != nil {
		t.Fatal(err)
	}
	if client.filter.layerKey != windowsFWPLayerOutboundTransportV4 ||
		client.filter.action.calloutKey != windowsFWPCalloutIPSecOutboundTransportV4 {
		t.Fatalf("client filter layer/action = %#v/%#v", client.filter.layerKey, client.filter.action)
	}
	if client.filter.flags&wfpFilterFlagNoAcquire == 0 {
		t.Fatal("client filter permits native IKE acquisition")
	}
	if len(client.conditions) != 5 {
		t.Fatalf("client condition count = %d, want 5", len(client.conditions))
	}
	if got := conditionValue(t, client.conditions, windowsFWPConditionIPLocalPort); got != uintptr(testIPSecSAConfig().UEClientPort) {
		t.Fatalf("local port = %d", got)
	}
	if got := conditionValue(t, client.conditions, windowsFWPConditionIPRemotePort); got != uintptr(testIPSecSAConfig().PCSCFServerPort) {
		t.Fatalf("remote port = %d", got)
	}

	serverInbound, err := buildWindowsWFPFilter(plan[1].inbound, testWindowsIPSecSubLayer)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverInbound.conditions) != 4 {
		t.Fatalf("server inbound condition count = %d, want 4", len(serverInbound.conditions))
	}
	for _, condition := range serverInbound.conditions {
		if condition.fieldKey == windowsFWPConditionIPRemotePort {
			t.Fatal("server inbound filter unexpectedly constrained the carrier source port")
		}
	}
}

func TestWindowsIPSecAddressRepresentations(t *testing.T) {
	version, ipv4, err := windowsIPSecAddress(net.IPv4(10, 0, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	if version != wfpIPVersionV4 || !reflect.DeepEqual(ipv4[:4], []byte{2, 0, 0, 10}) {
		t.Fatalf("IPv4 representation = %d/%x", version, ipv4)
	}

	ip := net.ParseIP("2001:db8::102:304").To16()
	version, ipv6, err := windowsIPSecAddress(ip)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), ip...)
	if version != wfpIPVersionV6 || !reflect.DeepEqual(ipv6[:], want) {
		t.Fatalf("IPv6 representation = %d/%x, want %x", version, ipv6, want)
	}
}

func TestWindowsIPSecBundlesSupportNegotiatedTransforms(t *testing.T) {
	tests := []struct {
		name          string
		integrity     string
		encryption    string
		integrityKey  int
		encryptionKey int
		transform     uint32
		authType      uint32
		cipherType    uint32
	}{
		{"SHA1 null", "hmac-sha-1-96", "null", 20, 0, wfpIPSecTransformESPAuth, 1, 0},
		{"SHA1 AES", "hmac-sha-1-96", "aes-cbc", 20, 16, wfpIPSecTransformESPAuthAndCipher, 1, 3},
		{"MD5 3DES", "hmac-md5-96", "des-ede3-cbc", 16, 24, wfpIPSecTransformESPAuthAndCipher, 0, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testIPSecSAConfig()
			config.IntegrityAlgorithm = test.integrity
			config.EncryptionAlgorithm = test.encryption
			config.IntegrityKey = []byte(strings.Repeat("I", test.integrityKey))
			config.EncryptionKey = []byte(strings.Repeat("E", test.encryptionKey))
			material, err := buildWindowsIPSecBundle(config, 0x10203040, 42, wfpIPVersionV4)
			if err != nil {
				t.Fatal(err)
			}
			if material.sa.spi != 0x10203040 || material.sa.transformType != test.transform {
				t.Fatalf("SA = %#v", material.sa)
			}
			if material.auth.authTransform.authTransformID.authType != test.authType {
				t.Fatalf("auth transform = %#v", material.auth.authTransform.authTransformID)
			}
			if test.transform == wfpIPSecTransformESPAuthAndCipher &&
				material.authAndCipher.saCipherInformation.cipherTransform.cipherTransformID.cipherType != test.cipherType {
				t.Fatalf("cipher transform = %#v", material.authAndCipher.saCipherInformation.cipherTransform.cipherTransformID)
			}
			if material.bundle.qmSAID != 42 || material.bundle.numSAs != 1 || material.bundle.saList != &material.sa {
				t.Fatalf("bundle = %#v", material.bundle)
			}
			material.zeroKeys()
			for _, key := range append(material.authKey, material.cipherKey...) {
				if key != 0 {
					t.Fatal("bundle retained key material after zeroKeys")
				}
			}
		})
	}
}

func TestWindowsIPSecInstallerOrderAndCleanup(t *testing.T) {
	api := &fakeWindowsWFPAPI{}
	handle, err := (windowsIPSecInstaller{api: api}).Install(context.Background(), testIPSecSAConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantInstall := []string{
		"open", "add-sublayer",
		"add-filter", "add-filter", "create-context", "set-spi", "add-inbound", "add-outbound",
		"add-filter", "add-filter", "create-context", "set-spi", "add-inbound", "add-outbound",
	}
	if !reflect.DeepEqual(api.operations, wantInstall) {
		t.Fatalf("install operations = %v, want %v", api.operations, wantInstall)
	}
	if got, want := api.spis, []uint32{testIPSecSAConfig().UEClientSPI, testIPSecSAConfig().UEServerSPI}; !reflect.DeepEqual(got, want) {
		t.Fatalf("inbound SPIs = %v, want %v", got, want)
	}
	if len(api.subLayerKeys) != 1 || api.subLayerKeys[0] == (windows.GUID{}) {
		t.Fatalf("dynamic sublayer keys = %#v", api.subLayerKeys)
	}
	for _, key := range api.filterSubLayerKeys {
		if key != api.subLayerKeys[0] {
			t.Fatalf("filter sublayer key = %#v, want %#v", key, api.subLayerKeys[0])
		}
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantTail := []string{
		"delete-context:102", "delete-context:101",
		"delete-filter:4", "delete-filter:3", "delete-filter:2", "delete-filter:1",
		"delete-sublayer", "close",
	}
	if got := api.operations[len(wantInstall):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("cleanup operations = %v, want %v", got, wantTail)
	}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := api.operations[len(wantInstall):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("second close changed operations: %v", got)
	}
}

func TestWindowsIPSecInstallerUsesUniqueSubLayerPerInstall(t *testing.T) {
	firstAPI := &fakeWindowsWFPAPI{}
	first, err := (windowsIPSecInstaller{api: firstAPI}).Install(context.Background(), testIPSecSAConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	secondAPI := &fakeWindowsWFPAPI{}
	second, err := (windowsIPSecInstaller{api: secondAPI}).Install(context.Background(), testIPSecSAConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if firstAPI.subLayerKeys[0] == secondAPI.subLayerKeys[0] {
		t.Fatalf("two installs reused WFP sublayer key %#v", firstAPI.subLayerKeys[0])
	}
}

func TestWindowsIPSecInstallerRollsBackPartialInstall(t *testing.T) {
	sentinel := errors.New("injected WFP failure")
	api := &fakeWindowsWFPAPI{failOperation: "add-outbound", failErr: sentinel}
	handle, err := (windowsIPSecInstaller{api: api}).Install(context.Background(), testIPSecSAConfig())
	if handle != nil {
		t.Fatal("partial install returned a handle")
	}
	if !errors.Is(err, ErrIPSecInstall) || !errors.Is(err, sentinel) {
		t.Fatalf("error = %v", err)
	}
	wantTail := []string{
		"delete-context:101", "delete-filter:2", "delete-filter:1", "delete-sublayer", "close",
	}
	if got := api.operations[len(api.operations)-len(wantTail):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("rollback operations = %v, want %v", got, wantTail)
	}
}

func conditionValue(t *testing.T, conditions []wfpFilterCondition0, key windows.GUID) uintptr {
	t.Helper()
	for _, condition := range conditions {
		if condition.fieldKey == key {
			return condition.conditionValue.value
		}
	}
	t.Fatalf("condition %v not found", key)
	return 0
}

type fakeWindowsWFPAPI struct {
	operations         []string
	filterID           uint64
	contextID          uint64
	spis               []uint32
	subLayerKeys       []windows.GUID
	filterSubLayerKeys []windows.GUID
	failOperation      string
	failErr            error
}

func (api *fakeWindowsWFPAPI) operation(name string) error {
	api.operations = append(api.operations, name)
	if name == api.failOperation {
		return api.failErr
	}
	return nil
}

func (api *fakeWindowsWFPAPI) openEngine(*wfpSession0) (windows.Handle, error) {
	if err := api.operation("open"); err != nil {
		return 0, err
	}
	return windows.Handle(1), nil
}

func (api *fakeWindowsWFPAPI) closeEngine(windows.Handle) error {
	return api.operation("close")
}

func (api *fakeWindowsWFPAPI) addSubLayer(_ windows.Handle, subLayer *wfpSubLayer0) error {
	api.subLayerKeys = append(api.subLayerKeys, subLayer.subLayerKey)
	return api.operation("add-sublayer")
}

func (api *fakeWindowsWFPAPI) deleteSubLayer(windows.Handle, *windows.GUID) error {
	return api.operation("delete-sublayer")
}

func (api *fakeWindowsWFPAPI) addFilter(_ windows.Handle, filter *wfpFilter0) (uint64, error) {
	api.filterSubLayerKeys = append(api.filterSubLayerKeys, filter.subLayerKey)
	if err := api.operation("add-filter"); err != nil {
		return 0, err
	}
	api.filterID++
	return api.filterID, nil
}

func (api *fakeWindowsWFPAPI) deleteFilter(_ windows.Handle, id uint64) error {
	return api.operation("delete-filter:" + strconv.FormatUint(id, 10))
}

func (api *fakeWindowsWFPAPI) createSAContext(windows.Handle, *wfpIPSecTraffic1) (uint64, error) {
	if err := api.operation("create-context"); err != nil {
		return 0, err
	}
	api.contextID++
	return 100 + api.contextID, nil
}

func (api *fakeWindowsWFPAPI) setSAContextSPI(
	_ windows.Handle,
	_ uint64,
	_ *wfpIPSecGetSPI1,
	spi uint32,
) error {
	api.spis = append(api.spis, spi)
	return api.operation("set-spi")
}

func (api *fakeWindowsWFPAPI) addInboundSA(windows.Handle, uint64, *wfpIPSecSABundle1) error {
	return api.operation("add-inbound")
}

func (api *fakeWindowsWFPAPI) addOutboundSA(windows.Handle, uint64, *wfpIPSecSABundle1) error {
	return api.operation("add-outbound")
}

func (api *fakeWindowsWFPAPI) deleteSAContext(_ windows.Handle, id uint64) error {
	return api.operation("delete-context:" + strconv.FormatUint(id, 10))
}
