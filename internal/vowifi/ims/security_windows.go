//go:build windows && (amd64 || arm64)

package ims

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsIPSecInstaller struct {
	api windowsWFPAPI
}

func defaultIPSecInstaller() IPSecSAInstaller {
	return windowsIPSecInstaller{api: windowsWFPSystemAPI{}}
}

type windowsWFPAPI interface {
	openEngine(*wfpSession0) (windows.Handle, error)
	closeEngine(windows.Handle) error
	addSubLayer(windows.Handle, *wfpSubLayer0) error
	deleteSubLayer(windows.Handle, *windows.GUID) error
	addFilter(windows.Handle, *wfpFilter0) (uint64, error)
	deleteFilter(windows.Handle, uint64) error
	createSAContext(windows.Handle, *wfpIPSecTraffic1) (uint64, error)
	setSAContextSPI(windows.Handle, uint64, *wfpIPSecGetSPI1, uint32) error
	addInboundSA(windows.Handle, uint64, *wfpIPSecSABundle1) error
	addOutboundSA(windows.Handle, uint64, *wfpIPSecSABundle1) error
	deleteSAContext(windows.Handle, uint64) error
}

type windowsWFPSystemAPI struct{}

var (
	windowsFWPDLL = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0            = windowsFWPDLL.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0           = windowsFWPDLL.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0           = windowsFWPDLL.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0   = windowsFWPDLL.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0             = windowsFWPDLL.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByID0      = windowsFWPDLL.NewProc("FwpmFilterDeleteById0")
	procIPSecSAContextCreate1      = windowsFWPDLL.NewProc("IPsecSaContextCreate1")
	procIPSecSAContextSetSPI0      = windowsFWPDLL.NewProc("IPsecSaContextSetSpi0")
	procIPSecSAContextAddInbound1  = windowsFWPDLL.NewProc("IPsecSaContextAddInbound1")
	procIPSecSAContextAddOutbound1 = windowsFWPDLL.NewProc("IPsecSaContextAddOutbound1")
	procIPSecSAContextDeleteByID0  = windowsFWPDLL.NewProc("IPsecSaContextDeleteById0")
)

func (windowsWFPSystemAPI) openEngine(session *wfpSession0) (windows.Handle, error) {
	var engine windows.Handle
	status, _, _ := procFwpmEngineOpen0.Call(
		0,
		uintptr(rpcCAuthnWinNT),
		0,
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&engine)),
	)
	runtime.KeepAlive(session)
	return engine, windowsWFPStatus("open filtering engine", status)
}

func (windowsWFPSystemAPI) closeEngine(engine windows.Handle) error {
	status, _, _ := procFwpmEngineClose0.Call(uintptr(engine))
	return windowsWFPStatus("close filtering engine", status)
}

func (windowsWFPSystemAPI) addSubLayer(engine windows.Handle, subLayer *wfpSubLayer0) error {
	status, _, _ := procFwpmSubLayerAdd0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(subLayer)),
		0,
	)
	runtime.KeepAlive(subLayer)
	return windowsWFPStatus("add VoCat filtering sublayer", status)
}

func (windowsWFPSystemAPI) deleteSubLayer(engine windows.Handle, key *windows.GUID) error {
	status, _, _ := procFwpmSubLayerDeleteByKey0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(key)),
	)
	runtime.KeepAlive(key)
	return windowsWFPStatus("delete VoCat filtering sublayer", status)
}

func (windowsWFPSystemAPI) addFilter(engine windows.Handle, filter *wfpFilter0) (uint64, error) {
	var id uint64
	status, _, _ := procFwpmFilterAdd0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(filter)),
		0,
		uintptr(unsafe.Pointer(&id)),
	)
	runtime.KeepAlive(filter)
	return id, windowsWFPStatus("add IPsec transport filter", status)
}

func (windowsWFPSystemAPI) deleteFilter(engine windows.Handle, id uint64) error {
	status, _, _ := procFwpmFilterDeleteByID0.Call(uintptr(engine), uintptr(id))
	return windowsWFPStatus("delete IPsec transport filter", status)
}

func (windowsWFPSystemAPI) createSAContext(engine windows.Handle, traffic *wfpIPSecTraffic1) (uint64, error) {
	var id uint64
	status, _, _ := procIPSecSAContextCreate1.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(traffic)),
		0,
		0,
		uintptr(unsafe.Pointer(&id)),
	)
	runtime.KeepAlive(traffic)
	return id, windowsWFPStatus("create IPsec SA context", status)
}

func (windowsWFPSystemAPI) setSAContextSPI(
	engine windows.Handle,
	id uint64,
	getSPI *wfpIPSecGetSPI1,
	spi uint32,
) error {
	status, _, _ := procIPSecSAContextSetSPI0.Call(
		uintptr(engine),
		uintptr(id),
		uintptr(unsafe.Pointer(getSPI)),
		uintptr(spi),
	)
	runtime.KeepAlive(getSPI)
	return windowsWFPStatus("set inbound IPsec SPI", status)
}

func (windowsWFPSystemAPI) addInboundSA(
	engine windows.Handle,
	id uint64,
	bundle *wfpIPSecSABundle1,
) error {
	status, _, _ := procIPSecSAContextAddInbound1.Call(
		uintptr(engine),
		uintptr(id),
		uintptr(unsafe.Pointer(bundle)),
	)
	runtime.KeepAlive(bundle)
	return windowsWFPStatus("add inbound IPsec SA", status)
}

func (windowsWFPSystemAPI) addOutboundSA(
	engine windows.Handle,
	id uint64,
	bundle *wfpIPSecSABundle1,
) error {
	status, _, _ := procIPSecSAContextAddOutbound1.Call(
		uintptr(engine),
		uintptr(id),
		uintptr(unsafe.Pointer(bundle)),
	)
	runtime.KeepAlive(bundle)
	return windowsWFPStatus("add outbound IPsec SA", status)
}

func (windowsWFPSystemAPI) deleteSAContext(engine windows.Handle, id uint64) error {
	status, _, _ := procIPSecSAContextDeleteByID0.Call(uintptr(engine), uintptr(id))
	return windowsWFPStatus("delete IPsec SA context", status)
}

func windowsWFPStatus(operation string, status uintptr) error {
	if status == 0 {
		return nil
	}
	code := uint32(status)
	return fmt.Errorf("%s: WFP status 0x%08X: %w", operation, code, windows.Errno(code))
}

type windowsIPSecFlowPlan struct {
	name       string
	inbound    bool
	localIP    net.IP
	remoteIP   net.IP
	localPort  uint16
	remotePort uint16
}

type windowsIPSecPairPlan struct {
	name        string
	inbound     windowsIPSecFlowPlan
	outbound    windowsIPSecFlowPlan
	inboundSPI  uint32
	outboundSPI uint32
	qmSAID      uint32
}

func buildWindowsIPSecPlan(config IPSecSAConfig) ([]windowsIPSecPairPlan, error) {
	if err := validateIPSecSAConfig(config); err != nil {
		return nil, err
	}
	flow := func(name string, inbound bool, localPort int, remotePort int) windowsIPSecFlowPlan {
		return windowsIPSecFlowPlan{
			name:       name,
			inbound:    inbound,
			localIP:    append(net.IP(nil), config.LocalIP...),
			remoteIP:   append(net.IP(nil), config.RemoteIP...),
			localPort:  uint16(localPort),
			remotePort: uint16(remotePort),
		}
	}
	return []windowsIPSecPairPlan{
		{
			name: "UE-client and P-CSCF-server",
			outbound: flow(
				"VoCat IMS UE-client to P-CSCF-server",
				false,
				config.UEClientPort,
				config.PCSCFServerPort,
			),
			inbound: flow(
				"VoCat IMS P-CSCF-server to UE-client",
				true,
				config.UEClientPort,
				config.PCSCFServerPort,
			),
			outboundSPI: config.PCSCFServerSPI,
			inboundSPI:  config.UEClientSPI,
			qmSAID:      clientPairReqID(config),
		},
		{
			name: "UE-server and P-CSCF-client",
			outbound: flow(
				"VoCat IMS UE-server to P-CSCF-client",
				false,
				config.UEServerPort,
				config.PCSCFClientPort,
			),
			inbound: flow(
				"VoCat IMS P-CSCF-client to UE-server",
				true,
				config.UEServerPort,
				0,
			),
			outboundSPI: config.PCSCFClientSPI,
			inboundSPI:  config.UEServerSPI,
			qmSAID:      serverPairReqID(config),
		},
	}, nil
}

var (
	windowsFWPConditionIPLocalAddressType = windows.GUID{
		Data1: 0x6ec7f6c4, Data2: 0x376b, Data3: 0x45d7,
		Data4: [8]byte{0x9e, 0x9c, 0xd3, 0x37, 0xce, 0xdc, 0xd2, 0x37},
	}
	windowsFWPConditionIPLocalAddress = windows.GUID{
		Data1: 0xd9ee00de, Data2: 0xc1ef, Data3: 0x4617,
		Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57},
	}
	windowsFWPConditionIPRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
	windowsFWPConditionIPLocalPort = windows.GUID{
		Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f,
		Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
	}
	windowsFWPConditionIPRemotePort = windows.GUID{
		Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
)

var (
	windowsFWPLayerInboundTransportV4 = windows.GUID{
		Data1: 0x5926dfc8, Data2: 0xe3cf, Data3: 0x4426,
		Data4: [8]byte{0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d},
	}
	windowsFWPLayerOutboundTransportV4 = windows.GUID{
		Data1: 0x09e61aea, Data2: 0xd214, Data3: 0x46e2,
		Data4: [8]byte{0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8},
	}
	windowsFWPLayerInboundTransportV6 = windows.GUID{
		Data1: 0x634a869f, Data2: 0xfc23, Data3: 0x4b90,
		Data4: [8]byte{0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f},
	}
	windowsFWPLayerOutboundTransportV6 = windows.GUID{
		Data1: 0xe1735bde, Data2: 0x013f, Data3: 0x4655,
		Data4: [8]byte{0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0},
	}
)

var (
	windowsFWPCalloutIPSecInboundTransportV4 = windows.GUID{
		Data1: 0x5132900d, Data2: 0x5e84, Data3: 0x4b5f,
		Data4: [8]byte{0x80, 0xe4, 0x01, 0x74, 0x1e, 0x81, 0xff, 0x10},
	}
	windowsFWPCalloutIPSecOutboundTransportV4 = windows.GUID{
		Data1: 0x4b46bf0a, Data2: 0x4523, Data3: 0x4e57,
		Data4: [8]byte{0xaa, 0x38, 0xa8, 0x79, 0x87, 0xc9, 0x10, 0xd9},
	}
	windowsFWPCalloutIPSecInboundTransportV6 = windows.GUID{
		Data1: 0x49d3ac92, Data2: 0x2a6c, Data3: 0x4dcf,
		Data4: [8]byte{0x95, 0x5f, 0x1c, 0x3b, 0xe0, 0x09, 0xdd, 0x99},
	}
	windowsFWPCalloutIPSecOutboundTransportV6 = windows.GUID{
		Data1: 0x38d87722, Data2: 0xad83, Data3: 0x4f11,
		Data4: [8]byte{0xa9, 0x1f, 0xdf, 0x0f, 0xb0, 0x77, 0x22, 0x5b},
	}
)

type windowsWFPFilterMaterial struct {
	filter      wfpFilter0
	conditions  []wfpFilterCondition0
	addressesV6 []*wfpByteArray16
	name        []uint16
	description []uint16
}

func buildWindowsWFPFilter(
	flow windowsIPSecFlowPlan,
	subLayer windows.GUID,
) (*windowsWFPFilterMaterial, error) {
	material := &windowsWFPFilterMaterial{}
	name, err := windows.UTF16FromString(flow.name)
	if err != nil {
		return nil, fmt.Errorf("ims: encode Windows WFP filter name: %w", err)
	}
	description, err := windows.UTF16FromString("VoCat dynamic IMS ipsec-3gpp transport policy")
	if err != nil {
		return nil, fmt.Errorf("ims: encode Windows WFP filter description: %w", err)
	}
	material.name = name
	material.description = description
	material.conditions = append(material.conditions, wfpFilterCondition0{
		fieldKey:  windowsFWPConditionIPLocalAddressType,
		matchType: wfpMatchEqual,
		conditionValue: wfpValue0{
			typeID: wfpUint8,
			value:  uintptr(nlatUnicast),
		},
	})
	if err := material.appendAddressCondition(windowsFWPConditionIPLocalAddress, flow.localIP); err != nil {
		return nil, err
	}
	if err := material.appendAddressCondition(windowsFWPConditionIPRemoteAddress, flow.remoteIP); err != nil {
		return nil, err
	}
	material.appendPortCondition(windowsFWPConditionIPLocalPort, flow.localPort)
	material.appendPortCondition(windowsFWPConditionIPRemotePort, flow.remotePort)

	v6 := flow.localIP.To4() == nil
	layer := windowsFWPLayerOutboundTransportV4
	callout := windowsFWPCalloutIPSecOutboundTransportV4
	if flow.inbound {
		layer = windowsFWPLayerInboundTransportV4
		callout = windowsFWPCalloutIPSecInboundTransportV4
	}
	if v6 && flow.inbound {
		layer = windowsFWPLayerInboundTransportV6
		callout = windowsFWPCalloutIPSecInboundTransportV6
	} else if v6 {
		layer = windowsFWPLayerOutboundTransportV6
		callout = windowsFWPCalloutIPSecOutboundTransportV6
	}
	material.filter = wfpFilter0{
		displayData: wfpDisplayData0{
			name:        &material.name[0],
			description: &material.description[0],
		},
		flags:               wfpFilterFlagNoAcquire,
		layerKey:            layer,
		subLayerKey:         subLayer,
		weight:              wfpValue0{typeID: wfpEmpty},
		numFilterConditions: uint32(len(material.conditions)),
		filterCondition:     &material.conditions[0],
		action: wfpAction0{
			typeID:     wfpActionCalloutTerminating,
			calloutKey: callout,
		},
	}
	return material, nil
}

func (material *windowsWFPFilterMaterial) appendAddressCondition(field windows.GUID, ip net.IP) error {
	if ipv4 := ip.To4(); ipv4 != nil {
		material.conditions = append(material.conditions, wfpFilterCondition0{
			fieldKey:  field,
			matchType: wfpMatchEqual,
			conditionValue: wfpValue0{
				typeID: wfpUint32,
				value:  uintptr(binary.BigEndian.Uint32(ipv4)),
			},
		})
		return nil
	}
	ipv6 := ip.To16()
	if ipv6 == nil {
		return errors.New("ims: Windows WFP filter address is invalid")
	}
	value := &wfpByteArray16{}
	copy(value.bytes[:], ipv6)
	material.addressesV6 = append(material.addressesV6, value)
	material.conditions = append(material.conditions, wfpFilterCondition0{
		fieldKey:  field,
		matchType: wfpMatchEqual,
		conditionValue: wfpValue0{
			typeID: wfpByteArray16Type,
			value:  uintptr(unsafe.Pointer(value)),
		},
	})
	return nil
}

func (material *windowsWFPFilterMaterial) appendPortCondition(field windows.GUID, port uint16) {
	if port == 0 {
		return
	}
	material.conditions = append(material.conditions, wfpFilterCondition0{
		fieldKey:  field,
		matchType: wfpMatchEqual,
		conditionValue: wfpValue0{
			typeID: wfpUint16,
			value:  uintptr(port),
		},
	})
}

func buildWindowsIPSecTraffic(flow windowsIPSecFlowPlan, filterID uint64) (wfpIPSecTraffic1, error) {
	traffic := wfpIPSecTraffic1{
		trafficType:   wfpIPSecTransport,
		ipsecFilterID: filterID,
		remotePort:    flow.remotePort,
		localPort:     flow.localPort,
	}
	version, local, err := windowsIPSecAddress(flow.localIP)
	if err != nil {
		return wfpIPSecTraffic1{}, err
	}
	remoteVersion, remote, err := windowsIPSecAddress(flow.remoteIP)
	if err != nil {
		return wfpIPSecTraffic1{}, err
	}
	if version != remoteVersion {
		return wfpIPSecTraffic1{}, errors.New("ims: Windows WFP traffic endpoints use different IP families")
	}
	traffic.ipVersion = version
	traffic.localAddress = local
	traffic.remoteAddress = remote
	return traffic, nil
}

func windowsIPSecAddress(ip net.IP) (uint32, [16]byte, error) {
	var result [16]byte
	if ipv4 := ip.To4(); ipv4 != nil {
		binary.LittleEndian.PutUint32(result[:4], binary.BigEndian.Uint32(ipv4))
		return wfpIPVersionV4, result, nil
	}
	ipv6 := ip.To16()
	if ipv6 == nil {
		return 0, result, errors.New("ims: Windows WFP traffic address is invalid")
	}
	// The Windows SDK defines the IPv6 arm of IPSEC_TRAFFIC1's address union
	// as UINT8[16], not as a host-order integer. Preserve the network-order
	// byte sequence exactly. Only the IPv4 UINT32 arm needs host byte order.
	copy(result[:], ipv6)
	return wfpIPVersionV6, result, nil
}

type windowsIPSecBundleMaterial struct {
	bundle        wfpIPSecSABundle1
	sa            wfpIPSecSA0
	auth          wfpIPSecSAAuthInformation0
	authAndCipher wfpIPSecSAAuthAndCipherInformation0
	authKey       []byte
	cipherKey     []byte
}

func buildWindowsIPSecBundle(
	config IPSecSAConfig,
	spi uint32,
	qmSAID uint32,
	ipVersion uint32,
) (*windowsIPSecBundleMaterial, error) {
	material := &windowsIPSecBundleMaterial{
		authKey:   append([]byte(nil), config.IntegrityKey...),
		cipherKey: append([]byte(nil), config.EncryptionKey...),
	}
	authID, err := windowsIPSecAuthTransform(config)
	if err != nil {
		material.zeroKeys()
		return nil, err
	}
	material.auth = wfpIPSecSAAuthInformation0{
		authTransform: wfpIPSecAuthTransform0{authTransformID: authID},
		authKey:       windowsWFPBlob(material.authKey),
	}
	material.sa.spi = spi
	if ipsecEncryptionAlgorithm(config) == "null" {
		material.sa.transformType = wfpIPSecTransformESPAuth
		material.sa.transformDetail = unsafe.Pointer(&material.auth)
	} else {
		cipherID, cipherErr := windowsIPSecCipherTransform(config)
		if cipherErr != nil {
			material.zeroKeys()
			return nil, cipherErr
		}
		material.authAndCipher = wfpIPSecSAAuthAndCipherInformation0{
			saCipherInformation: wfpIPSecSACipherInformation0{
				cipherTransform: wfpIPSecCipherTransform0{cipherTransformID: cipherID},
				cipherKey:       windowsWFPBlob(material.cipherKey),
			},
			saAuthInformation: material.auth,
		}
		material.sa.transformType = wfpIPSecTransformESPAuthAndCipher
		material.sa.transformDetail = unsafe.Pointer(&material.authAndCipher)
	}
	material.bundle = wfpIPSecSABundle1{
		qmSAID:    qmSAID,
		numSAs:    1,
		saList:    &material.sa,
		ipVersion: ipVersion,
		pfsGroup:  wfpIPSecPFSGroupNone,
	}
	return material, nil
}

func windowsIPSecAuthTransform(config IPSecSAConfig) (wfpIPSecAuthTransformID0, error) {
	switch ipsecIntegrityAlgorithm(config) {
	case "hmac-md5-96":
		return wfpIPSecAuthTransformID0{authType: 0, authConfig: 0}, nil
	case "hmac-sha-1-96":
		return wfpIPSecAuthTransformID0{authType: 1, authConfig: 1}, nil
	default:
		return wfpIPSecAuthTransformID0{}, errors.New("ims: unsupported Windows WFP integrity transform")
	}
}

func windowsIPSecCipherTransform(config IPSecSAConfig) (wfpIPSecCipherTransformID0, error) {
	switch ipsecEncryptionAlgorithm(config) {
	case "des-ede3-cbc":
		return wfpIPSecCipherTransformID0{cipherType: 2, cipherConfig: 2}, nil
	case "aes-cbc":
		return wfpIPSecCipherTransformID0{cipherType: 3, cipherConfig: 3}, nil
	default:
		return wfpIPSecCipherTransformID0{}, errors.New("ims: unsupported Windows WFP cipher transform")
	}
}

func windowsWFPBlob(value []byte) wfpByteBlob {
	if len(value) == 0 {
		return wfpByteBlob{}
	}
	return wfpByteBlob{size: uint32(len(value)), data: &value[0]}
}

func (material *windowsIPSecBundleMaterial) zeroKeys() {
	zeroBytes(material.authKey)
	zeroBytes(material.cipherKey)
}

type windowsIPSecHandle struct {
	mu sync.Mutex

	api           windowsWFPAPI
	engine        windows.Handle
	subLayerKey   windows.GUID
	subLayerAdded bool
	filterIDs     []uint64
	contextIDs    []uint64
	closed        bool
}

func (installer windowsIPSecInstaller) Install(
	ctx context.Context,
	config IPSecSAConfig,
) (IPSecSAHandle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	plan, err := buildWindowsIPSecPlan(config)
	if err != nil {
		return nil, err
	}
	config = cloneIPSecSAConfig(config)
	defer zeroBytes(config.EncryptionKey)
	defer zeroBytes(config.IntegrityKey)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	api := installer.api
	if api == nil {
		api = windowsWFPSystemAPI{}
	}
	subLayerKey, err := windows.GenerateGUID()
	if err != nil {
		return nil, windowsIPSecInstallError("generate a unique Windows WFP sublayer key", err)
	}
	sessionName, _ := windows.UTF16FromString("VoCat IMS ipsec-3gpp")
	sessionDescription, _ := windows.UTF16FromString("Dynamic Windows WFP session for VoCat IMS transport-mode SAs")
	session := wfpSession0{
		displayData: wfpDisplayData0{
			name:        &sessionName[0],
			description: &sessionDescription[0],
		},
		flags:                wfpSessionFlagDynamic,
		txnWaitTimeoutInMSec: 5000,
	}
	engine, err := api.openEngine(&session)
	runtime.KeepAlive(sessionName)
	runtime.KeepAlive(sessionDescription)
	if err != nil {
		return nil, windowsIPSecInstallError("open Windows Filtering Platform", err)
	}
	handle := &windowsIPSecHandle{
		api:         api,
		engine:      engine,
		subLayerKey: subLayerKey,
	}

	subLayerName, _ := windows.UTF16FromString("VoCat IMS IPsec")
	subLayerDescription, _ := windows.UTF16FromString("Dynamic ipsec-3gpp transport filters")
	subLayer := wfpSubLayer0{
		subLayerKey: subLayerKey,
		displayData: wfpDisplayData0{
			name:        &subLayerName[0],
			description: &subLayerDescription[0],
		},
		weight: 0x100,
	}
	if err := api.addSubLayer(engine, &subLayer); err != nil {
		return nil, handle.rollback("add Windows WFP sublayer", err)
	}
	runtime.KeepAlive(subLayerName)
	runtime.KeepAlive(subLayerDescription)
	handle.subLayerAdded = true

	for _, pair := range plan {
		if err := ctx.Err(); err != nil {
			return nil, handle.rollback("install Windows WFP IMS security associations", err)
		}
		outboundFilter, err := buildWindowsWFPFilter(pair.outbound, handle.subLayerKey)
		if err != nil {
			return nil, handle.rollback("build outbound Windows WFP filter", err)
		}
		outboundFilterID, err := api.addFilter(engine, &outboundFilter.filter)
		runtime.KeepAlive(outboundFilter)
		if err != nil {
			return nil, handle.rollback("add outbound Windows WFP filter for "+pair.name, err)
		}
		handle.filterIDs = append(handle.filterIDs, outboundFilterID)

		inboundFilter, err := buildWindowsWFPFilter(pair.inbound, handle.subLayerKey)
		if err != nil {
			return nil, handle.rollback("build inbound Windows WFP filter", err)
		}
		inboundFilterID, err := api.addFilter(engine, &inboundFilter.filter)
		runtime.KeepAlive(inboundFilter)
		if err != nil {
			return nil, handle.rollback("add inbound Windows WFP filter for "+pair.name, err)
		}
		handle.filterIDs = append(handle.filterIDs, inboundFilterID)

		outboundTraffic, err := buildWindowsIPSecTraffic(pair.outbound, outboundFilterID)
		if err != nil {
			return nil, handle.rollback("build outbound Windows WFP traffic", err)
		}
		contextID, err := api.createSAContext(engine, &outboundTraffic)
		if err != nil {
			return nil, handle.rollback("create Windows WFP SA context for "+pair.name, err)
		}
		handle.contextIDs = append(handle.contextIDs, contextID)

		inboundTraffic, err := buildWindowsIPSecTraffic(pair.inbound, inboundFilterID)
		if err != nil {
			return nil, handle.rollback("build inbound Windows WFP traffic", err)
		}
		getSPI := wfpIPSecGetSPI1{
			inboundIPSecTraffic: inboundTraffic,
			ipVersion:           inboundTraffic.ipVersion,
		}
		if err := api.setSAContextSPI(engine, contextID, &getSPI, pair.inboundSPI); err != nil {
			return nil, handle.rollback("set Windows WFP inbound SPI for "+pair.name, err)
		}

		inboundBundle, err := buildWindowsIPSecBundle(
			config,
			pair.inboundSPI,
			pair.qmSAID,
			inboundTraffic.ipVersion,
		)
		if err != nil {
			return nil, handle.rollback("build Windows WFP inbound SA for "+pair.name, err)
		}
		err = api.addInboundSA(engine, contextID, &inboundBundle.bundle)
		runtime.KeepAlive(inboundBundle)
		inboundBundle.zeroKeys()
		if err != nil {
			return nil, handle.rollback("add Windows WFP inbound SA for "+pair.name, err)
		}

		outboundBundle, err := buildWindowsIPSecBundle(
			config,
			pair.outboundSPI,
			pair.qmSAID,
			outboundTraffic.ipVersion,
		)
		if err != nil {
			return nil, handle.rollback("build Windows WFP outbound SA for "+pair.name, err)
		}
		err = api.addOutboundSA(engine, contextID, &outboundBundle.bundle)
		runtime.KeepAlive(outboundBundle)
		outboundBundle.zeroKeys()
		if err != nil {
			return nil, handle.rollback("add Windows WFP outbound SA for "+pair.name, err)
		}
	}
	return handle, nil
}

func windowsIPSecInstallError(operation string, err error) error {
	hint := ""
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		hint = "; run vocat.exe as Administrator"
	}
	return fmt.Errorf("%w: %s%s: %w", ErrIPSecInstall, operation, hint, err)
}

func (handle *windowsIPSecHandle) rollback(operation string, cause error) error {
	primary := windowsIPSecInstallError(operation, cause)
	if cleanupErr := handle.Close(context.Background()); cleanupErr != nil {
		return errors.Join(primary, fmt.Errorf("ims: roll back Windows WFP IPsec: %w", cleanupErr))
	}
	return primary
}

func (handle *windowsIPSecHandle) Close(context.Context) error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil
	}
	handle.closed = true
	var cleanupErrors []error
	for index := len(handle.contextIDs) - 1; index >= 0; index-- {
		if err := handle.api.deleteSAContext(handle.engine, handle.contextIDs[index]); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	handle.contextIDs = nil
	for index := len(handle.filterIDs) - 1; index >= 0; index-- {
		if err := handle.api.deleteFilter(handle.engine, handle.filterIDs[index]); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	handle.filterIDs = nil
	if handle.subLayerAdded {
		if err := handle.api.deleteSubLayer(handle.engine, &handle.subLayerKey); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		handle.subLayerAdded = false
	}
	if handle.engine != 0 {
		if err := handle.api.closeEngine(handle.engine); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		handle.engine = 0
	}
	return errors.Join(cleanupErrors...)
}

var _ IPSecSAInstaller = windowsIPSecInstaller{}
var _ IPSecSAHandle = (*windowsIPSecHandle)(nil)
