//go:build windows && (amd64 || arm64)

package ims

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// These declarations mirror the Windows SDK 10.0.26100.0 ABI. They are kept
// local instead of using cgo so the Windows release remains a single Go
// executable. The layout tests below guard every pointer-sensitive structure
// used by fwpuclnt.dll on both supported 64-bit Windows architectures.

type wfpDataType uint32

const (
	wfpEmpty           wfpDataType = 0
	wfpUint8           wfpDataType = 1
	wfpUint16          wfpDataType = 2
	wfpUint32          wfpDataType = 3
	wfpByteArray16Type wfpDataType = 11
)

type wfpMatchType uint32

const wfpMatchEqual wfpMatchType = 0

const (
	wfpActionCalloutTerminating uint32 = 0x00005003
	wfpSessionFlagDynamic       uint32 = 0x00000001
	wfpFilterFlagNoAcquire      uint32 = 0x00000800
	rpcCAuthnWinNT              uint32 = 10
	nlatUnicast                 uint8  = 1
)

type wfpByteArray16 struct {
	bytes [16]byte
}

type wfpByteBlob struct {
	size uint32
	data *byte
}

type wfpValue0 struct {
	typeID wfpDataType
	value  uintptr
}

type wfpDisplayData0 struct {
	name        *uint16
	description *uint16
}

type wfpAction0 struct {
	typeID     uint32
	calloutKey windows.GUID
}

type wfpFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      wfpMatchType
	conditionValue wfpValue0
}

type wfpFilter0 struct {
	filterKey           windows.GUID
	displayData         wfpDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        wfpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              wfpValue0
	numFilterConditions uint32
	filterCondition     *wfpFilterCondition0
	action              wfpAction0
	_actionPadding      [4]byte
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     wfpValue0
}

type wfpSession0 struct {
	sessionKey           windows.GUID
	displayData          wfpDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type wfpSubLayer0 struct {
	subLayerKey  windows.GUID
	displayData  wfpDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData wfpByteBlob
	weight       uint16
}

type wfpIPSecAuthTransformID0 struct {
	authType   uint32
	authConfig uint8
	_padding   [3]byte
}

type wfpIPSecAuthTransform0 struct {
	authTransformID wfpIPSecAuthTransformID0
	cryptoModuleID  *windows.GUID
}

type wfpIPSecCipherTransformID0 struct {
	cipherType   uint32
	cipherConfig uint8
	_padding     [3]byte
}

type wfpIPSecCipherTransform0 struct {
	cipherTransformID wfpIPSecCipherTransformID0
	cryptoModuleID    *windows.GUID
}

type wfpIPSecSAAuthInformation0 struct {
	authTransform wfpIPSecAuthTransform0
	authKey       wfpByteBlob
}

type wfpIPSecSACipherInformation0 struct {
	cipherTransform wfpIPSecCipherTransform0
	cipherKey       wfpByteBlob
}

type wfpIPSecSAAuthAndCipherInformation0 struct {
	saCipherInformation wfpIPSecSACipherInformation0
	saAuthInformation   wfpIPSecSAAuthInformation0
}

const (
	wfpIPSecTransformESPAuth          uint32 = 2
	wfpIPSecTransformESPAuthAndCipher uint32 = 4
)

type wfpIPSecSA0 struct {
	spi             uint32
	transformType   uint32
	transformDetail unsafe.Pointer
}

type wfpIPSecSALifetime0 struct {
	lifetimeSeconds   uint32
	lifetimeKilobytes uint32
	lifetimePackets   uint32
}

type wfpIPSecSABundle1 struct {
	flags                      uint32
	lifetime                   wfpIPSecSALifetime0
	idleTimeoutSeconds         uint32
	ndAllowClearTimeoutSeconds uint32
	ipsecID                    unsafe.Pointer
	napContext                 uint32
	qmSAID                     uint32
	numSAs                     uint32
	saList                     *wfpIPSecSA0
	keyModuleState             unsafe.Pointer
	ipVersion                  uint32
	peerV4PrivateAddress       uint32
	mmSAID                     uint64
	pfsGroup                   uint32
	saLookupContext            windows.GUID
	qmFilterID                 uint64
}

const (
	wfpIPVersionV4       uint32 = 0
	wfpIPVersionV6       uint32 = 1
	wfpIPSecTransport    uint32 = 0
	wfpIPSecPFSGroupNone uint32 = 0
)

// IPSEC_TRAFFIC1 stores IPv4 and IPv6 addresses in the same 16-byte unions.
type wfpIPSecTraffic1 struct {
	ipVersion       uint32
	localAddress    [16]byte
	remoteAddress   [16]byte
	trafficType     uint32
	ipsecFilterID   uint64
	remotePort      uint16
	localPort       uint16
	ipProtocol      uint8
	_protocolPad    [3]byte
	localIfLUID     uint64
	realIfProfileID uint32
}

type wfpIPSecGetSPI1 struct {
	inboundIPSecTraffic     wfpIPSecTraffic1
	ipVersion               uint32
	inboundUDPEncapsulation unsafe.Pointer
	rngCryptoModuleID       *windows.GUID
}
