//go:build windows

package pcsc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsSCardScopeSystem = 2

	windowsSCardShareShared = 2

	windowsSCardProtocolT0  = 0x00000001
	windowsSCardProtocolT1  = 0x00000002
	windowsSCardProtocolAny = windowsSCardProtocolT0 | windowsSCardProtocolT1

	windowsSCardLeaveCard = 0
	windowsSCardResetCard = 1

	windowsSCardStatePresent = 0x00000020

	windowsSCardSuccess             = 0x00000000
	windowsSCardErrorCancelled      = 0x80100002
	windowsSCardErrorInvalidHandle  = 0x80100003
	windowsSCardErrorInvalidParam   = 0x80100004
	windowsSCardErrorInvalidTarget  = 0x80100005
	windowsSCardErrorNoMemory       = 0x80100006
	windowsSCardErrorWaitedTooLong  = 0x80100007
	windowsSCardErrorInsufficient   = 0x80100008
	windowsSCardErrorUnknownReader  = 0x80100009
	windowsSCardErrorTimeout        = 0x8010000A
	windowsSCardErrorSharing        = 0x8010000B
	windowsSCardErrorNoSmartCard    = 0x8010000C
	windowsSCardErrorUnknownCard    = 0x8010000D
	windowsSCardErrorCantDispose    = 0x8010000E
	windowsSCardErrorProtoMismatch  = 0x8010000F
	windowsSCardErrorNotReady       = 0x80100010
	windowsSCardErrorInvalidValue   = 0x80100011
	windowsSCardErrorSystemCancel   = 0x80100012
	windowsSCardErrorComm           = 0x80100013
	windowsSCardErrorInternal       = 0x80100014
	windowsSCardErrorInvalidATR     = 0x80100015
	windowsSCardErrorNotTransacted  = 0x80100016
	windowsSCardErrorReaderGone     = 0x80100017
	windowsSCardErrorShutdown       = 0x80100018
	windowsSCardErrorPCITooSmall    = 0x80100019
	windowsSCardErrorReaderUnsup    = 0x8010001A
	windowsSCardErrorDuplicate      = 0x8010001B
	windowsSCardErrorCardUnsup      = 0x8010001C
	windowsSCardErrorNoService      = 0x8010001D
	windowsSCardErrorServiceStopped = 0x8010001E
	windowsSCardErrorUnexpected     = 0x8010001F
	windowsSCardErrorUnsupported    = 0x80100022
	windowsSCardErrorNoReaders      = 0x8010002E
	windowsSCardWarningRemoved      = 0x80100069

	windowsMaxMultiStringCharacters = 1 << 20
	windowsMaxDeviceIDCharacters    = 1 << 15
	windowsMaxAPDUResponseBytes     = 65538
)

type windowsSCardAPI struct {
	establishContext  *windows.LazyProc
	releaseContext    *windows.LazyProc
	listReaders       *windows.LazyProc
	getStatusChange   *windows.LazyProc
	connect           *windows.LazyProc
	beginTransaction  *windows.LazyProc
	transmit          *windows.LazyProc
	endTransaction    *windows.LazyProc
	disconnect        *windows.LazyProc
	readerDeviceID    *windows.LazyProc
	hasReaderDeviceID bool
}

func newWindowsSCardAPI() *windowsSCardAPI {
	dll := windows.NewLazySystemDLL("winscard.dll")
	api := &windowsSCardAPI{
		establishContext: dll.NewProc("SCardEstablishContext"),
		releaseContext:   dll.NewProc("SCardReleaseContext"),
		listReaders:      dll.NewProc("SCardListReadersW"),
		getStatusChange:  dll.NewProc("SCardGetStatusChangeW"),
		connect:          dll.NewProc("SCardConnectW"),
		beginTransaction: dll.NewProc("SCardBeginTransaction"),
		transmit:         dll.NewProc("SCardTransmit"),
		endTransaction:   dll.NewProc("SCardEndTransaction"),
		disconnect:       dll.NewProc("SCardDisconnect"),
		readerDeviceID:   dll.NewProc("SCardGetReaderDeviceInstanceIdW"),
	}
	api.hasReaderDeviceID = api.readerDeviceID.Find() == nil
	return api
}

type windowsBackend struct {
	api *windowsSCardAPI
}

func newNativeBackend() Backend {
	return &windowsBackend{api: newWindowsSCardAPI()}
}

// windowsReaderState mirrors SCARD_READERSTATEW. Pointer-sized fields must
// remain first so the Go layout matches both 32-bit and 64-bit Windows.
type windowsReaderState struct {
	reader       *uint16
	userData     uintptr
	currentState uint32
	eventState   uint32
	atrLength    uint32
	atr          [36]byte
}

type windowsIORequest struct {
	protocol uint32
	length   uint32
}

func (backend *windowsBackend) Readers(ctx context.Context) ([]Reader, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	resource, err := backend.establishContext("enumerate readers")
	if err != nil {
		return nil, err
	}
	defer backend.releaseContext(resource)

	names, err := backend.readerNames(resource)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	namePointers := make([]*uint16, len(names))
	states := make([]windowsReaderState, len(names))
	for index, name := range names {
		namePointers[index], err = windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, fmt.Errorf("pcsc: encode Windows reader name: %w", err)
		}
		states[index].reader = namePointers[index]
	}
	status, _, _ := backend.api.getStatusChange.Call(
		resource,
		0,
		uintptr(unsafe.Pointer(&states[0])),
		uintptr(len(states)),
	)
	runtime.KeepAlive(namePointers)
	if code := uint32(status); code != windowsSCardSuccess {
		return nil, newWindowsPCSCError("query reader status", code)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	readers := make([]Reader, 0, len(names))
	for index, name := range names {
		reader := Reader{
			Name:        name,
			USBPath:     "pcsc:" + name,
			Product:     name,
			CardPresent: states[index].eventState&windowsSCardStatePresent != 0,
		}
		atrLength := int(states[index].atrLength)
		if atrLength > len(states[index].atr) {
			atrLength = len(states[index].atr)
		}
		if atrLength > 0 {
			reader.ATR = strings.ToUpper(fmt.Sprintf("%X", states[index].atr[:atrLength]))
		}
		if deviceID, ok := backend.readerDeviceInstanceID(resource, namePointers[index]); ok {
			reader.USBPath = deviceID
			reader.VendorID, reader.ProductID = parseWindowsUSBHardwareID(deviceID)
		}
		readers = append(readers, reader)
	}
	return filterVirtualPCDReaders(readers), nil
}

func (backend *windowsBackend) Open(ctx context.Context, selector Selector) (Card, error) {
	if err := selector.validate(); err != nil {
		return nil, err
	}
	readers, err := backend.Readers(ctx)
	if err != nil {
		return nil, err
	}
	reader, ok := matchReader(readers, selector)
	if !ok {
		return nil, ErrReaderNotFound
	}
	if !reader.CardPresent {
		return nil, ErrNoCard
	}
	resource, err := backend.establishContext("open reader")
	if err != nil {
		return nil, err
	}
	readerName, err := windows.UTF16PtrFromString(reader.Name)
	if err != nil {
		backend.releaseContext(resource)
		return nil, fmt.Errorf("pcsc: encode Windows reader name: %w", err)
	}
	var handle uintptr
	var protocol uint32
	status, _, _ := backend.api.connect.Call(
		resource,
		uintptr(unsafe.Pointer(readerName)),
		windowsSCardShareShared,
		windowsSCardProtocolAny,
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&protocol)),
	)
	runtime.KeepAlive(readerName)
	if code := uint32(status); code != windowsSCardSuccess {
		backend.releaseContext(resource)
		return nil, newWindowsPCSCError("connect to "+reader.Name, code)
	}
	status, _, _ = backend.api.beginTransaction.Call(handle)
	if code := uint32(status); code != windowsSCardSuccess {
		backend.disconnectCard(handle, windowsSCardLeaveCard)
		backend.releaseContext(resource)
		return nil, newWindowsPCSCError("begin card transaction", code)
	}
	if err := contextError(ctx); err != nil {
		backend.endTransaction(handle, windowsSCardLeaveCard)
		backend.disconnectCard(handle, windowsSCardLeaveCard)
		backend.releaseContext(resource)
		return nil, err
	}
	return &windowsCard{
		api:      backend.api,
		resource: resource,
		handle:   handle,
		protocol: protocol,
	}, nil
}

func (backend *windowsBackend) establishContext(operation string) (uintptr, error) {
	var resource uintptr
	status, _, _ := backend.api.establishContext.Call(
		windowsSCardScopeSystem,
		0,
		0,
		uintptr(unsafe.Pointer(&resource)),
	)
	if code := uint32(status); code != windowsSCardSuccess {
		return 0, newWindowsPCSCError(operation, code)
	}
	return resource, nil
}

func (backend *windowsBackend) releaseContext(resource uintptr) error {
	if resource == 0 {
		return nil
	}
	status, _, _ := backend.api.releaseContext.Call(resource)
	if code := uint32(status); code != windowsSCardSuccess {
		return newWindowsPCSCError("release resource manager context", code)
	}
	return nil
}

func (backend *windowsBackend) readerNames(resource uintptr) ([]string, error) {
	var length uint32
	status, _, _ := backend.api.listReaders.Call(
		resource,
		0,
		0,
		uintptr(unsafe.Pointer(&length)),
	)
	code := uint32(status)
	if code == windowsSCardErrorNoReaders {
		return []string{}, nil
	}
	if code != windowsSCardSuccess {
		return nil, newWindowsPCSCError("list readers", code)
	}
	if length == 0 {
		return []string{}, nil
	}
	if length > windowsMaxMultiStringCharacters {
		return nil, errors.New("pcsc: Windows reader list is unreasonably large")
	}
	buffer := make([]uint16, length)
	status, _, _ = backend.api.listReaders.Call(
		resource,
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&length)),
	)
	if code = uint32(status); code != windowsSCardSuccess {
		return nil, newWindowsPCSCError("list readers", code)
	}
	if int(length) < len(buffer) {
		buffer = buffer[:length]
	}
	return parseWindowsMultiString(buffer), nil
}

func (backend *windowsBackend) readerDeviceInstanceID(resource uintptr, readerName *uint16) (string, bool) {
	if !backend.api.hasReaderDeviceID || readerName == nil {
		return "", false
	}
	var length uint32
	status, _, _ := backend.api.readerDeviceID.Call(
		resource,
		uintptr(unsafe.Pointer(readerName)),
		0,
		uintptr(unsafe.Pointer(&length)),
	)
	code := uint32(status)
	if code != windowsSCardSuccess && code != windowsSCardErrorInsufficient {
		return "", false
	}
	if length == 0 || length > windowsMaxDeviceIDCharacters {
		return "", false
	}
	buffer := make([]uint16, length)
	status, _, _ = backend.api.readerDeviceID.Call(
		resource,
		uintptr(unsafe.Pointer(readerName)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&length)),
	)
	if uint32(status) != windowsSCardSuccess {
		return "", false
	}
	deviceID := strings.TrimSpace(windows.UTF16ToString(buffer))
	return deviceID, deviceID != ""
}

func (backend *windowsBackend) endTransaction(handle uintptr, disposition uint32) error {
	status, _, _ := backend.api.endTransaction.Call(handle, uintptr(disposition))
	if code := uint32(status); code != windowsSCardSuccess {
		return newWindowsPCSCError("end card transaction", code)
	}
	return nil
}

func (backend *windowsBackend) disconnectCard(handle uintptr, disposition uint32) error {
	status, _, _ := backend.api.disconnect.Call(handle, uintptr(disposition))
	if code := uint32(status); code != windowsSCardSuccess {
		return newWindowsPCSCError("disconnect card", code)
	}
	return nil
}

type windowsCard struct {
	mu       sync.Mutex
	api      *windowsSCardAPI
	resource uintptr
	handle   uintptr
	protocol uint32
	closed   bool
}

func (card *windowsCard) Transmit(ctx context.Context, command []byte) ([]byte, uint16, error) {
	if card == nil {
		return nil, 0, errors.New("pcsc: card session is closed")
	}
	card.mu.Lock()
	defer card.mu.Unlock()
	if card.closed || card.api == nil {
		return nil, 0, errors.New("pcsc: card session is closed")
	}
	return card.transmit(ctx, append([]byte(nil), command...), 0)
}

func (card *windowsCard) TransmitRaw(ctx context.Context, command []byte) ([]byte, uint16, error) {
	if card == nil {
		return nil, 0, errors.New("pcsc: card session is closed")
	}
	card.mu.Lock()
	defer card.mu.Unlock()
	if card.closed || card.api == nil {
		return nil, 0, errors.New("pcsc: card session is closed")
	}
	return card.transmitRaw(ctx, command)
}

func (card *windowsCard) transmit(ctx context.Context, command []byte, depth int) ([]byte, uint16, error) {
	if depth > 8 {
		return nil, 0, errors.New("pcsc: too many APDU continuations")
	}
	data, status, err := card.transmitRaw(ctx, command)
	if err != nil {
		return nil, 0, err
	}
	sw1, sw2 := byte(status>>8), byte(status)
	if sw1 == 0x6C && len(command) >= 5 {
		retry := append([]byte(nil), command...)
		retry[len(retry)-1] = sw2
		return card.transmit(ctx, retry, depth+1)
	}
	if sw1 == 0x61 || sw1 == 0x9F {
		more, sw, err := card.transmit(ctx, []byte{0x00, 0xC0, 0x00, 0x00, sw2}, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return append(data, more...), sw, nil
	}
	return data, status, contextError(ctx)
}

func (card *windowsCard) transmitRaw(ctx context.Context, command []byte) ([]byte, uint16, error) {
	if err := contextError(ctx); err != nil {
		return nil, 0, err
	}
	if len(command) == 0 {
		return nil, 0, errors.New("pcsc: APDU command is empty")
	}
	if uint64(len(command)) > uint64(^uint32(0)) {
		return nil, 0, errors.New("pcsc: APDU command is too large")
	}
	request := windowsIORequest{protocol: card.protocol, length: uint32(unsafe.Sizeof(windowsIORequest{}))}
	response := make([]byte, windowsMaxAPDUResponseBytes)
	responseLength := uint32(len(response))
	status, _, _ := card.api.transmit.Call(
		card.handle,
		uintptr(unsafe.Pointer(&request)),
		uintptr(unsafe.Pointer(&command[0])),
		uintptr(len(command)),
		0,
		uintptr(unsafe.Pointer(&response[0])),
		uintptr(unsafe.Pointer(&responseLength)),
	)
	runtime.KeepAlive(command)
	runtime.KeepAlive(response)
	if code := uint32(status); code != windowsSCardSuccess {
		return nil, 0, newWindowsPCSCError("transmit APDU", code)
	}
	if responseLength > uint32(len(response)) {
		return nil, 0, errors.New("pcsc: Windows returned an oversized APDU response")
	}
	if err := contextError(ctx); err != nil {
		return nil, 0, err
	}
	return splitAPDUResponse(response[:responseLength])
}

func (card *windowsCard) Close() error {
	return card.close(windowsSCardLeaveCard)
}

func (card *windowsCard) CloseWithReset() error {
	return card.close(windowsSCardResetCard)
}

func (card *windowsCard) close(disposition uint32) error {
	if card == nil {
		return nil
	}
	card.mu.Lock()
	defer card.mu.Unlock()
	if card.closed {
		return nil
	}
	card.closed = true
	var result []error
	if card.handle != 0 {
		status, _, _ := card.api.endTransaction.Call(card.handle, uintptr(disposition))
		if code := uint32(status); code != windowsSCardSuccess {
			result = append(result, newWindowsPCSCError("end card transaction", code))
		}
		status, _, _ = card.api.disconnect.Call(card.handle, uintptr(disposition))
		if code := uint32(status); code != windowsSCardSuccess {
			result = append(result, newWindowsPCSCError("disconnect card", code))
		}
		card.handle = 0
	}
	if card.resource != 0 {
		status, _, _ := card.api.releaseContext.Call(card.resource)
		if code := uint32(status); code != windowsSCardSuccess {
			result = append(result, newWindowsPCSCError("release resource manager context", code))
		}
		card.resource = 0
	}
	return errors.Join(result...)
}

type windowsPCSCError struct {
	operation string
	code      uint32
	kind      error
}

func (err *windowsPCSCError) Error() string {
	if err == nil {
		return "pcsc: Windows smart-card error"
	}
	message := windowsPCSCErrorText(err.code)
	if err.operation == "" {
		return fmt.Sprintf("pcsc: %s (0x%08X)", message, err.code)
	}
	return fmt.Sprintf("pcsc: %s: %s (0x%08X)", err.operation, message, err.code)
}

func (err *windowsPCSCError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.kind
}

func newWindowsPCSCError(operation string, code uint32) error {
	err := &windowsPCSCError{operation: operation, code: code}
	switch code {
	case windowsSCardErrorNoService, windowsSCardErrorServiceStopped,
		windowsSCardErrorReaderGone, windowsSCardErrorShutdown:
		err.kind = ErrUnavailable
	case windowsSCardErrorUnknownReader, windowsSCardErrorNoReaders:
		err.kind = ErrReaderNotFound
	case windowsSCardErrorNoSmartCard, windowsSCardWarningRemoved:
		err.kind = ErrNoCard
	}
	return err
}

func windowsPCSCErrorText(code uint32) string {
	switch code {
	case windowsSCardErrorCancelled:
		return "operation was cancelled"
	case windowsSCardErrorInvalidHandle:
		return "invalid smart-card handle"
	case windowsSCardErrorInvalidParam:
		return "invalid parameter"
	case windowsSCardErrorInvalidTarget:
		return "invalid target"
	case windowsSCardErrorNoMemory:
		return "not enough memory"
	case windowsSCardErrorWaitedTooLong:
		return "operation waited too long"
	case windowsSCardErrorInsufficient:
		return "buffer is too small"
	case windowsSCardErrorUnknownReader:
		return "reader is unknown"
	case windowsSCardErrorTimeout:
		return "operation timed out"
	case windowsSCardErrorSharing:
		return "reader or card is in use by another process"
	case windowsSCardErrorNoSmartCard:
		return "no smart card is present"
	case windowsSCardErrorUnknownCard:
		return "card type is not recognized"
	case windowsSCardErrorCantDispose:
		return "card cannot be disposed"
	case windowsSCardErrorProtoMismatch:
		return "card protocol does not match"
	case windowsSCardErrorNotReady:
		return "reader or card is not ready"
	case windowsSCardErrorInvalidValue:
		return "invalid value"
	case windowsSCardErrorSystemCancel:
		return "operation was cancelled by Windows"
	case windowsSCardErrorComm:
		return "reader communication failed"
	case windowsSCardErrorInternal:
		return "Windows smart-card service internal error"
	case windowsSCardErrorInvalidATR:
		return "card ATR is invalid"
	case windowsSCardErrorNotTransacted:
		return "card transaction failed"
	case windowsSCardErrorReaderGone:
		return "reader is unavailable"
	case windowsSCardErrorShutdown:
		return "Windows is shutting down"
	case windowsSCardErrorPCITooSmall:
		return "protocol control information buffer is too small"
	case windowsSCardErrorReaderUnsup:
		return "reader is unsupported"
	case windowsSCardErrorDuplicate:
		return "reader name is duplicated"
	case windowsSCardErrorCardUnsup:
		return "card is unsupported"
	case windowsSCardErrorNoService:
		return "Windows Smart Card service is unavailable"
	case windowsSCardErrorServiceStopped:
		return "Windows Smart Card service is stopped"
	case windowsSCardErrorUnexpected:
		return "unexpected card error"
	case windowsSCardErrorUnsupported:
		return "requested smart-card feature is unsupported"
	case windowsSCardErrorNoReaders:
		return "no smart-card readers are available"
	case windowsSCardWarningRemoved:
		return "card was removed"
	default:
		return "Windows smart-card operation failed"
	}
}

func parseWindowsMultiString(value []uint16) []string {
	result := make([]string, 0)
	for offset := 0; offset < len(value); {
		end := offset
		for end < len(value) && value[end] != 0 {
			end++
		}
		if end == offset {
			break
		}
		if name := strings.TrimSpace(windows.UTF16ToString(value[offset:end])); name != "" {
			result = append(result, name)
		}
		offset = end + 1
	}
	return result
}

func parseWindowsUSBHardwareID(deviceID string) (vendorID, productID string) {
	upper := strings.ToUpper(strings.TrimSpace(deviceID))
	return windowsHardwareIDField(upper, "VID_"), windowsHardwareIDField(upper, "PID_")
}

func windowsHardwareIDField(value, marker string) string {
	index := strings.Index(value, marker)
	if index < 0 {
		return ""
	}
	start := index + len(marker)
	if start+4 > len(value) {
		return ""
	}
	field := value[start : start+4]
	for _, character := range field {
		if (character < '0' || character > '9') && (character < 'A' || character > 'F') {
			return ""
		}
	}
	return strings.ToLower(field)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
