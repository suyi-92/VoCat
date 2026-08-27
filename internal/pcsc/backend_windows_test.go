//go:build windows

package pcsc

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestParseWindowsMultiString(t *testing.T) {
	first, err := windows.UTF16FromString("SCR Prime 0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := windows.UTF16FromString("Generic reader 1")
	if err != nil {
		t.Fatal(err)
	}
	encoded := append(append(first, second...), 0)
	want := []string{"SCR Prime 0", "Generic reader 1"}
	if got := parseWindowsMultiString(encoded); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWindowsMultiString() = %#v, want %#v", got, want)
	}
}

func TestParseWindowsUSBHardwareID(t *testing.T) {
	vendor, product := parseWindowsUSBHardwareID(`USB\VID_04D9&PID_C001&MI_01\7&123456&0&0001`)
	if vendor != "04d9" || product != "c001" {
		t.Fatalf("parseWindowsUSBHardwareID() = %q, %q", vendor, product)
	}
	vendor, product = parseWindowsUSBHardwareID(`ROOT\SMARTCARDREADER\0000`)
	if vendor != "" || product != "" {
		t.Fatalf("non-USB IDs must not produce VID/PID: %q, %q", vendor, product)
	}
}

func TestWindowsPCSCErrorClassification(t *testing.T) {
	if err := newWindowsPCSCError("connect", windowsSCardErrorNoSmartCard); !errors.Is(err, ErrNoCard) {
		t.Fatalf("no-card error = %v", err)
	}
	if err := newWindowsPCSCError("enumerate", windowsSCardErrorNoService); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("service error = %v", err)
	}
	if err := newWindowsPCSCError("connect", windowsSCardErrorSharing); errors.Is(err, ErrNoCard) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("sharing violation was misclassified: %v", err)
	}
}

func TestWindowsSCardCancellationAPIsResolveWithoutPanicking(t *testing.T) {
	api := newWindowsSCardAPI()
	if err := api.cancel.Find(); err != nil {
		t.Fatalf("SCardCancel is unavailable: %v", err)
	}
	api.cancel.Call(0)
}

func TestListWindowsReaderNamesRetriesResizedBuffer(t *testing.T) {
	first, err := windows.UTF16FromString("SCR Prime 0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := windows.UTF16FromString("Generic reader 1")
	if err != nil {
		t.Fatal(err)
	}
	encoded := append(append(first, second...), 0)
	calls := 0
	readers, err := listWindowsReaderNames(func(buffer []uint16, length *uint32) uint32 {
		calls++
		switch calls {
		case 1:
			*length = uint32(len(first))
			return windowsSCardSuccess
		case 2:
			*length = uint32(len(encoded))
			return windowsSCardErrorInsufficient
		default:
			copy(buffer, encoded)
			*length = uint32(len(encoded))
			return windowsSCardSuccess
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SCR Prime 0", "Generic reader 1"}
	if !reflect.DeepEqual(readers, want) {
		t.Fatalf("listWindowsReaderNames() = %#v, want %#v", readers, want)
	}
	if calls != 3 {
		t.Fatalf("SCardListReadersW calls = %d, want 3", calls)
	}
}

func TestListWindowsReaderNamesBoundsResizeRetries(t *testing.T) {
	calls := 0
	_, err := listWindowsReaderNames(func(_ []uint16, length *uint32) uint32 {
		calls++
		*length = 8
		return windowsSCardErrorInsufficient
	})
	if err == nil {
		t.Fatal("repeated reader-list resize unexpectedly succeeded")
	}
	if calls != windowsListReadersMaxCalls {
		t.Fatalf("SCardListReadersW calls = %d, want %d", calls, windowsListReadersMaxCalls)
	}
}

func TestCallWindowsSCardWithContextCancelsBlockingCall(t *testing.T) {
	ctx, cancelContext := context.WithCancel(context.Background())
	defer cancelContext()
	entered := make(chan struct{})
	nativeDone := make(chan struct{})
	var closeNative sync.Once
	var cancelCalls atomic.Int32
	go func() {
		<-entered
		cancelContext()
	}()

	status, err := callWindowsSCardWithContext(
		ctx,
		func() uintptr {
			close(entered)
			<-nativeDone
			return uintptr(windowsSCardErrorCancelled)
		},
		func() {
			cancelCalls.Add(1)
			closeNative.Do(func() { close(nativeDone) })
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("callWindowsSCardWithContext() error = %v, want context.Canceled", err)
	}
	if uint32(status) != windowsSCardErrorCancelled {
		t.Fatalf("status = 0x%08X, want SCARD_E_CANCELLED", uint32(status))
	}
	if cancelCalls.Load() == 0 {
		t.Fatal("native cancellation was not requested")
	}
}

func TestCallWindowsSCardWithContextDoesNotCancelCompletedCall(t *testing.T) {
	ctx, cancelContext := context.WithCancel(context.Background())
	var cancelCalls atomic.Int32
	status, err := callWindowsSCardWithContext(
		ctx,
		func() uintptr { return windowsSCardSuccess },
		func() { cancelCalls.Add(1) },
	)
	cancelContext()
	if err != nil || uint32(status) != windowsSCardSuccess {
		t.Fatalf("completed call = 0x%08X, %v", uint32(status), err)
	}
	if cancelCalls.Load() != 0 {
		t.Fatalf("completed call was cancelled %d time(s)", cancelCalls.Load())
	}
}

func TestCallWindowsSCardWithContextCancelsAfterPreEntrySchedulingGap(t *testing.T) {
	ctx, cancelContext := context.WithCancel(context.Background())
	callScheduled := make(chan struct{})
	enterNative := make(chan struct{})
	nativeDone := make(chan struct{})
	nativeEntered := make(chan struct{})
	retriesBeforeEntry := make(chan struct{})
	var closeRetriesBeforeEntry sync.Once
	var closeNative sync.Once
	var cancelCalls atomic.Int32
	done := make(chan error, 1)
	go func() {
		_, err := callWindowsSCardWithContext(
			ctx,
			func() uintptr {
				close(callScheduled)
				<-enterNative
				close(nativeEntered)
				<-nativeDone
				return uintptr(windowsSCardErrorCancelled)
			},
			func() {
				calls := cancelCalls.Add(1)
				select {
				case <-nativeEntered:
					closeNative.Do(func() { close(nativeDone) })
				default:
					if calls == 12 {
						closeRetriesBeforeEntry.Do(func() { close(retriesBeforeEntry) })
					}
				}
			},
		)
		done <- err
	}()
	<-callScheduled
	cancelContext()
	select {
	case <-retriesBeforeEntry:
	case <-time.After(2 * time.Second):
		close(enterNative)
		t.Fatal("timed out waiting for cancellation retries before native entry")
	}
	close(enterNative)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("callWindowsSCardWithContext() error = %v, want context.Canceled", err)
	}
	if got := cancelCalls.Load(); got <= 12 {
		t.Fatalf("native cancellation stopped before delayed call entry: %d attempts", got)
	}
}

func TestCallWindowsSCardWithContextWaitsForCancellationCallback(t *testing.T) {
	ctx, cancelContext := context.WithCancel(context.Background())
	entered := make(chan struct{})
	nativeDone := make(chan struct{})
	nativeReturned := make(chan struct{})
	cancelStarted := make(chan struct{})
	releaseCancel := make(chan struct{})
	var closeNative sync.Once
	done := make(chan error, 1)
	go func() {
		_, err := callWindowsSCardWithContext(
			ctx,
			func() uintptr {
				close(entered)
				<-nativeDone
				close(nativeReturned)
				return uintptr(windowsSCardErrorCancelled)
			},
			func() {
				close(cancelStarted)
				closeNative.Do(func() { close(nativeDone) })
				<-releaseCancel
			},
		)
		done <- err
	}()
	<-entered
	cancelContext()
	<-cancelStarted
	<-nativeReturned
	select {
	case err := <-done:
		t.Fatalf("helper returned before cancellation callback finished: %v", err)
	default:
	}
	close(releaseCancel)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("callWindowsSCardWithContext() error = %v, want context.Canceled", err)
	}
}

func TestCallWindowsSCardWithContextNativeReturnCancellationRace(t *testing.T) {
	const iterations = 256
	for iteration := 0; iteration < iterations; iteration++ {
		ctx, cancelContext := context.WithCancel(context.Background())
		entered := make(chan struct{})
		startRace := make(chan struct{})
		done := make(chan struct{})
		var status uintptr
		var callErr error
		var cancelCalls atomic.Int32
		var callbackInFlight atomic.Int32
		var subsequentWork atomic.Bool
		var lateCancellation atomic.Bool

		go func() {
			status, callErr = callWindowsSCardWithContext(
				ctx,
				func() uintptr {
					close(entered)
					<-startRace
					return windowsSCardSuccess
				},
				func() {
					callbackInFlight.Add(1)
					if subsequentWork.Load() {
						lateCancellation.Store(true)
					}
					cancelCalls.Add(1)
					runtime.Gosched()
					callbackInFlight.Add(-1)
				},
			)
			close(done)
		}()
		<-entered
		cancelReady := make(chan struct{})
		go func() {
			close(cancelReady)
			<-startRace
			cancelContext()
		}()
		<-cancelReady
		close(startRace)
		<-done
		subsequentWork.Store(true)
		callsAtReturn := cancelCalls.Load()
		runtime.Gosched()

		if uint32(status) != windowsSCardSuccess {
			t.Fatalf("iteration %d: status = 0x%08X, want success", iteration, uint32(status))
		}
		if callErr == nil {
			if callsAtReturn != 0 {
				t.Fatalf("iteration %d: successful call was cancelled %d time(s)", iteration, callsAtReturn)
			}
		} else if !errors.Is(callErr, context.Canceled) {
			t.Fatalf("iteration %d: error = %v, want nil or context.Canceled", iteration, callErr)
		}
		if callbackInFlight.Load() != 0 {
			t.Fatalf("iteration %d: cancellation callback still running after helper returned", iteration)
		}
		if cancelCalls.Load() != callsAtReturn || lateCancellation.Load() {
			t.Fatalf("iteration %d: cancellation ran after subsequent work started", iteration)
		}
	}
}
