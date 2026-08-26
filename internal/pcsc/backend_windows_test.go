//go:build windows

package pcsc

import (
	"errors"
	"reflect"
	"testing"

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
