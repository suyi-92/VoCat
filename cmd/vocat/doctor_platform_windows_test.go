//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"vocat/internal/wintunsecure"

	"golang.org/x/sys/windows"
)

func TestParsePEMachine(t *testing.T) {
	image := make([]byte, 0x90)
	copy(image[:2], "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:0x40], 0x80)
	copy(image[0x80:0x84], "PE\x00\x00")
	binary.LittleEndian.PutUint16(image[0x84:0x86], 0xaa64)
	machine, err := wintunsecure.ParsePEMachine(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	if machine != 0xaa64 || wintunsecure.MachineArchitecture(machine) != "arm64" {
		t.Fatalf("machine = 0x%04X/%s", machine, wintunsecure.MachineArchitecture(machine))
	}
}

func TestParsePEMachineRejectsInvalidImage(t *testing.T) {
	if _, err := wintunsecure.ParsePEMachine(bytes.NewReader(make([]byte, 64))); err == nil {
		t.Fatal("invalid PE image was accepted")
	}
}

func TestWindowsWintunDLLCheckRejectsMissingExports(t *testing.T) {
	path := filepath.Join(mustWindowsSystemDirectory(t), "version.dll")
	check := windowsWintunDLLCheck(path)
	if check.Status != "failed" || check.Code != "wintun_dll_exports_missing" {
		t.Fatalf("version.dll check = %#v", check)
	}
	evidence, ok := check.Evidence.(map[string]any)
	if !ok {
		t.Fatalf("version.dll evidence = %#v", check.Evidence)
	}
	missing, ok := evidence["missing_exports"].([]string)
	if !ok || !slices.Contains(missing, "WintunCreateAdapter") {
		t.Fatalf("missing exports = %#v", evidence["missing_exports"])
	}
}

func TestVerifyWindowsAuthenticodeTrustsSystemDLL(t *testing.T) {
	path := filepath.Join(mustWindowsSystemDirectory(t), "version.dll")
	if err := wintunsecure.VerifyAuthenticode(path); err != nil {
		t.Fatalf("trusted system DLL did not verify: %v", err)
	}
}

func TestWindowsWintunDLLCheckRejectsUnsignedPE(t *testing.T) {
	image := make([]byte, 0x90)
	copy(image[:2], "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:0x40], 0x80)
	copy(image[0x80:0x84], "PE\x00\x00")
	binary.LittleEndian.PutUint16(image[0x84:0x86], currentPEMachine(t))
	path := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	check := windowsWintunDLLCheck(path)
	if check.Status != "failed" || check.Code != "wintun_dll_untrusted" {
		t.Fatalf("unsigned PE check = %#v", check)
	}
	if err := wintunsecure.VerifyAuthenticode(path); err == nil {
		t.Fatal("unsigned PE unexpectedly passed Authenticode verification")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsigned PE was not inspected: %v", err)
	}
}

func mustWindowsSystemDirectory(t *testing.T) string {
	t.Helper()
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func currentPEMachine(t *testing.T) uint16 {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return 0x8664
	case "arm64":
		return 0xaa64
	case "386":
		return 0x014c
	default:
		t.Fatalf("unsupported Windows test architecture %q", runtime.GOARCH)
		return 0
	}
}
