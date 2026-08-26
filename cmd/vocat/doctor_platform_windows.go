//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func doctorPlatformChecks() []doctorCheck {
	checks := []doctorCheck{windowsElevationCheck()}
	checks = append(checks, windowsServiceCheck("BFE", "base_filtering_engine"))
	checks = append(checks, windowsServiceCheck("SCardSvr", "smart_card_service"))
	checks = append(checks, windowsWintunCheck())
	return checks
}

func windowsElevationCheck() doctorCheck {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	if elevated {
		return doctorCheck{
			Name:     "windows_elevation",
			Status:   "passed",
			Code:     "administrator_token",
			Message:  "Process is elevated; Wintun and WFP configuration are permitted",
			Evidence: map[string]any{"elevated": true},
		}
	}
	return doctorCheck{
		Name:     "windows_elevation",
		Status:   "warning",
		Code:     "administrator_required_for_vowifi",
		Message:  "Run vocat.exe as Administrator before starting VoWiFi; PC/SC eSIM operations may still work without elevation",
		Evidence: map[string]any{"elevated": false},
	}
}

func windowsServiceCheck(serviceName string, checkName string) doctorCheck {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return doctorCheck{
			Name: checkName, Status: "failed", Code: "service_manager_unavailable",
			Message: fmt.Sprintf("Cannot query Windows service %s: %v", serviceName, err),
		}
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return doctorCheck{Name: checkName, Status: "failed", Code: "invalid_service_name", Message: err.Error()}
	}
	service, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return doctorCheck{
			Name: checkName, Status: "failed", Code: "service_unavailable",
			Message: fmt.Sprintf("Cannot open Windows service %s: %v", serviceName, err),
		}
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err = windows.QueryServiceStatusEx(
		service,
		windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		&needed,
	)
	if err != nil {
		return doctorCheck{
			Name: checkName, Status: "failed", Code: "service_status_failed",
			Message: fmt.Sprintf("Cannot read Windows service %s status: %v", serviceName, err),
		}
	}
	evidence := map[string]any{
		"service": serviceName,
		"state":   windowsServiceState(status.CurrentState),
		"pid":     status.ProcessId,
	}
	if status.CurrentState == windows.SERVICE_RUNNING {
		return doctorCheck{
			Name: checkName, Status: "passed", Code: "service_running",
			Message: fmt.Sprintf("Windows service %s is running", serviceName), Evidence: evidence,
		}
	}
	statusName := "warning"
	code := "service_not_running"
	message := fmt.Sprintf("Windows service %s is %s", serviceName, windowsServiceState(status.CurrentState))
	if serviceName == "BFE" {
		statusName = "failed"
		code = "wfp_service_not_running"
		message += "; Windows WFP IMS IPsec cannot be installed"
	} else {
		message += "; PC/SC may start it on demand, otherwise start the Smart Card service"
	}
	return doctorCheck{Name: checkName, Status: statusName, Code: code, Message: message, Evidence: evidence}
}

func windowsServiceState(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "continue_pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "pause_pending"
	case windows.SERVICE_PAUSED:
		return "paused"
	default:
		return fmt.Sprintf("unknown_%d", state)
	}
}

func windowsWintunCheck() doctorCheck {
	executable, executableErr := os.Executable()
	systemDirectory, systemErr := windows.GetSystemDirectory()
	var candidates []string
	if executableErr == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "wintun.dll"))
	}
	if systemErr == nil {
		candidates = append(candidates, filepath.Join(systemDirectory, "wintun.dll"))
	}
	var path string
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			path = candidate
			break
		}
	}
	if path == "" {
		return doctorCheck{
			Name:    "wintun",
			Status:  "warning",
			Code:    "wintun_dll_missing",
			Message: "Official architecture-matched wintun.dll was not found beside vocat.exe or in System32; eSIM remains available, but VoWiFi cannot start",
			Evidence: map[string]any{
				"searched": candidates,
			},
		}
	}
	machine, err := readPEMachine(path)
	if err != nil {
		return doctorCheck{
			Name: "wintun", Status: "failed", Code: "wintun_dll_invalid",
			Message:  fmt.Sprintf("Cannot validate wintun.dll PE header: %v", err),
			Evidence: map[string]any{"path": path},
		}
	}
	architecture := peMachineArchitecture(machine)
	if architecture != runtime.GOARCH {
		return doctorCheck{
			Name: "wintun", Status: "failed", Code: "wintun_architecture_mismatch",
			Message:  fmt.Sprintf("wintun.dll is %s but vocat.exe is %s", architecture, runtime.GOARCH),
			Evidence: map[string]any{"path": path, "machine": fmt.Sprintf("0x%04X", machine)},
		}
	}
	return doctorCheck{
		Name: "wintun", Status: "passed", Code: "wintun_dll_ready",
		Message:  "Architecture-matched wintun.dll is available from a safe DLL search location",
		Evidence: map[string]any{"path": path, "architecture": architecture},
	}
}

func readPEMachine(path string) (uint16, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return parsePEMachine(file)
}

func parsePEMachine(reader io.ReaderAt) (uint16, error) {
	dosHeader := make([]byte, 64)
	if _, err := reader.ReadAt(dosHeader, 0); err != nil {
		return 0, fmt.Errorf("read DOS header: %w", err)
	}
	if string(dosHeader[:2]) != "MZ" {
		return 0, errors.New("missing MZ signature")
	}
	peOffset := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:0x40]))
	if peOffset < 64 || peOffset > 64<<20 {
		return 0, errors.New("invalid PE header offset")
	}
	peHeader := make([]byte, 6)
	if _, err := reader.ReadAt(peHeader, peOffset); err != nil {
		return 0, fmt.Errorf("read PE header: %w", err)
	}
	if string(peHeader[:4]) != "PE\x00\x00" {
		return 0, errors.New("missing PE signature")
	}
	return binary.LittleEndian.Uint16(peHeader[4:6]), nil
}

func peMachineArchitecture(machine uint16) string {
	switch machine {
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	case 0x014c:
		return "386"
	default:
		return fmt.Sprintf("unknown-0x%04X", machine)
	}
}
