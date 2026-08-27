//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"vocat/internal/wintunsecure"

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
	path, candidates, err := wintunsecure.FindDLL()
	if errors.Is(err, os.ErrNotExist) {
		return doctorCheck{
			Name:    "wintun",
			Status:  "warning",
			Code:    "wintun_dll_missing",
			Message: "A trusted architecture-matched wintun.dll was not found beside vocat.exe or in System32; eSIM remains available, but VoWiFi cannot start",
			Evidence: map[string]any{
				"searched": candidates,
			},
		}
	}
	if err != nil {
		return doctorCheck{
			Name: "wintun", Status: "failed", Code: "wintun_dll_invalid",
			Message:  fmt.Sprintf("Cannot select wintun.dll safely: %v", err),
			Evidence: map[string]any{"searched": candidates},
		}
	}
	return windowsWintunDLLCheck(path)
}

func windowsWintunDLLCheck(path string) doctorCheck {
	report, err := wintunsecure.Inspect(path)
	evidence := map[string]any{
		"path":         report.Path,
		"machine":      fmt.Sprintf("0x%04X", report.Machine),
		"architecture": report.Architecture,
		"sha256":       report.SHA256,
		"trust":        report.Trust,
	}
	if evidence["path"] == "" {
		evidence["path"] = path
	}
	if err != nil {
		var validationErr *wintunsecure.ValidationError
		if !errors.As(err, &validationErr) {
			return doctorCheck{
				Name: "wintun", Status: "failed", Code: "wintun_dll_invalid",
				Message: fmt.Sprintf("Cannot validate wintun.dll safely: %v", err), Evidence: evidence,
			}
		}
		switch validationErr.Failure {
		case wintunsecure.FailureArchitectureMismatch:
			return doctorCheck{
				Name: "wintun", Status: "failed", Code: "wintun_architecture_mismatch",
				Message: fmt.Sprintf("wintun.dll architecture does not match vocat.exe: %v", err), Evidence: evidence,
			}
		case wintunsecure.FailureUntrusted:
			evidence["authenticode"] = "untrusted"
			return doctorCheck{
				Name: "wintun", Status: "failed", Code: "wintun_dll_untrusted",
				Message: fmt.Sprintf("wintun.dll does not have a trusted Authenticode signature: %v", err), Evidence: evidence,
			}
		case wintunsecure.FailureExportsUnreadable:
			return doctorCheck{
				Name: "wintun", Status: "failed", Code: "wintun_dll_exports_unreadable",
				Message: fmt.Sprintf("Cannot inspect wintun.dll exports without executing it: %v", err), Evidence: evidence,
			}
		case wintunsecure.FailureExportsMissing:
			evidence["missing_exports"] = validationErr.MissingExports
			return doctorCheck{
				Name: "wintun", Status: "failed", Code: "wintun_dll_exports_missing",
				Message: fmt.Sprintf("wintun.dll is missing %d API export(s) required by VoCat", len(validationErr.MissingExports)), Evidence: evidence,
			}
		default:
			return doctorCheck{
				Name: "wintun", Status: "failed", Code: "wintun_dll_invalid",
				Message: fmt.Sprintf("Cannot validate wintun.dll safely: %v", err), Evidence: evidence,
			}
		}
	}
	evidence["authenticode"] = "trusted"
	evidence["exports"] = report.Exports
	return doctorCheck{
		Name: "wintun", Status: "passed", Code: "wintun_dll_ready",
		Message:  "Architecture-matched wintun.dll has a trusted Authenticode signature and all APIs required by VoCat",
		Evidence: evidence,
	}
}
