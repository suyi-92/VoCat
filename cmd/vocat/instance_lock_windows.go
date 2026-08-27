//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsServerInstanceMutexName = `Global\VoCat.Server.Instance.4F7588F4-9880-4C88-9C2F-73D88B73907A`

var errWindowsServerInstanceRunning = errors.New("another vocat server already controls this host's modem and smart-card resources")

// windowsServerInstanceLock keeps the sole handle to a machine-wide named
// mutex object. The object existence is the lock: it deliberately does not
// take mutex ownership, because Windows mutex ownership is thread-affine while
// a Go goroutine may resume on a different OS thread when Close runs.
type windowsServerInstanceLock struct {
	mu     sync.Mutex
	handle windows.Handle
}

func lockServerInstance(_ string) (*windowsServerInstanceLock, error) {
	return lockWindowsServerInstance(windowsServerInstanceMutexName)
}

func lockWindowsServerInstance(name string) (*windowsServerInstanceLock, error) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, `Global\`) {
		return nil, errors.New("server instance mutex must use the Windows Global namespace")
	}
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("encode server instance mutex name: %w", err)
	}
	security, err := windowsServerInstanceMutexSecurity()
	if err != nil {
		return nil, err
	}
	handle, createErr := windows.CreateMutex(security, false, namePointer)
	runtime.KeepAlive(namePointer)
	runtime.KeepAlive(security)
	if createErr == nil && handle != 0 {
		return &windowsServerInstanceLock{handle: handle}, nil
	}
	if handle != 0 {
		_ = windows.CloseHandle(handle)
	}
	if errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
		return nil, errWindowsServerInstanceRunning
	}
	if errors.Is(createErr, windows.ERROR_ACCESS_DENIED) {
		// Fail closed. A mutex created by a different, non-administrator identity
		// intentionally does not grant this process control of its handle.
		return nil, fmt.Errorf("%w (the machine-wide mutex exists but its security policy denies access)", errWindowsServerInstanceRunning)
	}
	if createErr == nil {
		createErr = windows.ERROR_INVALID_HANDLE
	}
	return nil, fmt.Errorf("create machine-wide server instance mutex: %w", createErr)
}

func windowsServerInstanceMutexSecurity() (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read Windows user for server instance mutex: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return nil, errors.New("read Windows user for server instance mutex: token omitted its SID")
	}
	userSID := user.User.Sid.String()
	if userSID == "" {
		return nil, errors.New("read Windows user for server instance mutex: format user SID")
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsServerInstanceMutexSDDL(userSID))
	if err != nil {
		return nil, fmt.Errorf("create server instance mutex security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      0,
	}, nil
}

func windowsServerInstanceMutexSDDL(userSID string) string {
	// Protected DACL: LocalSystem, Administrators, LocalService,
	// NetworkService, and the creating identity can inspect the sentinel.
	// No Everyone/Authenticated Users ACE is present, so an unrelated desktop
	// user cannot open, release, or otherwise control a legitimate mutex.
	return "D:P" +
		"(A;;GA;;;SY)" +
		"(A;;GA;;;BA)" +
		"(A;;GA;;;LS)" +
		"(A;;GA;;;NS)" +
		"(A;;GA;;;" + userSID + ")"
}

func (lock *windowsServerInstanceLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.handle == 0 {
		return nil
	}
	handle := lock.handle
	lock.handle = 0
	if err := windows.CloseHandle(handle); err != nil {
		return fmt.Errorf("close machine-wide server instance mutex: %w", err)
	}
	return nil
}
