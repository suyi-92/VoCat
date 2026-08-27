//go:build windows

package proxy

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureProxyCoreCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}
