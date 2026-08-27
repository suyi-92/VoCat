//go:build linux

package ims

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type linuxIPSecInstaller struct {
	ipCommand string
}

func defaultIPSecInstaller() IPSecSAInstaller {
	return linuxIPSecInstaller{ipCommand: "ip"}
}

type linuxIPSecHandle struct {
	mu        sync.Mutex
	ipCommand string
	cleanup   []xfrmOperation
	closed    bool
}

func (installer linuxIPSecInstaller) Install(ctx context.Context, config IPSecSAConfig) (IPSecSAHandle, error) {
	command := installer.ipCommand
	if command == "" {
		command = "ip"
	}
	if _, err := exec.LookPath(command); err != nil {
		return nil, errors.New("ims: Linux iproute2 is required for ipsec-3gpp")
	}
	install, err := buildXFRMInstallPlan(config)
	if err != nil {
		return nil, err
	}
	handle := &linuxIPSecHandle{
		ipCommand: command,
	}
	cleanup := buildXFRMCleanupPlan(config)
	if len(cleanup) != len(install) {
		zeroBytes(config.EncryptionKey)
		zeroBytes(config.IntegrityKey)
		return nil, fmt.Errorf("%w: internal XFRM install/cleanup plan mismatch", ErrIPSecInstall)
	}
	for index, operation := range install {
		if err := runIPCommand(ctx, command, operation); err != nil {
			rollbackErr := closeAbandonedIPSecHandle(handle)
			zeroBytes(config.EncryptionKey)
			zeroBytes(config.IntegrityKey)
			installErr := fmt.Errorf("%w: %v", ErrIPSecInstall, err)
			if rollbackErr != nil {
				return nil, errors.Join(
					installErr,
					fmt.Errorf("ims: roll back partial Linux XFRM install: %w", rollbackErr),
				)
			}
			return nil, installErr
		}
		// The cleanup plan is the exact reverse of the install plan. Record
		// only objects this handle successfully created so a partial-install
		// rollback cannot delete a pre-existing object that caused a later add
		// to fail.
		cleanupOperation := cleanup[len(cleanup)-1-index]
		handle.cleanup = append([]xfrmOperation{cleanupOperation}, handle.cleanup...)
	}
	zeroBytes(config.EncryptionKey)
	zeroBytes(config.IntegrityKey)
	return handle, nil
}

func (handle *linuxIPSecHandle) Close(ctx context.Context) error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.closed {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := handle.cleanupPending(ctx); err != nil {
		return err
	}
	handle.closed = true
	return nil
}

func (handle *linuxIPSecHandle) cleanupPending(ctx context.Context) error {
	for len(handle.cleanup) > 0 {
		operation := handle.cleanup[0]
		if err := runIPCleanupCommand(ctx, handle.ipCommand, operation); err != nil {
			// Stop at the first uncertain deletion. The operation remains owned by
			// this handle, and a later Close resumes from the same point.
			return err
		}
		handle.cleanup = handle.cleanup[1:]
	}
	return nil
}

func runIPCommand(ctx context.Context, command string, operation xfrmOperation) error {
	output, err := exec.CommandContext(ctx, command, operation.arguments...).CombinedOutput()
	if err == nil {
		return nil
	}
	return formatIPCommandError(operation, output, err)
}

func runIPCleanupCommand(ctx context.Context, command string, operation xfrmOperation) error {
	process := exec.CommandContext(ctx, command, operation.arguments...)
	process.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := process.CombinedOutput()
	if err == nil || linuxIPSecDeleteReportsAbsent(output) {
		return nil
	}
	return formatIPCommandError(operation, output, err)
}

func formatIPCommandError(operation xfrmOperation, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	if strings.Contains(strings.ToLower(message), "protocol not supported") ||
		strings.Contains(strings.ToLower(message), "operation not supported") {
		return fmt.Errorf(
			"%s: host kernel lacks XFRM/IPsec support; install matching kmod-ipsec and kmod-ipsec4/6 (OpenWrt), or enable CONFIG_XFRM_USER and ESP in the kernel: %s",
			operation.description,
			message,
		)
	}
	// Operation descriptions contain no SPI keys or subscriber identity.
	return fmt.Errorf("%s: %s", operation.description, message)
}

func linuxIPSecDeleteReportsAbsent(output []byte) bool {
	message := strings.ToLower(strings.TrimSpace(string(output)))
	return strings.Contains(message, "no such file or directory") ||
		strings.Contains(message, "no such process") ||
		strings.Contains(message, "does not exist")
}
