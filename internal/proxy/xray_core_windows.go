//go:build windows

package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"

	"vocat/internal/wintunsecure"
)

const maxXrayExecutableBytes = 100 << 20

var approvedXraySHA256 = map[string]string{
	"amd64": "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1",
	"arm64": "e3340409afd87c1cd928e19208c78cb7271e9f95777aa5122db30759b6d2dc81",
}

func lockAndValidateProxyCore(path string) (io.Closer, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("make Xray path absolute: %w", err)
	}
	pointer, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("encode Xray path: %w", err)
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, "", fmt.Errorf("lock Xray executable against replacement: %w", err)
	}
	file := os.NewFile(uintptr(handle), absolute)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, "", errors.New("wrap locked Xray executable handle")
	}
	closeWithError := func(err error) (io.Closer, string, error) {
		file.Close()
		return nil, "", err
	}
	info, err := file.Stat()
	if err != nil {
		return closeWithError(fmt.Errorf("inspect Xray executable: %w", err))
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxXrayExecutableBytes {
		return closeWithError(fmt.Errorf("Xray executable size %d is outside the accepted range", info.Size()))
	}
	machine, err := wintunsecure.ParsePEMachine(file)
	if err != nil {
		return closeWithError(fmt.Errorf("inspect Xray PE architecture: %w", err))
	}
	architecture := wintunsecure.MachineArchitecture(machine)
	if architecture != runtime.GOARCH {
		return closeWithError(fmt.Errorf("Xray architecture %s does not match VoCat architecture %s", architecture, runtime.GOARCH))
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(file, 0, info.Size())); err != nil {
		return closeWithError(fmt.Errorf("hash locked Xray executable: %w", err))
	}
	actual := digest.Sum(nil)
	expected, err := hex.DecodeString(approvedXraySHA256[architecture])
	if err != nil || len(expected) != sha256.Size || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return closeWithError(fmt.Errorf(
			"Xray executable is not the approved %s v%s build (SHA256 %s)",
			architecture,
			XrayCoreVersion,
			hex.EncodeToString(actual),
		))
	}
	finalPath, err := finalProxyCorePath(handle)
	if err != nil {
		return closeWithError(fmt.Errorf("resolve locked Xray executable path: %w", err))
	}
	return file, normalizeWindowsExtendedPath(finalPath), nil
}

func finalProxyCorePath(handle windows.Handle) (string, error) {
	size := uint32(512)
	for size <= 1<<15 {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if length < size {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		size = length + 1
	}
	return "", errors.New("resolved Xray executable path is too long")
}

func normalizeWindowsExtendedPath(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	}
	return strings.TrimPrefix(path, `\\?\`)
}
