//go:build windows && !(amd64 || arm64)

package ike

import (
	"errors"
)

func installWindowsSourceGuard(
	ChildSAConfig,
	uint32,
) (windowsSourceGuardHandle, error) {
	return nil, errors.New("ike: Windows source guard requires amd64 or arm64")
}
