//go:build windows && !amd64 && !arm64

package ims

import (
	"context"
	"errors"
)

type unsupportedWindowsIPSecInstaller struct{}

func defaultIPSecInstaller() IPSecSAInstaller {
	return unsupportedWindowsIPSecInstaller{}
}

func (unsupportedWindowsIPSecInstaller) Install(context.Context, IPSecSAConfig) (IPSecSAHandle, error) {
	return nil, errors.New("ims: Windows WFP ipsec-3gpp requires amd64 or arm64")
}
