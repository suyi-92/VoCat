//go:build !windows

package proxy

import "os/exec"

func configureProxyCoreCommand(*exec.Cmd) {}
