//go:build !windows

package update

func inPlaceUpdateSupported() bool { return true }
