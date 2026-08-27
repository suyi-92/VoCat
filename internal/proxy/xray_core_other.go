//go:build !windows

package proxy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func lockAndValidateProxyCore(path string) (io.Closer, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("make Xray path absolute: %w", err)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("open Xray executable: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, "", fmt.Errorf("Xray path is not a regular file")
	}
	return file, absolute, nil
}
