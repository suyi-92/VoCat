package update

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseSHA256SUMS scans the contents of a GNU-style sha256sums file (one
// "<hash>  <filename>" line per entry) and returns the hex digest recorded for
// filename. Both the binary ("hash  name") and text ("hash *name") forms are
// accepted. An empty content or a missing entry yields an error.
func ParseSHA256SUMS(content, filename string) (string, error) {
	var matchedHash string
	matches := 0
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "<64-hex> [ *]name". Split on the first run of whitespace.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := fields[0]
		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
		if name == filename {
			decoded, err := hex.DecodeString(hash)
			if err != nil || len(decoded) != sha256.Size {
				return "", fmt.Errorf("update: malformed sha256 %q for %s", hash, filename)
			}
			matches++
			matchedHash = strings.ToLower(hash)
		}
	}
	switch matches {
	case 0:
		return "", fmt.Errorf("update: %s not found in SHA256SUMS", filename)
	case 1:
		return matchedHash, nil
	default:
		return "", fmt.Errorf("update: SHA256SUMS contains %d records for %s; expected exactly one", matches, filename)
	}
}

// VerifyFileSHA256 hashes the file at path and reports whether its hex digest
// matches expectedHex (constant-time comparison).
func VerifyFileSHA256(path, expectedHex string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	actual := h.Sum(nil)
	want, err := hex.DecodeString(strings.TrimSpace(expectedHex))
	if err != nil {
		return false, fmt.Errorf("update: invalid expected hash: %w", err)
	}
	return subtle.ConstantTimeCompare(actual, want) == 1, nil
}
