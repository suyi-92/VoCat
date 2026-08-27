package update

import (
	"strings"
	"testing"
)

func TestParseSHA256SUMSRequiresOneStrictRecord(t *testing.T) {
	const (
		filename = "vocat-linux-amd64.tar.gz"
		hash     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	parsed, err := ParseSHA256SUMS(hash+"  "+filename+"\n", filename)
	if err != nil || parsed != hash {
		t.Fatalf("ParseSHA256SUMS valid record = %q, %v", parsed, err)
	}
	for _, test := range []struct {
		name    string
		content string
	}{
		{"missing", hash + "  another.tar.gz\n"},
		{"duplicate", hash + "  " + filename + "\n" + strings.ToUpper(hash) + " *" + filename + "\n"},
		{"non-hex", strings.Repeat("z", 64) + "  " + filename + "\n"},
		{"short", strings.Repeat("a", 63) + "  " + filename + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseSHA256SUMS(test.content, filename); err == nil {
				t.Fatal("invalid SHA256SUMS content was accepted")
			}
		})
	}
}
