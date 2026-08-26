//go:build windows

package update

import (
	"errors"
	"testing"
)

func TestWindowsInPlaceUpdateIsExplicitlyUnsupported(t *testing.T) {
	if SupportsInPlaceApply() {
		t.Fatal("Windows unexpectedly reports in-place update support")
	}
	if err := applyUpdate(nil, nil, Options{}, nil, "", false); !errors.Is(err, ErrInPlaceUpdateUnsupported) {
		t.Fatalf("applyUpdate error = %v, want ErrInPlaceUpdateUnsupported", err)
	}
}
