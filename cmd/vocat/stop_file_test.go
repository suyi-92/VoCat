package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestContextWithStopFileCancelsOnRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stop-vocat")
	ctx, cancel := contextWithStopFile(context.Background(), path, 5*time.Millisecond, nil)
	defer cancel()
	if err := os.WriteFile(path, []byte("stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stop-file trigger did not cancel the context")
	}
}

func TestContextWithStopFileIgnoresDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stop-vocat")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, stopParent := context.WithCancel(context.Background())
	ctx, cancel := contextWithStopFile(parent, path, 5*time.Millisecond, nil)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("directory incorrectly activated the stop-file trigger")
	case <-time.After(40 * time.Millisecond):
	}
	stopParent()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not propagate")
	}
}
