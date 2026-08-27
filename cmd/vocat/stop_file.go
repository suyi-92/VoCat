package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultStopFilePollInterval = 250 * time.Millisecond

// contextWithStopFile adds a local, file-based graceful-stop trigger to the
// normal signal context. The ready-to-run Windows launcher uses it because a
// detached, hidden console process cannot reliably receive Ctrl+C from a later
// shell. Direct and systemd launches leave VOCAT_STOP_FILE unset and retain the
// existing signal-only behavior.
func contextWithStopFile(
	parent context.Context,
	path string,
	interval time.Duration,
	logger *slog.Logger,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	path = strings.TrimSpace(path)
	if path == "" {
		return ctx, cancel
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		if logger != nil {
			logger.Warn("disable stop-file watcher", "error", err)
		}
		return ctx, cancel
	}
	if interval <= 0 {
		interval = defaultStopFilePollInterval
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		lastError := ""
		for {
			info, statErr := os.Stat(absolute)
			switch {
			case statErr == nil && info.Mode().IsRegular():
				if logger != nil {
					logger.Info("stop-file trigger received")
				}
				cancel()
				return
			case statErr == nil:
				lastError = ""
			case errors.Is(statErr, os.ErrNotExist):
				lastError = ""
			default:
				message := statErr.Error()
				if logger != nil && message != lastError {
					logger.Warn("inspect stop-file trigger", "error", statErr)
				}
				lastError = message
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return ctx, cancel
}
