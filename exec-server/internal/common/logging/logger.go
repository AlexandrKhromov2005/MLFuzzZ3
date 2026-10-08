// Package logging installs the project-wide slog logger from the
// YAML configuration. It is the Go-side companion of the C++ facade in
// src/common/log.{h,cpp}; the two must accept the same log.level and
// log.format vocabulary documented in docs/CONFIG.md.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"mlfuzzz3/exec-server/internal/common/config"
)

// Init constructs a *slog.Logger from the log subtree and installs it
// as slog.Default(). Output goes to stderr; when file or remote sinks
// arrive in a later phase, this is the seam.
func Init(cfg config.Log) (*slog.Logger, error) {
	return initTo(os.Stderr, cfg)
}

// initTo is Init with a caller-supplied writer, so tests can capture
// output without touching os.Stderr.
func initTo(w io.Writer, cfg config.Log) (*slog.Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "", "text":
		handler = slog.NewTextHandler(w, opts)
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("log.format: unknown value %q (want \"text\" or \"json\")", cfg.Format)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger, nil
}

// parseLevel maps the vocabulary from docs/CONFIG.md to slog's limited
// level enum. slog has no trace level and no critical level, so trace
// collapses into debug and critical into error — the log.level field in
// docs/CONFIG.md flags this explicitly so readers do not get surprised.
func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "trace", "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "critical":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log.level: unknown value %q", s)
}
