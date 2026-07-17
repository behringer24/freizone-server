// Package logging configures the process-wide structured logger.
package logging

import (
	"io"
	"log/slog"
)

// Format selects the log output encoding.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// New builds a slog.Logger writing to w in the given format and level.
func New(w io.Writer, format Format, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if format == FormatJSON {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}
