package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, FormatJSON, slog.LevelInfo)
	logger.Info("hello", "key", "value")

	out := buf.String()
	if !strings.Contains(out, `"msg":"hello"`) {
		t.Errorf("expected JSON output to contain msg field, got: %s", out)
	}
	if !strings.Contains(out, `"key":"value"`) {
		t.Errorf("expected JSON output to contain key field, got: %s", out)
	}
}

func TestNewText(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, FormatText, slog.LevelInfo)
	logger.Info("hello", "key", "value")

	out := buf.String()
	if !strings.Contains(out, "msg=hello") {
		t.Errorf("expected text output to contain msg=hello, got: %s", out)
	}
}

func TestNewRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, FormatText, slog.LevelWarn)
	logger.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("expected no output below configured level, got: %s", buf.String())
	}
}
