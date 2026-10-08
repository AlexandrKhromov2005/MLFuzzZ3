package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"mlfuzzz3/exec-server/internal/common/config"
)

func TestInitTextDefaultEmitsPlainText(t *testing.T) {
	var buf bytes.Buffer
	logger, err := initTo(&buf, config.Log{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if logger == nil {
		t.Fatal("logger is nil")
	}
	logger.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("expected payload in output, got %q", buf.String())
	}
}

func TestInitJsonEmitsValidJson(t *testing.T) {
	var buf bytes.Buffer
	logger, err := initTo(&buf, config.Log{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	logger.Info("hello", "count", 42)

	line := bytes.TrimSpace(buf.Bytes())
	var parsed map[string]any
	if err := json.Unmarshal(line, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
	}
	if parsed["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", parsed["msg"])
	}
	if got, ok := parsed["count"].(float64); !ok || got != 42 {
		t.Errorf("count = %v, want 42", parsed["count"])
	}
}

func TestInitAcceptsDocumentedLevelVocabulary(t *testing.T) {
	var buf bytes.Buffer
	for _, lvl := range []string{
		"", "trace", "debug", "info", "warn", "warning", "error", "critical",
	} {
		if _, err := initTo(&buf, config.Log{Level: lvl}); err != nil {
			t.Errorf("level %q should be accepted: %v", lvl, err)
		}
	}
}

func TestInitRejectsUnknownLevel(t *testing.T) {
	var buf bytes.Buffer
	if _, err := initTo(&buf, config.Log{Level: "bogus"}); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func TestInitRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if _, err := initTo(&buf, config.Log{Format: "xml"}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
