package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAreZeroValue(t *testing.T) {
	cfg := Defaults()
	if cfg.Log.Level != "" || cfg.Log.Format != "" {
		t.Errorf("Defaults should be zero-valued, got %+v", cfg)
	}
}

func TestLoadFromBytesParsesMinimalYaml(t *testing.T) {
	cfg, err := LoadFromBytes([]byte("log:\n  level: debug\n  format: json\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Log.Format)
	}
}

func TestLoadFromBytesEmptyDocumentIsDefaults(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(""))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg != Defaults() {
		t.Errorf("empty document should equal Defaults(), got %+v", cfg)
	}
}

func TestLoadFromBytesSilentlyIgnoresUnknownKeys(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(
		"log:\n" +
			"  level: info\n" +
			"  unknown_key: 1\n" +
			"future_section:\n" +
			"  placeholder: value\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Level = %q, want info", cfg.Log.Level)
	}
}

func TestLoadFromBytesErrsOnMalformedYaml(t *testing.T) {
	if _, err := LoadFromBytes([]byte("[unclosed: list:")); err == nil {
		t.Fatal("expected error on malformed YAML")
	}
}

func TestLoadFromFileReadsDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fuzzer.yaml")
	if err := os.WriteFile(path, []byte("log:\n  level: warn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("Level = %q, want warn", cfg.Log.Level)
	}
}

func TestLoadFromFileErrsOnMissingFile(t *testing.T) {
	if _, err := LoadFromFile("/no/such/path/fuzzer.yaml"); err == nil {
		t.Fatal("expected error on missing file")
	}
}
