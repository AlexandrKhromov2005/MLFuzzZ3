// Package config parses the project's YAML configuration file. The
// authoritative schema lives in docs/CONFIG.md and is mirrored in the
// C++ Core at src/common/config.{h,cpp}; any change here must also
// touch those and the docs file in the same commit.
package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Log is the `log:` subtree of the YAML configuration. Field values
// follow the vocabulary documented in docs/CONFIG.md; empty strings
// mean "fall back to the consumer's default".
type Log struct {
	Level  string `json:"level,omitempty"`
	Format string `json:"format,omitempty"`
}

// Config is the Go-side view of the project's YAML configuration.
// Sections not yet implemented (exec_server, llm, ...) are not listed
// here: sigs.k8s.io/yaml silently drops unknown keys, which matches
// the forward-compatibility rule in docs/CONFIG.md.
type Config struct {
	Log Log `json:"log,omitempty"`
}

// Defaults returns a Config populated entirely with zero-values.
// Individual consumers (e.g. logging.Init) treat zero-values as
// "use the implementation default"; the struct itself stays a faithful
// transport of whatever the YAML said.
func Defaults() Config {
	return Config{}
}

// LoadFromFile reads and parses the YAML document at path. Errors from
// the filesystem and from YAML parsing are wrapped with path context so
// they are actionable in logs.
func LoadFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses a raw YAML payload. Primary use is in tests.
func LoadFromBytes(data []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	return cfg, nil
}
