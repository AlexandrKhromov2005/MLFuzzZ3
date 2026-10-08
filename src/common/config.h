#pragma once

#include <string>

// Project-wide configuration types. The authoritative YAML schema lives
// in docs/CONFIG.md and is shared with the Go Execution Server, which
// has its own mirror in exec-server/internal/common/config/. Any edit
// to the schema must touch all three (this header, the Go struct, and
// docs/CONFIG.md) in the same change.

namespace fuzzer::config {

enum class LogLevel {
    kTrace,
    kDebug,
    kInfo,
    kWarn,
    kError,
    kCritical,
};

enum class LogFormat {
    kText,
    kJson,
};

// Subtree matching the `log:` section of the YAML document.
struct LogConfig {
    LogLevel level = LogLevel::kInfo;
    LogFormat format = LogFormat::kText;
};

// Top-level parsed configuration. Extends with new subtrees (exec_server,
// llm, ...) as later phases flesh them out. Unknown keys in the source
// YAML are silently dropped here — see docs/CONFIG.md for the policy.
struct FuzzerConfig {
    LogConfig log{};
};

// A FuzzerConfig populated entirely with defaults; equivalent to loading
// an empty YAML document.
FuzzerConfig Defaults();

// TODO: migrate to tl::expected when more error-returning APIs emerge
// (config + ipc + more). Single-point migration is cheaper than
// piecewise introduction.

// Load and parse the YAML document at `path`. Throws std::runtime_error
// on I/O failure, parse failure, or an invalid value in a known field.
// Unknown keys are ignored silently for forward compatibility.
FuzzerConfig LoadFromFile(const std::string& path);

// Same as LoadFromFile, but the YAML document is passed inline. Primary
// use is in tests; also convenient for embedding default profiles.
FuzzerConfig LoadFromYamlString(const std::string& yaml);

// Scalar converters. Exposed so callers can validate individual values
// (e.g. a CLI flag overriding log.level) with the same grammar as the
// YAML loader. Throw std::runtime_error on an unknown token.
LogLevel ParseLogLevel(const std::string& s);
LogFormat ParseLogFormat(const std::string& s);

// Inverse converters for logging and diagnostics. Total: every enum
// value has a string; unreachable defaults never fire in practice but
// keep the switch exhaustive under -Werror.
std::string LogLevelName(LogLevel l);
std::string LogFormatName(LogFormat f);

}  // namespace fuzzer::config
