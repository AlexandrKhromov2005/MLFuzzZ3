#pragma once

#include <spdlog/spdlog.h>

#include "config.h"

// Project-wide logging facade. Project code must emit log records only
// through the LOG_* macros below (project conventions); never call
// spdlog::* directly, never std::cout / std::cerr. The facade owns the
// default spdlog logger so that a single Init call propagates the
// configured level and format to every call site.

namespace fuzzer::log {

// Build and install the project's default spdlog logger based on cfg.
// Idempotent: calling Init again replaces the previously installed
// logger. Must be invoked before any LOG_* macro fires.
void Init(const config::LogConfig& cfg);

// Restore the project default (info / text / stdout-color) and clear
// any thresholds set by Init. Primarily a test helper — production
// code configures once and lives with that.
void Reset();

}  // namespace fuzzer::log

// Level-tagged logging entry points. Arguments follow spdlog's fmtlib
// dialect (`"x={} y={}", x, y`). At call sites below the default log
// level these expand to a no-op; the cost is one comparison and an
// early branch.
#define LOG_TRACE(...) SPDLOG_TRACE(__VA_ARGS__)
#define LOG_DEBUG(...) SPDLOG_DEBUG(__VA_ARGS__)
#define LOG_INFO(...) SPDLOG_INFO(__VA_ARGS__)
#define LOG_WARN(...) SPDLOG_WARN(__VA_ARGS__)
#define LOG_ERROR(...) SPDLOG_ERROR(__VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_CRITICAL(__VA_ARGS__)
