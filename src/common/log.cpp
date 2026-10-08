#include "log.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <memory>

namespace fuzzer::log {

namespace {

spdlog::level::level_enum ToSpdlogLevel(config::LogLevel lvl) {
    using config::LogLevel;
    switch (lvl) {
        case LogLevel::kTrace:
            return spdlog::level::trace;
        case LogLevel::kDebug:
            return spdlog::level::debug;
        case LogLevel::kInfo:
            return spdlog::level::info;
        case LogLevel::kWarn:
            return spdlog::level::warn;
        case LogLevel::kError:
            return spdlog::level::err;
        case LogLevel::kCritical:
            return spdlog::level::critical;
    }
    return spdlog::level::info;
}

// Phase 0 JSON pattern is best-effort: a message containing embedded
// quotes or newlines will produce non-strict JSON. Structured helpers
// with proper escaping arrive alongside the first real JSON consumer
// in a later phase.
constexpr const char* kJsonPattern =
    R"({"ts":"%Y-%m-%dT%H:%M:%S.%e%z","level":"%l","logger":"%n","msg":"%v"})";

constexpr const char* kTextPattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v";

}  // namespace

void Init(const config::LogConfig& cfg) {
    auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("fuzzer", sink);

    logger->set_pattern(cfg.format == config::LogFormat::kJson ? kJsonPattern : kTextPattern);
    logger->set_level(ToSpdlogLevel(cfg.level));

    spdlog::set_default_logger(logger);
}

void Reset() {
    auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("fuzzer", sink);
    logger->set_pattern(kTextPattern);
    logger->set_level(spdlog::level::info);
    spdlog::set_default_logger(logger);
}

}  // namespace fuzzer::log
