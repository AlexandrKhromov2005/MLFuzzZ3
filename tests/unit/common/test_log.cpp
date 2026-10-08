#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "config.h"
#include "log.h"

namespace {

TEST(LogFacade, InitAppliesRequestedLevel) {
    fuzzer::config::LogConfig cfg;
    cfg.level = fuzzer::config::LogLevel::kWarn;
    fuzzer::log::Init(cfg);

    EXPECT_EQ(spdlog::default_logger()->level(), spdlog::level::warn);
    fuzzer::log::Reset();
}

TEST(LogFacade, InitAcceptsJsonFormat) {
    fuzzer::config::LogConfig cfg;
    cfg.format = fuzzer::config::LogFormat::kJson;
    EXPECT_NO_THROW(fuzzer::log::Init(cfg));
    // Smoke-test: an emit with JSON formatting must not throw.
    LOG_INFO("payload {}", 1);
    fuzzer::log::Reset();
}

TEST(LogFacade, AllMacrosCompileAndRun) {
    fuzzer::log::Init(fuzzer::config::Defaults().log);
    // Compile-check that every LOG_* macro expands and runs without
    // aborting, regardless of the runtime level filter.
    LOG_TRACE("t");
    LOG_DEBUG("d");
    LOG_INFO("i {}", 1);
    LOG_WARN("w {}", "x");
    LOG_ERROR("e {}", 3.14);
    LOG_CRITICAL("c");
    fuzzer::log::Reset();
}

TEST(LogFacade, ResetReturnsToInfoLevel) {
    fuzzer::config::LogConfig cfg;
    cfg.level = fuzzer::config::LogLevel::kCritical;
    fuzzer::log::Init(cfg);
    ASSERT_EQ(spdlog::default_logger()->level(), spdlog::level::critical);

    fuzzer::log::Reset();
    EXPECT_EQ(spdlog::default_logger()->level(), spdlog::level::info);
}

}  // namespace
