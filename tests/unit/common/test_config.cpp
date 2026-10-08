#include <gtest/gtest.h>

#include <stdexcept>

#include "config.h"

namespace {

using fuzzer::config::LogFormat;
using fuzzer::config::LogLevel;

TEST(ConfigDefaults, MatchSpec) {
    const auto cfg = fuzzer::config::Defaults();
    EXPECT_EQ(cfg.log.level, LogLevel::kInfo);
    EXPECT_EQ(cfg.log.format, LogFormat::kText);
}

TEST(ConfigParse, ReadsMinimalYaml) {
    const auto cfg = fuzzer::config::LoadFromYamlString(
        "log:\n"
        "  level: debug\n"
        "  format: json\n");
    EXPECT_EQ(cfg.log.level, LogLevel::kDebug);
    EXPECT_EQ(cfg.log.format, LogFormat::kJson);
}

TEST(ConfigParse, EmptyDocumentGivesDefaults) {
    const auto cfg = fuzzer::config::LoadFromYamlString("");
    EXPECT_EQ(cfg.log.level, LogLevel::kInfo);
    EXPECT_EQ(cfg.log.format, LogFormat::kText);
}

TEST(ConfigParse, SilentlyIgnoresUnknownKeys) {
    EXPECT_NO_THROW({
        const auto cfg = fuzzer::config::LoadFromYamlString(
            "log:\n"
            "  level: warn\n"
            "  unknown_key: 1\n"
            "future_section:\n"
            "  placeholder: value\n");
        EXPECT_EQ(cfg.log.level, LogLevel::kWarn);
    });
}

TEST(ConfigParse, RaisesOnInvalidLevelToken) {
    EXPECT_THROW(fuzzer::config::LoadFromYamlString("log:\n  level: bogus\n"), std::runtime_error);
}

TEST(ConfigParse, RaisesOnInvalidFormatToken) {
    EXPECT_THROW(fuzzer::config::LoadFromYamlString("log:\n  format: xml\n"), std::runtime_error);
}

TEST(ConfigParse, RaisesOnMalformedYaml) {
    EXPECT_THROW(fuzzer::config::LoadFromYamlString("[unclosed: list:"), std::runtime_error);
}

TEST(ConfigHelpers, LogLevelNameRoundTrips) {
    for (auto lvl : {LogLevel::kTrace, LogLevel::kDebug, LogLevel::kInfo, LogLevel::kWarn,
                     LogLevel::kError, LogLevel::kCritical}) {
        EXPECT_EQ(fuzzer::config::ParseLogLevel(fuzzer::config::LogLevelName(lvl)), lvl);
    }
}

TEST(ConfigHelpers, LogFormatNameRoundTrips) {
    for (auto fmt : {LogFormat::kText, LogFormat::kJson}) {
        EXPECT_EQ(fuzzer::config::ParseLogFormat(fuzzer::config::LogFormatName(fmt)), fmt);
    }
}

}  // namespace
