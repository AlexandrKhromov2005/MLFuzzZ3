#include "config.h"

#include <yaml-cpp/yaml.h>

#include <stdexcept>
#include <string>

namespace fuzzer::config {

namespace {

[[noreturn]] void ThrowInvalid(const std::string& field, const std::string& value) {
    throw std::runtime_error("invalid value for \"" + field + "\": \"" + value + "\"");
}

FuzzerConfig FromYamlNode(const YAML::Node& root) {
    FuzzerConfig cfg = Defaults();

    if (auto log = root["log"]; log && log.IsMap()) {
        if (auto level = log["level"]; level && level.IsScalar()) {
            cfg.log.level = ParseLogLevel(level.as<std::string>());
        }
        if (auto format = log["format"]; format && format.IsScalar()) {
            cfg.log.format = ParseLogFormat(format.as<std::string>());
        }
    }
    // Unknown keys and future sections (exec_server, llm, ...) are
    // deliberately left untouched — see docs/CONFIG.md forward-compat rule.
    return cfg;
}

}  // namespace

LogLevel ParseLogLevel(const std::string& s) {
    if (s == "trace") {
        return LogLevel::kTrace;
    }
    if (s == "debug") {
        return LogLevel::kDebug;
    }
    if (s == "info") {
        return LogLevel::kInfo;
    }
    if (s == "warn") {
        return LogLevel::kWarn;
    }
    if (s == "error") {
        return LogLevel::kError;
    }
    if (s == "critical") {
        return LogLevel::kCritical;
    }
    ThrowInvalid("log.level", s);
}

LogFormat ParseLogFormat(const std::string& s) {
    if (s == "text") {
        return LogFormat::kText;
    }
    if (s == "json") {
        return LogFormat::kJson;
    }
    ThrowInvalid("log.format", s);
}

std::string LogLevelName(LogLevel l) {
    switch (l) {
        case LogLevel::kTrace:
            return "trace";
        case LogLevel::kDebug:
            return "debug";
        case LogLevel::kInfo:
            return "info";
        case LogLevel::kWarn:
            return "warn";
        case LogLevel::kError:
            return "error";
        case LogLevel::kCritical:
            return "critical";
    }
    return "?";
}

std::string LogFormatName(LogFormat f) {
    switch (f) {
        case LogFormat::kText:
            return "text";
        case LogFormat::kJson:
            return "json";
    }
    return "?";
}

FuzzerConfig Defaults() {
    return FuzzerConfig{};
}

FuzzerConfig LoadFromFile(const std::string& path) {
    try {
        auto root = YAML::LoadFile(path);
        return FromYamlNode(root);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("config parse error in \"" + path + "\": " + e.what());
    }
}

FuzzerConfig LoadFromYamlString(const std::string& yaml) {
    try {
        auto root = YAML::Load(yaml);
        return FromYamlNode(root);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error(std::string{"config parse error: "} + e.what());
    }
}

}  // namespace fuzzer::config
