#pragma once

/// @file
/// @brief Compile-time version metadata for the fuzzer library and CLI.

namespace fuzzer {

/// Semantic version string of the fuzzer, exposed to both the library and
/// the CLI. Updated as part of the release process.
inline constexpr const char* kVersion = "0.0.0";

}  // namespace fuzzer
