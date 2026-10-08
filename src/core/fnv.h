#pragma once

#include <cstdint>
#include <span>
#include <string_view>

// Phase 2 (ADR 0029). FNV-1a 64-bit — a small, stable, platform- and
// stdlib-independent hash. Used for content-addressed finding file names
// (Corpus crashes/, hangs/) and the config component of the metrics
// run id, both of which must be reproducible across builds — unlike
// std::hash, whose value is implementation-defined.

namespace mlfuzzz3::core {

inline constexpr std::uint64_t kFnvOffsetBasis = 0xcbf29ce484222325ULL;
inline constexpr std::uint64_t kFnvPrime = 0x100000001b3ULL;

[[nodiscard]] constexpr std::uint64_t FnvHash(std::span<const std::uint8_t> bytes) {
    std::uint64_t hash = kFnvOffsetBasis;
    for (const std::uint8_t byte : bytes) {
        hash ^= static_cast<std::uint64_t>(byte);
        hash *= kFnvPrime;
    }
    return hash;
}

[[nodiscard]] constexpr std::uint64_t FnvHash(std::string_view text) {
    std::uint64_t hash = kFnvOffsetBasis;
    for (const char ch : text) {
        hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(ch));
        hash *= kFnvPrime;
    }
    return hash;
}

}  // namespace mlfuzzz3::core
