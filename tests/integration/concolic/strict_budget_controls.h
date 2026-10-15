// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
namespace mlfuzzz3::core::test_support {
// These published controls ended with an SMT candidate. The former loop
// admitted that candidate after its preparation consumed the last slot,
// so a requested legacy budget N actually executed N+1 inputs (ADR-0056).
// Convert only those pinned terminal-candidate controls; this is not a
// conversion for arbitrary campaigns, first solver calls or mutation arms.
constexpr std::uint64_t strict_terminal_budget(std::uint64_t legacy_requested) {
    return legacy_requested + 1;
}
}  // namespace mlfuzzz3::core::test_support
