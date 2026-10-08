#pragma once

#include <random>

#include "fuzz_input.h"

// Phase 2 mutation foundation (ADR 0027). Abstract base class for
// all mutators.
//
// Contract:
//   * Pure function of (input, rng state). Same input + same RNG
//     state ⇒ bit-identical output (replay invariant).
//   * Empty input (size == 0) ⇒ empty FuzzInput, no crash.
//   * Throws nothing except std::bad_alloc from allocating the
//     output buffer.
//   * Not thread-safe with a shared RNG: caller owns the RNG and
//     is responsible for one RNG per thread if running concurrently.
//   * Returning rather than in-place: chosen to keep the interface
//     trivially testable by comparison. Buffer-reuse APIs are an
//     optimization that belongs to the future mutation loop, not
//     to this contract (see ADR 0027 §Решение).

namespace mlfuzzz3::mutation {

class Mutator {
   public:
    Mutator() = default;
    Mutator(const Mutator&) = delete;
    Mutator& operator=(const Mutator&) = delete;
    Mutator(Mutator&&) = delete;
    Mutator& operator=(Mutator&&) = delete;
    virtual ~Mutator() = default;

    [[nodiscard]] virtual FuzzInput mutate(const FuzzInput& input, std::mt19937_64& rng) const = 0;

    // Stable identifier for logs, reports, and replay metadata. Must
    // be a printable ASCII string with no whitespace; uniqueness
    // across mutators is the registry's concern, not the mutator's.
    [[nodiscard]] virtual const char* name() const noexcept = 0;
};

}  // namespace mlfuzzz3::mutation
