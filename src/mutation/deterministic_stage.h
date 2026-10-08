#pragma once

#include <cstdint>

#include "fuzz_input.h"

// Phase 2 deterministic stage (ADR 0031). DeterministicStage is the
// systematic positional sweep that runs before havoc on a fresh seed.
// It is deliberately NOT a mutation::Mutator: the Mutator contract is a
// pure stateless function of (input, rng), and a positional sweep needs a
// position/operator cursor instead of an RNG (ADR 0031, Развилка 1). So
// the stage is a separate, additive operator keyed by a cursor.
//
// Contract:
//   * Pure, deterministic, RNG-free: apply(input, cursor) is a pure
//     function of its two arguments — no entropy is consulted, so the
//     same pair always yields a bit-identical output.
//   * Length-preserving: the output has exactly input.size() bytes.
//   * length(input) is the total number of deterministic steps for the
//     input — the sum over operators and positions. The valid cursor
//     range is [0, length(input)). Empty input ⇒ length == 0.
//
// Operators, in cursor order (length-preserving, AFL-classic):
//   walking bit-flips of 1/2/4 bits, walking byte/word/dword flips,
//   per-position arithmetic ±(8/16/32, both endiannesses), and
//   per-position "interesting" values (8/16/32). The per-operation
//   semantics live in the shared ops.h primitives.

namespace mlfuzzz3::mutation {

class DeterministicStage {
   public:
    // Total number of deterministic steps for `input` (0 for an empty
    // input). The valid cursor range for apply() is [0, length(input)).
    // Static: the sweep is stateless: a pure function of its arguments.
    [[nodiscard]] static std::uint64_t length(const FuzzInput& input) noexcept;

    // The mutated input for step `cursor`. Precondition:
    // cursor < length(input). Pure function of (input, cursor),
    // length-preserving.
    [[nodiscard]] static FuzzInput apply(const FuzzInput& input, std::uint64_t cursor);
};

}  // namespace mlfuzzz3::mutation
