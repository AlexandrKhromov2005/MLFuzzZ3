#pragma once

#include <cstddef>
#include <random>

#include "../fuzz_input.h"
#include "../mutator.h"

namespace mlfuzzz3::mutation {

// Upper bound on the output length of a single HavocMutator::mutate
// (ADR 0030). Length-changing operations are gated by this cap so block
// insertions cannot grow an input without bound.
inline constexpr std::size_t kHavocMaxLen = 65536;

// HavocMutator (ADR 0030) — the mutation-engine workhorse. Per call it
// applies a random stack of AFL-style operations (bit/byte flips,
// arithmetic, "interesting" boundary values, block insert/duplicate/
// delete) so each execution explores further than the single-edit
// bit/byte flips of ADR 0027.
//
// Pure stateless function of (input, rng): same input + same initial
// RNG state ⇒ bit-identical output (replay invariant). Empty input ⇒
// empty output. For a non-empty input the output length stays in
// [1, kHavocMaxLen]. All randomness flows through the seeded RNG; no
// other entropy source is consulted.
class HavocMutator final : public Mutator {
   public:
    [[nodiscard]] FuzzInput mutate(const FuzzInput& input, std::mt19937_64& rng) const override;
    [[nodiscard]] const char* name() const noexcept override {
        return "havoc";
    }
};

}  // namespace mlfuzzz3::mutation
