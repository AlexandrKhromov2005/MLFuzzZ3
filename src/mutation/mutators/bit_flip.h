#pragma once

#include <random>

#include "../fuzz_input.h"
#include "../mutator.h"

namespace mlfuzzz3::mutation {

// Flips a single uniformly-chosen bit in a uniformly-chosen byte.
// Preserves length. Empty input ⇒ empty output (no-op). Two RNG
// draws per call: one for the byte index, one for the bit index.
class BitFlipMutator final : public Mutator {
   public:
    [[nodiscard]] FuzzInput mutate(const FuzzInput& input, std::mt19937_64& rng) const override;
    [[nodiscard]] const char* name() const noexcept override {
        return "bitflip";
    }
};

}  // namespace mlfuzzz3::mutation
