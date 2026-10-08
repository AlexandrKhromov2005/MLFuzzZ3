#pragma once

#include <random>

#include "../fuzz_input.h"
#include "../mutator.h"

namespace mlfuzzz3::mutation {

// Overwrites a single uniformly-chosen byte with a uniformly-chosen
// byte value (which may, by chance, equal the original — that is
// statistically inherent and not a defect). Preserves length. Empty
// input ⇒ empty output (no-op). Two RNG draws per call: one for the
// byte index, one for the replacement value.
class ByteFlipMutator final : public Mutator {
   public:
    [[nodiscard]] FuzzInput mutate(const FuzzInput& input, std::mt19937_64& rng) const override;
    [[nodiscard]] const char* name() const noexcept override {
        return "byteflip";
    }
};

}  // namespace mlfuzzz3::mutation
