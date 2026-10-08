// Property tests for the havoc mutator (ADR 0030).
//
// The ADR-0027 length-invariance template does not apply (havoc changes
// length), so havoc has its own properties:
//   * Replay: same input + same initial RNG state ⇒ bit-identical
//     output (incl. across repeated runs).
//   * Empty input ⇒ empty output.
//   * Non-empty input ⇒ output length in [1, kHavocMaxLen].
//   * Diversity: distinct seeds yield distinct outputs.
//   * Bounds/no-UB stress: short inputs (1/2/4 bytes) across many seeds
//     never escape [1, kHavocMaxLen] and never crash — every
//     length-changing op respects bounds / no-ops on an unfit block.
//
// All seeds are constants; no system entropy is consulted.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

#include "fuzz_input.h"
#include "mutators/havoc.h"
#include "rng.h"

namespace mlfuzzz3::mutation {
namespace {

std::vector<std::uint8_t> ToVector(const FuzzInput& in) {
    return std::vector<std::uint8_t>(in.data(), in.data() + in.size());
}

FuzzInput MakeInput(std::size_t n, std::uint8_t fill) {
    return FuzzInput{std::vector<std::uint8_t>(n, fill)};
}

TEST(HavocMutator, ReplayIdenticalForFixedSeed) {
    const HavocMutator mutator;
    const FuzzInput input = MakeInput(16, 0xAB);
    for (const std::uint64_t seed : {0ULL, 1ULL, 0xDEADBEEFULL, 0x12345ULL}) {
        auto rng_a = make_rng(seed);
        auto rng_b = make_rng(seed);
        EXPECT_EQ(ToVector(mutator.mutate(input, rng_a)), ToVector(mutator.mutate(input, rng_b)))
            << "seed=" << seed;
    }
}

TEST(HavocMutator, EmptyInputProducesEmptyOutput) {
    const HavocMutator mutator;
    const FuzzInput empty;
    for (std::uint64_t seed = 0; seed < 32; ++seed) {
        auto rng = make_rng(seed);
        EXPECT_EQ(mutator.mutate(empty, rng).size(), 0U) << "seed=" << seed;
    }
}

TEST(HavocMutator, NonEmptyOutputLengthWithinBounds) {
    const HavocMutator mutator;
    for (const std::size_t in_len :
         {std::size_t{1}, std::size_t{2}, std::size_t{4}, std::size_t{64}}) {
        const FuzzInput input = MakeInput(in_len, 0x41);
        for (std::uint64_t seed = 0; seed < 200; ++seed) {
            auto rng = make_rng(seed);
            const FuzzInput out = mutator.mutate(input, rng);
            EXPECT_GE(out.size(), 1U) << "in_len=" << in_len << " seed=" << seed;
            EXPECT_LE(out.size(), kHavocMaxLen) << "in_len=" << in_len << " seed=" << seed;
        }
    }
}

TEST(HavocMutator, DistinctSeedsYieldDistinctOutputs) {
    const HavocMutator mutator;
    const FuzzInput input = MakeInput(32, 0x55);
    std::set<std::vector<std::uint8_t>> outputs;
    for (std::uint64_t seed = 0; seed < 32; ++seed) {
        auto rng = make_rng(seed);
        outputs.insert(ToVector(mutator.mutate(input, rng)));
    }
    EXPECT_GT(outputs.size(), 1U);
}

TEST(HavocMutator, NameIsStable) {
    const HavocMutator mutator;
    EXPECT_STREQ(mutator.name(), "havoc");
}

}  // namespace
}  // namespace mlfuzzz3::mutation
