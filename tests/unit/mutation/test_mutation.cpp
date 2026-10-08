// Property tests for the Phase 2 mutation foundation (ADR 0027).
//
// Coverage:
//   * Determinism (replay invariant): same input + same seed ⇒
//     bit-identical output across runs.
//   * Length invariance: bit/byte flip preserve size.
//   * Real change: bitflip on a known input + known seed flips
//     exactly one bit.
//   * Empty input: size 0 ⇒ size 0 output, no crash.
//   * Diversity: a small fixed set of distinct seeds produces
//     statistically distinct outputs.
//
// All seeds are constants; the tests do not consult system time
// or any other entropy source, so behavior is identical in CI
// and on developer machines.

#include <gtest/gtest.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

#include "fuzz_input.h"
#include "mutator.h"
#include "mutators/bit_flip.h"
#include "mutators/byte_flip.h"
#include "rng.h"

namespace {

using mlfuzzz3::mutation::BitFlipMutator;
using mlfuzzz3::mutation::ByteFlipMutator;
using mlfuzzz3::mutation::FuzzInput;
using mlfuzzz3::mutation::make_rng;

constexpr std::uint64_t kCanonicalSeed = 0xDEADBEEFULL;

std::vector<std::uint8_t> ToVector(const FuzzInput& in) {
    return std::vector<std::uint8_t>(in.data(), in.data() + in.size());
}

FuzzInput MakeInput(std::initializer_list<std::uint8_t> bytes) {
    return FuzzInput{std::vector<std::uint8_t>(bytes)};
}

template <typename M>
void ExpectReplayIdentical(const M& mutator, const FuzzInput& input) {
    auto rng_a = make_rng(kCanonicalSeed);
    auto rng_b = make_rng(kCanonicalSeed);
    const auto out_a = mutator.mutate(input, rng_a);
    const auto out_b = mutator.mutate(input, rng_b);
    ASSERT_EQ(ToVector(out_a), ToVector(out_b));
}

template <typename M>
void ExpectDiverseOutputs(const M& mutator, const FuzzInput& input) {
    constexpr std::array<std::uint64_t, 5> kSeeds = {
        0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 0xAAAAAAAAAAAAAAAAULL,
        0x5555555555555555ULL, 0xCAFEBABE12345678ULL,
    };
    std::set<std::vector<std::uint8_t>> distinct;
    for (auto seed : kSeeds) {
        auto rng = make_rng(seed);
        const auto out = mutator.mutate(input, rng);
        distinct.insert(ToVector(out));
    }
    // Threshold ≥ 3/5 leaves slack for the rare collision while
    // still proving the mutator is actually seed-sensitive.
    EXPECT_GE(distinct.size(), 3U);
}

// ---- FuzzInput basics --------------------------------------------------

TEST(FuzzInput, DefaultConstructedIsEmpty) {
    FuzzInput in;
    EXPECT_EQ(in.size(), 0U);
    EXPECT_EQ(in.data(), nullptr);
}

TEST(FuzzInput, ConstructFromPointerAndLength) {
    const std::array<std::uint8_t, 4> src{1, 2, 3, 4};
    FuzzInput in(src.data(), src.size());
    ASSERT_EQ(in.size(), src.size());
    EXPECT_EQ(in.data()[0], 1);
    EXPECT_EQ(in.data()[3], 4);
}

TEST(FuzzInput, ConstructFromPointerAndZeroLengthAcceptsNullptr) {
    FuzzInput in(nullptr, 0);
    EXPECT_EQ(in.size(), 0U);
}

TEST(FuzzInput, CopyIsDeep) {
    FuzzInput a = MakeInput({1, 2, 3});
    FuzzInput b = a;
    b.data()[0] = 0xFF;
    EXPECT_EQ(a.data()[0], 1);
    EXPECT_EQ(b.data()[0], 0xFF);
}

TEST(FuzzInput, MoveTransfersOwnership) {
    FuzzInput a = MakeInput({1, 2, 3});
    FuzzInput b = std::move(a);
    EXPECT_EQ(b.size(), 3U);
    EXPECT_EQ(b.data()[2], 3);
}

// ---- Mutator names -----------------------------------------------------

TEST(MutatorNames, AreStable) {
    EXPECT_STREQ(BitFlipMutator{}.name(), "bitflip");
    EXPECT_STREQ(ByteFlipMutator{}.name(), "byteflip");
}

// ---- Replay invariant --------------------------------------------------

TEST(BitFlipMutator, ReplayInvariant) {
    BitFlipMutator m;
    const FuzzInput input = MakeInput({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
    ExpectReplayIdentical(m, input);
}

TEST(ByteFlipMutator, ReplayInvariant) {
    ByteFlipMutator m;
    const FuzzInput input = MakeInput({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
    ExpectReplayIdentical(m, input);
}

// ---- Length invariant --------------------------------------------------

TEST(BitFlipMutator, PreservesLength) {
    BitFlipMutator m;
    const FuzzInput input = MakeInput({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
    auto rng = make_rng(kCanonicalSeed);
    const auto out = m.mutate(input, rng);
    EXPECT_EQ(out.size(), input.size());
}

TEST(ByteFlipMutator, PreservesLength) {
    ByteFlipMutator m;
    const FuzzInput input = MakeInput({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
    auto rng = make_rng(kCanonicalSeed);
    const auto out = m.mutate(input, rng);
    EXPECT_EQ(out.size(), input.size());
}

// ---- Real change: bitflip flips exactly one bit ------------------------

TEST(BitFlipMutator, FlipsExactlyOneBit) {
    BitFlipMutator m;
    const FuzzInput input = MakeInput({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    auto rng = make_rng(kCanonicalSeed);
    const auto out = m.mutate(input, rng);

    ASSERT_EQ(out.size(), input.size());
    int diff_bits = 0;
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::uint8_t xor_byte = static_cast<std::uint8_t>(input.data()[i] ^ out.data()[i]);
        diff_bits += std::popcount(xor_byte);
    }
    EXPECT_EQ(diff_bits, 1);
}

// ---- Empty input: no-op without crash ----------------------------------

TEST(BitFlipMutator, EmptyInputIsNoOp) {
    BitFlipMutator m;
    const FuzzInput input;
    auto rng = make_rng(kCanonicalSeed);
    const auto out = m.mutate(input, rng);
    EXPECT_EQ(out.size(), 0U);
}

TEST(ByteFlipMutator, EmptyInputIsNoOp) {
    ByteFlipMutator m;
    const FuzzInput input;
    auto rng = make_rng(kCanonicalSeed);
    const auto out = m.mutate(input, rng);
    EXPECT_EQ(out.size(), 0U);
}

// ---- Diversity across seeds --------------------------------------------

TEST(BitFlipMutator, DifferentSeedsProduceDifferentOutputs) {
    BitFlipMutator m;
    const FuzzInput input = MakeInput({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    ExpectDiverseOutputs(m, input);
}

TEST(ByteFlipMutator, DifferentSeedsProduceDifferentOutputs) {
    ByteFlipMutator m;
    const FuzzInput input = MakeInput({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    ExpectDiverseOutputs(m, input);
}

}  // namespace
