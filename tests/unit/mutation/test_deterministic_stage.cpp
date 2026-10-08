// Property tests for the deterministic stage operator (ADR 0031).
//
// Coverage:
//   * length(): zero for empty input; exact totals for known sizes,
//     pinning the per-operator/position enumeration.
//   * apply(): determinism (same input + cursor ⇒ identical output);
//     length invariance; the full cursor sweep stays in range and
//     length-preserving.
//   * Operator order and decoding: walking bit-flips cover every single
//     bit (incl. the high bit of byte 0 — the crash-path invariant), the
//     byte flip produces all-ones, arithmetic wraps, and "interesting"
//     values appear at the expected cursors.
//
// The stage is RNG-free, so every expectation below is exact and
// reproducible regardless of any seed.

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "deterministic_stage.h"
#include "fuzz_input.h"

namespace mlfuzzz3::mutation {
namespace {

using Bytes = std::vector<std::uint8_t>;

std::uint64_t Length(const DeterministicStage& stage, const Bytes& in) {
    return stage.length(FuzzInput{Bytes(in)});
}

Bytes Apply(const DeterministicStage& stage, const Bytes& in, std::uint64_t cursor) {
    const FuzzInput out = stage.apply(FuzzInput{Bytes(in)}, cursor);
    return Bytes(out.data(), out.data() + out.size());
}

// Independently re-derived expected step count for an input of `len`
// bytes, mirroring the operator menu in deterministic_stage.cpp. Kept
// separate from the implementation so the test is a real cross-check.
std::uint64_t ExpectedLength(std::uint64_t len) {
    if (len == 0) {
        return 0;
    }
    const std::uint64_t bits = len * 8;
    auto window = [len](std::uint64_t n) -> std::uint64_t { return len >= n ? len - n + 1 : 0; };
    constexpr std::uint64_t kArithMax = 35;
    std::uint64_t total = 0;
    // walking bit flips 1/2/4
    total += bits;      // width 1
    total += bits - 1;  // width 2
    total += bits - 3;  // width 4
    // walking byte/word/dword flips
    total += window(1) + window(2) + window(4);
    // arithmetic: add/sub × |delta| × endianness (1 endianness for 8-bit)
    total += window(1) * (2 * kArithMax * 1);
    total += window(2) * (2 * kArithMax * 2);
    total += window(4) * (2 * kArithMax * 2);
    // interesting: |table| × endianness (9 / 10 / 7 entries)
    total += window(1) * (9 * 1);
    total += window(2) * (10 * 2);
    total += window(4) * (7 * 2);
    return total;
}

TEST(DeterministicStageLength, EmptyInputIsZero) {
    const DeterministicStage stage;
    EXPECT_EQ(Length(stage, Bytes{}), 0U);
}

TEST(DeterministicStageLength, MatchesExpectedForKnownSizes) {
    const DeterministicStage stage;
    EXPECT_EQ(Length(stage, Bytes(1, 0x00)), 100U);
    EXPECT_EQ(Length(stage, Bytes(2, 0x00)), 365U);
    EXPECT_EQ(Length(stage, Bytes(4, 0x00)), 1050U);
}

TEST(DeterministicStageLength, MatchesIndependentFormula) {
    const DeterministicStage stage;
    for (std::uint64_t len = 0; len <= 16; ++len) {
        EXPECT_EQ(Length(stage, Bytes(len, 0x00)), ExpectedLength(len)) << "len=" << len;
    }
}

TEST(DeterministicStageApply, IsDeterministic) {
    const DeterministicStage stage;
    const Bytes seed{0x41, 0x42, 0x43};
    const std::uint64_t len = Length(stage, seed);
    for (std::uint64_t cursor : {std::uint64_t{0}, len / 3, len / 2, len - 1}) {
        EXPECT_EQ(Apply(stage, seed, cursor), Apply(stage, seed, cursor)) << "cursor=" << cursor;
    }
}

TEST(DeterministicStageApply, IsLengthPreserving) {
    const DeterministicStage stage;
    const Bytes seed{0x10, 0x20, 0x30};
    const std::uint64_t len = Length(stage, seed);
    for (std::uint64_t cursor = 0; cursor < len; ++cursor) {
        EXPECT_EQ(Apply(stage, seed, cursor).size(), seed.size()) << "cursor=" << cursor;
    }
}

TEST(DeterministicStageApply, WalkingBitFlipsCoverEverySingleBit) {
    const DeterministicStage stage;
    const Bytes seed{0x00};
    // The first 8 cursors are the width-1 walking bit flips of byte 0.
    for (std::uint64_t bit = 0; bit < 8; ++bit) {
        const Bytes out = Apply(stage, seed, bit);
        EXPECT_EQ(out, Bytes{static_cast<std::uint8_t>(1U << bit)}) << "bit=" << bit;
    }
    // Cursor 7 flips the high bit of byte 0 → 0x80 (the cov_crash trigger,
    // reached deterministically and independent of any seed).
    EXPECT_EQ(Apply(stage, seed, 7), Bytes{0x80});
}

TEST(DeterministicStageApply, OperatorBoundariesDecodeAsExpected) {
    const DeterministicStage stage;
    const Bytes seed{0x00};
    EXPECT_EQ(Apply(stage, seed, 8), Bytes{0x03});   // flip2 pos0: bits 0,1
    EXPECT_EQ(Apply(stage, seed, 15), Bytes{0x0F});  // flip4 pos0: bits 0..3
    EXPECT_EQ(Apply(stage, seed, 20), Bytes{0xFF});  // byte flip pos0
    EXPECT_EQ(Apply(stage, seed, 21), Bytes{0x01});  // arith8 pos0 +1
    EXPECT_EQ(Apply(stage, seed, 56), Bytes{0xFF});  // arith8 pos0 -1 (wraps)
    EXPECT_EQ(Apply(stage, seed, 97), Bytes{0x7F});  // interesting8 value 0x7F
}

TEST(DeterministicStageApply, ReachesEveryBytePosition) {
    const DeterministicStage stage;
    const Bytes seed{0x00, 0x00};
    // Width-1 bit flips run bits 0..15: cursor 8 is byte 1, bit 0.
    EXPECT_EQ(Apply(stage, seed, 8), (Bytes{0x00, 0x01}));
    EXPECT_EQ(Apply(stage, seed, 0), (Bytes{0x01, 0x00}));
}

TEST(DeterministicStageApply, FullSweepStaysInRangeAndPreservesLength) {
    const DeterministicStage stage;
    const Bytes seed{0xAB, 0xCD};
    const std::uint64_t len = Length(stage, seed);
    ASSERT_EQ(len, 365U);
    for (std::uint64_t cursor = 0; cursor < len; ++cursor) {
        EXPECT_EQ(Apply(stage, seed, cursor).size(), 2U) << "cursor=" << cursor;
    }
}

}  // namespace
}  // namespace mlfuzzz3::mutation
