// Unit tests for the shared positional op primitives (ops.h, ADR 0031).
//
// Coverage: each helper's correctness and boundary behavior —
//   * flip_bit: global-index addressing across bytes; involution.
//   * flip_bytes: byte/word/dword (FLIP8/16/32); offset; untouched tail.
//   * read_int / write_int: little- and big-endian round-trips; width-8
//     truncation; write-then-read identity.
//   * arith: add, subtract, modular wraparound, both endiannesses.
//   * set_interesting: endianness + truncation.
//   * canonical interesting tables: sizes and boundary membership.
//
// These primitives carry no RNG and operate in place, so behavior is
// fully determined by their arguments — identical in CI and locally.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

#include "ops.h"

namespace mlfuzzz3::mutation::ops {
namespace {

using Bytes = std::vector<std::uint8_t>;

std::span<std::uint8_t> Span(Bytes& bytes) {
    return std::span<std::uint8_t>{bytes};
}
std::span<const std::uint8_t> CSpan(const Bytes& bytes) {
    return std::span<const std::uint8_t>{bytes};
}

TEST(OpsFlipBit, FlipsSingleBitByGlobalIndex) {
    Bytes b{0x00};
    flip_bit(Span(b), 0);
    EXPECT_EQ(b[0], 0x01);
    flip_bit(Span(b), 7);
    EXPECT_EQ(b[0], 0x81);
}

TEST(OpsFlipBit, AddressesAcrossBytes) {
    Bytes b{0x00, 0x00};
    flip_bit(Span(b), 8);  // byte 1, bit 0
    EXPECT_EQ(b[0], 0x00);
    EXPECT_EQ(b[1], 0x01);
    flip_bit(Span(b), 15);  // byte 1, bit 7
    EXPECT_EQ(b[1], 0x81);
}

TEST(OpsFlipBit, IsInvolution) {
    Bytes b{0xA5};
    flip_bit(Span(b), 3);
    flip_bit(Span(b), 3);
    EXPECT_EQ(b[0], 0xA5);
}

TEST(OpsFlipBytes, FlipsWholeBytes) {
    Bytes b8{0x00};
    flip_bytes(Span(b8), 0, Width::k8);
    EXPECT_EQ(b8[0], 0xFF);

    Bytes b16{0x00, 0xFF, 0x00};
    flip_bytes(Span(b16), 0, Width::k16);
    EXPECT_EQ(b16[0], 0xFF);
    EXPECT_EQ(b16[1], 0x00);
    EXPECT_EQ(b16[2], 0x00);  // tail untouched

    Bytes b32{0x01, 0x02, 0x03, 0x04};
    flip_bytes(Span(b32), 0, Width::k32);
    EXPECT_EQ(b32[0], 0xFE);
    EXPECT_EQ(b32[1], 0xFD);
    EXPECT_EQ(b32[2], 0xFC);
    EXPECT_EQ(b32[3], 0xFB);
}

TEST(OpsFlipBytes, HonorsOffset) {
    Bytes b{0x00, 0x00, 0x00};
    flip_bytes(Span(b), 1, Width::k16);
    EXPECT_EQ(b[0], 0x00);
    EXPECT_EQ(b[1], 0xFF);
    EXPECT_EQ(b[2], 0xFF);
}

TEST(OpsReadWriteInt, RoundTripsLittleEndian) {
    Bytes b{0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(read_int(CSpan(b), 0, Width::k8, Endianness::kLittle), 0x01U);
    EXPECT_EQ(read_int(CSpan(b), 0, Width::k16, Endianness::kLittle), 0x0201U);
    EXPECT_EQ(read_int(CSpan(b), 0, Width::k32, Endianness::kLittle), 0x04030201U);
}

TEST(OpsReadWriteInt, RoundTripsBigEndian) {
    Bytes b{0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(read_int(CSpan(b), 0, Width::k16, Endianness::kBig), 0x0102U);
    EXPECT_EQ(read_int(CSpan(b), 0, Width::k32, Endianness::kBig), 0x01020304U);
}

TEST(OpsReadWriteInt, WriteRespectsEndiannessAndTruncates) {
    Bytes le{0, 0, 0, 0};
    write_int(Span(le), 0, Width::k16, Endianness::kLittle, 0x1234);
    EXPECT_EQ(le[0], 0x34);
    EXPECT_EQ(le[1], 0x12);

    Bytes be{0, 0, 0, 0};
    write_int(Span(be), 0, Width::k16, Endianness::kBig, 0x1234);
    EXPECT_EQ(be[0], 0x12);
    EXPECT_EQ(be[1], 0x34);

    // width-8 write keeps only the low byte.
    Bytes d{0x00};
    write_int(Span(d), 0, Width::k8, Endianness::kLittle, 0x0100);
    EXPECT_EQ(d[0], 0x00);
}

TEST(OpsReadWriteInt, WriteThenReadIsIdentity) {
    Bytes b{0, 0, 0, 0};
    write_int(Span(b), 0, Width::k32, Endianness::kBig, 0xDEADBEEF);
    EXPECT_EQ(read_int(CSpan(b), 0, Width::k32, Endianness::kBig), 0xDEADBEEFU);
}

TEST(OpsArith, AddsAndSubtracts) {
    Bytes b{0x10};
    arith(Span(b), 0, Width::k8, Endianness::kLittle, 5);
    EXPECT_EQ(b[0], 0x15);
    arith(Span(b), 0, Width::k8, Endianness::kLittle, -5);
    EXPECT_EQ(b[0], 0x10);
}

TEST(OpsArith, WrapsModuloWidth) {
    Bytes lo{0x00};
    arith(Span(lo), 0, Width::k8, Endianness::kLittle, -1);
    EXPECT_EQ(lo[0], 0xFF);

    Bytes hi{0xFF};
    arith(Span(hi), 0, Width::k8, Endianness::kLittle, 1);
    EXPECT_EQ(hi[0], 0x00);
}

TEST(OpsArith, HonorsEndianness) {
    Bytes le{0xFF, 0x00};                                    // LE value 0x00FF
    arith(Span(le), 0, Width::k16, Endianness::kLittle, 1);  // -> 0x0100
    EXPECT_EQ(le[0], 0x00);
    EXPECT_EQ(le[1], 0x01);

    Bytes be{0x00, 0xFF};                                 // BE value 0x00FF
    arith(Span(be), 0, Width::k16, Endianness::kBig, 1);  // -> 0x0100
    EXPECT_EQ(be[0], 0x01);
    EXPECT_EQ(be[1], 0x00);
}

TEST(OpsSetInteresting, WritesValueWithEndiannessAndTruncation) {
    Bytes le{0, 0};
    set_interesting(Span(le), 0, Width::k16, Endianness::kLittle, 0x7FFF);
    EXPECT_EQ(le[0], 0xFF);
    EXPECT_EQ(le[1], 0x7F);

    Bytes b8{0x12};
    set_interesting(Span(b8), 0, Width::k8, Endianness::kLittle, 0xFF);
    EXPECT_EQ(b8[0], 0xFF);
}

TEST(OpsInterestingTables, HaveCanonicalSizesAndBoundaries) {
    EXPECT_EQ(kInteresting8.size(), 9U);
    EXPECT_EQ(kInteresting16.size(), 10U);
    EXPECT_EQ(kInteresting32.size(), 7U);
    // Signed-min boundary patterns are present at each width.
    EXPECT_NE(std::find(kInteresting8.begin(), kInteresting8.end(), 0x80U), kInteresting8.end());
    EXPECT_NE(std::find(kInteresting16.begin(), kInteresting16.end(), 0x8000U),
              kInteresting16.end());
    EXPECT_NE(std::find(kInteresting32.begin(), kInteresting32.end(), 0x80000000U),
              kInteresting32.end());
}

TEST(OpsWidthBytes, MapsEnumToByteCount) {
    EXPECT_EQ(width_bytes(Width::k8), 1U);
    EXPECT_EQ(width_bytes(Width::k16), 2U);
    EXPECT_EQ(width_bytes(Width::k32), 4U);
}

}  // namespace
}  // namespace mlfuzzz3::mutation::ops
