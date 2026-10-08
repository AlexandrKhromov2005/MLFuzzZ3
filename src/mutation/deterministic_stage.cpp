#include "deterministic_stage.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "ops.h"

namespace mlfuzzz3::mutation {
namespace {

using ops::Endianness;
using ops::Width;

// AFL ARITH_MAX: arithmetic deltas range over ±[1, kArithMax]. Kept equal
// to havoc's arithmetic span (canonical semantics, ADR 0031). uint64 so
// the variant-count multiplications stay in the cursor's width.
constexpr std::uint64_t kArithMax = 35;

// The operator classes of the deterministic sweep, in cursor order.
enum class OpClass : std::uint8_t { kFlipBit, kFlipBytes, kArith, kInteresting };

// One operator at one width. `width` is a bit-run width (1/2/4) for
// kFlipBit and a byte width (1/2/4) for every other class.
struct OpSpec {
    OpClass op;
    std::size_t width;
};

// Operator order is the cursor order and is part of the replay contract:
// reordering changes which mutation a given cursor produces.
constexpr std::array<OpSpec, 12> kOpSpecs = {{
    {.op = OpClass::kFlipBit, .width = 1},
    {.op = OpClass::kFlipBit, .width = 2},
    {.op = OpClass::kFlipBit, .width = 4},
    {.op = OpClass::kFlipBytes, .width = 1},
    {.op = OpClass::kFlipBytes, .width = 2},
    {.op = OpClass::kFlipBytes, .width = 4},
    {.op = OpClass::kArith, .width = 1},
    {.op = OpClass::kArith, .width = 2},
    {.op = OpClass::kArith, .width = 4},
    {.op = OpClass::kInteresting, .width = 1},
    {.op = OpClass::kInteresting, .width = 2},
    {.op = OpClass::kInteresting, .width = 4},
}};

Width to_width(std::size_t byte_width) noexcept {
    return static_cast<Width>(byte_width);
}

// Endianness variants enumerated for a byte width: 1 byte has a single
// (trivial) order; 2/4 bytes enumerate little- then big-endian.
std::uint64_t endian_variants(std::size_t byte_width) noexcept {
    return byte_width == 1 ? 1 : 2;
}

std::span<const std::uint32_t> interesting_table(std::size_t byte_width) noexcept {
    switch (byte_width) {
        case 1:
            return ops::kInteresting8;
        case 2:
            return ops::kInteresting16;
        default:
            return ops::kInteresting32;
    }
}

// Number of start positions this operator has over an input of `len`
// bytes (0 if the operator's window does not fit).
std::uint64_t spec_positions(const OpSpec& spec, std::size_t len) noexcept {
    if (spec.op == OpClass::kFlipBit) {
        const std::uint64_t total_bits = static_cast<std::uint64_t>(len) * ops::kBitsPerByte;
        return total_bits >= spec.width ? total_bits - spec.width + 1 : 0;
    }
    return len >= spec.width ? static_cast<std::uint64_t>(len - spec.width + 1) : 0;
}

// Number of distinct mutations this operator enumerates per position.
std::uint64_t spec_variants(const OpSpec& spec) noexcept {
    switch (spec.op) {
        case OpClass::kFlipBit:
        case OpClass::kFlipBytes:
            return 1;
        case OpClass::kArith:
            // add/subtract × |delta| × endianness.
            return 2 * kArithMax * endian_variants(spec.width);
        case OpClass::kInteresting:
            return interesting_table(spec.width).size() * endian_variants(spec.width);
    }
    return 0;
}

// Apply the operator `spec` at the in-stage offset `local` (which encodes
// both the position and, for the integer ops, the per-position variant).
// Variant decoding is inlined to keep the position and variant as locals
// rather than same-typed parameters.
void apply_spec(std::span<std::uint8_t> buf, const OpSpec& spec, std::uint64_t local) {
    const std::uint64_t variants = spec_variants(spec);
    const auto pos = static_cast<std::size_t>(local / variants);
    const std::uint64_t variant = local % variants;

    switch (spec.op) {
        case OpClass::kFlipBit:
            // `pos` is the global start bit; flip `spec.width` consecutive
            // bits. Positions are bounded so the run always fits.
            for (std::size_t i = 0; i < spec.width; ++i) {
                ops::flip_bit(buf, pos + i);
            }
            break;
        case OpClass::kFlipBytes:
            ops::flip_bytes(buf, pos, to_width(spec.width));
            break;
        case OpClass::kArith: {
            // variant layout: low factor is |delta|-1, then add/sub, then
            // endianness — matching spec_variants' factor order.
            const std::uint64_t magnitude = (variant % kArithMax) + 1;
            const std::uint64_t rest = variant / kArithMax;
            const bool subtract = (rest % 2) == 1;
            const Endianness endian = (rest / 2 == 0) ? Endianness::kLittle : Endianness::kBig;
            const auto delta = static_cast<std::int32_t>(magnitude);
            ops::arith(buf, pos, to_width(spec.width), endian, subtract ? -delta : delta);
            break;
        }
        case OpClass::kInteresting: {
            const std::span<const std::uint32_t> table = interesting_table(spec.width);
            const auto value_index = static_cast<std::size_t>(variant % table.size());
            const Endianness endian =
                (variant / table.size() == 0) ? Endianness::kLittle : Endianness::kBig;
            ops::set_interesting(buf, pos, to_width(spec.width), endian, table[value_index]);
            break;
        }
    }
}

}  // namespace

std::uint64_t DeterministicStage::length(const FuzzInput& input) noexcept {
    std::uint64_t total = 0;
    for (const OpSpec& spec : kOpSpecs) {
        total += spec_positions(spec, input.size()) * spec_variants(spec);
    }
    return total;
}

FuzzInput DeterministicStage::apply(const FuzzInput& input, std::uint64_t cursor) {
    const std::span<const std::uint8_t> in{input.data(), input.size()};
    std::vector<std::uint8_t> buf(in.begin(), in.end());
    const std::span<std::uint8_t> span{buf};

    std::uint64_t remaining = cursor;
    for (const OpSpec& spec : kOpSpecs) {
        const std::uint64_t count = spec_positions(spec, input.size()) * spec_variants(spec);
        if (remaining < count) {
            apply_spec(span, spec, remaining);
            return FuzzInput{std::move(buf)};
        }
        remaining -= count;
    }
    // Precondition cursor < length(input) violated; callers guarantee it.
    assert(false && "DeterministicStage::apply: cursor >= length(input)");
    return FuzzInput{std::move(buf)};
}

}  // namespace mlfuzzz3::mutation
