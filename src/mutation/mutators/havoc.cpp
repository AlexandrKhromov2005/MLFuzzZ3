#include "havoc.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "../rng.h"

namespace mlfuzzz3::mutation {
namespace {

constexpr std::size_t kBitsPerByte = 8;
constexpr std::size_t kByteAlphabetSize = 256;
// Stacked-op count is 1 << uniform(0..kStackPow2) — AFL's havoc shape.
constexpr std::size_t kStackPow2 = 7;
// Max absolute delta for arithmetic operations (AFL ARITH_MAX).
constexpr std::uint32_t kArithMax = 35;
// Cap on the byte count a single block op inserts/deletes, so one op
// cannot jump straight to kHavocMaxLen.
constexpr std::size_t kMaxBlockLen = 32;
constexpr std::size_t kCoinSides = 2;

// Operand width for arithmetic / interesting-value operations. Using an
// enum (rather than a bare size_t) also keeps adjacent parameters
// distinctly typed.
enum class Width : std::size_t { k8 = 1, k16 = 2, k32 = 4 };

std::size_t WidthBytes(Width width) {
    return static_cast<std::size_t>(width);
}

// AFL-style "interesting" boundary constants, stored as unsigned bit
// patterns (WriteInt truncates to the operand width). These are
// well-known fuzzing boundary values — specification, not magic numbers.
// NOLINTBEGIN(readability-magic-numbers)
constexpr auto kInteresting8 =
    std::to_array<std::uint32_t>({0x00, 0x01, 0x10, 0x20, 0x40, 0x64, 0x7F, 0x80, 0xFF});
constexpr auto kInteresting16 = std::to_array<std::uint32_t>(
    {0x0080, 0x00FF, 0x0100, 0x03E8, 0x0400, 0x1000, 0x7FFF, 0x8000, 0xFF7F, 0xFFFF});
constexpr auto kInteresting32 = std::to_array<std::uint32_t>(
    {0x00008000, 0x0000FFFF, 0x00010000, 0x7FFFFFFF, 0x80000000, 0xFFFF7FFF, 0xFFFFFFFF});
// NOLINTEND(readability-magic-numbers)

bool CoinFlip(std::mt19937_64& rng) {
    return rng_next_index(rng, kCoinSides) == 1;
}

std::uint8_t RandomByte(std::mt19937_64& rng) {
    return static_cast<std::uint8_t>(rng_next_index(rng, kByteAlphabetSize));
}

// Inclusive random length in [1, max_len]. Precondition: max_len >= 1.
std::size_t RandomBlockLen(std::mt19937_64& rng, std::size_t max_len) {
    return rng_next_index(rng, max_len) + 1;
}

std::uint32_t ReadInt(const std::vector<std::uint8_t>& buf, std::size_t offset, Width width,
                      bool big_endian) {
    const std::size_t nbytes = WidthBytes(width);
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < nbytes; ++i) {
        const std::size_t shift = (big_endian ? (nbytes - 1 - i) : i) * kBitsPerByte;
        value |= static_cast<std::uint32_t>(buf[offset + i]) << shift;
    }
    return value;
}

void WriteInt(std::vector<std::uint8_t>& buf, std::size_t offset, Width width, bool big_endian,
              std::uint32_t value) {
    const std::size_t nbytes = WidthBytes(width);
    for (std::size_t i = 0; i < nbytes; ++i) {
        const std::size_t shift = (big_endian ? (nbytes - 1 - i) : i) * kBitsPerByte;
        buf[offset + i] = static_cast<std::uint8_t>(value >> shift);
    }
}

void FlipBits(std::vector<std::uint8_t>& buf, std::mt19937_64& rng, std::size_t width) {
    const std::size_t total_bits = buf.size() * kBitsPerByte;
    if (total_bits == 0) {
        return;
    }
    const std::size_t start = rng_next_index(rng, total_bits);
    for (std::size_t i = 0; i < width; ++i) {
        const std::size_t bit = start + i;
        if (bit >= total_bits) {
            break;
        }
        buf[bit / kBitsPerByte] ^= static_cast<std::uint8_t>(1U << (bit % kBitsPerByte));
    }
}

void SetByte(std::vector<std::uint8_t>& buf, std::mt19937_64& rng) {
    if (buf.empty()) {
        return;
    }
    buf[rng_next_index(rng, buf.size())] = RandomByte(rng);
}

void Arith(std::vector<std::uint8_t>& buf, std::mt19937_64& rng, Width width) {
    const std::size_t nbytes = WidthBytes(width);
    if (buf.size() < nbytes) {
        return;
    }
    const std::size_t offset = rng_next_index(rng, buf.size() - nbytes + 1);
    const bool big_endian = CoinFlip(rng);
    const std::uint32_t delta = static_cast<std::uint32_t>(rng_next_index(rng, kArithMax)) + 1;
    const std::uint32_t value = ReadInt(buf, offset, width, big_endian);
    WriteInt(buf, offset, width, big_endian, CoinFlip(rng) ? value - delta : value + delta);
}

void SetInteresting(std::vector<std::uint8_t>& buf, std::mt19937_64& rng, Width width,
                    std::span<const std::uint32_t> table) {
    const std::size_t nbytes = WidthBytes(width);
    if (buf.size() < nbytes) {
        return;
    }
    const std::size_t offset = rng_next_index(rng, buf.size() - nbytes + 1);
    const std::uint32_t value = table[rng_next_index(rng, table.size())];
    WriteInt(buf, offset, width, CoinFlip(rng), value);
}

void InsertBlock(std::vector<std::uint8_t>& buf, std::mt19937_64& rng) {
    if (buf.size() >= kHavocMaxLen) {
        return;
    }
    const std::size_t room = std::min(kHavocMaxLen - buf.size(), kMaxBlockLen);
    const std::size_t block_len = RandomBlockLen(rng, room);
    const std::size_t pos = rng_next_index(rng, buf.size() + 1);
    std::vector<std::uint8_t> block(block_len);
    for (std::uint8_t& byte : block) {
        byte = RandomByte(rng);
    }
    buf.insert(buf.begin() + static_cast<std::ptrdiff_t>(pos), block.begin(), block.end());
}

void DuplicateBlock(std::vector<std::uint8_t>& buf, std::mt19937_64& rng) {
    if (buf.empty() || buf.size() >= kHavocMaxLen) {
        return;
    }
    const std::size_t room = std::min(kHavocMaxLen - buf.size(), kMaxBlockLen);
    const std::size_t block_len = std::min(RandomBlockLen(rng, room), buf.size());
    const std::size_t src = rng_next_index(rng, buf.size() - block_len + 1);
    std::vector<std::uint8_t> block(buf.begin() + static_cast<std::ptrdiff_t>(src),
                                    buf.begin() + static_cast<std::ptrdiff_t>(src + block_len));
    const std::size_t pos = rng_next_index(rng, buf.size() + 1);
    buf.insert(buf.begin() + static_cast<std::ptrdiff_t>(pos), block.begin(), block.end());
}

void DeleteBlock(std::vector<std::uint8_t>& buf, std::mt19937_64& rng) {
    if (buf.size() <= 1) {
        return;
    }
    const std::size_t max_del = std::min(buf.size() - 1, kMaxBlockLen);
    const std::size_t del_len = RandomBlockLen(rng, max_del);
    const std::size_t pos = rng_next_index(rng, buf.size() - del_len + 1);
    buf.erase(buf.begin() + static_cast<std::ptrdiff_t>(pos),
              buf.begin() + static_cast<std::ptrdiff_t>(pos + del_len));
}

// Operation menu (ADR 0030). Order is fixed: changing it is a breaking
// change for replay reproducibility.
enum class Op : std::size_t {
    kFlip1,
    kFlip2,
    kFlip4,
    kByte,
    kArith8,
    kArith16,
    kArith32,
    kInteresting8,
    kInteresting16,
    kInteresting32,
    kInsert,
    kDuplicate,
    kDelete,
    kCount,
};

constexpr std::size_t kFlip2Width = 2;
constexpr std::size_t kFlip4Width = 4;

void ApplyOp(std::vector<std::uint8_t>& buf, std::mt19937_64& rng) {
    const auto op = static_cast<Op>(rng_next_index(rng, static_cast<std::size_t>(Op::kCount)));
    switch (op) {
        case Op::kFlip1:
            FlipBits(buf, rng, 1);
            break;
        case Op::kFlip2:
            FlipBits(buf, rng, kFlip2Width);
            break;
        case Op::kFlip4:
            FlipBits(buf, rng, kFlip4Width);
            break;
        case Op::kByte:
            SetByte(buf, rng);
            break;
        case Op::kArith8:
            Arith(buf, rng, Width::k8);
            break;
        case Op::kArith16:
            Arith(buf, rng, Width::k16);
            break;
        case Op::kArith32:
            Arith(buf, rng, Width::k32);
            break;
        case Op::kInteresting8:
            SetInteresting(buf, rng, Width::k8, kInteresting8);
            break;
        case Op::kInteresting16:
            SetInteresting(buf, rng, Width::k16, kInteresting16);
            break;
        case Op::kInteresting32:
            SetInteresting(buf, rng, Width::k32, kInteresting32);
            break;
        case Op::kInsert:
            InsertBlock(buf, rng);
            break;
        case Op::kDuplicate:
            DuplicateBlock(buf, rng);
            break;
        case Op::kDelete:
            DeleteBlock(buf, rng);
            break;
        case Op::kCount:
        default:
            break;
    }
}

}  // namespace

FuzzInput HavocMutator::mutate(const FuzzInput& input, std::mt19937_64& rng) const {
    if (input.size() == 0) {
        return FuzzInput{};
    }
    const std::span<const std::uint8_t> in{input.data(), input.size()};
    std::vector<std::uint8_t> buf(in.begin(), in.end());

    const std::size_t stack = std::size_t{1} << rng_next_index(rng, kStackPow2 + 1);
    for (std::size_t i = 0; i < stack; ++i) {
        ApplyOp(buf, rng);
    }
    return FuzzInput{std::move(buf)};
}

}  // namespace mlfuzzz3::mutation
