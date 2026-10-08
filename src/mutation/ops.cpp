#include "ops.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace mlfuzzz3::mutation::ops {
namespace {

// XOR mask that flips every bit of a byte (AFL byte/word/dword flips).
constexpr std::uint8_t kAllOnes = 0xFF;

// Bit shift for byte `i` of an `nbytes`-wide integer in the given order:
// little-endian places byte 0 in the low bits, big-endian in the high.
std::size_t ByteShift(std::size_t i, std::size_t nbytes, Endianness endian) noexcept {
    const std::size_t index = (endian == Endianness::kBig) ? (nbytes - 1 - i) : i;
    return index * kBitsPerByte;
}

}  // namespace

void flip_bit(std::span<std::uint8_t> buf, std::size_t bit) noexcept {
    buf[bit / kBitsPerByte] ^= static_cast<std::uint8_t>(1U << (bit % kBitsPerByte));
}

void flip_bytes(std::span<std::uint8_t> buf, std::size_t pos, Width width) noexcept {
    const std::size_t nbytes = width_bytes(width);
    for (std::size_t i = 0; i < nbytes; ++i) {
        buf[pos + i] ^= kAllOnes;
    }
}

std::uint32_t read_int(std::span<const std::uint8_t> buf, std::size_t pos, Width width,
                       Endianness endian) noexcept {
    const std::size_t nbytes = width_bytes(width);
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < nbytes; ++i) {
        value |= static_cast<std::uint32_t>(buf[pos + i]) << ByteShift(i, nbytes, endian);
    }
    return value;
}

void write_int(std::span<std::uint8_t> buf, std::size_t pos, Width width, Endianness endian,
               std::uint32_t value) noexcept {
    const std::size_t nbytes = width_bytes(width);
    for (std::size_t i = 0; i < nbytes; ++i) {
        buf[pos + i] = static_cast<std::uint8_t>(value >> ByteShift(i, nbytes, endian));
    }
}

void arith(std::span<std::uint8_t> buf, std::size_t pos, Width width, Endianness endian,
           std::int32_t delta) noexcept {
    const std::uint32_t value = read_int(buf, pos, width, endian);
    const std::uint32_t result = value + static_cast<std::uint32_t>(delta);
    write_int(buf, pos, width, endian, result);
}

void set_interesting(std::span<std::uint8_t> buf, std::size_t pos, Width width, Endianness endian,
                     std::uint32_t value) noexcept {
    write_int(buf, pos, width, endian, value);
}

}  // namespace mlfuzzz3::mutation::ops
