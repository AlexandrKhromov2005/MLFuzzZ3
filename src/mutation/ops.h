#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

// Phase 2 deterministic stage (ADR 0031). Canonical positional mutation
// primitives shared between the deterministic stage and (eventually)
// havoc. Pure free functions over a mutable byte span: no RNG, no
// allocation, no length change. Each helper carries an explicit
// precondition on positions/widths; the caller (the deterministic-stage
// cursor, or a future migrated havoc) is responsible for satisfying it.
//
// These functions are the single source of truth for what a "bit flip",
// "byte/word/dword flip", "arithmetic step", or "interesting value" means.
// HavocMutator currently carries an equivalent inline copy of the same
// semantics; migrating it onto these helpers is deferred (ADR 0031), so
// until then the two implementations must stay byte-for-byte equivalent —
// a divergence is a bug.

namespace mlfuzzz3::mutation::ops {

inline constexpr std::size_t kBitsPerByte = 8;

// Operand width in bytes for the integer-valued ops. Using an enum (not a
// bare std::size_t) keeps adjacent parameters distinctly typed and
// self-documents the 1/2/4 set.
enum class Width : std::size_t { k8 = 1, k16 = 2, k32 = 4 };

// Byte order for multi-byte integer reads/writes.
enum class Endianness : std::uint8_t { kLittle, kBig };

// width_bytes(Width) -> 1 | 2 | 4.
[[nodiscard]] constexpr std::size_t width_bytes(Width width) noexcept {
    return static_cast<std::size_t>(width);
}

// Canonical AFL-style "interesting" boundary values, stored as unsigned
// bit patterns (write_int truncates to the operand width). These are
// well-known fuzzing boundary constants — specification, not magic
// numbers — and are the single source of truth shared with havoc.
// NOLINTBEGIN(readability-magic-numbers)
inline constexpr auto kInteresting8 =
    std::to_array<std::uint32_t>({0x00, 0x01, 0x10, 0x20, 0x40, 0x64, 0x7F, 0x80, 0xFF});
inline constexpr auto kInteresting16 = std::to_array<std::uint32_t>(
    {0x0080, 0x00FF, 0x0100, 0x03E8, 0x0400, 0x1000, 0x7FFF, 0x8000, 0xFF7F, 0xFFFF});
inline constexpr auto kInteresting32 = std::to_array<std::uint32_t>(
    {0x00008000, 0x0000FFFF, 0x00010000, 0x7FFFFFFF, 0x80000000, 0xFFFF7FFF, 0xFFFFFFFF});
// NOLINTEND(readability-magic-numbers)

// flip_bit: XOR a single bit identified by its global bit index `bit`
// (byte bit / kBitsPerByte, in-byte position bit % kBitsPerByte). A global
// index avoids an error-prone (byte, bit) parameter pair. Precondition:
// bit < buf.size() * kBitsPerByte.
void flip_bit(std::span<std::uint8_t> buf, std::size_t bit) noexcept;

// flip_bytes: XOR every bit (^ 0xFF) of `width` whole bytes starting at
// byte `pos` — AFL FLIP8 / FLIP16 / FLIP32. Precondition:
// pos + width_bytes(width) <= buf.size().
void flip_bytes(std::span<std::uint8_t> buf, std::size_t pos, Width width) noexcept;

// read_int: the width-byte integer at byte `pos`, in the requested byte
// order. Precondition: pos + width_bytes(width) <= buf.size().
[[nodiscard]] std::uint32_t read_int(std::span<const std::uint8_t> buf, std::size_t pos,
                                     Width width, Endianness endian) noexcept;

// write_int: store `value` (truncated to the operand width) at byte `pos`
// in the requested byte order. Precondition: pos + width_bytes(width) <=
// buf.size().
void write_int(std::span<std::uint8_t> buf, std::size_t pos, Width width, Endianness endian,
               std::uint32_t value) noexcept;

// arith: add the signed `delta` to the width-byte integer at `pos`
// (wrapping mod 2^(8*width_bytes), truncated to width). Negative deltas
// subtract. Precondition: pos + width_bytes(width) <= buf.size().
void arith(std::span<std::uint8_t> buf, std::size_t pos, Width width, Endianness endian,
           std::int32_t delta) noexcept;

// set_interesting: overwrite the width-byte integer at `pos` with `value`
// (truncated to width) in the requested byte order. Precondition:
// pos + width_bytes(width) <= buf.size().
void set_interesting(std::span<std::uint8_t> buf, std::size_t pos, Width width, Endianness endian,
                     std::uint32_t value) noexcept;

}  // namespace mlfuzzz3::mutation::ops
