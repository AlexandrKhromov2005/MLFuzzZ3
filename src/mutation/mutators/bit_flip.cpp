#include "bit_flip.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "../rng.h"

namespace mlfuzzz3::mutation {

namespace {

constexpr std::size_t kBitsPerByte = 8;

}  // namespace

FuzzInput BitFlipMutator::mutate(const FuzzInput& input, std::mt19937_64& rng) const {
    if (input.size() == 0) {
        return FuzzInput{};
    }
    FuzzInput out = input;
    const std::span<std::uint8_t> buf{out.data(), out.size()};
    const std::size_t byte_index = rng_next_index(rng, buf.size());
    const std::size_t bit_index = rng_next_index(rng, kBitsPerByte);
    buf[byte_index] ^= static_cast<std::uint8_t>(1U << bit_index);
    return out;
}

}  // namespace mlfuzzz3::mutation
