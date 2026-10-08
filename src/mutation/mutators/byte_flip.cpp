#include "byte_flip.h"

#include <cstddef>
#include <cstdint>
#include <span>

#include "../rng.h"

namespace mlfuzzz3::mutation {

namespace {

constexpr std::size_t kByteAlphabetSize = 256;

}  // namespace

FuzzInput ByteFlipMutator::mutate(const FuzzInput& input, std::mt19937_64& rng) const {
    if (input.size() == 0) {
        return FuzzInput{};
    }
    FuzzInput out = input;
    const std::span<std::uint8_t> buf{out.data(), out.size()};
    const std::size_t byte_index = rng_next_index(rng, buf.size());
    const std::size_t byte_value = rng_next_index(rng, kByteAlphabetSize);
    buf[byte_index] = static_cast<std::uint8_t>(byte_value);
    return out;
}

}  // namespace mlfuzzz3::mutation
