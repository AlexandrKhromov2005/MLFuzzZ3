#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <random>

// Phase 2 mutation foundation (ADR 0027). Thin helpers around
// std::mt19937_64. The RNG itself is owned by the caller (replay
// pillar: all non-determinism is concentrated at the caller's
// seeding point); mutators never construct their own RNG. A
// dedicated RNG abstraction is not introduced — std::mt19937_64
// is deterministic for a fixed seed by the C++ standard, which
// is enough for in-process replay. Cross-stdlib bit compatibility
// is explicitly out of scope for this slice (see ADR 0027).

namespace mlfuzzz3::mutation {

// Build a std::mt19937_64 seeded with `seed`. Wrapping the
// constructor keeps the choice of engine encapsulated, so a future
// switch to a different deterministic engine touches only this
// header.
inline std::mt19937_64 make_rng(std::uint64_t seed) {
    return std::mt19937_64{seed};
}

// Uniformly sample an index in [0, size). Precondition: size > 0;
// indexing an empty range is undefined and the caller is expected
// to short-circuit on the empty case before reaching here.
inline std::size_t rng_next_index(std::mt19937_64& rng, std::size_t size) {
    assert(size > 0 && "rng_next_index requires size > 0");
    std::uniform_int_distribution<std::size_t> dist(0, size - 1);
    return dist(rng);
}

}  // namespace mlfuzzz3::mutation
