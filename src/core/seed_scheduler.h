#pragma once

#include <cstddef>
#include <cstdint>
#include <random>

#include "rng.h"

// Phase 2 MVP fuzzing loop (ADR 0029). SeedScheduler is the seam that
// decides which corpus entry the campaign loop fuzzes next. The MVP
// ships a trivial random scheduler; the abstract interface is the
// drop-in point for a future ML-based seed scheduler (ADR 0029
// Развилка 4) — the loop is written against SeedScheduler, so swapping
// the strategy touches no loop code.

namespace mlfuzzz3::core {

// Abstract chooser over corpus indices. Stateful by design: an
// implementation may keep a cursor or an owned RNG. Not thread-safe;
// the MVP loop is single-threaded (ADR 0029 Развилка 3).
class SeedScheduler {
   public:
    SeedScheduler() = default;
    SeedScheduler(const SeedScheduler&) = delete;
    SeedScheduler& operator=(const SeedScheduler&) = delete;
    SeedScheduler(SeedScheduler&&) = delete;
    SeedScheduler& operator=(SeedScheduler&&) = delete;
    virtual ~SeedScheduler() = default;

    // Choose returns an index in [0, corpus_size). Precondition:
    // corpus_size > 0 — the loop bootstraps at least one corpus entry
    // before scheduling begins (ADR 0029 §Решение, Corpus bootstrap).
    [[nodiscard]] virtual std::size_t Choose(std::size_t corpus_size) = 0;

    // Stable identifier for logs and metrics. Mirrors Mutator::name().
    [[nodiscard]] virtual const char* name() const noexcept = 0;
};

// RandomScheduler picks a uniformly random index using an owned
// std::mt19937_64 (seeded via mutation::make_rng — the same engine the
// mutators use). Deterministic for a fixed seed (replay pillar,
// ADR 0027/0029): two RandomSchedulers constructed with the same seed
// produce the same Choose() sequence for the same corpus_size inputs.
class RandomScheduler final : public SeedScheduler {
   public:
    explicit RandomScheduler(std::uint64_t seed) : rng_(mutation::make_rng(seed)) {}

    [[nodiscard]] std::size_t Choose(std::size_t corpus_size) override {
        return mutation::rng_next_index(rng_, corpus_size);
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "random";
    }

   private:
    std::mt19937_64 rng_;
};

}  // namespace mlfuzzz3::core
