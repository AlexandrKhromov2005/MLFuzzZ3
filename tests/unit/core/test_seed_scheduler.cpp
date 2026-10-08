#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "seed_scheduler.h"

namespace mlfuzzz3::core {
namespace {

// Determinism (replay invariant, ADR 0029): two schedulers seeded
// identically produce identical Choose() sequences.
TEST(RandomScheduler, DeterministicForFixedSeed) {
    constexpr std::uint64_t kSeed = 0xC0FFEEULL;
    constexpr std::size_t kCorpusSize = 7;
    constexpr int kDraws = 64;

    RandomScheduler a(kSeed);
    RandomScheduler b(kSeed);

    std::vector<std::size_t> seq_a;
    std::vector<std::size_t> seq_b;
    seq_a.reserve(kDraws);
    seq_b.reserve(kDraws);
    for (int i = 0; i < kDraws; ++i) {
        seq_a.push_back(a.Choose(kCorpusSize));
        seq_b.push_back(b.Choose(kCorpusSize));
    }
    EXPECT_EQ(seq_a, seq_b);
}

// Every choice stays within [0, corpus_size).
TEST(RandomScheduler, ChoiceWithinRange) {
    constexpr std::size_t kCorpusSize = 5;
    RandomScheduler s(1234);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_LT(s.Choose(kCorpusSize), kCorpusSize);
    }
}

// Different seeds diverge (sanity that the seed actually drives the
// sequence, not a constant).
TEST(RandomScheduler, DifferentSeedsDiverge) {
    constexpr std::size_t kCorpusSize = 1000;
    constexpr int kDraws = 64;

    RandomScheduler a(1);
    RandomScheduler b(2);

    std::vector<std::size_t> seq_a;
    std::vector<std::size_t> seq_b;
    seq_a.reserve(kDraws);
    seq_b.reserve(kDraws);
    for (int i = 0; i < kDraws; ++i) {
        seq_a.push_back(a.Choose(kCorpusSize));
        seq_b.push_back(b.Choose(kCorpusSize));
    }
    EXPECT_NE(seq_a, seq_b);
}

TEST(RandomScheduler, NameIsStable) {
    RandomScheduler s(0);
    EXPECT_STREQ(s.name(), "random");
}

}  // namespace
}  // namespace mlfuzzz3::core
