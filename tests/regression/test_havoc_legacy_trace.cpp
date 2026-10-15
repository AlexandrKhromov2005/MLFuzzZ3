// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "mutators/havoc.h"
#include "rng.h"
namespace mlfuzzz3::mutation {
TEST(HavocLegacyRegression, ComposedMenuPreservesBytesAndNextRngWord) {
    struct Case {
        std::uint64_t seed;
        std::size_t size;
        std::uint64_t hash;
        std::uint64_t next;
    };
    const std::array<Case, 4> cases{
        {{0, 30, 7130698406219306917ULL, 15536964167022953318ULL},
         {1, 32, 4643336305634894295ULL, 16811588669333006409ULL},
         {1234, 98, 9098301226232063583ULL, 15248410258639322967ULL},
         {99999, 32, 10751713112655307675ULL, 10463719440368157895ULL}}};
    std::vector<std::uint8_t> bytes(32);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(index);
    }
    for (const auto& test : cases) {
        auto rng = make_rng(test.seed);
        HavocMutator mutator;
        const auto output = mutator.mutate(FuzzInput(bytes), rng);
        std::uint64_t hash = 14695981039346656037ULL;
        for (std::size_t index = 0; index < output.size(); ++index) {
            hash = (hash ^ output.data()[index]) * 1099511628211ULL;
        }
        EXPECT_EQ(output.size(), test.size);
        EXPECT_EQ(hash, test.hash);
        EXPECT_EQ(rng(), test.next);
    }
}
}  // namespace mlfuzzz3::mutation

namespace mlfuzzz3::mutation {
namespace {
class FirstOperator final : public OperatorSelector {
   public:
    std::size_t choose(std::span<const MutationOperator>, std::mt19937_64&) const override {
        return 0;
    }
};
class OneOperation final : public StackingPolicy {
   public:
    std::size_t count(std::mt19937_64&) const override {
        return 1;
    }
};
TEST(HavocComposition, CustomOperatorAndPoliciesNeedNoCampaignChanges) {
    std::vector<MutationOperator> operators;
    operators.push_back(
        {.name = "marker", .apply = [](auto& bytes, auto&) { bytes.at(0) = 0xab; }});
    HavocMutator mutator(std::move(operators), std::make_unique<FirstOperator>(),
                         std::make_unique<OneOperation>());
    const FuzzInput input(std::vector<std::uint8_t>{1, 2});
    auto rng = make_rng(42);
    auto expected_rng = make_rng(42);
    const auto result = mutator.mutate(input, rng);
    ASSERT_EQ(result.size(), 2U);
    EXPECT_EQ(result.data()[0], 0xab);
    EXPECT_EQ(result.data()[1], 2);
    EXPECT_EQ(rng(), expected_rng());
}
}  // namespace
}  // namespace mlfuzzz3::mutation
