// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include "components.h"
#include "mutators/havoc.h"
#include "rng.h"

namespace mlfuzzz3::composition {
namespace {

TEST(Composition, DefaultPreservesLegacyRandomStreams) {
    const auto components = Registry{}.Build({.seed = 1234});
    mutation::HavocMutator legacy_mutator;
    core::RandomScheduler legacy_scheduler(1234);
    auto actual_rng = mutation::make_rng(1234);
    auto legacy_rng = mutation::make_rng(1234);
    const std::array<std::uint8_t, 4> bytes{0, 17, 128, 255};
    const mutation::FuzzInput input(bytes.data(), bytes.size());
    for (std::size_t size = 1; size <= 32; ++size) {
        EXPECT_EQ(components.seed_scheduler->Choose(size), legacy_scheduler.Choose(size));
        const auto actual = components.mutator->mutate(input, actual_rng);
        const auto expected = legacy_mutator.mutate(input, legacy_rng);
        EXPECT_EQ(std::vector<std::uint8_t>(actual.data(), actual.data() + actual.size()),
                  std::vector<std::uint8_t>(expected.data(), expected.data() + expected.size()));
    }
}

TEST(Composition, BuiltinMutatorNamesResolve) {
    for (const auto* name : {"havoc", "bitflip", "byteflip"}) {
        const auto components = Registry{}.Build({.mutator = name});
        EXPECT_STREQ(components.mutator->name(), name);
    }
}

TEST(Composition, RoundRobinHandlesCorpusGrowthAndSmallerViews) {
    const auto components = Registry{}.Build({.seed_scheduler = "round-robin"});
    auto& scheduler = *components.seed_scheduler;
    EXPECT_STREQ(scheduler.name(), "round-robin");
    EXPECT_EQ(scheduler.Choose(2), 0U);
    EXPECT_EQ(scheduler.Choose(2), 1U);
    EXPECT_EQ(scheduler.Choose(3), 2U);
    EXPECT_EQ(scheduler.Choose(3), 0U);
    EXPECT_EQ(scheduler.Choose(1), 0U);
    EXPECT_EQ(scheduler.Choose(2), 1U);
}

TEST(Composition, UnknownNamesFailBeforeInvokingFactories) {
    Registry registry;
    bool called = false;
    registry.RegisterMutator("probe", [&called] {
        called = true;
        return std::make_unique<mutation::HavocMutator>();
    });
    EXPECT_THROW((void)registry.Build({.mutator = "missing"}), std::runtime_error);
    EXPECT_THROW((void)registry.Build({.mutator = "probe", .seed_scheduler = "missing"}),
                 std::runtime_error);
    EXPECT_FALSE(called);
}

TEST(Composition, RejectsDuplicateAndEmptyRegistrations) {
    Registry registry;
    EXPECT_THROW(registry.RegisterMutator(
                     "havoc", [] { return std::make_unique<mutation::HavocMutator>(); }),
                 std::invalid_argument);
    EXPECT_THROW(registry.RegisterMutator("", Registry::SimpleMutatorFactory{}),
                 std::invalid_argument);
    EXPECT_THROW(
        registry.RegisterScheduler(
            "random",
            [](std::uint64_t seed) { return std::make_unique<core::RandomScheduler>(seed); }),
        std::invalid_argument);
    EXPECT_THROW(registry.RegisterScheduler("custom", {}), std::invalid_argument);
}

TEST(Composition, RejectsMissingFactoryProducts) {
    Registry registry;
    registry.RegisterMutator("null", [] { return std::unique_ptr<mutation::Mutator>{}; });
    registry.RegisterScheduler(
        "null", [](std::uint64_t) { return std::unique_ptr<core::SeedScheduler>{}; });
    EXPECT_THROW((void)registry.Build({.mutator = "null"}), std::runtime_error);
    EXPECT_THROW((void)registry.Build({.seed_scheduler = "null"}), std::runtime_error);
}

TEST(Composition, RegistrationsAreLocalToComposition) {
    Registry registry;
    registry.RegisterScheduler(
        "custom", [](std::uint64_t seed) { return std::make_unique<core::RandomScheduler>(seed); });
    const auto components = registry.Build({.seed_scheduler = "custom", .seed = 77});
    core::RandomScheduler expected(77);
    EXPECT_EQ(components.seed_scheduler->Choose(100), expected.Choose(100));
    EXPECT_THROW((void)Registry{}.Build({.seed_scheduler = "custom"}), std::runtime_error);
}

}  // namespace
}  // namespace mlfuzzz3::composition
