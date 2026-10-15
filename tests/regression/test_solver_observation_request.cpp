// SPDX-License-Identifier: MIT
// Unavailable observations must never be consumed, even with a retained buffer.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

#include "campaign_types.h"
#include "execution.h"
#include "rng.h"
#include "solver_stage.h"
namespace mlfuzzz3::core {
namespace {
class UnavailableBackend final : public ExecutionBackend {
   public:
    ExecutionResult execute(std::span<const std::uint8_t>, RunPurpose) override {
        return {.status = ExecutionStatus::kOk,
                .comparisons = {{0, 0, 8, 0x11, 0x42}},
                .comparisons_available = false,
                .comparisons_complete = false,
                .diagnostic = ""};
    }
    Capabilities capabilities() const override {
        return {.comparisons = true};
    }
};
StageResult generate_without_observations(bool legacy) {
    UnavailableBackend backend;
    ExecutionService service(backend, {.max_execs = 2, .max_seconds = 0}, {});
    CampaignConfig config;
    config.legacy_preparation = legacy;
    config.allow_incomplete_comparisons = true;
    auto stage = composition::make_solver_stage(config);
    auto rng = mutation::make_rng(1);
    const std::array<std::uint8_t, 1> seed{0x11};
    return stage->generate({.seed = seed}, service, rng);
}
TEST(SolverObservationRegression, LegacyCountsMissingBindingWithoutUsingAnUnavailableBuffer) {
    const auto result = generate_without_observations(true);
    EXPECT_EQ(result.outcome, StageOutcome::kNoBinding);
    EXPECT_TRUE(result.solver_called);
    EXPECT_FALSE(result.candidate);
}
TEST(SolverObservationRegression, NewProfileRejectsMissingObservationsDespitePartialOptIn) {
    const auto result = generate_without_observations(false);
    EXPECT_EQ(result.outcome, StageOutcome::kNotApplicable);
    EXPECT_FALSE(result.solver_called);
    EXPECT_FALSE(result.candidate);
}
}  // namespace
}  // namespace mlfuzzz3::core
