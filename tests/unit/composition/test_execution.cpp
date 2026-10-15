// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <stop_token>
#include <thread>

#include "execution.h"
#include "i2s_stage.h"
#include "rng.h"
namespace mlfuzzz3::core {
namespace {
class Backend final : public ExecutionBackend {
   public:
    ExecutionResult execute(std::span<const std::uint8_t>, RunPurpose) override {
        ++calls;
        return {.status = ExecutionStatus::kOk,
                .run_id = calls,
                .comparisons = {{0, 0, 8, 0x11, 0x42}},
                .comparisons_available = available,
                .comparisons_complete = complete,
                .diagnostic = ""};
    }
    Capabilities capabilities() const override {
        return {.comparisons = true};
    }
    std::uint64_t calls = 0;
    bool available = true;
    bool complete = true;
};
TEST(ExecutionService, AccountsAndDispatchesEveryRealRunWithinBudget) {
    Backend backend;
    unsigned dispatched = 0;
    ExecutionService service(backend, {.max_execs = 1, .max_seconds = 0},
                             [&](const auto& result, auto, auto purpose) {
                                 ++dispatched;
                                 EXPECT_EQ(result.decision_id, 77U);
                                 EXPECT_EQ(purpose, RunPurpose::kComparisons);
                             });
    auto first = service.execute({}, RunPurpose::kComparisons, 77);
    ASSERT_TRUE(first);
    EXPECT_FALSE(service.execute({}, RunPurpose::kCandidate, 77));
    EXPECT_EQ(backend.calls, 1U);
    EXPECT_EQ(dispatched, 1U);
    EXPECT_EQ(service.executions(), 1U);
}
TEST(ExecutionService, ResultsOwnIndependentObservationSnapshots) {
    Backend backend;
    ExecutionService service(backend, {.max_execs = 0, .max_seconds = 0}, {});
    auto first = service.execute({}, RunPurpose::kComparisons, 1);
    auto second = service.execute({}, RunPurpose::kComparisons, 2);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    second->comparisons.front().lhs = 0;
    EXPECT_EQ(first->comparisons.front().lhs, 0x11U);
    EXPECT_NE(first->run_id, second->run_id);
}
TEST(ExecutionService, PreCancelledServiceNeverExecutes) {
    Backend backend;
    std::stop_source stop;
    stop.request_stop();
    ExecutionService service(backend, {.max_execs = 0, .max_seconds = 0}, {}, stop.get_token());
    EXPECT_FALSE(service.execute({}, RunPurpose::kSeed, 0));
    EXPECT_EQ(service.solver_timeout(1000), 0U);
    EXPECT_EQ(backend.calls, 0U);
}
TEST(ExecutionService, SolverTimeoutIsCappedByRemainingWallTime) {
    Backend backend;
    ExecutionService service(backend, {.max_execs = 0, .max_seconds = 0.03}, {});
    EXPECT_LE(service.solver_timeout(1000), 30U);
    std::this_thread::sleep_for(std::chrono::milliseconds(35));
    EXPECT_EQ(service.solver_timeout(1000), 0U);
    EXPECT_FALSE(service.execute({}, RunPurpose::kCandidate, 0));
}
#ifdef MLFUZZZ3_WITH_I2S
TEST(I2sStage, ProducesConcreteCandidateWithoutSolver) {
    Backend backend;
    ExecutionService service(backend, {.max_execs = 2, .max_seconds = 0}, {});
    auto stage = composition::make_i2s_stage(false);
    auto rng = mutation::make_rng(1);
    const std::array<std::uint8_t, 1> seed{0x11};
    const auto result = stage->generate({.seed = seed, .decision_id = 3}, service, rng);
    ASSERT_EQ(result.outcome, StageOutcome::kCandidate);
    ASSERT_TRUE(result.candidate);
    EXPECT_EQ(result.candidate->data()[0], 0x42);
    EXPECT_EQ(backend.calls, 1U);
}
TEST(I2sStage, MissingObservationsCannotBeOptedInAsPartial) {
    Backend backend;
    backend.available = false;
    ExecutionService service(backend, {.max_execs = 2, .max_seconds = 0}, {});
    auto stage = composition::make_i2s_stage(true);
    auto rng = mutation::make_rng(1);
    const std::array<std::uint8_t, 1> seed{0x11};
    EXPECT_EQ(stage->generate({.seed = seed}, service, rng).outcome, StageOutcome::kNotApplicable);
}
TEST(I2sStage, IncompleteTraceRequiresExplicitOptIn) {
    Backend backend;
    backend.complete = false;
    ExecutionService service(backend, {.max_execs = 4, .max_seconds = 0}, {});
    auto rng = mutation::make_rng(1);
    const std::array<std::uint8_t, 1> seed{0x11};
    auto strict = composition::make_i2s_stage(false);
    EXPECT_EQ(strict->generate({.seed = seed}, service, rng).outcome, StageOutcome::kNotApplicable);
    auto partial = composition::make_i2s_stage(true);
    EXPECT_EQ(partial->generate({.seed = seed}, service, rng).outcome, StageOutcome::kCandidate);
}
#endif
}  // namespace
}  // namespace mlfuzzz3::core
