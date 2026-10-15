// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <filesystem>
#include <vector>

#include "hybrid_strategy.h"
namespace mlfuzzz3::core {
namespace {
TEST(HybridStrategy, LearnedPolicyUsesOnlyRealExecutionReward) {
    const auto base = std::filesystem::path(::testing::TempDir()) / "hybrid_policy_reward";
    std::filesystem::remove_all(base);
    auto corpus = Corpus::Create(base);
    ASSERT_TRUE(corpus);
    ASSERT_TRUE(corpus->Bootstrap({}));
    CampaignConfig config;
    config.max_det_steps = 0;
    config.concolic_stagnation_threshold = 0;
    RandomScheduler scheduler(1);
    HybridStrategyPolicy policy(
        scheduler, config, {.learned = true, .has_solver = true, .epsilon = 0, .learning_rate = 1},
        nullptr);
    CampaignStats stats;
    const CorpusView view(*corpus);
    auto decision = policy.choose({view, {}}, stats);
    EXPECT_EQ(decision.stage, StageKind::kMutation);
    policy.observe(decision, {.outcome = StageOutcome::kCandidate}, {.execs = 1}, stats);
    decision = policy.choose({view, {}}, stats);
    EXPECT_EQ(decision.stage, StageKind::kI2s);
    policy.observe(decision, {.outcome = StageOutcome::kCandidate}, {.execs = 2, .new_edges = 7},
                   stats);
    for (const auto timeout : {1U, 10U, 100U, 1000U}) {
        decision = policy.choose({view, {}}, stats);
        EXPECT_EQ(decision.stage, StageKind::kI2sSmt);
        EXPECT_EQ(decision.timeout_ms, timeout);
        EXPECT_EQ(decision.max_executions, 2U);
        policy.observe(decision, {.outcome = StageOutcome::kCandidate}, {.execs = 2}, stats);
    }
    decision = policy.choose({view, {}}, stats);
    EXPECT_EQ(decision.stage, StageKind::kI2s);
    std::filesystem::remove_all(base);
}
TEST(HybridStrategy, UnavailableSolverIsNeverSelected) {
    const auto base = std::filesystem::path(::testing::TempDir()) / "hybrid_policy_no_solver";
    std::filesystem::remove_all(base);
    auto corpus = Corpus::Create(base);
    ASSERT_TRUE(corpus);
    ASSERT_TRUE(corpus->Bootstrap({}));
    CampaignConfig config;
    config.max_det_steps = 0;
    config.concolic_stagnation_threshold = 0;
    RandomScheduler scheduler(1);
    HybridStrategyPolicy policy(
        scheduler, config, {.learned = true, .has_solver = false, .epsilon = 1, .learning_rate = 1},
        nullptr);
    CampaignStats stats;
    for (unsigned turn = 0; turn < 30; ++turn) {
        auto decision = policy.choose({CorpusView(*corpus), {}}, stats);
        EXPECT_NE(decision.stage, StageKind::kI2sSmt);
        policy.observe(decision, {.outcome = StageOutcome::kCandidate}, {.execs = 1}, stats);
    }
    std::filesystem::remove_all(base);
}
}  // namespace
}  // namespace mlfuzzz3::core
