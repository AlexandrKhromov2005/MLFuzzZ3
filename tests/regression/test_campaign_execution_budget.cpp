// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include "campaign.h"
#include "fake_runner.h"
#include "mutators/byte_flip.h"
namespace mlfuzzz3::core {
TEST(CampaignBudgetRegression, NoCandidateExecutionAfterPreparationConsumesLastSlot) {
    const auto base = std::filesystem::path(::testing::TempDir()) / "campaign_strict_budget";
    std::filesystem::remove_all(base);
    auto corpus = Corpus::Create(base);
    ASSERT_TRUE(corpus);
    const std::vector<std::uint8_t> bytes{0, 0, 0, 0x20, 0, 0, 0, 0x30};
    ASSERT_TRUE(corpus->Add(mutation::FuzzInput(bytes), 0));
    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "budget-regression");
    ASSERT_TRUE(metrics);
    testing::FakeRunner runner;
    runner.set_branch_records({{0, 4, 32, 0x20000000, 0x10000000},
                               {1, 4, 32, 0x30000000, 0x10000000},
                               {2, 2, 32, 0x20000000, 0x30000000},
                               {3, 0, 32, 0x50000000, 5}});
    runner.set_script({testing::FakeRunner::MakeOk(0),
                       testing::FakeRunner::MakeStatus(ipc::v1::EXEC_STATUS_CRASH)});
    mutation::ByteFlipMutator mutator;
    RandomScheduler scheduler(1);
    CampaignConfig config;
    config.max_iterations = 1;
    config.max_det_steps = 0;
    config.concolic_stagnation_threshold = 0;
    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, config);
    const auto stats = loop.Run();
    EXPECT_EQ(stats.execs, 1U);
    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.crashes, 0U);
    EXPECT_EQ(runner.last_input(), bytes);
    std::filesystem::remove_all(base);
}
TEST(CampaignBudgetRegression, LegacyFailedPreparationKeepsMissingBindingCounters) {
    const auto base = std::filesystem::path(::testing::TempDir()) / "campaign_missing_preparation";
    std::filesystem::remove_all(base);
    auto corpus = Corpus::Create(base);
    ASSERT_TRUE(corpus);
    ASSERT_TRUE(corpus->Add(mutation::FuzzInput(std::vector<std::uint8_t>{1}), 0));
    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "missing-preparation");
    ASSERT_TRUE(metrics);
    testing::FakeRunner runner;
    runner.set_script({testing::FakeRunner::MakeTransportError()});
    mutation::ByteFlipMutator mutator;
    RandomScheduler scheduler(1);
    CampaignConfig config;
    config.max_iterations = 1;
    config.max_det_steps = 0;
    config.concolic_stagnation_threshold = 0;
    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, config);
    const auto stats = loop.Run();
    EXPECT_EQ(stats.execs, 1U);
    EXPECT_EQ(stats.ipc_errors, 1U);
    EXPECT_EQ(stats.concolic_calls, 1U);
    EXPECT_EQ(stats.concolic_no_binding, 1U);
    EXPECT_EQ(stats.concolic_candidates, 0U);
    std::filesystem::remove_all(base);
}
}  // namespace mlfuzzz3::core
