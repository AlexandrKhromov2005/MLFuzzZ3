// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <vector>

#include "campaign.h"
namespace mlfuzzz3::core {
namespace {
class DomainBackend final : public ExecutionBackend {
   public:
    explicit DomainBackend(ExecutionStatus status) : status_(status) {}
    ExecutionResult execute(std::span<const std::uint8_t>, RunPurpose) override {
        ExecutionResult result;
        result.status = status_;
        result.new_edges = 1;
        return result;
    }
    Capabilities capabilities() const override {
        return {};
    }

   private:
    ExecutionStatus status_;
};
class FixedStage final : public Stage {
   public:
    explicit FixedStage(StageKind kind, bool comparisons = false)
        : kind_(kind), comparisons_(comparisons) {}
    std::string_view name() const override {
        return "fixed";
    }
    StageKind kind() const override {
        return kind_;
    }
    Capabilities required() const override {
        return {.comparisons = comparisons_};
    }
    StageResult generate(const StageContext& context, ExecutionService&,
                         std::mt19937_64&) override {
        return {.outcome = StageOutcome::kCandidate,
                .candidate = mutation::FuzzInput(context.seed.data(), context.seed.size())};
    }

   private:
    StageKind kind_;
    bool comparisons_;
};
class FixedPolicy final : public StrategyPolicy {
   public:
    explicit FixedPolicy(StageKind kind) : kind_(kind) {}
    Decision choose(const DecisionContext&, CampaignStats&) override {
        return {.id = 1, .stage = kind_};
    }
    void observe(const Decision&, const StageResult&, const DecisionFeedback&,
                 CampaignStats&) override {}

   private:
    StageKind kind_;
};
class RejectAll final : public AdmissionPolicy {
   public:
    bool accept(const ExecutionResult&) const override {
        return false;
    }
};
TEST(DomainCampaign, FindingsFromEveryStageAreIndependentOfAdmissionAndSolverLinkage) {
    const auto base = std::filesystem::path(::testing::TempDir()) / "domain_campaign_findings";
    for (const auto kind :
         {StageKind::kDeterministic, StageKind::kMutation, StageKind::kI2s, StageKind::kI2sSmt}) {
        for (const auto status : {ExecutionStatus::kCrash, ExecutionStatus::kHang}) {
            std::filesystem::remove_all(base);
            auto corpus = Corpus::Create(base);
            ASSERT_TRUE(corpus);
            ASSERT_TRUE(corpus->Bootstrap({}));
            auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "domain-test");
            ASSERT_TRUE(metrics);
            CampaignParts parts;
            parts.backend = std::make_unique<DomainBackend>(status);
            parts.strategy = std::make_unique<FixedPolicy>(kind);
            parts.stages.push_back(std::make_unique<FixedStage>(kind));
            parts.admission = std::make_unique<RejectAll>();
            parts.objective = std::make_unique<StatusObjective>();
            CampaignConfig config;
            config.max_iterations = 1;
            CampaignLoop loop(std::move(parts), *corpus, *metrics, config);
            const auto stats = loop.Run();
            EXPECT_EQ(stats.execs, 1U);
            EXPECT_EQ(stats.accepted, 0U);
            EXPECT_EQ(stats.crashes, status == ExecutionStatus::kCrash ? 1U : 0U);
            EXPECT_EQ(stats.hangs, status == ExecutionStatus::kHang ? 1U : 0U);
        }
    }
    std::filesystem::remove_all(base);
}
TEST(DomainCampaign, MissingRequiredCapabilityFailsBeforeExecution) {
    const auto base = std::filesystem::path(::testing::TempDir()) / "domain_campaign_capability";
    std::filesystem::remove_all(base);
    auto corpus = Corpus::Create(base);
    ASSERT_TRUE(corpus);
    ASSERT_TRUE(corpus->Bootstrap({}));
    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "caps-test");
    ASSERT_TRUE(metrics);
    CampaignParts parts;
    parts.backend = std::make_unique<DomainBackend>(ExecutionStatus::kOk);
    parts.strategy = std::make_unique<FixedPolicy>(StageKind::kI2s);
    parts.stages.push_back(std::make_unique<FixedStage>(StageKind::kI2s, true));
    parts.admission = std::make_unique<RejectAll>();
    parts.objective = std::make_unique<StatusObjective>();
    EXPECT_THROW((void)CampaignLoop(std::move(parts), *corpus, *metrics, CampaignConfig{}),
                 std::invalid_argument);
    std::filesystem::remove_all(base);
}
}  // namespace
}  // namespace mlfuzzz3::core
