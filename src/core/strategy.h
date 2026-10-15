// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <utility>

#include "campaign_types.h"
#include "corpus.h"
#include "seed_scheduler.h"
#include "stage.h"
namespace mlfuzzz3::core {
struct DecisionContext {
    DecisionContext(CorpusView corpus_view, BudgetView remaining_budget)
        : corpus(corpus_view), budget(remaining_budget) {}
    CorpusView corpus;
    BudgetView budget;
};
struct Decision {
    std::uint64_t id = 0;
    std::size_t seed_index = 0;
    StageKind stage = StageKind::kMutation;
    std::uint64_t max_executions = 1;
    unsigned timeout_ms = kDefaultConcolicTimeoutMs;
    std::size_t action_index = 0;
    std::size_t context_bin = 0;
};
struct DecisionFeedback {
    std::uint64_t execs = 0;
    std::uint64_t new_edges = 0;
    std::uint64_t successful_edges = 0;
    std::uint64_t findings = 0;
    double wall_seconds = 0;
    double process_cpu_seconds = 0;
};
class StrategyPolicy {
   public:
    StrategyPolicy() = default;
    StrategyPolicy(const StrategyPolicy&) = delete;
    StrategyPolicy& operator=(const StrategyPolicy&) = delete;
    StrategyPolicy(StrategyPolicy&&) = delete;
    StrategyPolicy& operator=(StrategyPolicy&&) = delete;
    virtual ~StrategyPolicy() = default;
    virtual Decision choose(const DecisionContext& context, CampaignStats& stats) = 0;
    virtual void observe(const Decision& decision, const StageResult& result,
                         const DecisionFeedback& feedback, CampaignStats& stats) = 0;
};
class LegacyStrategyPolicy : public StrategyPolicy {
   public:
    LegacyStrategyPolicy(SeedScheduler& scheduler, CampaignConfig config,
                         std::unique_ptr<AdaptiveBudget> adaptive = nullptr);
    Decision choose(const DecisionContext& context, CampaignStats& stats) override;
    void observe(const Decision& decision, const StageResult& result,
                 const DecisionFeedback& feedback, CampaignStats& stats) override;

   protected:
    void notify_seed(const Decision& decision, const DecisionFeedback& feedback);
    [[nodiscard]] std::optional<std::size_t> deterministic_seed(const CorpusView& corpus);
    [[nodiscard]] const CampaignConfig& config() const {
        return config_;
    }

   private:
    SeedScheduler* scheduler_;
    CampaignConfig config_;
    std::unique_ptr<AdaptiveBudget> adaptive_;
    std::unordered_map<std::size_t, std::uint32_t> stagnation_;
    std::size_t frontier_ = 0;
    std::uint64_t next_decision_ = 0;
    std::uint64_t last_solve_exec_ = 0;
    bool solved_ = false;
};
}  // namespace mlfuzzz3::core
