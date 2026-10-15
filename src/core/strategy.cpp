// SPDX-License-Identifier: MIT
#include "strategy.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "deterministic_stage.h"
namespace mlfuzzz3::core {
LegacyStrategyPolicy::LegacyStrategyPolicy(SeedScheduler& scheduler, CampaignConfig config,
                                           std::unique_ptr<AdaptiveBudget> adaptive)
    : scheduler_(&scheduler), config_(config), adaptive_(std::move(adaptive)) {}
std::optional<std::size_t> LegacyStrategyPolicy::deterministic_seed(const CorpusView& corpus) {
    while (frontier_ < corpus.size()) {
        const auto& entry = corpus.at(frontier_);
        if (entry.det.phase == SeedPhase::kDeterministic &&
            entry.det.cursor < std::min(entry.deterministic_length, config_.max_det_steps)) {
            return frontier_;
        }
        ++frontier_;
    }
    return std::nullopt;
}
Decision LegacyStrategyPolicy::choose(const DecisionContext& context, CampaignStats& stats) {
    const auto& corpus = context.corpus;
    Decision decision{.id = ++next_decision_, .timeout_ms = config_.concolic_timeout_ms};
    if (auto index = deterministic_seed(corpus)) {
        decision.seed_index = *index;
        decision.stage = StageKind::kDeterministic;
        return decision;
    }
    decision.seed_index = scheduler_->choose(corpus);
    if (!config_.concolic_enabled ||
        stagnation_[decision.seed_index] < config_.concolic_stagnation_threshold) {
        return decision;
    }
    const auto adaptive_interval = adaptive_ ? adaptive_->interval() : 0;
    const auto interval = std::max(config_.concolic_min_exec_interval, adaptive_interval);
    stats.concolic_throttle_engagements = adaptive_ ? adaptive_->engagements() : 0;
    if (interval != 0 && solved_ && stats.execs - last_solve_exec_ < interval) {
        ++stats.concolic_budget_skips;
        if (stats.execs - last_solve_exec_ >= config_.concolic_min_exec_interval) {
            ++stats.concolic_throttle_skips;
        }
        return decision;
    }
    decision.stage = StageKind::kI2sSmt;
    decision.max_executions = 2;
    return decision;
}
void LegacyStrategyPolicy::notify_seed(const Decision& decision, const DecisionFeedback& feedback) {
    scheduler_->on_result(
        decision.seed_index,
        {.execs = feedback.execs, .new_edges = feedback.new_edges, .findings = feedback.findings});
}
void LegacyStrategyPolicy::observe(const Decision& decision, const StageResult& result,
                                   const DecisionFeedback& feedback, CampaignStats& stats) {
    notify_seed(decision, feedback);
    if (decision.stage == StageKind::kI2sSmt) {
        if (adaptive_) {
            adaptive_->observe(result.outcome);
        }
        stats.concolic_throttle_engagements = adaptive_ ? adaptive_->engagements() : 0;
        last_solve_exec_ = stats.execs;
        solved_ = true;
        stagnation_[decision.seed_index] = 0;
    } else if (decision.stage == StageKind::kMutation) {
        auto& value = stagnation_[decision.seed_index];
        if (feedback.successful_edges > 0) {
            value = 0;
        } else if (value < std::numeric_limits<std::uint32_t>::max()) {
            ++value;
        }
    }
}
}  // namespace mlfuzzz3::core
