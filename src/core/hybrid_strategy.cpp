// SPDX-License-Identifier: MIT
#include "hybrid_strategy.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>
namespace mlfuzzz3::core {
namespace {
constexpr std::size_t kLargeInputThreshold = 64;
constexpr std::uint64_t kMaskDecisions = 64;
CampaignConfig mutation_base(CampaignConfig config) {
    config.concolic_enabled = false;
    return config;
}
constexpr unsigned kShortSolveMs = 10;
constexpr unsigned kMediumSolveMs = 100;
constexpr std::array<unsigned, 4> kSolverBudgets{1, kShortSolveMs, kMediumSolveMs,
                                                 kDefaultConcolicTimeoutMs};
Decision with_arm(Decision decision, std::size_t arm) {
    decision.action_index = arm;
    decision.max_executions = arm == 0 ? 1 : 2;
    decision.stage = arm == 0 ? StageKind::kMutation : StageKind::kI2s;
    if (arm >= 2) {
        decision.stage = StageKind::kI2sSmt;
        decision.timeout_ms = kSolverBudgets.at(arm - 2);
    }
    return decision;
}
}  // namespace
HybridStrategyPolicy::HybridStrategyPolicy(SeedScheduler& scheduler, CampaignConfig config,
                                           HybridOptions options,
                                           std::unique_ptr<AdaptiveBudget> budget)
    : LegacyStrategyPolicy(scheduler, mutation_base(config)),
      budget_(std::move(budget)),
      policy_rng_(mutation::make_rng(config.rng_seed)),
      learned_(options.learned),
      has_solver_(options.has_solver),
      epsilon_(options.epsilon),
      learning_rate_(options.learning_rate) {}
Decision HybridStrategyPolicy::choose(const DecisionContext& context, CampaignStats& stats) {
    const auto& corpus = context.corpus;
    auto decision = LegacyStrategyPolicy::choose(context, stats);
    if (decision.stage == StageKind::kDeterministic) {
        return decision;
    }
    const auto& history = history_[decision.seed_index];
    const auto interval =
        std::max(config().concolic_min_exec_interval, budget_ ? budget_->interval() : 0);
    const bool can_prepare =
        !context.budget.remaining_execs || *context.budget.remaining_execs >= 2;
    const bool solver_allowed = can_prepare && has_solver_ &&
                                decision.id >= history.solver_mask_until &&
                                (!solved_ || stats.execs - last_solver_exec_ >= interval);
    const bool i2s_allowed = can_prepare && decision.id >= history.i2s_mask_until;
    context_ = (corpus.at(decision.seed_index).byte_size >= kLargeInputThreshold ? 2 : 0) +
               (history.stagnation >= config().concolic_stagnation_threshold ? 1 : 0);
    decision.context_bin = context_;
    if (!learned_) {
        if (history.stagnation < config().concolic_stagnation_threshold) {
            return decision;
        }
        if (i2s_allowed && !history.tried_i2s) {
            decision.stage = StageKind::kI2s;
            decision.max_executions = 2;
        } else if (solver_allowed) {
            decision.stage = StageKind::kI2sSmt;
            decision.max_executions = 2;
        }
        return decision;
    }
    std::vector<std::size_t> available{0};
    if (i2s_allowed) {
        available.push_back(1);
    }
    if (solver_allowed) {
        for (std::size_t arm = 2; arm < kHybridArmCount; ++arm) {
            if (kSolverBudgets.at(arm - 2) <= config().concolic_timeout_ms) {
                available.push_back(arm);
            }
        }
    }
    return choose_learned(decision, available);
}
Decision HybridStrategyPolicy::choose_learned(Decision decision,
                                              const std::vector<std::size_t>& available) {
    auto& arms = arms_.at(context_);
    for (const auto arm : available) {
        if (arms.at(arm).samples == 0) {
            return with_arm(decision, arm);
        }
    }
    std::uniform_real_distribution<double> explore(0, 1);
    std::size_t selected = available.front();
    if (explore(policy_rng_) < epsilon_) {
        selected = available.at(mutation::rng_next_index(policy_rng_, available.size()));
    } else {
        for (const auto arm : available) {
            if (arms.at(arm).value > arms.at(selected).value) {
                selected = arm;
            }
        }
    }
    return with_arm(decision, selected);
}
void HybridStrategyPolicy::observe(const Decision& decision, const StageResult& result,
                                   const DecisionFeedback& feedback, CampaignStats& stats) {
    notify_seed(decision, feedback);
    if (decision.stage == StageKind::kDeterministic) {
        return;
    }
    auto& history = history_[decision.seed_index];
    if (learned_) {
        auto& arm = arms_.at(decision.context_bin).at(decision.action_index);
        const double reward = static_cast<double>(feedback.new_edges + (4 * feedback.findings)) /
                              static_cast<double>(std::max<std::uint64_t>(1, feedback.execs));
        arm.value += learning_rate_ * (reward - arm.value);
        ++arm.samples;
    }
    if (feedback.new_edges > 0) {
        history.stagnation = 0;
        history.tried_i2s = false;
    } else if (decision.stage == StageKind::kMutation &&
               history.stagnation != std::numeric_limits<std::uint64_t>::max()) {
        ++history.stagnation;
        if (!has_solver_ && history.tried_i2s) {
            history.tried_i2s = false;
            history.stagnation = 0;
        }
    }
    if (decision.stage == StageKind::kI2s) {
        history.tried_i2s = true;
        if (result.outcome == StageOutcome::kNoBinding ||
            result.outcome == StageOutcome::kNotApplicable) {
            history.i2s_mask_until = decision.id + kMaskDecisions;
        }
    }
    if (decision.stage == StageKind::kI2sSmt) {
        if (budget_) {
            budget_->observe(result.outcome);
        }
        last_solver_exec_ = stats.execs;
        solved_ = true;
        history.stagnation = 0;
        history.tried_i2s = false;
        if (result.outcome == StageOutcome::kNoBinding) {
            history.solver_mask_until = decision.id + kMaskDecisions;
        }
    }
    stats.concolic_throttle_engagements = budget_ ? budget_->engagements() : 0;
}
}  // namespace mlfuzzz3::core
