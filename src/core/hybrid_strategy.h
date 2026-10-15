// SPDX-License-Identifier: MIT
#pragma once
#include <array>
#include <random>
#include <unordered_map>
#include <vector>

#include "strategy.h"
namespace mlfuzzz3::core {
// A contextual epsilon-greedy controller. It learns only from real execution feedback.
inline constexpr std::size_t kHybridArmCount = 6;
struct HybridOptions {
    bool learned = false;
    bool has_solver = false;
    double epsilon = 0;
    double learning_rate = 1;
};
class HybridStrategyPolicy final : public LegacyStrategyPolicy {
   public:
    HybridStrategyPolicy(SeedScheduler& scheduler, CampaignConfig config, HybridOptions options,
                         std::unique_ptr<AdaptiveBudget> budget);
    Decision choose(const DecisionContext& context, CampaignStats& stats) override;
    void observe(const Decision& decision, const StageResult& result,
                 const DecisionFeedback& feedback, CampaignStats& stats) override;

   private:
    Decision choose_learned(Decision decision, const std::vector<std::size_t>& available);
    struct History {
        std::uint64_t stagnation = 0;
        bool tried_i2s = false;
        std::uint64_t i2s_mask_until = 0;
        std::uint64_t solver_mask_until = 0;
    };
    struct Arm {
        double value = 0;
        std::uint64_t samples = 0;
    };
    std::array<std::array<Arm, kHybridArmCount>, 4> arms_{};
    std::unordered_map<std::size_t, History> history_;
    std::unique_ptr<AdaptiveBudget> budget_;
    std::mt19937_64 policy_rng_;
    bool learned_;
    bool has_solver_;
    double epsilon_;
    double learning_rate_;
    std::size_t context_ = 0;
    std::uint64_t last_solver_exec_ = 0;
    bool solved_ = false;
};
}  // namespace mlfuzzz3::core
