// SPDX-License-Identifier: MIT
#include "campaign_factory.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "deterministic_stage.h"
#include "execution_adapter.h"
#include "hybrid_strategy.h"
#include "i2s_stage.h"
#ifdef MLFUZZZ3_WITH_CONCOLIC
#include "solver_stage.h"
#endif
namespace mlfuzzz3::composition {
namespace {
class DeterministicStage final : public core::Stage {
   public:
    explicit DeterministicStage(std::uint64_t cap) : cap_(cap) {}
    [[nodiscard]] std::string_view name() const override {
        return "deterministic";
    }
    [[nodiscard]] core::StageKind kind() const override {
        return core::StageKind::kDeterministic;
    }
    core::StageResult generate(const core::StageContext& context, core::ExecutionService& execution,
                               std::mt19937_64& /*rng*/) override {
        if (execution.exhausted()) {
            return {.outcome = core::StageOutcome::kCancelled};
        }
        const mutation::FuzzInput copy =
            context.original != nullptr
                ? mutation::FuzzInput{}
                : mutation::FuzzInput(context.seed.data(), context.seed.size());
        const auto& input = context.original != nullptr ? *context.original : copy;
        const auto length = std::min(mutation::DeterministicStage::length(input), cap_);
        if (context.cursor >= length) {
            return {.outcome = core::StageOutcome::kExhausted};
        }
        return {.outcome = core::StageOutcome::kCandidate,
                .candidate = mutation::DeterministicStage::apply(input, context.cursor),
                .progress = core::DetState{.phase = context.cursor + 1 >= length
                                                        ? core::SeedPhase::kHavoc
                                                        : core::SeedPhase::kDeterministic,
                                           .cursor = context.cursor + 1}};
    }

   private:
    std::uint64_t cap_;
};
class MutationStage final : public core::Stage {
   public:
    explicit MutationStage(const mutation::Mutator& mutator) : mutator_(&mutator) {}
    [[nodiscard]] std::string_view name() const override {
        return "mutation";
    }
    [[nodiscard]] core::StageKind kind() const override {
        return core::StageKind::kMutation;
    }
    core::StageResult generate(const core::StageContext& context, core::ExecutionService& execution,
                               std::mt19937_64& rng) override {
        if (execution.exhausted()) {
            return {.outcome = core::StageOutcome::kCancelled};
        }
        const mutation::FuzzInput copy =
            context.original != nullptr
                ? mutation::FuzzInput{}
                : mutation::FuzzInput(context.seed.data(), context.seed.size());
        const auto& input = context.original != nullptr ? *context.original : copy;
        return {.outcome = core::StageOutcome::kCandidate,
                .candidate = mutator_->mutate(input, rng)};
    }

   private:
    const mutation::Mutator* mutator_;
};
}  // namespace
core::CampaignParts make_campaign(core::Runner& runner, const mutation::Mutator& mutator,
                                  core::SeedScheduler& scheduler,
                                  const CompositionConfig& resolved) {
    validate_composition(resolved);
    auto config = resolved.campaign;
    config.allow_incomplete_comparisons = resolved.smt_allow_incomplete;
    core::CampaignParts parts;
    parts.backend = std::make_unique<RunnerBackend>(runner);
    bool solver = false;
    bool deterministic = false;
    for (const auto& stage : resolved.stages) {
        if (stage == "deterministic") {
            parts.stages.push_back(std::make_unique<DeterministicStage>(config.max_det_steps));
            deterministic = true;
        } else if (stage == "mutation") {
            parts.stages.push_back(std::make_unique<MutationStage>(mutator));
        }
#ifdef MLFUZZZ3_WITH_I2S
        else if (stage == "i2s") {
            parts.stages.push_back(make_i2s_stage(resolved.i2s_allow_incomplete));
        }
#endif
#ifdef MLFUZZZ3_WITH_CONCOLIC
        else if (stage == "i2s_smt") {
            parts.stages.push_back(make_solver_stage(config));
            solver = true;
        }
#endif
    }
    if (!deterministic) {
        config.max_det_steps = 0;
    }
    config.concolic_enabled = solver && config.concolic_enabled;
    std::unique_ptr<core::AdaptiveBudget> adaptive;
#ifdef MLFUZZZ3_WITH_CONCOLIC
    if (solver) {
        adaptive = make_solver_budget(config.concolic_adaptive_throttle);
    }
#endif
    if (resolved.strategy == "legacy") {
        parts.strategy =
            std::make_unique<core::LegacyStrategyPolicy>(scheduler, config, std::move(adaptive));
    } else {
        parts.strategy = std::make_unique<core::HybridStrategyPolicy>(
            scheduler, config,
            core::HybridOptions{.learned = resolved.strategy == "contextual_bandit",
                                .has_solver = solver,
                                .epsilon = resolved.epsilon,
                                .learning_rate = resolved.learning_rate},
            std::move(adaptive));
    }
    parts.admission = std::make_unique<core::CoverageAdmission>();
    parts.objective = std::make_unique<core::StatusObjective>();
    return parts;
}
core::CampaignParts make_legacy_campaign(core::Runner& runner, const mutation::Mutator& mutator,
                                         core::SeedScheduler& scheduler,
                                         core::CampaignConfig config) {
    auto resolved = parse_composition("");
    resolved.campaign = config;
    resolved.components.seed = config.rng_seed;
    if (!config.concolic_enabled || !solver_stage_available()) {
        std::erase(resolved.stages, "i2s_smt");
        resolved.campaign.concolic_enabled = false;
    }
    return make_campaign(runner, mutator, scheduler, resolved);
}
}  // namespace mlfuzzz3::composition
namespace mlfuzzz3::core {
CampaignLoop::CampaignLoop(Runner& runner, const mutation::Mutator& mutator,
                           SeedScheduler& scheduler, Corpus& corpus, MetricsEmitter& metrics,
                           const CampaignConfig& config)
    : CampaignLoop(composition::make_legacy_campaign(runner, mutator, scheduler, config), corpus,
                   metrics, config) {}
}  // namespace mlfuzzz3::core
