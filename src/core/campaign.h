// SPDX-License-Identifier: MIT
#pragma once
#include <memory>
#include <vector>

#include "campaign_types.h"
#include "corpus.h"
#include "execution.h"
#include "metrics.h"
#include "mutator.h"
#include "seed_scheduler.h"
#include "stage.h"
#include "strategy.h"
namespace mlfuzzz3::core {
class Runner;
class AdmissionPolicy {
   public:
    AdmissionPolicy() = default;
    AdmissionPolicy(const AdmissionPolicy&) = delete;
    AdmissionPolicy& operator=(const AdmissionPolicy&) = delete;
    AdmissionPolicy(AdmissionPolicy&&) = delete;
    AdmissionPolicy& operator=(AdmissionPolicy&&) = delete;
    virtual ~AdmissionPolicy() = default;
    [[nodiscard]] virtual bool accept(const ExecutionResult& result) const = 0;
};
class CoverageAdmission final : public AdmissionPolicy {
   public:
    [[nodiscard]] bool accept(const ExecutionResult& result) const override {
        return result.status == ExecutionStatus::kOk && result.new_edges > 0;
    }
};
enum class Finding { kNone, kCrash, kHang };
class Objective {
   public:
    Objective() = default;
    Objective(const Objective&) = delete;
    Objective& operator=(const Objective&) = delete;
    Objective(Objective&&) = delete;
    Objective& operator=(Objective&&) = delete;
    virtual ~Objective() = default;
    [[nodiscard]] virtual Finding classify(const ExecutionResult& result) const = 0;
};
class StatusObjective final : public Objective {
   public:
    [[nodiscard]] Finding classify(const ExecutionResult& result) const override;
};
class EventSink {
   public:
    EventSink() = default;
    EventSink(const EventSink&) = delete;
    EventSink& operator=(const EventSink&) = delete;
    EventSink(EventSink&&) = delete;
    EventSink& operator=(EventSink&&) = delete;
    virtual ~EventSink() = default;
    virtual void on_decision(const Decision& /*decision*/) {}
    virtual void on_execution(const ExecutionResult& /*result*/, RunPurpose /*purpose*/) {}
    virtual void on_outcome(const Decision& /*decision*/, StageOutcome /*outcome*/,
                            const DecisionFeedback& /*feedback*/) {}
};
struct CampaignParts {
    std::unique_ptr<ExecutionBackend> backend;
    std::unique_ptr<StrategyPolicy> strategy;
    std::vector<std::unique_ptr<Stage>> stages;
    std::unique_ptr<AdmissionPolicy> admission;
    std::unique_ptr<Objective> objective;
    std::unique_ptr<EventSink> events;
};
// The loop owns domain collaborators; it has no transport or solver dependency.
class CampaignLoop {
   public:
    CampaignLoop(CampaignParts parts, Corpus& corpus, MetricsEmitter& metrics,
                 const CampaignConfig& config);
    // Compatibility assembly is defined in composition, never in core.
    CampaignLoop(Runner& runner, const mutation::Mutator& mutator, SeedScheduler& scheduler,
                 Corpus& corpus, MetricsEmitter& metrics, const CampaignConfig& config);
    CampaignLoop(const CampaignLoop&) = delete;
    CampaignLoop& operator=(const CampaignLoop&) = delete;
    CampaignLoop(CampaignLoop&&) = delete;
    CampaignLoop& operator=(CampaignLoop&&) = delete;
    ~CampaignLoop() = default;
    CampaignStats Run(std::stop_token stop = {});

   private:
    void handle_result(const ExecutionResult& result, std::span<const std::uint8_t> input,
                       RunPurpose purpose, CampaignStats& stats);
    [[nodiscard]] bool AccountInfraError(bool errored, CampaignStats& stats);
    void EmitMetrics(const CampaignStats& stats, double elapsed_seconds);
    void EmitMetricsIfDue(const CampaignStats& stats, double elapsed_seconds);
    static void account_stage(const StageResult& result, CampaignStats& stats);
    void run_candidate(const Decision& decision, StageResult& result, ExecutionService& execution,
                       CampaignStats& stats);
    void run_decision(const Decision& decision, ExecutionService& execution, CampaignStats& stats);
    CampaignParts parts_;
    Corpus* corpus_;
    MetricsEmitter* metrics_;
    CampaignConfig cfg_;
    std::mt19937_64 rng_;
    std::uint64_t consecutive_errors_ = 0;
    bool decision_error_ = false;
    std::uint64_t decision_observed_edges_ = 0;
};
}  // namespace mlfuzzz3::core
