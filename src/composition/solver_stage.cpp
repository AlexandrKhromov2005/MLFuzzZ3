// SPDX-License-Identifier: MIT
#include "solver_stage.h"

#include <algorithm>
#include <chrono>
#include <vector>

#include "concolic.h"
#include "throttle.h"
namespace mlfuzzz3::composition {
namespace {
core::StageOutcome to_stage(concolic::SolveOutcome outcome) {
    switch (outcome) {
        case concolic::SolveOutcome::kCandidate:
            return core::StageOutcome::kCandidate;
        case concolic::SolveOutcome::kNoBinding:
            return core::StageOutcome::kNoBinding;
        case concolic::SolveOutcome::kUnsat:
            return core::StageOutcome::kUnsat;
        case concolic::SolveOutcome::kTimeout:
            return core::StageOutcome::kTimeout;
        default:
            return core::StageOutcome::kSolverError;
    }
}
std::vector<coverage::BranchReader::Record> copy_comparisons(const core::ExecutionResult& result) {
    std::vector<coverage::BranchReader::Record> records;
    if (!result.comparisons_available) {
        return records;
    }
    records.reserve(result.comparisons.size());
    for (const auto& record : result.comparisons) {
        records.push_back(
            {record.site_id, record.predicate, record.bit_width, record.lhs, record.rhs});
    }
    return records;
}
class SolverStage final : public core::Stage {
   public:
    explicit SolverStage(const core::CampaignConfig& config)
        : allow_partial_(config.allow_incomplete_comparisons), legacy_(config.legacy_preparation) {
        fixes_.findfirst_index = config.concolic_fix_findfirst_index;
        fixes_.strict_addvars = config.concolic_fix_addvars;
        fixes_.no_truncation = config.concolic_fix_writeback_width;
        if (config.concolic_system_form == 1) {
            fixes_.form = concolic::Fixes::Form::kPrefix;
        } else if (config.concolic_system_form == 2) {
            fixes_.form = concolic::Fixes::Form::kOptimistic;
        }
    }
    [[nodiscard]] std::string_view name() const override {
        return "i2s_smt";
    }
    [[nodiscard]] core::StageKind kind() const override {
        return core::StageKind::kI2sSmt;
    }
    [[nodiscard]] core::Capabilities required() const override {
        return {.comparisons = true};
    }
    core::StageResult generate(const core::StageContext& context, core::ExecutionService& execution,
                               std::mt19937_64& /*rng*/) override {
        using Clock = std::chrono::steady_clock;
        core::StageResult result;
        const auto start = Clock::now();
        auto seed =
            execution.execute(context.seed, core::RunPurpose::kComparisons, context.decision_id);
        result.preparation_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count());
        if (!seed) {
            result.outcome = core::StageOutcome::kCancelled;
            return result;
        }
        if (!legacy_ && seed->status != core::ExecutionStatus::kOk) {
            result.outcome = seed->status == core::ExecutionStatus::kInfrastructureError
                                 ? core::StageOutcome::kInfrastructureError
                                 : core::StageOutcome::kNotApplicable;
            return result;
        }
        if (trace_unusable(*seed)) {
            result.outcome = core::StageOutcome::kNotApplicable;
            return result;
        }
        const auto timeout = execution.solver_timeout(context.timeout_ms);
        if (timeout == 0) {
            result.outcome = core::StageOutcome::kCancelled;
            return result;
        }
        const auto records = copy_comparisons(*seed);
        concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
        auto fixes = fixes_;
        const auto deadline = Clock::now() + std::chrono::milliseconds(context.timeout_ms);
        fixes.remaining_timeout = [&execution, timeout = context.timeout_ms, deadline,
                                   legacy = legacy_]() {
            auto remaining = execution.solver_timeout(timeout);
            if (!legacy) {
                const auto local =
                    std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
                if (local <= 0) {
                    return 0U;
                }
                remaining = std::min(remaining, static_cast<unsigned>(local));
            }
            return remaining;
        };
        fixes.cancelled = [remaining = fixes.remaining_timeout]() { return remaining() == 0; };
        const auto solve_start = Clock::now();
        result.solver_called = true;
        result.candidate = concolic::SolveForCandidate(
            context.seed, records, timeout, &outcome, fixes,
            {.build_us = &result.build_us, .solve_us = &result.solve_us});
        result.solve_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - solve_start)
                .count());
        result.outcome = to_stage(outcome);
        result.legacy_width_overflow = legacy_ && outcome == concolic::SolveOutcome::kWidthOverflow;
        if (execution.solver_timeout(context.timeout_ms) == 0) {
            result.outcome = core::StageOutcome::kCancelled;
            result.candidate.reset();
        } else if (fixes.cancelled()) {
            result.outcome = core::StageOutcome::kTimeout;
            result.candidate.reset();
        }
        return result;
    }

   private:
    [[nodiscard]] bool trace_unusable(const core::ExecutionResult& trace) const {
        if (!legacy_ && !trace.comparisons_available) {
            return true;
        }
        return trace.comparisons_available && !allow_partial_ && !trace.comparisons_complete;
    }
    concolic::Fixes fixes_;
    bool allow_partial_;
    bool legacy_;
};
class SolverBudget final : public core::AdaptiveBudget {
   public:
    explicit SolverBudget(bool enabled) : throttle_(concolic::ThrottleConfig{.enabled = enabled}) {}
    void observe(core::StageOutcome outcome) override {
        concolic::SolveOutcome mapped = concolic::SolveOutcome::kNoBinding;
        switch (outcome) {
            case core::StageOutcome::kCandidate:
                mapped = concolic::SolveOutcome::kCandidate;
                break;
            case core::StageOutcome::kUnsat:
                mapped = concolic::SolveOutcome::kUnsat;
                break;
            case core::StageOutcome::kTimeout:
                mapped = concolic::SolveOutcome::kTimeout;
                break;
            case core::StageOutcome::kSolverError:
                mapped = concolic::SolveOutcome::kError;
                break;
            default:
                break;
        }
        throttle_.Observe(mapped);
    }
    [[nodiscard]] std::uint64_t interval() const override {
        return throttle_.CurrentInterval();
    }
    [[nodiscard]] std::uint64_t engagements() const override {
        return throttle_.engagements();
    }

   private:
    concolic::ConcolicThrottle throttle_;
};
}  // namespace
std::unique_ptr<core::Stage> make_solver_stage(const core::CampaignConfig& config) {
    return std::make_unique<SolverStage>(config);
}
std::unique_ptr<core::AdaptiveBudget> make_solver_budget(bool enabled) {
    return std::make_unique<SolverBudget>(enabled);
}
}  // namespace mlfuzzz3::composition
