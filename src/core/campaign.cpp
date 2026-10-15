// SPDX-License-Identifier: MIT
#include "campaign.h"

#include <algorithm>
#include <ctime>
#include <stdexcept>
#include <utility>

#include "log.h"
namespace mlfuzzz3::core {
namespace {
constexpr std::uint64_t kMaxConsecutiveErrors = 5;
}
Finding StatusObjective::classify(const ExecutionResult& result) const {
    if (result.status == ExecutionStatus::kCrash) {
        return Finding::kCrash;
    }
    if (result.status == ExecutionStatus::kHang) {
        return Finding::kHang;
    }
    return Finding::kNone;
}
CampaignLoop::CampaignLoop(CampaignParts parts, Corpus& corpus, MetricsEmitter& metrics,
                           const CampaignConfig& config)
    : parts_(std::move(parts)),
      corpus_(&corpus),
      metrics_(&metrics),
      cfg_(config),
      rng_(mutation::make_rng(config.rng_seed)) {
    if (!parts_.backend || !parts_.strategy || !parts_.admission || !parts_.objective ||
        parts_.stages.empty() || corpus.empty()) {
        throw std::invalid_argument("incomplete campaign composition");
    }
    const auto capabilities = parts_.backend->capabilities();
    for (const auto& stage : parts_.stages) {
        if (!stage) {
            throw std::invalid_argument("empty stage");
        }
        const auto required = stage->required();
        const auto stage_name = std::string(stage->name());
        if (required.execution && !capabilities.execution) {
            throw std::invalid_argument(stage_name + " requires execution capability");
        }
        if (required.coverage && !capabilities.coverage) {
            throw std::invalid_argument(stage_name + " requires coverage capability");
        }
        if (required.comparisons && !capabilities.comparisons) {
            throw std::invalid_argument(stage_name + " requires comparisons capability");
        }
    }
}
void CampaignLoop::handle_result(const ExecutionResult& result, std::span<const std::uint8_t> input,
                                 RunPurpose purpose, CampaignStats& stats) {
    ++stats.execs;
    decision_observed_edges_ += result.new_edges;
    if (parts_.events) {
        parts_.events->on_execution(result, purpose);
    }
    if (result.status == ExecutionStatus::kInfrastructureError) {
        decision_error_ = true;
        LOG_WARN("execution infrastructure error: {}", result.diagnostic);
    }
    // Explicit legacy compatibility: preparation has always been observed only
    // for comparisons and infrastructure errors, not admitted as a new seed.
    if (purpose == RunPurpose::kComparisons && cfg_.legacy_preparation) {
        return;
    }
    const auto finding = parts_.objective->classify(result);
    const bool admit = purpose == RunPurpose::kCandidate && parts_.admission->accept(result);
    if (result.status == ExecutionStatus::kOk) {
        stats.edges += result.new_edges;
    }
    if (finding == Finding::kNone && !admit) {
        return;
    }
    const mutation::FuzzInput bytes(input.data(), input.size());
    if (finding == Finding::kCrash) {
        ++stats.crashes;
        if (!corpus_->SaveCrash(bytes)) {
            LOG_WARN("save crash failed");
        }
    } else if (finding == Finding::kHang) {
        ++stats.hangs;
        if (!corpus_->SaveHang(bytes)) {
            LOG_WARN("save hang failed");
        }
    }
    if (admit) {
        if (corpus_->Add(bytes, result.new_edges)) {
            ++stats.accepted;
        } else {
            LOG_WARN("corpus add failed");
        }
    }
}
bool CampaignLoop::AccountInfraError(bool errored, CampaignStats& stats) {
    if (!errored) {
        consecutive_errors_ = 0;
        return false;
    }
    ++stats.ipc_errors;
    if (++consecutive_errors_ >= kMaxConsecutiveErrors) {
        stats.aborted = true;
        LOG_ERROR("aborting campaign after consecutive infrastructure errors");
        return true;
    }
    return false;
}
void CampaignLoop::EmitMetrics(const CampaignStats& stats, double elapsed_seconds) {
    const MetricsSnapshot snapshot{
        .execs = stats.execs,
        .execs_per_sec =
            elapsed_seconds > 0.0 ? static_cast<double>(stats.execs) / elapsed_seconds : 0.0,
        .corpus_size = corpus_->size(),
        .edges = stats.edges,
        .crashes = stats.crashes,
        .det_execs = stats.det_execs,
        .havoc_execs = stats.havoc_execs,
        .concolic_calls = stats.concolic_calls,
        .concolic_candidates = stats.concolic_candidates,
        .concolic_edges = stats.concolic_edges,
        .concolic_crashes = stats.concolic_crashes,
        .concolic_unsat = stats.concolic_unsat,
        .concolic_timeout = stats.concolic_timeout,
        .concolic_no_candidate = stats.concolic_no_candidate,
        .concolic_no_binding = stats.concolic_no_binding,
        .concolic_error = stats.concolic_error,
        .concolic_time_ms_total = stats.concolic_time_ms_total,
        .concolic_budget_skips = stats.concolic_budget_skips,
        .concolic_seed_run_ms_total = stats.concolic_seed_run_ms_total,
        .elapsed = elapsed_seconds,
    };
    if (auto emitted = metrics_->Emit(snapshot); !emitted) {
        LOG_WARN("metrics emit failed");
    }
}

void CampaignLoop::EmitMetricsIfDue(const CampaignStats& stats, double elapsed_seconds) {
    if (cfg_.metrics_interval != 0 && stats.execs % cfg_.metrics_interval == 0) {
        EmitMetrics(stats, elapsed_seconds);
    }
}

void CampaignLoop::account_stage(const StageResult& result, CampaignStats& stats) {
    stats.concolic_seed_run_ms_total += result.preparation_ms;
    stats.concolic_time_ms_total += result.solve_ms;
    stats.concolic_build_us_total += result.build_us;
    stats.concolic_solve_us_total += result.solve_us;
    switch (result.outcome) {
        case StageOutcome::kCandidate:
            ++stats.concolic_candidates;
            break;
        case StageOutcome::kUnsat:
            ++stats.concolic_unsat;
            break;
        case StageOutcome::kTimeout:
            ++stats.concolic_timeout;
            break;
        case StageOutcome::kSolverError:
            // Preserve the historic counter split; the typed event remains solver_error.
            if (result.legacy_width_overflow) {
                ++stats.concolic_no_binding;
            } else {
                ++stats.concolic_error;
            }
            ++stats.concolic_no_candidate;
            break;
        case StageOutcome::kNoBinding:
            ++stats.concolic_no_binding;
            ++stats.concolic_no_candidate;
            break;
        default:
            break;
    }
}
void CampaignLoop::run_candidate(const Decision& decision, StageResult& result,
                                 ExecutionService& execution, CampaignStats& stats) {
    if (result.candidate) {
        const auto& candidate = *result.candidate;
        auto response = execution.execute({candidate.data(), candidate.size()},
                                          RunPurpose::kCandidate, decision.id);
        if (response && decision.stage == StageKind::kDeterministic) {
            ++stats.det_execs;
        }
        if (response && decision.stage == StageKind::kMutation) {
            ++stats.havoc_execs;
        }
        if (!response) {
            result.outcome = StageOutcome::kCancelled;
        }
        if (response && decision.stage == StageKind::kI2sSmt) {
            if (response->status == ExecutionStatus::kOk && response->new_edges > 0) {
                ++stats.concolic_edges;
            } else if (response->status == ExecutionStatus::kCrash) {
                ++stats.concolic_crashes;
            }
        }
        if (response && result.progress) {
            corpus_->SetDetState(decision.seed_index, *result.progress);
        }
    }
}
void CampaignLoop::run_decision(const Decision& decision, ExecutionService& execution,
                                CampaignStats& stats) {
    const auto found = std::ranges::find_if(
        parts_.stages, [&decision](const auto& stage) { return stage->kind() == decision.stage; });
    if (found == parts_.stages.end()) {
        throw std::logic_error("policy selected unavailable stage");
    }
    const auto before = stats;
    const auto started = execution.elapsed();
    const auto cpu_started = std::clock();
    decision_observed_edges_ = 0;
    if (parts_.events) {
        parts_.events->on_decision(decision);
    }
    const auto& entry = corpus_->at(decision.seed_index);
    const StageContext context{
        .seed = {entry.input.data(), entry.input.size()},
        .cursor = entry.det.cursor,
        .decision_id = decision.id,
        .timeout_ms = std::min(cfg_.concolic_timeout_ms, decision.timeout_ms),
        .original = &entry.input};
    if (decision.max_executions == 0) {
        throw std::logic_error("decision has no execution budget");
    }
    execution.begin_decision(
        {.decision_id = decision.id, .max_executions = decision.max_executions});
    StageResult result = (*found)->generate(context, execution, rng_);
    if (decision.stage == StageKind::kI2sSmt) {
        if (result.solver_called) {
            ++stats.concolic_calls;
        }
        account_stage(result, stats);
    }
    run_candidate(decision, result, execution, stats);
    const DecisionFeedback feedback{
        .execs = stats.execs - before.execs,
        .new_edges = decision_observed_edges_,
        .successful_edges = stats.edges - before.edges,
        .findings = stats.crashes + stats.hangs - before.crashes - before.hangs,
        .wall_seconds = execution.elapsed() - started,
        .process_cpu_seconds = static_cast<double>(std::clock() - cpu_started) / CLOCKS_PER_SEC};
    parts_.strategy->observe(decision, result, feedback, stats);
    if (parts_.events) {
        parts_.events->on_outcome(decision, result.outcome, feedback);
    }
}
CampaignStats CampaignLoop::Run(std::stop_token stop) {
    CampaignStats stats;
    ExecutionService execution(
        *parts_.backend, {.max_execs = cfg_.max_iterations, .max_seconds = cfg_.max_seconds},
        [this, &stats](const auto& result, auto input, auto purpose) {
            handle_result(result, input, purpose, stats);
        },
        std::move(stop));
    if (cfg_.run_seeds_first) {
        const auto count = corpus_->size();
        for (std::size_t index = 0; index < count && !execution.exhausted(); ++index) {
            decision_error_ = false;
            const auto& seed = corpus_->at(index).input;
            (void)execution.execute({seed.data(), seed.size()}, RunPurpose::kSeed, 0);
            if (AccountInfraError(decision_error_, stats)) {
                break;
            }
            EmitMetricsIfDue(stats, execution.elapsed());
        }
    }
    while (!stats.aborted && !execution.exhausted()) {
        decision_error_ = false;
        const auto decision =
            parts_.strategy->choose({CorpusView(*corpus_), execution.budget()}, stats);
        run_decision(decision, execution, stats);
        if (AccountInfraError(decision_error_, stats)) {
            break;
        }
        EmitMetricsIfDue(stats, execution.elapsed());
        execution.begin_decision({});
    }
    EmitMetrics(stats, execution.elapsed());
    return stats;
}
}  // namespace mlfuzzz3::core
