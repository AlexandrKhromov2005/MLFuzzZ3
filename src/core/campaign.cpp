#include "campaign.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>

#include "deterministic_stage.h"
#include "fuzz_input.h"
#include "ipc.pb.h"
#include "log.h"

#ifdef MLFUZZZ3_WITH_CONCOLIC
#include <limits>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "throttle.h"
#endif

namespace mlfuzzz3::core {
namespace {

// Stop the loop after this many consecutive infrastructure errors
// (transport failures or EXEC_STATUS_IPC_ERROR). A reply of any other
// kind resets the streak.
constexpr std::uint64_t kMaxConsecutiveIpcErrors = 5;

std::span<const std::uint8_t> AsSpan(const mutation::FuzzInput& input) {
    return {input.data(), input.size()};
}

}  // namespace

CampaignLoop::CampaignLoop(Runner& runner, const mutation::Mutator& mutator,
                           SeedScheduler& scheduler, Corpus& corpus, MetricsEmitter& metrics,
                           const CampaignConfig& cfg)
    : runner_(runner),
      mutator_(mutator),
      scheduler_(scheduler),
      corpus_(corpus),
      metrics_(metrics),
      cfg_(cfg),
      rng_(mutation::make_rng(cfg.rng_seed)) {
#ifdef MLFUZZZ3_WITH_CONCOLIC
    // ADR 0038 adaptive extension: the throttle owns its own defaults;
    // the campaign config only decides whether it may speak at all.
    concolic_throttle_ = std::make_unique<concolic::ConcolicThrottle>(
        concolic::ThrottleConfig{.enabled = cfg.concolic_adaptive_throttle});
#endif
}

CampaignLoop::~CampaignLoop() = default;

void CampaignLoop::RecordCoverage(mutation::FuzzInput&& input, std::uint32_t new_edges,
                                  CampaignStats& stats) {
    if (new_edges == 0) {
        return;
    }
    stats.edges += new_edges;
    if (auto id = corpus_.Add(std::move(input), new_edges); id) {
        ++stats.accepted;
    } else {
        LOG_WARN("corpus add failed");
    }
}

bool CampaignLoop::StepSeed(std::size_t index, CampaignStats& stats) {
    // A copy: HandleResponse takes the input by mutable reference, and the
    // corpus entry itself must stay untouched.
    mutation::FuzzInput seed = corpus_.at(index).input;
    auto response = runner_.Run(AsSpan(seed));
    ++stats.execs;
    if (response && response->status() == ipc::v1::EXEC_STATUS_OK) {
        stats.edges += response->has_edge_result() ? response->edge_result().new_edges() : 0;
        return false;
    }
    return HandleResponse(response, seed, stats);
}

bool CampaignLoop::RunSeedPass(CampaignStats& stats, std::uint64_t& consecutive_ipc_errors,
                               const std::function<bool()>& budget_exhausted,
                               const std::function<double()>& elapsed_seconds) {
    // Every corpus entry runs once, as is, in corpus order (the pass itself
    // adds no entries). Same budgets and abort rule as a loop step.
    const std::size_t seed_count = corpus_.size();
    for (std::size_t index = 0; index < seed_count && !budget_exhausted(); ++index) {
        const bool infra_error = StepSeed(index, stats);
        if (AccountInfraError(infra_error, stats, consecutive_ipc_errors)) {
            return true;
        }
        EmitMetricsIfDue(stats, elapsed_seconds());
    }
    return false;
}

bool CampaignLoop::HandleResponse(const tl::expected<ipc::v1::RunResponse, ipc::IpcError>& response,
                                  mutation::FuzzInput& mutated, CampaignStats& stats) {
    if (!response) {
        LOG_WARN("run transport error ({})", static_cast<int>(response.error()));
        return true;
    }
    switch (response->status()) {
        case ipc::v1::EXEC_STATUS_OK:
            RecordCoverage(std::move(mutated),
                           response->has_edge_result() ? response->edge_result().new_edges() : 0,
                           stats);
            return false;
        case ipc::v1::EXEC_STATUS_CRASH:
            ++stats.crashes;
            if (auto saved = corpus_.SaveCrash(mutated); !saved) {
                LOG_WARN("save crash failed");
            }
            return false;
        case ipc::v1::EXEC_STATUS_HANG:
            ++stats.hangs;
            if (auto saved = corpus_.SaveHang(mutated); !saved) {
                LOG_WARN("save hang failed");
            }
            return false;
        case ipc::v1::EXEC_STATUS_IPC_ERROR:
            LOG_WARN("exec-server reported IPC error");
            return true;
        default:
            LOG_WARN("unexpected exec status ({})", static_cast<int>(response->status()));
            return false;
    }
}

void CampaignLoop::EmitMetrics(const CampaignStats& stats, double elapsed_seconds) {
    const MetricsSnapshot snapshot{
        .execs = stats.execs,
        .execs_per_sec =
            elapsed_seconds > 0.0 ? static_cast<double>(stats.execs) / elapsed_seconds : 0.0,
        .corpus_size = corpus_.size(),
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
    if (auto emitted = metrics_.Emit(snapshot); !emitted) {
        LOG_WARN("metrics emit failed");
    }
}

void CampaignLoop::EmitMetricsIfDue(const CampaignStats& stats, double elapsed_seconds) {
    if (cfg_.metrics_interval != 0 && stats.execs % cfg_.metrics_interval == 0) {
        EmitMetrics(stats, elapsed_seconds);
    }
}

bool CampaignLoop::AccountInfraError(bool errored, CampaignStats& stats,
                                     std::uint64_t& consecutive_ipc_errors) {
    if (!errored) {
        consecutive_ipc_errors = 0;
        return false;
    }
    ++stats.ipc_errors;
    ++consecutive_ipc_errors;
    if (consecutive_ipc_errors >= kMaxConsecutiveIpcErrors) {
        stats.aborted = true;
        LOG_ERROR("aborting campaign: {} consecutive infrastructure errors",
                  consecutive_ipc_errors);
        return true;
    }
    return false;
}

#ifdef MLFUZZZ3_WITH_CONCOLIC
// ADR 0038: cap for the saturating stagnation increment. Above the
// stagnation threshold the exact count carries no information (only
// "threshold reached" matters), so saturating here keeps the uint32
// counter from wrapping to 0 during a long budget block — a wrap would
// falsely reset stagnation and stop the seed ever triggering concolic.
constexpr std::uint32_t kStagnationMax = std::numeric_limits<std::uint32_t>::max();

bool CampaignLoop::StepConcolic(std::size_t index, CampaignStats& stats) {
    using Clock = std::chrono::steady_clock;
    ++stats.concolic_calls;

    // Run the seed itself to capture its branch path. Order invariant
    // (ADR 0036 §3): nothing else calls runner_.Run between this run and
    // LastBranchRecords(), so the records describe exactly this seed. The
    // seed is a non-crashing corpus entry; its run is used only for its
    // records (not routed through HandleResponse), but a transport/IPC
    // error on it still counts as an infrastructure error. Its wall time
    // is metered separately (ADR 0039) — the empirics for the deferred
    // double-run elimination.
    const mutation::FuzzInput& seed = corpus_.at(index).input;
    const Clock::time_point seed_run_start = Clock::now();
    auto seed_response = runner_.Run(AsSpan(seed));
    ++stats.execs;
    const std::vector<coverage::BranchReader::Record> records = runner_.LastBranchRecords();
    stats.concolic_seed_run_ms_total += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - seed_run_start)
            .count());
    bool infra_error =
        !seed_response.has_value() || seed_response->status() == ipc::v1::EXEC_STATUS_IPC_ERROR;

    // ADR 0039: the solve timer covers SolveForCandidate only (system
    // build + Z3 solve + write-back), keeping concolic_time_ms_total a
    // clean "time in Z3" for a future time-budget.
    concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
    const Clock::time_point solve_start = Clock::now();
    // ADR 0049: перевод плоских полей конфигурации в структуру починок.
    // campaign.h не включает заголовки concolic (ADR 0036), поэтому
    // структура собирается здесь, в единственной точке вызова.
    concolic::Fixes fixes;
    fixes.findfirst_index = cfg_.concolic_fix_findfirst_index;
    fixes.strict_addvars = cfg_.concolic_fix_addvars;
    fixes.no_truncation = cfg_.concolic_fix_writeback_width;
    switch (cfg_.concolic_system_form) {
        case 1:
            fixes.form = concolic::Fixes::Form::kPrefix;
            break;
        case 2:
            fixes.form = concolic::Fixes::Form::kOptimistic;
            break;
        default:
            fixes.form = concolic::Fixes::Form::kAllButTarget;
            break;
    }
    std::optional<mutation::FuzzInput> candidate = concolic::SolveForCandidate(
        AsSpan(seed), records, cfg_.concolic_timeout_ms, &outcome, fixes,
        {.build_us = &stats.concolic_build_us_total, .solve_us = &stats.concolic_solve_us_total});
    stats.concolic_time_ms_total += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - solve_start).count());
    // ADR 0038 adaptive extension: every finished solve feeds the throttle,
    // which is what makes the rate-limit react to THIS target instead of
    // charging a fixed toll everywhere.
    concolic_throttle_->Observe(outcome);
    stats.concolic_throttle_engagements = concolic_throttle_->engagements();

    if (!candidate) {
        if (outcome == concolic::SolveOutcome::kUnsat) {
            ++stats.concolic_unsat;
        } else if (outcome == concolic::SolveOutcome::kTimeout) {
            ++stats.concolic_timeout;
        } else if (outcome == concolic::SolveOutcome::kError) {
            ++stats.concolic_error;
            ++stats.concolic_no_candidate;  // kept as no_binding + error
        } else {
            ++stats.concolic_no_binding;    // kNoBinding
            ++stats.concolic_no_candidate;  // kept as no_binding + error
        }
        return infra_error;
    }
    ++stats.concolic_candidates;

    // The candidate goes through the same funnel as a mutation result.
    // Read its outcome for the concolic counters before HandleResponse
    // moves the input on an accepted run.
    auto candidate_response = runner_.Run(AsSpan(*candidate));
    ++stats.execs;
    if (candidate_response.has_value()) {
        if (candidate_response->status() == ipc::v1::EXEC_STATUS_OK) {
            const std::uint32_t new_edges = candidate_response->has_edge_result()
                                                ? candidate_response->edge_result().new_edges()
                                                : 0;
            if (new_edges > 0) {
                ++stats.concolic_edges;
            }
        } else if (candidate_response->status() == ipc::v1::EXEC_STATUS_CRASH) {
            ++stats.concolic_crashes;
        }
    }
    infra_error = HandleResponse(candidate_response, *candidate, stats) || infra_error;
    return infra_error;
}

bool CampaignLoop::TakeConcolicTurn(std::size_t index, CampaignStats& stats,
                                    std::uint64_t& consecutive_ipc_errors, double elapsed_seconds,
                                    bool& aborted) {
    // ADR 0036 experimental switch (--no-concolic): the arm is disarmed for
    // this whole run. Checked before the stagnation test so no solver call,
    // no seed re-run and no counter is charged — the disarmed arm is
    // observable as concolic_calls == 0, not merely as "nothing crashed".
    if (!cfg_.concolic_enabled) {
        return false;
    }
    if (stagnation_[index] < cfg_.concolic_stagnation_threshold) {
        return false;
    }
    // ADR 0038 rate-limit: once one real concolic call has happened, block
    // further calls until concolic_min_exec_interval execs have elapsed.
    // Blocking returns false WITHOUT resetting stagnation_ (the reset below
    // runs only after a real StepConcolic), so the stuck seed keeps its
    // accumulated stagnation and triggers again when the budget reopens
    // (§3). The first call is never blocked (first_concolic_done_, §2).
    // The adaptive throttle can only RAISE the demanded interval (its demand
    // is 0 while disengaged), so a target it never fires on behaves exactly
    // as it did under the static budget alone.
    const std::uint64_t throttle_interval = concolic_throttle_->CurrentInterval();
    const std::uint64_t interval = std::max(cfg_.concolic_min_exec_interval, throttle_interval);
    const bool budget_enabled = interval != 0;
    stats.concolic_throttle_engagements = concolic_throttle_->engagements();
    if (budget_enabled && first_concolic_done_ && stats.execs - last_concolic_exec_ < interval) {
        ++stats.concolic_budget_skips;
        // Attribute the block to the throttle only when the static budget
        // alone would have let this call through.
        if (stats.execs - last_concolic_exec_ >= cfg_.concolic_min_exec_interval) {
            ++stats.concolic_throttle_skips;
        }
        return false;
    }
    const bool infra_error = StepConcolic(index, stats);
    last_concolic_exec_ = stats.execs;  // ADR 0038: anchor for the rate-limit
    first_concolic_done_ = true;        // ADR 0038: gate is active from now on
    stagnation_[index] = 0;             // §2: reset after a concolic step
    aborted = AccountInfraError(infra_error, stats, consecutive_ipc_errors);
    if (!aborted) {
        EmitMetricsIfDue(stats, elapsed_seconds);
    }
    return true;
}

void CampaignLoop::RecordHavocStagnation(
    std::size_t index, const tl::expected<ipc::v1::RunResponse, ipc::IpcError>& response) {
    const std::uint32_t new_edges =
        (response.has_value() && response->status() == ipc::v1::EXEC_STATUS_OK &&
         response->has_edge_result())
            ? response->edge_result().new_edges()
            : 0;
    if (new_edges > 0) {
        stagnation_[index] = 0;
    } else if (stagnation_[index] < kStagnationMax) {
        // ADR 0038: saturating increment. Under the budget a seed can stay
        // >= threshold a long time while this keeps counting its havoc picks;
        // without the cap the uint32 would eventually wrap to 0 and falsely
        // reset stagnation. Above the threshold the exact value is irrelevant.
        ++stagnation_[index];
    }
}
#endif  // MLFUZZZ3_WITH_CONCOLIC

bool CampaignLoop::DeterministicEligible(std::size_t index) const {
    const CorpusEntry& entry = corpus_.at(index);
    if (entry.det.phase != SeedPhase::kDeterministic) {
        return false;
    }
    const std::uint64_t length = mutation::DeterministicStage::length(entry.input);
    return entry.det.cursor < std::min(length, cfg_.max_det_steps);
}

std::optional<std::size_t> CampaignLoop::NextDeterministicSeed() {
    while (det_frontier_ < corpus_.size() && !DeterministicEligible(det_frontier_)) {
        ++det_frontier_;
    }
    if (det_frontier_ < corpus_.size()) {
        return det_frontier_;
    }
    return std::nullopt;
}

void CampaignLoop::AdvanceDeterministic(std::size_t index) {
    DetState state = corpus_.at(index).det;
    ++state.cursor;
    const std::uint64_t length = mutation::DeterministicStage::length(corpus_.at(index).input);
    if (state.cursor >= std::min(length, cfg_.max_det_steps)) {
        state.phase = SeedPhase::kHavoc;
    }
    corpus_.SetDetState(index, state);
}

CampaignStats CampaignLoop::Run() {
    using Clock = std::chrono::steady_clock;
    const Clock::time_point start = Clock::now();
    const auto elapsed_seconds = [&start]() {
        return std::chrono::duration<double>(Clock::now() - start).count();
    };

    CampaignStats stats;
    std::uint64_t consecutive_ipc_errors = 0;
    const auto budget_exhausted = [&]() {
        return (cfg_.max_iterations != 0 && stats.execs >= cfg_.max_iterations) ||
               (cfg_.max_seconds > 0.0 && elapsed_seconds() >= cfg_.max_seconds);
    };

    // Seed pass (--run-seeds-first) before the det stage and havoc, which
    // follow unchanged. Kept out of Run to hold its cognitive complexity.
    const bool seed_pass_aborted =
        cfg_.run_seeds_first &&
        RunSeedPass(stats, consecutive_ipc_errors, budget_exhausted, elapsed_seconds);

    while (!seed_pass_aborted) {
        if (budget_exhausted()) {
            break;
        }

        // det-first (ADR 0031): advance the lowest-index seed still in its
        // deterministic stage by one positional step; once every seed is
        // past its sweep, fall back to havoc (scheduler + mutator).
        const std::optional<std::size_t> det_seed = NextDeterministicSeed();
        mutation::FuzzInput mutated;
#ifdef MLFUZZZ3_WITH_CONCOLIC
        std::optional<std::size_t> havoc_index;
#endif
        if (det_seed) {
            const CorpusEntry& entry = corpus_.at(*det_seed);
            mutated = mutation::DeterministicStage::apply(entry.input, entry.det.cursor);
            ++stats.det_execs;
        } else {
            const std::size_t index = scheduler_.Choose(corpus_.size());
#ifdef MLFUZZZ3_WITH_CONCOLIC
            // Stagnation trigger (ADR 0036 §2/§3): a seed picked in havoc
            // enough times without new coverage gets one concolic step
            // instead of another mutation; that ends this iteration.
            bool aborted = false;
            if (TakeConcolicTurn(index, stats, consecutive_ipc_errors, elapsed_seconds(),
                                 aborted)) {
                if (aborted) {
                    break;
                }
                continue;
            }
            havoc_index = index;
#endif
            mutated = mutator_.mutate(corpus_.at(index).input, rng_);
            ++stats.havoc_execs;
        }

        auto response = runner_.Run(AsSpan(mutated));
        ++stats.execs;
        const bool infra_error = HandleResponse(response, mutated, stats);

#ifdef MLFUZZZ3_WITH_CONCOLIC
        // Cumulative per-seed stagnation accounting for havoc runs
        // (ADR 0036 §2); det runs do not participate (positional sweep).
        if (havoc_index.has_value()) {
            RecordHavocStagnation(*havoc_index, response);
        }
#endif

        if (AccountInfraError(infra_error, stats, consecutive_ipc_errors)) {
            break;
        }

        // Advance the deterministic seed used this iteration. Done after
        // HandleResponse, which may append new entries (reallocating the
        // corpus); AdvanceDeterministic re-fetches the entry by index.
        if (det_seed) {
            AdvanceDeterministic(*det_seed);
        }

        EmitMetricsIfDue(stats, elapsed_seconds());
    }

    EmitMetrics(stats, elapsed_seconds());
    return stats;
}

}  // namespace mlfuzzz3::core
