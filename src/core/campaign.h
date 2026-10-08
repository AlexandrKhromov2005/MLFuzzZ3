#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <random>

#ifdef MLFUZZZ3_WITH_CONCOLIC
#include <cstddef>
#include <memory>
#include <unordered_map>
#endif

#include "corpus.h"
#include "metrics.h"
#include "mutator.h"
#include "runner.h"
#include "seed_scheduler.h"

// Phase 2 MVP fuzzing loop (ADR 0029, deterministic stage ADR 0031).
// CampaignLoop is the single-threaded mutation fuzzer. Each iteration runs
// one input: while any seed is still in its deterministic stage, the loop
// advances the lowest-index such seed by one positional step
// (DeterministicStage, RNG-free); once every seed is past its
// deterministic sweep it falls back to SeedScheduler → Mutator (havoc) as
// before. The result feeds Runner::Run → consume EdgeRunResult.new_edges +
// status. An input is accepted into the corpus iff new_edges > 0
// (server-side coverage frontier, ADR 0021; no second source of truth in
// C++). Crashes and hangs are persisted as findings and the loop continues
// — it never aborts on a target finding. Sustained infrastructure errors
// (broken transport / EXEC_STATUS_IPC_ERROR) stop the loop. Scope is
// mutation-only: no Z3, LLM, threads, culling, or power schedules.

#ifdef MLFUZZZ3_WITH_CONCOLIC
namespace mlfuzzz3::concolic {
// Held by pointer so campaign.h stays free of concolic headers and
// fuzzer::concolic remains a PRIVATE link of fuzzer::core (ADR 0036).
class ConcolicThrottle;
}  // namespace mlfuzzz3::concolic
#endif

namespace mlfuzzz3::core {

// Per-seed cap on deterministic-stage steps (ADR 0031). A seed whose
// positional sweep is longer than this is moved to havoc after this many
// steps, so very long inputs cover a prefix instead of starving havoc and
// throughput. The default covers the full sweep for inputs up to ~150
// bytes; it is a tunable default, not a contract.
inline constexpr std::uint64_t kDefaultMaxDetSteps = 1ULL << 16;

// Default metrics-snapshot interval: a snapshot is emitted every N execs
// (and once at the end). Tunable, not a contract.
inline constexpr std::uint64_t kDefaultMetricsInterval = 1000;

// Default concolic stagnation threshold (ADR 0036 §2): a seed selected in
// havoc this many times CUMULATIVELY without producing new coverage
// triggers a concolic step on it. 64 is a middle-ground default (a seed
// exhausted by ~64 fruitless havoc picks); tunable, not a contract.
inline constexpr std::uint32_t kDefaultConcolicStagnationThreshold = 64;

// Default per-solve timeout (ms) handed to SolverFacade via
// SolveForCandidate (ADR 0036 §3), bounding a single solve so the loop
// never hangs on a pathological system; MVP systems solve well under this.
inline constexpr unsigned kDefaultConcolicTimeoutMs = 1000;

struct CampaignConfig {
    std::uint64_t max_iterations = 0;  // 0 = unbounded
    double max_seconds = 0.0;          // 0 = unbounded
    std::uint64_t metrics_interval =
        kDefaultMetricsInterval;                        // snapshot every N execs (+ once at end)
    std::uint64_t rng_seed = 0;                         // seeds the mutation RNG (replay)
    std::uint64_t max_det_steps = kDefaultMaxDetSteps;  // per-seed deterministic cap (ADR 0031)
    // Seed pass (CLI --run-seeds-first): before the deterministic stage and
    // havoc, every corpus entry present at Run() start is executed once as
    // is, in corpus order, without the mutator and without concolic. The
    // runs count in execs and are bounded by max_iterations/max_seconds.
    // false (default) keeps the loop exactly as before; changing the default
    // is an owner-level ADR 0029 decision.
    bool run_seeds_first = false;

    // ADR 0036 experimental switch: disarms the concolic arm in THIS binary
    // (CLI --no-concolic) so one build can be run with the arm and without
    // it. false makes TakeConcolicTurn return before any solver call, so
    // concolic_calls stays 0; the default is true — the 0036 behavior is
    // unchanged and a default change stays an owner-level ADR decision.
    bool concolic_enabled = true;

    // ADR 0036 concolic integration (only consulted when built with
    // concolic, FUZZER_BUILD_Z3). concolic_stagnation_threshold N: a seed
    // selected in havoc this many times CUMULATIVELY without producing new
    // coverage triggers a concolic step on it (§2). Cumulative (not
    // consecutive) so the random scheduler cannot dilute it away on a
    // growing corpus.
    std::uint32_t concolic_stagnation_threshold = kDefaultConcolicStagnationThreshold;
    // Per-solve timeout handed to SolverFacade via SolveForCandidate (§3),
    // bounding a single solve so the loop never hangs on a pathological
    // system; MVP systems solve well under this.
    unsigned concolic_timeout_ms = kDefaultConcolicTimeoutMs;
    // ADR 0038: minimum execs between concolic calls (rate-limit against the
    // "concolic storm" risk from 0036). 0 = budget off (concolic fires on
    // stagnation with no frequency cap — 0036 behavior). Part of the common
    // config (not under #ifdef); simply ignored when built without concolic.
    std::uint64_t concolic_min_exec_interval = 0;
    // ADR 0049: четыре починки солверной руки, каждая за своим флагом.
    // Значения продублированы простыми полями, а не структурой
    // concolic::Fixes, чтобы campaign.h остался свободен от заголовков
    // concolic (см. предварительное объявление выше); перевод — в
    // campaign.cpp. Умолчания воспроизводят поведение до ADR 0049.
    bool concolic_fix_findfirst_index = false;  // F1
    bool concolic_fix_addvars = false;          // F2
    bool concolic_fix_writeback_width = false;  // F4
    // F3: 0 — всё-кроме-цели (как было), 1 — префикс, 2 — оптимистическая.
    unsigned concolic_system_form = 0;
    // ADR 0038 (adaptive extension): let the concolic stage rate-limit
    // ITSELF on a target whose inverted systems are overwhelmingly
    // unsatisfiable, where every call is pure cost. The demanded interval
    // is taken as max(static budget, throttle demand), so this knob can
    // only ever slow concolic down, never speed it past the static budget.
    // The throttle stays silent on a target that still yields candidates
    // (test CampaignConcolicTest.AdaptiveThrottleStaysSilentOnSatTarget).
    bool concolic_adaptive_throttle = true;
};

struct CampaignStats {
    std::uint64_t execs = 0;
    std::uint64_t accepted = 0;     // inputs added to the corpus
    std::uint64_t edges = 0;        // accumulated new_edges
    std::uint64_t crashes = 0;      // EXEC_STATUS_CRASH findings
    std::uint64_t hangs = 0;        // EXEC_STATUS_HANG (timeout) findings
    std::uint64_t ipc_errors = 0;   // infrastructure errors (transport / EXEC_STATUS_IPC_ERROR)
    std::uint64_t det_execs = 0;    // executions spent in the deterministic stage (ADR 0031)
    std::uint64_t havoc_execs = 0;  // executions spent in havoc (ADR 0031)
    // ADR 0036 concolic integration counters (§4); zero unless built with
    // concolic (FUZZER_BUILD_Z3).
    std::uint64_t concolic_calls = 0;         // stagnation triggered -> SolveForCandidate called
    std::uint64_t concolic_candidates = 0;    // calls that produced a candidate
    std::uint64_t concolic_edges = 0;         // candidates accepted into corpus (new_edges > 0)
    std::uint64_t concolic_crashes = 0;       // candidates that crashed the target
    std::uint64_t concolic_unsat = 0;         // calls whose inverted system was unsatisfiable
    std::uint64_t concolic_timeout = 0;       // calls whose solve timed out
    std::uint64_t concolic_no_candidate = 0;  // calls with no candidate, residual (unbound / error)
    // The two components of concolic_no_candidate, attributed separately so a
    // storm of fruitless calls can be read: "nothing bound to the input" is a
    // reconstruction gap, "solver error" is a solver defect. The legacy field
    // above stays exactly their sum (metrics.jsonl consumers).
    std::uint64_t concolic_no_binding = 0;     // SolveOutcome::kNoBinding (no constraint bound)
    std::uint64_t concolic_error = 0;          // SolveOutcome::kError (solver error / bad model)
    std::uint64_t concolic_time_ms_total = 0;  // time in SolveForCandidate only (ms) (ADR 0039)
    std::uint64_t concolic_budget_skips = 0;   // concolic calls blocked by the budget (ADR 0038)
    // The subset of concolic_budget_skips owed to the ADAPTIVE throttle
    // (the static budget alone would not have blocked that call), plus how
    // many times the throttle engaged — the measurement that separates
    // "the adaptive path fired" from "a fixed toll was paid".
    std::uint64_t concolic_throttle_skips = 0;
    std::uint64_t concolic_throttle_engagements = 0;
    // Total seed-run wall time in StepConcolic (ms) — the cost of the
    // double seed run, metered for its deferred elimination (ADR 0039).
    std::uint64_t concolic_seed_run_ms_total = 0;
    bool aborted = false;  // stopped early due to sustained infra errors
    // Цена вызова концолики, разложенная на построение системы и её решение
    // (ADR 0049), в МИКРОсекундах. Оба участка лежат внутри таймера
    // concolic_time_ms_total (ADR 0039) и его не заменяют: тот усекает каждый
    // вызов до целых миллисекунд. Решение копится только когда солвер зовётся.
    std::uint64_t concolic_build_us_total = 0;
    std::uint64_t concolic_solve_us_total = 0;
};

// Not thread-safe; the MVP loop is single-threaded (ADR 0029 Развилка 3).
class CampaignLoop {
   public:
    // Borrows all collaborators; they must outlive the loop. The corpus
    // must be non-empty before Run (the caller bootstraps it).
    CampaignLoop(Runner& runner, const mutation::Mutator& mutator, SeedScheduler& scheduler,
                 Corpus& corpus, MetricsEmitter& metrics, const CampaignConfig& cfg);

    CampaignLoop(const CampaignLoop&) = delete;
    CampaignLoop& operator=(const CampaignLoop&) = delete;
    CampaignLoop(CampaignLoop&&) = delete;
    CampaignLoop& operator=(CampaignLoop&&) = delete;
    // Out-of-line: the concolic throttle is held by pointer to an
    // incomplete type, so the destructor cannot be defined here.
    ~CampaignLoop();

    // Run executes until a stop condition (max_iterations / max_seconds)
    // or sustained infrastructure errors, emitting metrics by interval
    // and once at the end. Returns the final stats.
    CampaignStats Run();

   private:
    // Processes one run result: accepts new-coverage inputs and persists
    // crash/hang findings. Returns true if the run was an infrastructure
    // error (transport failure or EXEC_STATUS_IPC_ERROR), which the loop
    // counts toward the consecutive-error abort threshold.
    bool HandleResponse(const tl::expected<ipc::v1::RunResponse, ipc::IpcError>& response,
                        mutation::FuzzInput& mutated, CampaignStats& stats);
    // Seed pass step: runs corpus entry index unmutated through the same
    // funnel as a loop step, except that new coverage is only counted (the
    // seed is already an entry, and Corpus::Add does not deduplicate).
    // Returns true on an infrastructure error, like HandleResponse.
    bool StepSeed(std::size_t index, CampaignStats& stats);
    // Seed pass (run_seeds_first): StepSeed over every corpus entry present
    // at the call, in corpus order, until budget_exhausted() holds. Returns
    // true iff sustained infrastructure errors aborted the campaign.
    bool RunSeedPass(CampaignStats& stats, std::uint64_t& consecutive_ipc_errors,
                     const std::function<bool()>& budget_exhausted,
                     const std::function<double()>& elapsed_seconds);
    // Adds input to the corpus iff new_edges > 0 (ADR 0029 acceptance).
    void RecordCoverage(mutation::FuzzInput&& input, std::uint32_t new_edges, CampaignStats& stats);
    // Emits one metrics snapshot for the current stats and elapsed time.
    void EmitMetrics(const CampaignStats& stats, double elapsed_seconds);
    // Emits a snapshot only when the configured interval boundary is hit.
    void EmitMetricsIfDue(const CampaignStats& stats, double elapsed_seconds);
    // Folds an infrastructure-error outcome into the consecutive-error
    // counter (incrementing ipc_errors and the streak, or resetting it on
    // success); returns true when the streak reached the abort threshold.
    [[nodiscard]] static bool AccountInfraError(bool errored, CampaignStats& stats,
                                                std::uint64_t& consecutive_ipc_errors);

#ifdef MLFUZZZ3_WITH_CONCOLIC
    // If seed `index` has stagnated past the threshold (ADR 0036 §2), runs
    // a concolic step on it (StepConcolic), resets its counter, folds any
    // infrastructure error, and emits due metrics. Returns true when the
    // step ran (the caller should skip the normal mutation for this
    // iteration); sets `aborted` if the infra-error streak forces a stop.
    [[nodiscard]] bool TakeConcolicTurn(std::size_t index, CampaignStats& stats,
                                        std::uint64_t& consecutive_ipc_errors,
                                        double elapsed_seconds, bool& aborted);
    // Runs the concolic step on the stuck seed `index` (ADR 0036 §3): runs
    // the seed itself to capture its branch path (order invariant — no
    // other Run between that and LastBranchRecords()), solves the inverted
    // system via fuzzer::concolic, and on a candidate runs it through the
    // normal funnel (HandleResponse). Updates the concolic_* counters.
    // Returns true if any of its runs hit an infrastructure error.
    [[nodiscard]] bool StepConcolic(std::size_t index, CampaignStats& stats);
    // Folds a havoc run's outcome into the per-seed stagnation counter
    // (ADR 0036 §2): reset on new coverage from `index`, else increment.
    void RecordHavocStagnation(std::size_t index,
                               const tl::expected<ipc::v1::RunResponse, ipc::IpcError>& response);
#endif

    // Returns the lowest-index seed still eligible for a deterministic
    // step, or nullopt if none. Advances det_frontier_ past seeds that are
    // no longer eligible (ineligibility is permanent, so the frontier only
    // moves forward).
    std::optional<std::size_t> NextDeterministicSeed();
    // A seed is eligible for a deterministic step iff it is in the
    // Deterministic phase and its cursor has not yet reached
    // min(length(input), max_det_steps). With max_det_steps == 0 no seed is
    // ever eligible, so the deterministic stage is fully disabled (0
    // det-execs) and the loop is havoc-only (ADR 0032).
    [[nodiscard]] bool DeterministicEligible(std::size_t index) const;
    // Advances the deterministic cursor of entry `index` by one and flips
    // it to the Havoc phase once min(length, max_det_steps) is reached.
    void AdvanceDeterministic(std::size_t index);

    Runner& runner_;
    const mutation::Mutator& mutator_;
    SeedScheduler& scheduler_;
    Corpus& corpus_;
    MetricsEmitter& metrics_;
    CampaignConfig cfg_;
    std::mt19937_64 rng_;
    // Lowest corpus index that may still be in the Deterministic phase
    // (ADR 0031 det-first). Monotonic: never moves backward.
    std::size_t det_frontier_ = 0;

#ifdef MLFUZZZ3_WITH_CONCOLIC
    // Cumulative per-seed havoc-without-new-edges counter (ADR 0036 §2),
    // keyed by corpus index. Reset to 0 on new coverage from the seed and
    // after a concolic step on it.
    std::unordered_map<std::size_t, std::uint32_t> stagnation_;
    // ADR 0038 rate-limit budget: execs at the last REAL concolic call, and
    // whether any real call has happened yet. The gate never blocks the
    // first call (§2), so an explicit flag — not a magic last-exec sentinel
    // — distinguishes "no call yet" from "called at exec 0".
    std::uint64_t last_concolic_exec_ = 0;
    bool first_concolic_done_ = false;
    // ADR 0038 adaptive extension: reads the solve-outcome stream and
    // demands a growing exec interval while the target is unsat-dominated.
    // Always allocated when built with concolic; disabled through its own
    // config when cfg_.concolic_adaptive_throttle is false.
    std::unique_ptr<concolic::ConcolicThrottle> concolic_throttle_;
#endif
};

}  // namespace mlfuzzz3::core
