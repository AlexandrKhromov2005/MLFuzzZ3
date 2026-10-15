// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
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
    // it. false prevents the strategy from selecting the solver stage, so
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
    bool allow_incomplete_comparisons = true;
    bool legacy_preparation = true;
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
    // Total solver preparation seed-run wall time (ms) — the cost of the
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

}  // namespace mlfuzzz3::core
