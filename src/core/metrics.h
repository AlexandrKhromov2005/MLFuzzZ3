#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <tl/expected.hpp>

// Phase 2 MVP fuzzing loop (ADR 0029). MetricsEmitter appends one JSON
// object per emit to metrics.jsonl (append-only; one record per line).
// The campaign emits a snapshot by interval, so the loop is measurable
// from the first run — the foundation for later research comparisons.
// The run id (<timestamp>-<git_sha>-<config_hash>) is formed by the
// caller and attached to every record.

namespace mlfuzzz3::core {

enum class MetricsError {
    // metrics.jsonl could not be opened for append.
    kOpenFailed,
    // A write to metrics.jsonl failed.
    kWriteFailed,
};

// One metrics record (ADR 0029 §Решение, Метрики; phase counters ADR 0031).
struct MetricsSnapshot {
    std::uint64_t execs = 0;
    double execs_per_sec = 0.0;
    std::uint64_t corpus_size = 0;
    std::uint64_t edges = 0;  // accumulated new_edges over the campaign
    std::uint64_t crashes = 0;
    std::uint64_t det_execs = 0;    // executions spent in the deterministic stage (ADR 0031)
    std::uint64_t havoc_execs = 0;  // executions spent in havoc (ADR 0031)
    // ADR 0036 concolic integration counters (§4); zero unless built with
    // concolic (FUZZER_BUILD_Z3).
    std::uint64_t concolic_calls = 0;
    std::uint64_t concolic_candidates = 0;
    std::uint64_t concolic_edges = 0;
    std::uint64_t concolic_crashes = 0;
    std::uint64_t concolic_unsat = 0;
    std::uint64_t concolic_timeout = 0;
    std::uint64_t concolic_no_candidate = 0;
    // Components of concolic_no_candidate (== their sum); see CampaignStats.
    std::uint64_t concolic_no_binding = 0;
    std::uint64_t concolic_error = 0;
    std::uint64_t concolic_time_ms_total = 0;
    std::uint64_t concolic_budget_skips = 0;  // concolic calls blocked by the budget (ADR 0038)
    // Seed-run wall time in StepConcolic (ms) (ADR 0039).
    std::uint64_t concolic_seed_run_ms_total = 0;
    double elapsed = 0.0;  // seconds since campaign start
};

// Not thread-safe; the MVP loop is single-threaded (ADR 0029 Развилка 3).
// Each Emit opens the file in append mode, so an existing file is never
// truncated — records accumulate across emits and across emitter
// instances pointed at the same path.
class MetricsEmitter {
   public:
    // Create validates that path can be opened for append (creating it
    // if absent) and binds the run id attached to every record.
    [[nodiscard]] static tl::expected<MetricsEmitter, MetricsError> Create(
        std::filesystem::path path, std::string run_id);

    MetricsEmitter(const MetricsEmitter&) = delete;
    MetricsEmitter& operator=(const MetricsEmitter&) = delete;
    MetricsEmitter(MetricsEmitter&&) = default;
    MetricsEmitter& operator=(MetricsEmitter&&) = default;
    ~MetricsEmitter() = default;

    // Emit appends one JSON line for snapshot. Returns an error on I/O
    // failure; the loop logs and continues (metrics are observability,
    // not correctness).
    [[nodiscard]] tl::expected<void, MetricsError> Emit(const MetricsSnapshot& snapshot);

    [[nodiscard]] const std::string& run_id() const noexcept {
        return run_id_;
    }
    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

   private:
    MetricsEmitter(std::filesystem::path path, std::string run_id)
        : path_(std::move(path)), run_id_(std::move(run_id)) {}

    std::filesystem::path path_;
    std::string run_id_;
};

}  // namespace mlfuzzz3::core
