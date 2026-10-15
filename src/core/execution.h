// SPDX-License-Identifier: MIT
#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace mlfuzzz3::core {
enum class ExecutionStatus { kOk, kCrash, kHang, kInfrastructureError, kUnknown };
enum class RunPurpose { kSeed, kCandidate, kComparisons };
struct Comparison {
    std::uint32_t site_id = 0;
    std::uint8_t predicate = 0;
    std::uint8_t bit_width = 0;
    std::uint64_t lhs = 0;
    std::uint64_t rhs = 0;
};
struct Capabilities {
    bool execution = true;
    bool coverage = true;
    bool comparisons = false;
};
struct ExecutionResult {
    ExecutionStatus status = ExecutionStatus::kUnknown;
    std::uint64_t run_id = 0;
    std::uint64_t transport_run_id = 0;
    std::uint64_t decision_id = 0;
    std::uint32_t new_edges = 0;
    std::vector<Comparison> comparisons;
    bool comparisons_available = false;
    bool comparisons_complete = false;
    std::string diagnostic;
    double wall_seconds = 0;
    double cpu_seconds = 0;
};
class ExecutionBackend {
   public:
    ExecutionBackend() = default;
    ExecutionBackend(const ExecutionBackend&) = delete;
    ExecutionBackend& operator=(const ExecutionBackend&) = delete;
    ExecutionBackend(ExecutionBackend&&) = delete;
    ExecutionBackend& operator=(ExecutionBackend&&) = delete;
    virtual ~ExecutionBackend() = default;
    virtual ExecutionResult execute(std::span<const std::uint8_t> input, RunPurpose purpose) = 0;
    [[nodiscard]] virtual Capabilities capabilities() const = 0;
};
struct BudgetView {
    std::optional<std::uint64_t> remaining_execs = std::nullopt;
    std::optional<double> remaining_wall_seconds = std::nullopt;
};
struct DecisionBudget {
    std::uint64_t decision_id = 0;
    std::uint64_t max_executions = 0;
};
struct ExecutionLimits {
    std::uint64_t max_execs = 0;
    double max_seconds = 0;
};
class ExecutionService {
   public:
    using Clock = std::chrono::steady_clock;
    using Sink =
        std::function<void(const ExecutionResult&, std::span<const std::uint8_t>, RunPurpose)>;
    ExecutionService(ExecutionBackend& backend, ExecutionLimits limits, Sink sink,
                     std::stop_token stop = {});
    ExecutionService(const ExecutionService&) = delete;
    ExecutionService& operator=(const ExecutionService&) = delete;
    ExecutionService(ExecutionService&&) = delete;
    ExecutionService& operator=(ExecutionService&&) = delete;
    ~ExecutionService() = default;
    [[nodiscard]] std::optional<ExecutionResult> execute(std::span<const std::uint8_t> input,
                                                         RunPurpose purpose,
                                                         std::uint64_t decision_id);
    [[nodiscard]] bool exhausted() const;
    [[nodiscard]] BudgetView budget() const;
    [[nodiscard]] double elapsed() const;
    [[nodiscard]] unsigned solver_timeout(unsigned requested_ms) const;
    [[nodiscard]] std::uint64_t executions() const {
        return executions_;
    }

   private:
    friend class CampaignLoop;
    void begin_decision(DecisionBudget budget);
    std::uint64_t active_decision_ = 0;
    std::uint64_t local_limit_ = 0;
    std::uint64_t local_execs_ = 0;
    ExecutionBackend* backend_;
    std::uint64_t max_execs_;
    double max_seconds_;
    Sink sink_;
    std::stop_token stop_;
    Clock::time_point start_ = Clock::now();
    std::uint64_t executions_ = 0;
};
}  // namespace mlfuzzz3::core
