// SPDX-License-Identifier: MIT
#include "execution.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <utility>
namespace mlfuzzz3::core {
ExecutionService::ExecutionService(ExecutionBackend& backend, ExecutionLimits limits, Sink sink,
                                   std::stop_token stop)
    : backend_(&backend),
      max_execs_(limits.max_execs),
      max_seconds_(limits.max_seconds),
      sink_(std::move(sink)),
      stop_(std::move(stop)) {}
double ExecutionService::elapsed() const {
    return std::chrono::duration<double>(Clock::now() - start_).count();
}
bool ExecutionService::exhausted() const {
    return (local_limit_ != 0 && local_execs_ >= local_limit_) || stop_.stop_requested() ||
           (max_execs_ != 0 && executions_ >= max_execs_) ||
           (max_seconds_ > 0 && elapsed() >= max_seconds_);
}
BudgetView ExecutionService::budget() const {
    BudgetView view;
    if (max_execs_ != 0) {
        view.remaining_execs = executions_ >= max_execs_ ? 0 : max_execs_ - executions_;
    }
    if (max_seconds_ > 0) {
        view.remaining_wall_seconds = std::max(0.0, max_seconds_ - elapsed());
    }
    return view;
}
unsigned ExecutionService::solver_timeout(unsigned requested_ms) const {
    if (stop_.stop_requested() || (max_seconds_ > 0 && elapsed() >= max_seconds_)) {
        return 0;
    }
    if (max_seconds_ <= 0) {
        return requested_ms;
    }
    const double remaining_ms = std::floor((max_seconds_ - elapsed()) * 1000);
    if (remaining_ms < 1) {
        return 0;
    }
    return static_cast<unsigned>(std::min(static_cast<double>(requested_ms), remaining_ms));
}
void ExecutionService::begin_decision(DecisionBudget budget) {
    active_decision_ = budget.decision_id;
    local_limit_ = budget.max_executions;
    local_execs_ = 0;
}
std::optional<ExecutionResult> ExecutionService::execute(std::span<const std::uint8_t> input,
                                                         RunPurpose purpose,
                                                         std::uint64_t decision_id) {
    if (exhausted()) {
        return std::nullopt;
    }
    const auto start = Clock::now();
    const auto cpu = std::clock();
    ExecutionResult result = backend_->execute(input, purpose);
    result.wall_seconds = std::chrono::duration<double>(Clock::now() - start).count();
    result.cpu_seconds = static_cast<double>(std::clock() - cpu) / CLOCKS_PER_SEC;
    result.transport_run_id = result.run_id;
    result.run_id = executions_ + 1;
    result.decision_id = active_decision_ != 0 ? active_decision_ : decision_id;
    ++local_execs_;
    ++executions_;
    if (sink_) {
        sink_(result, input, purpose);
    }
    return result;
}
}  // namespace mlfuzzz3::core
