// SPDX-License-Identifier: MIT
#include "execution_adapter.h"

#include "ipc.pb.h"
namespace mlfuzzz3::composition {
core::ExecutionResult RunnerBackend::execute(std::span<const std::uint8_t> input,
                                             core::RunPurpose purpose) {
    core::ExecutionResult result;
    auto response = runner_->Run(input);
    if (!response) {
        result.status = core::ExecutionStatus::kInfrastructureError;
        result.diagnostic = "transport error";
        return result;
    }
    result.run_id = response->run_id();
    result.new_edges = response->has_edge_result() ? response->edge_result().new_edges() : 0;
    result.diagnostic = response->error_message();
    switch (response->status()) {
        case ipc::v1::EXEC_STATUS_OK:
            result.status = core::ExecutionStatus::kOk;
            break;
        case ipc::v1::EXEC_STATUS_CRASH:
            result.status = core::ExecutionStatus::kCrash;
            break;
        case ipc::v1::EXEC_STATUS_HANG:
            result.status = core::ExecutionStatus::kHang;
            break;
        case ipc::v1::EXEC_STATUS_IPC_ERROR:
            result.status = core::ExecutionStatus::kInfrastructureError;
            break;
        default:
            result.status = core::ExecutionStatus::kUnknown;
            break;
    }
    if (purpose == core::RunPurpose::kComparisons && result.status == core::ExecutionStatus::kOk &&
        runner_->has_comparison_channel()) {
        const auto records = runner_->LastBranchRecords();
        result.comparisons.reserve(records.size());
        for (const auto& record : records) {
            result.comparisons.push_back(
                {record.site_id, record.predicate, record.bit_width, record.lhs, record.rhs});
        }
        result.comparisons_available = true;
        result.comparisons_complete = !runner_->last_branch_overflow();
    }
    return result;
}
}  // namespace mlfuzzz3::composition
