#include "runner.h"

#include <utility>

#include "ipc.pb.h"

// SessionRunner implementation (ADR 0036 §1). The branch-value mapping is
// created once over the session's borrowed branch fd and re-read after
// each run; only an OK run surfaces records (LastBranchRecords()).

namespace mlfuzzz3::core {

SessionRunner::SessionRunner(ipc::ClientSession& session) : session_(session) {
    const int branch_fd = session_.branch_fd();
    if (branch_fd < 0) {
        return;  // no branch channel announced -> records always empty
    }
    if (auto reader = coverage::BranchReader::Create(branch_fd, coverage::kBranchSegmentSize);
        reader) {
        branch_reader_ = std::move(*reader);
    }
}

tl::expected<ipc::v1::RunResponse, ipc::IpcError> SessionRunner::Run(
    std::span<const std::uint8_t> input) {
    auto response = session_.Run(input);
    last_run_ok_ = response.has_value() && response->status() == ipc::v1::EXEC_STATUS_OK;
    return response;
}

std::vector<coverage::BranchReader::Record> SessionRunner::LastBranchRecords() const {
    if (!branch_reader_ || !last_run_ok_) {
        return {};
    }
    return branch_reader_->Records();
}

}  // namespace mlfuzzz3::core
