#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

#include "branch_reader.h"
#include "ipc.pb.h"
#include "runner.h"

// In-memory Runner double (ADR 0036). Mirrors SessionRunner's contract
// without a live exec-server: Run replays scripted RunResponse replies and
// tracks whether the last run was OK; LastBranchRecords() returns the
// canned branch records ONLY after an OK run (empty otherwise, or when no
// records were set). This is the infrastructure the campaign-loop concolic
// integration is unit-tested with (the loop sees the same records it would
// get from a real SessionRunner, but with no IPC).

namespace mlfuzzz3::core::testing {

class FakeRunner final : public Runner {
   public:
    using Reply = tl::expected<ipc::v1::RunResponse, ipc::IpcError>;

    // Records the next OK run exposes via LastBranchRecords().
    void set_branch_records(std::vector<coverage::BranchReader::Record> records) {
        records_ = std::move(records);
    }

    // FIFO replies for successive Run calls. Once exhausted, Run returns OK
    // with new_edges == 0.
    void set_script(std::vector<Reply> script) {
        script_ = std::move(script);
        next_ = 0;
    }

    [[nodiscard]] Reply Run(std::span<const std::uint8_t> input) override {
        last_input_.assign(input.begin(), input.end());
        Reply reply = next_ < script_.size() ? std::move(script_[next_++]) : MakeOk(0);
        last_run_ok_ = reply.has_value() && reply->status() == ipc::v1::EXEC_STATUS_OK;
        return reply;
    }

    [[nodiscard]] std::vector<coverage::BranchReader::Record> LastBranchRecords() const override {
        if (!last_run_ok_) {
            return {};
        }
        return records_;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& last_input() const noexcept {
        return last_input_;
    }

    static Reply MakeOk(std::uint32_t new_edges) {
        ipc::v1::RunResponse resp;
        resp.set_status(ipc::v1::EXEC_STATUS_OK);
        resp.mutable_edge_result()->set_new_edges(new_edges);
        return resp;
    }

    static Reply MakeStatus(ipc::v1::ExecStatus status) {
        ipc::v1::RunResponse resp;
        resp.set_status(status);
        return resp;
    }

    static Reply MakeTransportError() {
        return tl::unexpected(ipc::IpcError::kTransportError);
    }

   private:
    std::vector<Reply> script_;
    std::size_t next_ = 0;
    std::vector<coverage::BranchReader::Record> records_;
    std::vector<std::uint8_t> last_input_;
    bool last_run_ok_ = false;
};

}  // namespace mlfuzzz3::core::testing
