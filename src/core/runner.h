#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <tl/expected.hpp>
#include <vector>

#include "branch_reader.h"
#include "session.h"

// Compatibility transport seam (ADR 0029/0036). SessionRunner forwards to
// ipc::ClientSession and owns the mapped comparison reader. RunnerBackend
// in composition copies each response and its observations into an owning
// domain ExecutionResult before another run. CampaignLoop uses only that
// domain backend; research runners retain this transport API.

namespace mlfuzzz3::core {

class Runner {
   public:
    Runner() = default;
    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;
    Runner(Runner&&) = delete;
    Runner& operator=(Runner&&) = delete;
    virtual ~Runner() = default;

    // Run executes the target once with input and returns the server's
    // RunResponse, or an IpcError on transport failure.
    [[nodiscard]] virtual tl::expected<ipc::v1::RunResponse, ipc::IpcError> Run(
        std::span<const std::uint8_t> input) = 0;

    // Compatibility defaults keep in-memory research runners usable.
    [[nodiscard]] virtual bool has_coverage_channel() const {
        return true;
    }
    [[nodiscard]] virtual bool has_comparison_channel() const {
        return true;
    }
    [[nodiscard]] virtual bool last_branch_overflow() const {
        return false;
    }

    // LastBranchRecords returns the branch-value comparison records of the
    // last OK run (ADR 0036). Empty when no branch channel is active or the
    // last run did not complete cleanly (CRASH/HANG/IPC/transport error) —
    // so the concolic step never reasons over a stale or foreign path.
    [[nodiscard]] virtual std::vector<coverage::BranchReader::Record> LastBranchRecords() const = 0;
};

// SessionRunner adapts a borrowed ipc::ClientSession to the Runner seam.
// The session must outlive the runner.
class SessionRunner final : public Runner {
   public:
    // Maps the branch-value segment once (if the session announced one,
    // branch_fd() >= 0) and re-reads it after every run. The borrowed
    // branch fd is owned by the session — which outlives this runner — so
    // the read-only mapping stays valid for the runner's whole lifetime.
    // The segment itself does not change across runs (same fd); the
    // exec-server resets its contents before each spawn, so a fresh
    // Records() read always reflects the most recent run.
    explicit SessionRunner(ipc::ClientSession& session);

    [[nodiscard]] tl::expected<ipc::v1::RunResponse, ipc::IpcError> Run(
        std::span<const std::uint8_t> input) override;

    [[nodiscard]] std::vector<coverage::BranchReader::Record> LastBranchRecords() const override;

    [[nodiscard]] bool has_coverage_channel() const override {
        return session_.coverage_fd() >= 0;
    }
    [[nodiscard]] bool has_comparison_channel() const override {
        return branch_reader_.has_value();
    }
    [[nodiscard]] bool last_branch_overflow() const override {
        return branch_reader_ && last_run_ok_ && branch_reader_->Overflow();
    }

   private:
    ipc::ClientSession& session_;
    // Mapped once at construction; nullopt when the session has no branch
    // channel (branch_fd() < 0) or the mapping failed.
    std::optional<coverage::BranchReader> branch_reader_;
    // Whether the most recent Run returned EXEC_STATUS_OK. Gates
    // LastBranchRecords() so a CRASH/HANG/IPC/transport run yields no
    // records.
    bool last_run_ok_ = false;
};

}  // namespace mlfuzzz3::core
