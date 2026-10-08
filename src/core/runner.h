#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <tl/expected.hpp>
#include <vector>

#include "branch_reader.h"
#include "session.h"

// Phase 2 MVP fuzzing loop (ADR 0029). Runner is the seam between the
// campaign loop and the execution transport. The loop drives
// Runner::Run; the production adapter (SessionRunner) forwards to
// ipc::ClientSession::Run. The seam keeps the loop unit-testable without
// a live exec-server and leaves room for a future batch/parallel runner
// (the MVP stays on the single Run, ADR 0029 §Граница scope).
//
// ADR 0036 (D4-б1) extends the seam with LastBranchRecords(): the concolic
// campaign integration needs the branch-value records of the last run, and
// the records are NOT on the RunResponse wire (only the summary is) — they
// live in the announced SHM segment. SessionRunner owns the BranchReader
// over that segment so the records reach the loop through the same seam,
// keeping the loop testable with a fake runner that returns canned records.

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
