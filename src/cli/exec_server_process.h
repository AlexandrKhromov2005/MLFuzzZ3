#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <tl/expected.hpp>

// Phase 2 MVP fuzzing loop (ADR 0029). ExecServerProcess spawns the
// execution server as a fuzzer-core subprocess (ADR 0012) and owns the
// parent-side IPC socket fd. The server-side socket is installed at the
// child's fd 3 (the inherited IPC socket per cmd/exec-server/main.go),
// matching the fork+exec contract proven by the coverage bridge
// integration test (ADR 0028). RAII reaps the child.

namespace mlfuzzz3::cli {

class ExecServerProcess {
   public:
    // Spawn fork+exec's exec_server_bin against target with cov_lib, a
    // single worker, and the given per-run timeout. target_args, when
    // non-empty, is forwarded to the exec-server -target-args flag and
    // passed to the target on every run (ADR 0040); empty leaves the
    // child argv unchanged. Stdout/stderr of the child are redirected to
    // /dev/null. On success the returned process holds the connected
    // parent-side socket fd (TakeClientFd) and the child pid. On failure
    // returns a human-readable error string.
    //
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): order mirrors the
    // exec-server CLI flags; the single call site passes them by name.
    [[nodiscard]] static tl::expected<ExecServerProcess, std::string> Spawn(
        const std::string& exec_server_bin, const std::string& target, const std::string& cov_lib,
        const std::string& target_args, std::uint64_t run_timeout_ms);

    ExecServerProcess(const ExecServerProcess&) = delete;
    ExecServerProcess& operator=(const ExecServerProcess&) = delete;
    ExecServerProcess(ExecServerProcess&& other) noexcept;
    ExecServerProcess& operator=(ExecServerProcess&& other) noexcept;
    ~ExecServerProcess();

    // TakeClientFd transfers ownership of the parent-side socket fd to
    // the caller (to build an ipc::Conn). Returns -1 if already taken.
    [[nodiscard]] int TakeClientFd() noexcept;

   private:
    // Private ctor with a single internal call site (the Spawn factory); pid
    // and fd are bound by construction there, never positionally at a public
    // boundary. The marker sits on the line directly above the declaration so
    // it actually attaches to it.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    ExecServerProcess(pid_t pid, int client_fd) noexcept : pid_(pid), client_fd_(client_fd) {}
    void Reap() noexcept;

    pid_t pid_ = -1;
    int client_fd_ = -1;
};

}  // namespace mlfuzzz3::cli
