// End-to-end coverage bridge integration test
// (ADR 0028 Phase 2). Spawns a real exec-server subprocess
// against the pass-instrumented cov_stdin fixture and
// verifies that the C++ Core:
//
//   1. receives the edge-coverage memfd attached to the
//      ChannelAnnouncement via SCM_RIGHTS (ADR 0028 part A,
//      task 009a) — surfaced as ClientSession::coverage_fd();
//   2. can map that borrowed fd read-only through
//      coverage::CoverageReader (ADR 0028 part B, task 009a)
//      and observe per-run bitmaps written by the target;
//   3. distinguishes inputs that traverse different branches
//      of the cov_stdin fixture — different first-byte inputs
//      yield different bitmaps.
//
// The expected nonzero cell sets are the same analytical
// values asserted by exec-server/internal/coverage/
// pass_oracle_test.go (same fixture, same EdgeCoveragePass).
// This is a cross-language consistency check, not a new
// oracle mechanism.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "coverage_reader.h"
#include "session.h"

namespace mlfuzzz3::ipc {
namespace {

// ExecServerProcess owns the child pid and the parent-side
// IPC socket. Destructor reaps the child (SIGKILL fallback)
// so a test failure mid-flight does not leak processes.
struct ExecServerProcess {
    pid_t pid = -1;
    int client_fd = -1;

    ExecServerProcess() = default;
    ExecServerProcess(const ExecServerProcess&) = delete;
    ExecServerProcess& operator=(const ExecServerProcess&) = delete;

    ~ExecServerProcess() {
        if (client_fd >= 0) {
            ::close(client_fd);
        }
        if (pid > 0) {
            ::kill(pid, SIGKILL);
            int status = 0;
            ::waitpid(pid, &status, 0);
        }
    }
};

// SpawnExecServer creates a SOCK_STREAM AF_UNIX socketpair,
// fork+exec's exec_server_bin with the server-side fd
// installed at fd 3 (the inherited IPC socket per
// cmd/exec-server/main.go). Stdout and stderr of the child
// are redirected to /dev/null so slog output and any target
// printf chatter do not pollute test output. The returned
// out.client_fd is the parent's end of the socket and must
// be moved into a Conn before Dial.
bool SpawnExecServer(const std::string& bin, const std::string& target, const std::string& cov_lib,
                     ExecServerProcess& out, std::string& out_err) {
    std::array<int, 2> sv{};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv.data()) != 0) {
        out_err = std::string("socketpair: ") + std::strerror(errno);
        return false;
    }
    const int client_fd = sv[0];
    const int server_fd = sv[1];

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        ::close(client_fd);
        ::close(server_fd);
        out_err = std::string("fork: ") + std::strerror(err);
        return false;
    }
    if (pid == 0) {
        // Child: install server_fd at fd 3, silence stdio,
        // exec exec-server.
        ::close(client_fd);
        if (server_fd != 3) {
            if (::dup2(server_fd, 3) < 0) {
                ::_exit(127);
            }
            ::close(server_fd);
        }
        // Clear FD_CLOEXEC on fd 3 — dup2 already does this,
        // but if server_fd == 3 (unusual) we must clear it
        // explicitly so the IPC socket survives execv.
        const int flags3 = ::fcntl(3, F_GETFD);
        if (flags3 >= 0) {
            (void)::fcntl(3, F_SETFD, flags3 & ~FD_CLOEXEC);
        }
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)::dup2(devnull, 1);
            (void)::dup2(devnull, 2);
            if (devnull > 2) {
                ::close(devnull);
            }
        }

        // Flags mirror what the project's own callers will
        // eventually pass: instrumented target binary,
        // absolute -cov-library path (validated by
        // cmd/exec-server/main.go), single worker, ample
        // per-run timeout for a 1-syscall fixture.
        const char* argv[] = {
            bin.c_str(), "-target", target.c_str(),    "-cov-library", cov_lib.c_str(),
            "-workers",  "1",       "-run-timeout-ms", "5000",         nullptr,
        };
        ::execv(bin.c_str(), const_cast<char* const*>(argv));
        ::_exit(127);
    }

    // Parent.
    ::close(server_fd);
    out.client_fd = client_fd;
    out.pid = pid;
    return true;
}

bool PathReadable(const std::string& path) {
    return ::access(path.c_str(), R_OK) == 0;
}

bool PathExecutable(const std::string& path) {
    return ::access(path.c_str(), R_OK | X_OK) == 0;
}

// RunOne sends a Run(input) and returns the bitmap snapshot
// observed via the borrowed coverage fd. exec-server's
// worker.Pool.runOnce resets the channel before each run,
// so the snapshot reflects exactly the just-completed run.
std::vector<std::uint8_t> RunOne(ClientSession& session, const coverage::CoverageReader& reader,
                                 std::string_view input) {
    const std::span<const std::uint8_t> bytes{reinterpret_cast<const std::uint8_t*>(input.data()),
                                              input.size()};
    auto rr = session.Run(bytes);
    EXPECT_TRUE(rr.has_value()) << "Run(" << input << ") failed: " << static_cast<int>(rr.error());
    if (rr.has_value()) {
        EXPECT_EQ(rr->status(), v1::EXEC_STATUS_OK)
            << "Run(" << input << ") status=" << rr->status() << " err=" << rr->error_message();
    }
    return reader.Read();
}

std::vector<int> NonZeroCells(const std::vector<std::uint8_t>& bm) {
    std::vector<int> out;
    out.reserve(16);
    for (std::size_t i = 0; i < bm.size(); ++i) {
        if (bm[i] != 0) {
            out.push_back(static_cast<int>(i));
        }
    }
    return out;
}

bool AnyNonZero(const std::vector<std::uint8_t>& bm) {
    for (const auto b : bm) {
        if (b != 0) {
            return true;
        }
    }
    return false;
}

// TestCoverageBridgeE2E is the cross-language acceptance
// gate for ADR 0028: real exec-server announces a coverage
// channel with SCM_RIGHTS, C++ ClientSession::Dial receives
// the fd, CoverageReader maps it, and bitmaps observed for
// the cov_stdin fixture's three reachable branches match the
// analytical cell sets shared with the Go-side oracle.
TEST(CoverageBridgeE2E, RealExecServerDeliversPerInputBitmaps) {
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string cov_stdin = COV_STDIN_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(cov_stdin)) {
        GTEST_SKIP() << "cov_stdin_target missing: " << cov_stdin;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(exec_server, cov_stdin, cov_lib, proc, spawn_err)) << spawn_err;

    Conn client_conn(proc.client_fd);
    // Conn now owns the fd; clear it from the RAII guard so
    // the destructor does not double-close.
    proc.client_fd = -1;

    // expected_channels = 2 since ADR 0033: the server announces an
    // edge memfd and a branch-value memfd per worker. This test only
    // exercises the edge channel; the branch fd is received and held.
    auto session_or = ClientSession::Dial(
        std::move(client_conn), ClientConfig{.run_timeout_ms = 2000, .expected_channels = 2});
    ASSERT_TRUE(session_or.has_value()) << "Dial failed: " << static_cast<int>(session_or.error());
    auto& session = *session_or;

    // Coverage fd must be present and live.
    const int cov_fd = session.coverage_fd();
    ASSERT_GE(cov_fd, 0);
    struct stat st{};
    ASSERT_EQ(::fstat(cov_fd, &st), 0) << "fstat errno=" << errno;

    auto reader_or = coverage::CoverageReader::Create(cov_fd, coverage::kMapSize);
    ASSERT_TRUE(reader_or.has_value())
        << "CoverageReader::Create failed: " << static_cast<int>(reader_or.error());
    auto& reader = *reader_or;
    EXPECT_EQ(reader.size(), coverage::kMapSize);

    const auto bm_A = RunOne(session, reader, "A");
    const auto bm_B = RunOne(session, reader, "B");
    const auto bm_C = RunOne(session, reader, "C");

    EXPECT_TRUE(AnyNonZero(bm_A)) << "bitmap for input 'A' was all zero";
    EXPECT_TRUE(AnyNonZero(bm_B)) << "bitmap for input 'B' was all zero";
    EXPECT_TRUE(AnyNonZero(bm_C)) << "bitmap for input 'C' was all zero";

    // Different first bytes traverse different branches of
    // the cov_stdin fixture; bitmaps must differ pairwise.
    EXPECT_NE(bm_A, bm_B);
    EXPECT_NE(bm_B, bm_C);
    EXPECT_NE(bm_A, bm_C);

    // Cross-language consistency with the analytical cell
    // sets in exec-server/internal/coverage/
    // pass_oracle_test.go (same fixture, same pass). Each
    // visited cell's counter equals 1 because the cov_stdin
    // arms enter each block exactly once per run.
    const std::vector<int> kExpectedCellsA = {1, 3, 4, 9};
    const std::vector<int> kExpectedCellsB = {1, 3, 5, 7, 9};
    const std::vector<int> kExpectedCellsC = {1, 3, 5, 6, 9};

    EXPECT_EQ(NonZeroCells(bm_A), kExpectedCellsA);
    EXPECT_EQ(NonZeroCells(bm_B), kExpectedCellsB);
    EXPECT_EQ(NonZeroCells(bm_C), kExpectedCellsC);
    for (const int c : kExpectedCellsA) {
        EXPECT_EQ(bm_A[c], 1U) << "cell " << c << " counter on 'A'";
    }
    for (const int c : kExpectedCellsB) {
        EXPECT_EQ(bm_B[c], 1U) << "cell " << c << " counter on 'B'";
    }
    for (const int c : kExpectedCellsC) {
        EXPECT_EQ(bm_C[c], 1U) << "cell " << c << " counter on 'C'";
    }

    // Graceful shutdown — server drains the run loop, replies,
    // and exits with status 0. Reap explicitly so the dtor
    // does not have to SIGKILL.
    auto shutdown = session.Shutdown();
    ASSERT_TRUE(shutdown.has_value()) << "Shutdown failed: " << static_cast<int>(shutdown.error());

    int wstatus = 0;
    const pid_t reaped = ::waitpid(proc.pid, &wstatus, 0);
    EXPECT_EQ(reaped, proc.pid);
    proc.pid = -1;
    EXPECT_TRUE(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)
        << "exec-server exit status raw=" << wstatus;
}

}  // namespace
}  // namespace mlfuzzz3::ipc
