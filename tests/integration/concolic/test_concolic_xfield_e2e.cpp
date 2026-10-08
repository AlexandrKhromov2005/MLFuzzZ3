// End-to-end cross-field concolic test (ADR 0035, постановка "I" —
// solve through to the crash).
//
// Spawns a real exec-server against the cov_xfield fixture (branch + edge
// passes) and proves the concolic mechanism end-to-end:
//
//   1. a seed that satisfies C1,C2,C3 but NOT C4 (the wrapping sum != 5)
//      runs to a clean exit — no crash;
//   2. the orchestrator observes the seed's branch log, binds x and y as
//      input fields, recognises C4's operand as their sum (kAddVars),
//      inverts the unobserved C4 outcome, and the solver returns a pair
//      with sum-wrap == 5;
//   3. running that candidate CRASHES (SIGABRT) — the concolic step drove
//      the input across a cross-field wrap barrier a mutation fuzzer would
//      not cross;
//   4. the solved pair genuinely satisfies C1..C4 (it is the solver's
//      pair, not hard-coded).
//
// Five iterations guard against non-determinism (seed -> no crash,
// candidate -> crash). Self-skips when any artifact is unavailable.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "session.h"

namespace mlfuzzz3::ipc {
namespace {

// ExecServerProcess owns the child pid and parent-side IPC socket; the
// destructor reaps the child so a mid-test failure leaks nothing. Mirrors
// the helper in test_branch_channel_e2e.cpp (kept local for isolation).
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
        ::close(client_fd);
        if (server_fd != 3) {
            if (::dup2(server_fd, 3) < 0) {
                ::_exit(127);
            }
            ::close(server_fd);
        }
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
        const char* argv[] = {
            bin.c_str(), "-target", target.c_str(),    "-cov-library", cov_lib.c_str(),
            "-workers",  "1",       "-run-timeout-ms", "5000",         nullptr,
        };
        ::execv(bin.c_str(), const_cast<char* const*>(argv));
        ::_exit(127);
    }

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

// Seed fields: x = 0x20000000 at offset 0, y = 0x30000000 at offset 4 (LE).
// Passes C1,C2,C3; (x+y) = 0x50000000 != 5, so C4 fails -> no crash.
constexpr std::uint32_t kSeedX = 0x20000000U;
constexpr std::uint32_t kSeedY = 0x30000000U;
constexpr std::uint32_t kLowerBound = 0x10000000U;

std::vector<std::uint8_t> LeBytes(std::uint32_t x, std::uint32_t y) {
    return {
        static_cast<std::uint8_t>(x & 0xFFu),         static_cast<std::uint8_t>((x >> 8) & 0xFFu),
        static_cast<std::uint8_t>((x >> 16) & 0xFFu), static_cast<std::uint8_t>((x >> 24) & 0xFFu),
        static_cast<std::uint8_t>(y & 0xFFu),         static_cast<std::uint8_t>((y >> 8) & 0xFFu),
        static_cast<std::uint8_t>((y >> 16) & 0xFFu), static_cast<std::uint8_t>((y >> 24) & 0xFFu),
    };
}

std::uint32_t ReadU32Le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

TEST(ConcolicXfieldE2E, SolveReachesCrashAcrossWrapBarrier) {
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string fixture = COV_XFIELD_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(fixture)) {
        GTEST_SKIP() << "cov_xfield_target missing: " << fixture;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(exec_server, fixture, cov_lib, proc, spawn_err)) << spawn_err;

    Conn client_conn(proc.client_fd);
    proc.client_fd = -1;

    auto session_or = ClientSession::Dial(
        std::move(client_conn), ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
    ASSERT_TRUE(session_or.has_value()) << "Dial failed: " << static_cast<int>(session_or.error());
    auto& session = *session_or;

    const int branch_fd = session.branch_fd();
    ASSERT_GE(branch_fd, 0) << "no branch fd received";
    auto branch_reader_or = coverage::BranchReader::Create(branch_fd, coverage::kBranchSegmentSize);
    ASSERT_TRUE(branch_reader_or.has_value())
        << "BranchReader::Create failed: " << static_cast<int>(branch_reader_or.error());
    auto& branch_reader = *branch_reader_or;

    const std::vector<std::uint8_t> seed = LeBytes(kSeedX, kSeedY);

    for (int iter = 0; iter < 5; ++iter) {
        // (1) Seed runs without crashing.
        auto seed_run = session.Run(std::span<const std::uint8_t>{seed});
        ASSERT_TRUE(seed_run.has_value())
            << "iter " << iter << " seed Run failed: " << static_cast<int>(seed_run.error());
        EXPECT_EQ(seed_run->status(), v1::EXEC_STATUS_OK)
            << "iter " << iter << ": seed unexpectedly did not exit cleanly";

        const std::vector<coverage::BranchReader::Record> records = branch_reader.Records();
        ASSERT_FALSE(records.empty()) << "iter " << iter << ": no branch records for seed";

        // (2) Orchestrator solves the inverted cross-field system.
        const std::optional<mutation::FuzzInput> candidate =
            concolic::SolveForCandidate(std::span<const std::uint8_t>{seed}, records, 5000);
        ASSERT_TRUE(candidate.has_value()) << "iter " << iter << ": concolic produced no candidate";
        ASSERT_GE(candidate->size(), 8U) << "iter " << iter;

        // (4) The solved pair satisfies the full crash conjunction C1..C4.
        const std::uint32_t x = ReadU32Le(candidate->data());
        const std::uint32_t y = ReadU32Le(candidate->data() + 4);
        EXPECT_GT(x, kLowerBound) << "iter " << iter;                         // C1
        EXPECT_GT(y, kLowerBound) << "iter " << iter;                         // C2
        EXPECT_LT(x, y) << "iter " << iter;                                   // C3
        EXPECT_EQ(static_cast<std::uint32_t>(x + y), 5U) << "iter " << iter;  // C4 (u32 wrap)

        // (3) The candidate crashes — concolic crossed the wrap barrier.
        const std::span<const std::uint8_t> cand_bytes{candidate->data(), candidate->size()};
        auto cand_run = session.Run(cand_bytes);
        ASSERT_TRUE(cand_run.has_value())
            << "iter " << iter << " candidate Run failed: " << static_cast<int>(cand_run.error());
        EXPECT_EQ(cand_run->status(), v1::EXEC_STATUS_CRASH)
            << "iter " << iter << ": candidate did not crash (status "
            << static_cast<int>(cand_run->status()) << ")";
    }
}

}  // namespace
}  // namespace mlfuzzz3::ipc
