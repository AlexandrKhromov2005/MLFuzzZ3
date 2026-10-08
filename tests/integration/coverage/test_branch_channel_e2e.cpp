// End-to-end branch-value channel smoke test (ADR 0033 Шаг 6).
//
// Spawns a real exec-server subprocess against the branch_icmp
// fixture (built with the branch-tracing pass AND the edge pass) and
// verifies the full branch channel path:
//
//   1. the server announces a branch-value memfd via SCM_RIGHTS, which
//      ClientSession::Dial receives as branch_fd();
//   2. for a KNOWN input the logged records match the expected
//      (site_id, predicate, bit_width, lhs, rhs) tuples — a format
//      smoke check, not just non-emptiness — covering signed/unsigned
//      predicates and 32/64-bit widths;
//   3. RunResponse.branch_result carries record_count == 5, no
//      overflow;
//   4. the edge channel still works on the same run (branch did not
//      break edge).
//
// The expected operand values are the same ones produced by running
// the fixture directly with this input; this is the cross-language
// acceptance gate for the channel before any Z3 work (0034+).
//
// Runs the input five times to catch non-determinism.

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
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "coverage_reader.h"
#include "session.h"

namespace mlfuzzz3::ipc {
namespace {

// ExecServerProcess owns the child pid and parent-side IPC socket;
// the destructor reaps the child so a mid-test failure leaks nothing.
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

// SpawnExecServer fork+exec's the exec-server with the server-side
// socket installed at fd 3 and a single coverage worker. Mirrors the
// helper in test_coverage_bridge_e2e.cpp (kept local for test
// isolation).
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

// The 32-byte input window the branch_icmp fixture reads, with values
// chosen so each comparison's operands are known. See the fixture
// source for the offset/type layout.
std::vector<std::uint8_t> KnownInput() {
    std::vector<std::uint8_t> in(32, 0);
    // [0..3] int32 s32 = -2000 (0xFFFFF830, little-endian)
    in[0] = 0x30;
    in[1] = 0xF8;
    in[2] = 0xFF;
    in[3] = 0xFF;
    // [4..7] uint32 u32 = 500
    in[4] = 0xF4;
    in[5] = 0x01;
    // [8..11] uint32 e32 = 0xCAFEBABE
    in[8] = 0xBE;
    in[9] = 0xBA;
    in[10] = 0xFE;
    in[11] = 0xCA;
    // [12..19] uint64 u64 = 0x1122334455667788
    in[12] = 0x88;
    in[13] = 0x77;
    in[14] = 0x66;
    in[15] = 0x55;
    in[16] = 0x44;
    in[17] = 0x33;
    in[18] = 0x22;
    in[19] = 0x11;
    // [20..27] int64 s64 = -50000 (0xFFFFFFFFFFFF3CB0)
    in[20] = 0xB0;
    in[21] = 0x3C;
    in[22] = 0xFF;
    in[23] = 0xFF;
    in[24] = 0xFF;
    in[25] = 0xFF;
    in[26] = 0xFF;
    in[27] = 0xFF;
    return in;
}

// Expected records for KnownInput(), in execution order. Predicate
// codes: EQ=0, ULT=2, UGT=4, SLT=6, SGT=8.
std::vector<coverage::BranchReader::Record> ExpectedRecords() {
    return {
        {0, 6, 32, 0xFFFFFFFFFFFFF830ULL, 0xFFFFFFFFFFFFFC18ULL},  // s32 SLT -1000
        {1, 2, 32, 500ULL, 1000ULL},                               // u32 ULT 1000
        {2, 0, 32, 0xCAFEBABEULL, 0xCAFEBABEULL},                  // e32 EQ
        {3, 4, 64, 0x1122334455667788ULL, 0xDEADBEEFCAFEBABEULL},  // u64 UGT
        {4, 8, 64, 0xFFFFFFFFFFFF3CB0ULL, 0xFFFFFFFFFFFE7960ULL},  // s64 SGT -100000
    };
}

bool AnyNonZero(const std::vector<std::uint8_t>& bm) {
    for (const auto b : bm) {
        if (b != 0) {
            return true;
        }
    }
    return false;
}

TEST(BranchChannelE2E, RealExecServerDeliversBranchRecords) {
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string fixture = BRANCH_FIXTURE_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(fixture)) {
        GTEST_SKIP() << "branch_icmp_target missing: " << fixture;
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
        std::move(client_conn), ClientConfig{.run_timeout_ms = 2000, .expected_channels = 2});
    ASSERT_TRUE(session_or.has_value()) << "Dial failed: " << static_cast<int>(session_or.error());
    auto& session = *session_or;

    const int cov_fd = session.coverage_fd();
    const int branch_fd = session.branch_fd();
    ASSERT_GE(cov_fd, 0) << "no edge coverage fd received";
    ASSERT_GE(branch_fd, 0) << "no branch fd received";

    auto cov_reader_or = coverage::CoverageReader::Create(cov_fd, coverage::kMapSize);
    ASSERT_TRUE(cov_reader_or.has_value())
        << "CoverageReader::Create failed: " << static_cast<int>(cov_reader_or.error());
    auto branch_reader_or = coverage::BranchReader::Create(branch_fd, coverage::kBranchSegmentSize);
    ASSERT_TRUE(branch_reader_or.has_value())
        << "BranchReader::Create failed: " << static_cast<int>(branch_reader_or.error());
    auto& cov_reader = *cov_reader_or;
    auto& branch_reader = *branch_reader_or;

    const auto input = KnownInput();
    const auto expected = ExpectedRecords();
    const std::span<const std::uint8_t> bytes{input.data(), input.size()};

    // Five iterations: the records and edge coverage must be identical
    // each run (deterministic; the server resets both segments before
    // each spawn).
    for (int iter = 0; iter < 5; ++iter) {
        auto rr = session.Run(bytes);
        ASSERT_TRUE(rr.has_value())
            << "iter " << iter << " Run failed: " << static_cast<int>(rr.error());
        EXPECT_EQ(rr->status(), v1::EXEC_STATUS_OK) << "iter " << iter;

        // (3) RunResponse branch summary.
        ASSERT_TRUE(rr->has_branch_result()) << "iter " << iter << ": no branch_result";
        EXPECT_EQ(rr->branch_result().record_count(), 5u) << "iter " << iter;
        EXPECT_FALSE(rr->branch_result().overflow()) << "iter " << iter;

        // (1)+(2) Records read from the announced memfd match the
        // expected format/values exactly.
        EXPECT_EQ(branch_reader.RecordCount(), 5u) << "iter " << iter;
        EXPECT_FALSE(branch_reader.Overflow()) << "iter " << iter;
        const auto recs = branch_reader.Records();
        ASSERT_EQ(recs.size(), expected.size()) << "iter " << iter;
        for (std::size_t i = 0; i < expected.size(); ++i) {
            EXPECT_EQ(recs[i].site_id, expected[i].site_id) << "iter " << iter << " rec " << i;
            EXPECT_EQ(recs[i].predicate, expected[i].predicate) << "iter " << iter << " rec " << i;
            EXPECT_EQ(recs[i].bit_width, expected[i].bit_width) << "iter " << iter << " rec " << i;
            EXPECT_EQ(recs[i].lhs, expected[i].lhs) << "iter " << iter << " rec " << i;
            EXPECT_EQ(recs[i].rhs, expected[i].rhs) << "iter " << iter << " rec " << i;
        }

        // (4) Edge channel still works on the same run.
        EXPECT_TRUE(AnyNonZero(cov_reader.Read()))
            << "iter " << iter << ": edge bitmap empty (branch broke edge)";
    }

    // First-run edge coverage is new relative to the server's global
    // seen-map; assert at least the handshake's edge_result plumbing
    // is intact by re-running a fresh-ish check is unnecessary — the
    // non-empty bitmap above already proves edge delivery.
}

}  // namespace
}  // namespace mlfuzzz3::ipc
