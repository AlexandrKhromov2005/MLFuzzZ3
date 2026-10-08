// End-to-end campaign concolic integration on the add_gate fixture — the
// SECOND solver-requiring oracle in the tree (ADR 0036 §Тестирование), on
// a gate shaped differently from cov_xfield's cross-field wrap.
//
// The gate is `a + b == 0xDEADBEEF` over two verbatim u32 LE fields,
// nested inside guard() so that no degenerate "solution" counts
// (tests/fixtures/add_gate/gate_guard.h; the degenerate families are
// enumerated and shown rejected in
// tests/integration/solver/test_add_gate_smoke.cpp). The compared value —
// the sum — is not present in the input, which is why AFL++ cmplog does
// not take this gate (task-012: 0 crashes in 9.1M execs) while our
// concolic arm does (docs/experiments/kaddvars-solver-arm/report.md:
// 500-600 execs to crash).
//
// A real exec-server runs the fixture; a CampaignLoop with a production
// SessionRunner fuzzes the solver arm's own seed (a = 0x44332211,
// b = 0x2A2B2C2D — inside guard, sum 0x6E5E4E3E, no crash). Byte-flip
// mutation cannot realistically drive two independent fields to a fixed
// sum while both stay inside the band with all eight bytes non-zero, so
// the seed stalls; once its per-seed stagnation counter crosses the
// (test-lowered) threshold the loop itself invokes concolic, which solves
// the addition and reaches the abort.
//
// The positive test alone would only prove "a crash happened". The
// negative control is what makes it evidence about the SOLVER: the same
// campaign, same seed, same RNG seed and the same 200-exec budget, with
// only the stagnation threshold moved beyond that budget, must spend the
// whole budget without a single concolic call and without a crash.
//
// A FixedScheduler always selects seed 0 so its counter climbs
// deterministically; with a fixed RNG seed the whole campaign is
// reproducible. Self-skips when any artifact is unavailable.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "campaign.h"
#include "corpus.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"

namespace mlfuzzz3::core {
namespace {

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

// Empty when every artifact this oracle needs is present; otherwise the
// reason to skip. Same set of artifacts as the cov_xfield campaign oracle.
std::string MissingArtifact() {
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_BIN;
    }
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing: ") + ADD_GATE_BIN;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_PATH;
    }
    return {};
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger.
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// The solver arm's own seed (docs/experiments/kaddvars-solver-arm/run.sh:36):
// a = 0x44332211, b = 0x2A2B2C2D (LE). Both operands are inside
// [LO, HI] with all four bytes non-zero, so guard() passes and the gate
// comparison is reached and logged; the sum 0x6E5E4E3E is not MAGIC, so
// the seed itself runs clean (pinned by
// AddGateSmoke.ArmSeedDoesNotCrash).
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Shared budget of both campaigns. The stagnation threshold is the ONLY
// difference between the positive run and the negative control.
constexpr std::uint64_t kMaxIterations = 200;
constexpr std::uint64_t kRngSeed = 7;

// Runs one bounded campaign over the add_gate fixture in its own
// workspace. Fatal assertions inside report against the calling test;
// callers must bail out on ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint32_t stagnation_threshold, const char* workspace,
                 CampaignStats& out_stats) {
    const std::filesystem::path base = std::filesystem::path(::testing::TempDir()) / workspace;
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    const std::filesystem::path seed_dir = base / "seeds";
    std::filesystem::create_directories(seed_dir);
    {
        std::ofstream out(seed_dir / "add_gate", std::ios::binary);
        out.write(reinterpret_cast<const char*>(kArmSeed.data()),
                  static_cast<std::streamsize>(kArmSeed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_GE(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-e2e");
    ASSERT_TRUE(metrics.has_value());

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(EXEC_SERVER_BIN, ADD_GATE_BIN, COV_LIBRARY_PATH, proc, spawn_err))
        << spawn_err;

    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn), ipc::ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    SessionRunner runner(*session);
    FixedScheduler scheduler;
    mutation::ByteFlipMutator mutator;
    const CampaignConfig cfg{.max_iterations = kMaxIterations,
                             .metrics_interval = 0,
                             .rng_seed = kRngSeed,
                             .max_det_steps = 0,
                             .concolic_stagnation_threshold = stagnation_threshold,
                             .concolic_timeout_ms = 2000};

    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, cfg);
    out_stats = loop.Run();

    std::filesystem::remove_all(base, ec);
}

// The positive half of the add_gate / sub_gate control pair is read off the
// same raw ctest log as the negative half (task-032), so both runs print the
// same six counters in the same shape whether they pass or fail. Printing
// only; no assertion depends on it.
void PrintCounters(const char* label, const CampaignStats& s) {
    std::cout << label << " crashed=" << (s.crashes > 0 ? "yes" : "no") << " execs=" << s.execs
              << " concolic_calls=" << s.concolic_calls
              << " concolic_candidates=" << s.concolic_candidates
              << " concolic_edges=" << s.concolic_edges
              << " concolic_crashes=" << s.concolic_crashes
              << " concolic_unsat=" << s.concolic_unsat
              << " concolic_no_binding=" << s.concolic_no_binding
              << " concolic_timeout=" << s.concolic_timeout << '\n';
}

TEST(CampaignAddGateE2E, CampaignReachesCrashViaConcolicOnStagnation) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    CampaignStats stats;
    RunCampaign(/*stagnation_threshold=*/8, "mlfuzzz3_campaign_add_gate_e2e", stats);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    PrintCounters("POSITIVE-CONTROL-ADD", stats);

    EXPECT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";
    EXPECT_GT(stats.concolic_calls, 0U) << "stagnation never triggered concolic";
    EXPECT_GT(stats.concolic_crashes, 0U)
        << "concolic did not solve a + b == MAGIC (calls=" << stats.concolic_calls
        << ", candidates=" << stats.concolic_candidates << ", unsat=" << stats.concolic_unsat
        << ", timeout=" << stats.concolic_timeout << ")";
    // Every crash here is the guarded addition gate, unreachable by
    // byte-flip mutation: the crashes are the concolic ones.
    EXPECT_EQ(stats.crashes, stats.concolic_crashes);
}

// The control that makes the test above evidence about the solver rather
// than about the fixture: identical seed, RNG seed and exec budget, with
// the stagnation threshold moved past the budget so no concolic step can
// occur. The full budget is spent (execs == kMaxIterations) and nothing
// crashes.
TEST(CampaignAddGateE2E, SameBudgetWithoutConcolicNeverReachesCrash) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    CampaignStats stats;
    // Unreachable within kMaxIterations havoc selections of the single seed.
    RunCampaign(/*stagnation_threshold=*/static_cast<std::uint32_t>(kMaxIterations * 10),
                "mlfuzzz3_campaign_add_gate_negctl", stats);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    PrintCounters("POSITIVE-CONTROL-ADD-NOCONCOLIC", stats);

    EXPECT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";
    EXPECT_EQ(stats.execs, kMaxIterations) << "control did not spend the same budget";
    EXPECT_EQ(stats.concolic_calls, 0U) << "concolic fired despite the out-of-budget threshold";
    EXPECT_EQ(stats.crashes, 0U)
        << "mutation alone reached the gate — the positive test proves nothing";
}

}  // namespace
}  // namespace mlfuzzz3::core
