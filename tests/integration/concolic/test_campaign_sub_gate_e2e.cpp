// End-to-end campaign concolic run on the sub_gate fixture — the NEGATIVE
// control of the add_gate pair (task-032, ADR 0036 §Тестирование).
//
// The gate is `a - b == 0xDEADBEEF` over the same two verbatim u32 LE
// fields, inside the same guard(), at the same -O1 with the same plugin
// order as the positive control (tests/fixtures/sub_gate/CMakeLists.txt:
// 9-33). The fixture differs from add_gate in exactly one operator, and
// this oracle differs from test_campaign_add_gate_e2e.cpp in exactly the
// target binary: same seed, same RNG seed, same 200-exec budget, same
// stagnation threshold, same campaign config. Anything the two runs do
// differently is therefore owed to the algebraic form and to nothing else.
//
// What the pair is for. The solver domain map calls the sum BOUND and the
// difference NO-BINDING (docs/experiments/solver-domain-map/report.md:138),
// but that verdict comes from direct BuildSystem calls and has never been
// checked on a target. The positive control alone shows the solver takes
// SOME gate; only a negative control on the same program shape shows where
// its domain ENDS.
//
// Why the assertion is about the crash and not about candidates. The map
// records that all seven forms return kCandidate, so a NO-BINDING form is
// indistinguishable from a BOUND one by outcome code — the candidate is
// produced and useless. The distinguishing observable is whether the gate
// falls, so this test gates on crashes and merely RECORDS the counters
// (they are printed for the raw ctest log the report is built from).
//
// concolic_calls > 0 is asserted, not recorded: without it "no crash"
// would also be satisfied by a campaign where the concolic arm never
// fired, which measures the loop rather than the solver.
//
// Self-skips on exactly the same artifacts as the add_gate oracle, so a
// tree without clang or without the Z3 arm stays green.

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
// reason to skip. Same set of artifacts as the add_gate campaign oracle,
// with the difference fixture in place of the sum one.
std::string MissingArtifact() {
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_BIN;
    }
    if (!PathExecutable(SUB_GATE_BIN)) {
        return std::string("sub_gate fixture missing: ") + SUB_GATE_BIN;
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

// Byte-for-byte the positive control's seed
// (test_campaign_add_gate_e2e.cpp:145): a = 0x44332211, b = 0x2A2B2C2D
// (LE). Both operands are inside [LO, HI] with all four bytes non-zero, so
// guard() passes and the gate comparison is reached and logged; the
// difference 0x1A07F5E4 is not MAGIC, so the seed itself runs clean.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Copied from the positive control unchanged — the criterion of the
// negative control is that budget, RNG seed and threshold do not move.
constexpr std::uint64_t kMaxIterations = 200;
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;

// Runs one bounded campaign over the sub_gate fixture in its own
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
        std::ofstream out(seed_dir / "sub_gate", std::ios::binary);
        out.write(reinterpret_cast<const char*>(kArmSeed.data()),
                  static_cast<std::streamsize>(kArmSeed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_GE(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "sub-gate-e2e");
    ASSERT_TRUE(metrics.has_value());

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(EXEC_SERVER_BIN, SUB_GATE_BIN, COV_LIBRARY_PATH, proc, spawn_err))
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

// The raw ctest log is the evidence the report is written from, so the run
// prints its six counters whether it passes or fails.
void PrintCounters(const CampaignStats& s) {
    std::cout << "NEGATIVE-CONTROL-SUB crashed=" << (s.crashes > 0 ? "yes" : "no")
              << " execs=" << s.execs << " concolic_calls=" << s.concolic_calls
              << " concolic_candidates=" << s.concolic_candidates
              << " concolic_edges=" << s.concolic_edges
              << " concolic_crashes=" << s.concolic_crashes
              << " concolic_unsat=" << s.concolic_unsat
              << " concolic_no_binding=" << s.concolic_no_binding
              << " concolic_timeout=" << s.concolic_timeout << '\n';
}

TEST(CampaignSubGateE2E, ConcolicFiresAndTheDifferenceGateStandsUnbroken) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    CampaignStats stats;
    RunCampaign(kStagnationThreshold, "mlfuzzz3_campaign_sub_gate_e2e", stats);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    PrintCounters(stats);

    EXPECT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";
    // Separates "the solver did not take the gate" from "the campaign as a
    // whole did not get there": without a single call nothing about the
    // solver has been measured.
    ASSERT_GT(stats.concolic_calls, 0U) << "stagnation never triggered concolic — nothing measured";

    // The map's prediction, checked end-to-end for the first time. If this
    // fires, the map is REFUTED on a target and that is the finding: the
    // candidate the difference form produces turned out to be useful after
    // all, and the report says so instead of the expected verdict.
    EXPECT_EQ(stats.concolic_crashes, 0U)
        << "solver cracked a - b == MAGIC; the domain map calls the difference NO-BINDING "
           "(docs/experiments/solver-domain-map/report.md:138) — REFUTED on target";
    EXPECT_EQ(stats.crashes, 0U) << "the difference gate fell inside the same budget the positive "
                                    "control uses; see the counters printed above";
}

}  // namespace
}  // namespace mlfuzzz3::core
