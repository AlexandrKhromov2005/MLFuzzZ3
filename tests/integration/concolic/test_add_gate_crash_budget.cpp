// task-067 / ADR 0036 — the DENOMINATOR of the solver's reference cell:
// the minimal `max_iterations` budget at which the add_gate campaign still
// reaches its crash.
//
// What was missing. `add_gate` is the one gate in the tree our concolic arm
// takes and AFL++ with cmplog does not (0 finds in 9 147 655 execs,
// docs/experiments/cmplog-integer-addition-recon/report.md:105). That gives
// the superiority claim a numerator and no denominator: the existing oracle
// prints `execs=200` in every repeat, and that 200 is the BUDGET
// `kMaxIterations`, not the moment the gate falls
// (docs/experiments/solver-oracle-repeatability/report.md:181-187).
//
// How this harness gets the number WITHOUT touching src/. The campaign loop
// runs to budget exhaustion regardless of a crash, and `max_iterations`
// participates in exactly one place — the stop condition
// (src/core/campaign.cpp:339). So `stats.crashes > 0` under budget b means
// "the crash happened at some exec <= b", and the minimal such b is found
// from OUTSIDE by re-running the campaign with a truncated budget. This is
// an EXTERNAL estimate by repetition, not an in-run metric: the "exec of
// first crash" counter inside `CampaignStats` proposed by
// docs/experiments/solver-oracle-repeatability/report.md:194-195 is
// deliberately NOT added here — that is a src/ edit and the owner's call.
//
// Monotonicity is what makes a binary search legitimate, and it is CHECKED,
// not assumed: every probe is recorded, and a pair (b1 < b2) with crash at
// b1 and no crash at b2 would be reported as a finding rather than smoothed
// over by repeats.
//
// Two controls, both mandatory:
//   * the same protocol on `sub_gate` at the full budget must not crash —
//     otherwise the number describes the harness, not the addition gate;
//   * the same budget on `add_gate` with the stagnation threshold pushed
//     past it (no concolic call possible) must not crash — otherwise the
//     number describes byte-flip luck, not the solver.
//
// NOT the same number as "500-600 execs / under 0.5 s" from
// docs/experiments/kaddvars-solver-arm/report.md: that was a standalone arm
// on another repository state counting TARGET execs, this counts campaign
// iterations through this gtest harness. The report keeps them apart.
//
// Structural donor: RunCampaign() and its exec-server plumbing from
// tests/integration/concolic/test_campaign_add_gate_e2e.cpp:184-230, copied
// (that file is not modified) and parameterised by fixture and budget.
//
// Every path printed is relative to the repository root, so the raw log
// carries no absolute paths. Self-skips when any artifact is unavailable.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

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

// Empty when every artifact this sweep needs is present; otherwise the
// reason to skip. The message names artifacts by their REPO-RELATIVE path
// so that even a skipped run leaves no absolute path in the raw log.
std::string MissingArtifact() {
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_REL;
    }
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing: ") + ADD_GATE_REL;
    }
    if (!PathExecutable(SUB_GATE_BIN)) {
        return std::string("sub_gate fixture missing: ") + SUB_GATE_REL;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_REL;
    }
    return {};
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger (donor:
// test_campaign_add_gate_e2e.cpp:158-166).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// The solver arm's own seed, byte for byte the one both existing oracles
// use (test_campaign_add_gate_e2e.cpp:174): a = 0x44332211,
// b = 0x2A2B2C2D (LE). Inside guard(), and neither the sum nor the
// difference is MAGIC, so the seed itself runs clean on both fixtures.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Fixed across the whole sweep — the budget is the ONLY thing that moves.
// Both values are the existing oracle's
// (test_campaign_add_gate_e2e.cpp:178-179, :253).
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;

// Search interval mandated by the task: the crash is known to occur by 200
// (docs/experiments/solver-oracle-repeatability/report.md:190-192).
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 200;

// Repeats of the transition point and of the point below it.
constexpr int kRepeats = 5;

struct Probe {
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_enabled = true;
    const char* gate = "add_gate";
};

// One bounded campaign, its counters and its wall time. Fatal assertions
// inside report against the calling test; callers must bail out on
// ::testing::Test::HasFatalFailure().
void RunCampaign(const char* fixture_bin, const char* seed_name, const char* metrics_tag,
                 std::uint64_t max_iterations, std::uint32_t stagnation_threshold,
                 const char* workspace, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    const std::filesystem::path base = std::filesystem::path(::testing::TempDir()) / workspace;
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    const std::filesystem::path seed_dir = base / "seeds";
    std::filesystem::create_directories(seed_dir);
    {
        std::ofstream out(seed_dir / seed_name, std::ios::binary);
        out.write(reinterpret_cast<const char*>(kArmSeed.data()),
                  static_cast<std::streamsize>(kArmSeed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_GE(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", metrics_tag);
    ASSERT_TRUE(metrics.has_value());

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(EXEC_SERVER_BIN, fixture_bin, COV_LIBRARY_PATH, proc, spawn_err))
        << spawn_err;

    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn), ipc::ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    SessionRunner runner(*session);
    FixedScheduler scheduler;
    mutation::ByteFlipMutator mutator;
    const CampaignConfig cfg{.max_iterations = max_iterations,
                             .metrics_interval = 0,
                             .rng_seed = kRngSeed,
                             .max_det_steps = 0,
                             .concolic_stagnation_threshold = stagnation_threshold,
                             .concolic_timeout_ms = 2000};

    const auto t0 = std::chrono::steady_clock::now();
    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, cfg);
    out_stats = loop.Run();
    const auto t1 = std::chrono::steady_clock::now();
    out_wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    std::filesystem::remove_all(base, ec);
}

// Every measured number in the report is read off one of these lines. The
// shape is fixed so that a rerun differs only in `wall_ms`.
void PrintProbe(const char* phase, int seq, const Probe& p, const CampaignStats& s,
                std::uint64_t wall_ms) {
    std::cout << "BUDGET-PROBE phase=" << phase << " seq=" << seq << " gate=" << p.gate
              << " budget=" << p.budget << " concolic=" << (p.concolic_enabled ? "on" : "off")
              << " crashed=" << (s.crashes > 0 ? "yes" : "no") << " execs=" << s.execs
              << " crashes=" << s.crashes << " concolic_calls=" << s.concolic_calls
              << " concolic_candidates=" << s.concolic_candidates
              << " concolic_crashes=" << s.concolic_crashes
              << " concolic_unsat=" << s.concolic_unsat
              << " concolic_no_binding=" << s.concolic_no_binding
              << " concolic_timeout=" << s.concolic_timeout
              << " aborted=" << (s.aborted ? "yes" : "no") << " wall_ms=" << wall_ms << '\n'
              << std::flush;
}

// Runs one probe, records it in `log`, and reports whether it crashed.
// Returns false when a fatal assertion fired inside RunCampaign.
bool Probe1(const char* phase, int seq, const char* gate, const char* fixture_bin,
            const char* seed_name, const char* metrics_tag, std::uint64_t budget,
            std::uint32_t stagnation_threshold, bool armed, const char* workspace,
            std::vector<Probe>& log, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    RunCampaign(fixture_bin, seed_name, metrics_tag, budget, stagnation_threshold, workspace,
                out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    Probe p;
    p.budget = budget;
    p.crashed = out_stats.crashes > 0;
    p.concolic_enabled = armed;
    p.gate = gate;
    log.push_back(p);
    PrintProbe(phase, seq, p, out_stats, out_wall_ms);
    return true;
}

// Convenience wrapper for the common case: add_gate, concolic armed.
bool ProbeAdd(const char* phase, int seq, std::uint64_t budget, std::vector<Probe>& log,
              CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    return Probe1(phase, seq, "add_gate", ADD_GATE_BIN, "add_gate", "add-gate-crash-budget", budget,
                  kStagnationThreshold, /*armed=*/true, "mlfuzzz3_add_gate_crash_budget", log,
                  out_stats, out_wall_ms);
}

// A pair (b1 < b2) with a crash at b1 and none at b2 refutes monotonicity of
// the observation in the budget. Checked over ALL add_gate probes with
// concolic armed, not derived from reading the stop condition.
bool MonotonicOverLog(const std::vector<Probe>& log, std::string& out_witness) {
    for (const Probe& lo : log) {
        if (!lo.concolic_enabled || !lo.crashed) {
            continue;
        }
        for (const Probe& hi : log) {
            if (!hi.concolic_enabled || hi.crashed) {
                continue;
            }
            if (hi.budget > lo.budget) {
                out_witness = "crash at budget=" + std::to_string(lo.budget) +
                              " but none at budget=" + std::to_string(hi.budget);
                return false;
            }
        }
    }
    return true;
}

TEST(AddGateCrashBudget, MinimalBudgetThatStillReachesTheCrash) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    std::cout << "BUDGET-META add_gate=" << ADD_GATE_REL << " sub_gate=" << SUB_GATE_REL
              << " exec_server=" << EXEC_SERVER_REL << " cov_library=" << COV_LIBRARY_REL
              << " rng_seed=" << kRngSeed << " stagnation_threshold=" << kStagnationThreshold
              << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi << " repeats=" << kRepeats
              << '\n'
              << std::flush;

    std::vector<Probe> log;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    int seq = 0;

    // --- Entry ticket: the upper bound of the interval must actually crash.
    // Without it a binary search over [1, 200] is meaningless.
    ASSERT_TRUE(ProbeAdd("ticket", ++seq, kSearchHi, log, stats, wall_ms));
    ASSERT_GT(stats.crashes, 0U) << "upper bound of the search interval does not crash";
    ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";

    // --- Binary search for the minimal crashing budget in [1, 200].
    std::uint64_t lo = kSearchLo;
    std::uint64_t hi = kSearchHi;
    while (lo < hi) {
        const std::uint64_t mid = lo + (hi - lo) / 2;
        ASSERT_TRUE(ProbeAdd("search", ++seq, mid, log, stats, wall_ms));
        if (stats.crashes > 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    const std::uint64_t min_budget = lo;

    // --- Probes around the transition point: N-1, N, N+1, N+8.
    CampaignStats at_min;
    std::uint64_t wall_at_min = 0;
    ASSERT_TRUE(ProbeAdd("probe-N", ++seq, min_budget, log, at_min, wall_at_min));
    EXPECT_GT(at_min.crashes, 0U) << "no crash at the budget the search called minimal";

    bool crash_at_min_minus_1 = false;
    if (min_budget > kSearchLo) {
        CampaignStats below;
        std::uint64_t wall_below = 0;
        ASSERT_TRUE(ProbeAdd("probe-N-1", ++seq, min_budget - 1, log, below, wall_below));
        crash_at_min_minus_1 = below.crashes > 0;
        EXPECT_EQ(below.crashes, 0U) << "budget below the minimum crashes — the point is not the "
                                        "transition";
    }

    ASSERT_TRUE(ProbeAdd("probe-N+1", ++seq, min_budget + 1, log, stats, wall_ms));
    EXPECT_GT(stats.crashes, 0U) << "no crash one above the transition point";
    ASSERT_TRUE(ProbeAdd("probe-N+8", ++seq, min_budget + 8, log, stats, wall_ms));
    EXPECT_GT(stats.crashes, 0U) << "no crash eight above the transition point";

    // --- Repeats of the point and of the point below it. Per repeat the
    // observed transition is min-1 if that already crashes, min if only min
    // does, and min+1 as an out-of-band marker if neither does; `spread` is
    // the width of that observation over the repeats.
    std::uint64_t obs_lo = min_budget;
    std::uint64_t obs_hi = min_budget;
    for (int r = 1; r <= kRepeats; ++r) {
        CampaignStats rep_min;
        std::uint64_t rep_wall = 0;
        ASSERT_TRUE(ProbeAdd("repeat-N", ++seq, min_budget, log, rep_min, rep_wall));

        bool rep_below_crashed = false;
        if (min_budget > kSearchLo) {
            CampaignStats rep_below;
            std::uint64_t rep_below_wall = 0;
            ASSERT_TRUE(
                ProbeAdd("repeat-N-1", ++seq, min_budget - 1, log, rep_below, rep_below_wall));
            rep_below_crashed = rep_below.crashes > 0;
        }

        const std::uint64_t observed = rep_below_crashed     ? min_budget - 1
                                       : rep_min.crashes > 0 ? min_budget
                                                             : min_budget + 1;
        obs_lo = std::min(obs_lo, observed);
        obs_hi = std::max(obs_hi, observed);
    }
    const std::uint64_t spread = obs_hi - obs_lo;

    // --- Control 1: the same protocol on sub_gate at the full budget. The
    // difference gate is the tree's standing negative control
    // (test_campaign_sub_gate_e2e.cpp:264-269); if it falls here, the number
    // above describes the harness rather than the addition gate.
    std::vector<Probe> sub_log;
    CampaignStats sub_stats;
    std::uint64_t sub_wall = 0;
    ASSERT_TRUE(Probe1("control-sub", ++seq, "sub_gate", SUB_GATE_BIN, "sub_gate",
                       "sub-gate-crash-budget", kSearchHi, kStagnationThreshold, /*armed=*/true,
                       "mlfuzzz3_sub_gate_crash_budget", sub_log, sub_stats, sub_wall));
    const bool control_sub_no_crash = sub_stats.crashes == 0;
    EXPECT_EQ(sub_stats.crashes, 0U) << "sub_gate fell under the same protocol";

    // --- Control 2: the same budget on add_gate with the stagnation
    // threshold pushed past it, so no concolic call can occur. If this
    // crashes, byte-flip mutation reached the gate and the budget number
    // says nothing about the solver.
    std::vector<Probe> noconc_log;
    CampaignStats noconc_stats;
    std::uint64_t noconc_wall = 0;
    ASSERT_TRUE(Probe1("control-noconcolic", ++seq, "add_gate", ADD_GATE_BIN, "add_gate",
                       "add-gate-crash-budget-noconcolic", min_budget,
                       static_cast<std::uint32_t>(min_budget * 10 + 10), /*armed=*/false,
                       "mlfuzzz3_add_gate_crash_budget_noconc", noconc_log, noconc_stats,
                       noconc_wall));
    const bool control_noconc_no_crash = noconc_stats.crashes == 0;
    EXPECT_EQ(noconc_stats.concolic_calls, 0U) << "concolic fired despite the out-of-budget "
                                                  "threshold — the control is not a control";
    EXPECT_EQ(noconc_stats.crashes, 0U) << "mutation alone reached the gate at the minimal budget";

    // --- Monotonicity, checked over every add_gate probe taken above.
    std::string witness;
    const bool monotonic = MonotonicOverLog(log, witness);
    if (!monotonic) {
        std::cout << "BUDGET-NONMONOTONIC witness=" << witness << '\n' << std::flush;
    }
    EXPECT_TRUE(monotonic) << "observation is not monotonic in the budget: " << witness;

    std::cout << "BUDGET-VERDICT: ADD-GATE-CRASH-BUDGET: min_budget_crash=" << min_budget
              << ", probes=" << log.size() + sub_log.size() + noconc_log.size()
              << ", crash_at_min=" << (at_min.crashes > 0 ? "yes" : "no")
              << ", crash_at_min_minus_1=" << (crash_at_min_minus_1 ? "yes" : "no")
              << ", monotonic_verified=" << (monotonic ? "yes" : "no") << ", repeats=" << kRepeats
              << ", spread=" << spread << ", concolic_calls_at_min=" << at_min.concolic_calls
              << ", concolic_crashes_at_min=" << at_min.concolic_crashes
              << ", wall_ms_at_min=" << wall_at_min
              << ", control_sub_gate_no_crash_at_200=" << (control_sub_no_crash ? "yes" : "no")
              << ", control_no_concolic_no_crash_at_min="
              << (control_noconc_no_crash ? "yes" : "no")
              << ", kaddvars_arm_number_kept_separate=yes, src_modified=0, "
                 "new_benchmark_campaigns=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
