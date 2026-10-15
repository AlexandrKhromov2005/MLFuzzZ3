// What this measures. The minimal `max_iterations` budget at which the
// add_gate_be campaign still reaches the crash, and the same number taken by
// the same rule on the little-endian donor fixture in the same run (task-080,
// ADR-0047). The question is whether the published price of the verbatim niche
// — min_budget_crash=18 on seed 7,
// docs/experiments/solver-add-gate-crash-budget/report.md:10 — carries across
// the byte order of the fields, or is a property of one byte layout.
//
// What was missing. The domain map
// (docs/experiments/solver-domain-form-width-endian/report.md:95,
// endian_dependent_forms=none) settles BINDING across byte order by direct
// unit-level calls into the system builder. It says nothing about the PRICE in
// a campaign: before this harness the price had been measured on exactly one
// encoding.
//
// Method, fixed before the run. Binary search over [1, 200] by the rule of
// task-067 (test_add_gate_crash_budget.cpp:366-377), entered only after the
// upper bound is shown to crash; the donor RNG seed 7, the donor input seed
// bytes and the donor stagnation threshold 8; a hard wall-time budget of 900
// seconds as a constant below. The little-endian control runs FIRST, through
// this same harness and this same rule, so the stand is established before the
// measurement it is supposed to license: if the control does not return 18,
// every BE line in the report is undproven and no conclusion is drawn.
//
// What the numbers may NOT be compared against. The BE minimum is compared
// with the LE minimum ON SEED 7 ONLY. The seed-spread ensemble median 12
// (docs/experiments/solver-add-gate-budget-seed-spread/report.md:11-12) is a
// different population and is not a denominator here.
//
// Two controls make the BE number mean the solver rather than the harness:
//   * the little-endian donor fixture under the identical protocol, which must
//     return the published 18;
//   * the same budget on add_gate_be with the stagnation threshold pushed past
//     it, so no concolic call can occur — if THAT crashes, byte-flip mutation
//     reached the gate and the budget says nothing about the solver arm.
//
// A BE gate not taken by 200 is a RESULT, not a harness failure: be_cracked=no
// is published, 200 is reported as the upper bound the search reached and not
// as proof of impossibility, and the test still passes.
//
// The campaign plumbing below (exec-server spawn, fixed scheduler, RunCampaign,
// PrintProbe, Probe1, MonotonicOverLog) is copied unchanged from
// test_add_gate_crash_budget.cpp, which is not modified by this task.
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
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "campaign.h"
#include "corpus.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"
#include "strict_budget_controls.h"

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
    if (!PathExecutable(ADD_GATE_BE_BIN)) {
        return std::string("add_gate_be fixture missing: ") + ADD_GATE_BE_REL;
    }
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing (little-endian control): ") + ADD_GATE_REL;
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
// The solver arm's own seed, byte for byte the donor's
// (test_add_gate_crash_budget.cpp:194). Under the BIG-endian fixture the same
// eight bytes decode to a = 0x11223344, b = 0x2D2C2B2A -- both inside guard(),
// sum 0x3E4E5E6E != MAGIC, so the seed itself runs clean on the BE fixture
// exactly as it does on the LE one. Not re-encoded for BE on purpose: the task
// varies the byte order of the TARGET, not the input the arm starts from.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Fixed across the whole sweep -- the budget is the ONLY thing that moves, and
// both values are the donor's (test_add_gate_crash_budget.cpp:199-200).
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;

// Search interval and rule, both fixed before the run: the donor's interval
// (test_add_gate_crash_budget.cpp:204-205). Reaching 200 without a crash is
// the upper bound the search reached, not a proof that no budget works.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 200;

// The published little-endian number this stand must reproduce on seed 7
// (docs/experiments/solver-add-gate-crash-budget/report.md:10). It is an
// expectation about the STAND, not about the BE fixture.
constexpr std::uint64_t kControlLeExpected = test_support::strict_terminal_budget(18);

// Hard wall-time budget for the whole unit, named in the report before the
// run. Checked before every probe; when it is spent the sweep stops where it
// stands and publishes stop_reason=walltime instead of a number it did not
// finish earning.
constexpr double kWalltimeBudgetS = 900.0;

struct Probe {
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_enabled = true;
    const char* gate = "add_gate_be";
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
    EXPECT_LE(out_stats.execs, max_iterations) << "execution budget must include preparation";
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
// Convenience wrappers: the big-endian fixture under test, and the
// little-endian donor as the stand control. Both armed, both on the donor
// threshold, so the only difference between them is the fixture's byte order.
bool ProbeBe(const char* phase, int seq, std::uint64_t budget, std::vector<Probe>& log,
             CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    return Probe1(phase, seq, "add_gate_be", ADD_GATE_BE_BIN, "add_gate_be",
                  "add-gate-be-crash-budget", budget, kStagnationThreshold, /*armed=*/true,
                  "mlfuzzz3_add_gate_be_crash_budget", log, out_stats, out_wall_ms);
}

bool ProbeLe(const char* phase, int seq, std::uint64_t budget, std::vector<Probe>& log,
             CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    return Probe1(phase, seq, "add_gate", ADD_GATE_BIN, "add_gate", "add-gate-le-control-budget",
                  budget, kStagnationThreshold, /*armed=*/true,
                  "mlfuzzz3_add_gate_be_crash_budget_le", log, out_stats, out_wall_ms);
}

// The binary search of task-067, run over one fixture through `probe`. Returns
// false on a fatal assertion or when the wall-time budget ran out mid-search;
// `out_min` is meaningful only when it returns true.
template <typename ProbeFn, typename ClockFn>
bool BinarySearchMinBudget(ProbeFn probe, const char* phase, int& seq, std::vector<Probe>& log,
                           ClockFn elapsed_s, std::uint64_t& out_min, bool& out_walltime_spent) {
    std::uint64_t lo = kSearchLo;
    std::uint64_t hi = kSearchHi;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    while (lo < hi) {
        if (elapsed_s() > kWalltimeBudgetS) {
            out_walltime_spent = true;
            return false;
        }
        const std::uint64_t mid = lo + (hi - lo) / 2;
        if (!probe(phase, ++seq, mid, log, stats, wall_ms)) {
            return false;
        }
        if (stats.crashes > 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    out_min = lo;
    return true;
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
TEST(AddGateBeCrashBudget, MinimalBudgetThatStillReachesTheCrashBigEndian) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    std::cout << "BUDGET-META budget_units=strict_execs historical_controls=legacy_requested "
                 "terminal_control_adjustment=plus_one add_gate_be="
              << ADD_GATE_BE_REL << " add_gate=" << ADD_GATE_REL
              << " exec_server=" << EXEC_SERVER_REL << " cov_library=" << COV_LIBRARY_REL
              << " encoding=u32be fields_offsets=0|4 rng_seed=" << kRngSeed
              << " arm_seed=donor stagnation_threshold=" << kStagnationThreshold
              << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi
              << " rule=binary-search-task-067 control=le-seed7-only"
              << " control_le_expected=" << kControlLeExpected
              << " walltime_budget_s=" << kWalltimeBudgetS << '\n'
              << std::flush;

    std::vector<Probe> le_log;
    std::vector<Probe> be_log;
    std::vector<Probe> noconc_log;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    int seq = 0;
    std::string stop_reason = "crash";
    bool walltime_spent = false;

    // --- Control 1, run FIRST: the same harness and the same rule on the
    // little-endian donor fixture. It must return the published 18; until it
    // does, nothing measured below licenses a conclusion.
    ASSERT_TRUE(ProbeLe("le-control-ticket", ++seq, kSearchHi, le_log, stats, wall_ms));
    ASSERT_FALSE(stats.aborted) << "little-endian control campaign aborted on infrastructure "
                                   "errors";
    std::uint64_t control_le_min = 0;
    bool control_le_searched = false;
    if (stats.crashes > 0) {
        control_le_searched = BinarySearchMinBudget(ProbeLe, "le-control-search", seq, le_log,
                                                    elapsed_s, control_le_min, walltime_spent);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
    } else {
        ADD_FAILURE() << "little-endian donor fixture does not crash at budget " << kSearchHi
                      << " — the stand is broken, not the byte order";
    }
    const bool control_le_ok = control_le_searched && control_le_min == kControlLeExpected;
    EXPECT_TRUE(control_le_ok) << "little-endian control returned " << control_le_min
                               << " instead of expected strict budget " << kControlLeExpected
                               << "; every big-endian line in this run is undproven";

    // --- Entry ticket for the fixture under test: the upper bound of the
    // interval must actually crash, otherwise a binary search over [1, 200]
    // is meaningless and the honest outcome is be_cracked=no.
    bool be_cracked = false;
    if (!walltime_spent && elapsed_s() <= kWalltimeBudgetS) {
        ASSERT_TRUE(ProbeBe("ticket", ++seq, kSearchHi, be_log, stats, wall_ms));
        ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";
        be_cracked = stats.crashes > 0;
        if (!be_cracked) {
            stop_reason = "hi";
        }
    } else {
        walltime_spent = true;
    }

    // --- Binary search for the minimal crashing budget in [1, 200].
    std::uint64_t min_budget_be = 0;
    bool be_searched = false;
    if (be_cracked && !walltime_spent) {
        be_searched = BinarySearchMinBudget(ProbeBe, "search", seq, be_log, elapsed_s,
                                            min_budget_be, walltime_spent);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
    }
    if (walltime_spent) {
        stop_reason = "walltime";
    }

    // --- Probes around the transition point, plus the arming proof: at the
    // minimum the solver must have been called at least once, read off the
    // probe line rather than off the code.
    CampaignStats at_min;
    std::uint64_t wall_at_min = 0;
    bool crash_at_min = false;
    bool crash_at_min_minus_1 = false;
    if (be_searched) {
        ASSERT_TRUE(ProbeBe("probe-N", ++seq, min_budget_be, be_log, at_min, wall_at_min));
        crash_at_min = at_min.crashes > 0;
        EXPECT_GT(at_min.crashes, 0U) << "no crash at the budget the search called minimal";
        EXPECT_GE(at_min.concolic_calls, 1U) << "the solver arm never fired at the minimum — this "
                                                "probe says nothing about the solver";
        if (min_budget_be > kSearchLo && elapsed_s() <= kWalltimeBudgetS) {
            CampaignStats below;
            std::uint64_t wall_below = 0;
            ASSERT_TRUE(ProbeBe("probe-N-1", ++seq, min_budget_be - 1, be_log, below, wall_below));
            crash_at_min_minus_1 = below.crashes > 0;
            EXPECT_EQ(below.crashes, 0U) << "budget below the minimum crashes — the point is not "
                                            "the transition";
        }
        if (elapsed_s() <= kWalltimeBudgetS) {
            ASSERT_TRUE(ProbeBe("probe-N+1", ++seq, min_budget_be + 1, be_log, stats, wall_ms));
            EXPECT_GT(stats.crashes, 0U) << "no crash one above the transition point";
        }
    }

    // --- Control 2: the same budget on add_gate_be with the stagnation
    // threshold pushed past it, so no concolic call can occur. If this
    // crashes, byte-flip mutation reached the gate and the budget number
    // says nothing about the solver.
    bool control_noconc_no_crash = false;
    bool control_noconc_ran = false;
    if (be_searched && elapsed_s() <= kWalltimeBudgetS) {
        CampaignStats noconc_stats;
        std::uint64_t noconc_wall = 0;
        ASSERT_TRUE(Probe1("control-noconcolic", ++seq, "add_gate_be", ADD_GATE_BE_BIN,
                           "add_gate_be", "add-gate-be-crash-budget-noconcolic", min_budget_be,
                           static_cast<std::uint32_t>(min_budget_be * 10 + 10), /*armed=*/false,
                           "mlfuzzz3_add_gate_be_crash_budget_noconc", noconc_log, noconc_stats,
                           noconc_wall));
        control_noconc_ran = true;
        control_noconc_no_crash = noconc_stats.crashes == 0;
        EXPECT_EQ(noconc_stats.concolic_calls, 0U) << "concolic fired despite the out-of-budget "
                                                      "threshold — the control is not a control";
        EXPECT_EQ(noconc_stats.crashes, 0U) << "mutation alone reached the gate at the minimal "
                                               "budget";
    }

    // --- Monotonicity, checked separately over the armed probes of each
    // fixture: a crash at a smaller budget with none at a larger one refutes
    // it. The two fixtures are never mixed into one sequence.
    std::string witness_be;
    std::string witness_le;
    const bool monotonic =
        MonotonicOverLog(be_log, witness_be) && MonotonicOverLog(le_log, witness_le);
    if (!monotonic) {
        std::cout << "BUDGET-NONMONOTONIC witness_be=" << witness_be << " witness_le=" << witness_le
                  << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(monotonic) << "observation is not monotonic in the budget: " << witness_be << ' '
                           << witness_le;

    std::ostringstream ratio;
    if (be_searched && control_le_min > 0) {
        ratio << std::fixed << std::setprecision(2)
              << static_cast<double>(min_budget_be) / static_cast<double>(control_le_min);
    } else {
        ratio << "n/a";
    }
    std::ostringstream used;
    used << std::fixed << std::setprecision(1) << elapsed_s();

    std::cout << "BUDGET-VERDICT: ADD-GATE-BE-CRASH-BUDGET: encoding=u32be, fields_offsets=0|4"
              << ", rng_seed=" << kRngSeed << ", arm_seed=donor"
              << ", stagnation_threshold=" << kStagnationThreshold << ", search_range=" << kSearchLo
              << ".." << kSearchHi
              << ", probes=" << le_log.size() + be_log.size() + noconc_log.size()
              << ", be_cracked=" << (be_cracked ? "yes" : "no") << ", min_budget_be=";
    if (be_searched) {
        std::cout << min_budget_be;
    } else {
        std::cout << "none";
    }
    std::cout << ", crash_at_min=" << (crash_at_min ? "yes" : "no")
              << ", crash_at_min_minus_1=" << (crash_at_min_minus_1 ? "yes" : "no")
              << ", concolic_calls_at_min=" << at_min.concolic_calls
              << ", control_le_seed7_equals_18=" << (control_le_ok ? "yes" : "no")
              << ", control_le_min="
              << (control_le_searched ? std::to_string(control_le_min) : std::string("none"))
              << ", control_no_concolic_no_crash_at_min="
              << (control_noconc_ran ? (control_noconc_no_crash ? "yes" : "no") : "n/a")
              << ", ratio_be_over_le=" << ratio.str()
              << ", monotonic_verified=" << (monotonic ? "yes" : "no")
              << ", compared_against=le-seed7-only, domain_map_reclassified=no"
              << ", stop_reason=" << stop_reason << ", walltime_budget_s=" << kWalltimeBudgetS
              << ", walltime_used_s=" << used.str()
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
