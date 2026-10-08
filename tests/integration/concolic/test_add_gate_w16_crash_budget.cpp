// What this measures. Where the verbatim niche ENDS along the field-WIDTH
// axis: the minimal `max_iterations` budget at which the campaign still
// reaches the crash on a 16-bit twin of the add_gate fixture, the same number
// taken by the same rule on the 32-bit donor in the same process, and -- the
// question the task actually turns on -- whether the disarmed arm takes the
// 16-bit gate at all (task-102, ADR-0047).
//
// What was missing. The whole price series of the niche was measured at ONE
// field width, u32 (tests/fixtures/add_gate/add_gate.c). The byte-order axis
// was closed by task-080 (tests/fixtures/add_gate_be/, minimum 11 against the
// donor's 18) and the stagnation-threshold axis by task-081; the WIDTH axis
// had no cell in the matrix at all. Worse, the niche is called
// "solver-requiring" because the disarmed arm does not take the gate in 409600
// execs (docs/experiments/solver-add-gate-ceiling-depth/) -- and that was
// measured at 32 bits, where the pair space is 2^64. At 16 bits it is 2^32,
// and whether mutation alone reaches the gate there is simply unknown.
//
// Both outcomes are results. noconcolic_w16_cracked=yes is a MEASURED LOWER
// BOUND of the niche by width: the gate stops being solver-requiring once the
// fields are small enough, and the claim about the niche has to carry that
// limit. noconcolic_w16_cracked=no at the ladder ceiling means the niche holds
// at 16 bits too, published with the budget it was searched to -- an upper
// bound of the search, never a proof of impossibility. Neither outcome fails
// this test, so nothing below asserts on the disarmed arm's crash count.
//
// Method, fixed before the run. Binary search over [1, 200] by the rule of
// task-067 (test_add_gate_crash_budget.cpp:366-377), entered only after the
// upper bound is shown to crash; the donor RNG seed 7, the donor input seed
// bytes and the donor stagnation threshold 8; a hard wall-time budget of 900
// seconds as a constant below. The 32-bit control runs FIRST, through this
// same harness and this same rule, so the stand is established before the
// measurement it is supposed to license: if the control does not return 18,
// every 16-bit line in this run is unproven and no conclusion is drawn.
//
// What the numbers may NOT be compared against. The w16 minimum is compared
// with the u32 minimum ON SEED 7 ONLY. The seed-spread ensemble median 12
// (docs/experiments/solver-add-gate-budget-seed-spread/report.md:11-12) is a
// different population and is not a denominator here.
//
// Two things make the w16 number mean the solver rather than the harness:
//   * the 32-bit donor fixture under the identical protocol, which must return
//     the published 18;
//   * the disarmed ladder on add_gate_w16 itself, with the stagnation
//     threshold pushed past each budget so no concolic call can occur. If it
//     crashes, mutation reached the gate and min_budget_w16 is no longer a
//     price of the solver -- which is exactly what the VERDICT line reports.
//
// What this harness does NOT print. `repeats` and `spread` of the task's
// verdict line are properties of the RAW FILE assembled from two runs of this
// binary, not of one process; a single process cannot honestly print them and
// therefore does not. Everything else in that line is printed below.
//
// The campaign plumbing (exec-server spawn, fixed scheduler, RunCampaign,
// PrintProbe, Probe1, BinarySearchMinBudget, MonotonicOverLog) is copied from
// test_add_gate_be_crash_budget.cpp, which is not modified by this task. The
// only edit to it is one line in Probe1 recording the slowest probe into
// g_max_probe_wall_ms, because the task's verdict line names that number and
// the binary search does not otherwise expose the per-probe wall time.
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
    if (!PathExecutable(ADD_GATE_W16_BIN)) {
        return std::string("add_gate_w16 fixture missing: ") + ADD_GATE_W16_REL;
    }
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing (32-bit control): ") + ADD_GATE_REL;
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
// (test_add_gate_crash_budget.cpp:194). Under the 16-bit fixture the first
// four bytes decode to a = 0x2211, b = 0x4433 -- both inside the width-scaled
// guard (add_gate_w16.c:52-54), sum 0x6644 != MAGIC, so the seed runs clean
// and still reaches the inner comparison, exactly as it does on the donor.
// Bytes 4..7 are past the fields the 16-bit target reads and are left in place
// on purpose: the task varies the width of the TARGET's fields, not the input
// the arm starts from.
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

// The published 32-bit number this stand must reproduce on seed 7
// (docs/experiments/solver-add-gate-crash-budget/report.md:10). It is an
// expectation about the STAND, not about the 16-bit fixture.
constexpr std::uint64_t kControlU32Expected = 18;

// The disarmed ladder, capped by the task at 1600 iterations. Each rung runs
// add_gate_w16 with the stagnation threshold pushed past its own budget, so no
// concolic call can occur and only mutation is left. The ladder stops at the
// first rung that crashes; the deepest rung actually run is published as
// noconcolic_ceiling. Going deeper than 1600 is a separate task and is not
// done here, so `no` at the end of the ladder is a bound of THIS search.
constexpr std::array<std::uint64_t, 4> kNoconcolicLadder = {200, 400, 800, 1600};

// Hard wall-time budget for the whole unit, named in the report before the
// run. Checked before every probe; when it is spent the sweep stops where it
// stands and publishes stop_reason=walltime instead of a number it did not
// finish earning.
constexpr double kWalltimeBudgetS = 900.0;

// The slowest single probe of the run, in milliseconds. Recorded in Probe1,
// which every probe of every phase goes through, and published as
// max_probe_walltime_s: the wall-time budget above bounds the SWEEP, this
// bounds the worst single campaign inside it.
std::uint64_t g_max_probe_wall_ms = 0;

struct Probe {
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_enabled = true;
    const char* gate = "add_gate_w16";
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
    g_max_probe_wall_ms = std::max(g_max_probe_wall_ms, out_wall_ms);
    Probe p;
    p.budget = budget;
    p.crashed = out_stats.crashes > 0;
    p.concolic_enabled = armed;
    p.gate = gate;
    log.push_back(p);
    PrintProbe(phase, seq, p, out_stats, out_wall_ms);
    return true;
}
// Convenience wrappers: the 16-bit fixture under test, and the 32-bit donor as
// the stand control. Both armed, both on the donor threshold, so the only
// difference between them is the width of the target's fields.
bool ProbeW16(const char* phase, int seq, std::uint64_t budget, std::vector<Probe>& log,
              CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    return Probe1(phase, seq, "add_gate_w16", ADD_GATE_W16_BIN, "add_gate_w16",
                  "add-gate-w16-crash-budget", budget, kStagnationThreshold, /*armed=*/true,
                  "mlfuzzz3_add_gate_w16_crash_budget", log, out_stats, out_wall_ms);
}

bool ProbeU32(const char* phase, int seq, std::uint64_t budget, std::vector<Probe>& log,
              CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    return Probe1(phase, seq, "add_gate", ADD_GATE_BIN, "add_gate", "add-gate-u32-control-budget",
                  budget, kStagnationThreshold, /*armed=*/true,
                  "mlfuzzz3_add_gate_w16_crash_budget_u32", log, out_stats, out_wall_ms);
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
TEST(AddGateW16CrashBudget, MinimalBudgetThatStillReachesTheCrashWidth16) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    std::cout << "BUDGET-META add_gate_w16=" << ADD_GATE_W16_REL << " add_gate=" << ADD_GATE_REL
              << " exec_server=" << EXEC_SERVER_REL << " cov_library=" << COV_LIBRARY_REL
              << " encoding=u16le width_bits=16 fields_offsets=0|2 rng_seed=" << kRngSeed
              << " arm_seed=donor stagnation_threshold=" << kStagnationThreshold
              << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi
              << " rule=binary-search-task-067 control=u32-seed7-only"
              << " control_u32_expected=" << kControlU32Expected << " noconcolic_ladder=";
    for (std::size_t i = 0; i < kNoconcolicLadder.size(); ++i) {
        std::cout << (i == 0 ? "" : "|") << kNoconcolicLadder[i];
    }
    std::cout << " walltime_budget_s=" << kWalltimeBudgetS << '\n' << std::flush;

    std::vector<Probe> u32_log;
    std::vector<Probe> w16_log;
    std::vector<Probe> noconc_log;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    int seq = 0;
    std::string stop_reason = "crash";
    bool walltime_spent = false;

    // --- Control, run FIRST: the same harness and the same rule on the 32-bit
    // donor fixture. It must return the published 18; until it does, nothing
    // measured below licenses a conclusion.
    ASSERT_TRUE(ProbeU32("u32-control-ticket", ++seq, kSearchHi, u32_log, stats, wall_ms));
    ASSERT_FALSE(stats.aborted) << "32-bit control campaign aborted on infrastructure errors";
    std::uint64_t control_u32_min = 0;
    bool control_u32_searched = false;
    if (stats.crashes > 0) {
        control_u32_searched = BinarySearchMinBudget(ProbeU32, "u32-control-search", seq, u32_log,
                                                     elapsed_s, control_u32_min, walltime_spent);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
    } else {
        ADD_FAILURE() << "32-bit donor fixture does not crash at budget " << kSearchHi
                      << " — the stand is broken, not the field width";
    }
    const bool control_u32_ok = control_u32_searched && control_u32_min == kControlU32Expected;
    EXPECT_TRUE(control_u32_ok) << "32-bit control returned " << control_u32_min
                                << " instead of the published " << kControlU32Expected
                                << "; every 16-bit line in this run is unproven";

    // --- Entry ticket for the fixture under test: the upper bound of the
    // interval must actually crash, otherwise a binary search over [1, 200]
    // is meaningless and the honest outcome is w16_cracked=no.
    bool w16_cracked = false;
    if (!walltime_spent && elapsed_s() <= kWalltimeBudgetS) {
        ASSERT_TRUE(ProbeW16("ticket", ++seq, kSearchHi, w16_log, stats, wall_ms));
        ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";
        w16_cracked = stats.crashes > 0;
        if (!w16_cracked) {
            stop_reason = "hi";
        }
    } else {
        walltime_spent = true;
    }

    // --- Binary search for the minimal crashing budget in [1, 200].
    std::uint64_t min_budget_w16 = 0;
    bool w16_searched = false;
    if (w16_cracked && !walltime_spent) {
        w16_searched = BinarySearchMinBudget(ProbeW16, "search", seq, w16_log, elapsed_s,
                                             min_budget_w16, walltime_spent);
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
    if (w16_searched) {
        ASSERT_TRUE(ProbeW16("probe-N", ++seq, min_budget_w16, w16_log, at_min, wall_at_min));
        crash_at_min = at_min.crashes > 0;
        EXPECT_GT(at_min.crashes, 0U) << "no crash at the budget the search called minimal";
        EXPECT_GE(at_min.concolic_calls, 1U) << "the solver arm never fired at the minimum — this "
                                                "probe says nothing about the solver";
        if (min_budget_w16 > kSearchLo && elapsed_s() <= kWalltimeBudgetS) {
            CampaignStats below;
            std::uint64_t wall_below = 0;
            ASSERT_TRUE(
                ProbeW16("probe-N-1", ++seq, min_budget_w16 - 1, w16_log, below, wall_below));
            crash_at_min_minus_1 = below.crashes > 0;
            EXPECT_EQ(below.crashes, 0U) << "budget below the minimum crashes — the point is not "
                                            "the transition";
        }
        if (elapsed_s() <= kWalltimeBudgetS) {
            ASSERT_TRUE(ProbeW16("probe-N+1", ++seq, min_budget_w16 + 1, w16_log, stats, wall_ms));
            EXPECT_GT(stats.crashes, 0U) << "no crash one above the transition point";
        }
    }

    // --- The disarmed ladder on add_gate_w16: the same fixture, the same RNG
    // seed and the same input seed, with the stagnation threshold pushed past
    // each budget so no concolic call can occur. This is the measurement the
    // task exists for, and its outcome is NOT asserted in either direction:
    // a crash here is the lower bound of the niche by width, not a defect.
    // What IS asserted is that the arm was really disarmed — a rung with a
    // concolic call is not a control and its crash would prove nothing.
    bool noconc_cracked = false;
    std::uint64_t noconc_ceiling = 0;
    std::uint64_t noconc_cracked_at = 0;
    for (const std::uint64_t rung : kNoconcolicLadder) {
        if (elapsed_s() > kWalltimeBudgetS) {
            walltime_spent = true;
            stop_reason = "walltime";
            break;
        }
        CampaignStats noconc_stats;
        std::uint64_t noconc_wall = 0;
        ASSERT_TRUE(Probe1("noconcolic-ladder", ++seq, "add_gate_w16", ADD_GATE_W16_BIN,
                           "add_gate_w16", "add-gate-w16-crash-budget-noconcolic", rung,
                           static_cast<std::uint32_t>(rung * 10 + 10), /*armed=*/false,
                           "mlfuzzz3_add_gate_w16_crash_budget_noconc", noconc_log, noconc_stats,
                           noconc_wall));
        EXPECT_EQ(noconc_stats.concolic_calls, 0U) << "concolic fired despite the out-of-budget "
                                                      "threshold at rung "
                                                   << rung << " — the control is not a control";
        noconc_ceiling = rung;
        if (noconc_stats.crashes > 0) {
            noconc_cracked = true;
            noconc_cracked_at = rung;
            break;
        }
    }

    // --- Monotonicity, checked separately over the armed probes of each
    // fixture: a crash at a smaller budget with none at a larger one refutes
    // it. The two fixtures are never mixed into one sequence.
    std::string witness_w16;
    std::string witness_u32;
    const bool monotonic =
        MonotonicOverLog(w16_log, witness_w16) && MonotonicOverLog(u32_log, witness_u32);
    if (!monotonic) {
        std::cout << "BUDGET-NONMONOTONIC witness_w16=" << witness_w16
                  << " witness_u32=" << witness_u32 << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(monotonic) << "observation is not monotonic in the budget: " << witness_w16 << ' '
                           << witness_u32;

    std::ostringstream ratio;
    if (w16_searched && control_u32_min > 0) {
        ratio << std::fixed << std::setprecision(2)
              << static_cast<double>(min_budget_w16) / static_cast<double>(control_u32_min);
    } else {
        ratio << "n/a";
    }
    std::ostringstream used;
    used << std::fixed << std::setprecision(1) << elapsed_s();
    std::ostringstream max_probe;
    max_probe << std::fixed << std::setprecision(3)
              << static_cast<double>(g_max_probe_wall_ms) / 1000.0;

    // The fields the task names, in the order it names them; `repeats` and
    // `spread` belong to the raw file built from two runs of this binary and
    // are deliberately absent. Everything after walltime_used_s is the donor
    // recipe's own bookkeeping, kept so the two logs stay comparable.
    std::cout << "BUDGET-VERDICT: ADD-GATE-W16: control_u32_min_budget="
              << (control_u32_searched ? std::to_string(control_u32_min) : std::string("none"))
              << ", w16_cracked=" << (w16_cracked ? "yes" : "no") << ", w16_min_budget=";
    if (w16_searched) {
        std::cout << min_budget_w16;
    } else {
        // Upper bound of the search, not a proof that no budget works.
        std::cout << ">=" << kSearchHi << "(upper-bound-of-search)";
    }
    std::cout << ", ratio_w16_over_u32=" << ratio.str()
              << ", noconcolic_w16_cracked=" << (noconc_cracked ? "yes" : "no")
              << ", noconcolic_ceiling=" << noconc_ceiling << ", noconcolic_cracked_at="
              << (noconc_cracked ? std::to_string(noconc_cracked_at) : std::string("none"))
              << ", rng_seed=" << kRngSeed << ", stagnation_threshold=" << kStagnationThreshold
              << ", endian=le, width_bits=16"
              << ", probes_total=" << u32_log.size() + w16_log.size() + noconc_log.size()
              << ", max_probe_walltime_s=" << max_probe.str() << ", walltime_used_s=" << used.str()
              << "/" << kWalltimeBudgetS << ", search_range=" << kSearchLo << ".." << kSearchHi
              << ", crash_at_min=" << (crash_at_min ? "yes" : "no")
              << ", crash_at_min_minus_1=" << (crash_at_min_minus_1 ? "yes" : "no")
              << ", concolic_calls_at_min=" << at_min.concolic_calls
              << ", control_u32_seed7_equals_18=" << (control_u32_ok ? "yes" : "no")
              << ", monotonic_verified=" << (monotonic ? "yes" : "no")
              << ", compared_against=u32-seed7-only, domain_map_reclassified=no"
              << ", stop_reason=" << stop_reason << ", walltime_budget_s=" << kWalltimeBudgetS
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
