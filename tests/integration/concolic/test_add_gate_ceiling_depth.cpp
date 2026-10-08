// task-076 / ADR 0036 — HOW DEEP is the havoc ceiling: turning `>=88.9` into an
// honest boundary.
//
// What was missing. task-070 walked the disarmed arm up to 1600 iterations and
// stopped there because the ladder ran out, not because the target did:
// `budget_hi=1600, stop_reason=hi, min_budget_noconcolic=none,
// ratio_vs_solver=>=88.8889, ratio_kind=lower-bound`
// (docs/experiments/solver-add-gate-noconcolic-ceiling/report.md:10-12). That
// `>=88.8889` is a property of the number 1600, which the previous task chose,
// and not a property of `add_gate`. Until the ceiling is deepened it is not even
// known what the bound refers to: that plain havoc does not take the gate at
// all, or that it was two orders of magnitude short of iterations.
//
// What this harness moves. Exactly one quantity, again: the budget of the
// DISARMED arm. The ladder continues by doubling from task-070's ceiling —
// 3200, 6400, 12800, 25600, 51200, 102400, 204800, 409600 — and the series is
// fixed here, before the run, so no rung can be chosen afterwards to flatter the
// result. Seed, RNG seed, stagnation threshold, scheduler, mutator and fixture
// are the donor's, byte for byte
// (test_add_gate_crash_budget.cpp:194, :199-200); the disarming mechanism is the
// donor's too — the stagnation threshold is pushed past the budget, so no
// concolic call can occur.
//
// `concolic_calls == 0` is checked in EVERY disarmed probe and printed on every
// raw line, so the disarming is proven from the log rather than by reading the
// code. A probe whose counter is non-zero is not a control: it is declared
// invalid BY NAME (phase and seq) and fails the test.
//
// The stopping rule, fixed before the run. Three events end the ladder, and the
// reason is reported verbatim as one of `crash|hi|walltime`:
//   * a crash — then the minimum is refined by binary search between the last
//     clean rung and the crashing one, and the ratio is published as EXACT;
//   * the last rung, 409600 — then the ratio is published as a new LOWER BOUND
//     with task-070's own word, `lower-bound`;
//   * 1200 seconds of wall time (kWalltimeBudgetS) — then the rung reached is
//     published as the new ceiling with `stop_reason=walltime`.
// The budget bounds the run rather than being noticed after it is blown: each
// rung doubles the iteration count, so it is predicted at twice the previous
// rung's measured wall time and is STARTED only if the prediction fits in what
// is left. Every prediction and every decision is printed, and a planned rung
// that is not run is named in the log instead of vanishing from it.
//
// No extrapolation is made past the deepest rung actually probed. If nothing
// crashes at 409600 this harness says exactly that and nothing more — the
// question "does havoc ever take the gate" stays as open as task-070 left it.
//
// Boundary of the claim: this is one seed, the donor's RNG seed 7. It is not an
// ensemble and does not become one; task-071 owns that axis.
//
// Control on the armed arm, on the same tree and in the same process: budgets 18
// and 17 with the threshold back at 8. They must reproduce task-067's pin
// (crash at 18, none at 17); if they do not, the disarmed numbers describe a
// drifted tree rather than the absence of a solver.
//
// Structural donor: this file's exec-server plumbing, RunCampaign(),
// FixedScheduler, the seed and the probe log are copied from
// tests/integration/concolic/test_add_gate_noconcolic_ceiling.cpp (that file is
// NOT modified, and neither is test_add_gate_crash_budget.cpp). src/ is not
// touched: "did it crash under budget b" stays an EXTERNAL estimate obtained by
// re-running, exactly as in task-067 and task-070.
//
// Every path printed is relative to the repository root, so the raw log carries
// no absolute paths. Self-skips when any artifact is unavailable.

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
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_REL;
    }
    return {};
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger (donor:
// test_add_gate_crash_budget.cpp:180-188).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// The solver arm's own seed, byte for byte the one task-067 measured with
// (test_add_gate_crash_budget.cpp:194): a = 0x44332211, b = 0x2A2B2C2D (LE).
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Held fixed across the whole sweep. `kArmedThreshold` is the value both
// existing oracles use (test_add_gate_crash_budget.cpp:199-200); the disarmed
// arm replaces it per-probe with a threshold past the budget.
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kArmedThreshold = 8;

// The ladder of task-076, fixed BEFORE the run and copied verbatim from the
// task-070's ceiling of 1600 and ends two orders of magnitude deeper. No rung
// below 3200 is added — the interval [1, 1600] is already swept by task-070
// and is not re-measured here.
constexpr std::array<std::uint64_t, 8> kLadder = {3200,  6400,   12800,  25600,
                                                  51200, 102400, 204800, 409600};

// The ceiling this run exists to deepen
// (docs/experiments/solver-add-gate-noconcolic-ceiling/report.md:10).
constexpr std::uint64_t kPrevBudgetHi = 1600;

// The disarming construction is `budget * 10 + 10` in a std::uint32_t. At
// 409600 that is 4 096 010 and fits; from budget 429496730 up it wraps and the
// "disarmed" arm would silently be armed again. The ladder is checked against
// that bound at compile time rather than left to a reader of the code.
static_assert(kLadder.back() <= (0xFFFFFFFFULL - 10) / 10,
              "disarming threshold budget*10+10 overflows std::uint32_t");

// The HARD wall-time budget of the whole run, in seconds, as the task requires
// it: on exhaustion the ladder stops at the rung reached, that rung is
// published as the new ceiling and `stop_reason=walltime` is printed. This is
// deliberately NOT the donor's cumulative 60 s extension cap
// (test_add_gate_noconcolic_ceiling.cpp:218) — that cap would have stopped this
// ladder at 102400 with the real budget still wide open, and the resulting
// ceiling would have looked legal while being two orders of magnitude short.
constexpr std::uint64_t kWalltimeBudgetS = 1200;
constexpr std::uint64_t kWalltimeBudgetMs = kWalltimeBudgetS * 1000;

// task-067's pinned answer for the ARMED arm, the denominator of the ratio
// this harness reports (report.md:10).
constexpr std::uint64_t kPinTask067MinBudget = 18;

// A disarmed probe uses a stagnation threshold past its own budget, so the
// campaign can never reach it. Same construction as the control of task-067
// (test_add_gate_crash_budget.cpp:449).
std::uint32_t DisarmedThreshold(std::uint64_t budget) {
    return static_cast<std::uint32_t>(budget * 10 + 10);
}

struct Probe {
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_enabled = false;
    std::uint64_t concolic_calls = 0;
    std::uint64_t wall_ms = 0;
    int seq = 0;
    std::string phase;
};

// One bounded campaign, its counters and its wall time. Fatal assertions
// inside report against the calling test; callers must bail out on
// ::testing::Test::HasFatalFailure(). Donor:
// test_add_gate_crash_budget.cpp:220-271.
void RunCampaign(std::uint64_t max_iterations, std::uint32_t stagnation_threshold,
                 const char* workspace, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-noconcolic-ceiling");
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
void PrintProbe(const Probe& p, const CampaignStats& s) {
    std::cout << "DEPTH-PROBE phase=" << p.phase << " seq=" << p.seq << " gate=add_gate"
              << " budget=" << p.budget << " concolic=" << (p.concolic_enabled ? "on" : "off")
              << " threshold="
              << (p.concolic_enabled ? kArmedThreshold : DisarmedThreshold(p.budget))
              << " crashed=" << (s.crashes > 0 ? "yes" : "no") << " execs=" << s.execs
              << " crashes=" << s.crashes << " concolic_calls=" << s.concolic_calls
              << " concolic_candidates=" << s.concolic_candidates
              << " concolic_crashes=" << s.concolic_crashes
              << " concolic_unsat=" << s.concolic_unsat
              << " concolic_no_binding=" << s.concolic_no_binding
              << " concolic_timeout=" << s.concolic_timeout
              << " aborted=" << (s.aborted ? "yes" : "no") << " wall_ms=" << p.wall_ms << '\n'
              << std::flush;
}

// Runs one probe, records it in `log`, prints it. Returns false when a fatal
// assertion fired inside RunCampaign. For a DISARMED probe the zero-call
// invariant is checked here — once per probe, not once per sweep — and a
// violation is named in the log by phase and seq.
bool Probe1(const char* phase, int seq, std::uint64_t budget, bool armed, const char* workspace,
            std::vector<Probe>& log, std::vector<std::string>& invalid, CampaignStats& out_stats,
            std::uint64_t& out_wall_ms) {
    RunCampaign(budget, armed ? kArmedThreshold : DisarmedThreshold(budget), workspace, out_stats,
                out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    Probe p;
    p.budget = budget;
    p.crashed = out_stats.crashes > 0;
    p.concolic_enabled = armed;
    p.concolic_calls = out_stats.concolic_calls;
    p.wall_ms = out_wall_ms;
    p.seq = seq;
    p.phase = phase;
    log.push_back(p);
    PrintProbe(p, out_stats);
    if (!armed && out_stats.concolic_calls != 0) {
        const std::string name =
            std::string(phase) + "#" + std::to_string(seq) + "@budget=" + std::to_string(budget);
        invalid.push_back(name);
        std::cout << "DEPTH-INVALID-PROBE probe=" << name
                  << " concolic_calls=" << out_stats.concolic_calls
                  << " reason=disarmed_probe_called_solver\n"
                  << std::flush;
    }
    return true;
}

// The disarmed sweep, which is the measurement.
bool ProbeOff(const char* phase, int seq, std::uint64_t budget, std::vector<Probe>& log,
              std::vector<std::string>& invalid, CampaignStats& out_stats,
              std::uint64_t& out_wall_ms) {
    return Probe1(phase, seq, budget, /*armed=*/false, "mlfuzzz3_add_gate_ceiling_depth", log,
                  invalid, out_stats, out_wall_ms);
}

// A pair (b1 < b2) with a crash at b1 and none at b2 refutes monotonicity of
// the observation in the budget. Checked over the disarmed probes only — the
// two armed control probes live on a different curve.
bool MonotonicOverLog(const std::vector<Probe>& log, std::string& out_witness) {
    for (const Probe& lo : log) {
        if (lo.concolic_enabled || !lo.crashed) {
            continue;
        }
        for (const Probe& hi : log) {
            if (hi.concolic_enabled || hi.crashed) {
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

TEST(AddGateCeilingDepth, HowDeepIsTheCeilingOfHavocAlone) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    std::cout << "DEPTH-META add_gate=" << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL << " rng_seed=" << kRngSeed
              << " armed_threshold=" << kArmedThreshold << " disarm=threshold_10x_budget_plus_10"
              << " ladder=3200,6400,12800,25600,51200,102400,204800,409600"
              << " rungs_planned=" << kLadder.size() << " prev_budget_hi=" << kPrevBudgetHi
              << " walltime_budget_s=" << kWalltimeBudgetS
              << " pin_task067_min_budget=" << kPinTask067MinBudget << '\n'
              << std::flush;

    std::vector<Probe> log;
    std::vector<std::string> invalid;
    std::vector<std::uint64_t> skipped;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    int seq = 0;

    // --- The ladder. `prev_clean` is the deepest rung that did not crash and is
    // the left edge of the refinement interval; `hi_reached` is the deepest rung
    // probed at all, crash included.
    std::uint64_t total_wall_ms = 0;
    std::uint64_t last_rung_wall_ms = 0;
    std::uint64_t rungs_executed = 0;
    std::uint64_t crash_budget = 0;
    std::uint64_t prev_clean = 0;
    std::uint64_t hi_reached = 0;
    bool crashed_anywhere = false;
    bool budget_exhausted = false;
    const char* stop_reason = "hi";

    for (std::size_t i = 0; i < kLadder.size(); ++i) {
        const std::uint64_t b = kLadder[i];

        // Admission before the probe, not regret after it: the rung doubles the
        // iterations, so it costs about twice the previous rung.
        const std::uint64_t predicted_ms = last_rung_wall_ms * 2;
        if (i > 0 && total_wall_ms + predicted_ms > kWalltimeBudgetMs) {
            budget_exhausted = true;
        }
        if (budget_exhausted) {
            skipped.push_back(b);
            std::cout << "DEPTH-RUNG-SKIPPED budget=" << b << " predicted_ms=" << predicted_ms
                      << " total_wall_ms=" << total_wall_ms
                      << " walltime_budget_ms=" << kWalltimeBudgetMs
                      << " reason=walltime_admission\n"
                      << std::flush;
            continue;
        }

        ASSERT_TRUE(ProbeOff("ladder", ++seq, b, log, invalid, stats, wall_ms));
        ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors at budget=" << b;
        total_wall_ms += wall_ms;
        last_rung_wall_ms = wall_ms;
        ++rungs_executed;
        hi_reached = b;

        if (stats.crashes > 0) {
            crashed_anywhere = true;
            crash_budget = b;
            stop_reason = "crash";
            break;
        }
        prev_clean = b;

        if (total_wall_ms >= kWalltimeBudgetMs) {
            budget_exhausted = true;
        }
    }
    if (!crashed_anywhere && budget_exhausted) {
        stop_reason = "walltime";
    }

    for (const std::uint64_t b : skipped) {
        std::cout << "DEPTH-RUNG-PLANNED-NOT-EXECUTED budget=" << b
                  << " stop_reason=" << stop_reason << '\n'
                  << std::flush;
    }

    // --- Refinement, meaningful only if something crashed: the minimal crashing
    // budget lies in (prev_clean, crash_budget]. Every probe is admitted against
    // what is left of the same budget, its cost predicted linearly from the
    // crashing rung. An interrupted refinement leaves a BRACKET and no point:
    // `min_budget_noconcolic` stays `none` and the ratio stays a lower bound.
    std::uint64_t min_budget = 0;
    std::uint64_t bracket_lo = 0;
    std::uint64_t bracket_hi = 0;
    bool refined = false;
    if (crashed_anywhere) {
        const std::uint64_t crash_wall_ms = log.back().wall_ms;
        std::uint64_t lo = prev_clean + 1;
        std::uint64_t hi = crash_budget;
        refined = true;
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            const std::uint64_t predicted_ms =
                crash_budget == 0 ? 0 : crash_wall_ms * mid / crash_budget;
            if (total_wall_ms + predicted_ms > kWalltimeBudgetMs) {
                refined = false;
                std::cout << "DEPTH-REFINE-STOPPED lo=" << lo << " hi=" << hi
                          << " predicted_ms=" << predicted_ms << " total_wall_ms=" << total_wall_ms
                          << " walltime_budget_ms=" << kWalltimeBudgetMs
                          << " reason=walltime_admission\n"
                          << std::flush;
                stop_reason = "walltime";
                break;
            }
            ASSERT_TRUE(ProbeOff("refine", ++seq, mid, log, invalid, stats, wall_ms));
            ASSERT_FALSE(stats.aborted)
                << "campaign aborted on infrastructure errors at budget=" << mid;
            total_wall_ms += wall_ms;
            if (stats.crashes > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        bracket_lo = lo;
        bracket_hi = hi;
        if (refined) {
            min_budget = lo;
        }
    }

    // --- Control on the ARMED arm: task-067's pin, reproduced here so the
    // disarmed numbers are known to come from the same tree. Threshold back at
    // 8, budgets 18 and 17 (report.md:10). Eighteen iterations cost milliseconds
    // and are not admitted against the budget, only counted into it.
    CampaignStats armed_at_pin;
    std::uint64_t armed_pin_wall = 0;
    ASSERT_TRUE(Probe1("control-armed-18", ++seq, kPinTask067MinBudget, /*armed=*/true,
                       "mlfuzzz3_add_gate_ceiling_depth_armed", log, invalid, armed_at_pin,
                       armed_pin_wall));
    total_wall_ms += armed_pin_wall;
    const bool armed_18_crash = armed_at_pin.crashes > 0;
    EXPECT_GT(armed_at_pin.crashes, 0U)
        << "armed arm no longer crashes at budget 18 — task-067's pin does not reproduce";

    CampaignStats armed_below;
    std::uint64_t armed_below_wall = 0;
    ASSERT_TRUE(Probe1("control-armed-17", ++seq, kPinTask067MinBudget - 1, /*armed=*/true,
                       "mlfuzzz3_add_gate_ceiling_depth_armed", log, invalid, armed_below,
                       armed_below_wall));
    total_wall_ms += armed_below_wall;
    const bool armed_17_crash = armed_below.crashes > 0;
    EXPECT_EQ(armed_below.crashes, 0U)
        << "armed arm crashes at budget 17 — task-067's pin does not reproduce";

    // --- Invariants of the disarmed arm.
    EXPECT_TRUE(invalid.empty()) << "disarmed probes that called the solver: " << invalid.size();
    for (const std::string& name : invalid) {
        ADD_FAILURE() << "invalid disarmed probe: " << name;
    }

    std::string witness;
    const bool monotonic = MonotonicOverLog(log, witness);
    if (!monotonic) {
        std::cout << "DEPTH-NONMONOTONIC witness=" << witness << '\n' << std::flush;
    }
    EXPECT_TRUE(monotonic) << "observation is not monotonic in the budget: " << witness;

    // --- The ratio. A point only when the minimum was actually pinned down by
    // the refinement; an explicit LOWER BOUND in every other case, carrying
    // task-070's own word. The numerator of a lower bound is the deepest budget
    // KNOWN to be clean, so nothing is claimed about budgets never probed.
    const bool exact = crashed_anywhere && refined;
    const std::uint64_t numerator =
        exact ? min_budget : (crashed_anywhere ? bracket_lo : prev_clean);
    const double ratio = static_cast<double>(numerator) / static_cast<double>(kPinTask067MinBudget);
    const std::uint64_t deepening_factor = hi_reached / kPrevBudgetHi;
    const std::uint64_t walltime_used_s = (total_wall_ms + 999) / 1000;

    std::uint64_t disarmed_probes = 0;
    for (const Probe& p : log) {
        if (!p.concolic_enabled) {
            ++disarmed_probes;
        }
    }

    // The wall-time budget is a bound, not a wish: overshooting it is a failure
    // of this harness, and stopping on it is a legal outcome.
    EXPECT_LE(total_wall_ms, kWalltimeBudgetMs)
        << "the run overshot its own wall-time budget of " << kWalltimeBudgetS << " s";

    std::cout << "DEPTH-SUMMARY probes=" << log.size() << " disarmed_probes=" << disarmed_probes
              << " invalid_probes=" << invalid.size() << " rungs_skipped=" << skipped.size()
              << " refined=" << (refined ? "yes" : "no") << " bracket_lo=" << bracket_lo
              << " bracket_hi=" << bracket_hi
              << " monotonic_verified=" << (monotonic ? "yes" : "no")
              << " control_armed_crash_at_18=" << (armed_18_crash ? "yes" : "no")
              << " control_armed_crash_at_17=" << (armed_17_crash ? "yes" : "no")
              << " walltime_used_ms=" << total_wall_ms
              << " walltime_budget_ms=" << kWalltimeBudgetMs << '\n'
              << std::flush;

    std::cout << "VERDICT: ADD-GATE-CEILING-DEPTH: seed=" << kRngSeed
              << ", rungs_planned=" << kLadder.size() << ", rungs_executed=" << rungs_executed
              << ", budget_hi_reached=" << hi_reached << ", prev_budget_hi=" << kPrevBudgetHi
              << ", deepening_factor=" << deepening_factor
              << ", noconcolic_crash=" << (crashed_anywhere ? "yes" : "no")
              << ", min_budget_noconcolic="
              << (exact ? std::to_string(min_budget) : std::string("none"))
              << ", ratio_vs_solver=" << (exact ? "" : ">=") << ratio
              << ", ratio_kind=" << (exact ? "exact" : "lower-bound")
              << ", control_solver_min_budget=" << kPinTask067MinBudget
              << ", stop_reason=" << stop_reason << ", walltime_budget_s=" << kWalltimeBudgetS
              << ", walltime_used_s=" << walltime_used_s
              << ", extrapolation_claimed=no, src_modified=0, new_fuzzing_runs=0, "
                 "reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
