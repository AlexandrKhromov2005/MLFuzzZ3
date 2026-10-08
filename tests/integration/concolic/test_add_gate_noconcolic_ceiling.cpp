// task-070 / ADR 0036 — the CEILING of the control arm: does `add_gate` fall
// at all when the solver is disarmed?
//
// What was missing. task-067 measured the denominator of the superiority
// claim — "min_budget_crash=18"
// (docs/experiments/solver-add-gate-crash-budget/report.md:10) — and pinned
// its no-solver control at exactly ONE point, budget 18
// (same report.md:145-147). From one point follows "on 18 iterations plain
// havoc does not take the gate", and nothing else. A world where havoc takes
// `add_gate` at budget 25 is not excluded by anything, and in that world the
// solver's advantage is 1.4x, not the order of magnitude the series silently
// implies.
//
// What this harness moves. Exactly one quantity: the budget of the DISARMED
// arm. The disarming mechanism is the one task-067 already used — the
// stagnation threshold is pushed past the budget, so no concolic call can
// occur (test_add_gate_crash_budget.cpp:447-453). Everything else — seed,
// RNG seed, scheduler, mutator, fixture — is held byte for byte.
//
// `concolic_calls == 0` is checked in EVERY disarmed probe, not once: a probe
// whose counter is non-zero is not a control, and it is declared invalid BY
// NAME (phase and seq) in the raw log instead of being averaged away.
//
// Probe order, fixed before the run: the doubling ladder 1, 2, 4, 8, 16, 32,
// 64, 128, 200; on the first crash the interval between the last clean rung
// and the crashing one is refined by binary search, and the transition point
// plus the point below it are repeated 5 times each, as in task-067
// (test_add_gate_crash_budget.cpp:208).
//
// Conditional extension, also fixed BEFORE the run and not rewritten
// afterwards: if nothing crashes at 200 AND the single probe at 200 fits in
// 10 s of wall time, the ladder continues 400, 800, 1600 and stops at the
// first of three events — crash, budget 1600, or 60 s of cumulative wall time
// spent on the extension. The reason is reported verbatim as one of
// `crash|hi|walltime`. Wall time of every probe is printed, so the condition
// is auditable from the raw log rather than taken on trust.
//
// When nothing crashes there is no transition point, so the 5x repeats go to
// the terminal budget reached and to the rung below it — declared here, ahead
// of the run, so the fallback cannot be chosen to flatter the result. The
// result is then published as a LOWER BOUND ("advantage >= hi/18"), never as
// a point, and no extrapolation past hi is made.
//
// Control on the armed arm, on the same tree and in the same process: budgets
// 18 and 17 with the threshold back at 8. They must reproduce task-067's pin
// (crash at 18, none at 17); if they do not, the disarmed numbers describe a
// drifted tree rather than the absence of a solver.
//
// Structural donor: this file's exec-server plumbing, RunCampaign(),
// FixedScheduler and the seed are copied from
// tests/integration/concolic/test_add_gate_crash_budget.cpp:79-271 (that file
// is NOT modified). src/ is not touched: the campaign loop already runs to
// budget exhaustion, so "did it crash under budget b" is an EXTERNAL estimate
// by re-running, exactly as in task-067.
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

// The doubling ladder and its conditional extension, both fixed before the
// run. `kLadderHi` is task-067's search ceiling, so the two sweeps meet at the
// same upper bound.
constexpr std::array<std::uint64_t, 9> kLadder = {1, 2, 4, 8, 16, 32, 64, 128, 200};
constexpr std::array<std::uint64_t, 3> kExtension = {400, 800, 1600};
constexpr std::uint64_t kLadderHi = 200;

// Extension gate: one probe at kLadderHi must fit in this wall time, and the
// extension as a whole must not exceed its own budget.
constexpr std::uint64_t kProbe200WallCapMs = 10000;
constexpr std::uint64_t kExtensionWallCapMs = 60000;

// Repeats of the transition point and of the point below it.
constexpr int kRepeats = 5;

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
    std::cout << "CEILING-PROBE phase=" << p.phase << " seq=" << p.seq << " gate=add_gate"
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
        std::cout << "CEILING-INVALID-PROBE probe=" << name
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
    return Probe1(phase, seq, budget, /*armed=*/false, "mlfuzzz3_add_gate_noconc_ceiling", log,
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

TEST(AddGateNoConcolicCeiling, MinimalBudgetAtWhichHavocAloneReachesTheCrash) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    std::cout << "CEILING-META add_gate=" << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL << " rng_seed=" << kRngSeed
              << " armed_threshold=" << kArmedThreshold
              << " disarm=threshold_10x_budget_plus_10 ladder=1,2,4,8,16,32,64,128,200"
              << " extension_if_no_crash=400,800,1600"
              << " extension_gate_probe200_wall_ms_le=" << kProbe200WallCapMs
              << " extension_wall_budget_ms=" << kExtensionWallCapMs << " repeats=" << kRepeats
              << " pin_task067_min_budget=" << kPinTask067MinBudget << '\n'
              << std::flush;

    std::vector<Probe> log;
    std::vector<std::string> invalid;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    int seq = 0;

    // --- The doubling ladder. `prev_clean` is the last rung that did not
    // crash; it is the left edge of the refinement interval.
    bool crashed_anywhere = false;
    std::uint64_t crash_budget = 0;
    std::uint64_t prev_clean = 0;
    std::uint64_t terminal_budget = 0;
    std::uint64_t below_terminal = 0;
    std::uint64_t probe_hi_wall_ms = 0;
    for (const std::uint64_t b : kLadder) {
        ASSERT_TRUE(ProbeOff("ladder", ++seq, b, log, invalid, stats, wall_ms));
        ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors at budget=" << b;
        if (b == kLadderHi) {
            probe_hi_wall_ms = wall_ms;
        }
        if (stats.crashes > 0) {
            crashed_anywhere = true;
            crash_budget = b;
            break;
        }
        below_terminal = terminal_budget;
        terminal_budget = b;
        prev_clean = b;
    }

    // --- Conditional extension, on the terms fixed in the header above.
    const char* stop_reason = crashed_anywhere ? "crash" : "hi";
    bool extension_taken = false;
    std::uint64_t extension_wall_ms = 0;
    if (!crashed_anywhere && probe_hi_wall_ms <= kProbe200WallCapMs) {
        extension_taken = true;
        for (const std::uint64_t b : kExtension) {
            ASSERT_TRUE(ProbeOff("extend", ++seq, b, log, invalid, stats, wall_ms));
            ASSERT_FALSE(stats.aborted)
                << "campaign aborted on infrastructure errors at budget=" << b;
            extension_wall_ms += wall_ms;
            if (stats.crashes > 0) {
                crashed_anywhere = true;
                crash_budget = b;
                stop_reason = "crash";
                break;
            }
            below_terminal = terminal_budget;
            terminal_budget = b;
            prev_clean = b;
            if (extension_wall_ms > kExtensionWallCapMs) {
                stop_reason = "walltime";
                break;
            }
        }
    }

    std::cout << "CEILING-EXTENSION taken=" << (extension_taken ? "yes" : "no") << " probe_at_"
              << kLadderHi << "_wall_ms=" << probe_hi_wall_ms
              << " gate_wall_ms_le=" << kProbe200WallCapMs
              << " extension_wall_ms=" << extension_wall_ms
              << " extension_wall_budget_ms=" << kExtensionWallCapMs
              << " stop_reason=" << stop_reason << '\n'
              << std::flush;

    // --- Refinement. Only meaningful if something crashed: the minimal
    // crashing budget lies in (prev_clean, crash_budget].
    std::uint64_t min_budget = 0;
    if (crashed_anywhere) {
        std::uint64_t lo = prev_clean + 1;
        std::uint64_t hi = crash_budget;
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            ASSERT_TRUE(ProbeOff("refine", ++seq, mid, log, invalid, stats, wall_ms));
            if (stats.crashes > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        min_budget = lo;
    }

    // --- Five repeats of the transition point and of the point below it.
    // With no crash anywhere there is no transition, so — as declared before
    // the run — the repeats go to the terminal budget and the rung below it.
    const std::uint64_t point = crashed_anywhere ? min_budget : terminal_budget;
    const std::uint64_t point_below =
        crashed_anywhere ? (min_budget > 1 ? min_budget - 1 : 0) : below_terminal;
    std::uint64_t obs_lo = point + 1;
    std::uint64_t obs_hi = point + 1;
    bool first_obs = true;
    CampaignStats at_point;
    std::uint64_t wall_at_point = 0;
    for (int r = 1; r <= kRepeats; ++r) {
        ASSERT_TRUE(ProbeOff("repeat-N", ++seq, point, log, invalid, at_point, wall_at_point));

        bool below_crashed = false;
        if (point_below > 0) {
            CampaignStats below;
            std::uint64_t below_wall = 0;
            ASSERT_TRUE(
                ProbeOff("repeat-N-1", ++seq, point_below, log, invalid, below, below_wall));
            below_crashed = below.crashes > 0;
        }

        // Same three-valued observation as task-067
        // (test_add_gate_crash_budget.cpp:419-421): the point below if that
        // already crashes, the point if only it does, and point+1 as an
        // out-of-band marker when neither does.
        const std::uint64_t observed = below_crashed          ? point_below
                                       : at_point.crashes > 0 ? point
                                                              : point + 1;
        if (first_obs) {
            obs_lo = observed;
            obs_hi = observed;
            first_obs = false;
        } else {
            obs_lo = std::min(obs_lo, observed);
            obs_hi = std::max(obs_hi, observed);
        }
    }
    const std::uint64_t spread = obs_hi - obs_lo;

    // --- Control on the ARMED arm: task-067's pin, reproduced here so the
    // disarmed numbers are known to come from the same tree. Threshold back
    // at 8, budgets 18 and 17 (report.md:10).
    CampaignStats armed_at_pin;
    std::uint64_t armed_pin_wall = 0;
    ASSERT_TRUE(Probe1("control-armed-18", ++seq, kPinTask067MinBudget, /*armed=*/true,
                       "mlfuzzz3_add_gate_noconc_ceiling_armed", log, invalid, armed_at_pin,
                       armed_pin_wall));
    const bool armed_18_crash = armed_at_pin.crashes > 0;
    EXPECT_GT(armed_at_pin.crashes, 0U)
        << "armed arm no longer crashes at budget 18 — task-067's pin does not reproduce";

    CampaignStats armed_below;
    std::uint64_t armed_below_wall = 0;
    ASSERT_TRUE(Probe1("control-armed-17", ++seq, kPinTask067MinBudget - 1, /*armed=*/true,
                       "mlfuzzz3_add_gate_noconc_ceiling_armed", log, invalid, armed_below,
                       armed_below_wall));
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
        std::cout << "CEILING-NONMONOTONIC witness=" << witness << '\n' << std::flush;
    }
    EXPECT_TRUE(monotonic) << "observation is not monotonic in the budget: " << witness;

    // --- The ratio. A point when the disarmed arm fell, an explicit LOWER
    // BOUND when it did not. `hi_reached` is the largest budget actually
    // probed clean; nothing is claimed past it.
    const std::uint64_t hi_reached = terminal_budget;
    const double ratio = static_cast<double>(crashed_anywhere ? min_budget : hi_reached) /
                         static_cast<double>(kPinTask067MinBudget);
    std::uint64_t disarmed_probes = 0;
    for (const Probe& p : log) {
        if (!p.concolic_enabled) {
            ++disarmed_probes;
        }
    }

    std::cout << "CEILING-VERDICT: ADD-GATE-NOCONCOLIC-CEILING: crash_without_solver="
              << (crashed_anywhere ? "yes" : "no") << ", min_budget_noconcolic="
              << (crashed_anywhere ? std::to_string(min_budget) : std::string("none"))
              << ", hi_reached=" << hi_reached << ", stop_reason=" << stop_reason
              << ", probes=" << log.size() << ", disarmed_probes=" << disarmed_probes
              << ", invalid_probes=" << invalid.size() << ", repeats=" << kRepeats
              << ", spread=" << spread << ", extension_taken=" << (extension_taken ? "yes" : "no")
              << ", probe_hi_wall_ms=" << probe_hi_wall_ms
              << ", extension_wall_ms=" << extension_wall_ms
              << ", pin_task067_min_budget=" << kPinTask067MinBudget
              << ", control_armed_crash_at_18=" << (armed_18_crash ? "yes" : "no")
              << ", control_armed_crash_at_17=" << (armed_17_crash ? "yes" : "no")
              << ", ratio_vs_18=" << (crashed_anywhere ? "" : ">=") << ratio
              << ", ratio_is_lower_bound=" << (crashed_anywhere ? "no" : "yes")
              << ", monotonic_verified=" << (monotonic ? "yes" : "no")
              << ", src_modified=0, new_benchmark_campaigns=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
