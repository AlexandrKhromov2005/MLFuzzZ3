// task-073 / ADR 0036 — the NUMERATOR of the superiority claim across an
// ensemble of RNG seeds, so the ratio is computed PAIRWISE inside one PRNG
// stream.
//
// What was missing. Both halves of "the solver beats plain havoc on
// `add_gate`" exist, but they were taken on different footings. The
// denominator became a distribution — "min_budget_min=10, min_budget_max=24,
// min_budget_median=12, spread_across_seeds=14"
// (docs/experiments/solver-add-gate-budget-seed-spread/report.md:11-13) over
// ten pre-registered RNG seeds. The numerator stayed one number —
// "budget_hi=1600, noconcolic_crash_within_hi=no, ratio_vs_solver=>=88.8889"
// (docs/experiments/solver-add-gate-noconcolic-ceiling/report.md:10-13) — and
// it was taken on seed 7 alone. Dividing the ceiling of seed 7 by the minimum
// of some other seed would mix two PRNG streams; task-071's closing entry
//
// What this harness moves. Exactly one quantity relative to
// tests/integration/concolic/test_add_gate_noconcolic_ceiling.cpp (which is
// NOT modified): the mutation RNG seed. The disarming mechanism, the input
// seed `kArmSeed`, the scheduler, the mutator and the fixture are held byte
// for byte. The ceiling stays at 1600 — deepening it is an adjacent axis and
// the subject of a separate task, so no rung above 1600 is ever probed here.
//
// The measurement, per seed. One probe at budget 1600 on the DISARMED arm.
// No crash -> `none`, `hi_reached=1600`, and no ladder is built for that
// seed. Crash -> binary search for the minimum over [1, 1600] by task-067's
// rule (test_add_gate_crash_budget.cpp:204-205), and the seed is named BY
// NAME in the verdict, never averaged away.
//
// `concolic_calls == 0` is checked in EVERY disarmed probe, not once per
// sweep: a probe whose counter is non-zero is not a control, and it is
// declared invalid BY NAME (phase, seq and seed) in the raw log.
//
// The ratio is PAIRWISE and only pairwise: seed s is divided by task-071's
// `min_budget` for THAT SAME seed s, read from its table as a constant below
// and never re-measured here. A ratio between the ceiling of one seed and the
// minimum of another is never formed, in the harness or in the report.
//
// Control: seed 7 is the one task-070 measured on, so its outcome must
// reproduce task-070's pin — no crash within 1600. If it does not, the tree
// has drifted and the other nine rows describe something else.
//
// Structural donor: the exec-server plumbing, RunCampaign(), FixedScheduler,
// `kArmSeed` and the disarming rule are copied from
// tests/integration/concolic/test_add_gate_noconcolic_ceiling.cpp:60-300,
// which in turn copies them from test_add_gate_crash_budget.cpp:79-271.
// Neither donor is modified. src/ is not touched: the campaign loop already
// runs to budget exhaustion, so "did it crash under budget b" is an EXTERNAL
// estimate obtained by re-running, exactly as in task-067 and task-070.
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
// reason to skip. The message names artifacts by their REPO-RELATIVE path so
// that even a skipped run leaves no absolute path in the raw log. No sub_gate
// is needed: the whole ensemble lives on add_gate.
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
// test_add_gate_noconcolic_ceiling.cpp:180-190).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// The arm's own input seed, byte for byte the donor's
// (test_add_gate_crash_budget.cpp:194): a = 0x44332211, b = 0x2A2B2C2D (LE).
// HELD FIXED — this sweep varies the mutation RNG seed only, and `kArmSeed`
// is named in the report as one of the two adjacent axes left unlifted.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// The armed value of the stagnation threshold
// (test_add_gate_crash_budget.cpp:200). It is printed for the record only:
// every probe of this sweep is DISARMED, so this value is never used as a
// campaign setting here. The threshold is the second adjacent axis this sweep
// does not lift.
constexpr std::uint32_t kArmedThreshold = 8;

// PRE-REGISTERED ensemble, in run order — the list of task-071 CARRIED OVER,
// not chosen anew (docs/experiments/solver-add-gate-budget-seed-spread/report.md:10).
// Index 0 is the control. This list is the contract: a seed is never swapped
// after the run.
constexpr std::array<std::uint64_t, 10> kRngSeeds = {7, 1, 2, 3, 11, 13, 17, 23, 29, 31};

// task-071's per-seed `min_budget` for the ARMED arm, index-aligned with
// `kRngSeeds`, taken from its table as-is and NOT re-measured here
// (docs/experiments/solver-add-gate-budget-seed-spread/report.md:97-106).
// This array is the whole denominator side of the ratio, and it is indexed by
// the seed's own position: that is what makes the division pairwise.
constexpr std::array<std::uint64_t, 10> kTask071MinBudget = {18, 10, 11, 10, 18,
                                                             24, 12, 10, 12, 23};

// The control seed and task-070's pinned outcome for it: no crash inside the
// ceiling (docs/experiments/solver-add-gate-noconcolic-ceiling/report.md:10-13).
constexpr std::uint64_t kControlRngSeed = 7;
constexpr bool kControlExpectedCrackedAtHi = false;

// The ceiling, task-070's (report.md:10-13), and the lower end of the search
// interval, task-067's (test_add_gate_crash_budget.cpp:204). Nothing above
// `kBudgetHi` is probed: deepening the ceiling is an adjacent axis.
constexpr std::uint64_t kBudgetHi = 1600;
constexpr std::uint64_t kSearchLo = 1;

// A disarmed probe uses a stagnation threshold past its own budget, so the
// campaign can never reach it. Same construction as the control of task-067
// (test_add_gate_crash_budget.cpp:449) and of task-070
// (test_add_gate_noconcolic_ceiling.cpp:230).
std::uint32_t DisarmedThreshold(std::uint64_t budget) {
    return static_cast<std::uint32_t>(budget * 10 + 10);
}

struct Probe {
    std::uint64_t rng_seed = 0;
    std::uint64_t budget = 0;
    bool crashed = false;
    std::uint64_t wall_ms = 0;
};

// One bounded campaign, its counters and its wall time. Fatal assertions
// inside report against the calling test; callers must bail out on
// ::testing::Test::HasFatalFailure(). Donor:
// test_add_gate_noconcolic_ceiling.cpp:246-297.
void RunCampaign(std::uint64_t rng_seed, std::uint64_t max_iterations,
                 std::uint32_t stagnation_threshold, CampaignStats& out_stats,
                 std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_ceiling_seed_spread";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-ceiling-seed-spread");
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
                             .rng_seed = rng_seed,
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
void PrintProbe(const char* phase, int seq, const Probe& p, const CampaignStats& s) {
    std::cout << "CEILING-SPREAD-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
              << " rng_seed=" << p.rng_seed << " budget=" << p.budget << " concolic=off"
              << " threshold=" << DisarmedThreshold(p.budget)
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

// Runs one DISARMED probe, records it in `log`, prints it. Returns false when
// a fatal assertion fired inside RunCampaign. The zero-call invariant is
// checked here — once per probe, not once per sweep — and a violation is
// named in the log by phase, seq and seed.
bool ProbeOff(const char* phase, int& seq, std::uint64_t rng_seed, std::uint64_t budget,
              std::vector<Probe>& log, std::vector<std::string>& invalid, CampaignStats& out_stats,
              std::uint64_t& out_wall_ms) {
    RunCampaign(rng_seed, budget, DisarmedThreshold(budget), out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    ++seq;
    Probe p;
    p.rng_seed = rng_seed;
    p.budget = budget;
    p.crashed = out_stats.crashes > 0;
    p.wall_ms = out_wall_ms;
    log.push_back(p);
    PrintProbe(phase, seq, p, out_stats);
    if (out_stats.concolic_calls != 0) {
        const std::string name = std::string(phase) + "#" + std::to_string(seq) +
                                 "@rng_seed=" + std::to_string(rng_seed) +
                                 ",budget=" + std::to_string(budget);
        invalid.push_back(name);
        std::cout << "CEILING-SPREAD-INVALID-PROBE probe=" << name
                  << " concolic_calls=" << out_stats.concolic_calls
                  << " reason=disarmed_probe_called_solver\n"
                  << std::flush;
    }
    return true;
}

// A pair (b1 < b2) with a crash at b1 and none at b2 refutes monotonicity of
// the observation in the budget. Checked over the probes of ONE seed only:
// mixing seeds would compare runs of different PRNG streams.
bool MonotonicOverLog(const std::vector<Probe>& log, std::string& out_witness) {
    for (const Probe& lo : log) {
        if (!lo.crashed) {
            continue;
        }
        for (const Probe& hi : log) {
            if (hi.crashed || hi.budget <= lo.budget) {
                continue;
            }
            out_witness = "crash at budget=" + std::to_string(lo.budget) +
                          " but none at budget=" + std::to_string(hi.budget);
            return false;
        }
    }
    return true;
}

// Ratios are doubles, so the median of an even sample is the mean of the two
// middle values; with an odd sample it is the middle one.
double MedianOf(std::vector<double> values) {
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    const std::size_t n = values.size();
    if (n % 2 == 1) {
        return values[n / 2];
    }
    return (values[n / 2 - 1] + values[n / 2]) / 2.0;
}

std::string Num(double v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

// One seed's outcome. `cracked_at_hi=false` — the expected case, reproducing
// task-070 — means no ladder was built for that seed and its ratio enters the
// summary as a LOWER BOUND.
struct SeedResult {
    std::uint64_t rng_seed = 0;
    std::uint64_t task071_min_budget = 0;
    bool cracked_at_hi = false;
    std::uint64_t min_budget = 0;
    std::size_t probes = 0;
    bool monotonic = false;
    std::uint64_t max_wall_ms = 0;
    double ratio = 0.0;
    bool ratio_is_lower_bound = true;
};

TEST(AddGateCeilingSeedSpread, DisarmedCeilingAcrossPreregisteredRngSeeds) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    std::cout << "CEILING-SPREAD-META add_gate=" << ADD_GATE_REL
              << " exec_server=" << EXEC_SERVER_REL << " cov_library=" << COV_LIBRARY_REL
              << " armed_threshold_not_used_here=" << kArmedThreshold
              << " disarm=threshold_10x_budget_plus_10 budget_hi=" << kBudgetHi
              << " search_lo=" << kSearchLo << " seeds=" << kRngSeeds.size()
              << " ceiling_deepened=no arm_seed_varied=no stagnation_threshold_varied=no\n"
              << std::flush;

    // --- Pre-registration, printed BEFORE any result: the ensemble and the
    // pairwise denominators, both carried over from task-071 unchanged.
    {
        std::cout << "CEILING-SPREAD-PREREGISTERED seeds=";
        for (std::size_t i = 0; i < kRngSeeds.size(); ++i) {
            std::cout << (i == 0 ? "" : ",") << kRngSeeds[i];
        }
        std::cout << " control=" << kControlRngSeed << " control_expected_cracked_at_hi="
                  << (kControlExpectedCrackedAtHi ? "yes" : "no") << " task071_min_budget=";
        for (std::size_t i = 0; i < kRngSeeds.size(); ++i) {
            std::cout << (i == 0 ? "" : ",") << kRngSeeds[i] << ":" << kTask071MinBudget[i];
        }
        std::cout << '\n' << std::flush;
    }

    // --- The ratio rule, fixed HERE, before any result is read.
    std::cout << "CEILING-SPREAD-RATIO-RULE pairing=per-seed"
              << " not_cracked=ratio_is_lower_bound_budget_hi_over_task071_min_budget_same_seed"
              << " cracked=ratio_is_exact_min_budget_noconcolic_over_task071_min_budget_same_seed"
              << " kind=lower-bound_if_all_lower_bounds|exact_if_all_exact|mixed_otherwise"
              << " cross_seed_ratio=never\n"
              << std::flush;

    int seq = 0;
    std::vector<SeedResult> results;
    std::vector<std::string> invalid;

    for (std::size_t i = 0; i < kRngSeeds.size(); ++i) {
        const std::uint64_t rng_seed = kRngSeeds[i];
        std::vector<Probe> log;
        CampaignStats stats;
        std::uint64_t wall_ms = 0;
        SeedResult r;
        r.rng_seed = rng_seed;
        r.task071_min_budget = kTask071MinBudget[i];

        // --- The single probe at the ceiling. No crash here means the ladder
        // is not built for this seed: that is the rule, declared before the
        // run, not a decision taken after seeing the outcome.
        ASSERT_TRUE(ProbeOff("ceiling", seq, rng_seed, kBudgetHi, log, invalid, stats, wall_ms));
        ASSERT_FALSE(stats.aborted)
            << "campaign aborted on infrastructure errors, rng_seed=" << rng_seed;
        r.cracked_at_hi = stats.crashes > 0;

        if (r.cracked_at_hi) {
            // --- Binary search for the minimal crashing budget over
            // [1, 1600], task-067's rule.
            std::uint64_t lo = kSearchLo;
            std::uint64_t hi = kBudgetHi;
            while (lo < hi) {
                const std::uint64_t mid = lo + (hi - lo) / 2;
                ASSERT_TRUE(ProbeOff("search", seq, rng_seed, mid, log, invalid, stats, wall_ms));
                if (stats.crashes > 0) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            r.min_budget = lo;

            // --- The point itself and the point below it, so the transition
            // is probed from both sides rather than inferred from the search.
            CampaignStats at_min;
            std::uint64_t wall_at_min = 0;
            ASSERT_TRUE(ProbeOff("probe-N", seq, rng_seed, r.min_budget, log, invalid, at_min,
                                 wall_at_min));
            EXPECT_GT(at_min.crashes, 0U)
                << "no crash at the budget the search called minimal, rng_seed=" << rng_seed;
            if (r.min_budget > kSearchLo) {
                CampaignStats below;
                std::uint64_t wall_below = 0;
                ASSERT_TRUE(ProbeOff("probe-N-1", seq, rng_seed, r.min_budget - 1, log, invalid,
                                     below, wall_below));
                EXPECT_EQ(below.crashes, 0U)
                    << "budget below the minimum crashes — the point is not the transition, "
                       "rng_seed="
                    << rng_seed;
            }
        }

        std::string witness;
        r.monotonic = MonotonicOverLog(log, witness);
        if (!r.monotonic) {
            std::cout << "CEILING-SPREAD-NONMONOTONIC rng_seed=" << rng_seed
                      << " witness=" << witness << '\n'
                      << std::flush;
        }
        EXPECT_TRUE(r.monotonic) << "observation is not monotonic in the budget for rng_seed="
                                 << rng_seed << ": " << witness;

        r.probes = log.size();
        for (const Probe& p : log) {
            r.max_wall_ms = std::max(r.max_wall_ms, p.wall_ms);
        }

        // --- PAIRWISE ratio: this seed's numerator over THIS seed's
        // task-071 denominator. No other seed's number enters here.
        r.ratio_is_lower_bound = !r.cracked_at_hi;
        r.ratio = static_cast<double>(r.cracked_at_hi ? r.min_budget : kBudgetHi) /
                  static_cast<double>(r.task071_min_budget);

        std::cout << "CEILING-SPREAD-SEED rng_seed=" << r.rng_seed
                  << " cracked_at_hi=" << (r.cracked_at_hi ? "yes" : "no")
                  << " min_budget_noconcolic="
                  << (r.cracked_at_hi ? std::to_string(r.min_budget) : std::string("none"))
                  << " hi_reached=" << kBudgetHi << " probes=" << r.probes
                  << " monotonic=" << (r.monotonic ? "yes" : "no")
                  << " task071_min_budget=" << r.task071_min_budget
                  << " ratio=" << (r.ratio_is_lower_bound ? ">=" : "") << Num(r.ratio)
                  << " ratio_kind=" << (r.ratio_is_lower_bound ? "lower-bound" : "exact")
                  << " max_wall_ms=" << r.max_wall_ms << '\n'
                  << std::flush;
        results.push_back(r);
    }

    // --- Ensemble summary. Every seed contributes exactly one pairwise
    // ratio; a seed that did not crack contributes it as a lower bound, and
    // that is why the summary's own kind is `mixed` unless all ten agree.
    std::vector<double> ratios;
    std::size_t no_crash_at_hi = 0;
    std::size_t cracked = 0;
    std::string cracked_names;
    std::size_t probes_total = 0;
    std::uint64_t max_probe_wall_ms = 0;
    int monotonic_seeds = 0;
    for (const SeedResult& r : results) {
        ratios.push_back(r.ratio);
        probes_total += r.probes;
        max_probe_wall_ms = std::max(max_probe_wall_ms, r.max_wall_ms);
        if (r.monotonic) {
            ++monotonic_seeds;
        }
        if (r.cracked_at_hi) {
            ++cracked;
            cracked_names += (cracked_names.empty() ? "" : ",") + std::to_string(r.rng_seed);
        } else {
            ++no_crash_at_hi;
        }
    }
    if (cracked_names.empty()) {
        cracked_names = "none";
    }
    const double ratio_min = ratios.empty() ? 0.0 : *std::min_element(ratios.begin(), ratios.end());
    const double ratio_max = ratios.empty() ? 0.0 : *std::max_element(ratios.begin(), ratios.end());
    const double ratio_median = MedianOf(ratios);

    // The kind, by the rule printed above and not rewritten after the fact.
    const char* ratio_kind = (cracked == 0)                ? "lower-bound"
                             : (cracked == results.size()) ? "exact"
                                                           : "mixed";

    // The control: seed 7 is task-070's, so its outcome must reproduce
    // task-070's pin. If it does not, no other row of the table is proven.
    bool control_reproduces = false;
    for (const SeedResult& r : results) {
        if (r.rng_seed == kControlRngSeed) {
            control_reproduces = (r.cracked_at_hi == kControlExpectedCrackedAtHi);
        }
    }
    EXPECT_TRUE(control_reproduces)
        << "control seed " << kControlRngSeed << " did not reproduce task-070's outcome at budget "
        << kBudgetHi;

    EXPECT_TRUE(invalid.empty()) << "disarmed probes that called the solver: " << invalid.size();
    for (const std::string& name : invalid) {
        ADD_FAILURE() << "invalid disarmed probe: " << name;
    }

    if (cracked > 0) {
        std::cout << "CEILING-SPREAD-CRACKED seeds=" << cracked_names << '\n' << std::flush;
    }

    std::cout << "CEILING-SPREAD-VERDICT: ADD-GATE-CEILING-SEED-SPREAD: seeds=" << kRngSeeds.size()
              << ", seeds_preregistered=yes, budget_hi=" << kBudgetHi
              << ", seeds_no_crash_at_hi=" << no_crash_at_hi
              << ", seeds_cracked_without_solver=" << cracked << ", cracked_seeds=" << cracked_names
              << ", ratio_min=" << Num(ratio_min) << ", ratio_max=" << Num(ratio_max)
              << ", ratio_median=" << Num(ratio_median) << ", ratio_kind=" << ratio_kind
              << ", control_seed7_reproduces_task070=" << (control_reproduces ? "yes" : "no")
              << ", pairing=per-seed"
              << ", monotonic_verified_per_seed=" << monotonic_seeds << "/" << kRngSeeds.size()
              << ", invalid_probes=" << invalid.size() << ", probes_total=" << probes_total
              << ", max_probe_wall_ms=" << max_probe_wall_ms
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
