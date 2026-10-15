// task-113 (ADR-0047): the BIG-ENDIAN arm at the PRODUCTION stagnation
// threshold T = 64, taken over the TEN pre-registered seeds instead of one.
//
// Why this harness exists. task-111 measured the big-endian gate at T = 64 on
// a SINGLE seed and published be_min_budget_t64=92
// (docs/experiments/solver-niche-be-threshold64/report.md:9). It said so
// itself: `seeds=1, seeds_are_a_median=no` stands inside its own verdict line.
// The little-endian arm at the same threshold, meanwhile, has a MEDIAN over
// ten seeds — 83 (docs/experiments/solver-niche-ensemble-threshold64/
// report.md:226). The published ratio be_over_le_t64=1.11
// (docs/experiments/solver-niche-be-threshold64/report.md:11) therefore
// divides a POINT by a MEDIAN. task-103 showed the donor seed can sit in the
// expensive third of the spread, so the sign of the endianness penalty at
// T = 64 currently rests on two estimators of different kinds. This harness
// takes the missing one: the same ten seeds, the same ladder, one process.
//
// What is NOT re-measured here. `median_le_min_budget_t64=83` and
// `be_over_le_point_t64=1.11` are QUOTED as constants from the committed
// reports of task-109 and task-111 and never recomputed; recomputing them
// would replace a published denominator with a fresh one and destroy the
// comparison this unit exists to make.
//
// PRE-REGISTERED BEFORE THE RUN (see run.sh of
// docs/experiments/solver-niche-be-ensemble-threshold64/):
//   the seed list is task-103's, byte for byte, and is NOT re-drawn
//     (kRngSeeds, below; source line quoted in run.sh);
//   the ladder interval [1, 400] and the search rule are task-081's, reached
//     here through task-111 unchanged (kSearchLo/kSearchHi);
//   the stagnation threshold is the production 64 (kStagnationThreshold);
//   the stand control is the DONOR seed 7, which must reproduce task-111's 92
//     (kDonorSeed/kDonorExpectedBeT64); when it misses, no statement about
//     medians is made and the verdict prints donor_control_matches_task111=no;
//   the hard wall-time budget is 1800 s (kWalltimeBudgetS), checked before
//     every probe; on exhaustion timeout_hit=yes is printed instead of a
//     number that was not finished;
//   the MEDIAN RULE and the RANK RULE are task-109's, verbatim (kMedianRule,
//     kRankRule), including the publication floor of six solved seeds;
//   the ROUNDING RULE: every ratio is computed on the printed, two-decimal
//     rounding (Round2), so a reader recomputing from the printed lines gets
//     the same digits by construction.
//
// The min_budget search method is task-111's without a single change: a ticket
// probe at the upper bound of the interval, then a bisection on the predicate
// (`hi = mid` on an observed crash, `lo = mid + 1` without one), answer `lo`.
// The claim of sameness is proved by a pin, not by paraphrase:
// tests/integration/concolic/test_add_gate_be_threshold64.cpp:438 is the probe
// inside that bisection loop.
//
// What this harness does NOT show. Not the MECHANISM of the difference between
// the arms: it prices, it does not explain. Not a statement about real
// targets: add_gate_be is synthetic. Not that task-111 is wrong: it called its
// own number a point estimate, and this unit completes it rather than refuting
// it.

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
#include <cmath>
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

// The arm's own seed, byte for byte task-111's (test_add_gate_be_threshold64.cpp:216).
// Under the BIG-endian fixture the same eight bytes decode to a = 0x11223344,
// b = 0x2D2C2B2A -- both inside guard(), sum 0x3E4E5E6E != MAGIC, so the seed
// itself runs clean on the BE fixture. Not re-encoded for BE on purpose: this
// task varies the RNG seed of the campaign, not the input the arm starts from.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// THE SEED LIST, pre-registered by task-103 and taken here without a single
// change or addition:
// docs/experiments/solver-add-gate-budget-seed-spread/raw-seed-spread.txt:16 --
// "SEED-SPREAD-PREREGISTERED seeds=7,1,2,3,11,13,17,23,29,31 control=7
// control_expected_min_budget=18". The traversal order below is that line's
// order, and it is printed into the raw log BEFORE the first measurement.
constexpr std::array<std::uint64_t, 10> kRngSeeds = {7, 1, 2, 3, 11, 13, 17, 23, 29, 31};
static_assert(kRngSeeds.size() == 10,
              "the ensemble is exactly the ten pre-registered seeds; adding or dropping one "
              "would silently change the ensemble the median is taken over");

// The stand control. The donor seed must reproduce the number task-111
// published on it: docs/experiments/solver-niche-be-threshold64/report.md:9 --
// "VERDICT: NICHE-BE-T64: gate=add_gate_be, rng_seed=7, be_min_budget_t64=92,".
constexpr std::uint64_t kDonorSeed = 7;
constexpr std::uint64_t kDonorExpectedBeT64 = test_support::strict_terminal_budget(92);

// The production default, and the whole point of the unit.
constexpr std::uint32_t kStagnationThreshold = 64;

// Search interval, task-081's through task-111, unchanged. Widening or
// narrowing it would make the located minima incomparable with 92 and 83.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 400;

// QUOTED, NOT MEASURED. The little-endian median over the same ten seeds at
// the same threshold: docs/experiments/solver-niche-ensemble-threshold64/
// report.md:226 -- "median_min_budget_t64=83". And the point-estimate ratio
// task-111 published: docs/experiments/solver-niche-be-threshold64/
// report.md:11 -- "be_over_le_t64=1.11, be_over_le_t8=0.61,".
constexpr std::uint64_t kMedianLeT64 = 83;
constexpr double kBeOverLePointT64 = 1.11;

// THE MEDIAN RULE, task-109's verbatim, fixed in source before any number of
// this run is read.
constexpr std::size_t kMinSolvedForMedian = 6;
constexpr const char* kMedianRule =
    "median_be_min_budget_t64 is taken over the SOLVED seeds only (min_budget!=none), sorted "
    "ascending; for an even count the two central order statistics are averaged and rounded "
    "half up; it is computed only when seeds_solved>=6 AND the donor control reproduced "
    "task-111's 92, otherwise median_be_min_budget_t64=undefined with the reason printed";

// THE RANK RULE, task-109's verbatim (itself task-103's): rank counts how many
// seeds are STRICTLY cheaper than the donor, plus one, so ties do not inflate it.
constexpr const char* kRankRule =
    "donor_rank_be_t64=k/n where n=seeds_solved and k=1+#{solved seeds with min_budget strictly "
    "below the donor's}; ties therefore do not inflate it, which is task-103's conservative "
    "lower rank";

// THE OVERSTATEMENT RULE, fixed before the run: the published POINT ratio
// divided by the ratio of the two MEDIANS, on the printed two-decimal
// roundings. Above 1.00 the point estimate overstated the endianness penalty,
// below 1.00 it understated it. Undefined whenever the BE median is undefined.
constexpr const char* kOverstatementRule =
    "point_estimate_overstated_by = Round2(be_over_le_point_t64 / be_over_le_medians_t64), both "
    "operands taken as printed; >1.00 means the point estimate overstated the penalty, <1.00 "
    "means it understated it; undefined when the BE median is undefined";

// Hard wall-time budget for the whole unit, named in run.sh and in the report
// before the run. Checked before every probe; when it is spent the sweep stops
// where it stands and publishes stop_reason=walltime and timeout_hit=yes
// instead of a number it did not finish earning.
constexpr double kWalltimeBudgetS = 1800.0;

struct Probe {
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_enabled = true;
    const char* gate = "add_gate_be";
    std::uint64_t rng_seed = 0;
    // Carried per probe so the per-seed rollup below is a sum over exactly the
    // campaigns that ran, rather than a number re-derived from the log text.
    std::uint64_t execs = 0;
    std::uint64_t concolic_calls = 0;
    std::uint64_t wall_ms = 0;
};

// One bounded campaign, its counters and its wall time. Identical to
// test_add_gate_be_threshold64.cpp:275-326 except that the RNG seed is a
// PARAMETER here rather than the file-scope constant kRngSeed -- that is the
// only degree of freedom this task varies.
void RunCampaign(const char* fixture_bin, const char* seed_name, const char* metrics_tag,
                 std::uint64_t rng_seed, std::uint64_t max_iterations,
                 std::uint32_t stagnation_threshold, const char* workspace,
                 CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
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
                             .rng_seed = rng_seed,
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
    std::cout << "BE-ENS64-PROBE phase=" << phase << " seq=" << seq << " gate=" << p.gate
              << " rng_seed=" << p.rng_seed << " budget=" << p.budget
              << " concolic=" << (p.concolic_enabled ? "on" : "off")
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

// The per-seed rollup this task fixed before the run, one line per seed, all
// ten out of ONE process and ONE run. `probes` counts the campaigns this seed
// actually ran; `execs`, `concolic_calls` and `wall_ms` are the sums over
// exactly those campaigns; `min_budget` is the ladder's answer, or `none` when
// the seed was not cracked inside [kSearchLo, kSearchHi].
void PrintSeed(std::uint64_t rng_seed, const std::vector<Probe>& log, bool solved,
               std::uint64_t min_budget) {
    std::uint64_t execs = 0;
    std::uint64_t calls = 0;
    std::uint64_t wall = 0;
    for (const Probe& p : log) {
        execs += p.execs;
        calls += p.concolic_calls;
        wall += p.wall_ms;
    }
    std::cout << "BE-ENS64 rng_seed=" << rng_seed << " gate=add_gate_be"
              << " threshold=" << kStagnationThreshold << " min_budget=";
    if (solved) {
        std::cout << min_budget;
    } else {
        std::cout << "none";
    }
    std::cout << " probes=" << log.size() << " execs=" << execs << " concolic_calls=" << calls
              << " wall_ms=" << wall << '\n'
              << std::flush;
}

// Every ratio is compared AS PRINTED: rounded to two decimals, so the verdict
// a reader computes from the printed line and the verdict the harness prints
// are the same number by construction.
double Round2(double v) {
    return std::round(v * 100.0) / 100.0;
}

// Runs one probe, records it in `log`, and reports whether it crashed.
// Returns false when a fatal assertion fired inside RunCampaign.
bool Probe1(const char* phase, int seq, std::uint64_t rng_seed, std::uint64_t budget,
            std::uint32_t stagnation_threshold, bool armed, const char* workspace,
            std::vector<Probe>& log, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    RunCampaign(ADD_GATE_BE_BIN, "add_gate_be", "add-gate-be-ensemble-threshold64", rng_seed,
                budget, stagnation_threshold, workspace, out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    Probe p;
    p.budget = budget;
    p.crashed = out_stats.crashes > 0;
    p.concolic_enabled = armed;
    p.gate = "add_gate_be";
    p.rng_seed = rng_seed;
    p.execs = out_stats.execs;
    p.concolic_calls = out_stats.concolic_calls;
    p.wall_ms = out_wall_ms;
    log.push_back(p);
    PrintProbe(phase, seq, p, out_stats, out_wall_ms);
    return true;
}

// The bisection of task-067 as task-111 runs it at this threshold, applied to
// one seed. The predicate, the update rule and the answer are byte for byte
// tests/integration/concolic/test_add_gate_be_threshold64.cpp:425-449; the
// probe inside the loop is that file's line 438. Returns false on a fatal
// assertion or when the wall-time budget ran out mid-search; `out_min` is
// meaningful only when it returns true.
template <typename ClockFn>
bool BinarySearchMinBudget(std::uint64_t rng_seed, const char* phase, int& seq,
                           std::vector<Probe>& log, ClockFn elapsed_s, std::uint64_t& out_min,
                           bool& out_walltime_spent) {
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
        if (!Probe1(phase, ++seq, rng_seed, mid, kStagnationThreshold, /*armed=*/true,
                    "mlfuzzz3_add_gate_be_ensemble_threshold64", log, stats, wall_ms)) {
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
// the observation in the budget. Checked per seed over the armed probes.
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
                out_witness = "seed " + std::to_string(lo.rng_seed) +
                              ": crash at budget=" + std::to_string(lo.budget) +
                              " but none at budget=" + std::to_string(hi.budget);
                return false;
            }
        }
    }
    return true;
}

}  // namespace

TEST(AddGateBeEnsembleThreshold64, EnsembleOfTenSeedsOnTheBigEndianGateAtTheProductionThreshold) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    std::cout << "BE-ENS64-META budget_units=strict_execs historical_controls=legacy_requested "
                 "terminal_control_adjustment=plus_one add_gate_be="
              << ADD_GATE_BE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL
              << " encoding=u32be fields_offsets=0|4 arm_seed=donor stagnation_threshold="
              << kStagnationThreshold << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi
              << " rule=binary-search-task-067 method_pin=tests/integration/concolic/"
                 "test_add_gate_be_threshold64.cpp:438"
              << " walltime_budget_s=" << kWalltimeBudgetS << '\n'
              << std::flush;

    // --- The traversal order, printed BEFORE the first measurement so that a
    // reader can check it against task-103's pre-registered line without
    // trusting anything measured below.
    std::cout << "BE-ENS64-ORDER seeds=";
    for (std::size_t i = 0; i < kRngSeeds.size(); ++i) {
        std::cout << (i == 0 ? "" : ",") << kRngSeeds[i];
    }
    std::cout << " n=" << kRngSeeds.size() << " donor=" << kDonorSeed
              << " donor_expected_be_min_budget_t64=" << kDonorExpectedBeT64
              << " source=docs/experiments/solver-add-gate-budget-seed-spread/"
                 "raw-seed-spread.txt:16\n"
              << std::flush;
    std::cout << "BE-ENS64-RULES median=\"" << kMedianRule << "\" rank=\"" << kRankRule
              << "\" overstatement=\"" << kOverstatementRule
              << "\" min_solved_for_median=" << kMinSolvedForMedian
              << " median_le_min_budget_t64=" << kMedianLeT64
              << " (quoted: docs/experiments/solver-niche-ensemble-threshold64/report.md:226)"
              << " be_over_le_point_t64=" << std::fixed << std::setprecision(2) << kBeOverLePointT64
              << " (quoted: docs/experiments/solver-niche-be-threshold64/report.md:11)\n"
              << std::defaultfloat << std::flush;

    int seq = 0;
    bool walltime_spent = false;
    std::string stop_reason = "crash";
    std::vector<std::uint64_t> solved_budgets;
    std::uint64_t donor_min = 0;
    bool donor_solved = false;
    bool monotonic_all = true;
    std::string witness;
    std::size_t seeds_seen = 0;

    // --- One ladder per seed, all ten inside this single process and this
    // single run: no seed's number can come from a different sweep.
    for (const std::uint64_t rng_seed : kRngSeeds) {
        if (walltime_spent || elapsed_s() > kWalltimeBudgetS) {
            walltime_spent = true;
            stop_reason = "walltime";
            break;
        }
        ++seeds_seen;
        std::vector<Probe> log;
        CampaignStats stats;
        std::uint64_t wall_ms = 0;

        // Entry ticket: the upper bound of the interval must actually crash,
        // otherwise a bisection over [1, 400] is meaningless and the honest
        // outcome for this seed is min_budget=none.
        ASSERT_TRUE(Probe1("ticket", ++seq, rng_seed, kSearchHi, kStagnationThreshold,
                           /*armed=*/true, "mlfuzzz3_add_gate_be_ensemble_threshold64", log, stats,
                           wall_ms));
        ASSERT_FALSE(stats.aborted)
            << "campaign aborted on infrastructure errors, seed " << rng_seed;

        std::uint64_t min_budget = 0;
        bool searched = false;
        if (stats.crashes > 0) {
            searched = BinarySearchMinBudget(rng_seed, "search", seq, log, elapsed_s, min_budget,
                                             walltime_spent);
            if (::testing::Test::HasFatalFailure()) {
                return;
            }
        }
        if (walltime_spent) {
            stop_reason = "walltime";
        }

        // Probes around the transition, plus the arming proof: at the minimum
        // the solver must have fired at least once, read off the probe line
        // rather than off the code.
        if (searched) {
            CampaignStats at_min;
            std::uint64_t wall_at_min = 0;
            ASSERT_TRUE(Probe1("probe-N", ++seq, rng_seed, min_budget, kStagnationThreshold,
                               /*armed=*/true, "mlfuzzz3_add_gate_be_ensemble_threshold64", log,
                               at_min, wall_at_min));
            EXPECT_GT(at_min.crashes, 0U) << "no crash at the budget the search called minimal, "
                                             "seed "
                                          << rng_seed;
            EXPECT_GE(at_min.concolic_calls, 1U)
                << "the solver arm never fired at the minimum for seed " << rng_seed
                << " — this ladder says nothing about the solver";
            if (min_budget > kSearchLo && elapsed_s() <= kWalltimeBudgetS) {
                CampaignStats below;
                std::uint64_t wall_below = 0;
                ASSERT_TRUE(Probe1("probe-N-1", ++seq, rng_seed, min_budget - 1,
                                   kStagnationThreshold, /*armed=*/true,
                                   "mlfuzzz3_add_gate_be_ensemble_threshold64", log, below,
                                   wall_below));
                EXPECT_EQ(below.crashes, 0U) << "budget below the minimum crashes for seed "
                                             << rng_seed << " — the point is not the transition";
            }
        }

        std::string w;
        if (!MonotonicOverLog(log, w)) {
            monotonic_all = false;
            witness = w;
            std::cout << "BUDGET-NONMONOTONIC " << w << '\n' << std::flush;
        }

        PrintSeed(rng_seed, log, searched, min_budget);
        if (searched) {
            solved_budgets.push_back(min_budget);
            if (rng_seed == kDonorSeed) {
                donor_min = min_budget;
                donor_solved = true;
            }
        }
    }

    EXPECT_TRUE(monotonic_all) << "observation is not monotonic in the budget: " << witness;

    // --- THE STAND CONTROL. The donor seed must reproduce task-111's 92. When
    // it does not, nothing below licenses a statement about medians and the
    // verdict says so with a number, not with prose.
    const bool donor_control_ok = donor_solved && donor_min == kDonorExpectedBeT64;
    EXPECT_TRUE(donor_control_ok) << "donor seed " << kDonorSeed << " returned "
                                  << (donor_solved ? std::to_string(donor_min)
                                                   : std::string("none"))
                                  << " instead of expected strict budget " << kDonorExpectedBeT64
                                  << "; every median in this run is unproven";

    // --- The median, by the rule fixed above and nothing else.
    const std::size_t seeds_solved = solved_budgets.size();
    std::vector<std::uint64_t> sorted = solved_budgets;
    std::sort(sorted.begin(), sorted.end());
    const bool median_defined =
        seeds_solved >= kMinSolvedForMedian && donor_control_ok && !walltime_spent;
    std::uint64_t median_be = 0;
    if (median_defined) {
        if (seeds_solved % 2 == 1) {
            median_be = sorted[seeds_solved / 2];
        } else {
            const std::uint64_t a = sorted[seeds_solved / 2 - 1];
            const std::uint64_t b = sorted[seeds_solved / 2];
            median_be = static_cast<std::uint64_t>(
                std::floor((static_cast<double>(a) + static_cast<double>(b)) / 2.0 + 0.5));
        }
    }
    const char* median_undefined_reason = median_defined ? "none"
                                          : (seeds_solved < kMinSolvedForMedian)
                                              ? "seeds_solved_below_floor"
                                          : (!donor_control_ok) ? "donor_control_missed_task111"
                                                                : "walltime";

    // --- The donor's rank inside its own ensemble, by task-103's rule.
    std::size_t donor_rank = 0;
    if (donor_solved) {
        std::size_t cheaper = 0;
        for (const std::uint64_t b : solved_budgets) {
            if (b < donor_min) {
                ++cheaper;
            }
        }
        donor_rank = cheaper + 1;
    }

    const double ratio_donor_over_median =
        (median_defined && median_be > 0)
            ? Round2(static_cast<double>(donor_min) / static_cast<double>(median_be))
            : 0.0;
    const bool medians_ratio_defined = median_defined && median_be > 0;
    const double be_over_le_medians =
        medians_ratio_defined
            ? Round2(static_cast<double>(median_be) / static_cast<double>(kMedianLeT64))
            : 0.0;
    const bool overstated_defined = medians_ratio_defined && be_over_le_medians > 0.0;
    const double overstated_by =
        overstated_defined ? Round2(kBeOverLePointT64 / be_over_le_medians) : 0.0;

    const char* endian_sign = "undefined";
    if (medians_ratio_defined) {
        endian_sign = (median_be > kMedianLeT64)   ? "be_dearer"
                      : (median_be < kMedianLeT64) ? "le_dearer"
                                                   : "equal";
    }

    std::ostringstream med;
    if (median_defined) {
        med << median_be;
    } else {
        med << "undefined";
    }
    std::ostringstream rdm;
    std::ostringstream rmm;
    std::ostringstream ovr;
    if (medians_ratio_defined) {
        rdm << std::fixed << std::setprecision(2) << ratio_donor_over_median;
        rmm << std::fixed << std::setprecision(2) << be_over_le_medians;
    } else {
        rdm << "undefined";
        rmm << "undefined";
    }
    if (overstated_defined) {
        ovr << std::fixed << std::setprecision(2) << overstated_by;
    } else {
        ovr << "undefined";
    }
    std::ostringstream pnt;
    pnt << std::fixed << std::setprecision(2) << kBeOverLePointT64;
    std::ostringstream used;
    used << std::fixed << std::setprecision(1) << elapsed_s();

    std::cout << "BE-ENS64-VERDICT: NICHE-BE-ENSEMBLE-T64: gate=add_gate_be"
              << ", seeds=" << kRngSeeds.size() << ", seeds_solved=" << seeds_solved
              << ", median_be_min_budget_t64=" << med.str() << ", donor_be_min_budget_t64="
              << (donor_solved ? std::to_string(donor_min) : std::string("none"))
              << ", donor_control_matches_task111=" << (donor_control_ok ? "yes" : "no")
              << ", donor_rank_be_t64="
              << (donor_solved ? std::to_string(donor_rank) : std::string("none")) << "/"
              << seeds_solved << ", ratio_donor_over_median_be=" << rdm.str()
              << ", median_le_min_budget_t64=" << kMedianLeT64
              << ", be_over_le_medians_t64=" << rmm.str() << ", be_over_le_point_t64=" << pnt.str()
              << ", point_estimate_overstated_by=" << ovr.str()
              << ", endian_penalty_sign_at_t64_on_medians=" << endian_sign
              << ", stagnation_threshold=" << kStagnationThreshold
              << ", budget_ladder_max=" << kSearchHi
              << ", timeout_hit=" << (walltime_spent ? "yes" : "no") << ", seeds_are_a_median=yes"
              << ", src_modified=0, reports_modified=0\n"
              << std::flush;

    std::cout << "BE-ENS64-DETAIL: seeds_seen=" << seeds_seen
              << ", donor_expected_be_min_budget_t64=" << kDonorExpectedBeT64
              << ", median_undefined_reason=" << median_undefined_reason
              << ", min_solved_for_median=" << kMinSolvedForMedian << ", search_range=" << kSearchLo
              << ".." << kSearchHi << ", probes_total=" << seq
              << ", monotonic_verified=" << (monotonic_all ? "yes" : "no") << ", solved_sorted=";
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        std::cout << (i == 0 ? "" : ",") << sorted[i];
    }
    std::cout << ", stop_reason=" << stop_reason << ", walltime_budget_s=" << kWalltimeBudgetS
              << ", walltime_used_s=" << used.str()
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace mlfuzzz3::core
