// task-109, ADR 0047: the empty cell of task-100 — the ensemble of ten seeds
// at the PRODUCTION stagnation threshold 64.
//
// task-100 reduced the denominators of every superiority ratio this project
// publishes and left exactly one cell empty:
// docs/experiments/solver-niche-ratio-denominators/report.md:96 "Отношение C
// при T=64 не пересчитывается: знаменатель при T=64 не измерен", and the same
// in the verdict line report.md:150 (ratios_uncomputable=1).
//
// Two later units narrowed the gap without closing it. task-103 showed the
// point publication overstates the price: the donor rng_seed=7 holds 18 and
// stands at rank 7/10 against an ensemble median of 12
// (docs/experiments/solver-niche-donor-representativeness/report.md), a
// correction of about 1.5x — but measured at threshold 8 only. task-108 then
// tried to carry that correction across the threshold on THREE seeds and was
// refused by the numbers: t8=10,12,18 became t64=107,87,83, order_preserved=no,
// correction_transferable=no
// (docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt:228).
//
// So the transfer is forbidden by measurement, and the cell is still empty:
// three points are not a median, which task-108's own report says. This
// harness measures the denominator DIRECTLY — all ten pre-registered seeds at
// threshold 64 — instead of transporting a correction that has already been
// shown not to travel.
//
// The ten seeds are NOT chosen here. They are task-071's pre-registration,
// quoted line by line from the committed raw log
// (docs/experiments/solver-add-gate-budget-seed-spread/raw-seed-spread.txt:16
// "SEED-SPREAD-PREREGISTERED seeds=7,1,2,3,11,13,17,23,29,31 ..."), and each
// seed's threshold-8 value is quoted verbatim with its line by
// PrintSourcePins() before the first probe runs. Inventing an ensemble here
// would make the T=64 median incomparable with the T=8 median it is meant to
// stand beside.
//
// The method of locating min_budget is task-081's, unchanged, exactly as
// task-108 kept it unchanged: one ticket probe at the top of the interval,
// then binary search on the predicate with `hi = mid` when the observation is
// present and `lo = mid + 1` when it is not, answer `lo`, then probe-N and
// probe-N-1 around the located transition
// (the crash-search loop at
// test_add_gate_budget_threshold64.cpp:495-511, inside MeasureThreshold at
// test_add_gate_budget_threshold64.cpp:443-593). The interval stays 1..400,
// also task-081's. Changing either would make these ten numbers incomparable
// with the three the controls have to reproduce.
//
// THE CONTROL IS INSIDE THE MEASUREMENT. Three of the ten seeds were already
// measured at 64 by task-108 and must land back on their published values:
//   rng_seed=7  -> 83   (raw-rank-across-threshold.txt:101)
//   rng_seed=1  -> 107  (raw-rank-across-threshold.txt:160)
//   rng_seed=17 -> 87   (raw-rank-across-threshold.txt:225)
// They run FIRST, so by the time the seven new seeds are measured the stand
// has already had to reproduce three published numbers. If any one of them
// misses, the median is NOT published: the verdict prints
// median_min_budget_t64=undefined with the mismatch spelled out in numbers,
// because a stand that cannot reproduce task-108 is not measuring what this
// file claims it measures.
//
// THE MEDIAN RULE, fixed here before any number of this run is read
// (kMedianRule): the median is taken over the SOLVED seeds only, in ascending
// order of min_budget; for an even count the two central order statistics are
// averaged and rounded half up; and it is computed at all only when at least
// kMinSolvedForMedian seeds were solved. Fewer than that prints
// median_min_budget_t64=undefined with the named reason — an honest outcome,
// not a failure. The rule is self-checked against task-071 before the sweep:
// applied to the ten pinned t8 values it must reproduce the published
// min_budget_median=12 (raw-seed-spread.txt:378), and that check is printed
// whatever it says.
//
// A seed whose crash is not reached inside 1..400 publishes min_budget=none
// with the lower bound 400 and stays out of the median rather than being
// folded in as a number nobody measured.
//
// Hard wall-clock budget for the whole harness: kWalltimeBudgetS seconds.
// task-108 spent 25 s on three seeds over the same interval at the same
// threshold (raw-rank-across-threshold.txt:228, walltime_used_s=25), so ten
// seeds are of the order of a minute and the budget below is two orders of
// margin. Stopping on it is a legal outcome; every probe that was planned and
// not run is named in the raw log rather than dropped, and timeout_hit is
// printed in either case.
//
// Boundaries. src/ is not modified by a single character, the default in
// campaign.h is not touched, and the reports of task-071, task-081, task-100,
// task-103 and task-108 are not edited. No benchmark fuzzing campaigns are
// started: the fixture is synthetic and each probe is one bounded in-process
// campaign.

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

// Empty when every artifact this sweep needs is present; otherwise the reason
// to skip. The message names artifacts by their REPO-RELATIVE path so that
// even a skipped run leaves no absolute path in the raw log. Like task-108
// this sweep needs no sub_gate: the whole ensemble is measured on add_gate,
// and the negative controls of the series already stand in task-067.
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

// The solver arm's own input seed, byte for byte the donor's
// (test_add_gate_crash_budget.cpp:194): a = 0x44332211, b = 0x2A2B2C2D (LE).
// HELD FIXED: this measurement varies the RNG seed only.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// The threshold every seed here is measured at. TAKEN from the header the
// campaign itself reads, exactly as task-081 and task-108 take it, so the
// ensemble measured here cannot drift away from the number the fuzzer runs
// with.
constexpr std::uint32_t kProductionThreshold = kDefaultConcolicStagnationThreshold;
static_assert(kProductionThreshold == 64,
              "src/core/campaign.h's kDefaultConcolicStagnationThreshold moved away from 64; "
              "task-109 measures the ensemble AT the production default and must be "
              "re-registered, not patched");

// One seed of task-071's pre-registration, carried with everything needed to
// pin it: the threshold-8 value, the line of the committed raw log it is
// quoted from, and the quoted line itself. Nothing here is typed from memory
// — every `quote` is the source line, byte for byte.
struct SeedSource {
    std::uint64_t rng_seed;
    std::uint64_t t8_min_budget;
    int t8_pin_line;
    const char* t8_quote;
};

// THE ENSEMBLE. Order is task-071's own pre-registration order
// (raw-seed-spread.txt:16 "SEED-SPREAD-PREREGISTERED
// seeds=7,1,2,3,11,13,17,23,29,31 control=7 control_expected_min_budget=18").
// Ten seeds, not one of them this unit's invention.
constexpr const char* kT8Pin =
    "docs/experiments/solver-add-gate-budget-seed-spread/raw-seed-spread.txt";

constexpr std::array<SeedSource, 10> kEnsemble = {{
    {7, 18, 53,
     "SEED-SPREAD-SEED rng_seed=7 crashed_at_hi=yes min_budget=18 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {1, 10, 87,
     "SEED-SPREAD-SEED rng_seed=1 crashed_at_hi=yes min_budget=10 probes=11 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {2, 11, 124,
     "SEED-SPREAD-SEED rng_seed=2 crashed_at_hi=yes min_budget=11 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {3, 10, 158,
     "SEED-SPREAD-SEED rng_seed=3 crashed_at_hi=yes min_budget=10 probes=11 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {11, 18, 195,
     "SEED-SPREAD-SEED rng_seed=11 crashed_at_hi=yes min_budget=18 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {13, 24, 232,
     "SEED-SPREAD-SEED rng_seed=13 crashed_at_hi=yes min_budget=24 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {17, 12, 269,
     "SEED-SPREAD-SEED rng_seed=17 crashed_at_hi=yes min_budget=12 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {23, 10, 303,
     "SEED-SPREAD-SEED rng_seed=23 crashed_at_hi=yes min_budget=10 probes=11 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {29, 12, 340,
     "SEED-SPREAD-SEED rng_seed=29 crashed_at_hi=yes min_budget=12 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
    {31, 23, 377,
     "SEED-SPREAD-SEED rng_seed=31 crashed_at_hi=yes min_budget=23 probes=12 monotonic=yes "
     "concolic_calls_at_min=1 concolic_crashes_at_min=1 crash_at_min_minus_1=no"},
}};

// The donor, the seed every point publication of this series is quoted from.
constexpr std::uint64_t kDonorRngSeed = 7;

// THE CONTROLS. Three of the ten already have a published value at 64 from
// task-108, and each is RE-RUN here rather than cited. A control that is only
// cited proves nothing about the stand the seven new numbers came from.
struct ControlSource {
    std::uint64_t rng_seed;
    std::uint64_t expected_t64;
    int pin_line;
    const char* quote;
};

constexpr const char* kControlPin =
    "docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt";

constexpr std::array<ControlSource, 3> kControls = {{
    {7, 83, 101,
     "RANK-ACROSS-THRESHOLD rng_seed=7 threshold=64 min_budget=83 probes=21 wall_ms=9391"},
    {1, 107, 160,
     "RANK-ACROSS-THRESHOLD rng_seed=1 threshold=64 min_budget=107 probes=19 wall_ms=8649"},
    {17, 87, 225,
     "RANK-ACROSS-THRESHOLD rng_seed=17 threshold=64 min_budget=87 probes=21 wall_ms=7572"},
}};

// PRE-REGISTERED sweep order: the three controls FIRST, in task-108's own
// order, then the seven new seeds in task-071's pre-registration order. So
// the stand has to reproduce three published numbers before it is allowed to
// produce a single new one.
constexpr std::array<std::uint64_t, 10> kSweepOrder = {7, 1, 17, 2, 3, 11, 13, 23, 29, 31};

// The sweep order must be a PERMUTATION of the ensemble, not merely a subset
// of it. The loop below indexes `results` by sweep position and only checks
// that each swept seed exists in kEnsemble, so a seed written twice — with
// another dropped — would pass that check, enter the median twice, and still
// print seeds=10. That is exactly the failure the unit's "ровно десять сидов
// из raw-seed-spread.txt, ни одного своего" forbids, so it is caught here, at
// compile time, rather than trusted to proofreading.
constexpr bool SweepOrderIsAPermutationOfEnsemble() {
    for (const SeedSource& s : kEnsemble) {
        int seen = 0;
        for (const std::uint64_t swept : kSweepOrder) {
            if (swept == s.rng_seed) {
                ++seen;
            }
        }
        if (seen != 1) {
            return false;
        }
    }
    return true;
}
static_assert(kSweepOrder.size() == kEnsemble.size(),
              "kSweepOrder and kEnsemble must hold the same number of seeds");
static_assert(SweepOrderIsAPermutationOfEnsemble(),
              "kSweepOrder must name every pre-registered seed exactly once; a repeated or "
              "dropped seed would silently change the ensemble the median is taken over");

// Search interval, task-081's, unchanged and shared with task-108. Widening
// or narrowing it would make the located minima incomparable with the three
// numbers the controls have to hit.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 400;

// THE MEDIAN RULE, fixed in source before any number of this run is read.
constexpr std::size_t kMinSolvedForMedian = 6;
constexpr const char* kMedianRule =
    "median_min_budget_t64 is taken over the SOLVED seeds only (min_budget!=none), sorted "
    "ascending; for an even count the two central order statistics are averaged and rounded "
    "half up; it is computed only when seeds_solved>=6 AND all three task-108 controls "
    "reproduced, otherwise median_min_budget_t64=undefined with the reason printed";

// THE RANK RULE, likewise fixed before the run. It is task-103's rule, the one
// that put the donor at 7/10 at threshold 8: rank counts how many seeds are
// STRICTLY cheaper than the donor, plus one, so ties do not inflate the rank.
constexpr const char* kRankRule =
    "donor_rank_t64=k/n where n=seeds_solved and k=1+#{solved seeds with min_budget strictly "
    "below the donor's}; ties therefore do not inflate it, which is task-103's own "
    "conservative lower rank (rank_low), and applied to task-071's t8 values it reproduces the "
    "donor's published 7/10";

// THE ORDER RULE. task-108 saw a full inversion on three points; on ten the
// comparison needs a rule that survives ties. Over all ordered pairs (i,j)
// with t8_i < t8_j: `preserved` iff every such pair has t64_i <= t64_j,
// `inverted` iff every such pair has t64_i >= t64_j, otherwise `mixed`. Both
// can hold only when every t64 is equal, and that case reads `preserved`.
constexpr const char* kOrderRule =
    "over all pairs (i,j) with t8_i<t8_j: order_vs_t8=preserved iff every such pair has "
    "t64_i<=t64_j; inverted iff every such pair has t64_i>=t64_j; otherwise mixed; undefined "
    "if fewer than two seeds were solved";

// Hard wall-clock budget for the WHOLE harness, controls included. task-108
// spent walltime_used_s=25 on three seeds over the same interval at the same
// threshold (raw-rank-across-threshold.txt:228); ten seeds are of the same
// order of magnitude and 1800 s is the ceiling this unit was registered with.
constexpr double kWalltimeBudgetS = 1800.0;

// Wall-clock accounting for the budget above. Started at process start, which
// is before the single test body runs, so it covers everything the harness
// does and not just the campaigns.
const std::chrono::steady_clock::time_point g_started = std::chrono::steady_clock::now();

double WalltimeUsedS() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - g_started).count();
}

// Admission control: a probe is admitted only while budget remains. Returning
// false is a legal stop, not a failure — the caller names the probe it did
// not run.
bool BudgetLeft() {
    return WalltimeUsedS() < kWalltimeBudgetS;
}

// Ratios are printed as integers scaled by 100 and rendered by hand: the
// verdict must be byte-identical on a rerun, and a locale-dependent float
// formatter is not worth that risk. Rounds half up.
std::string Ratio2(std::uint64_t num, std::uint64_t den) {
    if (den == 0) {
        return "undefined";
    }
    const std::uint64_t x100 = (num * 100 + den / 2) / den;
    const std::uint64_t whole = x100 / 100;
    const std::uint64_t frac = x100 % 100;
    return std::to_string(whole) + "." + (frac < 10 ? "0" : "") + std::to_string(frac);
}

// The median of kMedianRule, applied to an ALREADY SORTED ascending vector.
// Even counts average the two central order statistics and round half up, so
// the returned value stays an integer budget like every other number on the
// ladder. Callers guarantee the vector is non-empty.
std::uint64_t MedianSorted(const std::vector<std::uint64_t>& sorted) {
    const std::size_t n = sorted.size();
    if (n % 2 == 1) {
        return sorted[n / 2];
    }
    const std::uint64_t a = sorted[n / 2 - 1];
    const std::uint64_t b = sorted[n / 2];
    return (a + b + 1) / 2;
}

struct Probe {
    std::uint64_t rng_seed = 0;
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_called = false;
};

// One bounded campaign, its counters and its wall time. Identical to
// task-108's RunCampaign (test_add_gate_rank_across_threshold.cpp:334-385),
// which is in turn task-081's
// (test_add_gate_budget_threshold64.cpp:275-326): the RNG seed is the swept
// parameter and the stagnation threshold is the constant. Fatal assertions
// inside report against the calling test; callers must bail out on
// ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint64_t rng_seed, std::uint64_t max_iterations, CampaignStats& out_stats,
                 std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_ensemble_threshold64";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-ensemble-threshold64");
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
                             .concolic_stagnation_threshold = kProductionThreshold,
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
void PrintProbe(const char* phase, int seq, std::uint64_t rng_seed, std::uint64_t budget,
                const CampaignStats& s, std::uint64_t wall_ms) {
    std::cout << "ENSEMBLE64-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
              << " threshold=" << kProductionThreshold << " rng_seed=" << rng_seed
              << " budget=" << budget << " crashed=" << (s.crashes > 0 ? "yes" : "no")
              << " execs=" << s.execs << " crashes=" << s.crashes
              << " concolic_calls=" << s.concolic_calls
              << " concolic_candidates=" << s.concolic_candidates
              << " concolic_crashes=" << s.concolic_crashes
              << " concolic_unsat=" << s.concolic_unsat
              << " concolic_no_binding=" << s.concolic_no_binding
              << " concolic_timeout=" << s.concolic_timeout
              << " aborted=" << (s.aborted ? "yes" : "no") << " wall_ms=" << wall_ms << '\n'
              << std::flush;
}

// Runs one probe, records it in `log`, and returns false when a fatal
// assertion fired inside RunCampaign.
bool Probe1(const char* phase, int& seq, std::uint64_t rng_seed, std::uint64_t budget,
            std::vector<Probe>& log, CampaignStats& out_stats, std::uint64_t& out_wall_ms,
            std::uint64_t& inout_wall_total_ms) {
    RunCampaign(rng_seed, budget, out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    ++seq;
    inout_wall_total_ms += out_wall_ms;
    log.push_back(Probe{rng_seed, budget, out_stats.crashes > 0, out_stats.concolic_calls > 0});
    PrintProbe(phase, seq, rng_seed, budget, out_stats, out_wall_ms);
    return true;
}

// A pair (b1 < b2) with the observation present at b1 and absent at b2
// refutes monotonicity of that observation in the budget. Checked over ALL
// probes of ONE seed — mixing seeds would compare different campaign
// configurations. `pick` selects which observation is examined, so the crash
// and the concolic call are checked by the same predicate.
bool MonotonicOverLog(const std::vector<Probe>& log, bool (*pick)(const Probe&),
                      std::string& out_witness) {
    for (const Probe& lo : log) {
        if (!pick(lo)) {
            continue;
        }
        for (const Probe& hi : log) {
            if (pick(hi) || hi.budget <= lo.budget) {
                continue;
            }
            out_witness = "present at budget=" + std::to_string(lo.budget) +
                          " but absent at budget=" + std::to_string(hi.budget);
            return false;
        }
    }
    return true;
}

bool PickCrashed(const Probe& p) {
    return p.crashed;
}
bool PickConcolicCalled(const Probe& p) {
    return p.concolic_called;
}

// One seed's outcome at the production threshold. `crashed_at_hi=false` means
// the crash search never ran: that seed publishes min_budget=none and stays
// OUT of the median rather than being folded in as a zero.
struct SeedResult {
    std::uint64_t rng_seed = 0;
    std::uint64_t t8_min_budget = 0;
    bool ran = false;
    bool crashed_at_hi = false;
    bool concolic_called_at_hi = false;
    std::uint64_t concolic_calls_at_hi = 0;
    std::uint64_t execs_at_hi = 0;
    bool first_call_search_complete = false;
    std::uint64_t first_concolic_iteration = 0;
    bool crash_search_complete = false;
    std::uint64_t min_budget = 0;
    bool at_min_probed = false;
    std::uint64_t concolic_calls_at_min = 0;
    std::uint64_t concolic_crashes_at_min = 0;
    std::uint64_t execs_at_min = 0;
    bool min_minus_1_probed = false;
    bool crash_at_min_minus_1 = false;
    bool monotonic_crash = true;
    bool monotonic_call = true;
    int probes = 0;
    std::uint64_t wall_ms = 0;
    bool walltime_hit = false;
    std::string skipped;
};

// A probe the protocol planned and the wall-clock budget refused. It is
// NAMED, in the raw log and in the result, rather than silently dropped: a
// missing probe that nobody names is indistinguishable from a probe that was
// never planned.
void NameSkipped(SeedResult& out, const char* what) {
    out.walltime_hit = true;
    out.skipped += out.skipped.empty() ? "" : ",";
    out.skipped += what;
    std::cout << "ENSEMBLE64-SKIPPED rng_seed=" << out.rng_seed << " probe=" << what
              << " reason=walltime walltime_used_s=" << static_cast<std::uint64_t>(WalltimeUsedS())
              << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n'
              << std::flush;
}

const char* StopReason(const SeedResult& r) {
    if (r.walltime_hit) {
        return "walltime";
    }
    return r.crashed_at_hi ? "crash" : "hi";
}

// The whole protocol for ONE seed, identical in rule to task-081's
// MeasureThreshold (test_add_gate_budget_threshold64.cpp:443-593) and to
// task-108's MeasureSeed: a ticket probe at the top of the interval, then the
// same binary search — mid, probe, `hi = mid` when the observation is present
// and `lo = mid + 1` when it is not, answer `lo`
// (test_add_gate_budget_threshold64.cpp:495-511) — run once on
// `concolic_calls > 0` for the iteration of the first concolic call and once
// on `crashes > 0` for the minimal crash budget, then probe-N and probe-N-1.
// What changed against task-108 is how many seeds are swept, and nothing else.
void MeasureSeed(std::uint64_t rng_seed, std::uint64_t t8_min_budget, int& seq, SeedResult& out) {
    out.rng_seed = rng_seed;
    out.t8_min_budget = t8_min_budget;
    std::vector<Probe> log;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    const int seq_before = seq;

    if (!BudgetLeft()) {
        NameSkipped(out, "ticket");
        out.probes = seq - seq_before;
        return;
    }
    ASSERT_TRUE(Probe1("ticket", seq, rng_seed, kSearchHi, log, stats, wall_ms, out.wall_ms));
    ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors, rng_seed="
                                << rng_seed;
    out.ran = true;
    out.crashed_at_hi = stats.crashes > 0;
    out.concolic_called_at_hi = stats.concolic_calls > 0;
    out.concolic_calls_at_hi = stats.concolic_calls;
    out.execs_at_hi = stats.execs;

    // Iteration of the first concolic call. The minimal budget that produces
    // a call IS the iteration of that call: max_iterations enters only the
    // loop's stop condition, so a budget of N runs iterations 1..N.
    if (out.concolic_called_at_hi) {
        std::uint64_t lo = kSearchLo;
        std::uint64_t hi = kSearchHi;
        bool complete = true;
        while (lo < hi) {
            if (!BudgetLeft()) {
                NameSkipped(out, "first-call-search");
                complete = false;
                break;
            }
            const std::uint64_t mid = lo + (hi - lo) / 2;
            ASSERT_TRUE(
                Probe1("first-call-search", seq, rng_seed, mid, log, stats, wall_ms, out.wall_ms));
            if (stats.concolic_calls > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        out.first_call_search_complete = complete;
        if (complete) {
            out.first_concolic_iteration = lo;
        }
    }

    // Minimal crash budget, same search, predicate `crashes > 0`.
    if (out.crashed_at_hi) {
        std::uint64_t lo = kSearchLo;
        std::uint64_t hi = kSearchHi;
        bool complete = true;
        while (lo < hi) {
            if (!BudgetLeft()) {
                NameSkipped(out, "crash-search");
                complete = false;
                break;
            }
            const std::uint64_t mid = lo + (hi - lo) / 2;
            ASSERT_TRUE(
                Probe1("crash-search", seq, rng_seed, mid, log, stats, wall_ms, out.wall_ms));
            if (stats.crashes > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        out.crash_search_complete = complete;
        if (complete) {
            out.min_budget = lo;

            // The minimum re-run, so the raw log carries the counters at the
            // exact point the verdict quotes. `concolic_calls >= 1` HERE is
            // what proves the arm was armed at the minimum; a zero on this
            // line annuls the line rather than being explained away.
            if (BudgetLeft()) {
                CampaignStats at_min;
                std::uint64_t wall_at_min = 0;
                ASSERT_TRUE(Probe1("probe-N", seq, rng_seed, out.min_budget, log, at_min,
                                   wall_at_min, out.wall_ms));
                out.at_min_probed = true;
                out.concolic_calls_at_min = at_min.concolic_calls;
                out.concolic_crashes_at_min = at_min.concolic_crashes;
                out.execs_at_min = at_min.execs;
                EXPECT_GT(at_min.crashes, 0U)
                    << "crash absent at the located minimum, rng_seed=" << rng_seed;
                EXPECT_GT(at_min.concolic_calls, 0U)
                    << "arm DISARMED at the minimum (concolic_calls=0), rng_seed=" << rng_seed;
            } else {
                NameSkipped(out, "probe-N");
            }

            // One budget below the minimum must not crash: the local check
            // that the search landed on a real transition and not on an
            // artefact of the interval.
            if (out.min_budget > kSearchLo) {
                if (BudgetLeft()) {
                    CampaignStats below;
                    std::uint64_t wall_below = 0;
                    ASSERT_TRUE(Probe1("probe-N-1", seq, rng_seed, out.min_budget - 1, log, below,
                                       wall_below, out.wall_ms));
                    out.min_minus_1_probed = true;
                    out.crash_at_min_minus_1 = below.crashes > 0;
                    EXPECT_EQ(below.crashes, 0U)
                        << "crash present one below the located minimum, rng_seed=" << rng_seed;
                } else {
                    NameSkipped(out, "probe-N-1");
                }
            }
        }
    }

    std::string crash_witness;
    out.monotonic_crash = MonotonicOverLog(log, PickCrashed, crash_witness);
    if (!out.monotonic_crash) {
        std::cout << "ENSEMBLE64-NONMONOTONIC observation=crash rng_seed=" << rng_seed
                  << " witness=" << crash_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_crash) << "crash not monotone in the budget, rng_seed=" << rng_seed;

    std::string call_witness;
    out.monotonic_call = MonotonicOverLog(log, PickConcolicCalled, call_witness);
    if (!out.monotonic_call) {
        std::cout << "ENSEMBLE64-NONMONOTONIC observation=concolic_call rng_seed=" << rng_seed
                  << " witness=" << call_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_call)
        << "concolic call not monotone in the budget, rng_seed=" << rng_seed;

    out.probes = seq - seq_before;

    // THE line the report reads each seed's number off. Its shape is fixed by
    // the unit's registration and nothing else is printed with this prefix.
    // `concolic_calls` and `execs` here are the counters of the probe-N run AT
    // the located minimum; when the minimum was not located they are the
    // ticket probe's counters at budget=kSearchHi, and the same line already
    // says min_budget=none. Which of the two is being read is stated on the
    // ENSEMBLE64-META line, not left to the reader.
    const std::uint64_t line_calls =
        out.at_min_probed ? out.concolic_calls_at_min : out.concolic_calls_at_hi;
    const std::uint64_t line_execs = out.at_min_probed ? out.execs_at_min : out.execs_at_hi;
    std::cout << "ENSEMBLE64 rng_seed=" << out.rng_seed << " threshold=" << kProductionThreshold
              << " min_budget="
              << (out.crash_search_complete ? std::to_string(out.min_budget) : std::string("none"))
              << " probes=" << out.probes << " concolic_calls=" << line_calls
              << " execs=" << line_execs << " wall_ms=" << out.wall_ms << '\n'
              << std::flush;

    std::cout
        << "ENSEMBLE64-POINT rng_seed=" << out.rng_seed << " t8_min_budget=" << out.t8_min_budget
        << " crashed_at_hi=" << (out.crashed_at_hi ? "yes" : "no") << " first_concolic_iteration="
        << (out.first_call_search_complete ? std::to_string(out.first_concolic_iteration)
                                           : std::string("none"))
        << " concolic_calls_at_hi=" << out.concolic_calls_at_hi << " concolic_calls_at_min="
        << (out.at_min_probed ? std::to_string(out.concolic_calls_at_min) : std::string("n/a"))
        << " concolic_crashes_at_min="
        << (out.at_min_probed ? std::to_string(out.concolic_crashes_at_min) : std::string("n/a"))
        << " crash_at_min_minus_1="
        << (out.min_minus_1_probed ? (out.crash_at_min_minus_1 ? "yes" : "no") : "n/a")
        << " monotonic_crash=" << (out.monotonic_crash ? "yes" : "no")
        << " monotonic_call=" << (out.monotonic_call ? "yes" : "no")
        << " stop_reason=" << StopReason(out)
        << " skipped=" << (out.skipped.empty() ? std::string("none") : out.skipped) << '\n'
        << std::flush;
}

// Every input number of this run, with the line it is quoted from and the
// quoted line itself. Printed BEFORE the first probe, so the raw log carries
// its own inputs and a reader never has to trust this file's memory of them.
void PrintSourcePins() {
    for (const SeedSource& s : kEnsemble) {
        std::cout << "ENSEMBLE64-SOURCE rng_seed=" << s.rng_seed
                  << " t8_min_budget=" << s.t8_min_budget << " pin=" << kT8Pin << ':'
                  << s.t8_pin_line << " quote=\"" << s.t8_quote << "\"\n";
    }
    // The method itself, pinned to the line of task-081 that runs the very
    // probe this file's crash-search runs. The pin and its verbatim quote sit
    // on ONE line, because a quote a line away from its pin binds to nothing.
    std::cout << "ENSEMBLE64-METHOD-SOURCE pin=tests/integration/concolic/"
                 "test_add_gate_budget_threshold64.cpp:502 quote=\"            "
                 "ASSERT_TRUE(Probe1(\\\"crash-search\\\", seq, threshold, mid, log, stats, "
                 "wall_ms));\" function=MeasureThreshold function_pin=tests/integration/concolic/"
                 "test_add_gate_budget_threshold64.cpp:443 loop_range=495-511\n";
    for (const ControlSource& c : kControls) {
        std::cout << "ENSEMBLE64-CONTROL-SOURCE rng_seed=" << c.rng_seed
                  << " expected_min_budget_t64=" << c.expected_t64 << " pin=" << kControlPin << ':'
                  << c.pin_line << " quote=\"" << c.quote << "\"\n";
    }
    std::cout << std::flush;
}

// The header of the raw log: what was fixed before the first probe ran.
void PrintMeta() {
    std::cout
        << "ENSEMBLE64-META gate=add_gate add_gate=" << ADD_GATE_REL
        << " exec_server=" << EXEC_SERVER_REL << " cov_library=" << COV_LIBRARY_REL
        << " threshold=" << kProductionThreshold
        << " threshold_source=src/core/campaign.h:58 arm_seed=donor"
        << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi << " seeds=" << kEnsemble.size()
        << " controls=" << kControls.size()
        << " method_source=tests/integration/concolic/test_add_gate_budget_threshold64.cpp:495-511"
        << " ensemble_line_counters_source=probe-N-at-min|ticket-when-none"
        << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n';

    std::cout << "ENSEMBLE64-PREREGISTERED seeds=";
    for (std::size_t i = 0; i < kEnsemble.size(); ++i) {
        std::cout << (i ? "," : "") << kEnsemble[i].rng_seed;
    }
    std::cout << " sweep_order=";
    for (std::size_t i = 0; i < kSweepOrder.size(); ++i) {
        std::cout << (i ? "," : "") << kSweepOrder[i];
    }
    std::cout << " t8=";
    for (std::size_t i = 0; i < kEnsemble.size(); ++i) {
        std::cout << (i ? "," : "") << kEnsemble[i].t8_min_budget;
    }
    std::cout << " donor=" << kDonorRngSeed << " controls=";
    for (std::size_t i = 0; i < kControls.size(); ++i) {
        std::cout << (i ? "," : "") << kControls[i].rng_seed << ':' << kControls[i].expected_t64;
    }
    std::cout << " seed_list_source=" << kT8Pin << ":16"
              << " control_source=" << kControlPin << ":101,160,225\n";

    std::cout << "ENSEMBLE64-MEDIAN-RULE min_solved_for_median=" << kMinSolvedForMedian
              << " rule=\"" << kMedianRule << "\"\n"
              << "ENSEMBLE64-RANK-RULE rule=\"" << kRankRule << "\"\n"
              << "ENSEMBLE64-ORDER-RULE rule=\"" << kOrderRule << "\"\n"
              << std::flush;
}

// The rank of kRankRule: how many values are STRICTLY below `of`, plus one.
// `sorted` is ascending. Used BOTH by the self-check below and by the verdict,
// so the rule that is checked is literally the rule that is applied.
std::size_t RankOf(const std::vector<std::uint64_t>& sorted, std::uint64_t of) {
    std::size_t cheaper = 0;
    for (const std::uint64_t v : sorted) {
        if (v < of) {
            ++cheaper;
        }
    }
    return cheaper + 1;
}

// The rank rule checked against task-103 BEFORE the sweep, on task-071's own
// ten t8 values: it must reproduce the donor's published rank 7/10. Without
// this the comment on kRankRule is a claim nobody executes, and a T=64 rank
// computed by a different rule would not be comparable with the T=8 one.
bool PrintRankRuleSelfCheck() {
    std::vector<std::uint64_t> t8;
    t8.reserve(kEnsemble.size());
    std::uint64_t donor_t8 = 0;
    for (const SeedSource& s : kEnsemble) {
        t8.push_back(s.t8_min_budget);
        if (s.rng_seed == kDonorRngSeed) {
            donor_t8 = s.t8_min_budget;
        }
    }
    std::sort(t8.begin(), t8.end());
    const std::size_t rank = RankOf(t8, donor_t8);
    const bool holds = rank == 7 && t8.size() == 10;
    std::cout << "ENSEMBLE64-RANK-RULE-CHECK donor_t8=" << donor_t8
              << " t8_rank_recomputed=" << rank << "/" << t8.size() << " task103_published=7/10"
              << " rule_reproduces_task103=" << (holds ? "yes" : "no")
              << " pin=docs/experiments/solver-niche-donor-representativeness/"
                 "raw-donor-representativeness.txt:89 quote=\"donor_seed=7 donor_value=18 "
                 "rank_low=7/10 rank_high=8/10 tie_with_seeds=11\"\n"
              << std::flush;
    return holds;
}

// The median rule checked against task-071 BEFORE the sweep, on task-071's own
// ten t8 values: it must reproduce the published min_budget_median=12
// (raw-seed-spread.txt:378). This costs no campaign and catches the case where
// the rule coded here is not the rule the T=8 median was computed with — in
// which case the T=64 median would not be comparable with it.
bool PrintMedianRuleSelfCheck() {
    std::vector<std::uint64_t> t8;
    t8.reserve(kEnsemble.size());
    for (const SeedSource& s : kEnsemble) {
        t8.push_back(s.t8_min_budget);
    }
    std::sort(t8.begin(), t8.end());
    const std::uint64_t recomputed = MedianSorted(t8);
    const bool holds = recomputed == 12;
    std::cout << "ENSEMBLE64-MEDIAN-RULE-CHECK t8_median_recomputed=" << recomputed
              << " task071_published=12 rule_reproduces_task071=" << (holds ? "yes" : "no")
              << " pin=" << kT8Pin << ":378"
              << " quote=\"min_budget_median=12\"\n"
              << std::flush;
    return holds;
}

// The whole unit in one test: the three controls and the seven new seeds under
// one wall-clock budget. They are not split, because the controls are what
// license the seven new numbers to be read at all — running them apart would
// let the median be published beside controls from a different process.
TEST(AddGateEnsembleThreshold64, EnsembleOfTenSeedsAtTheProductionStagnationThreshold) {
    const std::string why = MissingArtifact();
    if (!why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta();
    PrintSourcePins();
    const bool rank_rule_holds = PrintRankRuleSelfCheck();
    EXPECT_TRUE(rank_rule_holds)
        << "the rank rule coded here does not reproduce task-103's published donor rank 7/10 on "
           "task-071's own ten t8 values; a T=64 rank computed by a different rule is not "
           "comparable with the T=8 one";

    const bool median_rule_holds = PrintMedianRuleSelfCheck();
    EXPECT_TRUE(median_rule_holds)
        << "the median rule coded here does not reproduce task-071's published median 12 on "
           "task-071's own ten t8 values; a T=64 median computed by a different rule is not "
           "comparable with the T=8 one";

    int seq = 0;
    std::array<SeedResult, kEnsemble.size()> results{};
    for (std::size_t i = 0; i < kSweepOrder.size(); ++i) {
        const std::uint64_t rng_seed = kSweepOrder[i];
        std::uint64_t t8 = 0;
        bool found = false;
        for (const SeedSource& s : kEnsemble) {
            if (s.rng_seed == rng_seed) {
                t8 = s.t8_min_budget;
                found = true;
            }
        }
        ASSERT_TRUE(found) << "sweep order names a seed outside the pre-registered ensemble: "
                           << rng_seed;
        MeasureSeed(rng_seed, t8, seq, results[i]);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
    }

    auto find = [&results](std::uint64_t rng_seed) -> const SeedResult* {
        for (const SeedResult& r : results) {
            if (r.rng_seed == rng_seed) {
                return &r;
            }
        }
        return nullptr;
    };

    // The controls, each printed with its expectation, its pin and its
    // measurement side by side. A mismatch is printed in NUMBERS and then
    // gates the median below; it is not explained away in prose.
    bool controls_match = true;
    for (const ControlSource& c : kControls) {
        const SeedResult* r = find(c.rng_seed);
        ASSERT_NE(r, nullptr);
        const bool holds = r->crash_search_complete && r->min_budget == c.expected_t64;
        controls_match = controls_match && holds;
        std::cout << "ENSEMBLE64-CONTROL rng_seed=" << c.rng_seed
                  << " expected_min_budget=" << c.expected_t64 << " measured_min_budget="
                  << (r->crash_search_complete ? std::to_string(r->min_budget)
                                               : std::string("none"))
                  << " matches=" << (holds ? "yes" : "no") << " pin=" << kControlPin << ':'
                  << c.pin_line << " quote=\"" << c.quote << "\"\n"
                  << std::flush;
    }
    std::cout << "ENSEMBLE64-CONTROL-VERDICT controls=" << kControls.size()
              << " control_seeds_match_task108=" << (controls_match ? "yes" : "no")
              << " bench_verdict=" << (controls_match ? "same-bench" : "not-the-same-bench") << '\n'
              << std::flush;

    // The solved seeds, in ascending order of the located minimum. Only these
    // enter the median, the rank and the order comparison.
    std::vector<std::uint64_t> solved;
    for (const SeedResult& r : results) {
        if (r.crash_search_complete) {
            solved.push_back(r.min_budget);
        }
    }
    std::sort(solved.begin(), solved.end());
    const std::size_t seeds_solved = solved.size();

    const SeedResult* donor = find(kDonorRngSeed);
    ASSERT_NE(donor, nullptr);
    const bool donor_solved = donor->crash_search_complete;

    // The median by kMedianRule, gated on BOTH the solved count and the
    // controls. Either gate failing prints undefined with the reason named.
    const bool enough_solved = seeds_solved >= kMinSolvedForMedian;
    const bool median_defined = enough_solved && controls_match && median_rule_holds;
    const std::uint64_t median = median_defined ? MedianSorted(solved) : 0;
    std::string median_str = median_defined ? std::to_string(median) : std::string("undefined");
    std::string median_reason = "computed";
    if (!median_rule_holds) {
        median_reason = "median-rule-does-not-reproduce-task071";
    } else if (!controls_match) {
        median_reason = "task108-controls-mismatch";
    } else if (!enough_solved) {
        median_reason = "seeds_solved=" + std::to_string(seeds_solved) + "<" +
                        std::to_string(kMinSolvedForMedian);
    }

    // The donor's rank by kRankRule: strictly cheaper seeds, plus one.
    std::string donor_rank = "undefined";
    if (donor_solved && seeds_solved > 0) {
        donor_rank =
            std::to_string(RankOf(solved, donor->min_budget)) + "/" + std::to_string(seeds_solved);
    }

    // The order comparison by kOrderRule, over every pair of SOLVED seeds
    // whose t8 values differ.
    std::vector<const SeedResult*> solved_seeds;
    for (const SeedResult& r : results) {
        if (r.crash_search_complete) {
            solved_seeds.push_back(&r);
        }
    }
    bool all_le = true;
    bool all_ge = true;
    for (const SeedResult* a : solved_seeds) {
        for (const SeedResult* b : solved_seeds) {
            if (a->t8_min_budget >= b->t8_min_budget) {
                continue;
            }
            if (a->min_budget > b->min_budget) {
                all_le = false;
            }
            if (a->min_budget < b->min_budget) {
                all_ge = false;
            }
        }
    }
    std::string order_vs_t8 = "undefined";
    if (solved_seeds.size() >= 2) {
        order_vs_t8 = all_le ? "preserved" : (all_ge ? "inverted" : "mixed");
    }

    const std::string donor_str =
        donor_solved ? std::to_string(donor->min_budget) : std::string("none");
    const std::string ratio_donor_over_median = (median_defined && donor_solved && median > 0)
                                                    ? Ratio2(donor->min_budget, median)
                                                    : std::string("undefined");

    bool walltime_hit = false;
    for (const SeedResult& r : results) {
        walltime_hit = walltime_hit || r.walltime_hit;
    }
    const std::uint64_t walltime_used = static_cast<std::uint64_t>(WalltimeUsedS());

    // The full sorted ensemble, so the median printed below can be recomputed
    // by hand from the raw log without rerunning anything.
    std::cout << "ENSEMBLE64-SORTED seeds_solved=" << seeds_solved << " min_budgets_ascending=";
    for (std::size_t i = 0; i < solved.size(); ++i) {
        std::cout << (i ? "," : "") << solved[i];
    }
    std::cout << " median_reason=" << median_reason << '\n' << std::flush;

    std::cout << "VERDICT: NICHE-ENSEMBLE-T64: seeds=" << kEnsemble.size()
              << ", seeds_solved=" << seeds_solved << ", median_min_budget_t64=" << median_str
              << ", donor_min_budget_t64=" << donor_str << ", donor_rank_t64=" << donor_rank
              << ", ratio_donor_over_median_t64=" << ratio_donor_over_median
              << ", denominator_for_task100_cell=" << median_str << ", order_vs_t8=" << order_vs_t8
              << ", control_seeds_match_task108=" << (controls_match ? "yes" : "no")
              << ", stagnation_threshold=" << kProductionThreshold
              << ", budget_ladder_max=" << kSearchHi
              << ", timeout_hit=" << (walltime_hit ? "yes" : "no")
              << ", walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS)
              << ", walltime_used_s=" << walltime_used
              << ", seeds_are_a_median=yes, src_modified=0, reports_modified=0\n"
              << std::flush;

    EXPECT_TRUE(controls_match)
        << "at least one of task-108's control seeds (7, 1, 17) did not reproduce its published "
           "min_budget at the production threshold; the stand is not the same stand and no "
           "median is published from this run";
    EXPECT_LE(walltime_used, static_cast<std::uint64_t>(kWalltimeBudgetS))
        << "the harness overran its own wall-clock budget";
}

}  // namespace
}  // namespace mlfuzzz3::core
