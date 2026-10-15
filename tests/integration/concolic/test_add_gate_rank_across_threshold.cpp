// task-108, ADR 0047: does the DONOR's rank survive the stagnation threshold?
//
// Everything this series publishes about the price of the verbatim-composition
// niche is quoted from ONE RNG seed, the donor rng_seed=7. task-071 measured
// the ensemble of ten seeds and put the donor at rank 7/10
// (docs/experiments/solver-add-gate-budget-seed-spread/raw-seed-spread.txt:53),
// and task-103 turned that into a correction: point publications overstate the
// price by roughly 1.5x against the ensemble median
// (docs/experiments/solver-niche-donor-representativeness/report.md).
//
// That correction was measured at the DONOR's stagnation threshold 8 and only
// there. The fuzzer's own default is 64 (src/core/campaign.h:58), and task-081
// showed the price at 64 is a different number entirely: min_budget=83 against
// 18 at threshold 8 (docs/experiments/solver-add-gate-threshold64/report.md).
// Nobody has measured whether the ORDER of the seeds is the same at 64 as at
// 8, so nobody is licensed to carry the x1.5 correction across the threshold.
// task-100 left exactly this cell empty (ratios_uncomputable=1).
//
// This harness answers the smaller question that fits in one unit: on THREE
// pre-registered seeds, is the order at 64 the order at 8? The full ensemble of
// ten at 64 does not fit — each probe at 64 costs several times a probe at 8.
// Three points are NOT a median and this file never calls them one.
//
// The three seeds and the tie-break, both fixed here before the run:
//   * minimal   t8 min_budget = 10 -> seeds 1, 3, 23 all hold 10;
//   * median    t8 min_budget = 12 -> seeds 17, 29 both hold 12;
//   * donor     t8 min_budget = 18 -> seed 7, unique.
// The extremes are NOT unique, so a rule is needed rather than a preference:
// among the seeds holding the wanted value, take the FIRST in task-071's own
// pre-registration order 7,1,2,3,11,13,17,23,29,31 (raw-seed-spread.txt:16).
// That yields seed 1 for the minimum and seed 17 for the median. The rule is
// mechanical and is printed with the seeds before the first probe.
//
// The donor is re-run here as the CONTROL of the stand, not quoted: it must
// land back on task-081's 83. It runs FIRST, so by the time the two new seeds
// are measured the bench has already had to reproduce a published number. If
// the control misses, every line about transferability is void — the
// disagreement is then about this stand, not about task-081.
//
// The method of locating min_budget is task-081's, unchanged: one ticket probe
// at the top of the interval, then binary search on `crashes > 0` with
// `hi = mid` / `lo = mid + 1`, answer `lo`, then probe-N and probe-N-1 around
// the transition (test_add_gate_budget_threshold64.cpp:490-551). The interval
// stays 1..400, also task-081's. Changing either would make the numbers
// incomparable with the very report this file re-measures.
//
// The verdict rule is fixed BEFORE the run (kOrderRule, kTransferRule) so that
// order_preserved and correction_transferable are read off the printed triples
// mechanically instead of argued in prose afterwards.
//
// A seed whose crash is not reached inside 1..400 publishes min_budget=none
// and a lower bound. That is a result, not a failure.
//
// Hard wall-clock budget for the whole harness: kWalltimeBudgetS seconds.
// Stopping on it is a legal outcome; every probe that was planned and not run
// is named in the raw log rather than dropped.
//
// Boundaries. src/ is not modified by a single character, the default in
// campaign.h is not touched, and the reports of task-081, task-100 and
// task-103 are not edited. No benchmark fuzzing campaigns are started: the
// fixture is synthetic and each probe is one bounded in-process campaign.

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
// reason to skip. The message names artifacts by their REPO-RELATIVE path so
// that even a skipped run leaves no absolute path in the raw log. Unlike the
// donor this sweep needs no sub_gate: the whole axis is measured on add_gate,
// and the negative controls of the series (sub_gate at full budget, add_gate
// with concolic out of reach) already stand in task-067.
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
// campaign itself reads, exactly as task-081 takes it, so the point measured
// here cannot drift away from the number the fuzzer runs with.
constexpr std::uint32_t kProductionThreshold = kDefaultConcolicStagnationThreshold;
static_assert(kProductionThreshold == 64,
              "src/core/campaign.h's kDefaultConcolicStagnationThreshold moved away from 64; "
              "task-108 compares seeds AT the production default and must be re-registered, "
              "not patched");

// The three seeds, and the threshold-8 numbers they were chosen by. Each value
// is quoted from the committed raw log of task-071 with its line; the choice is
// made by number, never by eye.
constexpr std::uint64_t kMinRngSeed = 1;      // raw-seed-spread.txt:87,  min_budget=10
constexpr std::uint64_t kMedianRngSeed = 17;  // raw-seed-spread.txt:269, min_budget=12
constexpr std::uint64_t kDonorRngSeed = 7;    // raw-seed-spread.txt:53,  min_budget=18

constexpr std::uint64_t kT8Min = 10;
constexpr std::uint64_t kT8Median = 12;
constexpr std::uint64_t kT8Donor = 18;

// The tie-break, fixed before the run. Both extremes are shared: 10 by seeds
// 1, 3, 23 and 12 by seeds 17, 29. Ties are resolved by task-071's own
// pre-registration order (raw-seed-spread.txt:16), first wins.
constexpr const char* kSelectionRule =
    "t8 min_budget read from task-071 raw-seed-spread.txt; minimum value 10 is held by seeds "
    "1,3,23 and median value 12 by seeds 17,29, so ties are broken by task-071's "
    "pre-registration order 7,1,2,3,11,13,17,23,29,31 (raw-seed-spread.txt:16), first wins: "
    "min->1, median->17, donor->7";

// The control. The donor at the production threshold was measured by task-081
// (docs/experiments/solver-add-gate-threshold64/report.md:12, min_budget_at_64=83)
// and is RE-RUN here. A control that is only cited proves nothing about the
// stand the two new numbers came from.
constexpr std::uint64_t kDonorExpectedT64 = test_support::strict_terminal_budget(83);

// PRE-REGISTERED sweep order: the control FIRST, the two new seeds after it.
constexpr std::array<std::uint64_t, 3> kSeeds = {kDonorRngSeed, kMinRngSeed, kMedianRngSeed};

// PRE-REGISTERED publication order for the triples in the verdict, which is a
// different order from the sweep: ascending in the t8 value, so `t8` reads
// 10,12,18 and `t64` reads the same three seeds in the same slots.
constexpr std::array<std::uint64_t, 3> kPublishSeeds = {kMinRngSeed, kMedianRngSeed, kDonorRngSeed};
constexpr std::array<std::uint64_t, 3> kPublishT8 = {kT8Min, kT8Median, kT8Donor};

// Search interval, task-081's, unchanged. Widening or narrowing it would make
// the located minima incomparable with the number the control has to hit.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 400;

// THE ORDER RULE, fixed in source before any number of this run is read. At
// threshold 8 the three values are strictly increasing in the published order
// (10 < 12 < 18). Preservation is read non-strictly: a tie does not refute a
// RANK, it only fails to confirm the strict version, which is printed
// separately so both readings are visible.
constexpr const char* kOrderRule =
    "order_preserved=yes iff t64(min-seed) <= t64(median-seed) <= t64(donor-seed); "
    "order_strict=yes iff both inequalities are strict, matching 10<12<18 at t8; "
    "either is undecided if any of the three has min_budget=none";

// THE TRANSFER RULE, likewise fixed before the run. The correction may be
// carried across the threshold only if the ORDER holds and the donor/min ratio
// is the same ratio within the resolution of the ladder itself. That
// resolution is not a taste: each minimum is located to +-1 budget unit, so
// the ratio donor/min carries about 1/18 + 1/10 ~ 16% at threshold 8. The band
// is set at 20%, just outside it, and is not widened afterwards.
constexpr std::int64_t kTransferTolerancePct = 20;
constexpr const char* kTransferRule =
    "correction_transferable=yes iff order_preserved=yes and |ratio_t64 - ratio_t8| <= 20% of "
    "ratio_t8, where ratio = min_budget(donor)/min_budget(min-seed); the 20% band is the "
    "ladder's own resolution (+-1 budget unit on each of 18 and 10 is about 16%); undecided "
    "if any min_budget is none or the wall-clock budget was hit";

// Hard wall-clock budget for the WHOLE harness, control included. Checked
// before every probe is admitted; a probe is never started that the budget
// cannot pay for. task-081 measured three thresholds over 1..400 well inside
// its own 900 s, and the 64-point is the expensive one; three seeds all at 64
// are therefore given 2700 s, the ceiling this unit was registered with.
constexpr double kWalltimeBudgetS = 2700.0;

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
        return "n/a";
    }
    const std::uint64_t x100 = (num * 100 + den / 2) / den;
    const std::uint64_t whole = x100 / 100;
    const std::uint64_t frac = x100 % 100;
    return std::to_string(whole) + "." + (frac < 10 ? "0" : "") + std::to_string(frac);
}

std::int64_t RatioX100(std::uint64_t num, std::uint64_t den) {
    if (den == 0) {
        return -1;
    }
    return static_cast<std::int64_t>((num * 100 + den / 2) / den);
}

struct Probe {
    std::uint64_t rng_seed = 0;
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_called = false;
};

// One bounded campaign, its counters and its wall time. Identical to the
// donor's (test_add_gate_budget_threshold64.cpp:275-326) except that the RNG
// seed is the swept parameter and the stagnation threshold is the constant.
// Fatal assertions inside report against the calling test; callers must bail
// out on ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint64_t rng_seed, std::uint64_t max_iterations, CampaignStats& out_stats,
                 std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_rank_across_threshold";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-rank-across-threshold");
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
    EXPECT_LE(out_stats.execs, max_iterations) << "execution budget must include preparation";
    const auto t1 = std::chrono::steady_clock::now();
    out_wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    std::filesystem::remove_all(base, ec);
}

// Every measured number in the report is read off one of these lines. The
// shape is fixed so that a rerun differs only in `wall_ms`.
void PrintProbe(const char* phase, int seq, std::uint64_t rng_seed, std::uint64_t budget,
                const CampaignStats& s, std::uint64_t wall_ms) {
    std::cout << "RANK-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
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
// probes of ONE seed — mixing seeds would compare different
// campaign configurations. `pick` selects which observation is examined, so
// the crash and the concolic call are checked by the same predicate.
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
// OUT of the order comparison rather than being folded in as a zero.
struct SeedResult {
    std::uint64_t rng_seed = 0;
    std::uint64_t t8_min_budget = 0;
    bool ran = false;
    bool crashed_at_hi = false;
    bool concolic_called_at_hi = false;
    std::uint64_t concolic_calls_at_hi = 0;
    bool first_call_search_complete = false;
    std::uint64_t first_concolic_iteration = 0;
    bool crash_search_complete = false;
    std::uint64_t min_budget = 0;
    bool at_min_probed = false;
    std::uint64_t concolic_calls_at_min = 0;
    std::uint64_t concolic_crashes_at_min = 0;
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
    std::cout << "RANK-SKIPPED rng_seed=" << out.rng_seed << " probe=" << what
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
// MeasureThreshold (test_add_gate_budget_threshold64.cpp:443-593): a ticket
// probe at the top of the interval, then the same binary search — mid, probe,
// `hi = mid` when the observation is present and `lo = mid + 1` when it is
// not, answer `lo` — run once on `concolic_calls > 0` for the iteration of the
// first concolic call and once on `crashes > 0` for the minimal crash budget,
// then probe-N and probe-N-1. What changed against the donor harness is which
// parameter is swept, and nothing else.
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
        std::cout << "RANK-NONMONOTONIC observation=crash rng_seed=" << rng_seed
                  << " witness=" << crash_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_crash) << "crash not monotone in the budget, rng_seed=" << rng_seed;

    std::string call_witness;
    out.monotonic_call = MonotonicOverLog(log, PickConcolicCalled, call_witness);
    if (!out.monotonic_call) {
        std::cout << "RANK-NONMONOTONIC observation=concolic_call rng_seed=" << rng_seed
                  << " witness=" << call_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_call)
        << "concolic call not monotone in the budget, rng_seed=" << rng_seed;

    out.probes = seq - seq_before;

    // THE line the report reads its three numbers off. Its shape is fixed by
    // the unit's registration and nothing else is printed with this prefix.
    std::cout << "RANK-ACROSS-THRESHOLD rng_seed=" << out.rng_seed
              << " threshold=" << kProductionThreshold << " min_budget="
              << (out.crash_search_complete ? std::to_string(out.min_budget) : std::string("none"))
              << " probes=" << out.probes << " wall_ms=" << out.wall_ms << '\n'
              << std::flush;

    std::cout << "RANK-POINT rng_seed=" << out.rng_seed << " t8_min_budget=" << out.t8_min_budget
              << " crashed_at_hi=" << (out.crashed_at_hi ? "yes" : "no")
              << " first_concolic_iteration="
              << (out.first_call_search_complete ? std::to_string(out.first_concolic_iteration)
                                                 : std::string("none"))
              << " concolic_calls_at_hi=" << out.concolic_calls_at_hi << " concolic_calls_at_min="
              << (out.at_min_probed ? std::to_string(out.concolic_calls_at_min)
                                    : std::string("n/a"))
              << " concolic_crashes_at_min="
              << (out.at_min_probed ? std::to_string(out.concolic_crashes_at_min)
                                    : std::string("n/a"))
              << " crash_at_min_minus_1="
              << (out.min_minus_1_probed ? (out.crash_at_min_minus_1 ? "yes" : "no") : "n/a")
              << " monotonic_crash=" << (out.monotonic_crash ? "yes" : "no")
              << " monotonic_call=" << (out.monotonic_call ? "yes" : "no")
              << " stop_reason=" << StopReason(out)
              << " skipped=" << (out.skipped.empty() ? std::string("none") : out.skipped) << '\n'
              << std::flush;
}

// The header of the raw log: what was fixed before the first probe ran.
void PrintMeta() {
    std::cout << "RANK-META budget_units=strict_execs historical_controls=legacy_requested "
                 "terminal_control_adjustment=plus_one gate=add_gate add_gate="
              << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL << " threshold=" << kProductionThreshold
              << " threshold_source=src/core/campaign.h:58 arm_seed=donor"
              << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi
              << " seeds=" << kSeeds.size()
              << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n'
              << "RANK-PREREGISTERED sweep_order=" << kSeeds[0] << "," << kSeeds[1] << ","
              << kSeeds[2] << " publish_order=" << kPublishSeeds[0] << "," << kPublishSeeds[1]
              << "," << kPublishSeeds[2] << " t8=" << kPublishT8[0] << "," << kPublishT8[1] << ","
              << kPublishT8[2] << " control_seed=" << kDonorRngSeed
              << " control_expected_min_budget=" << kDonorExpectedT64
              << " control_source=docs/experiments/solver-add-gate-threshold64/report.md:12"
              << " t8_source=docs/experiments/solver-add-gate-budget-seed-spread/"
                 "raw-seed-spread.txt:87,269,53"
              << " selection_rule=\"" << kSelectionRule << "\"\n"
              << "RANK-ORDER-RULE rule=\"" << kOrderRule << "\"\n"
              << "RANK-TRANSFER-RULE tolerance_pct=" << kTransferTolerancePct << " rule=\""
              << kTransferRule << "\"\n"
              << std::flush;
}

// The whole unit in one test: the control and the two new seeds under one
// wall-clock budget. They are not split, because the control is what licenses
// the two new numbers to be read at all — running them apart would let the
// comparison be published beside a control from a different process.
TEST(AddGateRankAcrossThreshold, DonorRankAtTheProductionStagnationThreshold) {
    const std::string why = MissingArtifact();
    if (!why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta();

    int seq = 0;
    std::array<SeedResult, kSeeds.size()> results{};
    for (std::size_t i = 0; i < kSeeds.size(); ++i) {
        // The control runs FIRST: by the time the two new seeds are measured,
        // the stand has already had to reproduce task-081's published 83.
        std::uint64_t t8 = 0;
        for (std::size_t k = 0; k < kPublishSeeds.size(); ++k) {
            if (kPublishSeeds[k] == kSeeds[i]) {
                t8 = kPublishT8[k];
            }
        }
        MeasureSeed(kSeeds[i], t8, seq, results[i]);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
    }

    // Re-indexed into publication order (min, median, donor) so the verdict's
    // two triples line up slot by slot.
    std::array<const SeedResult*, 3> pub{};
    for (std::size_t k = 0; k < kPublishSeeds.size(); ++k) {
        for (const SeedResult& r : results) {
            if (r.rng_seed == kPublishSeeds[k]) {
                pub[k] = &r;
            }
        }
        ASSERT_NE(pub[k], nullptr);
    }
    const SeedResult& s_min = *pub[0];
    const SeedResult& s_median = *pub[1];
    const SeedResult& s_donor = *pub[2];

    const bool control_holds =
        s_donor.crash_search_complete && s_donor.min_budget == kDonorExpectedT64;

    std::cout << "RANK-CONTROL-VERDICT control_seed=" << kDonorRngSeed
              << " expected_min_budget=" << kDonorExpectedT64 << " measured_min_budget="
              << (s_donor.crash_search_complete ? std::to_string(s_donor.min_budget)
                                                : std::string("none"))
              << " control_holds=" << (control_holds ? "yes" : "no")
              << " bench_verdict=" << (control_holds ? "same-bench" : "not-the-same-bench") << '\n'
              << std::flush;

    // The order, read off the three located minima by kOrderRule and nothing
    // else. A seed without a minimum makes the comparison undecided rather
    // than false: an unlocated minimum is above 400, which orders it against
    // nothing measured.
    const bool all_located = s_min.crash_search_complete && s_median.crash_search_complete &&
                             s_donor.crash_search_complete;
    const bool order_preserved = all_located && s_min.min_budget <= s_median.min_budget &&
                                 s_median.min_budget <= s_donor.min_budget;
    const bool order_strict = all_located && s_min.min_budget < s_median.min_budget &&
                              s_median.min_budget < s_donor.min_budget;

    const std::string ratio_t8 = Ratio2(kT8Donor, kT8Min);
    const std::string ratio_t64 =
        all_located ? Ratio2(s_donor.min_budget, s_min.min_budget) : std::string("n/a");

    const bool walltime_hit = s_min.walltime_hit || s_median.walltime_hit || s_donor.walltime_hit;

    // Transferability by kTransferRule, computed in integers scaled by 100 so
    // the printed decision and the printed ratios cannot disagree.
    const std::int64_t r8 = RatioX100(kT8Donor, kT8Min);
    const std::int64_t r64 = all_located ? RatioX100(s_donor.min_budget, s_min.min_budget) : -1;
    const bool within_band = all_located && r64 >= 0 &&
                             (r64 > r8 ? r64 - r8 : r8 - r64) * 100 <= kTransferTolerancePct * r8;
    const char* transferable = "undecided";
    if (all_located && !walltime_hit) {
        transferable = (order_preserved && within_band) ? "yes" : "no";
    }

    const std::uint64_t walltime_used = static_cast<std::uint64_t>(WalltimeUsedS());

    auto min_or_none = [](const SeedResult& r) {
        return r.crash_search_complete ? std::to_string(r.min_budget) : std::string("none");
    };

    std::cout << "RANK-VERDICT: RANK-ACROSS-THRESHOLD: seeds=" << kSeeds.size()
              << ", t8=" << kPublishT8[0] << "," << kPublishT8[1] << "," << kPublishT8[2]
              << ", t64=" << min_or_none(s_min) << "," << min_or_none(s_median) << ","
              << min_or_none(s_donor) << ", donor_control_t64=" << min_or_none(s_donor)
              << ", donor_control_matches_task081=" << (control_holds ? "yes" : "no")
              << ", order_preserved="
              << (all_located ? (order_preserved ? "yes" : "no") : std::string("undecided"))
              << ", order_strict="
              << (all_located ? (order_strict ? "yes" : "no") : std::string("undecided"))
              << ", ratio_donor_over_min_t8=" << ratio_t8
              << ", ratio_donor_over_min_t64=" << ratio_t64
              << ", correction_transferable=" << transferable
              << ", stagnation_threshold=" << kProductionThreshold
              << ", budget_ladder_max=" << kSearchHi
              << ", timeout_hit=" << (walltime_hit ? "yes" : "no") << ", probes=" << seq
              << ", seeds_are_a_median=no"
              << ", walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS)
              << ", walltime_used_s=" << walltime_used
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;

    EXPECT_TRUE(control_holds)
        << "control seed " << kDonorRngSeed
        << " did not reproduce the strict-budget equivalent of task-081's " << kDonorExpectedT64
        << " at the production threshold; the stand is not the same stand and every line about "
           "transferability is unproven";
    EXPECT_LE(walltime_used, static_cast<std::uint64_t>(kWalltimeBudgetS))
        << "the harness overran its own wall-clock budget";
}

}  // namespace
}  // namespace mlfuzzz3::core
