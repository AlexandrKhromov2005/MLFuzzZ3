// task-110, ADR 0047: where does the seed order break — the intermediate
// stagnation threshold 32.
//
// What is already known. task-108 measured the same three RNG seeds at the
// donor's threshold 8 and at the production threshold 64 and found not a
// dented order but a full inversion: `t8=10,12,18` against `t64=107,87,83`,
// i.e. the cheapest seed at 8 is the dearest at 64 and back
// (docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt:228,
// line `RANK-VERDICT:`). The donor seed itself climbs monotonically over the
// same axis — 8 -> 18, 32 -> 51, 64 -> 83
// (docs/experiments/solver-add-gate-threshold64/report.md:14, «control_
// threshold32_equals_51=yes, prediction_printed_before_run=51,»).
//
// The gap. The inversion is a fact on TWO thresholds and is explained by
// nothing. Where it happens — immediately past 8 or only near 64 — is not
// measured, and whether it has any observable correlate in the counters the
// campaign already keeps is not measured either. This harness adds exactly
// one intermediate point, threshold 32, on the same ladder, for the same
// three seeds, and prints the counters beside each located minimum.
//
// What is fixed BEFORE the run, and why each thing is fixed here rather than
// decided afterwards:
//
//   * The three seeds and the numbers they were chosen by. 1 (t8=10),
//     17 (t8=12) and 7 (t8=18, the donor). Not re-picked: they are quoted
//     from task-108's committed raw log, so this point sits on the same three
//     seeds as the two points it is compared with.
//   * The ladder. task-081's method unchanged — a ticket probe at the top of
//     [1, 400], then binary search on `crashes > 0` for the minimal crash
//     budget, then probe-N and probe-N-1 around the located transition. A
//     different search would produce minima that are not comparable with the
//     control the stand has to hit.
//   * The control. The donor at threshold 32 must reproduce task-081's 51.
//     It runs FIRST, so by the time the two new seeds are measured the stand
//     has already had to prove it is the same stand.
//   * WHERE the counters on the RANK32 line come from (kCounterRule below):
//     the probe at the SMALLEST budget that crashes, i.e. the located minimum
//     re-run as probe-N. The ladder walks budgets, not time, so "the probe
//     where the crash appeared first" is the first budget that crashes and
//     NOT the chronologically first probe — the latter is the 400-iteration
//     ticket, which is the same budget for every seed and therefore carries
//     no information about rank. The ticket's counters are printed too, on
//     the RANK32-POINT line, so the raw log answers the other reading without
//     a rerun.
//   * The order rule (kOrderRule) and the correlate rule (kCorrelateRule),
//     both evaluated in code from the printed triples, so the word in the
//     verdict is a function of the numbers and not of the reading.
//
// Scope of the two mixed scopes on one line, said plainly: `probes` and
// `wall_ms` are the seed's totals over its whole ladder; `concolic_calls`,
// `concolic_candidates`, `concolic_no_binding` and `execs` are the snapshot
// at probe-N. When no minimum was located there is no snapshot, and all four
// counters print `none` rather than a zero that would read as a measurement.
//
// What this harness does NOT claim. That three points are a median — they are
// not, and the verdict says `seeds_are_a_median=no` in its own line. That a
// matching order is a cause: agreement between the rank and a counter on
// three points is a correlate, and the word "mechanism" is not used without a
// separate separating probe. That the break is localised finer than an
// interval: exactly three thresholds exist here, 8, 32 and 64.
//
// Budget. A hard 1800 s inside the harness (kWalltimeBudgetS); task-108 spent
// 25 s on the same three seeds at the dearer threshold 64, so the ceiling is
// slack, not a target. Every probe the protocol planned and the budget
// refused is NAMED in the raw log rather than dropped, and the run publishes
// the seeds that did fit.
//
// Boundaries. src/ is not modified by a single character, the default in
// campaign.h is not touched, and the reports of task-081 and task-108 are not
// edited. No benchmark fuzzing campaigns are started: the fixture is
// synthetic and each probe is one bounded in-process campaign.

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

// THE point this unit adds: the intermediate threshold, between the donor's 8
// and the production default. Written as a literal because it is NOT a
// default anybody runs with — it is the third rung of the axis 8, 32, 64 —
// while the two ends stay pinned to what the campaign itself reads, so the
// interval cannot silently stop being an interval.
constexpr std::uint32_t kThreshold32 = 32;
constexpr std::uint32_t kDonorThreshold = 8;
static_assert(kDefaultConcolicStagnationThreshold == 64,
              "src/core/campaign.h's kDefaultConcolicStagnationThreshold moved away from 64; "
              "task-108's t64 triple was measured at 64 and this harness compares against it");
static_assert(kDonorThreshold < kThreshold32 && kThreshold32 < kDefaultConcolicStagnationThreshold,
              "32 is only an INTERMEDIATE point while it lies strictly between the donor's "
              "threshold and the production default");

// The three seeds. NOT re-picked here: they are task-108's three, and both
// triples they are compared against are quoted, not recomputed.
constexpr std::uint64_t kMinRngSeed = 1;      // t8=10, t64=107
constexpr std::uint64_t kMedianRngSeed = 17;  // t8=12, t64=87
constexpr std::uint64_t kDonorRngSeed = 7;    // t8=18, t64=83

constexpr const char* kSeedSource =
    "docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt:228";
constexpr const char* kSeedSourceQuote =
    "RANK-VERDICT: RANK-ACROSS-THRESHOLD: seeds=3, t8=10,12,18, t64=107,87,83, "
    "donor_control_t64=83, donor_control_matches_task081=yes";

// The two triples this run is compared with, in publication order
// (min, median, donor). Quoted from the line above; NOT measured again.
constexpr std::array<std::uint64_t, 3> kPublishSeeds = {kMinRngSeed, kMedianRngSeed, kDonorRngSeed};
constexpr std::array<std::uint64_t, 3> kPublishT8 = {10, 12, 18};
constexpr std::array<std::uint64_t, 3> kPublishT64 = {107, 87, 83};

// Sweep order: the control FIRST, then the two new seeds. See the header.
constexpr std::array<std::uint64_t, 3> kSeeds = {kDonorRngSeed, kMinRngSeed, kMedianRngSeed};

// The control of the stand. task-081 measured the donor at threshold 32 with
// this same ladder over this same interval and published 51
// (docs/experiments/solver-add-gate-threshold64/report.md:14, «control_
// threshold32_equals_51=yes, prediction_printed_before_run=51,»; the probe
// itself at docs/experiments/solver-add-gate-threshold64/raw-threshold64.txt:150,
// «min_budget=51 first_concolic_iteration=51»).
constexpr std::uint64_t kDonorExpectedT32 = 51;
constexpr const char* kControlSource = "docs/experiments/solver-add-gate-threshold64/report.md:14";

// The ladder's interval, task-081's unchanged. The donor's 51 and task-108's
// dearest point 107 both sit well inside it.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 400;

// Where the four counters on the RANK32 line are read. Fixed before the run.
constexpr const char* kCounterRule =
    "counters (concolic_calls, concolic_candidates, concolic_no_binding, execs) are read off the "
    "probe at the SMALLEST crashing budget - the located minimum re-run as probe-N - because the "
    "ladder walks budgets, not time; the chronologically first probe is the ticket at budget=400, "
    "the same budget for every seed; a seed without a located minimum prints none for all four";

// How two ordered triples are compared. Ties have no strict relation and make
// the answer mixed rather than being folded into one side.
constexpr const char* kOrderRule =
    "for each of the three pairs (i<j) the strict relation inside triple A is compared with the "
    "one inside triple B; all three agreeing is preserved, all three opposite is inverted, "
    "anything else - including a single tie - is mixed";

// The correlate question, answered by the SAME rule applied to a different
// pair of triples. `yes` only on agreement, `no` only on strict opposition,
// everything else undecided.
constexpr const char* kCorrelateRule =
    "ranking_tracks_concolic_calls = yes when the triple of located minima and the triple of "
    "concolic_calls at those minima compare as preserved, no when they compare as inverted, "
    "undecided on mixed or on any seed without a snapshot; three points are a CORRELATE, not a "
    "named cause";

// The hard ceiling this unit was registered with. task-108 spent 25 s on the
// same three seeds at the dearer threshold 64, so 1800 s is slack; the
// harness stops on it itself rather than being killed by ctest.
constexpr double kWalltimeBudgetS = 1800.0;

// Wall-clock accounting for the budget above. Started at process start, which
// is before the single test body runs, so it covers everything the harness
// does and not just the campaigns.
const std::chrono::steady_clock::time_point g_started = std::chrono::steady_clock::now();

double WalltimeUsedS() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - g_started).count();
}

// Admission control: a probe is admitted only while budget remains. Returning
// false is a legal stop, not a failure - the caller names the probe it did
// not run.
bool BudgetLeft() {
    return WalltimeUsedS() < kWalltimeBudgetS;
}

struct Probe {
    std::uint64_t rng_seed = 0;
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_called = false;
};

// One bounded campaign, its counters and its wall time. Identical to
// task-108's (test_add_gate_rank_across_threshold.cpp:337-387) except for the
// stagnation threshold, which is this unit's whole point, and the scratch
// directory name.
// Fatal assertions inside report against the calling test; callers must bail
// out on ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint64_t rng_seed, std::uint64_t max_iterations, CampaignStats& out_stats,
                 std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_rank_threshold32";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-rank-threshold32");
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
                             .concolic_stagnation_threshold = kThreshold32,
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
    std::cout << "RANK32-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
              << " threshold=" << kThreshold32 << " rng_seed=" << rng_seed << " budget=" << budget
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
// probes of ONE seed - mixing seeds would compare different campaign
// configurations.
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

// The pairwise-relation comparison named by kOrderRule, and the ONLY rule this
// harness uses to put a word on an order.
const char* CompareOrder(const std::array<std::uint64_t, 3>& a,
                         const std::array<std::uint64_t, 3>& b) {
    int agree = 0;
    int oppose = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        for (std::size_t j = i + 1; j < a.size(); ++j) {
            if (a[i] == a[j] || b[i] == b[j]) {
                return "mixed";
            }
            if ((a[i] < a[j]) == (b[i] < b[j])) {
                ++agree;
            } else {
                ++oppose;
            }
        }
    }
    if (agree == 3) {
        return "preserved";
    }
    if (oppose == 3) {
        return "inverted";
    }
    return "mixed";
}

// Which interval of the axis 8 -> 32 -> 64 the flip falls into, read off the
// two comparisons and nothing else. `undecided` is printed when either
// comparison has no strict order to speak of; naming an interval there would
// be a reading, not a measurement.
const char* FlipInterval(const char* vs_t8, const char* vs_t64) {
    const bool preserved_8 = std::strcmp(vs_t8, "preserved") == 0;
    const bool inverted_8 = std::strcmp(vs_t8, "inverted") == 0;
    const bool preserved_64 = std::strcmp(vs_t64, "preserved") == 0;
    const bool inverted_64 = std::strcmp(vs_t64, "inverted") == 0;
    if (preserved_8 && inverted_64) {
        return "32-64";
    }
    if (inverted_8 && preserved_64) {
        return "8-32";
    }
    if (preserved_8 && preserved_64) {
        return "none";
    }
    if (inverted_8 && inverted_64) {
        return "both";
    }
    return "undecided";
}

// One seed's outcome at threshold 32. `crashed_at_hi=false` means the crash
// search never ran: that seed publishes min_budget=none, prints none for the
// four snapshot counters, and stays OUT of the order comparison rather than
// being folded in as a zero.
struct SeedResult {
    std::uint64_t rng_seed = 0;
    std::uint64_t t8_min_budget = 0;
    std::uint64_t t64_min_budget = 0;
    bool ran = false;
    bool crashed_at_hi = false;
    bool concolic_called_at_hi = false;
    std::uint64_t concolic_calls_at_hi = 0;
    std::uint64_t concolic_candidates_at_hi = 0;
    std::uint64_t concolic_no_binding_at_hi = 0;
    std::uint64_t execs_at_hi = 0;
    bool first_call_search_complete = false;
    std::uint64_t first_concolic_iteration = 0;
    bool crash_search_complete = false;
    std::uint64_t min_budget = 0;
    // The snapshot named by kCounterRule: probe-N, the located minimum.
    bool snapshot_taken = false;
    std::uint64_t concolic_calls_at_min = 0;
    std::uint64_t concolic_candidates_at_min = 0;
    std::uint64_t concolic_no_binding_at_min = 0;
    std::uint64_t execs_at_min = 0;
    std::uint64_t concolic_crashes_at_min = 0;
    std::uint64_t wall_ms_at_min = 0;
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
    std::cout << "RANK32-SKIPPED rng_seed=" << out.rng_seed << " probe=" << what
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

// A counter that exists only when the snapshot exists. `none` and not 0: a
// zero on this line would read as a measured zero.
std::string SnapOrNone(const SeedResult& r, std::uint64_t value) {
    return r.snapshot_taken ? std::to_string(value) : std::string("none");
}

// The whole protocol for ONE seed, task-081's ladder unchanged and task-108's
// code path unchanged (test_add_gate_rank_across_threshold.cpp:510-670): a
// ticket probe at the top of the interval, then the same binary search - mid,
// probe, `hi = mid` when the observation is present and `lo = mid + 1` when it
// is not, answer `lo` - run once on `concolic_calls > 0` for the iteration of
// the first concolic call and once on `crashes > 0` for the minimal crash
// budget, then probe-N and probe-N-1. What changed against task-108 is the
// threshold and the counters kept at probe-N, and nothing else.
void MeasureSeed(std::uint64_t rng_seed, std::uint64_t t8_min_budget, std::uint64_t t64_min_budget,
                 int& seq, SeedResult& out) {
    out.rng_seed = rng_seed;
    out.t8_min_budget = t8_min_budget;
    out.t64_min_budget = t64_min_budget;
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
    out.concolic_candidates_at_hi = stats.concolic_candidates;
    out.concolic_no_binding_at_hi = stats.concolic_no_binding;
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

            // probe-N: the smallest crashing budget, re-run so that the raw
            // log carries the counters at the exact point the RANK32 line
            // quotes. This IS the snapshot named by kCounterRule.
            // `concolic_calls >= 1` HERE is what proves the arm was armed at
            // the minimum; a zero on this line annuls the line rather than
            // being explained away.
            if (BudgetLeft()) {
                CampaignStats at_min;
                std::uint64_t wall_at_min = 0;
                ASSERT_TRUE(Probe1("probe-N", seq, rng_seed, out.min_budget, log, at_min,
                                   wall_at_min, out.wall_ms));
                out.snapshot_taken = true;
                out.concolic_calls_at_min = at_min.concolic_calls;
                out.concolic_candidates_at_min = at_min.concolic_candidates;
                out.concolic_no_binding_at_min = at_min.concolic_no_binding;
                out.execs_at_min = at_min.execs;
                out.concolic_crashes_at_min = at_min.concolic_crashes;
                out.wall_ms_at_min = wall_at_min;
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
        std::cout << "RANK32-NONMONOTONIC observation=crash rng_seed=" << rng_seed
                  << " witness=" << crash_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_crash) << "crash not monotone in the budget, rng_seed=" << rng_seed;

    std::string call_witness;
    out.monotonic_call = MonotonicOverLog(log, PickConcolicCalled, call_witness);
    if (!out.monotonic_call) {
        std::cout << "RANK32-NONMONOTONIC observation=concolic_call rng_seed=" << rng_seed
                  << " witness=" << call_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_call)
        << "concolic call not monotone in the budget, rng_seed=" << rng_seed;

    out.probes = seq - seq_before;

    // THE line the report reads its three numbers off. Its shape is fixed by
    // the unit's registration and nothing else is printed with this prefix.
    // `probes` and `wall_ms` are the seed's totals over the whole ladder; the
    // four counters are the probe-N snapshot named by kCounterRule.
    std::cout << "RANK32 rng_seed=" << out.rng_seed << " threshold=" << kThreshold32
              << " min_budget="
              << (out.crash_search_complete ? std::to_string(out.min_budget) : std::string("none"))
              << " probes=" << out.probes
              << " concolic_calls=" << SnapOrNone(out, out.concolic_calls_at_min)
              << " concolic_candidates=" << SnapOrNone(out, out.concolic_candidates_at_min)
              << " concolic_no_binding=" << SnapOrNone(out, out.concolic_no_binding_at_min)
              << " execs=" << SnapOrNone(out, out.execs_at_min) << " wall_ms=" << out.wall_ms
              << '\n'
              << std::flush;

    // Everything the RANK32 line has no room for, including the counters at
    // the chronologically first crashing probe (the ticket), so the other
    // reading of "first crashing probe" is answerable from this log without a
    // rerun.
    std::cout << "RANK32-POINT rng_seed=" << out.rng_seed << " t8_min_budget=" << out.t8_min_budget
              << " t64_min_budget=" << out.t64_min_budget
              << " crashed_at_hi=" << (out.crashed_at_hi ? "yes" : "no")
              << " first_concolic_iteration="
              << (out.first_call_search_complete ? std::to_string(out.first_concolic_iteration)
                                                 : std::string("none"))
              << " snapshot_probe=" << (out.snapshot_taken ? "probe-N" : "none")
              << " wall_ms_at_snapshot=" << SnapOrNone(out, out.wall_ms_at_min)
              << " concolic_crashes_at_min=" << SnapOrNone(out, out.concolic_crashes_at_min)
              << " ticket_budget=" << kSearchHi << " execs_at_ticket=" << out.execs_at_hi
              << " concolic_calls_at_ticket=" << out.concolic_calls_at_hi
              << " concolic_candidates_at_ticket=" << out.concolic_candidates_at_hi
              << " concolic_no_binding_at_ticket=" << out.concolic_no_binding_at_hi
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
    std::cout << "RANK32-META gate=add_gate add_gate=" << ADD_GATE_REL
              << " exec_server=" << EXEC_SERVER_REL << " threshold=" << kThreshold32
              << " donor_threshold=" << kDonorThreshold
              << " production_threshold=" << kDefaultConcolicStagnationThreshold
              << " threshold_source=src/core/campaign.h:58 arm_seed=donor"
              << " budget_interval=" << kSearchLo << ".." << kSearchHi
              << " concolic_timeout_ms=2000"
              << " seeds=" << kSeeds.size()
              << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n'
              << "RANK32-PREREGISTERED sweep_order=" << kSeeds[0] << "," << kSeeds[1] << ","
              << kSeeds[2] << " publish_order=" << kPublishSeeds[0] << "," << kPublishSeeds[1]
              << "," << kPublishSeeds[2] << " t8=" << kPublishT8[0] << "," << kPublishT8[1] << ","
              << kPublishT8[2] << " t64=" << kPublishT64[0] << "," << kPublishT64[1] << ","
              << kPublishT64[2] << " seed_source=" << kSeedSource << " seed_source_quote=\""
              << kSeedSourceQuote << "\"\n"
              << "RANK32-CONTROL control_seed=" << kDonorRngSeed
              << " expected_min_budget=" << kDonorExpectedT32
              << " control_source=" << kControlSource
              << " control_quote=\"control_threshold32_equals_51=yes, "
                 "prediction_printed_before_run=51,\"\n"
              << "RANK32-COUNTER-RULE rule=\"" << kCounterRule << "\"\n"
              << "RANK32-ORDER-RULE rule=\"" << kOrderRule << "\"\n"
              << "RANK32-CORRELATE-RULE rule=\"" << kCorrelateRule << "\"\n"
              << std::flush;
}

// The whole unit in one test: the control and the two new seeds under one
// wall-clock budget. They are not split, because the control is what licenses
// the two new numbers to be read at all - running them apart would let the
// comparison be published beside a control from a different process.
TEST(AddGateRankThreshold32, SeedRankAtTheIntermediateStagnationThreshold) {
    const std::string why = MissingArtifact();
    if (!why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta();

    int seq = 0;
    std::array<SeedResult, kSeeds.size()> results{};
    for (std::size_t i = 0; i < kSeeds.size(); ++i) {
        // The control runs FIRST: by the time the two new seeds are measured,
        // the stand has already had to reproduce task-081's published 51.
        std::uint64_t t8 = 0;
        std::uint64_t t64 = 0;
        for (std::size_t k = 0; k < kPublishSeeds.size(); ++k) {
            if (kPublishSeeds[k] == kSeeds[i]) {
                t8 = kPublishT8[k];
                t64 = kPublishT64[k];
            }
        }
        MeasureSeed(kSeeds[i], t8, t64, seq, results[i]);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
    }

    // Re-indexed into publication order (min, median, donor) so the verdict's
    // triples line up slot by slot with the two quoted ones.
    std::array<const SeedResult*, 3> pub{};
    for (std::size_t k = 0; k < kPublishSeeds.size(); ++k) {
        for (const SeedResult& r : results) {
            if (r.rng_seed == kPublishSeeds[k]) {
                pub[k] = &r;
            }
        }
        ASSERT_NE(pub[k], nullptr);
    }
    const SeedResult& s_donor = *pub[2];

    const bool control_holds =
        s_donor.crash_search_complete && s_donor.min_budget == kDonorExpectedT32;

    std::cout << "RANK32-CONTROL-VERDICT control_seed=" << kDonorRngSeed
              << " expected_min_budget=" << kDonorExpectedT32 << " measured_min_budget="
              << (s_donor.crash_search_complete ? std::to_string(s_donor.min_budget)
                                                : std::string("none"))
              << " control_holds=" << (control_holds ? "yes" : "no")
              << " bench_verdict=" << (control_holds ? "same-bench" : "not-the-same-bench") << '\n'
              << std::flush;

    // The three located minima in publication order. A seed without a minimum
    // makes every comparison undecided rather than false: an unlocated
    // minimum lies above 400 and orders against nothing measured.
    const bool all_located = pub[0]->crash_search_complete && pub[1]->crash_search_complete &&
                             pub[2]->crash_search_complete;
    const bool all_snapshot =
        pub[0]->snapshot_taken && pub[1]->snapshot_taken && pub[2]->snapshot_taken;
    const std::array<std::uint64_t, 3> t32 = {pub[0]->min_budget, pub[1]->min_budget,
                                              pub[2]->min_budget};
    const std::array<std::uint64_t, 3> calls32 = {pub[0]->concolic_calls_at_min,
                                                  pub[1]->concolic_calls_at_min,
                                                  pub[2]->concolic_calls_at_min};

    // kOrderRule, applied. Nothing here reads the numbers by eye.
    const char* order_vs_t8 = all_located ? CompareOrder(t32, kPublishT8) : "undecided";
    const char* order_vs_t64 = all_located ? CompareOrder(t32, kPublishT64) : "undecided";
    const char* flip_interval = FlipInterval(order_vs_t8, order_vs_t64);

    // kCorrelateRule, applied. A correlate on three points, not a cause.
    const char* tracks_calls = "undecided";
    if (all_located && all_snapshot) {
        const char* rel = CompareOrder(t32, calls32);
        if (std::strcmp(rel, "preserved") == 0) {
            tracks_calls = "yes";
        } else if (std::strcmp(rel, "inverted") == 0) {
            tracks_calls = "no";
        }
    }

    const bool walltime_hit = pub[0]->walltime_hit || pub[1]->walltime_hit || pub[2]->walltime_hit;
    const std::uint64_t walltime_used = static_cast<std::uint64_t>(WalltimeUsedS());

    auto min_or_none = [](const SeedResult& r) {
        return r.crash_search_complete ? std::to_string(r.min_budget) : std::string("none");
    };

    std::cout << "RANK32-VERDICT: RANK-T32: seeds=" << kSeeds.size() << ", t8=" << kPublishT8[0]
              << "," << kPublishT8[1] << "," << kPublishT8[2] << ", t32=" << min_or_none(*pub[0])
              << "," << min_or_none(*pub[1]) << "," << min_or_none(*pub[2])
              << ", t64=" << kPublishT64[0] << "," << kPublishT64[1] << "," << kPublishT64[2]
              << ", donor_control_t32=" << min_or_none(s_donor)
              << ", donor_control_matches_task081=" << (control_holds ? "yes" : "no")
              << ", order_t32_vs_t8=" << order_vs_t8 << ", order_t32_vs_t64=" << order_vs_t64
              << ", flip_interval=" << flip_interval
              << ", ranking_tracks_concolic_calls=" << tracks_calls
              << ", concolic_calls_t32=" << SnapOrNone(*pub[0], calls32[0]) << ","
              << SnapOrNone(*pub[1], calls32[1]) << "," << SnapOrNone(*pub[2], calls32[2])
              << ", stagnation_threshold=" << kThreshold32 << ", budget_ladder_max=" << kSearchHi
              << ", timeout_hit=" << (walltime_hit ? "yes" : "no") << ", probes=" << seq
              << ", seeds_are_a_median=no"
              << ", walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS)
              << ", walltime_used_s=" << walltime_used
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;

    EXPECT_TRUE(control_holds)
        << "control seed " << kDonorRngSeed << " did not reproduce task-081's " << kDonorExpectedT32
        << " at threshold " << kThreshold32
        << "; the stand is not the same stand and no line about the order is licensed";
    EXPECT_LE(walltime_used, static_cast<std::uint64_t>(kWalltimeBudgetS))
        << "the harness overran its own wall-clock budget";
}

}  // namespace
}  // namespace mlfuzzz3::core
