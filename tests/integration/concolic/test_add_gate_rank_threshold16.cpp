// task-112, ADR 0047: where exactly does the seed order break — the
// intermediate stagnation threshold 16 INSIDE the interval 8-32.
//
// What is already known. task-108 measured three RNG seeds at the donor's
// threshold 8 and at the production threshold 64 and found not a dented order
// but a full inversion: `t8=10,12,18` against `t64=107,87,83`
// (docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt:228,
// line `RANK-VERDICT:`). task-110 then added the rung 32 and narrowed the
// break to 8-32: at 32 the order already matches 64 and not 8
// (docs/experiments/solver-rank-threshold32/report.md:13, «VERDICT: RANK-T32:
// seeds=3, t8=10,12,18, t32=75,55,51, t64=107,87,83,»).
//
// The gap. The interval 8-32 has never been split. "The break lies between 8
// and 32" rests on exactly two measured points, and inside that interval
// there may be one boundary or a gradual rearrangement. Until an intermediate
// point is taken, the width of the uncertainty IS the whole interval. This
// harness adds exactly one rung, threshold 16, on the same unchanged ladder,
// for the same three seeds.
//
// What is fixed BEFORE the run, and why each thing is fixed here rather than
// decided afterwards:
//
//   * The three seeds and the numbers they were chosen by. 1 (t8=10),
//     17 (t8=12) and 7 (t8=18, the donor). Not re-picked: they are quoted
//     from task-108's committed raw log, so this point sits on the same three
//     seeds as the three points it is compared with.
//   * The ladder. task-081's method unchanged — a ticket probe at the top of
//     [1, 400], then binary search on `crashes > 0` for the minimal crash
//     budget, then probe-N and probe-N-1 around the located transition. A
//     different search would produce minima that are not comparable with the
//     control the stand has to hit.
//   * The control, and why it is a WHOLE ladder rather than a quoted number.
//     The donor seed 7 is re-measured AT THRESHOLD 32, in this same process,
//     and must reproduce task-110's 51. It runs FIRST, so by the time the
//     three T=16 numbers are taken the stand has already had to prove it is
//     the same stand. A control that only quoted 51 would prove nothing about
//     THIS machine on THIS night.
//   * WHERE the counters on the RANK16 line come from (kCounterRule below):
//     the probe at the SMALLEST budget that crashes, i.e. the located minimum
//     re-run as probe-N. The ladder walks budgets, not time, so "the probe
//     where the crash appeared first" is the first budget that crashes and
//     NOT the chronologically first probe — the latter is the 400-iteration
//     ticket, which is the same budget for every seed and therefore carries
//     no information about rank. The ticket's counters are printed too, on
//     the RANK16-POINT line, so the raw log answers the other reading without
//     a rerun.
//   * The order rule (kOrderRule), evaluated in code from the printed
//     triples, so the word in the verdict is a function of the numbers and
//     not of the reading.
//
// THE ORDER RULE IS NOT INVENTED HERE. kOrderRule below is task-109's string,
// character for character, from its committed raw log
// (docs/experiments/solver-niche-ensemble-threshold64/raw-ensemble-threshold64.txt:58,
// line `ENSEMBLE64-ORDER-RULE`). Only the reference triple it is applied to
// changes: `order_t16_vs_t8` uses t8 to define the pairs, `order_t16_vs_t32`
// uses t32, and in both the MEASURED triple checked against them is t16.
//
// One honest note about that rule, written down before the numbers exist.
// task-109's rule tolerates a tie in the measured triple (`<=` / `>=`), while
// task-110's own harness folded any tie into `mixed`. On triples with no ties
// the two rules agree pair for pair, so the word printed here is comparable
// with task-110's published word; the reference triples t8=10,12,18 and
// t32=75,55,51 have no ties, so only a tie inside the NEW t16 triple could
// separate them. Whether that happened is printed as its own observation,
// `RANK16-ORDER-NOTE t16_has_ties=`, instead of being left for a reader to
// notice.
//
// Scope of the two mixed scopes on one line, said plainly: `probes` and
// `wall_ms` are the seed's totals over its whole ladder; `concolic_calls` and
// `execs` are the snapshot at probe-N. When no minimum was located there is
// no snapshot, and both counters print `none` rather than a zero that would
// read as a measurement.
//
// The shape of the RANK16 line is the one the queue registered, field for
// field: `rng_seed threshold min_budget probes execs concolic_calls wall_ms`.
// The control is printed on a line of the SAME shape and is told apart by its
// own `threshold=32` field — a reader selects the three new numbers with
// `threshold=16` and the control with `threshold=32`, and neither selection
// needs to know the seed list. The counters the registered shape has no room
// for (`concolic_candidates`, `concolic_no_binding`) are on RANK16-POINT.
//
// What this harness does NOT claim. That three points are a median — they are
// not, and the verdict says `seeds_are_a_median=no` in its own line. That the
// mechanism of the break is found: this unit takes a COORDINATE, not a cause,
// and unlike task-110 it does not even look for a correlate in the counters —
// task-110 already looked and found none. That the interval is localised
// finer than a half: exactly four thresholds exist on this axis, 8, 16, 32
// and 64.
//
// Both outcomes are a result. An order at 16 that matches T=8 puts the break
// into 16-32; one that matches T=32 puts it into 8-16; a mixed order says
// there is no boundary at all but a gradual rearrangement, and then the very
// phrase "the point of the break" is the wrong shape for the fact.
//
// Budget. A hard 1800 s inside the harness (kWalltimeBudgetS); task-110 spent
// its whole three-seed ladder at the DEARER threshold 32 in tens of seconds,
// and T=16 is cheaper still by construction, so the ceiling is slack, not a
// target. Every probe the protocol planned and the budget refused is NAMED in
// the raw log rather than dropped, and the run publishes the seeds that fit.
//
// Boundaries. src/ is not modified by a single character, the default in
// campaign.h is not touched, and the reports of task-108 and task-110 are not
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
// HELD FIXED: this measurement varies the RNG seed and the threshold only.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// THE point this unit adds: the rung that splits task-110's interval 8-32 in
// half. Written as a literal because it is NOT a default anybody runs with —
// it is the fourth rung of the axis 8, 16, 32, 64 — while the production end
// stays pinned to what the campaign itself reads, so the interval cannot
// silently stop being an interval.
constexpr std::uint32_t kThreshold16 = 16;
constexpr std::uint32_t kDonorThreshold = 8;
// The threshold the CONTROL ladder runs at: task-110's rung, re-measured in
// this same process. Not the threshold anything new is claimed about.
constexpr std::uint32_t kControlThreshold = 32;
static_assert(kDefaultConcolicStagnationThreshold == 64,
              "src/core/campaign.h's kDefaultConcolicStagnationThreshold moved away from 64; "
              "task-108's t64 triple was measured at 64 and this harness compares against it");
static_assert(kDonorThreshold < kThreshold16 && kThreshold16 < kControlThreshold &&
                  kControlThreshold < kDefaultConcolicStagnationThreshold,
              "16 splits task-110's interval only while it lies strictly between the donor's "
              "threshold and task-110's rung, which in turn lies below the production default");

// The three seeds. NOT re-picked here: they are task-108's three, and all
// three triples they are compared against are quoted, not recomputed.
constexpr std::uint64_t kMinRngSeed = 1;      // t8=10, t32=75, t64=107
constexpr std::uint64_t kMedianRngSeed = 17;  // t8=12, t32=55, t64=87
constexpr std::uint64_t kDonorRngSeed = 7;    // t8=18, t32=51, t64=83

constexpr const char* kSeedSource =
    "docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt:228";
constexpr const char* kSeedSourceQuote =
    "RANK-VERDICT: RANK-ACROSS-THRESHOLD: seeds=3, t8=10,12,18, t64=107,87,83, "
    "donor_control_t64=83, donor_control_matches_task081=yes";

// The middle triple, task-110's, quoted and NOT measured again.
constexpr const char* kT32Source = "docs/experiments/solver-rank-threshold32/report.md:13";
constexpr const char* kT32SourceQuote =
    "VERDICT: RANK-T32: seeds=3, t8=10,12,18, t32=75,55,51, t64=107,87,83,";

// The three triples this run is compared with, in publication order
// (min, median, donor). Quoted from the lines above; NOT measured again.
constexpr std::array<std::uint64_t, 3> kPublishSeeds = {kMinRngSeed, kMedianRngSeed, kDonorRngSeed};
constexpr std::array<std::uint64_t, 3> kPublishT8 = {10, 12, 18};
constexpr std::array<std::uint64_t, 3> kPublishT32 = {75, 55, 51};
constexpr std::array<std::uint64_t, 3> kPublishT64 = {107, 87, 83};

// Sweep order of the three NEW measurements at threshold 16: the donor first,
// exactly as task-110 swept it, so the two runs differ in the threshold and
// not in the order of the ladders.
constexpr std::array<std::uint64_t, 3> kSeeds = {kDonorRngSeed, kMinRngSeed, kMedianRngSeed};

// The control of the stand, and the only thing measured at a threshold other
// than 16: the donor at threshold 32 must reproduce task-110's 51
// (docs/experiments/solver-rank-threshold32/report.md:14, «donor_control_t32=51,
// donor_control_matches_task081=yes,»; the probe itself at
// docs/experiments/solver-rank-threshold32/raw-rank-threshold32.txt:101,
// «RANK32 rng_seed=7 threshold=32 min_budget=51 probes=21 concolic_calls=1
// concolic_candidates=1 concolic_no_binding=0 execs=52 wall_ms=16519»).
constexpr std::uint64_t kDonorExpectedT32 = test_support::strict_terminal_budget(51);
constexpr const char* kControlSource = "docs/experiments/solver-rank-threshold32/report.md:14";

// The ladder's interval, task-081's unchanged and task-110's unchanged. The
// control's 51 and task-108's dearest point 107 both sit well inside it.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 400;

// Where the counters on the RANK16 line are read. Fixed before the run.
constexpr const char* kCounterRule =
    "counters (concolic_calls, execs; concolic_candidates and concolic_no_binding on the POINT "
    "line) are read off the probe at the SMALLEST crashing budget - the located minimum re-run as "
    "probe-N - because the ladder walks budgets, not time; the chronologically first probe is the "
    "ticket at budget=400, the same budget for every seed; a seed without a located minimum prints "
    "none for all of them";

// HOW TWO ORDERS ARE COMPARED. task-109's string, character for character,
// from docs/experiments/solver-niche-ensemble-threshold64/raw-ensemble-threshold64.txt:58.
// Applied here twice: once with t8 as the triple that defines the pairs and
// once with t32, and in both the measured triple checked against it is t16.
constexpr const char* kOrderRule =
    "over all pairs (i,j) with t8_i<t8_j: order_vs_t8=preserved iff every such pair has "
    "t64_i<=t64_j; inverted iff every such pair has t64_i>=t64_j; otherwise mixed; undefined "
    "if fewer than two seeds were solved";
constexpr const char* kOrderRuleSource =
    "docs/experiments/solver-niche-ensemble-threshold64/raw-ensemble-threshold64.txt:58";

// The registration's own count of new fuzzing runs: the three T=16 ladders.
// The control ladder re-measures a point task-110 has already published and
// is a control, not a new number this unit publishes.
constexpr int kNewFuzzingRuns = 3;

// The hard ceiling this unit was registered with. task-110 ran the same three
// seeds on the same ladder at the DEARER threshold 32 in tens of seconds, and
// 16 is cheaper still, so 1800 s is slack; the harness stops on it itself
// rather than being killed by ctest.
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
// task-110's (test_add_gate_rank_threshold32.cpp:326-376) except that the
// stagnation threshold is a PARAMETER here - the control has to run at 32
// while everything published runs at 16 - and the scratch directory name.
// Fatal assertions inside report against the calling test; callers must bail
// out on ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint64_t rng_seed, std::uint32_t threshold, std::uint64_t max_iterations,
                 CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_rank_threshold16";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-rank-threshold16");
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
                             .concolic_stagnation_threshold = threshold,
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
void PrintProbe(const char* phase, int seq, std::uint64_t rng_seed, std::uint32_t threshold,
                std::uint64_t budget, const CampaignStats& s, std::uint64_t wall_ms) {
    std::cout << "RANK16-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
              << " threshold=" << threshold << " rng_seed=" << rng_seed << " budget=" << budget
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
bool Probe1(const char* phase, int& seq, std::uint64_t rng_seed, std::uint32_t threshold,
            std::uint64_t budget, std::vector<Probe>& log, CampaignStats& out_stats,
            std::uint64_t& out_wall_ms, std::uint64_t& inout_wall_total_ms) {
    RunCampaign(rng_seed, threshold, budget, out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    ++seq;
    inout_wall_total_ms += out_wall_ms;
    log.push_back(Probe{rng_seed, budget, out_stats.crashes > 0, out_stats.concolic_calls > 0});
    PrintProbe(phase, seq, rng_seed, threshold, budget, out_stats, out_wall_ms);
    return true;
}

// A pair (b1 < b2) with the observation present at b1 and absent at b2
// refutes monotonicity of that observation in the budget. Checked over ALL
// probes of ONE ladder - mixing ladders would compare different campaign
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

// One ladder's outcome. `crashed_at_hi=false` means the crash search never
// ran: that ladder publishes min_budget=none, prints none for the snapshot
// counters, and stays OUT of the order comparison rather than being folded in
// as a zero.
struct SeedResult {
    std::uint64_t rng_seed = 0;
    std::uint32_t threshold = 0;
    bool is_control = false;
    std::uint64_t t8_min_budget = 0;
    std::uint64_t t32_min_budget = 0;
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

// THE ORDER COMPARISON, kOrderRule applied and nothing else. `ref` is the
// triple whose STRICT order defines the pairs (t8 or t32) and `meas` is the
// measured triple checked against it (t16), matching the rule's own reading
// of `order_vs_t8`. Pairs are taken only over entries the caller marked
// solved; fewer than two solved is `undefined`. Both `all_le` and `all_ge`
// can hold only when every measured value is equal, and that case reads
// `preserved`, exactly as task-109's implementation resolves it
// (test_add_gate_ensemble_threshold64.cpp:1056).
const char* CompareOrder(const std::array<std::uint64_t, 3>& ref,
                         const std::array<std::uint64_t, 3>& meas,
                         const std::array<bool, 3>& solved) {
    int solved_count = 0;
    for (bool s : solved) {
        solved_count += s ? 1 : 0;
    }
    if (solved_count < 2) {
        return "undefined";
    }
    bool all_le = true;
    bool all_ge = true;
    for (std::size_t i = 0; i < ref.size(); ++i) {
        for (std::size_t j = 0; j < ref.size(); ++j) {
            if (!solved[i] || !solved[j] || ref[i] >= ref[j]) {
                continue;
            }
            if (meas[i] > meas[j]) {
                all_le = false;
            }
            if (meas[i] < meas[j]) {
                all_ge = false;
            }
        }
    }
    return all_le ? "preserved" : (all_ge ? "inverted" : "mixed");
}

// Which half of task-110's interval 8-32 the flip falls into, read off the
// two comparisons and nothing else. The registered vocabulary has exactly
// three words, so everything that is not one of the two clean cases -
// including a mixed order, which says there is no boundary but a gradual
// rearrangement - leaves the interval as task-110 left it.
const char* FlipInterval(const char* vs_t8, const char* vs_t32) {
    const bool preserved_8 = std::strcmp(vs_t8, "preserved") == 0;
    const bool inverted_8 = std::strcmp(vs_t8, "inverted") == 0;
    const bool preserved_32 = std::strcmp(vs_t32, "preserved") == 0;
    const bool inverted_32 = std::strcmp(vs_t32, "inverted") == 0;
    // Still the donor's order at 16 and already the other one at 32.
    if (preserved_8 && inverted_32) {
        return "16-32";
    }
    // Already flipped by 16 and unchanged from there to 32.
    if (inverted_8 && preserved_32) {
        return "8-16";
    }
    return "8-32-unrefined";
}

// A probe the protocol planned and the wall-clock budget refused. It is
// NAMED, in the raw log and in the result, rather than silently dropped: a
// missing probe that nobody names is indistinguishable from a probe that was
// never planned.
void NameSkipped(SeedResult& out, const char* what) {
    out.walltime_hit = true;
    out.skipped += out.skipped.empty() ? "" : ",";
    out.skipped += what;
    std::cout << "RANK16-SKIPPED rng_seed=" << out.rng_seed << " threshold=" << out.threshold
              << " probe=" << what
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

std::string MinOrNone(const SeedResult& r) {
    return r.crash_search_complete ? std::to_string(r.min_budget) : std::string("none");
}

// The whole protocol for ONE ladder, task-081's method unchanged and
// task-110's code path unchanged (test_add_gate_rank_threshold32.cpp:564-748):
// a ticket probe at the top of the interval, then the same binary search -
// mid, probe, `hi = mid` when the observation is present and `lo = mid + 1`
// when it is not, answer `lo` - run once on `concolic_calls > 0` for the
// iteration of the first concolic call and once on `crashes > 0` for the
// minimal crash budget, then probe-N and probe-N-1. What changed against
// task-110 is that the threshold is passed in, and nothing else.
void MeasureSeed(std::uint64_t rng_seed, std::uint32_t threshold, bool is_control,
                 std::uint64_t t8_min_budget, std::uint64_t t32_min_budget,
                 std::uint64_t t64_min_budget, int& seq, SeedResult& out) {
    out.rng_seed = rng_seed;
    out.threshold = threshold;
    out.is_control = is_control;
    out.t8_min_budget = t8_min_budget;
    out.t32_min_budget = t32_min_budget;
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
    ASSERT_TRUE(
        Probe1("ticket", seq, rng_seed, threshold, kSearchHi, log, stats, wall_ms, out.wall_ms));
    ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors, rng_seed="
                                << rng_seed << " threshold=" << threshold;
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
            ASSERT_TRUE(Probe1("first-call-search", seq, rng_seed, threshold, mid, log, stats,
                               wall_ms, out.wall_ms));
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
            ASSERT_TRUE(Probe1("crash-search", seq, rng_seed, threshold, mid, log, stats, wall_ms,
                               out.wall_ms));
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
            // log carries the counters at the exact point the RANK16 line
            // quotes. This IS the snapshot named by kCounterRule.
            // `concolic_calls >= 1` HERE is what proves the arm was armed at
            // the minimum; a zero on this line annuls the line rather than
            // being explained away.
            if (BudgetLeft()) {
                CampaignStats at_min;
                std::uint64_t wall_at_min = 0;
                ASSERT_TRUE(Probe1("probe-N", seq, rng_seed, threshold, out.min_budget, log, at_min,
                                   wall_at_min, out.wall_ms));
                out.snapshot_taken = true;
                out.concolic_calls_at_min = at_min.concolic_calls;
                out.concolic_candidates_at_min = at_min.concolic_candidates;
                out.concolic_no_binding_at_min = at_min.concolic_no_binding;
                out.execs_at_min = at_min.execs;
                out.concolic_crashes_at_min = at_min.concolic_crashes;
                out.wall_ms_at_min = wall_at_min;
                EXPECT_GT(at_min.crashes, 0U)
                    << "crash absent at the located minimum, rng_seed=" << rng_seed
                    << " threshold=" << threshold;
                EXPECT_GT(at_min.concolic_calls, 0U)
                    << "arm DISARMED at the minimum (concolic_calls=0), rng_seed=" << rng_seed
                    << " threshold=" << threshold;
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
                    ASSERT_TRUE(Probe1("probe-N-1", seq, rng_seed, threshold, out.min_budget - 1,
                                       log, below, wall_below, out.wall_ms));
                    out.min_minus_1_probed = true;
                    out.crash_at_min_minus_1 = below.crashes > 0;
                    EXPECT_EQ(below.crashes, 0U)
                        << "crash present one below the located minimum, rng_seed=" << rng_seed
                        << " threshold=" << threshold;
                } else {
                    NameSkipped(out, "probe-N-1");
                }
            }
        }
    }

    std::string crash_witness;
    out.monotonic_crash = MonotonicOverLog(log, PickCrashed, crash_witness);
    if (!out.monotonic_crash) {
        std::cout << "RANK16-NONMONOTONIC observation=crash rng_seed=" << rng_seed
                  << " threshold=" << threshold << " witness=" << crash_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_crash)
        << "crash not monotone in the budget, rng_seed=" << rng_seed << " threshold=" << threshold;

    std::string call_witness;
    out.monotonic_call = MonotonicOverLog(log, PickConcolicCalled, call_witness);
    if (!out.monotonic_call) {
        std::cout << "RANK16-NONMONOTONIC observation=concolic_call rng_seed=" << rng_seed
                  << " threshold=" << threshold << " witness=" << call_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_call)
        << "concolic call not monotone in the budget, rng_seed=" << rng_seed
        << " threshold=" << threshold;

    out.probes = seq - seq_before;

    // THE line the report reads its numbers off, in the field order the queue
    // registered. Its shape is fixed by that registration and nothing else is
    // printed with this prefix. The CONTROL is printed with the same shape and
    // is told apart by `threshold=32`. `probes` and `wall_ms` are the ladder's
    // totals; `execs` and `concolic_calls` are the probe-N snapshot named by
    // kCounterRule.
    std::cout << "RANK16 rng_seed=" << out.rng_seed << " threshold=" << out.threshold
              << " min_budget=" << MinOrNone(out) << " probes=" << out.probes
              << " execs=" << SnapOrNone(out, out.execs_at_min)
              << " concolic_calls=" << SnapOrNone(out, out.concolic_calls_at_min)
              << " wall_ms=" << out.wall_ms << '\n'
              << std::flush;

    // Everything the RANK16 line has no room for, including the counters at
    // the chronologically first crashing probe (the ticket), so the other
    // reading of "first crashing probe" is answerable from this log without a
    // rerun.
    std::cout << "RANK16-POINT rng_seed=" << out.rng_seed << " threshold=" << out.threshold
              << " role=" << (out.is_control ? "control" : "new")
              << " t8_min_budget=" << out.t8_min_budget << " t32_min_budget=" << out.t32_min_budget
              << " t64_min_budget=" << out.t64_min_budget
              << " crashed_at_hi=" << (out.crashed_at_hi ? "yes" : "no")
              << " first_concolic_iteration="
              << (out.first_call_search_complete ? std::to_string(out.first_concolic_iteration)
                                                 : std::string("none"))
              << " snapshot_probe=" << (out.snapshot_taken ? "probe-N" : "none")
              << " wall_ms_at_snapshot=" << SnapOrNone(out, out.wall_ms_at_min)
              << " concolic_candidates_at_min=" << SnapOrNone(out, out.concolic_candidates_at_min)
              << " concolic_no_binding_at_min=" << SnapOrNone(out, out.concolic_no_binding_at_min)
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
    std::cout << "RANK16-META budget_units=strict_execs historical_controls=legacy_requested "
                 "terminal_control_adjustment=plus_one gate=add_gate add_gate="
              << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL << " threshold=" << kThreshold16
              << " donor_threshold=" << kDonorThreshold
              << " control_threshold=" << kControlThreshold
              << " production_threshold=" << kDefaultConcolicStagnationThreshold
              << " threshold_source=src/core/campaign.h:58 arm_seed=donor"
              << " budget_interval=" << kSearchLo << ".." << kSearchHi
              << " concolic_timeout_ms=2000"
              << " seeds=" << kSeeds.size() << " new_fuzzing_runs=" << kNewFuzzingRuns
              << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n'
              << "RANK16-PREREGISTERED sweep_order=" << kSeeds[0] << "," << kSeeds[1] << ","
              << kSeeds[2] << " publish_order=" << kPublishSeeds[0] << "," << kPublishSeeds[1]
              << "," << kPublishSeeds[2] << " t8=" << kPublishT8[0] << "," << kPublishT8[1] << ","
              << kPublishT8[2] << " t32=" << kPublishT32[0] << "," << kPublishT32[1] << ","
              << kPublishT32[2] << " t64=" << kPublishT64[0] << "," << kPublishT64[1] << ","
              << kPublishT64[2] << " seed_source=" << kSeedSource << " seed_source_quote=\""
              << kSeedSourceQuote << "\"\n"
              << "RANK16-T32-SOURCE t32_source=" << kT32Source << " t32_source_quote=\""
              << kT32SourceQuote << "\"\n"
              << "RANK16-CONTROL control_seed=" << kDonorRngSeed
              << " control_threshold=" << kControlThreshold
              << " expected_min_budget=" << kDonorExpectedT32
              << " control_source=" << kControlSource
              << " control_quote=\"donor_control_t32=51, donor_control_matches_task081=yes,\"\n"
              << "RANK16-COUNTER-RULE rule=\"" << kCounterRule << "\"\n"
              << "RANK16-ORDER-RULE source=" << kOrderRuleSource << " rule=\"" << kOrderRule
              << "\"\n"
              << std::flush;
}

// The whole unit in one test: the control at threshold 32 and the three seeds
// at threshold 16 under one wall-clock budget. They are not split, because the
// control is what licenses the three new numbers to be read at all - running
// them apart would let the comparison be published beside a control from a
// different process.
TEST(AddGateRankThreshold16, SeedRankInsideTheIntervalEightToThirtyTwo) {
    const std::string why = MissingArtifact();
    if (!why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta();

    int seq = 0;

    auto quoted = [](std::uint64_t seed, const std::array<std::uint64_t, 3>& triple) {
        for (std::size_t k = 0; k < kPublishSeeds.size(); ++k) {
            if (kPublishSeeds[k] == seed) {
                return triple[k];
            }
        }
        return std::uint64_t{0};
    };

    // The control FIRST, at task-110's threshold 32: by the time the three
    // T=16 ladders run, the stand has already had to reproduce the published
    // 51 on this machine, in this process, tonight.
    SeedResult control{};
    MeasureSeed(kDonorRngSeed, kControlThreshold, /*is_control=*/true,
                quoted(kDonorRngSeed, kPublishT8), quoted(kDonorRngSeed, kPublishT32),
                quoted(kDonorRngSeed, kPublishT64), seq, control);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());

    const bool control_holds =
        control.crash_search_complete && control.min_budget == kDonorExpectedT32;

    std::cout << "RANK16-CONTROL-VERDICT control_seed=" << kDonorRngSeed
              << " control_threshold=" << kControlThreshold
              << " expected_min_budget=" << kDonorExpectedT32
              << " measured_min_budget=" << MinOrNone(control)
              << " control_holds=" << (control_holds ? "yes" : "no")
              << " bench_verdict=" << (control_holds ? "same-bench" : "not-the-same-bench") << '\n'
              << std::flush;

    // The three new ladders, all at threshold 16.
    std::array<SeedResult, kSeeds.size()> results{};
    for (std::size_t i = 0; i < kSeeds.size(); ++i) {
        MeasureSeed(kSeeds[i], kThreshold16, /*is_control=*/false, quoted(kSeeds[i], kPublishT8),
                    quoted(kSeeds[i], kPublishT32), quoted(kSeeds[i], kPublishT64), seq,
                    results[i]);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
    }

    // Re-indexed into publication order (min, median, donor) so the verdict's
    // triples line up slot by slot with the three quoted ones.
    std::array<const SeedResult*, 3> pub{};
    for (std::size_t k = 0; k < kPublishSeeds.size(); ++k) {
        for (const SeedResult& r : results) {
            if (r.rng_seed == kPublishSeeds[k]) {
                pub[k] = &r;
            }
        }
        ASSERT_NE(pub[k], nullptr);
    }

    // A ladder without a located minimum takes no part in the comparison: an
    // unlocated minimum lies above 400 and orders against nothing measured.
    // kOrderRule handles that itself - it counts the solved entries and says
    // `undefined` below two.
    const std::array<bool, 3> solved = {pub[0]->crash_search_complete,
                                        pub[1]->crash_search_complete,
                                        pub[2]->crash_search_complete};
    const std::array<std::uint64_t, 3> t16 = {pub[0]->min_budget, pub[1]->min_budget,
                                              pub[2]->min_budget};

    // kOrderRule, applied. Nothing here reads the numbers by eye.
    const char* order_vs_t8 = CompareOrder(kPublishT8, t16, solved);
    const char* order_vs_t32 = CompareOrder(kPublishT32, t16, solved);
    const char* flip_interval = FlipInterval(order_vs_t8, order_vs_t32);

    // The one case in which task-109's rule (ties tolerated) and task-110's
    // harness (any tie is mixed) could put different words on the same
    // numbers. Printed as an observation so a reader never has to reconstruct
    // it; it changes nothing in the verdict, which follows kOrderRule alone.
    bool ties = false;
    for (std::size_t i = 0; i < t16.size(); ++i) {
        for (std::size_t j = i + 1; j < t16.size(); ++j) {
            if (solved[i] && solved[j] && t16[i] == t16[j]) {
                ties = true;
            }
        }
    }
    std::cout << "RANK16-ORDER-NOTE t16_has_ties=" << (ties ? "yes" : "no")
              << " rule_is_task109_verbatim=yes rule_source=" << kOrderRuleSource
              << " note=\"task-109's rule tolerates a tie in the measured triple; task-110's "
                 "harness folded any tie into mixed; without ties the two agree pair for pair\"\n"
              << std::flush;

    const bool walltime_hit = control.walltime_hit || pub[0]->walltime_hit ||
                              pub[1]->walltime_hit || pub[2]->walltime_hit;
    const std::uint64_t walltime_used = static_cast<std::uint64_t>(WalltimeUsedS());

    std::cout << "RANK16-VERDICT: RANK-T16: seeds=" << kSeeds.size() << ", t8=" << kPublishT8[0]
              << "," << kPublishT8[1] << "," << kPublishT8[2] << ", t16=" << MinOrNone(*pub[0])
              << "," << MinOrNone(*pub[1]) << "," << MinOrNone(*pub[2])
              << ", t32=" << kPublishT32[0] << "," << kPublishT32[1] << "," << kPublishT32[2]
              << ", t64=" << kPublishT64[0] << "," << kPublishT64[1] << "," << kPublishT64[2]
              << ", order_t16_vs_t8=" << order_vs_t8 << ", order_t16_vs_t32=" << order_vs_t32
              << ", flip_interval=" << flip_interval << ", donor_control_t32=" << MinOrNone(control)
              << ", donor_control_matches_task110=" << (control_holds ? "yes" : "no")
              << ", stagnation_threshold=" << kThreshold16 << ", budget_ladder_max=" << kSearchHi
              << ", timeout_hit=" << (walltime_hit ? "yes" : "no") << ", seeds=" << kSeeds.size()
              << ", seeds_are_a_median=no"
              << ", src_modified=0, new_fuzzing_runs=" << kNewFuzzingRuns << ", reports_modified=0"
              << ", probes=" << seq
              << ", walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS)
              << ", walltime_used_s=" << walltime_used << '\n'
              << std::flush;

    EXPECT_TRUE(control_holds)
        << "control seed " << kDonorRngSeed
        << " did not reproduce the strict-budget equivalent of task-110's " << kDonorExpectedT32
        << " at threshold " << kControlThreshold
        << "; the stand is not the same stand and no line about the order is licensed";
    EXPECT_LE(walltime_used, static_cast<std::uint64_t>(kWalltimeBudgetS))
        << "the harness overran its own wall-clock budget";
}

}  // namespace
}  // namespace mlfuzzz3::core
