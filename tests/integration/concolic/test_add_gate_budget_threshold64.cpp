// task-081, ADR 0036: what the niche costs at the PRODUCTION stagnation
// threshold. Everything the series has published about the price of the
// verbatim-composition niche on add_gate — min_budget=18, the ratios to the
// disarmed arm, the seed ensemble — was measured with the stagnation
// threshold pinned at the donor's 8. The fuzzer's own default is a different
// number: src/core/campaign.h:58 fixes
// kDefaultConcolicStagnationThreshold = 64. The measured axis of task-072
// (docs/experiments/solver-add-gate-stagnation-axis/report.md:12) stops at
// 32, where the minimum is already 51 — so the production configuration lies
// OUTSIDE every interval this project has measured.
//
// This harness adds exactly one point to that axis: threshold 64, with the
// RNG seed, the input seed, the gate and the fixture held at the donor's
// values. It varies the threshold and nothing else.
//
// Why the point is measured and not computed. task-072 printed a prediction
// for the intermediate threshold 24 and the prediction did not hold; a model
// that misses inside its own axis is not licensed to speak outside it. This
// file therefore carries NO model of the series: the only thing predicted
// ahead of the run is the direction that monotonicity already gives
// (kPredictionRule), and even that is printed before the number and reported
// as-is afterwards.
//
// Search interval 1..400, not the series' 1..200. The reason is a measured
// one and is named before the run: at threshold 32 the minimum is already 51
// (docs/experiments/solver-add-gate-stagnation-axis/report.md:12,
// "min_budget_min=3, min_budget_max=51, monotonic_in_threshold=yes,"), and a
// monotone axis puts the minimum at 64 at or above that. A ceiling of 200
// could therefore be reached without settling anything.
//
// Two controls, both RE-RUN here rather than quoted: threshold 8 must land
// back on 18 (docs/experiments/solver-add-gate-crash-budget/report.md:10) and
// threshold 32 on 51. If either misses, the stand is not the same stand, and
// every line about 64 is declared unproven — the disagreement is about this
// bench, not about the earlier numbers.
//
// The gate is not cracked by 400 => that is a RESULT, not an extrapolation.
// 400 is then published as the top of the SEARCH, and nothing here claims the
// gate would stay uncracked at a larger budget.
//
// Hard wall-clock budget for the whole harness: kWalltimeBudgetS seconds.
// Stopping on it is a legal outcome (stop_reason=walltime); every probe that
// was planned and not run is named in the raw log rather than dropped.
//
// Boundaries. src/ is not modified by a single character and the default in
// campaign.h is not touched: the behaviour is measured as it is. No fuzzing
// campaigns of the benchmark are started; the fixture is synthetic and each
// probe is one bounded in-process campaign.
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
// HELD FIXED: this measurement varies the stagnation threshold only.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Held fixed at the donor's value (test_add_gate_crash_budget.cpp:199), the
// same seed the whole price series ran on.
constexpr std::uint64_t kRngSeed = 7;

// THE point of this file. The production threshold is TAKEN from the header
// the campaign itself reads, not retyped as a literal, so the number measured
// here cannot drift away from the number the fuzzer runs with. The assertion
// below is the link to src/core/campaign.h:58: if that default ever moves,
// this harness stops compiling instead of quietly measuring a stale point.
constexpr std::uint32_t kProductionThreshold = kDefaultConcolicStagnationThreshold;
static_assert(kProductionThreshold == 64,
              "src/core/campaign.h's kDefaultConcolicStagnationThreshold moved away from 64; "
              "task-081 measures the PRODUCTION default and must be re-registered, not patched");

// The two controls. Both are RE-RUN by this harness, never quoted: a control
// that is only cited proves nothing about the bench the new number came from.
constexpr std::uint32_t kControlThresholdA = 8;
constexpr std::uint64_t kControlExpectedA = 18;  // task-067, crash-budget/report.md:10
constexpr std::uint32_t kControlThresholdB = 32;
constexpr std::uint64_t kControlExpectedB = 51;  // task-072, stagnation-axis/report.md:12

// PRE-REGISTERED axis in run order: both controls first, the production point
// last, so its prediction is printed after the controls have vouched for the
// bench and before its own result exists.
constexpr std::array<std::uint32_t, 3> kThresholds = {kControlThresholdA, kControlThresholdB,
                                                      kProductionThreshold};

// Search interval. The series used 1..200; this one uses 1..400 for the
// measured reason named in the file header — at threshold 32 the minimum is
// already 51 and the axis is monotone, so 200 may not be enough to settle the
// question at 64. The interval is fixed here, before the run, and is not
// widened afterwards to chase a result.
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 400;

// THE PREDICTION, fixed in source before any number of this run is read. It
// is deliberately weak: monotonicity is the ONLY thing the measured axis
// licenses outside its own range, and task-072's formula already failed out
// of sample at threshold 24, so no formula is used to produce a point value.
constexpr std::uint64_t kPredictedLowerBound = kControlExpectedB;
constexpr const char* kPredictionRule =
    "monotonicity only: min_budget(64) >= min_budget(32) = 51. prediction_held=yes iff the "
    "measured min_budget at 64 is >= 51, or the gate is not cracked at 400 (which puts any "
    "minimum above 400 and so above 51). No point value is predicted and no formula of "
    "task-072 is refitted: that model already missed out of sample at threshold 24";

// Hard wall-clock budget for the WHOLE harness, controls included. Checked
// before every probe is admitted; a probe is never started that the budget
// cannot pay for. Measured cost of the neighbouring six-point axis over
// 1..200 was 270 s for 220 probes
// (docs/experiments/solver-add-gate-stagnation-axis/raw-stagnation-axis.txt),
// so 900 s is a wide margin for three points over 1..400 rather than a guess.
constexpr double kWalltimeBudgetS = 900.0;

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
struct Probe {
    std::uint32_t threshold = 0;
    std::uint64_t budget = 0;
    bool crashed = false;
    bool concolic_called = false;
};

// One bounded campaign, its counters and its wall time. Fatal assertions
// inside report against the calling test; callers must bail out on
// ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint32_t stagnation_threshold, std::uint64_t max_iterations,
                 CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_budget_threshold64";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-threshold64");
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
void PrintProbe(const char* phase, int seq, std::uint32_t threshold, std::uint64_t budget,
                const CampaignStats& s, std::uint64_t wall_ms) {
    std::cout << "THRESHOLD64-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
              << " threshold=" << threshold << " rng_seed=" << kRngSeed << " budget=" << budget
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
bool Probe1(const char* phase, int& seq, std::uint32_t threshold, std::uint64_t budget,
            std::vector<Probe>& log, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    RunCampaign(threshold, budget, out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    ++seq;
    log.push_back(Probe{threshold, budget, out_stats.crashes > 0, out_stats.concolic_calls > 0});
    PrintProbe(phase, seq, threshold, budget, out_stats, out_wall_ms);
    return true;
}

// A pair (b1 < b2) with the observation present at b1 and absent at b2
// refutes monotonicity of that observation in the budget. Checked over ALL
// probes of ONE threshold — mixing thresholds would compare different
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

// One threshold's outcome. `crashed_at_hi=false` means the crash search never
// One threshold's outcome. `crashed_at_hi=false` means the crash search never
// ran: that threshold publishes min_budget=none and stays OUT of the
// monotonicity comparison rather than being folded in as a zero.
struct ThresholdResult {
    std::uint32_t threshold = 0;
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
    bool walltime_hit = false;
    std::string skipped;
};

// A probe the protocol planned and the wall-clock budget refused. It is
// NAMED, in the raw log and in the result, rather than silently dropped: a
// missing probe that nobody names is indistinguishable from a probe that was
// never planned.
void NameSkipped(ThresholdResult& out, const char* what) {
    out.walltime_hit = true;
    out.skipped += out.skipped.empty() ? "" : ",";
    out.skipped += what;
    std::cout << "THRESHOLD64-SKIPPED threshold=" << out.threshold << " probe=" << what
              << " reason=walltime walltime_used_s=" << static_cast<std::uint64_t>(WalltimeUsedS())
              << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n'
              << std::flush;
}

const char* StopReason(const ThresholdResult& r) {
    if (r.walltime_hit) {
        return "walltime";
    }
    return r.crashed_at_hi ? "crash" : "hi";
}

// The whole protocol for ONE threshold, identical in rule to task-067 and
// task-072: a ticket probe at the top of the interval, then the same binary
// search — mid, probe, `hi = mid` when the observation is present and
// `lo = mid + 1` when it is not, answer `lo` — run once on `concolic_calls >
// 0` for the iteration of the first concolic call and once on `crashes > 0`
// for the minimal crash budget. What changed against the donor is the
// interval (1..400) and nothing else.
void MeasureThreshold(std::uint32_t threshold, int& seq, ThresholdResult& out) {
    out.threshold = threshold;
    std::vector<Probe> log;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    const int seq_before = seq;

    if (!BudgetLeft()) {
        NameSkipped(out, "ticket");
        out.probes = seq - seq_before;
        return;
    }
    ASSERT_TRUE(Probe1("ticket", seq, threshold, kSearchHi, log, stats, wall_ms));
    ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors, threshold="
                                << threshold;
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
            ASSERT_TRUE(Probe1("first-call-search", seq, threshold, mid, log, stats, wall_ms));
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
            ASSERT_TRUE(Probe1("crash-search", seq, threshold, mid, log, stats, wall_ms));
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
                ASSERT_TRUE(
                    Probe1("probe-N", seq, threshold, out.min_budget, log, at_min, wall_at_min));
                out.at_min_probed = true;
                out.concolic_calls_at_min = at_min.concolic_calls;
                out.concolic_crashes_at_min = at_min.concolic_crashes;
                EXPECT_GT(at_min.crashes, 0U)
                    << "crash absent at the located minimum, threshold=" << threshold;
                EXPECT_GT(at_min.concolic_calls, 0U)
                    << "arm DISARMED at the minimum (concolic_calls=0), threshold=" << threshold;
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
                    ASSERT_TRUE(Probe1("probe-N-1", seq, threshold, out.min_budget - 1, log, below,
                                       wall_below));
                    out.min_minus_1_probed = true;
                    out.crash_at_min_minus_1 = below.crashes > 0;
                    EXPECT_EQ(below.crashes, 0U)
                        << "crash present one below the located minimum, threshold=" << threshold;
                } else {
                    NameSkipped(out, "probe-N-1");
                }
            }
        }
    }

    std::string crash_witness;
    out.monotonic_crash = MonotonicOverLog(log, PickCrashed, crash_witness);
    if (!out.monotonic_crash) {
        std::cout << "THRESHOLD64-NONMONOTONIC observation=crash threshold=" << threshold
                  << " witness=" << crash_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_crash) << "crash not monotone in the budget, threshold=" << threshold;

    std::string call_witness;
    out.monotonic_call = MonotonicOverLog(log, PickConcolicCalled, call_witness);
    if (!out.monotonic_call) {
        std::cout << "THRESHOLD64-NONMONOTONIC observation=concolic_call threshold=" << threshold
                  << " witness=" << call_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_call)
        << "concolic call not monotone in the budget, threshold=" << threshold;

    out.probes = seq - seq_before;

    std::cout << "THRESHOLD64-POINT threshold=" << out.threshold
              << " crashed_at_hi=" << (out.crashed_at_hi ? "yes" : "no") << " min_budget="
              << (out.crash_search_complete ? std::to_string(out.min_budget) : std::string("none"))
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
              << " probes=" << out.probes << " stop_reason=" << StopReason(out)
              << " skipped=" << (out.skipped.empty() ? std::string("none") : out.skipped) << '\n'
              << std::flush;
}

// The header of the raw log: what was fixed before the first probe ran.
void PrintMeta() {
    std::cout << "THRESHOLD64-META gate=add_gate add_gate=" << ADD_GATE_REL
              << " exec_server=" << EXEC_SERVER_REL << " cov_library=" << COV_LIBRARY_REL
              << " rng_seed=" << kRngSeed << " arm_seed=donor"
              << " production_default=" << kProductionThreshold
              << " production_default_source=src/core/campaign.h:58"
              << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi
              << " walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS) << '\n'
              << "THRESHOLD64-PREREGISTERED thresholds=" << kControlThresholdA << ","
              << kControlThresholdB << "," << kProductionThreshold
              << " control_a=" << kControlThresholdA << " control_a_expected=" << kControlExpectedA
              << " control_b=" << kControlThresholdB << " control_b_expected=" << kControlExpectedB
              << " search_range=" << kSearchLo << ".." << kSearchHi
              << " range_reason=\"min_budget at threshold 32 is already 51 and the axis is "
                 "monotone, so 200 may not settle 64\"\n"
              << "THRESHOLD64-PREDICTION predicted_lower_bound=" << kPredictedLowerBound
              << " rule=\"" << kPredictionRule << "\"\n"
              << std::flush;
}

// The whole unit in one test: both controls and the production point, under
// one wall-clock budget. They are not split, because the controls are what
// licenses the production point to be read at all — running them apart would
// let the point be published beside controls from a different process.
TEST(AddGateBudgetThreshold64, ProductionDefaultStagnationThreshold) {
    const std::string why = MissingArtifact();
    if (!why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta();

    int seq = 0;
    std::array<ThresholdResult, kThresholds.size()> results{};
    for (std::size_t i = 0; i < kThresholds.size(); ++i) {
        // The controls run FIRST and the production point LAST: by the time
        // 64 is measured, the bench has already had to reproduce 18 and 51.
        MeasureThreshold(kThresholds[i], seq, results[i]);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
    }

    const ThresholdResult& a = results[0];
    const ThresholdResult& b = results[1];
    const ThresholdResult& p = results[2];

    const bool control_a_holds = a.crash_search_complete && a.min_budget == kControlExpectedA;
    const bool control_b_holds = b.crash_search_complete && b.min_budget == kControlExpectedB;
    const bool controls_hold = control_a_holds && control_b_holds;

    std::cout << "THRESHOLD64-CONTROL-VERDICT control_threshold8_equals_18="
              << (control_a_holds ? "yes" : "no") << " measured_at_8="
              << (a.crash_search_complete ? std::to_string(a.min_budget) : std::string("none"))
              << " control_threshold32_equals_51=" << (control_b_holds ? "yes" : "no")
              << " measured_at_32="
              << (b.crash_search_complete ? std::to_string(b.min_budget) : std::string("none"))
              << " controls_hold=" << (controls_hold ? "yes" : "no")
              << " bench_verdict=" << (controls_hold ? "same-bench" : "not-the-same-bench") << '\n'
              << std::flush;

    // The prediction was printed before the first probe (PrintMeta). Held
    // means only what kPredictionRule says: the measured minimum is at or
    // above the neighbouring point's, or there is no minimum inside 1..400.
    const bool prediction_held = p.crash_search_complete ? (p.min_budget >= kPredictedLowerBound)
                                                         : (p.ran && !p.crashed_at_hi);

    std::cout << "THRESHOLD64-PREDICTION-RESULT predicted_lower_bound=" << kPredictedLowerBound
              << " measured_min_budget="
              << (p.crash_search_complete ? std::to_string(p.min_budget) : std::string("none"))
              << " prediction_held=" << (prediction_held ? "yes" : "no") << '\n'
              << std::flush;

    // Monotonicity over the joined axis {8, 32, 64}. A threshold whose
    // minimum was never located does not enter the comparison; when 64 has no
    // minimum inside 1..400 its minimum is above 400 and therefore above both
    // controls, which is monotone by construction and is said so in the log.
    bool monotonic = true;
    if (a.crash_search_complete && b.crash_search_complete) {
        monotonic = monotonic && b.min_budget >= a.min_budget;
    }
    if (b.crash_search_complete && p.crash_search_complete) {
        monotonic = monotonic && p.min_budget >= b.min_budget;
    }
    if (b.crash_search_complete && !p.crash_search_complete && p.ran && !p.crashed_at_hi) {
        monotonic = monotonic && kSearchHi >= b.min_budget;
    }

    const std::uint64_t walltime_used = static_cast<std::uint64_t>(WalltimeUsedS());
    const int probes_total = seq;

    std::cout << "THRESHOLD64-VERDICT: ADD-GATE-THRESHOLD64: threshold=" << kProductionThreshold
              << ", production_default=" << kProductionThreshold << ", prev_axis_max=32"
              << ", rng_seed=" << kRngSeed << ", arm_seed=donor, search_range=" << kSearchLo << ".."
              << kSearchHi << ", probes=" << probes_total
              << ", cracked_at_64=" << (p.crash_search_complete ? "yes" : "no")
              << ", min_budget_at_64="
              << (p.crash_search_complete ? std::to_string(p.min_budget) : std::string("none"))
              << ", first_concolic_iteration="
              << (p.first_call_search_complete ? std::to_string(p.first_concolic_iteration)
                                               : std::string("n/a"))
              << ", concolic_calls_at_min="
              << (p.at_min_probed ? std::to_string(p.concolic_calls_at_min) : std::string("n/a"))
              << ", control_threshold8_equals_18=" << (control_a_holds ? "yes" : "no")
              << ", control_threshold32_equals_51=" << (control_b_holds ? "yes" : "no")
              << ", prediction_printed_before_run=" << kPredictedLowerBound
              << ", prediction_held=" << (prediction_held ? "yes" : "no")
              << ", monotonic_over_8_32_64=" << (monotonic ? "yes" : "no")
              << ", extrapolation_claimed=no, default_value_modified=0"
              << ", stop_reason=" << StopReason(p)
              << ", walltime_budget_s=" << static_cast<std::uint64_t>(kWalltimeBudgetS)
              << ", walltime_used_s=" << walltime_used
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;

    EXPECT_TRUE(control_a_holds)
        << "control at threshold 8 did not reproduce task-067's " << kControlExpectedA
        << "; the bench is not the same bench and every line about 64 is unproven";
    EXPECT_TRUE(control_b_holds)
        << "control at threshold 32 did not reproduce task-072's " << kControlExpectedB
        << "; the bench is not the same bench and every line about 64 is unproven";
    EXPECT_LE(walltime_used, static_cast<std::uint64_t>(kWalltimeBudgetS))
        << "the harness overran its own wall-clock budget";
}

}  // namespace
}  // namespace mlfuzzz3::core
