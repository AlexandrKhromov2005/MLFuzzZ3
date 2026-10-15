// task-072 / ADR 0036 — are the extra eight iterations of the first interval
// the stagnation threshold, or a coincidence?
//
// What was missing. task-067 fitted the concolic call cadence of the
// add_gate campaign — "первый вызов — на 18-м exec, дальше каждые 10"
// (docs/experiments/solver-add-gate-crash-budget/report.md:69-70) — and left
// exactly one quantity unexplained, in as many words: "ПОЧЕМУ первый интервал
// длиннее последующих на 8 — здесь не выяснялось и не объявляется: это
// отдельный вопрос к счётчику стагнации"
// (docs/experiments/solver-add-gate-crash-budget/report.md:83-85). That run
// held the stagnation threshold at exactly eight
// (tests/integration/concolic/test_add_gate_crash_budget.cpp:200), so the
// excess and the threshold share a value and nothing yet says whether they
// share a cause.
//
// What this harness moves and what it does not. ONLY
// `concolic_stagnation_threshold`. The mutation RNG seed (`kRngSeed = 7`,
// donor :199) and the input seed (`kArmSeed`, donor :194) keep their donor
// values byte for byte, so a difference between two thresholds cannot be a
// difference of RNG stream. src/ is not touched and no default is proposed:
// the minimal budget stays an EXTERNAL estimate obtained by re-running a
// truncated campaign, never an in-run counter.
//
// The two numbers per threshold, and how each is obtained from OUTSIDE.
//   * minimal crashing budget — binary search over [1, 200] on
//     `stats.crashes > 0`, the donor's protocol
//     (test_add_gate_crash_budget.cpp);
//   * iteration of the FIRST concolic call — the same binary search run on
//     `stats.concolic_calls > 0` instead. `max_iterations` participates in
//     exactly one place, the stop condition (src/core/campaign.cpp:339), so
//     the smallest budget under which a call is counted IS the iteration
//     that call happens on;
//   * iteration of the SECOND call — the same search once more, on
//     `stats.concolic_calls >= 2`.
// TWO cadences, and they do not agree. task-067 built its "дальше каждые 10"
// by FITTING the call counts against the budget, which is the quotient
// c_fit = (200 - first) / (calls_at_200 - 1); measured directly, the gap
// between the first and the second call at the control threshold is 11, not
// 10 (first=18, second=29). The hypothesis under test is task-067's, so the
// verdict field is computed on c_fit — anything else would test a statement
// nobody made — and the directly measured gap and its own offset are printed
// beside it, so the disagreement is on the record and needs no rerun to see.
//
// The model is fixed HERE, in source, before any number is read — see
// kModelFormula and kModelKindRule below — and the prediction for the
// seventh, out-of-sample threshold 24 is printed BEFORE that threshold is
// run. A prediction that misses demotes the model to descriptive; the
// equality "offset == threshold" that fails on any one of the six demotes it
// to none. Neither outcome is patched over with a second formula.
//
// Monotonicity is CHECKED, not assumed: for every threshold all probes of
// that threshold are examined for a pair (b1 < b2) crashing at b1 and not at
// b2, and the same for the "a concolic call happened" observation.
//
// Structural donor: the campaign plumbing, the fixed scheduler, the probe
// record and the monotonicity predicate are copied from
// tests/integration/concolic/test_add_gate_crash_budget.cpp and its already
// parameterised sibling test_add_gate_budget_seed_spread.cpp (neither file is
// modified) and re-parameterised by the stagnation threshold.
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
// HELD FIXED: this sweep varies the stagnation threshold only.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Held fixed at the donor's value (test_add_gate_crash_budget.cpp:199). The
// RNG seed is the adjacent axis task-071 lifted and this one does not.
constexpr std::uint64_t kRngSeed = 7;

// PRE-REGISTERED axis, in run order. 8 is the control — it is the donor's
// threshold, and its minimal budget must reproduce task-067's 18
// (docs/experiments/solver-add-gate-crash-budget/report.md:10). The six
// values are the ones named in the queue entry for task-072; the list is the
// contract and a value is never swapped after the run.
constexpr std::array<std::uint32_t, 6> kThresholds = {1, 2, 4, 8, 16, 32};

// The seventh value, deliberately OUTSIDE the six: the model is checked
// against it out of sample, and it is run last so its prediction can be
// printed before its result.
constexpr std::uint32_t kPredictionThreshold = 24;

constexpr std::uint32_t kControlThreshold = 8;
constexpr std::uint64_t kControlExpectedMinBudget = test_support::strict_terminal_budget(18);

// Search interval, the donor's (test_add_gate_crash_budget.cpp:204-205).
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 200;

// THE MODEL, fixed in source before any number of this sweep is read. It is
// printed by both tests ahead of their first probe, so the raw log carries it
// above its own evidence.
constexpr const char* kModelFormula =
    "first_concolic_iteration(T) = T + c and min_budget(T) = first_concolic_iteration(T) "
    "while the crash lands on the first concolic call; c is task-067's fitted cadence "
    "c_fit = (200 - first) / (calls_at_200 - 1); the offset tested against T is "
    "offset = first_concolic_iteration - c_fit, and the directly measured first gap "
    "(second - first) is reported beside it under offset_gap without entering the verdict";

// The rule that decides model_kind, fixed with the formula rather than after
// the table: a formula that has to be rewritten to fit is not a model.
constexpr const char* kModelKindRule =
    "predictive iff offset==threshold holds on all six thresholds AND the printed prediction for "
    "threshold 24 equals its measured min_budget exactly; descriptive iff the six hold but the "
    "out-of-sample prediction misses; none iff the equality fails on any of the six";

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
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_budget_stagnation_axis";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-stagnation-axis");
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
    EXPECT_LE(out_stats.execs, max_iterations) << "execution budget must include preparation";
    const auto t1 = std::chrono::steady_clock::now();
    out_wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    std::filesystem::remove_all(base, ec);
}

// Every measured number in the report is read off one of these lines. The
// shape is fixed so that a rerun differs only in `wall_ms`.
void PrintProbe(const char* phase, int seq, std::uint32_t threshold, std::uint64_t budget,
                const CampaignStats& s, std::uint64_t wall_ms) {
    std::cout << "STAGNATION-AXIS-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
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
// ran: such a threshold is named in the verdict and kept OUT of the min/max
// rather than folded in as a zero.
struct ThresholdResult {
    std::uint32_t threshold = 0;
    bool crashed_at_hi = false;
    bool concolic_called_at_hi = false;
    std::uint64_t min_budget = 0;
    std::uint64_t first_concolic_iteration = 0;
    std::uint64_t concolic_calls_at_hi = 0;
    std::uint64_t second_concolic_iteration = 0;
    std::uint64_t cadence_fit = 0;  // (200 - first) / (calls_at_200 - 1): task-067's construction
    std::uint64_t first_gap = 0;    // second - first, measured directly; 0 when no second call
    std::uint64_t offset = 0;       // first - cadence_fit: the quantity the hypothesis is about
    std::uint64_t offset_gap = 0;   // first - first_gap: the same quantity on the measured gap
    bool offset_equals_threshold = false;      // on offset
    bool offset_gap_equals_threshold = false;  // on offset_gap
    std::uint64_t concolic_calls_at_min = 0;
    std::uint64_t concolic_crashes_at_min = 0;
    bool crash_at_min_minus_1 = false;
    bool monotonic_crash = false;
    bool monotonic_call = false;
    std::size_t probes = 0;
};

// The whole protocol for ONE threshold: entry ticket, the two binary
// searches, the three probes around the transition, both monotonicity checks
// and one summary line. Fatal assertions inside report against the calling
// test; callers must bail out on ::testing::Test::HasFatalFailure().
void MeasureThreshold(std::uint32_t threshold, int& seq, ThresholdResult& out) {
    std::vector<Probe> log;
    CampaignStats stats;
    std::uint64_t wall_ms = 0;
    out = ThresholdResult{};
    out.threshold = threshold;

    // --- Entry ticket: without a crash at the top of the interval a binary
    // search over [1, 200] is meaningless. A threshold that fails the ticket
    // is a FINDING, recorded and carried, not a reason to stop.
    ASSERT_TRUE(Probe1("ticket", seq, threshold, kSearchHi, log, stats, wall_ms));
    ASSERT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors, threshold="
                                << threshold;
    out.crashed_at_hi = stats.crashes > 0;
    out.concolic_called_at_hi = stats.concolic_calls > 0;
    out.concolic_calls_at_hi = stats.concolic_calls;

    // --- Iteration of the FIRST concolic call: the same binary search, run
    // on "a call was counted" instead of "a crash was found".
    if (out.concolic_called_at_hi) {
        std::uint64_t lo = kSearchLo;
        std::uint64_t hi = kSearchHi;
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            ASSERT_TRUE(Probe1("first-call-search", seq, threshold, mid, log, stats, wall_ms));
            if (stats.concolic_calls > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        out.first_concolic_iteration = lo;

        // --- Iteration of the SECOND call, so the cadence is a difference of
        // two measured iterations rather than a rounded quotient. The search
        // starts above the first call: no budget below it can hold two.
        if (out.concolic_calls_at_hi >= 2) {
            out.cadence_fit =
                (kSearchHi - out.first_concolic_iteration) / (out.concolic_calls_at_hi - 1);
            lo = out.first_concolic_iteration + 1;
            hi = kSearchHi;
            while (lo < hi) {
                const std::uint64_t mid = lo + (hi - lo) / 2;
                ASSERT_TRUE(Probe1("second-call-search", seq, threshold, mid, log, stats, wall_ms));
                if (stats.concolic_calls >= 2) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            out.second_concolic_iteration = lo;
            out.first_gap = out.second_concolic_iteration - out.first_concolic_iteration;
        }
        if (out.cadence_fit > 0 && out.first_concolic_iteration >= out.cadence_fit) {
            out.offset = out.first_concolic_iteration - out.cadence_fit;
            out.offset_equals_threshold = out.offset == static_cast<std::uint64_t>(threshold);
        }
        if (out.first_gap > 0 && out.first_concolic_iteration >= out.first_gap) {
            out.offset_gap = out.first_concolic_iteration - out.first_gap;
            out.offset_gap_equals_threshold =
                out.offset_gap == static_cast<std::uint64_t>(threshold);
        }
    }

    if (out.crashed_at_hi) {
        // --- Binary search for the minimal crashing budget in [1, 200].
        std::uint64_t lo = kSearchLo;
        std::uint64_t hi = kSearchHi;
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            ASSERT_TRUE(Probe1("search", seq, threshold, mid, log, stats, wall_ms));
            if (stats.crashes > 0) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        out.min_budget = lo;

        // --- The point itself, re-probed so the counters at the minimum come
        // from a probe of their own rather than from a search step.
        CampaignStats at_min;
        std::uint64_t wall_at_min = 0;
        ASSERT_TRUE(Probe1("probe-N", seq, threshold, out.min_budget, log, at_min, wall_at_min));
        EXPECT_GT(at_min.crashes, 0U)
            << "no crash at the budget the search called minimal, threshold=" << threshold;
        out.concolic_calls_at_min = at_min.concolic_calls;
        out.concolic_crashes_at_min = at_min.concolic_crashes;

        // --- The point below it: the transition is a claim about a boundary,
        // so the boundary is probed from underneath too.
        if (out.min_budget > kSearchLo) {
            CampaignStats below;
            std::uint64_t wall_below = 0;
            ASSERT_TRUE(
                Probe1("probe-N-1", seq, threshold, out.min_budget - 1, log, below, wall_below));
            out.crash_at_min_minus_1 = below.crashes > 0;
            EXPECT_EQ(below.crashes, 0U)
                << "budget below the minimum crashes — the point is not the transition, threshold="
                << threshold;
        }

        // --- One above, so monotonicity has a witness on both sides of the
        // transition and not only the search's own steps.
        ASSERT_TRUE(Probe1("probe-N+1", seq, threshold, out.min_budget + 1, log, stats, wall_ms));
        EXPECT_GT(stats.crashes, 0U)
            << "no crash one above the transition point, threshold=" << threshold;
    }

    // --- Both monotonicity checks, over every probe taken for THIS threshold.
    std::string crash_witness;
    out.monotonic_crash = MonotonicOverLog(log, PickCrashed, crash_witness);
    if (!out.monotonic_crash) {
        std::cout << "STAGNATION-AXIS-NONMONOTONIC observation=crash threshold=" << threshold
                  << " witness=" << crash_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_crash)
        << "crash is not monotonic in the budget for threshold=" << threshold << ": "
        << crash_witness;

    std::string call_witness;
    out.monotonic_call = MonotonicOverLog(log, PickConcolicCalled, call_witness);
    if (!out.monotonic_call) {
        std::cout << "STAGNATION-AXIS-NONMONOTONIC observation=concolic_call threshold="
                  << threshold << " witness=" << call_witness << '\n'
                  << std::flush;
    }
    EXPECT_TRUE(out.monotonic_call)
        << "the first concolic call is not monotonic in the budget for threshold=" << threshold
        << ": " << call_witness;

    out.probes = log.size();
    std::cout << "STAGNATION-AXIS-THRESHOLD threshold=" << out.threshold
              << " crashed_at_hi=" << (out.crashed_at_hi ? "yes" : "no") << " min_budget="
              << (out.crashed_at_hi ? std::to_string(out.min_budget) : std::string("none"))
              << " first_concolic_iteration="
              << (out.concolic_called_at_hi ? std::to_string(out.first_concolic_iteration)
                                            : std::string("none"))
              << " second_concolic_iteration="
              << (out.second_concolic_iteration > 0 ? std::to_string(out.second_concolic_iteration)
                                                    : std::string("none"))
              << " concolic_calls_at_200=" << out.concolic_calls_at_hi
              << " cadence_fit=" << out.cadence_fit << " first_gap=" << out.first_gap
              << " offset=" << out.offset
              << " offset_equals_threshold=" << (out.offset_equals_threshold ? "yes" : "no")
              << " offset_gap=" << out.offset_gap
              << " offset_gap_equals_threshold=" << (out.offset_gap_equals_threshold ? "yes" : "no")
              << " concolic_calls_at_min=" << out.concolic_calls_at_min
              << " concolic_crashes_at_min=" << out.concolic_crashes_at_min
              << " crash_at_min_minus_1=" << (out.crash_at_min_minus_1 ? "yes" : "no")
              << " monotonic_crash=" << (out.monotonic_crash ? "yes" : "no")
              << " monotonic_call=" << (out.monotonic_call ? "yes" : "no")
              << " probes=" << out.probes << '\n'
              << std::flush;
}

// The header both tests print before their first probe, so the model stands
// above its own evidence in the raw log.
void PrintMeta(const char* scope, std::size_t thresholds) {
    std::cout << "STAGNATION-AXIS-META budget_units=strict_execs "
                 "historical_controls=legacy_requested terminal_control_adjustment=plus_one scope="
              << scope << " add_gate=" << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL << " rng_seed=" << kRngSeed << " arm_seed=fixed"
              << " search_lo=" << kSearchLo << " search_hi=" << kSearchHi
              << " thresholds=" << thresholds << '\n'
              << "STAGNATION-AXIS-MODEL formula=\"" << kModelFormula << "\" model_kind_rule=\""
              << kModelKindRule << "\"\n"
              << std::flush;
}

// This unit's own check, and the only one it claims: at the donor's threshold
// the binary search over [1, 200] must land back on task-067's 18
// (docs/experiments/solver-add-gate-crash-budget/report.md:10). It is a
// separate test so the control can be run — and can fail — without the full
// six-value sweep.
TEST(AddGateBudgetStagnationAxis, ControlThreshold8ReproducesTask067MinBudget) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta("control", 1);
    std::cout << "STAGNATION-AXIS-PREREGISTERED thresholds=1,2,4,8,16,32 prediction_threshold="
              << kPredictionThreshold << " control=" << kControlThreshold
              << " control_expected_min_budget=" << kControlExpectedMinBudget << '\n'
              << std::flush;

    int seq = 0;
    ThresholdResult r;
    MeasureThreshold(kControlThreshold, seq, r);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());

    const bool control_matches_legacy_pin =
        r.crashed_at_hi && r.min_budget == kControlExpectedMinBudget;
    EXPECT_TRUE(control_matches_legacy_pin)
        << "control threshold " << kControlThreshold
        << " did not reproduce min_budget_crash=" << kControlExpectedMinBudget << " from task-067";

    std::cout << "STAGNATION-AXIS-CONTROL-VERDICT: ADD-GATE-STAGNATION-AXIS-CONTROL: threshold="
              << kControlThreshold << ", min_budget="
              << (r.crashed_at_hi ? std::to_string(r.min_budget) : std::string("none"))
              << ", control_threshold8_equals_18=" << (control_matches_legacy_pin ? "yes" : "no")
              << ", first_concolic_iteration="
              << (r.concolic_called_at_hi ? std::to_string(r.first_concolic_iteration)
                                          : std::string("none"))
              << ", second_concolic_iteration="
              << (r.second_concolic_iteration > 0 ? std::to_string(r.second_concolic_iteration)
                                                  : std::string("none"))
              << ", cadence_fit=" << r.cadence_fit << ", first_gap=" << r.first_gap
              << ", offset=" << r.offset
              << ", offset_equals_threshold=" << (r.offset_equals_threshold ? "yes" : "no")
              << ", offset_gap=" << r.offset_gap
              << ", offset_gap_equals_threshold=" << (r.offset_gap_equals_threshold ? "yes" : "no")
              << ", concolic_calls_at_min=" << r.concolic_calls_at_min
              << ", monotonic_crash=" << (r.monotonic_crash ? "yes" : "no")
              << ", probes=" << r.probes << ", src_modified=0, new_fuzzing_runs=0, "
              << "reports_modified=0\n"
              << std::flush;
}

// The full axis. Not run by this unit — the sweep and its report are the next
// unit's work; the target is built and the control above is what this unit
// proves.
TEST(AddGateBudgetStagnationAxis, MinimalBudgetAcrossStagnationThresholds) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    PrintMeta("axis", kThresholds.size());
    {
        std::cout << "STAGNATION-AXIS-PREREGISTERED thresholds=";
        for (std::size_t i = 0; i < kThresholds.size(); ++i) {
            std::cout << (i == 0 ? "" : ",") << kThresholds[i];
        }
        std::cout << " prediction_threshold=" << kPredictionThreshold
                  << " control=" << kControlThreshold
                  << " control_expected_min_budget=" << kControlExpectedMinBudget << '\n'
                  << std::flush;
    }

    int seq = 0;
    std::vector<ThresholdResult> results;
    for (const std::uint32_t threshold : kThresholds) {
        ThresholdResult r;
        MeasureThreshold(threshold, seq, r);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        results.push_back(r);
    }

    std::vector<std::uint64_t> minima;
    std::size_t no_crash_at_hi = 0;
    std::string no_crash_names;
    std::size_t offset_holds = 0;
    std::size_t offset_gap_holds = 0;
    std::string offset_fails_names;
    std::size_t probes_total = 0;
    std::uint64_t control_cadence = 0;
    bool control_matches_legacy_pin = false;
    for (const ThresholdResult& r : results) {
        probes_total += r.probes;
        if (r.crashed_at_hi) {
            minima.push_back(r.min_budget);
        } else {
            ++no_crash_at_hi;
            no_crash_names += (no_crash_names.empty() ? "" : ",") + std::to_string(r.threshold);
        }
        if (r.offset_gap_equals_threshold) {
            ++offset_gap_holds;
        }
        if (r.offset_equals_threshold) {
            ++offset_holds;
        } else {
            offset_fails_names +=
                (offset_fails_names.empty() ? "" : ",") + std::to_string(r.threshold);
        }
        if (r.threshold == kControlThreshold) {
            control_cadence = r.cadence_fit;
            control_matches_legacy_pin =
                r.crashed_at_hi && r.min_budget == kControlExpectedMinBudget;
        }
    }

    // The control decides whether anything else in the table is proven: a
    // harness that cannot reproduce the pinned 18 is not measuring task-067's
    // quantity.
    EXPECT_TRUE(control_matches_legacy_pin)
        << "control threshold " << kControlThreshold
        << " did not reproduce min_budget_crash=" << kControlExpectedMinBudget << " from task-067";

    // Minima are monotone in the threshold when no pair goes backwards; the
    // thresholds that never crashed are excluded from the statement rather
    // than counted as zero.
    bool monotonic_in_threshold = true;
    std::uint64_t prev = 0;
    bool have_prev = false;
    for (const ThresholdResult& r : results) {
        if (!r.crashed_at_hi) {
            continue;
        }
        if (have_prev && r.min_budget < prev) {
            monotonic_in_threshold = false;
        }
        prev = r.min_budget;
        have_prev = true;
    }

    const bool offset_equals_threshold_all = offset_holds == results.size();

    // --- The out-of-sample check. The prediction is computed from the model
    // above and PRINTED FIRST; only then is threshold 24 run.
    const std::uint64_t predicted =
        static_cast<std::uint64_t>(kPredictionThreshold) + control_cadence;
    std::cout << "STAGNATION-AXIS-PREDICTION threshold=" << kPredictionThreshold
              << " cadence_from_control=" << control_cadence << " predicted_min_budget="
              << (control_cadence > 0 ? std::to_string(predicted) : std::string("not-attempted"))
              << " basis=\"" << kModelFormula << "\"\n"
              << std::flush;

    ThresholdResult pr;
    MeasureThreshold(kPredictionThreshold, seq, pr);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    probes_total += pr.probes;

    // "not-attempted" is reserved for the case where no prediction could be
    // computed at all (no cadence at the control). Once a number has been
    // printed, its outcome is `yes` or `no` — a model refuted on the six is
    // not thereby excused from its own out-of-sample number.
    const bool prediction_attempted = control_cadence > 0;
    const bool prediction_held =
        prediction_attempted && pr.crashed_at_hi && pr.min_budget == predicted;
    std::cout << "STAGNATION-AXIS-PREDICTION-RESULT threshold=" << kPredictionThreshold
              << " predicted_min_budget="
              << (control_cadence > 0 ? std::to_string(predicted) : std::string("none"))
              << " measured_min_budget="
              << (pr.crashed_at_hi ? std::to_string(pr.min_budget) : std::string("none"))
              << " prediction_held="
              << (!prediction_attempted ? "not-attempted" : (prediction_held ? "yes" : "no"))
              << '\n'
              << std::flush;

    const char* model_kind = "none";
    if (offset_equals_threshold_all) {
        model_kind = prediction_held ? "predictive" : "descriptive";
    }

    if (no_crash_at_hi > 0) {
        std::cout << "STAGNATION-AXIS-NO-CRASH thresholds=" << no_crash_names << '\n' << std::flush;
    }
    // The competing definition, kept out of the verdict but never out of the
    // log: whichever way the fitted cadence lands, the directly measured gap
    // gets its own count on its own line.
    std::cout << "STAGNATION-AXIS-OFFSET-GAP offset_gap_equals_threshold=" << offset_gap_holds
              << "/" << results.size() << '\n'
              << std::flush;

    if (!offset_fails_names.empty()) {
        std::cout << "STAGNATION-AXIS-OFFSET-MISMATCH thresholds=" << offset_fails_names << '\n'
                  << std::flush;
    }

    const std::uint64_t min_of_minima =
        minima.empty() ? 0 : *std::min_element(minima.begin(), minima.end());
    const std::uint64_t max_of_minima =
        minima.empty() ? 0 : *std::max_element(minima.begin(), minima.end());

    std::cout << "STAGNATION-AXIS-VERDICT: ADD-GATE-STAGNATION-AXIS: thresholds="
              << kThresholds.size() << ", values=1|2|4|8|16|32, control_threshold8_equals_18="
              << (control_matches_legacy_pin ? "yes" : "no")
              << ", offset_equals_threshold=" << (offset_equals_threshold_all ? "yes" : "no")
              << ", min_budget_min=" << min_of_minima << ", min_budget_max=" << max_of_minima
              << ", monotonic_in_threshold=" << (monotonic_in_threshold ? "yes" : "non-monotonic")
              << ", thresholds_no_crash_at_200=" << no_crash_at_hi << ", model=\"" << kModelFormula
              << "\", prediction_threshold24="
              << (control_cadence > 0 ? std::to_string(predicted) : std::string("none"))
              << ", prediction_held="
              << (!prediction_attempted ? "not-attempted" : (prediction_held ? "yes" : "no"))
              << ", model_kind=" << model_kind << ", probes_total=" << probes_total
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
