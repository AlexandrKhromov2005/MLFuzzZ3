// task-071 / ADR 0036 — is 18 a property of the engine or of one RNG seed?
//
// What was missing. `min_budget_crash=18` was taken with the mutation RNG
// pinned to a single value — `constexpr std::uint64_t kRngSeed = 7;`
// (tests/integration/concolic/test_add_gate_crash_budget.cpp:199) — and the
// spread published alongside it was measured over five repeats of THAT ONE
// configuration (docs/experiments/solver-add-gate-crash-budget/report.md:128).
// Five repeats of one configuration measure environmental flake, not
// stability: the previous report in the series says so in as many words —
// "Устойчивость по сидам и по конфигурации" is what N=10 does NOT close
// (docs/experiments/solver-oracle-repeatability/report.md:161), and the
// spread over seeds is "предмет отдельной задачи, а не этой"
// (docs/experiments/solver-oracle-repeatability/report.md:170-171).
//
// Why this and not another cell of the domain. 18 is the only price number
// the series owns, and it sits in the denominator of every future claim of
// solver superiority. If it wanders across the ensemble, it cannot be
// published as a single number and the derived claims have to be restated as
// a distribution. If it holds, the number acquires a basis wider than one
// seed for the first time.
//
// Pre-registration, not post-hoc selection. The ten seeds are fixed here in
// source, in the order they are run — the control 7 first, then 1, 2, 3, 11,
// 13, 17, 23, 29, 31 — and the report lists them ABOVE its results table.
// A seed that has to be excluded stays in this list with the reason named.
//
// What moves and what does not. ONLY the mutation RNG seed. The input seed
// `kArmSeed` (test_add_gate_crash_budget.cpp:194) and the stagnation
// threshold (:200) keep their donor values byte for byte, and those are the
// adjacent axes this harness does NOT lift. src/ is not touched: exactly as
// in the donor, the minimal budget is an EXTERNAL estimate obtained by
// re-running a truncated campaign, not an in-run counter.
//
// Monotonicity is what makes the binary search legitimate, and it is CHECKED
// PER SEED by probes — every probe of that seed is kept and all pairs
// (b1 < b2) are examined for a crash at b1 with none at b2 — never inferred
// from reading the stop condition (src/core/campaign.cpp:339).
//
// Structural donor: the campaign plumbing, the fixed scheduler, the probe
// record and the monotonicity predicate are copied from
// tests/integration/concolic/test_add_gate_crash_budget.cpp (that file is not
// modified) and parameterised by the RNG seed.
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
// reason to skip. The message names artifacts by their REPO-RELATIVE path so
// that even a skipped run leaves no absolute path in the raw log. Unlike the
// donor this sweep needs no sub_gate: the ensemble is entirely within
// add_gate, and the negative control of the series already stands in
// task-067.
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
// test_add_gate_crash_budget.cpp:181-190).
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
// It is HELD FIXED here — this sweep varies the mutation RNG seed only.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Held fixed at the donor's value (test_add_gate_crash_budget.cpp:200); the
// stagnation threshold is the second adjacent axis this sweep does not lift.
constexpr std::uint32_t kStagnationThreshold = 8;

// PRE-REGISTERED ensemble, in run order. Index 0 is the control: it is the
// donor's seed, and its minimal budget must reproduce task-067's 18
// (docs/experiments/solver-add-gate-crash-budget/report.md:10). The other
// nine are the ones named in the queue entry for task-071. This list is the
// contract — a seed is never swapped after the run.
constexpr std::array<std::uint64_t, 10> kRngSeeds = {7, 1, 2, 3, 11, 13, 17, 23, 29, 31};
constexpr std::uint64_t kControlRngSeed = 7;
constexpr std::uint64_t kControlExpectedMinBudget = 18;

// Search interval, the donor's (test_add_gate_crash_budget.cpp:204-205).
constexpr std::uint64_t kSearchLo = 1;
constexpr std::uint64_t kSearchHi = 200;

struct Probe {
    std::uint64_t rng_seed = 0;
    std::uint64_t budget = 0;
    bool crashed = false;
};

// One bounded campaign, its counters and its wall time. Fatal assertions
// inside report against the calling test; callers must bail out on
// ::testing::Test::HasFatalFailure().
void RunCampaign(std::uint64_t rng_seed, std::uint64_t max_iterations, CampaignStats& out_stats,
                 std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_add_gate_budget_seed_spread";
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

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "add-gate-budget-seed-spread");
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
                             .concolic_stagnation_threshold = kStagnationThreshold,
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
    std::cout << "SEED-SPREAD-PROBE phase=" << phase << " seq=" << seq << " gate=add_gate"
              << " rng_seed=" << rng_seed << " budget=" << budget
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
            std::vector<Probe>& log, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    RunCampaign(rng_seed, budget, out_stats, out_wall_ms);
    if (::testing::Test::HasFatalFailure()) {
        return false;
    }
    ++seq;
    log.push_back(Probe{rng_seed, budget, out_stats.crashes > 0});
    PrintProbe(phase, seq, rng_seed, budget, out_stats, out_wall_ms);
    return true;
}

// A pair (b1 < b2) with a crash at b1 and none at b2 refutes monotonicity of
// the observation in the budget. Checked over ALL probes of ONE seed — this
// is a statement about that seed's search, and mixing seeds would compare
// runs of different RNG streams.
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

// Median of an even-sized sorted sample without dragging in floating point:
// "18" when the two middle values agree, "18.5" when they straddle.
std::string MedianText(std::vector<std::uint64_t> values) {
    if (values.empty()) {
        return "n/a";
    }
    std::sort(values.begin(), values.end());
    const std::size_t n = values.size();
    if (n % 2 == 1) {
        return std::to_string(values[n / 2]);
    }
    const std::uint64_t sum = values[n / 2 - 1] + values[n / 2];
    if (sum % 2 == 0) {
        return std::to_string(sum / 2);
    }
    return std::to_string(sum / 2) + ".5";
}

// One seed's outcome. `crashed_at_hi=false` means the binary search never
// ran: such a seed is named in the verdict and kept OUT of min/max/median
// rather than averaged in.
struct SeedResult {
    std::uint64_t rng_seed = 0;
    bool crashed_at_hi = false;
    std::uint64_t min_budget = 0;
    std::size_t probes = 0;
    bool monotonic = false;
    std::uint64_t concolic_calls_at_min = 0;
    std::uint64_t concolic_crashes_at_min = 0;
    bool crash_at_min_minus_1 = false;
};

TEST(AddGateBudgetSeedSpread, MinimalBudgetAcrossPreregisteredRngSeeds) {
    if (const std::string why = MissingArtifact(); !why.empty()) {
        GTEST_SKIP() << why;
    }

    std::cout << "SEED-SPREAD-META add_gate=" << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL
              << " stagnation_threshold=" << kStagnationThreshold << " search_lo=" << kSearchLo
              << " search_hi=" << kSearchHi << " seeds=" << kRngSeeds.size() << '\n'
              << std::flush;
    {
        std::cout << "SEED-SPREAD-PREREGISTERED seeds=";
        for (std::size_t i = 0; i < kRngSeeds.size(); ++i) {
            std::cout << (i == 0 ? "" : ",") << kRngSeeds[i];
        }
        std::cout << " control=" << kControlRngSeed
                  << " control_expected_min_budget=" << kControlExpectedMinBudget << '\n'
                  << std::flush;
    }

    int seq = 0;
    std::vector<SeedResult> results;

    for (const std::uint64_t rng_seed : kRngSeeds) {
        std::vector<Probe> log;
        CampaignStats stats;
        std::uint64_t wall_ms = 0;
        SeedResult r;
        r.rng_seed = rng_seed;

        // --- Entry ticket: without a crash at the top of the interval a
        // binary search over [1, 200] is meaningless. A seed that fails the
        // ticket is a FINDING, recorded and carried, not a reason to stop.
        ASSERT_TRUE(Probe1("ticket", seq, rng_seed, kSearchHi, log, stats, wall_ms));
        ASSERT_FALSE(stats.aborted)
            << "campaign aborted on infrastructure errors, rng_seed=" << rng_seed;
        r.crashed_at_hi = stats.crashes > 0;

        if (r.crashed_at_hi) {
            // --- Binary search for the minimal crashing budget in [1, 200].
            std::uint64_t lo = kSearchLo;
            std::uint64_t hi = kSearchHi;
            while (lo < hi) {
                const std::uint64_t mid = lo + (hi - lo) / 2;
                ASSERT_TRUE(Probe1("search", seq, rng_seed, mid, log, stats, wall_ms));
                if (stats.crashes > 0) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            r.min_budget = lo;

            // --- The point itself, re-probed so the counters at the minimum
            // come from a probe of their own rather than from a search step.
            CampaignStats at_min;
            std::uint64_t wall_at_min = 0;
            ASSERT_TRUE(Probe1("probe-N", seq, rng_seed, r.min_budget, log, at_min, wall_at_min));
            EXPECT_GT(at_min.crashes, 0U)
                << "no crash at the budget the search called minimal, rng_seed=" << rng_seed;
            r.concolic_calls_at_min = at_min.concolic_calls;
            r.concolic_crashes_at_min = at_min.concolic_crashes;

            // --- The point below it: the transition is a claim about a
            // boundary, so the boundary is probed from underneath too.
            if (r.min_budget > kSearchLo) {
                CampaignStats below;
                std::uint64_t wall_below = 0;
                ASSERT_TRUE(
                    Probe1("probe-N-1", seq, rng_seed, r.min_budget - 1, log, below, wall_below));
                r.crash_at_min_minus_1 = below.crashes > 0;
                EXPECT_EQ(below.crashes, 0U)
                    << "budget below the minimum crashes — the point is not the transition, "
                       "rng_seed="
                    << rng_seed;
            }

            // --- One above, so monotonicity has a witness on both sides of
            // the transition and not only the search's own steps.
            ASSERT_TRUE(Probe1("probe-N+1", seq, rng_seed, r.min_budget + 1, log, stats, wall_ms));
            EXPECT_GT(stats.crashes, 0U)
                << "no crash one above the transition point, rng_seed=" << rng_seed;
        }

        // --- Monotonicity over every probe taken for THIS seed.
        std::string witness;
        r.monotonic = MonotonicOverLog(log, witness);
        if (!r.monotonic) {
            std::cout << "SEED-SPREAD-NONMONOTONIC rng_seed=" << rng_seed << " witness=" << witness
                      << '\n'
                      << std::flush;
        }
        EXPECT_TRUE(r.monotonic) << "observation is not monotonic in the budget for rng_seed="
                                 << rng_seed << ": " << witness;

        r.probes = log.size();
        std::cout << "SEED-SPREAD-SEED rng_seed=" << r.rng_seed
                  << " crashed_at_hi=" << (r.crashed_at_hi ? "yes" : "no") << " min_budget="
                  << (r.crashed_at_hi ? std::to_string(r.min_budget) : std::string("none"))
                  << " probes=" << r.probes << " monotonic=" << (r.monotonic ? "yes" : "no")
                  << " concolic_calls_at_min=" << r.concolic_calls_at_min
                  << " concolic_crashes_at_min=" << r.concolic_crashes_at_min
                  << " crash_at_min_minus_1=" << (r.crash_at_min_minus_1 ? "yes" : "no") << '\n'
                  << std::flush;
        results.push_back(r);
    }

    // --- Ensemble summary. Seeds that never crashed at the top of the
    // interval are counted separately and excluded from the statistics.
    std::vector<std::uint64_t> minima;
    std::size_t no_crash_at_hi = 0;
    std::string no_crash_names;
    int monotonic_seeds = 0;
    std::size_t probes_total = 0;
    for (const SeedResult& r : results) {
        probes_total += r.probes;
        if (r.monotonic) {
            ++monotonic_seeds;
        }
        if (r.crashed_at_hi) {
            minima.push_back(r.min_budget);
        } else {
            ++no_crash_at_hi;
            no_crash_names += (no_crash_names.empty() ? "" : ",") + std::to_string(r.rng_seed);
        }
    }
    const std::uint64_t min_of_minima =
        minima.empty() ? 0 : *std::min_element(minima.begin(), minima.end());
    const std::uint64_t max_of_minima =
        minima.empty() ? 0 : *std::max_element(minima.begin(), minima.end());
    const std::uint64_t spread = max_of_minima - min_of_minima;

    // The publication rule, fixed HERE — before any result is read: the
    // number may stay a single number only when the ensemble is degenerate,
    // i.e. every seed crashed within the interval and all ten minima agree.
    const bool publishable_as_single_number = (no_crash_at_hi == 0) && (spread == 0);

    // The control: seed 7 is the donor's, so its minimum must reproduce
    // task-067's 18. If it does not, nothing else in the table is proven —
    // the harness and the pinned number disagree.
    bool control_equals_18 = false;
    for (const SeedResult& r : results) {
        if (r.rng_seed == kControlRngSeed) {
            control_equals_18 = r.crashed_at_hi && r.min_budget == kControlExpectedMinBudget;
        }
    }
    EXPECT_TRUE(control_equals_18)
        << "control seed " << kControlRngSeed
        << " did not reproduce min_budget_crash=" << kControlExpectedMinBudget << " from task-067";

    if (no_crash_at_hi > 0) {
        std::cout << "SEED-SPREAD-NO-CRASH seeds=" << no_crash_names << '\n' << std::flush;
    }

    std::cout << "SEED-SPREAD-VERDICT: ADD-GATE-BUDGET-SEED-SPREAD: seeds=" << kRngSeeds.size()
              << ", seeds_preregistered=yes, min_budget_min=" << min_of_minima
              << ", min_budget_max=" << max_of_minima
              << ", min_budget_median=" << MedianText(minima) << ", spread_across_seeds=" << spread
              << ", seeds_no_crash_at_200=" << no_crash_at_hi
              << ", control_seed7_equals_18=" << (control_equals_18 ? "yes" : "no")
              << ", monotonic_verified_per_seed=" << monotonic_seeds << "/" << kRngSeeds.size()
              << ", publishable_as_single_number=" << (publishable_as_single_number ? "yes" : "no")
              << ", probes_total=" << probes_total
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
