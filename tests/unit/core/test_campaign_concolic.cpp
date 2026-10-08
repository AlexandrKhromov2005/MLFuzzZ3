#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "campaign.h"
#include "concolic.h"
#include "corpus.h"
#include "fake_runner.h"
#include "fuzz_input.h"
#include "ipc.pb.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "seed_scheduler.h"

// Campaign-loop concolic-trigger coverage WITHOUT a live exec-server
// (ADR 0036 §Тестирование) — the payoff of the D4-б1 Runner seam. A
// FakeRunner scripts run outcomes and exposes the canonical cov_xfield
// branch records, so the whole "mutation stalls -> concolic -> candidate
// through the funnel" path is driven deterministically in-process.
//
// Built only with concolic (FUZZER_BUILD_Z3): the stagnation trigger lives
// behind MLFUZZZ3_WITH_CONCOLIC, and a candidate is only produced when
// fuzzer::concolic is linked into fuzzer::core.

namespace mlfuzzz3::core {
namespace {

using testing::FakeRunner;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUlt = 2, kUgt = 4 };

// Seed whose cov_xfield branch log makes the solver produce a crash pair:
// x=0x20000000 @0, y=0x30000000 @4 (LE) — passes C1,C2,C3 but not C4.
std::vector<std::uint8_t> XfieldSeedBytes() {
    return {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
}

std::vector<coverage::BranchReader::Record> XfieldRecords() {
    return {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kUlt, 32, 0x20000000ULL, 0x30000000ULL},
        {3, kEq, 32, 0x50000000ULL, 0x00000005ULL},
    };
}

// A branch log whose operands appear nowhere in the seed: every record drops
// to both-const, nothing binds, and SolveForCandidate reports kNoBinding
// (ADR 0036 §4) — the reachable half of the old kNoBinding/kError lump.
std::vector<coverage::BranchReader::Record> UnbindableRecords() {
    return {
        {0, kEq, 32, 0x11111111ULL, 0x22222222ULL},
    };
}

// A branch log that DOES bind (both records' lhs is x = 0x20000000, findable
// at offset 0) but whose inverted target is unsatisfiable: both comparisons
// are true on the seed, so both survive as-taken, and inverting the last one
// asks for x <=u 0x0AAAAAAA while the first still demands x >u 0x11111111.
// Neither constant occurs in the seed, nor is either a sum of its fields
// (x+x=0x40000000, x+y=0x50000000, y+y=0x60000000), so both stay constants.
// SolveForCandidate reports kUnsat — the OTHER fruitless outcome, pinned at
// the unit level by tests/unit/concolic/test_concolic.cpp
// SolveOutcomeSeparatesUnsatFromNoBinding.
std::vector<coverage::BranchReader::Record> UnsatRecords() {
    return {
        {0, kUgt, 32, 0x20000000ULL, 0x11111111ULL},
        {1, kUgt, 32, 0x20000000ULL, 0x0AAAAAAAULL},
    };
}

// Which counter the campaign must charge an outcome to. The switch is
// deliberately exhaustive with NO `default:` label — src/core/campaign.cpp
// attributes kNoBinding through a bare `else`, so a newly added SolveOutcome
// would be filed there silently, reported as a reconstruction gap that never
// happened. That is exactly the lump ADR 0036 §4 broke apart, one level down.
// Debug builds with -Werror (CMakeLists.txt:32), so -Wswitch turns a new
// enumerator into a BUILD failure here, forcing whoever adds it to choose a
// counter rather than inherit `else`. The guard is the compile, not the
// EXPECTs in the test below.
enum class Attribution { kCandidate, kNoBinding, kUnsat, kTimeout, kError };

constexpr Attribution AttributionFor(concolic::SolveOutcome outcome) {
    switch (outcome) {
        case concolic::SolveOutcome::kCandidate:
            return Attribution::kCandidate;
        case concolic::SolveOutcome::kNoBinding:
            return Attribution::kNoBinding;
        case concolic::SolveOutcome::kUnsat:
            return Attribution::kUnsat;
        case concolic::SolveOutcome::kTimeout:
            return Attribution::kTimeout;
        default:  // kError и kWidthOverflow (ADR 0049): здесь недостижим
            return Attribution::kError;
    }
    return Attribution::kNoBinding;  // unreachable; -Wreturn-type wants a tail
}

// Delegates to a FakeRunner but sleeps before every run, so the seed-run
// timer (ADR 0039) accumulates a nonzero duration even though the fake
// itself is instantaneous. The delay makes accumulation observable; the
// assertions stay presence/accumulation-only (no absolute timings).
class SlowRunner final : public Runner {
   public:
    explicit SlowRunner(FakeRunner& inner) : inner_(inner) {}

    [[nodiscard]] FakeRunner::Reply Run(std::span<const std::uint8_t> input) override {
        std::this_thread::sleep_for(kRunDelay);
        return inner_.Run(input);
    }

    [[nodiscard]] std::vector<coverage::BranchReader::Record> LastBranchRecords() const override {
        return inner_.LastBranchRecords();
    }

   private:
    static constexpr std::chrono::milliseconds kRunDelay{2};
    FakeRunner& inner_;
};

// Picks corpus indices from a fixed script (then 0), to drive cumulative
// stagnation across interleaved seeds deterministically.
class ScriptedScheduler final : public SeedScheduler {
   public:
    explicit ScriptedScheduler(std::vector<std::size_t> picks) : picks_(std::move(picks)) {}
    std::size_t Choose(std::size_t corpus_size) override {
        const std::size_t pick = next_ < picks_.size() ? picks_[next_++] : 0;
        return pick < corpus_size ? pick : 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "scripted";
    }

   private:
    std::vector<std::size_t> picks_;
    std::size_t next_ = 0;
};

class CampaignConcolicTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_campaign_concolic" /
                (std::string(info->test_suite_name()) + "_" + info->name());
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);

        // Seed dir with a single file = the cov_xfield seed (corpus index 0).
        const std::filesystem::path seed_dir = base_ / "seeds";
        std::filesystem::create_directories(seed_dir);
        const std::vector<std::uint8_t> seed = XfieldSeedBytes();
        std::ofstream out(seed_dir / "xfield", std::ios::binary);
        out.write(reinterpret_cast<const char*>(seed.data()),
                  static_cast<std::streamsize>(seed.size()));
        out.close();

        auto corpus = Corpus::Create(base_ / "corpus");
        ASSERT_TRUE(corpus.has_value());
        corpus_.emplace(std::move(*corpus));
        ASSERT_TRUE(corpus_->Bootstrap(seed_dir).has_value());
        ASSERT_EQ(corpus_->size(), 1U);

        auto metrics = MetricsEmitter::Create(base_ / "metrics.jsonl", "test-run");
        ASSERT_TRUE(metrics.has_value());
        metrics_.emplace(std::move(*metrics));
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);
    }

    // Havoc-only (det disabled), small stagnation threshold for fast triggering.
    CampaignConfig Config(std::uint64_t max_iterations, std::uint32_t threshold) {
        return CampaignConfig{.max_iterations = max_iterations,
                              .metrics_interval = 0,
                              .rng_seed = 1,
                              .max_det_steps = 0,
                              .concolic_stagnation_threshold = threshold};
    }

    // As Config, plus the ADR 0038 rate-limit budget (minimum execs between
    // concolic calls). interval == 0 leaves the budget off (0036 behavior).
    CampaignConfig BudgetConfig(std::uint64_t max_iterations, std::uint32_t threshold,
                                std::uint64_t interval) {
        return CampaignConfig{.max_iterations = max_iterations,
                              .metrics_interval = 0,
                              .rng_seed = 1,
                              .max_det_steps = 0,
                              .concolic_stagnation_threshold = threshold,
                              .concolic_min_exec_interval = interval};
    }

    // As Config, plus the ADR 0038 adaptive-throttle switch. The static
    // budget is left at 0 on purpose: any rate-limiting observed under this
    // config can only come from the adaptive throttle.
    CampaignConfig AdaptiveConfig(std::uint64_t max_iterations, std::uint32_t threshold,
                                  bool adaptive) {
        return CampaignConfig{.max_iterations = max_iterations,
                              .metrics_interval = 0,
                              .rng_seed = 1,
                              .max_det_steps = 0,
                              .concolic_stagnation_threshold = threshold,
                              .concolic_min_exec_interval = 0,
                              .concolic_adaptive_throttle = adaptive};
    }

    // As Config, with the ADR 0036 experimental arm switch flipped. Only
    // concolic_enabled differs from Config(max_iterations, threshold), so a
    // difference in outcome is owed to the switch and to nothing else.
    CampaignConfig ArmConfig(std::uint64_t max_iterations, std::uint32_t threshold, bool armed) {
        return CampaignConfig{.max_iterations = max_iterations,
                              .metrics_interval = 0,
                              .rng_seed = 1,
                              .max_det_steps = 0,
                              .concolic_enabled = armed,
                              .concolic_stagnation_threshold = threshold};
    }

    std::filesystem::path base_;
    std::optional<Corpus> corpus_;
    std::optional<MetricsEmitter> metrics_;
    RandomScheduler scheduler_{1};
    mutation::ByteFlipMutator mutator_;
};

// After `threshold` fruitless havoc picks the loop runs a concolic step on
// the stuck seed; the cov_xfield records yield a candidate which, run with
// new coverage, is accepted into the corpus through the normal funnel.
TEST_F(CampaignConcolicTest, StagnationTriggersConcolicAndCandidateAccepted) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    // 3 fruitless havoc mutants -> stagnation 3; iter 4 triggers: seed run
    // (OK, exposes records) then candidate run (OK with new edges).
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(5, 3));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 1U);
    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_edges, 1U);
    EXPECT_EQ(stats.concolic_no_candidate, 0U);
    EXPECT_EQ(stats.concolic_no_candidate, stats.concolic_no_binding + stats.concolic_error);
    EXPECT_EQ(stats.concolic_crashes, 0U);
    EXPECT_EQ(corpus_->size(), 2U);  // bootstrap seed + accepted concolic candidate
}

// A concolic candidate that crashes is recorded as a crash finding (same
// funnel as a mutation crash) and counted in concolic_crashes.
TEST_F(CampaignConcolicTest, ConcolicCandidateCrashIsRecorded) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeStatus(ipc::v1::EXEC_STATUS_CRASH)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(5, 3));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 1U);
    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_crashes, 1U);
    EXPECT_GE(stats.crashes, 1U);  // funnel recorded the crash finding
}

// New coverage from a seed resets its cumulative counter, so the threshold
// is not reached and no concolic step runs.
TEST_F(CampaignConcolicTest, NewCoverageResetsStagnation) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    // iter1 no edges (stag 1), iter2 NEW edges (stag reset to 0), iter3/4 no
    // edges (stag 1,2) — never reaches threshold 3 within 4 iterations.
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(9), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(4, 3));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 0U);
}

// The per-seed counter is cumulative and keyed by seed: picking other seeds
// in between does NOT reset a seed's count. With seed 0 (cov_xfield) picked
// every other turn, its counter still reaches the threshold and triggers.
TEST_F(CampaignConcolicTest, StagnationIsCumulativeAcrossInterleavedSeeds) {
    // Add a second corpus seed (index 1); index 0 stays the cov_xfield seed.
    ASSERT_TRUE(
        corpus_->Add(mutation::FuzzInput(std::vector<std::uint8_t>(8, 0xCC)), 1).has_value());
    ASSERT_EQ(corpus_->size(), 2U);

    // Alternate seed 0 and seed 1; seed 0 is picked on turns 1,3,5 -> its
    // cumulative count hits 3 on turn 7 despite seed 1 interleaving.
    ScriptedScheduler scheduler({0, 1, 0, 1, 0, 1, 0});
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    // 6 fruitless havoc mutants (3 per seed), then seed-0 run + candidate.
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});

    CampaignLoop loop(runner, mutator_, scheduler, *corpus_, *metrics_, Config(8, 3));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 1U);
    EXPECT_EQ(stats.concolic_candidates, 1U);  // the cov_xfield seed (index 0) triggered
}

// ADR 0038 (а)+(д): with the budget on and a large interval, only the FIRST
// stagnation-triggered concolic call runs; every later trigger is blocked by
// the rate-limit (concolic_calls stays 1) and counted as a budget skip —
// concolic_calls and concolic_budget_skips are decoupled (the skip path never
// enters StepConcolic, where ++concolic_calls lives).
TEST_F(CampaignConcolicTest, BudgetBlocksRepeatConcolicAndCountsSkips) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());  // exhausted script -> MakeOk(0)

    // threshold 1 (re-stagnates in one havoc), interval 1000 (never reopens
    // within 20 execs): after the first call every later trigger is blocked.
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, BudgetConfig(20, 1, 1000));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 1U);         // only the first call ran
    EXPECT_GT(stats.concolic_budget_skips, 0U);  // later triggers were blocked
    EXPECT_EQ(stats.concolic_candidates, 1U);    // candidate only from the one real call
}

// ADR 0038 §2 (в): the budget never blocks the FIRST concolic call, even when
// fewer than `interval` execs have elapsed (the first_concolic_done_ guard).
// Without that guard, stats.execs - 0 >= interval would be false at the start
// and the first stagnating seed would be wrongly blocked.
TEST_F(CampaignConcolicTest, BudgetDoesNotBlockFirstCall) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());

    // interval 1000 >> the 3 execs the loop runs; threshold 1 triggers on
    // iteration 2 at execs == 1 < interval.
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, BudgetConfig(3, 1, 1000));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 1U);         // first call ran despite execs < interval
    EXPECT_EQ(stats.concolic_budget_skips, 0U);  // nothing blocked yet
}

// ADR 0038 §3 (б): a budget-blocked trigger does NOT reset stagnation (the
// reset runs only after a real StepConcolic). The stuck seed keeps its count
// across the block and fires again once the interval reopens — the budget
// DEFERS, it does not cancel. Repeated skips (the seed stays >= threshold
// throughout the block) plus a second call after the window confirm it; if the
// reset had moved before the gate, the seed would drop below threshold on the
// first block and the skips would not accumulate this densely.
TEST_F(CampaignConcolicTest, BudgetDefersConcolicButPreservesStagnation) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());

    // threshold 3, interval 10: first call ~exec 5, then a window of blocked
    // triggers (skips accumulate while stagnation stays >= 3), then a second
    // call once 10 execs have elapsed since the first.
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, BudgetConfig(40, 3, 10));
    const CampaignStats stats = loop.Run();

    EXPECT_GE(stats.concolic_calls, 2U);         // fired again after the interval reopened
    EXPECT_GE(stats.concolic_budget_skips, 3U);  // blocked repeatedly while staying >= threshold
}

// ADR 0038 (г): interval == 0 disables the budget -> identical to 0036.
// Concolic fires on every stagnation trigger and no skip is ever recorded.
TEST_F(CampaignConcolicTest, IntervalZeroMatchesPre0038Behavior) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, BudgetConfig(20, 1, 0));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_budget_skips, 0U);  // budget off -> never blocks
    EXPECT_GT(stats.concolic_calls, 1U);         // fires repeatedly (no rate limit)
}

// ADR 0039: the seed-run timer accumulates on a concolic call and the new
// field reaches the jsonl emit alongside the (now solve-only)
// concolic_time_ms_total. SlowRunner injects a constant delay per run, so
// the one seed run inside StepConcolic must meter > 0 ms; absolute values
// are deliberately not asserted (ADR 0039 §Тестирование).
TEST_F(CampaignConcolicTest, SeedRunTimeAccumulatesAndReachesJsonl) {
    FakeRunner inner;
    inner.set_branch_records(XfieldRecords());
    // 3 fruitless havoc mutants -> stagnation 3; iter 4 triggers: seed run
    // (OK, exposes records) then candidate run (OK with new edges).
    inner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                      FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});
    SlowRunner runner(inner);

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(5, 3));
    const CampaignStats stats = loop.Run();

    ASSERT_EQ(stats.concolic_calls, 1U);
    // The delayed seed run was metered into the dedicated field.
    EXPECT_GT(stats.concolic_seed_run_ms_total, 0U);

    // Both time fields are distinct keys in the final jsonl emit.
    std::ifstream in(base_ / "metrics.jsonl");
    std::string line;
    std::string last;
    while (std::getline(in, line)) {
        last = line;
    }
    ASSERT_FALSE(last.empty());
    EXPECT_NE(last.find("\"concolic_seed_run_ms_total\":"), std::string::npos);
    EXPECT_NE(last.find("\"concolic_time_ms_total\":"), std::string::npos);
}

// task-021: a concolic call whose records bind nothing is attributed to
// concolic_no_binding, NOT to concolic_error — the two used to be squashed
// into concolic_no_candidate, which made a storm of fruitless calls
// unreadable. Operands absent from the seed drop every record to
// both-const, so BuildSystem is not invertible (the same shape as
// tests/unit/concolic/test_concolic.cpp NoFindableOperandsYieldsNoCandidate).
TEST_F(CampaignConcolicTest, NoBindingRecordsCountAsNoBindingNotError) {
    FakeRunner runner;
    runner.set_branch_records(UnbindableRecords());
    // 3 fruitless havoc mutants -> stagnation 3; iter 4 triggers the concolic
    // step, whose seed run exposes records that bind nothing.
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(4, 3));
    const CampaignStats stats = loop.Run();

    ASSERT_EQ(stats.concolic_calls, 1U);
    EXPECT_EQ(stats.concolic_candidates, 0U);
    EXPECT_EQ(stats.concolic_no_binding, 1U);
    EXPECT_EQ(stats.concolic_error, 0U);  // kError is a solver defect, not this
    EXPECT_EQ(stats.concolic_unsat, 0U);
    EXPECT_EQ(stats.concolic_timeout, 0U);
    // Backward compatibility: the legacy field is exactly the sum, so already
    // collected metrics.jsonl runs and the scripts reading them keep working.
    EXPECT_EQ(stats.concolic_no_candidate, 1U);
    EXPECT_EQ(stats.concolic_no_candidate, stats.concolic_no_binding + stats.concolic_error);
}

// Negative (контур rule): a call that DID produce a candidate must leave both
// new counters silent — the split must not turn a productive call into a
// fruitless one. The sum invariant holds here too (0 == 0 + 0).
TEST_F(CampaignConcolicTest, CandidateCallLeavesBothFruitlessCountersSilent) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(5, 3));
    const CampaignStats stats = loop.Run();

    ASSERT_EQ(stats.concolic_calls, 1U);
    ASSERT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_no_binding, 0U);
    EXPECT_EQ(stats.concolic_error, 0U);
    EXPECT_EQ(stats.concolic_no_candidate, 0U);
    EXPECT_EQ(stats.concolic_no_candidate, stats.concolic_no_binding + stats.concolic_error);
}

// The split reaches the jsonl emit (not just the returned stats), and the
// legacy key is still written — this is what makes existing metrics
// consumers safe.
TEST_F(CampaignConcolicTest, FruitlessReasonSplitReachesJsonl) {
    FakeRunner runner;
    runner.set_branch_records(UnbindableRecords());

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(4, 3));
    const CampaignStats stats = loop.Run();
    ASSERT_EQ(stats.concolic_no_binding, 1U);

    std::ifstream in(base_ / "metrics.jsonl");
    std::string line;
    std::string last;
    while (std::getline(in, line)) {
        last = line;
    }
    ASSERT_FALSE(last.empty());
    EXPECT_NE(last.find("\"concolic_no_binding\":1"), std::string::npos);
    EXPECT_NE(last.find("\"concolic_error\":0"), std::string::npos);
    EXPECT_NE(last.find("\"concolic_no_candidate\":1"), std::string::npos);
}

// task-021, catch-all guard: a fruitless call whose system BOUND but came
// back unsatisfiable must be charged to concolic_unsat and must leave
// concolic_no_binding at zero. This is the negative test that the `else` in
// src/core/campaign.cpp is not a catch-all in practice: kNoBinding is the
// residual branch there, so an outcome that fell through would be reported
// as "we failed to bind the input" — sending a diagnosis after a
// reconstruction bug that does not exist. It matters operationally because
// the libtiff campaign is 99.5% unsat
// (docs/experiments/comparative-magma-libtiff/ANALYSIS.md): if unsat leaked
// into no_binding, that whole storm would read as our reconstruction gap.
TEST_F(CampaignConcolicTest, UnsatCallIsChargedToUnsatNotNoBinding) {
    FakeRunner runner;
    runner.set_branch_records(UnsatRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(4, 3));
    const CampaignStats stats = loop.Run();

    ASSERT_EQ(stats.concolic_calls, 1U);
    EXPECT_EQ(stats.concolic_candidates, 0U);
    EXPECT_EQ(stats.concolic_unsat, 1U);
    EXPECT_EQ(stats.concolic_no_binding, 0U);  // the residual branch must stay silent
    EXPECT_EQ(stats.concolic_error, 0U);
    EXPECT_EQ(stats.concolic_timeout, 0U);
    // unsat has its own counter and never fed the legacy lump.
    EXPECT_EQ(stats.concolic_no_candidate, 0U);
    EXPECT_EQ(stats.concolic_no_candidate, stats.concolic_no_binding + stats.concolic_error);
}

// The sum invariant on a scenario where the fruitless call is NOT a
// no-binding one — the existing task-021 tests only exercise it at 1 == 1 + 0
// and 0 == 0 + 0 with no_binding as the only live component.
TEST_F(CampaignConcolicTest, UnsatSplitReachesJsonlWithoutTouchingNoBinding) {
    FakeRunner runner;
    runner.set_branch_records(UnsatRecords());

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(4, 3));
    const CampaignStats stats = loop.Run();
    ASSERT_EQ(stats.concolic_unsat, 1U);

    std::ifstream in(base_ / "metrics.jsonl");
    std::string line;
    std::string last;
    while (std::getline(in, line)) {
        last = line;
    }
    ASSERT_FALSE(last.empty());
    EXPECT_NE(last.find("\"concolic_unsat\":1"), std::string::npos);
    EXPECT_NE(last.find("\"concolic_no_binding\":0"), std::string::npos);
    EXPECT_NE(last.find("\"concolic_error\":0"), std::string::npos);
    EXPECT_NE(last.find("\"concolic_no_candidate\":0"), std::string::npos);
}

// Every SolveOutcome has its own counter — no two share one, which is the
// property task-021 restored. The load-bearing half of this test is the
// exhaustive switch in AttributionFor above: it fails to COMPILE under
// -Werror when a SolveOutcome enumerator is added without deciding where it
// is charged. The assertions below only pin that today's five map apart.
TEST(CampaignConcolicAttribution, EachSolveOutcomeHasItsOwnCounter) {
    using concolic::SolveOutcome;

    EXPECT_EQ(AttributionFor(SolveOutcome::kCandidate), Attribution::kCandidate);
    EXPECT_EQ(AttributionFor(SolveOutcome::kNoBinding), Attribution::kNoBinding);
    EXPECT_EQ(AttributionFor(SolveOutcome::kUnsat), Attribution::kUnsat);
    EXPECT_EQ(AttributionFor(SolveOutcome::kTimeout), Attribution::kTimeout);
    EXPECT_EQ(AttributionFor(SolveOutcome::kError), Attribution::kError);

    // The specific collapse ADR 0036 §4 undid: these two were one counter.
    EXPECT_NE(AttributionFor(SolveOutcome::kNoBinding), AttributionFor(SolveOutcome::kError));
    // And the residual branch must not absorb the solver's own verdicts.
    EXPECT_NE(AttributionFor(SolveOutcome::kNoBinding), AttributionFor(SolveOutcome::kUnsat));
    EXPECT_NE(AttributionFor(SolveOutcome::kNoBinding), AttributionFor(SolveOutcome::kTimeout));
}

// ADR 0038 (adaptive extension) — POSITIVE, at the call site.
// On a target whose inverted systems are always unsatisfiable, the throttle
// engages after enough evidence and the gate in TakeConcolicTurn
// (src/core/campaign.cpp) then blocks every further trigger, even though the
// STATIC budget is off (interval 0). That is the cost reclaimed: the loop
// stops paying for solves this target never converts.
TEST_F(CampaignConcolicTest, AdaptiveThrottleStopsUnsatDominatedTarget) {
    FakeRunner runner;
    runner.set_branch_records(UnsatRecords());  // exhausted script -> MakeOk(0)

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_,
                      AdaptiveConfig(200, 1, /*adaptive=*/true));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_throttle_engagements, 1U);
    EXPECT_GT(stats.concolic_throttle_skips, 0U);           // the throttle, not the static budget
    EXPECT_EQ(stats.concolic_unsat, stats.concolic_calls);  // every call was unsat
    // It stopped the storm: without the throttle the same 200 iterations keep
    // calling concolic (the control test below).
    EXPECT_LT(stats.concolic_calls, 25U);
}

// The control for the test above: with the adaptive throttle switched off and
// everything else identical, the same unsat-dominated target keeps calling
// concolic and records no skip at all. Without this pair, "few calls" could be
// an artifact of the loop rather than the throttle.
TEST_F(CampaignConcolicTest, AdaptiveThrottleOffLeavesUnsatStormRunning) {
    FakeRunner runner;
    runner.set_branch_records(UnsatRecords());

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_,
                      AdaptiveConfig(200, 1, /*adaptive=*/false));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_throttle_skips, 0U);
    EXPECT_EQ(stats.concolic_budget_skips, 0U);
    EXPECT_GT(stats.concolic_calls, 50U);  // the storm ADR 0038 describes
}

// ADR 0038 (adaptive extension) — NEGATIVE, the guard this task exists for.
// On a target that keeps producing candidates the throttle must never engage
// and must never block a call: the cost-cut may not be paid for with solves
// that were actually converting. Same loop, same iterations, throttle on.
TEST_F(CampaignConcolicTest, AdaptiveThrottleStaysSilentOnSatTarget) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());  // solvable -> candidates

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_,
                      AdaptiveConfig(200, 1, /*adaptive=*/true));
    const CampaignStats stats = loop.Run();

    ASSERT_GT(stats.concolic_candidates, 0U);            // the target really is sat-yielding
    EXPECT_EQ(stats.concolic_throttle_engagements, 0U);  // never engaged
    EXPECT_EQ(stats.concolic_throttle_skips, 0U);        // never blocked a call
    EXPECT_EQ(stats.concolic_budget_skips, 0U);          // static budget is off too
    EXPECT_GT(stats.concolic_calls, 50U);                // the sat target keeps its full rate
}

}  // namespace

// ADR 0036 experimental switch (CLI --no-concolic), both arms of the same
// binary on the SAME scripted run. Observable value is the solver-call
// counter, not the absence of a crash: armed the loop charges calls,
// disarmed it charges exactly zero.
TEST_F(CampaignConcolicTest, ArmSwitchOffMakesSolverCallsZero) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, ArmConfig(5, 3, false));
    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.concolic_calls, 0U);
    EXPECT_EQ(stats.concolic_candidates, 0U);
    // Not a rate-limit skip either: the disarmed arm never enters the budget.
    EXPECT_EQ(stats.concolic_budget_skips, 0U);
    // Nothing in the corpus came from the arm: the fifth scripted run is a
    // havoc mutant with new edges, so the entry admitted here is the
    // mutator's, and concolic_edges stays 0.
    EXPECT_EQ(stats.concolic_edges, 0U);
}

// The same scripted run with the switch left at its default value: the arm
// fires. Read together with the test above this is the "default unchanged"
// evidence — ArmConfig(..., true) is what Config() already produces.
TEST_F(CampaignConcolicTest, ArmSwitchOnKeepsSolverCallsPositive) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, ArmConfig(5, 3, true));
    const CampaignStats stats = loop.Run();

    EXPECT_GT(stats.concolic_calls, 0U);
}

// The default of the campaign config itself (no argument, no CLI): armed.
TEST(CampaignConcolicArmDefault, ConcolicEnabledDefaultsToTrue) {
    EXPECT_TRUE(CampaignConfig{}.concolic_enabled);
}

// ADR 0049: the campaign charges each concolic call to a build and a solve
// accumulator in microseconds. Both sit inside the ADR 0039 solve timer: for
// a call of wall time w, build + solve <= w < (floor_ms(w) + 1) * 1000, so
// the sum stays under (concolic_time_ms_total + concolic_calls) * 1000.
TEST_F(CampaignConcolicTest, CallCostSplitNestsInsideSolveTimer) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0), FakeRunner::MakeOk(5)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(5, 3));
    const CampaignStats stats = loop.Run();

    ASSERT_EQ(stats.concolic_calls, 1U);
    ASSERT_EQ(stats.concolic_candidates, 1U);
    EXPECT_GT(stats.concolic_solve_us_total, 0U);
    EXPECT_LT(stats.concolic_build_us_total + stats.concolic_solve_us_total,
              (stats.concolic_time_ms_total + stats.concolic_calls) * 1000U);
}

// A call whose records bind nothing never reaches the solver: the solve
// accumulator stays at zero even though the call was made and timed.
TEST_F(CampaignConcolicTest, NoBindingCallChargesNothingToSolve) {
    FakeRunner runner;
    runner.set_branch_records(UnbindableRecords());
    runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                       FakeRunner::MakeOk(0)});

    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(4, 3));
    const CampaignStats stats = loop.Run();

    ASSERT_EQ(stats.concolic_calls, 1U);
    ASSERT_EQ(stats.concolic_no_binding, 1U);
    EXPECT_EQ(stats.concolic_solve_us_total, 0U);
    EXPECT_LT(stats.concolic_build_us_total,
              (stats.concolic_time_ms_total + stats.concolic_calls) * 1000U);
}

}  // namespace mlfuzzz3::core
