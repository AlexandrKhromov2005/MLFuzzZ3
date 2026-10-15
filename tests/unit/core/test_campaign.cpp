#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

#include "campaign.h"
#include "corpus.h"
#include "deterministic_stage.h"
#include "ipc.pb.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "rng.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"

namespace mlfuzzz3::core {
namespace {

using Reply = tl::expected<ipc::v1::RunResponse, ipc::IpcError>;

Reply Ok(std::uint32_t new_edges) {
    ipc::v1::RunResponse resp;
    resp.set_status(ipc::v1::EXEC_STATUS_OK);
    resp.mutable_edge_result()->set_new_edges(new_edges);
    return resp;
}

Reply WithStatus(ipc::v1::ExecStatus status) {
    ipc::v1::RunResponse resp;
    resp.set_status(status);
    return resp;
}

Reply Transport() {
    return tl::unexpected(ipc::IpcError::kTransportError);
}

// ScriptedRunner replays a fixed list of replies; once exhausted it
// returns OK with no new coverage so a loop bounded by max_iterations
// can run past the script.
class ScriptedRunner final : public Runner {
   public:
    explicit ScriptedRunner(std::vector<Reply> script) : script_(std::move(script)) {}

    Reply Run(std::span<const std::uint8_t> /*input*/) override {
        if (next_ < script_.size()) {
            return script_[next_++];
        }
        return Ok(0);
    }

    [[nodiscard]] std::vector<coverage::BranchReader::Record> LastBranchRecords() const override {
        return {};
    }

   private:
    std::vector<Reply> script_;
    std::size_t next_ = 0;
};

// RecordingRunner captures every input byte-string it is handed and
// replies from an optional FIFO script, then OK with no new coverage. Used to
// assert that the deterministic stage produces a fixed input sequence
// independent of the RNG seed, and what the seed pass hands the target.
class RecordingRunner final : public Runner {
   public:
    RecordingRunner() = default;
    explicit RecordingRunner(std::vector<Reply> script) : script_(std::move(script)) {}

    Reply Run(std::span<const std::uint8_t> input) override {
        recorded_.emplace_back(input.begin(), input.end());
        if (next_ < script_.size()) {
            return script_[next_++];
        }
        return Ok(0);
    }
    [[nodiscard]] std::vector<coverage::BranchReader::Record> LastBranchRecords() const override {
        return {};
    }
    [[nodiscard]] const std::vector<std::vector<std::uint8_t>>& inputs() const {
        return recorded_;
    }

   private:
    std::vector<std::vector<std::uint8_t>> recorded_;
    std::vector<Reply> script_;
    std::size_t next_ = 0;
};

std::size_t CountFiles(const std::filesystem::path& dir) {
    std::error_code ec;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (entry.is_regular_file()) {
            ++count;
        }
    }
    return count;
}

class CampaignTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_campaign_test" /
                (std::string(info->test_suite_name()) + "_" + info->name());
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);

        auto corpus = Corpus::Create(base_);
        ASSERT_TRUE(corpus.has_value());
        corpus_.emplace(std::move(*corpus));
        ASSERT_TRUE(corpus_->Bootstrap(std::filesystem::path{}).has_value());
        ASSERT_EQ(corpus_->size(), 1U);

        auto metrics = MetricsEmitter::Create(base_ / "metrics.jsonl", "test-run");
        ASSERT_TRUE(metrics.has_value());
        metrics_.emplace(std::move(*metrics));
    }
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);
    }

    CampaignConfig Config(std::uint64_t max_iterations) {
        return CampaignConfig{.max_iterations = max_iterations,
                              .max_seconds = 0.0,
                              .metrics_interval = 10,
                              .rng_seed = 1234};
    }

    std::filesystem::path base_;
    std::optional<Corpus> corpus_;
    std::optional<MetricsEmitter> metrics_;
    RandomScheduler scheduler_{1234};
    mutation::ByteFlipMutator mutator_;
};

// Legacy trace: discovering a seed must finish the current deterministic
// cursor, sweep the appended seed, then consume the untouched havoc RNG.
TEST_F(CampaignTest, LegacyTracePreservesAdmissionDetFirstAndHavocRng) {
    RecordingRunner runner({Ok(3)});
    CampaignConfig cfg = Config(8);
    cfg.max_det_steps = 2;
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, cfg);
    const CampaignStats stats = loop.Run();
    const std::vector<std::vector<std::uint8_t>> expected{{1},  {2},   {0},   {3},
                                                          {13}, {242}, {242}, {241}};
    EXPECT_EQ(runner.inputs(), expected);
    EXPECT_EQ(stats.execs, 8U);
    EXPECT_EQ(stats.det_execs, 4U);
    EXPECT_EQ(stats.havoc_execs, 4U);
    EXPECT_EQ(stats.accepted, 1U);
    ASSERT_EQ(corpus_->size(), 2U);
    EXPECT_EQ(corpus_->at(0).det.cursor, 2U);
    EXPECT_EQ(corpus_->at(1).det.cursor, 2U);
}

TEST_F(CampaignTest, AcceptsInputsWithNewEdges) {
    ScriptedRunner runner({Ok(3), Ok(0), Ok(5)});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(3));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 3U);
    EXPECT_EQ(stats.accepted, 2U);
    EXPECT_EQ(stats.edges, 8U);
    EXPECT_FALSE(stats.aborted);
    EXPECT_EQ(corpus_->size(), 3U);  // 1 bootstrap + 2 accepted
}

TEST_F(CampaignTest, ContinuesAndPersistsOnCrash) {
    ScriptedRunner runner(
        {WithStatus(ipc::v1::EXEC_STATUS_CRASH), Ok(0), WithStatus(ipc::v1::EXEC_STATUS_CRASH)});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(3));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 3U);
    EXPECT_EQ(stats.crashes, 2U);
    EXPECT_FALSE(stats.aborted);  // the loop does not crash itself on a finding
    EXPECT_GE(CountFiles(corpus_->crashes_dir()), 1U);
    EXPECT_EQ(stats.accepted, 0U);
}

TEST_F(CampaignTest, ContinuesAndPersistsOnHang) {
    ScriptedRunner runner(
        {WithStatus(ipc::v1::EXEC_STATUS_HANG), WithStatus(ipc::v1::EXEC_STATUS_HANG)});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(2));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.hangs, 2U);
    EXPECT_FALSE(stats.aborted);
    EXPECT_GE(CountFiles(corpus_->hangs_dir()), 1U);
}

TEST_F(CampaignTest, IpcErrorIsNotAFindingAndIsRecoverable) {
    ScriptedRunner runner({WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR), Ok(7),
                           WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR)});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(3));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 3U);
    EXPECT_EQ(stats.ipc_errors, 2U);
    EXPECT_EQ(stats.accepted, 1U);  // the interleaved OK(7) is accepted
    EXPECT_FALSE(stats.aborted);    // errors were not consecutive
    EXPECT_EQ(CountFiles(corpus_->crashes_dir()), 0U);
    EXPECT_EQ(CountFiles(corpus_->hangs_dir()), 0U);
}

TEST_F(CampaignTest, AbortsOnSustainedIpcErrors) {
    ScriptedRunner runner(
        {WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR), WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR),
         WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR), WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR),
         WithStatus(ipc::v1::EXEC_STATUS_IPC_ERROR)});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(100));

    const CampaignStats stats = loop.Run();

    EXPECT_TRUE(stats.aborted);
    EXPECT_EQ(stats.execs, 5U);  // stops at the 5th consecutive infrastructure error
    EXPECT_EQ(stats.ipc_errors, 5U);
}

TEST_F(CampaignTest, AbortsOnSustainedTransportErrors) {
    ScriptedRunner runner({Transport(), Transport(), Transport(), Transport(), Transport()});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(100));

    const CampaignStats stats = loop.Run();

    EXPECT_TRUE(stats.aborted);
    EXPECT_EQ(stats.execs, 5U);
    EXPECT_EQ(stats.ipc_errors, 5U);
}

// --- Deterministic stage (ADR 0031) ---------------------------------------

TEST_F(CampaignTest, DeterministicStageTransitionsToHavocAtSweepLength) {
    // Empty script ⇒ always Ok(0): nothing is accepted, so the corpus stays
    // at the single 1-byte bootstrap seed, whose sweep is exactly 100 steps.
    ScriptedRunner runner({});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(150));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 150U);
    EXPECT_EQ(stats.det_execs, 100U);   // the 1-byte seed has exactly 100 det steps
    EXPECT_EQ(stats.havoc_execs, 50U);  // the remainder falls through to havoc
    EXPECT_EQ(corpus_->size(), 1U);
    EXPECT_EQ(corpus_->at(0).det.phase, SeedPhase::kHavoc);
    EXPECT_EQ(corpus_->at(0).det.cursor, 100U);
}

TEST_F(CampaignTest, DeterministicStageHonorsStepCap) {
    ScriptedRunner runner({});
    CampaignConfig cfg = Config(10);
    cfg.max_det_steps = 3;  // cap well below the 100-step sweep
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, cfg);

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 10U);
    EXPECT_EQ(stats.det_execs, 3U);  // capped early
    EXPECT_EQ(stats.havoc_execs, 7U);
    EXPECT_EQ(corpus_->at(0).det.phase, SeedPhase::kHavoc);
    EXPECT_EQ(corpus_->at(0).det.cursor, 3U);
}

TEST_F(CampaignTest, AcceptedSeedsEnterDeterministicPhase) {
    ScriptedRunner runner({Ok(5)});  // the first exec discovers coverage
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(1));

    const CampaignStats stats = loop.Run();

    ASSERT_EQ(corpus_->size(), 2U);
    EXPECT_EQ(stats.accepted, 1U);
    EXPECT_EQ(corpus_->at(1).det.phase, SeedPhase::kDeterministic);
    EXPECT_EQ(corpus_->at(1).det.cursor, 0U);
}

TEST_F(CampaignTest, PhaseCountersAccountForEveryExec) {
    ScriptedRunner runner({});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(120));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.det_execs + stats.havoc_execs, stats.execs);
    EXPECT_EQ(stats.det_execs, 100U);
    EXPECT_EQ(stats.havoc_execs, 20U);  // 120 execs, 100 of them deterministic
}

TEST_F(CampaignTest, DeterministicPhaseIsSeedIndependent) {
    // The deterministic stage never consults the RNG, so two campaigns with
    // different seeds must drive an identical input sequence while purely in
    // the deterministic phase (50 < the 100-step sweep of the 1-byte seed).
    auto run_det_only = [this](std::uint64_t seed) {
        const std::filesystem::path dir = base_ / ("rng_" + std::to_string(seed));
        auto corpus = Corpus::Create(dir);
        EXPECT_TRUE(corpus.has_value());
        EXPECT_TRUE(corpus->Bootstrap(std::filesystem::path{}).has_value());
        auto metrics = MetricsEmitter::Create(dir / "metrics.jsonl", "rng-test");
        EXPECT_TRUE(metrics.has_value());

        RecordingRunner runner;
        RandomScheduler scheduler{seed};
        CampaignConfig cfg = Config(50);
        cfg.rng_seed = seed;
        CampaignLoop loop(runner, mutator_, scheduler, *corpus, *metrics, cfg);
        loop.Run();
        return runner.inputs();
    };

    const auto first = run_det_only(1);
    const auto second = run_det_only(999);
    EXPECT_EQ(first.size(), 50U);
    EXPECT_EQ(first, second);
}

TEST_F(CampaignTest, MaxDetStepsZeroDisablesDeterministicStage) {
    RecordingRunner runner;
    CampaignConfig cfg = Config(20);
    cfg.max_det_steps = 0;  // ADR 0032: 0 ⇒ deterministic stage fully off
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, cfg);

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 20U);
    EXPECT_EQ(stats.det_execs, 0U);  // no deterministic exec at all
    EXPECT_EQ(stats.havoc_execs, 20U);
    EXPECT_EQ(corpus_->at(0).det.cursor, 0U);  // bootstrap seed never advanced

    // The recorded input sequence must equal a plain havoc-only loop:
    // ByteFlipMutator over the single 1-byte bootstrap seed, same RNG seed.
    ASSERT_EQ(runner.inputs().size(), 20U);
    auto ref_rng = mutation::make_rng(1234);
    const mutation::FuzzInput seed_input{std::vector<std::uint8_t>{0x00}};
    for (std::size_t i = 0; i < runner.inputs().size(); ++i) {
        const mutation::FuzzInput out = mutator_.mutate(seed_input, ref_rng);
        const std::vector<std::uint8_t> expected(out.data(), out.data() + out.size());
        EXPECT_EQ(runner.inputs()[i], expected) << "exec " << i;
    }
}

// --run-seeds-first (task-212). The fixture corpus holds the 1-byte
// bootstrap seed; two more entries make three seeds of distinct lengths. The
// deterministic stage preserves length, so none of its steps on one seed can
// equal another; the budgets below never leave that stage (havoc_execs == 0).
class SeedPassTest : public CampaignTest {
   protected:
    void SetUp() override {
        CampaignTest::SetUp();
        ASSERT_TRUE(corpus_->Add(mutation::FuzzInput{std::vector<std::uint8_t>{'A', 'B', 'C'}}, 1)
                        .has_value());
        ASSERT_TRUE(
            corpus_->Add(mutation::FuzzInput{std::vector<std::uint8_t>{'x', 'y'}}, 1).has_value());
        ASSERT_EQ(corpus_->size(), 3U);
        for (std::size_t i = 0; i < corpus_->size(); ++i) {
            const mutation::FuzzInput& in = corpus_->at(i).input;
            seeds_.emplace_back(in.data(), in.data() + in.size());
        }
    }
    CampaignConfig SeedPassConfig(std::uint64_t max_iterations, bool run_seeds_first) {
        CampaignConfig cfg = Config(max_iterations);
        cfg.run_seeds_first = run_seeds_first;
        return cfg;
    }
    std::vector<std::vector<std::uint8_t>> seeds_;
};

TEST_F(SeedPassTest, BudgetEqualToSeedCountRunsExactlyTheSeedsInOrder) {
    RecordingRunner runner;
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, SeedPassConfig(3, true));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 3U);
    EXPECT_EQ(stats.det_execs, 0U);  // no mutator stage reached
    EXPECT_EQ(stats.havoc_execs, 0U);
    EXPECT_EQ(runner.inputs(), seeds_);  // byte for byte, corpus order
}

TEST_F(SeedPassTest, MutationsFollowTheSeedPass) {
    RecordingRunner runner;
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, SeedPassConfig(8, true));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 8U);
    EXPECT_EQ(stats.det_execs, 5U);  // seed runs are in neither phase
    EXPECT_EQ(stats.havoc_execs, 0U);
    ASSERT_EQ(runner.inputs().size(), 8U);
    const std::vector<std::vector<std::uint8_t>> head(runner.inputs().begin(),
                                                      runner.inputs().begin() + 3);
    EXPECT_EQ(head, seeds_);
    // The deterministic stage then starts at seed 0, cursor 0, as without the pass.
    const mutation::FuzzInput first_det =
        mutation::DeterministicStage::apply(corpus_->at(0).input, 0);
    EXPECT_EQ(runner.inputs()[3],
              std::vector<std::uint8_t>(first_det.data(), first_det.data() + first_det.size()));
    for (std::size_t i = 3; i < runner.inputs().size(); ++i) {
        for (const auto& seed : seeds_) {
            EXPECT_NE(runner.inputs()[i], seed) << "exec " << i;
        }
    }
}

TEST_F(SeedPassTest, OffByDefaultAndNoRunEqualsASeed) {
    EXPECT_FALSE(CampaignConfig{}.run_seeds_first);
    RecordingRunner runner;
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(3));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 3U);
    EXPECT_EQ(stats.det_execs, 3U);
    EXPECT_EQ(stats.havoc_execs, 0U);
    ASSERT_EQ(runner.inputs().size(), 3U);
    for (const auto& input : runner.inputs()) {
        for (const auto& seed : seeds_) {
            EXPECT_NE(input, seed);
        }
    }
}

TEST_F(SeedPassTest, BudgetBelowSeedCountStopsInsideThePass) {
    RecordingRunner runner;
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, SeedPassConfig(2, true));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.execs, 2U);
    const std::vector<std::vector<std::uint8_t>> first_two(seeds_.begin(), seeds_.begin() + 2);
    EXPECT_EQ(runner.inputs(), first_two);
}

TEST_F(SeedPassTest, SeedRunsGoThroughTheResultFunnelWithoutReaddingSeeds) {
    RecordingRunner runner({Ok(5), WithStatus(ipc::v1::EXEC_STATUS_CRASH), Ok(3)});
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, SeedPassConfig(3, true));

    const CampaignStats stats = loop.Run();

    EXPECT_EQ(stats.edges, 8U);     // new coverage is counted...
    EXPECT_EQ(stats.accepted, 0U);  // ...but a seed is not appended again
    EXPECT_EQ(corpus_->size(), 3U);
    EXPECT_EQ(stats.crashes, 1U);
    EXPECT_EQ(CountFiles(base_ / "crashes"), 1U);
}

TEST_F(SeedPassTest, SustainedInfraErrorsAbortBeforeMutations) {
    std::vector<Reply> script(5, Transport());
    RecordingRunner runner(std::move(script));
    ASSERT_TRUE(corpus_->Add(mutation::FuzzInput{std::vector<std::uint8_t>{1, 2, 3, 4}}, 1));
    ASSERT_TRUE(corpus_->Add(mutation::FuzzInput{std::vector<std::uint8_t>{5, 6, 7, 8, 9}}, 1));
    CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, SeedPassConfig(50, true));

    const CampaignStats stats = loop.Run();

    EXPECT_TRUE(stats.aborted);
    EXPECT_EQ(stats.execs, 5U);
    EXPECT_EQ(stats.det_execs + stats.havoc_execs, 0U);
}

}  // namespace
}  // namespace mlfuzzz3::core
