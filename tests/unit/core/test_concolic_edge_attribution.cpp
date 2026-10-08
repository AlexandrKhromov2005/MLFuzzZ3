#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include "campaign.h"
#include "concolic.h"
#include "corpus.h"
#include "fake_runner.h"
#include "ipc.pb.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "seed_scheduler.h"

// task-030 / ADR 0036 §4: WHERE the edges of a concolic candidate are
// attributed. The OK and CRASH branches of StepConcolic
// (src/core/campaign.cpp:226 vs :233) are mutually exclusive, and
// ++stats.concolic_edges (:231) sits inside the OK branch only. This file
// pins the OBSERVED behaviour of the four cells of the pair
// (candidate response status, new_edges), including the cell that the
// stock FakeRunner builders cannot express — CRASH carrying a non-empty
// edge_result — which is assembled by hand here.
//
// No production code is touched: the accounting rule is ADR 0036 encoding
// and an owner decision. This is characterization, not a fix.

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

// The cell the stock builders cannot express: FakeRunner::MakeStatus leaves
// edge_result unset (tests/unit/core/fake_runner.h:65-69) and MakeOk hard-codes
// EXEC_STATUS_OK (:58-63). Built here by the same shape as MakeOk, with the
// status replaced. The real exec-server does emit this shape: it fills
// EdgeResult by coverage presence, not by status
// (exec-server/cmd/exec-server/main.go:268-286, and the coverage read in
// exec-server/internal/worker/pool.go:389-413 sits AFTER the exit/signal
// switch, so a signal-killed run still carries it).
FakeRunner::Reply MakeCrashWithEdges(std::uint32_t new_edges) {
    ipc::v1::RunResponse resp;
    resp.set_status(ipc::v1::EXEC_STATUS_CRASH);
    resp.mutable_edge_result()->set_new_edges(new_edges);
    return resp;
}

// Same shape for EXEC_STATUS_HANG (proto/ipc.proto:20-21). The status space of
// a candidate answer is OK / CRASH / HANG / IPC_ERROR / UNSPECIFIED, and only
// the first two are named in StepConcolic (src/core/campaign.cpp:226 and :233),
// so HANG is a third attribution cell, not a variant of the two above.
FakeRunner::Reply MakeHangWithEdges(std::uint32_t new_edges) {
    ipc::v1::RunResponse resp;
    resp.set_status(ipc::v1::EXEC_STATUS_HANG);
    resp.mutable_edge_result()->set_new_edges(new_edges);
    return resp;
}

// Same harness as tests/unit/core/test_campaign_concolic.cpp:150-224: a single
// bootstrap seed, havoc-only, small stagnation threshold. The five scripted
// replies are consumed as: three havoc runs, the StepConcolic seed re-run, and
// finally the CANDIDATE run — the last entry is the cell under test.
class ConcolicEdgeAttributionTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_concolic_edge_attr" /
                (std::string(info->test_suite_name()) + "_" + info->name());
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);

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
        ASSERT_EQ(corpus_->size(), 1U);  // corpus size BEFORE the step

        auto metrics = MetricsEmitter::Create(base_ / "metrics.jsonl", "test-run");
        ASSERT_TRUE(metrics.has_value());
        metrics_.emplace(std::move(*metrics));
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);
    }

    CampaignConfig Config(std::uint64_t max_iterations, std::uint32_t threshold) {
        return CampaignConfig{.max_iterations = max_iterations,
                              .metrics_interval = 0,
                              .rng_seed = 1,
                              .max_det_steps = 0,
                              .concolic_stagnation_threshold = threshold};
    }

    // Runs the campaign with `candidate_reply` as the answer to the concolic
    // candidate; every earlier run is a fruitless OK.
    CampaignStats RunWithCandidateReply(FakeRunner::Reply candidate_reply) {
        FakeRunner runner;
        runner.set_branch_records(XfieldRecords());
        runner.set_script({FakeRunner::MakeOk(0), FakeRunner::MakeOk(0), FakeRunner::MakeOk(0),
                           FakeRunner::MakeOk(0), std::move(candidate_reply)});
        CampaignLoop loop(runner, mutator_, scheduler_, *corpus_, *metrics_, Config(5, 3));
        return loop.Run();
    }

    std::filesystem::path base_;
    std::optional<Corpus> corpus_;
    std::optional<MetricsEmitter> metrics_;
    RandomScheduler scheduler_{1};
    mutation::ByteFlipMutator mutator_;
};

// Cell (OK, new_edges > 0) — the control. Mirrors the reference assertion
// tests/unit/core/test_campaign_concolic.cpp:242 and is repeated here so the
// three other cells are read against a live positive in the same fixture.
TEST_F(ConcolicEdgeAttributionTest, OkWithNewEdgesCountsEverywhere) {
    const CampaignStats stats = RunWithCandidateReply(FakeRunner::MakeOk(5));

    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_edges, 1U);
    EXPECT_EQ(stats.concolic_crashes, 0U);
    EXPECT_EQ(stats.edges, 5U);
    EXPECT_EQ(stats.crashes, 0U);
    EXPECT_EQ(corpus_->size(), 2U);  // GREW: bootstrap seed + accepted candidate
}

// Cell (OK, new_edges == 0): the candidate ran clean but added nothing. The
// zero here is a fact about the candidate, not about attribution.
TEST_F(ConcolicEdgeAttributionTest, OkWithoutNewEdgesCountsNowhere) {
    const CampaignStats stats = RunWithCandidateReply(FakeRunner::MakeOk(0));

    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_edges, 0U);
    EXPECT_EQ(stats.concolic_crashes, 0U);
    EXPECT_EQ(stats.edges, 0U);
    EXPECT_EQ(stats.crashes, 0U);
    EXPECT_EQ(corpus_->size(), 1U);  // NOT grown
}

// THE CELL OF task-030: a CRASH response carrying new_edges > 0. The edges are
// dropped by BOTH accountants — StepConcolic never reaches :231 outside the OK
// branch, and HandleResponse (src/core/campaign.cpp:282-287) reads new_edges
// only on EXEC_STATUS_OK, so RecordCoverage (:59-65) never runs and stats.edges
// stays 0. The input is preserved as a crash finding, not as corpus coverage.
TEST_F(ConcolicEdgeAttributionTest, CrashWithNewEdgesLosesThoseEdgesEverywhere) {
    const CampaignStats stats = RunWithCandidateReply(MakeCrashWithEdges(5));

    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_edges, 0U);  // NOT 1, though new_edges == 5
    EXPECT_EQ(stats.concolic_crashes, 1U);
    EXPECT_EQ(stats.edges, 0U);  // the 5 edges are attributed NOWHERE
    EXPECT_EQ(stats.crashes, 1U);
    EXPECT_EQ(stats.accepted, 0U);
    EXPECT_EQ(corpus_->size(), 1U);  // NOT grown: crash inputs go to the crash dir
}

// Cell (CRASH, no edge_result) — the shape the stock builder produces. Same
// counters as the cell above: the presence or absence of edge_result makes no
// observable difference once the status is CRASH.
TEST_F(ConcolicEdgeAttributionTest, CrashWithoutEdgeResultMatchesCrashWithEdges) {
    const CampaignStats stats =
        RunWithCandidateReply(FakeRunner::MakeStatus(ipc::v1::EXEC_STATUS_CRASH));

    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_edges, 0U);
    EXPECT_EQ(stats.concolic_crashes, 1U);
    EXPECT_EQ(stats.edges, 0U);
    EXPECT_EQ(stats.crashes, 1U);
    EXPECT_EQ(stats.accepted, 0U);
    EXPECT_EQ(corpus_->size(), 1U);  // NOT grown
}

// Cell (HANG, edge_result with new_edges > 0) — the residual the four cells
// above do not cover. StepConcolic names only OK (src/core/campaign.cpp:226)
// and CRASH (:233), so a hung candidate increments NEITHER concolic_edges NOR
// concolic_crashes: it is invisible to both concolic accountants at once, while
// stats.hangs (:90-95) does see it. This matters for reading a campaign's
// numbers: `concolic_candidates - concolic_crashes` is NOT the count of
// "OK candidates that added nothing".
TEST_F(ConcolicEdgeAttributionTest, HangWithNewEdgesIsInvisibleToBothConcolicCounters) {
    const CampaignStats stats = RunWithCandidateReply(MakeHangWithEdges(5));

    EXPECT_EQ(stats.concolic_candidates, 1U);
    EXPECT_EQ(stats.concolic_edges, 0U);    // not OK -> :231 unreachable
    EXPECT_EQ(stats.concolic_crashes, 0U);  // not CRASH -> :233 unreachable either
    EXPECT_EQ(stats.edges, 0U);             // the 5 edges are attributed NOWHERE
    EXPECT_EQ(stats.crashes, 0U);
    EXPECT_EQ(stats.hangs, 1U);  // the only counter that saw this candidate
    EXPECT_EQ(stats.accepted, 0U);
    EXPECT_EQ(corpus_->size(), 1U);  // NOT grown: hang inputs go to the hang dir
}

}  // namespace
}  // namespace mlfuzzz3::core
