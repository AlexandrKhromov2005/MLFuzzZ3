#include <gtest/gtest.h>

#include <cstdint>

#include "concolic.h"
#include "throttle.h"

// Unit coverage for the adaptive concolic throttle (ADR 0038, adaptive
// extension). The policy is tested here in isolation — no campaign loop, no
// solver — so the decision itself is pinned, not only its downstream effect.
// The call site that consumes it (src/core/campaign.cpp TakeConcolicTurn) is
// covered end-to-end in tests/unit/core/test_campaign_concolic.cpp.

namespace mlfuzzz3::concolic {
namespace {

// Small config so the tests read in a few lines instead of dozens.
ThrottleConfig SmallConfig() {
    return ThrottleConfig{.enabled = true,
                          .window = 10,
                          .min_samples = 4,
                          .unsat_ratio = 0.9,
                          .base_interval = 100,
                          .max_shift = 2};
}

void Feed(ConcolicThrottle& t, SolveOutcome outcome, int times) {
    for (int i = 0; i < times; ++i) {
        t.Observe(outcome);
    }
}

// POSITIVE: a target whose inverted systems are all unsatisfiable engages the
// throttle once enough evidence is in, and the demanded interval then grows
// multiplicatively up to the cap.
TEST(ConcolicThrottle, EngagesAndBacksOffOnUnsatDominatedTarget) {
    ConcolicThrottle t(SmallConfig());

    // Below min_samples there is no judgement, however unsat the calls are.
    Feed(t, SolveOutcome::kUnsat, 3);
    EXPECT_FALSE(t.engaged());
    EXPECT_EQ(t.CurrentInterval(), 0U);

    t.Observe(SolveOutcome::kUnsat);  // 4th sample -> min_samples reached
    EXPECT_TRUE(t.engaged());
    EXPECT_EQ(t.engagements(), 1U);
    EXPECT_EQ(t.CurrentInterval(), 100U);  // base_interval << 0

    t.Observe(SolveOutcome::kUnsat);
    EXPECT_EQ(t.CurrentInterval(), 200U);  // << 1
    t.Observe(SolveOutcome::kUnsat);
    EXPECT_EQ(t.CurrentInterval(), 400U);  // << 2 == cap (max_shift 2)
    Feed(t, SolveOutcome::kUnsat, 5);
    EXPECT_EQ(t.CurrentInterval(), 400U);  // capped, never runs away
}

// NEGATIVE (the guard this task exists for): a target that keeps producing
// candidates is unsat-poor, so the throttle never engages and never demands an
// interval — the sat path is not slowed down by the cost-cut.
TEST(ConcolicThrottle, StaysSilentOnSatDominatedTarget) {
    ConcolicThrottle t(SmallConfig());

    Feed(t, SolveOutcome::kCandidate, 20);
    EXPECT_FALSE(t.engaged());
    EXPECT_EQ(t.engagements(), 0U);
    EXPECT_EQ(t.CurrentInterval(), 0U);
}

// NEGATIVE, mixed: unsat well past min_samples but interleaved with candidates
// stays under unsat_ratio — "some unsat" is not "unsat-dominated".
TEST(ConcolicThrottle, StaysSilentWhenUnsatIsMerelyFrequent) {
    ConcolicThrottle t(SmallConfig());

    for (int i = 0; i < 5; ++i) {  // 8 unsat / 10 window = 0.8 < 0.9
        t.Observe(SolveOutcome::kUnsat);
        t.Observe(SolveOutcome::kUnsat);
        t.Observe(SolveOutcome::kCandidate);
    }
    EXPECT_FALSE(t.engaged());
    EXPECT_EQ(t.CurrentInterval(), 0U);
}

// A single candidate on an already-throttled target releases the stage at once
// and drops the accumulated backoff: cost is reclaimed slowly, productivity is
// honoured immediately.
TEST(ConcolicThrottle, OneCandidateDisengagesAndResetsBackoff) {
    ConcolicThrottle t(SmallConfig());

    Feed(t, SolveOutcome::kUnsat, 8);
    ASSERT_TRUE(t.engaged());
    ASSERT_EQ(t.CurrentInterval(), 400U);  // at the cap

    t.Observe(SolveOutcome::kCandidate);
    EXPECT_FALSE(t.engaged());
    EXPECT_EQ(t.CurrentInterval(), 0U);

    // Re-engaging starts from the base interval again, not from the old cap:
    // one more unsat puts the window back over the ratio (9/10) and the
    // demand comes back at base_interval, not at the 400 it had reached.
    t.Observe(SolveOutcome::kUnsat);
    EXPECT_TRUE(t.engaged());
    EXPECT_EQ(t.engagements(), 2U);
    EXPECT_EQ(t.CurrentInterval(), 100U);
}

// kNoBinding is NOT unsat: a target that never binds is a reconstruction gap,
// a different defect with a different fix, and this throttle must not claim it.
// (Pinned because the task-020 recon found the real libtiff target is
// kNoBinding-dominated at 98.8%, not unsat-dominated — docs/experiments/
// concolic-cost-reclaim/RECON.md.)
TEST(ConcolicThrottle, NoBindingDoesNotEngageTheUnsatThrottle) {
    ConcolicThrottle t(SmallConfig());

    Feed(t, SolveOutcome::kNoBinding, 20);
    EXPECT_FALSE(t.engaged());
    EXPECT_EQ(t.unsat_samples(), 0U);
    EXPECT_EQ(t.CurrentInterval(), 0U);
}

// The window really slides: unsat evidence that has aged out stops counting,
// so a target that recovers is released rather than held on stale history.
TEST(ConcolicThrottle, WindowEvictsStaleUnsatEvidence) {
    ConcolicThrottle t(SmallConfig());

    Feed(t, SolveOutcome::kUnsat, 10);  // window full, all unsat
    ASSERT_TRUE(t.engaged());
    ASSERT_EQ(t.unsat_samples(), 10U);

    Feed(t, SolveOutcome::kTimeout, 10);  // push every unsat out of the window
    EXPECT_EQ(t.samples(), 10U);
    EXPECT_EQ(t.unsat_samples(), 0U);
    EXPECT_FALSE(t.engaged());
    EXPECT_EQ(t.CurrentInterval(), 0U);
}

// The master switch: disabled config means the throttle observes but never
// demands anything, restoring exact pre-throttle behavior.
TEST(ConcolicThrottle, DisabledNeverDemandsAnInterval) {
    ThrottleConfig cfg = SmallConfig();
    cfg.enabled = false;
    ConcolicThrottle t(cfg);

    Feed(t, SolveOutcome::kUnsat, 20);
    EXPECT_TRUE(t.engaged());            // the reading is still taken...
    EXPECT_EQ(t.CurrentInterval(), 0U);  // ...but it is never acted on
}

}  // namespace
}  // namespace mlfuzzz3::concolic
