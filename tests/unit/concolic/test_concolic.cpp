#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Unit tests for the cross-field concolic orchestrator (ADR 0035 §2),
// without exec-server: synthetic branch records (the real cov_xfield log
// captured for seed x=0x20000000, y=0x30000000 — see the e2e) are fed to
// BuildSystem / SolveForCandidate directly.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr std::uint32_t kLowerBound = 0x10000000U;

// Seed: x = 0x20000000 at offset 0, y = 0x30000000 at offset 4 (LE).
// Passes C1,C2,C3 but not C4 (sum 0x50000000 != 5), so it does not crash.
std::vector<std::uint8_t> Seed() {
    return {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
}

// The branch log this seed produces (captured from the real fixture):
// C1: x >u K, C2: y >u K, C3: x <u y, C4: (x+y) ==u 5 (lhs is the SUM).
std::vector<BranchReader::Record> Records() {
    return {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},  // C1
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},  // C2
        {2, kUlt, 32, 0x20000000ULL, 0x30000000ULL},  // C3
        {3, kEq, 32, 0x50000000ULL, 0x00000005ULL},   // C4: lhs = x + y (the sum)
    };
}

std::uint32_t ReadU32Le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

}  // namespace

// (а) x,y bind as var0/var1 by OFFSET; (б) C4's sum operand is recognised
// as kAddVars(0,1) THROUGH PAIR ENUMERATION (the sum value is not a
// substring of the seed); plus the as-taken encoding negates the C4
// predicate (eq -> ne) because the comparison was false on the seed.
TEST(Concolic, BuildSystemBindsFieldsAndRecognisesSum) {
    const std::vector<std::uint8_t> seed = Seed();
    const System sys = BuildSystem(seed, Records());

    ASSERT_TRUE(sys.invertible);
    ASSERT_EQ(sys.num_vars, 2U);
    ASSERT_EQ(sys.path.size(), 4U);
    EXPECT_EQ(sys.target_index, 3U);

    // (а) variables bound by offset, little-endian.
    ASSERT_EQ(sys.vars.size(), 2U);
    EXPECT_EQ(sys.vars[0].offset, 0U);
    EXPECT_EQ(sys.vars[0].bit_width, 32U);
    EXPECT_FALSE(sys.vars[0].big_endian);
    EXPECT_EQ(sys.vars[1].offset, 4U);

    // C1: var0 >u const(K).
    EXPECT_EQ(sys.path[0].predicate, kUgt);
    EXPECT_EQ(sys.path[0].lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path[0].lhs.var_index, 0U);
    EXPECT_EQ(sys.path[0].rhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(sys.path[0].rhs.const_value, kLowerBound);

    // C2: var1 >u const(K).
    EXPECT_EQ(sys.path[1].lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path[1].lhs.var_index, 1U);

    // C3: var0 <u var1 (cross-field, both variables).
    EXPECT_EQ(sys.path[2].predicate, kUlt);
    EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path[2].lhs.var_index, 0U);
    EXPECT_EQ(sys.path[2].rhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path[2].rhs.var_index, 1U);

    // (б) C4: sum recognised as kAddVars(0,1); predicate negated to ne
    // (as-taken: eq was false on the seed). SolveInverted will flip ne
    // back to eq, i.e. solve (var0 + var1) == 5.
    EXPECT_EQ(sys.path[3].predicate, kNe);
    EXPECT_EQ(sys.path[3].lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(sys.path[3].lhs.var_index, 0U);
    EXPECT_EQ(sys.path[3].lhs.var_index2, 1U);
    EXPECT_EQ(sys.path[3].rhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(sys.path[3].rhs.const_value, 5U);
}

// (в)+(г) The orchestrator solves the assembled system and places the
// solved pair at offsets 0/4; the candidate's (x,y) satisfies the full
// crash conjunction C1..C4 (this is the solver's pair, not hard-coded).
TEST(Concolic, SolveForCandidateReachesCrashPair) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto candidate = SolveForCandidate(seed, Records(), kTimeoutMs);
    ASSERT_TRUE(candidate.has_value());
    ASSERT_GE(candidate->size(), 8U);

    const std::uint32_t x = ReadU32Le(candidate->data());
    const std::uint32_t y = ReadU32Le(candidate->data() + 4);

    EXPECT_GT(x, kLowerBound);                         // C1
    EXPECT_GT(y, kLowerBound);                         // C2
    EXPECT_LT(x, y);                                   // C3
    EXPECT_EQ(static_cast<std::uint32_t>(x + y), 5U);  // C4 (u32 wrap)

    // The pair genuinely changed from the seed (0x20000000/0x30000000).
    EXPECT_FALSE(x == 0x20000000U && y == 0x30000000U);
}

// A log whose operands are not findable in the seed yields no candidate
// (every record drops to both-const -> empty path -> not invertible).
TEST(Concolic, NoFindableOperandsYieldsNoCandidate) {
    const std::vector<std::uint8_t> seed = {0xAA, 0xBB, 0xCC, 0xDD};
    const std::vector<BranchReader::Record> records = {
        {0, kEq, 32, 0x11111111ULL, 0x22222222ULL},
    };
    const System sys = BuildSystem(seed, records);
    EXPECT_EQ(sys.num_vars, 0U);
    EXPECT_FALSE(sys.invertible);
    EXPECT_FALSE(SolveForCandidate(seed, records, kTimeoutMs).has_value());
}

// The optional outcome out-parameter (ADR 0036 §4) reports why a call did
// or did not produce a candidate, for campaign metrics.
TEST(Concolic, SolveOutcomeIsReported) {
    using mlfuzzz3::concolic::SolveOutcome;

    // The cov_xfield system yields a candidate -> kCandidate.
    const std::vector<std::uint8_t> seed = Seed();
    SolveOutcome outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, Records(), kTimeoutMs, &outcome);
    EXPECT_TRUE(candidate.has_value());
    EXPECT_EQ(outcome, SolveOutcome::kCandidate);

    // No findable operands -> nothing binds -> kNoBinding.
    const std::vector<std::uint8_t> opaque = {0xAA, 0xBB, 0xCC, 0xDD};
    const std::vector<BranchReader::Record> unbindable = {
        {0, kEq, 32, 0x11111111ULL, 0x22222222ULL},
    };
    outcome = SolveOutcome::kCandidate;
    EXPECT_FALSE(SolveForCandidate(opaque, unbindable, kTimeoutMs, &outcome).has_value());
    EXPECT_EQ(outcome, SolveOutcome::kNoBinding);
}

// The outcome axis must separate "nothing bound to the input" from "bound,
// but the inverted system has no solution". Both are fruitless calls that
// yield no candidate, and before ADR 0036 §4 they were indistinguishable at
// the call site — yet they mean opposite things: kNoBinding is a
// reconstruction gap (our side), kUnsat is the solver honestly reporting the
// branch is unreachable from this seed. The libtiff campaign is 99.5% unsat
// (docs/experiments/comparative-magma-libtiff/ANALYSIS.md), so misfiling
// those calls as "no binding" would send the whole diagnosis after a
// reconstruction bug that is not there.
//
// Construction: BOTH records' lhs is x (0x20000000, findable at offset 0 ->
// var0), so the system genuinely binds — this is not the empty-path case.
// Both constants are absent from the seed and are not a sum of its fields
// (x+x=0x40000000, x+y=0x50000000, y+y=0x60000000), so they stay constants.
// Both comparisons are TRUE on the seed, so both are kept as-taken; the
// target is the last one, and inverting it gives x <=u 0x0AAAAAAA against a
// surviving x >u 0x11111111 — unsatisfiable, with 0x0AAAAAAA < 0x11111111.
TEST(Concolic, SolveOutcomeSeparatesUnsatFromNoBinding) {
    using mlfuzzz3::concolic::SolveOutcome;

    const std::vector<std::uint8_t> seed = Seed();
    const std::vector<BranchReader::Record> conflicting = {
        {0, kUgt, 32, 0x20000000ULL, 0x11111111ULL},  // x >u 0x11111111 (true on seed)
        {1, kUgt, 32, 0x20000000ULL, 0x0AAAAAAAULL},  // target: x >u 0x0AAAAAAA (true)
    };

    // Precondition: the system really did bind — otherwise this test would
    // be a second, more elaborate copy of the kNoBinding case.
    const System sys = BuildSystem(seed, conflicting);
    ASSERT_GT(sys.num_vars, 0U) << "records must bind, else this is not an unsat test";
    ASSERT_TRUE(sys.invertible);

    SolveOutcome outcome = SolveOutcome::kCandidate;
    EXPECT_FALSE(SolveForCandidate(seed, conflicting, kTimeoutMs, &outcome).has_value());
    EXPECT_EQ(outcome, SolveOutcome::kUnsat);
    EXPECT_NE(outcome, SolveOutcome::kNoBinding);
}

// Цена вызова, разложенная на построение и решение (ADR 0049): накопители
// прибавляются, солвер действительно отмерен, а кандидат и исход те же, что у
// перегрузки без разметки времени.
TEST(Concolic, CallTimingAccumulatesBuildAndSolve) {
    using mlfuzzz3::concolic::CallTiming;
    using mlfuzzz3::concolic::Fixes;
    using mlfuzzz3::concolic::SolveOutcome;

    const std::vector<std::uint8_t> seed = Seed();
    std::uint64_t build_us = 0;
    std::uint64_t solve_us = 0;
    SolveOutcome timed = SolveOutcome::kError;
    const auto candidate =
        SolveForCandidate(seed, Records(), kTimeoutMs, &timed, Fixes{},
                          CallTiming{.build_us = &build_us, .solve_us = &solve_us});
    SolveOutcome plain = SolveOutcome::kError;
    const auto reference = SolveForCandidate(seed, Records(), kTimeoutMs, &plain, Fixes{});
    ASSERT_TRUE(candidate.has_value());
    ASSERT_TRUE(reference.has_value());
    EXPECT_EQ(timed, plain);
    EXPECT_EQ(std::vector<std::uint8_t>(candidate->data(), candidate->data() + candidate->size()),
              std::vector<std::uint8_t>(reference->data(), reference->data() + reference->size()));
    // Z3 was called: its context and check cannot fit under one microsecond.
    EXPECT_GT(solve_us, 0U);

    // Accumulators add up across calls, never reset.
    const std::uint64_t build_after_first = build_us;
    const std::uint64_t solve_after_first = solve_us;
    EXPECT_TRUE(SolveForCandidate(seed, Records(), kTimeoutMs, nullptr, Fixes{},
                                  CallTiming{.build_us = &build_us, .solve_us = &solve_us})
                    .has_value());
    EXPECT_GE(build_us, build_after_first);
    EXPECT_GT(solve_us, solve_after_first);

    // A null accumulator is simply not metered.
    EXPECT_TRUE(
        SolveForCandidate(seed, Records(), kTimeoutMs, nullptr, Fixes{}, CallTiming{}).has_value());
}

// A system that does not invert never reaches the solver, so the solve
// accumulator gets nothing while the build one is charged. A 1 MiB seed with
// no findable operand makes the FindFirst scan (F1 off) take well over a
// microsecond, so "build was metered" is observable, not assumed.
TEST(Concolic, CallTimingChargesNoSolveWhenSystemDoesNotInvert) {
    using mlfuzzz3::concolic::CallTiming;
    using mlfuzzz3::concolic::Fixes;
    using mlfuzzz3::concolic::SolveOutcome;

    const std::vector<std::uint8_t> seed(std::size_t{1} << 20U, 0xAA);
    const std::vector<BranchReader::Record> records = {
        {0, kEq, 32, 0x11111111ULL, 0x22222222ULL},
    };
    std::uint64_t build_us = 0;
    std::uint64_t solve_us = 0;
    SolveOutcome outcome = SolveOutcome::kCandidate;
    EXPECT_FALSE(SolveForCandidate(seed, records, kTimeoutMs, &outcome, Fixes{},
                                   CallTiming{.build_us = &build_us, .solve_us = &solve_us})
                     .has_value());
    EXPECT_EQ(outcome, SolveOutcome::kNoBinding);
    EXPECT_GT(build_us, 0U);
    EXPECT_EQ(solve_us, 0U);
}
