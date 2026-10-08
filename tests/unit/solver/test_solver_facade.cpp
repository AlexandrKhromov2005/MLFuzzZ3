#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "solver_facade.h"

// Unit tests for the multi-variable SolverFacade (ADR 0035; supersedes
// the single-variable ADR 0034 v1). No exec-server: constraint systems
// are synthetic. A self-contained C++ oracle mirrors the facade semantics
// (per-field truncation, signed/unsigned predicates, wrapping kAddVars)
// so each model can be checked by substitution, and so the Z3-necessity
// case can prove that no single observed operand satisfies the system.

namespace {

using mlfuzzz3::solver::Constraint;
using mlfuzzz3::solver::Operand;
using mlfuzzz3::solver::SolveInverted;
using mlfuzzz3::solver::SolveResult;

// fuzzer_rt_cmp_kind values (ADR 0033, fixed ABI).
enum : std::uint8_t {
    kEq = 0,
    kNe = 1,
    kUlt = 2,
    kUle = 3,
    kUgt = 4,
    kUge = 5,
    kSlt = 6,
    kSle = 7,
    kSgt = 8,
    kSge = 9,
};

constexpr unsigned kTimeoutMs = 5000;
constexpr std::uint32_t kLowerBound = 0x10000000U;  // C1/C2 threshold in the fixture system.

// Operand / constraint builders for readable test systems.
Operand Var(std::size_t i) {
    return {Operand::Kind::kVar, i, 0, 0};
}
Operand Const(std::uint64_t v) {
    return {Operand::Kind::kConst, 0, 0, v};
}
Operand Add(std::size_t i, std::size_t j) {
    return {Operand::Kind::kAddVars, i, j, 0};
}
Constraint Cmp(std::uint8_t pred, std::uint8_t bw, Operand lhs, Operand rhs) {
    return {pred, bw, lhs, rhs};
}

std::uint64_t Mask(unsigned bit_width) {
    return bit_width >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bit_width) - 1U);
}

// Sign-extend the low bit_width bits of v to a signed 64-bit value
// (C++20 guarantees arithmetic right shift on signed integers).
std::int64_t SignExtend(std::uint64_t v, unsigned bit_width) {
    if (bit_width >= 64) {
        return static_cast<std::int64_t>(v);
    }
    const unsigned shift = 64U - bit_width;
    return static_cast<std::int64_t>(v << shift) >> shift;
}

// Value of one operand at the constraint's width. kAddVars wraps mod
// 2^bit_width, mirroring the facade's bvadd.
std::uint64_t OperandValue(const std::vector<std::uint64_t>& vals, const Operand& op,
                           unsigned bit_width) {
    const std::uint64_t mask = Mask(bit_width);
    switch (op.kind) {
        case Operand::Kind::kConst:
            return op.const_value & mask;
        case Operand::Kind::kVar:
            return vals[op.var_index] & mask;
        case Operand::Kind::kAddVars:
            return ((vals[op.var_index] & mask) + (vals[op.var_index2] & mask)) & mask;
    }
    return 0;
}

bool EvalConstraint(const std::vector<std::uint64_t>& vals, const Constraint& c) {
    const std::uint64_t l = OperandValue(vals, c.lhs, c.bit_width);
    const std::uint64_t r = OperandValue(vals, c.rhs, c.bit_width);
    switch (c.predicate) {
        case kEq:
            return l == r;
        case kNe:
            return l != r;
        case kUlt:
            return l < r;
        case kUle:
            return l <= r;
        case kUgt:
            return l > r;
        case kUge:
            return l >= r;
        case kSlt:
            return SignExtend(l, c.bit_width) < SignExtend(r, c.bit_width);
        case kSle:
            return SignExtend(l, c.bit_width) <= SignExtend(r, c.bit_width);
        case kSgt:
            return SignExtend(l, c.bit_width) > SignExtend(r, c.bit_width);
        case kSge:
            return SignExtend(l, c.bit_width) >= SignExtend(r, c.bit_width);
        default:
            return false;
    }
}

// True iff `vals` satisfies the inverted system: every non-target
// constraint holds and the target constraint is flipped (violated).
bool SatisfiesInverted(const std::vector<std::uint64_t>& vals, const std::vector<Constraint>& path,
                       std::size_t target) {
    for (std::size_t i = 0; i < path.size(); ++i) {
        const bool holds = EvalConstraint(vals, path[i]);
        if (i == target) {
            if (holds) {
                return false;
            }
        } else if (!holds) {
            return false;
        }
    }
    return true;
}

// The cross-field fixture system (ADR 0035 §3): two 32-bit fields with
// lower bounds, ordering, and a sum that wraps to 5.
std::vector<Constraint> FixtureSystem() {
    return {
        Cmp(kUgt, 32, Var(0), Const(kLowerBound)),  // C1: var0 >u 0x10000000
        Cmp(kUgt, 32, Var(1), Const(kLowerBound)),  // C2: var1 >u 0x10000000
        Cmp(kUlt, 32, Var(0), Var(1)),              // C3: var0 <u var1
        Cmp(kEq, 32, Add(0, 1), Const(5)),          // C4: (var0 + var1) ==u 5 (wrap)
    };
}

}  // namespace

// Cross-field SAT with the ordering target inverted: the model must keep
// both bounds and the wrapping sum (C4) while violating C3, and the sum
// must genuinely wrap to 5 modulo 2^32.
TEST(SolverFacade, CrossFieldSatWithWrap) {
    const std::vector<Constraint> path = FixtureSystem();
    const std::size_t target = 2;  // invert C3 (var0 <u var1) -> var0 >=u var1

    const SolveResult r = SolveInverted(/*num_vars=*/2, path, target, kTimeoutMs);
    ASSERT_EQ(r.status, SolveResult::Status::kSat);
    ASSERT_EQ(r.model_values.size(), 2U);
    EXPECT_TRUE(SatisfiesInverted(r.model_values, path, target));

    // C4 held (non-target): the 32-bit sum wrapped to 5.
    const std::uint64_t wrapped = (r.model_values[0] + r.model_values[1]) & 0xFFFFFFFFULL;
    EXPECT_EQ(wrapped, 5U);
    EXPECT_GT(r.model_values[0], kLowerBound);
    EXPECT_GT(r.model_values[1], kLowerBound);
    EXPECT_GE(r.model_values[0], r.model_values[1]);  // C3 violated
}

// var0 == 5 AND (invert var0 == 5) is contradictory.
TEST(SolverFacade, UnsatContradiction) {
    const std::vector<Constraint> path = {
        Cmp(kEq, 32, Var(0), Const(5)), Cmp(kEq, 32, Var(0), Const(5)),  // target -> var0 != 5
    };
    const SolveResult r = SolveInverted(/*num_vars=*/1, path, /*target_index=*/1, kTimeoutMs);
    EXPECT_EQ(r.status, SolveResult::Status::kUnsat);
}

// A 32-bit constant with nonzero high 32 bits (as if sign-extended in the
// log) must be solved as if truncated to 32 bits. A 64-bit reading of
// var0 >=u 0xFFFFFFFFFFFFFFF0 would be unsatisfiable for a 32-bit field;
// the truncated form var0 >=u 0xFFFFFFF0 is solvable at the top of range.
TEST(SolverFacade, ConstantTruncatedToBitWidth) {
    const std::vector<Constraint> path = {
        Cmp(kUge, 32, Var(0), Const(0xFFFFFFFFFFFFFFF0ULL)),  // -> var0 >=u 0xFFFFFFF0
        Cmp(kEq, 32, Var(0), Const(0)),                       // target -> var0 != 0
    };
    const SolveResult r = SolveInverted(/*num_vars=*/1, path, /*target_index=*/1, kTimeoutMs);
    ASSERT_EQ(r.status, SolveResult::Status::kSat);
    ASSERT_EQ(r.model_values.size(), 1U);
    EXPECT_GE(r.model_values[0], 0xFFFFFFF0ULL);
    EXPECT_LE(r.model_values[0], 0xFFFFFFFFULL);  // proves 32-bit field width
}

// Same operand pair (0xFFFFFFF0 vs 0x10), only the predicate's signedness
// differs. As unsigned, 0xFFFFFFF0 <u 0x10 is false; as signed, -16 <s 16
// is true. Pinning var0 to 0xFFFFFFF0 and inverting the comparison flips
// the verdict between Ult (SAT) and Slt (UNSAT).
TEST(SolverFacade, SignednessIsDistinguished) {
    const std::vector<Constraint> path_ult = {
        Cmp(kEq, 32, Var(0), Const(0xFFFFFFF0ULL)),  // pin var0
        Cmp(kUlt, 32, Var(0), Const(0x10)),          // target: false at pin -> invert true
    };
    const SolveResult ult = SolveInverted(/*num_vars=*/1, path_ult, /*target_index=*/1, kTimeoutMs);
    ASSERT_EQ(ult.status, SolveResult::Status::kSat);
    ASSERT_EQ(ult.model_values.size(), 1U);
    EXPECT_EQ(ult.model_values[0], 0xFFFFFFF0ULL);

    const std::vector<Constraint> path_slt = {
        Cmp(kEq, 32, Var(0), Const(0xFFFFFFF0ULL)),  // pin var0
        Cmp(kSlt, 32, Var(0), Const(0x10)),          // target: true at pin -> invert false
    };
    const SolveResult slt = SolveInverted(/*num_vars=*/1, path_slt, /*target_index=*/1, kTimeoutMs);
    EXPECT_EQ(slt.status, SolveResult::Status::kUnsat);
}

// Z3-necessity (closes the "decorative solver" risk from review). The
// full cross-field system C1..C4 must hold (target is a trivially
// invertible C5: var0 == 0 -> var0 != 0, free for any valid solution), so
// the satisfying pair is the diagonal sum-with-overflow solution. No
// single observed operand (0x10000000 or 5), substituted into one or both
// fields (the RedQueen / input-to-state corollary), passes the system —
// yet the facade finds a joint solution.
TEST(SolverFacade, Z3NecessaryNoSingleOperandSatisfies) {
    std::vector<Constraint> path = FixtureSystem();
    path.push_back(Cmp(kEq, 32, Var(0), Const(0)));  // C5 target -> var0 != 0
    const std::size_t target = 4;

    // Naive single-operand substitutions into (var0, var1): none satisfy.
    // Observed operands are 0x10000000 and 5 (plus 0 from C5).
    const std::vector<std::vector<std::uint64_t>> naive = {
        {kLowerBound, kLowerBound}, {5, 5}, {kLowerBound, 5},
        {5, kLowerBound},           {0, 0}, {kLowerBound, 0},
    };
    for (const std::vector<std::uint64_t>& cand : naive) {
        EXPECT_FALSE(SatisfiesInverted(cand, path, target))
            << "naive substitution unexpectedly satisfied: var0=" << cand[0] << " var1=" << cand[1];
    }

    // The solver finds a value satisfying the full cross-field system.
    const SolveResult r = SolveInverted(/*num_vars=*/2, path, target, kTimeoutMs);
    ASSERT_EQ(r.status, SolveResult::Status::kSat);
    ASSERT_EQ(r.model_values.size(), 2U);
    EXPECT_TRUE(SatisfiesInverted(r.model_values, path, target));
    // The crash conjunction C1..C4 genuinely holds at the solution.
    const std::uint64_t wrapped = (r.model_values[0] + r.model_values[1]) & 0xFFFFFFFFULL;
    EXPECT_EQ(wrapped, 5U);
    EXPECT_LT(r.model_values[0], r.model_values[1]);  // C3 holds
}

// Degenerate inputs are reported as kError, not undefined behaviour.
TEST(SolverFacade, ErrorsOnDegenerateInput) {
    EXPECT_EQ(SolveInverted(1, {}, 0, kTimeoutMs).status, SolveResult::Status::kError);

    const std::vector<Constraint> one = {Cmp(kEq, 32, Var(0), Const(7))};
    EXPECT_EQ(SolveInverted(1, one, /*target_index=*/5, kTimeoutMs).status,
              SolveResult::Status::kError);

    const std::vector<Constraint> bad_width = {Cmp(kEq, 0, Var(0), Const(7))};
    EXPECT_EQ(SolveInverted(1, bad_width, 0, kTimeoutMs).status, SolveResult::Status::kError);

    // Operand references a variable index >= num_vars.
    const std::vector<Constraint> bad_index = {Cmp(kEq, 32, Var(3), Const(7))};
    EXPECT_EQ(SolveInverted(1, bad_index, 0, kTimeoutMs).status, SolveResult::Status::kError);
}
