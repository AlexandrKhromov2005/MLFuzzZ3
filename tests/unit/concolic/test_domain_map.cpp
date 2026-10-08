#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Solver domain map (task-022, ADR 0035 §2). This file MEASURES which
// algebraic gate forms over two verbatim u32 input fields the existing
// reconstruction in src/concolic actually binds — it adds no rules.
//
// Method. For every form, the same two-field seed carries a = field at
// offset 0 and b = field at offset 4 (little-endian). Two guard records
// (a >u LOW, b >u LOW — both TRUE on the seed) make the fields findable,
// exactly as sites C1/C2 do in the real cov_xfield log
// (tests/unit/concolic/test_concolic.cpp:40-41); without them nothing in
// the log carries a verbatim field value and no variable is ever
// discovered (BuildSystem pass 1, src/concolic/concolic.cpp:225-228).
// The third record is the gate under test: the value the runtime would
// log for `a <op> b` on its LHS, the gate's magic constant on its RHS.
//
// A cell of the map is (i) the Operand::Kind BindOperand
// (src/concolic/concolic.cpp:185) gave the DERIVED operand and (ii) the
// SolveOutcome of the whole form. NO-BINDING cells are pinned as
// findings, not failures: they are the map of where the solver cannot
// help.
//
// Reading SolveOutcome alone is a trap and this file pins that too: when
// both sides of the gate classify as kConst, the record is DROPPED
// (concolic.cpp:244-247) and the last surviving guard silently becomes
// the target. Solve then returns kCandidate for a branch that is not the
// gate. Hence every cell also records whether the gate record survived.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUlt = 2, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;

// Two u32 fields, little-endian, offsets 0 and 4. Every byte is non-zero
// and no 4-byte window repeats, so none of the derived values below is
// accidentally findable as a substring (that would alias a derived
// operand onto a field and forge an in-domain verdict).
constexpr std::uint32_t kFieldA = 0x11223344U;
constexpr std::uint32_t kFieldB = 0x55667788U;

// Guard bound: below both fields and absent from the seed.
constexpr std::uint32_t kLow = 0x01010101U;

// The gate's magic constant. Absent from the seed (all seed bytes are
// non-zero) and not the sum of any field pair.
constexpr std::uint32_t kMagic = 0x0000002AU;

std::vector<std::uint8_t> SeedOf(std::uint32_t lo, std::uint32_t hi) {
    std::vector<std::uint8_t> seed(8);
    for (unsigned k = 0; k < 4; ++k) {
        seed[k] = static_cast<std::uint8_t>(lo >> (8U * k));
        seed[4 + k] = static_cast<std::uint8_t>(hi >> (8U * k));
    }
    return seed;
}

std::vector<std::uint8_t> Seed() {
    return SeedOf(kFieldA, kFieldB);
}

// One measured cell of the domain map.
struct Cell {
    Operand::Kind derived_kind;  ///< what BindOperand made of the derived operand
    bool gate_survived;          ///< did the gate record reach the path at all?
    std::size_t path_size;       ///< surviving constraints (2 guards + gate = 3)
    SolveOutcome outcome;        ///< what SolveForCandidate reported for the form
    bool has_candidate;          ///< did the call actually hand back an input?
};

// Measure one gate form. `derived` is the value the runtime logs on the
// gate's LHS (a <op> b, computed here in u32 exactly as C would), `rhs`
// is the value on its RHS, `predicate` the logged comparison.
//
// The derived operand's Kind is read off a PROBE system whose gate record
// is `derived <eq> b`: BindOperand classifies each side independently
// (concolic.cpp:240-243), so the LHS classification is identical to the
// real form's — but the probe's RHS binds to a field, which keeps the
// record from being dropped and makes the LHS Kind directly observable
// instead of inferred from the drop.
Cell Measure(const std::vector<std::uint8_t>& seed, std::uint32_t field_a, std::uint32_t field_b,
             std::uint64_t derived, std::uint64_t rhs, std::uint8_t predicate) {
    const std::vector<BranchReader::Record> guards = {
        {0, kUgt, 32, field_a, kLow},
        {1, kUgt, 32, field_b, kLow},
    };

    std::vector<BranchReader::Record> form = guards;
    form.push_back({2, predicate, 32, derived, rhs});

    std::vector<BranchReader::Record> probe = guards;
    probe.push_back({2, kEq, 32, derived, field_b});

    const System probe_sys = BuildSystem(seed, probe);
    const System form_sys = BuildSystem(seed, form);

    Cell cell{};
    if (probe_sys.path.empty()) {
        ADD_FAILURE() << "probe system kept no constraint — the probe fixture itself is broken";
        cell.derived_kind = Operand::Kind::kConst;
    } else {
        cell.derived_kind = probe_sys.path.back().lhs.kind;
    }
    cell.path_size = form_sys.path.size();
    cell.gate_survived = form_sys.path.size() == form.size();
    cell.outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, form, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    return cell;
}

// The guards alone always bind, so a NO-BINDING cell here never means
// "the log was opaque" — it means the GATE fell out of the system while
// the guards stayed. Asserting this keeps the pinned map honest.
void ExpectGuardsBound(const System& sys) {
    ASSERT_EQ(sys.num_vars, 2U);
    ASSERT_EQ(sys.vars[0].offset, 0U);
    ASSERT_EQ(sys.vars[1].offset, 4U);
}

}  // namespace

// Sanity for the fixture itself: the two fields are discovered by offset
// from the guards alone. If this breaks, every cell below is measuring
// something other than what it claims.
TEST(SolverDomainMap, FixtureBindsBothFields) {
    const std::vector<std::uint8_t> seed = Seed();
    const Cell cell = Measure(seed, kFieldA, kFieldB, kFieldA, kFieldB, kUlt);
    const System sys =
        BuildSystem(seed, {{0, kUgt, 32, kFieldA, kLow}, {1, kUgt, 32, kFieldB, kLow}});
    ExpectGuardsBound(sys);
    EXPECT_EQ(cell.path_size, 3U);
}

// FORM 1 — a + b == K. The baseline: the sum is not a substring of the
// seed, so it can only bind through the pair enumeration in
// concolic.cpp:195-205. IN DOMAIN (kAddVars), same finding as
// tests/unit/concolic/test_concolic.cpp:96.
TEST(SolverDomainMap, AddVarsIsInDomain) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto derived = static_cast<std::uint32_t>(kFieldA + kFieldB);
    const Cell cell = Measure(seed, kFieldA, kFieldB, derived, kMagic, kEq);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kAddVars);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// FORM 2 — a - b == K. The difference is neither a substring of the seed
// nor a sum of two fields, so it degrades to a constant; the magic is a
// constant too, so the gate record is DROPPED and the last guard becomes
// the target. OUT OF DOMAIN.
TEST(SolverDomainMap, SubIsOutOfDomain) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto derived = static_cast<std::uint32_t>(kFieldA - kFieldB);
    const Cell cell = Measure(seed, kFieldA, kFieldB, derived, kMagic, kEq);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    // The hazard: a candidate IS produced, for the guard branch — not for
    // the gate. Outcome alone cannot tell in-domain from out-of-domain.
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// FORM 3 — a ^ b == K. Out of domain in general; but xor of two fields
// with DISJOINT bits equals their sum, and the pair enumeration matches
// on the VALUE, so such a gate is silently re-encoded as a + b. That
// aliasing is pinned in the second half of this test: it produces a
// candidate satisfying a + b == K, which for a real xor gate need not
// satisfy a ^ b == K.
TEST(SolverDomainMap, XorIsOutOfDomainExceptWhenItAliasesTheSum) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto derived = static_cast<std::uint32_t>(kFieldA ^ kFieldB);
    const Cell cell = Measure(seed, kFieldA, kFieldB, derived, kMagic, kEq);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);

    // Disjoint bits: a ^ b == a + b, so the sum rule fires on a gate that
    // is not a sum.
    constexpr std::uint32_t kDisjointA = 0x0F0F0F0FU;
    constexpr std::uint32_t kDisjointB = 0xF0F0F0F0U;
    static_assert((kDisjointA & kDisjointB) == 0U);
    const std::vector<std::uint8_t> disjoint_seed = SeedOf(kDisjointA, kDisjointB);
    const auto aliased = static_cast<std::uint32_t>(kDisjointA ^ kDisjointB);
    const Cell alias = Measure(disjoint_seed, kDisjointA, kDisjointB, aliased, kMagic, kEq);

    EXPECT_EQ(alias.derived_kind, Operand::Kind::kAddVars);
    EXPECT_TRUE(alias.gate_survived);
    EXPECT_EQ(alias.outcome, SolveOutcome::kCandidate);
}

// FORM 4 — a & b == K. OUT OF DOMAIN: bitwise AND has no rule and its
// value is not a field.
TEST(SolverDomainMap, AndIsOutOfDomain) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto derived = static_cast<std::uint32_t>(kFieldA & kFieldB);
    const Cell cell = Measure(seed, kFieldA, kFieldB, derived, kMagic, kEq);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// FORM 5 — a * b == K. OUT OF DOMAIN: kAddVars is the only arithmetic
// link the Operand kind set has (src/solver/solver_facade.h Operand).
TEST(SolverDomainMap, MulIsOutOfDomain) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto derived = static_cast<std::uint32_t>(kFieldA * kFieldB);
    const Cell cell = Measure(seed, kFieldA, kFieldB, derived, kMagic, kEq);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// FORM 6 — a + K1 == K2 (one field plus a compile-time constant). OUT OF
// DOMAIN, and this is the sharpest cell of the map: the pair enumeration
// sums two VARIABLES only (concolic.cpp:195-205), so field-plus-constant
// — the single most common shape in real parsers (offset/length
// arithmetic) — never binds.
TEST(SolverDomainMap, AddConstIsOutOfDomain) {
    const std::vector<std::uint8_t> seed = Seed();
    constexpr std::uint32_t kConstAddend = 0x00000010U;
    const auto derived = static_cast<std::uint32_t>(kFieldA + kConstAddend);
    const Cell cell = Measure(seed, kFieldA, kFieldB, derived, kMagic, kEq);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// FORM 7 — a <u b (ordering; site 2 of the cov_xfield fixture). IN
// DOMAIN: both operands are verbatim fields, so no reconstruction rule is
// needed at all — this is the cheap half of the domain.
TEST(SolverDomainMap, UnsignedLessThanIsInDomain) {
    const std::vector<std::uint8_t> seed = Seed();
    const Cell cell = Measure(seed, kFieldA, kFieldB, kFieldA, kFieldB, kUlt);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kVar);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);

    // Both sides are variables, and the gate really is the target.
    std::vector<BranchReader::Record> form = {
        {0, kUgt, 32, kFieldA, kLow},
        {1, kUgt, 32, kFieldB, kLow},
        {2, kUlt, 32, kFieldA, kFieldB},
    };
    const System sys = BuildSystem(seed, form);
    ASSERT_EQ(sys.path.size(), 3U);
    EXPECT_EQ(sys.target_index, 2U);
    EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path[2].rhs.kind, Operand::Kind::kVar);
}
