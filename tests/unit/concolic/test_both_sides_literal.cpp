#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

// Solver domain map, BOTH-SIDES-LITERAL forms (task-049, ADR 0035 §2).
//
// The axis is "which side of the gate carries a code constant", and two of
// its three positions are already measured:
//
//   * one side  — `expr == MAGIC`, the whole of
//     docs/experiments/solver-domain-map/report.md:138;
//   * neither side — `a + b == c + d`, task-045,
//     docs/experiments/solver-both-sides-derived/report.md:168.
//
// The third position — a code constant on EACH side, `a + K1 == b + K2` —
// is the largest connected blank in the coverage matrix
// (docs/experiments/solver-domain-coverage-matrix/report.md:176). This file
// MEASURES it. It adds no rules and changes nothing under src/.
//
// The mechanism the measurement has to respect. BindOperand
// (src/concolic/concolic.cpp:185-207) classifies a side by VALUE, not by
// expression: it gets the u64 the runtime logged and nothing else. It (a)
// looks that value up verbatim in the seed (:188-193), else (b) scans PAIRS
// of already-discovered fields and returns the FIRST pair whose wrapped sum
// equals it (:195-205), else (c) folds it into a kConst (:206). When BOTH
// sides come back kConst the whole record is dropped and never reaches
// sys.path (:244-247) — the gate is then not the solver's target at all,
// which is why "in domain" is decided by gate_survived and not by
// SolveOutcome.
//
// So the question this file answers is narrow and mechanical: does shifting
// a side by a code constant always push it out of the seed's reach, or does
// the pair scan sometimes land on `a + K1` by arithmetic accident and bind
// the side anyway (false composition, task-027)? The second is a defect
// class that was named before but never measured on this form.
//
// The grid: the SAME algebraic forms the domain map lists
// (docs/experiments/solver-domain-map/report.md:65-72), re-instantiated with
// one seed field and one code constant on each side. Rows map like this:
//
//   row 1  `a + b == MAGIC`      -> `a + K1 == b + K2`
//   row 2  `a - b == MAGIC`      -> `a - K1 == b - K2`
//   row 3  `a ^ b == MAGIC`      -> `a ^ K1 == b ^ K2`
//   row 3b `a ^ b` disjoint bits -> `a ^ K1d == b ^ K2d`, (field & K) == 0
//   row 4  `a & b == MAGIC`      -> `a & K1 == b & K2`
//   row 5  `a * b == MAGIC`      -> `a * K1 == b * K2`
//   row 7  `a <u b`              -> `b + K1 <u a + K2`
//
// Row 6 of that table (`a + CONST == MAGIC`) has NO image of its own here:
// its both-sides instantiation IS row 1's cell above, because every side of
// this grid already is "field + code constant". That degeneracy is itself
// worth stating rather than papering over with a duplicate cell, so row 3b —
// which the domain map measured separately and which is the one row that
// bound accidentally there — takes the seventh slot, and row 6 is
// cross-checked on this fixture by its own test
// (DomainMapRowSixIsAlreadyOutOfDomainOnThisFixture) instead.
//
// Two control cells carry the already-accepted outcomes onto this fixture,
// so a harness bug cannot pass unnoticed: `a + b == MAGIC` must reproduce
// the domain map's row 1, and `a + b == c + d` must reproduce task-045.
//
// Fields are registered exactly as the reference harnesses do: each field
// gets a guard record `field >u LOW` that is TRUE on the seed, because pass 1
// (concolic.cpp:216-234) only discovers a field if some record LOGGED its
// value.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (src/runtime/coverage/mlfuzzz3_branch.h:41-52).
enum : std::uint8_t { kEq = 0, kUlt = 2, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr unsigned kFieldCount = 4;
constexpr unsigned kFieldBytes = 4;
constexpr std::uint8_t kWidth = 32;

using Fields = std::array<std::uint32_t, kFieldCount>;

// The task-045 fixture A numbers, reused on purpose: the two control cells
// only reproduce accepted outcomes if they run on the seed those outcomes
// were taken on (tests/unit/concolic/test_both_sides_derived.cpp:88).
constexpr Fields kFields = {0xEA7BAE6CU, 0x5DD86C83U, 0x54676FA2U, 0x35202910U};

// Guard bound: below every field, absent from the seed.
constexpr std::uint32_t kLow = 0x01010101U;

// The one-literal control's magic, carried over from the measured domain map
// (docs/experiments/solver-domain-map/report.md:138).
constexpr std::uint32_t kMagic = 0x2A2A2A2AU;

// The code constants this grid is about. Neither is a field, neither occurs
// in the seed, and neither is the wrapped sum of any field pair — all three
// re-measured in ConstantsAndSideValuesAreOutsideTheSeedsReach.
constexpr std::uint32_t kK1 = 0x9E3779B9U;  // golden-ratio constant
constexpr std::uint32_t kK2 = 0x85EBCA77U;  // murmur3 mixing constant

// Disjoint-bit twins for row 3b: (kFields[0] & kK1Disjoint) == 0 and
// (kFields[1] & kK2Disjoint) == 0, so `a ^ K1d` is numerically `a + K1d`.
// That numeric alias is exactly what let row 3b bind as kAddVars in the
// domain map; here it is measured against a constant instead of a field.
constexpr std::uint32_t kK1Disjoint = 0x05840181U;
constexpr std::uint32_t kK2Disjoint = 0xA0258124U;

std::vector<std::uint8_t> SeedOf(const Fields& fields) {
    std::vector<std::uint8_t> seed(kFieldBytes * kFieldCount);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            seed[(kFieldBytes * i) + b] = static_cast<std::uint8_t>(fields[i] >> (8U * b));
        }
    }
    return seed;
}

std::vector<BranchReader::Record> GuardsFor(const Fields& fields) {
    std::vector<BranchReader::Record> guards;
    guards.reserve(kFieldCount);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        guards.push_back({i, kUgt, kWidth, fields[i], kLow});
    }
    return guards;
}

// Read the four u32 fields back out of a solved candidate under the same
// encoding the bindings used (little endian, offsets 0/4/8/12). This is what
// decides whether the gate is actually satisfied, as opposed to
// SolveForCandidate merely handing something back.
Fields FieldsOfCandidate(const mlfuzzz3::mutation::FuzzInput& input) {
    Fields out{};
    for (unsigned i = 0; i < kFieldCount; ++i) {
        std::uint32_t field = 0;
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            field |= static_cast<std::uint32_t>(input.data()[(kFieldBytes * i) + b]) << (8U * b);
        }
        out[i] = field;
    }
    return out;
}

enum class Op : std::uint8_t { kAdd, kSub, kXor, kAnd, kMul, kNone };

// How one side of the gate is BUILT — the values are recomputed from this,
// both for the seed and for a candidate, so nothing is logged by hand.
enum class SideKind : std::uint8_t {
    kFieldOpConst,  ///< fields[a] OP literal — a code constant on this side
    kFieldPair,     ///< fields[a] + fields[b] — no literal on this side
    kLiteral,       ///< the side is nothing but a code literal
};

struct SideSpec {
    SideKind kind;
    Op op;
    unsigned a;
    unsigned b;
    std::uint32_t literal;
};

constexpr SideSpec FieldOpConst(Op op, unsigned a, std::uint32_t literal) {
    return SideSpec{SideKind::kFieldOpConst, op, a, 0, literal};
}

constexpr SideSpec FieldPair(unsigned a, unsigned b) {
    return SideSpec{SideKind::kFieldPair, Op::kNone, a, b, 0};
}

constexpr SideSpec Literal(std::uint32_t literal) {
    return SideSpec{SideKind::kLiteral, Op::kNone, 0, 0, literal};
}

struct Form {
    const char* name;
    const char* map_row;  ///< row of docs/experiments/solver-domain-map/report.md
    SideSpec lhs;
    SideSpec rhs;
    std::uint8_t predicate;
    bool is_control;
};

std::uint32_t Apply(Op op, std::uint32_t v, std::uint32_t k) {
    switch (op) {
        case Op::kAdd:
            return v + k;
        case Op::kSub:
            return v - k;
        case Op::kXor:
            return v ^ k;
        case Op::kAnd:
            return v & k;
        case Op::kMul:
            return v * k;
        case Op::kNone:
            break;
    }
    return v;
}

std::uint32_t ValueOf(const SideSpec& side, const Fields& v) {
    switch (side.kind) {
        case SideKind::kFieldOpConst:
            return Apply(side.op, v[side.a], side.literal);
        case SideKind::kFieldPair:
            return v[side.a] + v[side.b];
        case SideKind::kLiteral:
            break;
    }
    return side.literal;
}

bool GateHolds(const Form& form, const Fields& v) {
    const std::uint32_t lhs = ValueOf(form.lhs, v);
    const std::uint32_t rhs = ValueOf(form.rhs, v);
    return form.predicate == kUlt ? lhs < rhs : lhs == rhs;
}

// What BindOperand made of one side.
struct Side {
    Operand::Kind kind;
    std::size_t var_index;
    std::size_t var_index2;
};

// One measured cell.
struct Cell {
    Side lhs;
    Side rhs;
    std::size_t num_vars;    ///< sys.num_vars for the whole form
    std::size_t path_size;   ///< surviving constraints (4 guards + gate = 5)
    bool gate_survived;      ///< did the gate record reach sys.path at all?
    bool invertible;         ///< sys.invertible for the whole form
    SolveOutcome outcome;    ///< what SolveForCandidate reported
    bool has_candidate;      ///< did the call actually hand back an input?
    bool gate_on_seed;       ///< did the gate hold BEFORE solving?
    bool gate_on_candidate;  ///< does it hold on the returned candidate?
    bool flipped;            ///< candidate exists and inverted the gate
};

// A side built as `field OP const` is FALSELY BOUND if BindOperand gave it
// anything but kConst: the shifted value coincided with a field (kVar) or
// with the wrapped sum of some field pair (kAddVars) by arithmetic accident,
// not because the gate was built out of those fields. Zero is a legal
// answer; this predicate is what makes it a measurement rather than a claim.
bool IsFalseBinding(const SideSpec& spec, const Side& side) {
    return spec.kind == SideKind::kFieldOpConst && side.kind != Operand::Kind::kConst;
}

// Read a side's binding off a PROBE system rather than off the form itself.
// A form whose two sides both classify as kConst is dropped whole
// (concolic.cpp:244-247) and would leave nothing to observe — which is the
// expected shape of most of this grid — so each probe keeps the OTHER side
// pinned to a field. BindOperand classifies each side independently, so the
// probe reports the same Kind the real form produced, and the real form is
// cross-checked against it whenever it survives.
Side ProbeSide(const Fields& fields, std::uint64_t lhs_value, std::uint64_t rhs_value,
               bool want_lhs) {
    const std::vector<std::uint8_t> seed = SeedOf(fields);
    std::vector<BranchReader::Record> recs = GuardsFor(fields);
    recs.push_back({kFieldCount, kEq, kWidth, lhs_value, rhs_value});
    const System sys = BuildSystem(seed, recs);
    if (sys.path.size() != recs.size()) {
        ADD_FAILURE() << "probe record was dropped — the probe itself is broken, "
                         "the Kind reported here is not measured";
        return Side{Operand::Kind::kConst, 0, 0};
    }
    EXPECT_EQ(sys.num_vars, kFieldCount)
        << "probe discovered a field the guards did not — the var set under the "
           "pair scan is not the one this cell claims to measure";
    const Operand& op = want_lhs ? sys.path.back().lhs : sys.path.back().rhs;
    return Side{op.kind, op.var_index, op.var_index2};
}

Cell Measure(const Form& form) {
    const Fields& fields = kFields;
    const std::vector<std::uint8_t> seed = SeedOf(fields);
    const auto lhs_value = static_cast<std::uint64_t>(ValueOf(form.lhs, fields));
    const auto rhs_value = static_cast<std::uint64_t>(ValueOf(form.rhs, fields));

    std::vector<BranchReader::Record> recs = GuardsFor(fields);
    recs.push_back({kFieldCount, form.predicate, kWidth, lhs_value, rhs_value});

    Cell cell{};
    cell.lhs = ProbeSide(fields, lhs_value, fields[kFieldCount - 1U], true);
    cell.rhs = ProbeSide(fields, fields[0], rhs_value, false);

    const System sys = BuildSystem(seed, recs);
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == recs.size();
    cell.invertible = sys.invertible;
    if (cell.gate_survived) {
        EXPECT_EQ(sys.path.back().lhs.kind, cell.lhs.kind) << form.name;
        EXPECT_EQ(sys.path.back().rhs.kind, cell.rhs.kind) << form.name;
    }

    cell.outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, recs, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    cell.gate_on_seed = GateHolds(form, fields);
    cell.gate_on_candidate =
        candidate.has_value() && GateHolds(form, FieldsOfCandidate(*candidate));
    cell.flipped = candidate.has_value() && (cell.gate_on_candidate != cell.gate_on_seed);
    return cell;
}

const char* NameOf(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kConst:
            return "kConst";
        case Operand::Kind::kAddVars:
            return "kAddVars";
    }
    return "?";
}

const char* NameOf(SolveOutcome outcome) {
    switch (outcome) {
        case SolveOutcome::kCandidate:
            return "kCandidate";
        case SolveOutcome::kNoBinding:
            return "kNoBinding";
        case SolveOutcome::kUnsat:
            return "kUnsat";
        case SolveOutcome::kTimeout:
            return "kTimeout";
        default:  // kError и kWidthOverflow (ADR 0049): здесь недостижим
            return "kError";
    }
    return "?";
}

std::string Describe(const Side& side) {
    std::string out = NameOf(side.kind);
    if (side.kind == Operand::Kind::kAddVars) {
        out += "(" + std::to_string(side.var_index) + "," + std::to_string(side.var_index2) + ")";
    } else if (side.kind == Operand::Kind::kVar) {
        out += "(" + std::to_string(side.var_index) + ")";
    }
    return out;
}

// The seven forms of the grid: a code constant on EACH side, u32, LE,
// arity 2 (one field and one constant per side).
constexpr Form kAddBoth = {
    "a+K1 == b+K2", "1", FieldOpConst(Op::kAdd, 0, kK1), FieldOpConst(Op::kAdd, 1, kK2), kEq,
    false};
constexpr Form kSubBoth = {
    "a-K1 == b-K2", "2", FieldOpConst(Op::kSub, 0, kK1), FieldOpConst(Op::kSub, 1, kK2), kEq,
    false};
constexpr Form kXorBoth = {
    "a^K1 == b^K2", "3", FieldOpConst(Op::kXor, 0, kK1), FieldOpConst(Op::kXor, 1, kK2), kEq,
    false};
constexpr Form kXorDisjointBoth = {
    "a^K1d == b^K2d (disjoint bits)",       "3b", FieldOpConst(Op::kXor, 0, kK1Disjoint),
    FieldOpConst(Op::kXor, 1, kK2Disjoint), kEq,  false};
constexpr Form kAndBoth = {
    "a&K1 == b&K2", "4", FieldOpConst(Op::kAnd, 0, kK1), FieldOpConst(Op::kAnd, 1, kK2), kEq,
    false};
constexpr Form kMulBoth = {
    "a*K1 == b*K2", "5", FieldOpConst(Op::kMul, 0, kK1), FieldOpConst(Op::kMul, 1, kK2), kEq,
    false};
// Row 7 keeps the domain map's predicate (unsigned <) and picks the field
// order that leaves the gate FALSE on the seed, like every other cell here.
constexpr Form kLtBoth = {
    "b+K1 <u a+K2", "7",  FieldOpConst(Op::kAdd, 1, kK1), FieldOpConst(Op::kAdd, 0, kK2),
    kUlt,           false};

// The two controls: one literal side (domain map row 1,
// docs/experiments/solver-domain-map/report.md:138) and no literal side
// (task-045, docs/experiments/solver-both-sides-derived/report.md:168).
constexpr Form kControlOneLiteralSide = {
    "a+b == MAGIC", "control/one-literal-side", FieldPair(0, 1), Literal(kMagic), kEq, true};
constexpr Form kControlNoLiteralSide = {
    "a+b == c+d", "control/no-literal-side", FieldPair(0, 1), FieldPair(2, 3), kEq, true};

constexpr std::array<const Form*, 9> kAllForms = {&kAddBoth,
                                                  &kSubBoth,
                                                  &kXorBoth,
                                                  &kXorDisjointBoth,
                                                  &kAndBoth,
                                                  &kMulBoth,
                                                  &kLtBoth,
                                                  &kControlOneLiteralSide,
                                                  &kControlNoLiteralSide};

constexpr std::array<const Form*, 7> kLiteralForms = {
    &kAddBoth, &kSubBoth, &kXorBoth, &kXorDisjointBoth, &kAndBoth, &kMulBoth, &kLtBoth};

}  // namespace

// ---------------------------------------------------------------------------
// Fixture sanity. If any of these break, every cell below is measuring
// something other than what it claims.
// ---------------------------------------------------------------------------

// The guards alone must register exactly the four fields — no more (an
// unaligned window would add a fifth var and change the pair scan) and no
// fewer (an undiscovered field cannot be bound at all).
TEST(BothSidesLiteral, FixtureRegistersExactlyFourFields) {
    const std::vector<std::uint8_t> seed = SeedOf(kFields);
    const std::vector<BranchReader::Record> guards = GuardsFor(kFields);
    const System sys = BuildSystem(seed, guards);
    ASSERT_EQ(sys.num_vars, 4U);
    ASSERT_EQ(sys.path.size(), guards.size());
    for (unsigned i = 0; i < kFieldCount; ++i) {
        EXPECT_EQ(sys.vars[i].offset, kFieldBytes * i);
        EXPECT_EQ(sys.vars[i].bit_width, kWidth);
        EXPECT_FALSE(sys.vars[i].big_endian);
    }
}

// Neither code constant, nor any value this grid puts on a side, is
// reachable from the seed: not as a 4-byte window in either byte order (the
// kVar branch, concolic.cpp:188-193) and not as the wrapped sum of a field
// pair (the kAddVars branch, :195-205). This is the property that makes
// false_binding == 0 a measurement rather than an assumption — it is checked
// arithmetically here and observed through BindOperand in the table below.
TEST(BothSidesLiteral, ConstantsAndSideValuesAreOutsideTheSeedsReach) {
    const std::vector<std::uint8_t> seed = SeedOf(kFields);
    std::vector<std::uint32_t> windows;
    for (std::size_t off = 0; off + kFieldBytes <= seed.size(); ++off) {
        std::uint32_t le = 0;
        std::uint32_t be = 0;
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            le |= static_cast<std::uint32_t>(seed[off + b]) << (8U * b);
            be |= static_cast<std::uint32_t>(seed[off + b]) << (8U * (kFieldBytes - 1U - b));
        }
        windows.push_back(le);
        windows.push_back(be);
    }
    std::vector<std::uint32_t> pair_sums;
    for (unsigned i = 0; i < kFieldCount; ++i) {
        for (unsigned j = i; j < kFieldCount; ++j) {
            pair_sums.push_back(kFields[i] + kFields[j]);
        }
    }
    ASSERT_EQ(pair_sums.size(), 10U);

    const auto unreachable = [&](std::uint32_t value, const char* what) {
        SCOPED_TRACE(what);
        EXPECT_EQ(std::count(windows.begin(), windows.end(), value), 0)
            << std::hex << value << " occurs verbatim in the seed";
        EXPECT_EQ(std::count(pair_sums.begin(), pair_sums.end(), value), 0)
            << std::hex << value << " equals a field pair sum";
    };
    unreachable(kK1, "K1");
    unreachable(kK2, "K2");
    unreachable(kK1Disjoint, "K1 disjoint");
    unreachable(kK2Disjoint, "K2 disjoint");
    unreachable(kLow, "guard bound");
    unreachable(kMagic, "MAGIC");
    for (const Form* form : kLiteralForms) {
        SCOPED_TRACE(form->name);
        unreachable(ValueOf(form->lhs, kFields), "lhs value");
        unreachable(ValueOf(form->rhs, kFields), "rhs value");
    }
}

// Row 3b only means anything if the constants really are bit-disjoint from
// their fields, which is what makes `field ^ K` numerically `field + K`.
TEST(BothSidesLiteral, DisjointConstantsReallyAliasTheSum) {
    EXPECT_EQ(kFields[0] & kK1Disjoint, 0U);
    EXPECT_EQ(kFields[1] & kK2Disjoint, 0U);
    EXPECT_EQ(kFields[0] ^ kK1Disjoint, kFields[0] + kK1Disjoint);
    EXPECT_EQ(kFields[1] ^ kK2Disjoint, kFields[1] + kK2Disjoint);
}

// Every cell of the grid is FALSE on the seed, so "the gate was taken" can
// only mean the solver flipped it, never that it was already true.
TEST(BothSidesLiteral, EveryGateIsFalseOnTheSeed) {
    for (const Form* form : kAllForms) {
        SCOPED_TRACE(form->name);
        EXPECT_FALSE(GateHolds(*form, kFields));
    }
}

// ---------------------------------------------------------------------------
// The measurement.
// ---------------------------------------------------------------------------

// The core cell of the grid, spelled out on its own: a constant on each side
// puts BOTH sides in kConst, so BuildSystem drops the record at
// concolic.cpp:244-247, the path keeps only the four guards, and the gate is
// never the solver's target — even though SolveForCandidate still reports
// success on what is left.
TEST(BothSidesLiteral, AddWithAConstantOnEachSideIsDropped) {
    const Cell cell = Measure(kAddBoth);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 4U);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_FALSE(cell.flipped);
}

// The same for all seven forms: the operator on the sides does not matter,
// only that neither side's VALUE is findable. Nothing here is form-specific,
// which is the point — the domain map's split into BOUND and NO-BINDING rows
// collapses once both sides carry a constant.
TEST(BothSidesLiteral, AllSevenLiteralFormsFallOutOfTheDomain) {
    for (const Form* form : kLiteralForms) {
        SCOPED_TRACE(std::string(form->name) + " (map row " + form->map_row + ")");
        const Cell cell = Measure(*form);
        EXPECT_EQ(cell.lhs.kind, Operand::Kind::kConst);
        EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
        EXPECT_FALSE(cell.gate_survived);
        EXPECT_EQ(cell.path_size, 4U);
        EXPECT_FALSE(cell.flipped);
        EXPECT_FALSE(IsFalseBinding(form->lhs, cell.lhs));
        EXPECT_FALSE(IsFalseBinding(form->rhs, cell.rhs));
    }
}

// Row 3b is the sharp one: its left side is numerically `a + K1d`, the exact
// shape the pair scan looks for. It still folds into kConst, because the
// scan ranges over pairs of FIELDS and a code constant is not a field. The
// escape hatch that made xor bind in the domain map does not exist here.
TEST(BothSidesLiteral, DisjointBitXorDoesNotAliasIntoAPairSum) {
    const Cell cell = Measure(kXorDisjointBoth);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
}

// Row 7 loses the most. In the domain map `a <u b` was IN the domain with no
// reconstruction at all — both sides were plain kVar
// (docs/experiments/solver-domain-map/report.md:138). Both halves are
// measured here on one fixture: unshifted it still binds kVar/kVar and
// survives; shifted by a constant on each side it drops like the rest.
TEST(BothSidesLiteral, UnsignedLessThanLosesItsBindingOnceBothSidesShift) {
    const std::vector<std::uint8_t> seed = SeedOf(kFields);
    std::vector<BranchReader::Record> bare = GuardsFor(kFields);
    bare.push_back({kFieldCount, kUlt, kWidth, kFields[1], kFields[0]});
    const System bare_sys = BuildSystem(seed, bare);
    ASSERT_EQ(bare_sys.path.size(), bare.size());
    EXPECT_EQ(bare_sys.path.back().lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(bare_sys.path.back().rhs.kind, Operand::Kind::kVar);

    const Cell shifted = Measure(kLtBoth);
    EXPECT_EQ(shifted.lhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(shifted.rhs.kind, Operand::Kind::kConst);
    EXPECT_FALSE(shifted.gate_survived);
}

// Row 6 of the domain map (`a + CONST == MAGIC`) has no image of its own in
// this grid — its both-sides instantiation is the kAddBoth cell. What it
// does give is a third check against accepted numbers: measured on THIS
// fixture it must still be out of the domain, as the map recorded it
// (docs/experiments/solver-domain-map/report.md:138, add-const=NO-BINDING).
TEST(BothSidesLiteral, DomainMapRowSixIsAlreadyOutOfDomainOnThisFixture) {
    constexpr Form row_six = {"a+K1 == MAGIC", "6", FieldOpConst(Op::kAdd, 0, kK1),
                              Literal(kMagic), kEq, false};
    const Cell cell = Measure(row_six);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_FALSE(cell.flipped);
}

// ---------------------------------------------------------------------------
// Controls: the harness must reproduce outcomes that are already accepted.
// ---------------------------------------------------------------------------

// Domain map row 1 (docs/experiments/solver-domain-map/report.md:138):
// add=BOUND(kAddVars), kCandidate, gate in domain.
TEST(BothSidesLiteral, ControlOneLiteralSideMatchesDomainMap) {
    const Cell cell = Measure(kControlOneLiteralSide);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// task-045 (docs/experiments/solver-both-sides-derived/report.md:168):
// `a + b == c + d` is in the domain, solved, and the gate is taken.
TEST(BothSidesLiteral, ControlNoLiteralSideMatchesBothSidesDerived) {
    const Cell cell = Measure(kControlNoLiteralSide);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.var_index, 2U);
    EXPECT_EQ(cell.rhs.var_index2, 3U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// Dropping the record is invisible from the outside: every cell of the grid,
// in domain or not, hands back kCandidate. This is the domain map's finding
// №4 re-measured on the both-sides-literal forms.
TEST(BothSidesLiteral, OutcomeDoesNotSeparateInDomainFromDropped) {
    for (const Form* form : kAllForms) {
        SCOPED_TRACE(form->name);
        const Cell cell = Measure(*form);
        EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
        EXPECT_TRUE(cell.has_candidate);
    }
}

// The table itself, emitted for the raw log so the report can pin numbers
// rather than restate them.
TEST(BothSidesLiteral, MeasuredTableIsEmitted) {
    unsigned in_domain = 0;
    unsigned dropped_records = 0;
    unsigned false_binding = 0;
    unsigned solved = 0;
    unsigned gate_taken = 0;
    std::array<Cell, kAllForms.size()> cells{};
    for (std::size_t i = 0; i < kAllForms.size(); ++i) {
        const Form* form = kAllForms[i];
        const Cell cell = Measure(*form);
        cells[i] = cell;
        if (cell.gate_survived) {
            ++in_domain;
        } else {
            ++dropped_records;
        }
        false_binding += static_cast<unsigned>(IsFalseBinding(form->lhs, cell.lhs));
        false_binding += static_cast<unsigned>(IsFalseBinding(form->rhs, cell.rhs));
        if (cell.outcome == SolveOutcome::kCandidate) {
            ++solved;
        }
        if (cell.flipped) {
            ++gate_taken;
        }
        std::cout << "CELL form=" << form->name << " map_row=" << form->map_row
                  << " control=" << form->is_control << " lhs=" << Describe(cell.lhs)
                  << " rhs=" << Describe(cell.rhs) << " num_vars=" << cell.num_vars
                  << " path=" << cell.path_size << " gate_survived=" << cell.gate_survived
                  << " invertible=" << cell.invertible << " outcome=" << NameOf(cell.outcome)
                  << " gate_on_seed=" << cell.gate_on_seed
                  << " gate_on_candidate=" << cell.gate_on_candidate << " flipped=" << cell.flipped
                  << "\n";
    }

    // The controls are what makes the rest of the table trustworthy: they
    // must land exactly where the two accepted reports left them.
    const Cell& one_literal = cells[7];
    const Cell& no_literal = cells[8];
    const bool controls_match =
        one_literal.lhs.kind == Operand::Kind::kAddVars &&
        one_literal.rhs.kind == Operand::Kind::kConst && one_literal.gate_survived &&
        one_literal.outcome == SolveOutcome::kCandidate && one_literal.flipped &&
        no_literal.lhs.kind == Operand::Kind::kAddVars &&
        no_literal.rhs.kind == Operand::Kind::kAddVars && no_literal.gate_survived &&
        no_literal.outcome == SolveOutcome::kCandidate && no_literal.flipped;

    std::cout << "SUMMARY: forms=" << kLiteralForms.size() << ", cells=" << kAllForms.size()
              << ", in_domain=" << in_domain << ", dropped_records=" << dropped_records
              << ", false_binding=" << false_binding << ", solved=" << solved
              << ", gate_taken=" << gate_taken
              << ", controls_match_accepted=" << (controls_match ? "yes" : "no")
              << ", width=u32, endian=LE, arity=2\n";
    EXPECT_EQ(kLiteralForms.size(), 7U);
    EXPECT_EQ(kAllForms.size(), 9U);
    EXPECT_EQ(in_domain, 2U);
    EXPECT_EQ(dropped_records, 7U);
    EXPECT_EQ(false_binding, 0U);
    EXPECT_EQ(solved, 9U);
    EXPECT_EQ(gate_taken, 2U);
    EXPECT_TRUE(controls_match);
}
