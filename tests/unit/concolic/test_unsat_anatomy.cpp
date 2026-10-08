#include <gtest/gtest.h>

#include <cstdint>
#include <iostream>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Anatomy of kUnsat (task-024, ADR 0035 §2). On the real target the
// solver spends its whole budget on kUnsat — 713 of 717 calls, 99.44%,
// at 100% binding (docs/experiments/concolic-cost-reclaim/data/
// ab-throttle-off.metrics.jsonl, throttle=off arm). This file MEASURES
// which SHAPES OF THE RECONSTRUCTED SYSTEM the existing code in
// src/concolic + src/solver turns into kUnsat and which it does not. It
// changes no rule and adds none: every cell is a characterization of
// observed behaviour.
//
// The axis here is the shape of the SYSTEM (which Operand::Kind each side
// of the inverted record got, where the record sits in the path, how the
// bindings overlap, at what bit width) — not the algebraic shape of the
// gate, which is task-022's axis (tests/unit/concolic/test_domain_map.cpp).
//
// Method, same fixture family as the domain map. A two-field seed carries
// a = field at offset 0 and b = field at offset 4, little-endian. Guard
// records (a >u LOW, b >u LOW, both TRUE on the seed) make the fields
// findable, exactly as sites C1/C2 do in the real cov_xfield log; without
// them nothing in the log carries a verbatim field value and no variable
// is discovered (BuildSystem pass 1, src/concolic/concolic.cpp:225-228).
// The LAST record of each list is the record that BuildSystem would make
// the target (src/concolic/concolic.cpp:255).
//
// Reading the Kind of a side off the built path only works while the
// record survives: a record whose BOTH sides are kConst is DROPPED
// (src/concolic/concolic.cpp:244-247) and never appears in the path. So
// the Kinds are read off a PROBE system instead — the same record list
// plus one appended record pairing the value under test with a verbatim
// field value, which always binds and therefore keeps the probe record in
// the path. The probe adds no value that pass 1 did not already see, so
// the variable set — and with it every classification — is unchanged.
//
// Each cell prints one `UNSAT-ANATOMY-CELL` line to stdout so the raw
// ctest output is the measurement table itself.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUle = 3, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr std::uint32_t kProbeSite = 99;

// Two u32 fields, little-endian, offsets 0 and 4. Every byte is non-zero
// and no 4-byte window repeats, so no constant used below is accidentally
// findable as a substring (that would silently turn a constant into a
// variable and forge the cell's verdict).
constexpr std::uint32_t kFieldA = 0x11223344U;
constexpr std::uint32_t kFieldB = 0x55667788U;

// Guard bound: below both fields and absent from the seed.
constexpr std::uint32_t kLow = 0x01010101U;

// Two constants that are neither a substring of the seed nor the sum of
// any field pair (2a = 0x22446688, a + b = 0x6688AACC, 2b = 0xAACCEF10),
// so BindOperand must degrade both to kConst.
constexpr std::uint32_t kConstLhs = 0x0000002AU;
constexpr std::uint32_t kConstRhs = 0x00000037U;

// A constant above the guard bound: an `a == kFar` target inverts into a
// requirement the guards do not contradict.
constexpr std::uint32_t kFar = 0x33445566U;

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

std::vector<BranchReader::Record> Guards() {
    return {
        {0, kUgt, 32, kFieldA, kLow},
        {1, kUgt, 32, kFieldB, kLow},
    };
}

const char* KindName(Operand::Kind kind) {
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

const char* OutcomeName(SolveOutcome outcome) {
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

// One measured cell of the anatomy.
struct Cell {
    std::size_t num_records = 0;                     ///< records handed to BuildSystem
    std::size_t path_size = 0;                       ///< constraints that survived binding
    std::size_t num_vars = 0;                        ///< variables discovered by pass 1
    std::size_t dropped = 0;                         ///< records - path_size
    bool last_record_dropped = false;                ///< was the intended target dropped?
    Operand::Kind lhs_kind = Operand::Kind::kConst;  ///< last record, lhs
    Operand::Kind rhs_kind = Operand::Kind::kConst;  ///< last record, rhs
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
};

// Classify one logged operand value exactly as BuildSystem would, without
// perturbing the variable set (see the file header): append a probe record
// that pairs the value with `anchor` — a verbatim field value, which
// always binds to a variable and so keeps the probe record out of the
// both-sides-const drop.
Operand::Kind ProbeKind(const std::vector<std::uint8_t>& seed,
                        const std::vector<BranchReader::Record>& records, std::uint64_t value,
                        std::uint8_t bit_width, std::uint64_t anchor, bool value_on_lhs) {
    const std::size_t base = BuildSystem(seed, records).path.size();
    std::vector<BranchReader::Record> probe = records;
    probe.push_back(
        {kProbeSite, kEq, bit_width, value_on_lhs ? value : anchor, value_on_lhs ? anchor : value});

    const System sys = BuildSystem(seed, probe);
    if (sys.path.size() != base + 1) {
        ADD_FAILURE() << "probe record did not survive — the anchor 0x" << std::hex << anchor
                      << std::dec << " does not bind, so this probe measures nothing";
        return Operand::Kind::kConst;
    }
    const mlfuzzz3::solver::Constraint& probed = sys.path.back();
    return value_on_lhs ? probed.lhs.kind : probed.rhs.kind;
}

// Measure one system shape. `anchor` must be a value that is verbatim
// present in `seed` at the last record's `bit_width` (the probe's pivot).
Cell Measure(const char* id, const char* form, const std::vector<std::uint8_t>& seed,
             const std::vector<BranchReader::Record>& records, std::uint64_t anchor) {
    const BranchReader::Record& last = records.back();
    const System sys = BuildSystem(seed, records);

    Cell cell;
    cell.num_records = records.size();
    cell.path_size = sys.path.size();
    cell.num_vars = sys.num_vars;
    cell.dropped = records.size() - sys.path.size();
    cell.lhs_kind = ProbeKind(seed, records, last.lhs, last.bit_width, anchor, true);
    cell.rhs_kind = ProbeKind(seed, records, last.rhs, last.bit_width, anchor, false);

    // The drop rule (src/concolic/concolic.cpp:244-247) applied to the
    // probed Kinds. Not taken on faith: when the last record is predicted
    // to survive, the target constraint must carry exactly those Kinds —
    // and that cross-check is what pins the rule.
    cell.last_record_dropped =
        cell.lhs_kind == Operand::Kind::kConst && cell.rhs_kind == Operand::Kind::kConst;
    if (!cell.last_record_dropped && !sys.path.empty()) {
        const mlfuzzz3::solver::Constraint& target = sys.path[sys.target_index];
        EXPECT_EQ(target.lhs.kind, cell.lhs_kind);
        EXPECT_EQ(target.rhs.kind, cell.rhs_kind);
        EXPECT_EQ(target.bit_width, last.bit_width);
    }

    cell.has_candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome).has_value();

    std::cout << "UNSAT-ANATOMY-CELL cell=" << id << " form=" << form
              << " records=" << cell.num_records << " path=" << cell.path_size
              << " vars=" << cell.num_vars << " dropped=" << cell.dropped
              << " last_record_dropped=" << (cell.last_record_dropped ? 1 : 0)
              << " lhs=" << KindName(cell.lhs_kind) << " rhs=" << KindName(cell.rhs_kind)
              << " outcome=" << OutcomeName(cell.outcome)
              << " candidate=" << (cell.has_candidate ? 1 : 0) << '\n';
    return cell;
}

}  // namespace

// CELL (a) — both sides kVar. The baseline: two verbatim fields compared
// with each other, nothing derived, nothing degenerate. Inverting
// `a <u b` into `a >=u b` leaves both guards satisfiable, so this shape
// is solvable and no amount of it can produce the observed 713/717.
TEST(UnsatAnatomy, BothSidesVarIsSolvable) {
    const std::vector<std::uint8_t> seed = Seed();
    std::vector<BranchReader::Record> records = Guards();
    records.push_back({2, kUle, 32, kFieldA, kFieldB});

    const Cell cell = Measure("a", "var-vs-var", seed, records, kFieldA);

    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kVar);
    EXPECT_FALSE(cell.last_record_dropped);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.num_vars, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
}

// CELL (b) — both sides kConst in the LAST record. This is the suspicion
// task-024 was opened to test: if both sides of the inverted record
// degenerated to literals (ADR 0047, src/concolic/concolic.cpp:206), the
// negation would be `0x2A == 0x37` — unsatisfiable by construction,
// independent of the target.
//
// MEASURED: it is not unsatisfiable, because the record never reaches the
// solver. The drop rule fires first (src/concolic/concolic.cpp:244-247),
// the path loses the record, the last surviving GUARD silently becomes
// the target, and the call reports kCandidate for a branch nobody asked
// about. So a degenerate-const target cannot account for kUnsat at all —
// it is invisible in the unsat counter and shows up as a wasted candidate
// instead. Same hazard as tests/unit/concolic/test_domain_map.cpp:169.
TEST(UnsatAnatomy, BothSidesConstIsDroppedNotUnsat) {
    const std::vector<std::uint8_t> seed = Seed();
    std::vector<BranchReader::Record> records = Guards();
    records.push_back({2, kEq, 32, kConstLhs, kConstRhs});

    const Cell cell = Measure("b", "const-vs-const-last", seed, records, kFieldA);

    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_TRUE(cell.last_record_dropped);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.dropped, 1U);
    EXPECT_EQ(cell.num_vars, 2U);
    EXPECT_NE(cell.outcome, SolveOutcome::kUnsat);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);

    // The target really is the surviving guard, not the intended record.
    const System sys = BuildSystem(seed, records);
    ASSERT_EQ(sys.path.size(), 2U);
    EXPECT_EQ(sys.target_index, 1U);
    EXPECT_EQ(sys.path[1].rhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(sys.path[1].rhs.const_value, kLow);
}

// CELL (c) — one side kConst, one side kVar. The mixed shape survives the
// drop rule and is the ordinary case: `a == kFar` inverts to a demand on
// a single free variable, which the guards do not contradict because kFar
// is above the guard bound. Solvable, so the Kind pair alone does not
// predict unsat — cell (f) has the same pair and is unsat.
TEST(UnsatAnatomy, VarVsConstIsSolvableWhenTheConstantIsInRange) {
    const std::vector<std::uint8_t> seed = Seed();
    std::vector<BranchReader::Record> records = Guards();
    records.push_back({2, kEq, 32, kFieldA, kFar});

    const Cell cell = Measure("c", "var-vs-const", seed, records, kFieldA);

    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.last_record_dropped);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// CELL (d) — the degenerate record is NOT last: it sits between the
// guards and a solvable var-vs-var gate. MEASURED: position does not
// matter to the drop rule, the record disappears from the middle of the
// path (4 records in, 3 constraints out) and the intended last record
// stays the target. The only trace of the loss is `path.size()`, which no
// caller of SolveForCandidate ever sees — the metric counters
// (concolic_unsat / concolic_candidates) cannot distinguish a system that
// kept every record from one that silently lost half of them.
TEST(UnsatAnatomy, DegenerateRecordInTheMiddleIsDroppedSilently) {
    const std::vector<std::uint8_t> seed = Seed();
    std::vector<BranchReader::Record> records = Guards();
    records.push_back({2, kEq, 32, kConstLhs, kConstRhs});
    records.push_back({3, kUle, 32, kFieldA, kFieldB});

    const Cell cell = Measure("d", "const-vs-const-middle", seed, records, kFieldA);

    EXPECT_EQ(cell.num_records, 4U);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.dropped, 1U);
    EXPECT_FALSE(cell.last_record_dropped);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);

    // The surviving target is the gate (both sides variables), and the
    // dropped record left no marker between the guards and the gate.
    const System sys = BuildSystem(seed, records);
    ASSERT_EQ(sys.path.size(), 3U);
    EXPECT_EQ(sys.target_index, 2U);
    EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path[2].rhs.kind, Operand::Kind::kVar);
}

// CELL (e) — aliasing. Two records read two DIFFERENT input fields that
// happen to hold the SAME value; FindFirst returns the first occurrence
// (src/concolic/concolic.cpp:136-166), so both bind to the offset-0
// variable and the second field vanishes as an independent unknown. The
// guard on the first field then applies to the second, and inverting the
// second record demands a value the guard forbids: kUnsat, produced
// entirely by the reconstruction, with no contradiction in the program.
//
// The contrast run pins that it really is the aliasing: the same record
// shapes over a seed whose two fields differ keep two variables and solve.
TEST(UnsatAnatomy, AliasedOffsetsMakeIndependentRecordsContradictory) {
    constexpr std::uint32_t kGuardLow = 0x10000000U;
    constexpr std::uint32_t kSmall = 0x00000005U;

    // Aliased: field at offset 4 holds the same value as field at offset 0.
    const std::vector<std::uint8_t> aliased_seed = SeedOf(kFieldA, kFieldA);
    const std::vector<BranchReader::Record> aliased = {
        {0, kUgt, 32, kFieldA, kGuardLow},
        {1, kEq, 32, kFieldA, kSmall},
    };
    const Cell cell = Measure("e", "aliased-offsets", aliased_seed, aliased, kFieldA);

    EXPECT_EQ(cell.num_vars, 1U);  // two fields, one variable
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_FALSE(cell.last_record_dropped);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.outcome, SolveOutcome::kUnsat);
    EXPECT_FALSE(cell.has_candidate);

    // Same shapes, distinct field values: two variables, no contradiction.
    const std::vector<std::uint8_t> distinct_seed = Seed();
    const std::vector<BranchReader::Record> distinct = {
        {0, kUgt, 32, kFieldA, kGuardLow},
        {1, kEq, 32, kFieldB, kSmall},
    };
    const Cell control = Measure("e-control", "distinct-offsets", distinct_seed, distinct, kFieldA);

    EXPECT_EQ(control.num_vars, 2U);
    EXPECT_EQ(control.path_size, 2U);
    EXPECT_EQ(control.outcome, SolveOutcome::kCandidate);
}

// CELL (f) — width overflow on inversion. An 8-bit record `x <=u 0xFF` is
// TRUE on the seed and is kept as taken; the variable's width is the max
// width of the constraints referencing it (src/solver/solver_facade.h
// SolveInverted), here 8. Inverting the target asks for `x >u 0xFF` at 8
// bits — a value that does not exist in the variable's range. kUnsat,
// again produced by the encoding rather than by the program: the branch
// is simply unreachable-by-inversion at that width.
//
// The contrast run moves the bound off the width boundary (0x7F) and the
// identical shape solves — so the cause is the width, not the predicate
// and not the kVar/kConst pair (which cell (c) shares while solving).
TEST(UnsatAnatomy, InversionPastTheWidthBoundaryIsUnsat) {
    const std::vector<std::uint8_t> seed = Seed();
    const auto kByte = static_cast<std::uint8_t>(kFieldA);  // seed[0] == 0x44
    constexpr std::uint64_t kWidthMax = 0xFFU;
    constexpr std::uint64_t kInRange = 0x7FU;

    const std::vector<BranchReader::Record> saturated = {
        {0, kUle, 8, kByte, kWidthMax},
    };
    const Cell cell = Measure("f", "width-boundary-8bit", seed, saturated, kByte);

    EXPECT_EQ(cell.num_vars, 1U);
    EXPECT_EQ(cell.path_size, 1U);
    EXPECT_FALSE(cell.last_record_dropped);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.outcome, SolveOutcome::kUnsat);
    EXPECT_FALSE(cell.has_candidate);

    // Same shape, bound inside the range: solvable.
    const std::vector<BranchReader::Record> in_range = {
        {0, kUle, 8, kByte, kInRange},
    };
    const Cell control = Measure("f-control", "in-range-8bit", seed, in_range, kByte);

    EXPECT_EQ(control.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(control.rhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(control.outcome, SolveOutcome::kCandidate);
}
