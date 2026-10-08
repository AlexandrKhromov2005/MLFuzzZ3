#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

// FALSE SUCCESS of the solver (task-048, ADR 0035). task-044 measured ONE
// cell of a mode nobody in the series had named before: the target record
// is dropped in BuildSystem because both of its sides collapsed to kConst
// (src/concolic/concolic.cpp:244-247), the last SURVIVING record silently
// becomes the target (concolic.cpp:253-254), and SolveForCandidate reports
// kCandidate for a branch that is not the gate the caller was inverting
// for. The observation is pinned by
// DomainArity.K3GateDroppedSolveSucceedsOnForeignConstraint
// (tests/unit/concolic/test_domain_arity.cpp).
//
// One cell says nothing about how WIDE the mode is, and the width costs
// money: an outcome of kCandidate is booked as useful work, while success
// on a foreign branch buys no coverage of the target gate at all. This
// file MEASURES the width on a 3x3 grid and changes nothing under src/.
//
// The grid.
//   Axis A — WHY the target record is dropped (three different roads to
//   the same both-sides-kConst condition):
//     * kArity      — `f0 + f1 + f2 == MAGIC`. Three addends; BindOperand
//                     enumerates PAIRS only (concolic.cpp:195-205), so the
//                     logged sum falls through to MakeConst.
//     * kDifference — `f0 - f1 == MAGIC`. A gate over a DIFFERENCE; the
//                     form axis of the domain map records subtraction as
//                     out of domain (docs/experiments/solver-domain-map/report.md:138).
//     * kLiteral    — `LIT_A == LIT_B`. Neither side is findable in the
//                     seed, so neither side can bind to anything.
//   Axis B — what ELSE is in the path (foreign records, i.e. records that
//   are not the target gate): zero, one, two. Every foreign record used
//   here survives binding AND is satisfiable when inverted, so it is a
//   candidate target the moment the real gate falls out.
//
// FALSE SUCCESS is defined operationally, and the definition is the whole
// point of the file: a cell is a false success if and only if
// SolveForCandidate RETURNED a candidate AND back-substituting that
// candidate into the TARGET gate leaves the gate NOT taken. Both halves
// are measured, neither is inferred from the outcome enum.
//
// The zero-foreign column is a built-in control: with no other record in
// the list, dropping the target empties sys.path, sys.invertible is false
// and SolveForCandidate cannot return anything at all. A false success
// there would mean the harness is broken, not that the mode is wide.
// PositiveControlGateTakenIsObservable is the control in the other
// direction: it keeps the same seed, the same foreign records and the same
// back-substitution oracle, changes only the gate to one that IS in
// domain, and shows the oracle reporting gate_taken=true. Without it,
// "gate_taken=0 in every cell" would be unfalsifiable.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr unsigned kWidth = 32;
constexpr unsigned kFieldCount = 3;
constexpr unsigned kFieldBytes = 4;

using Fields = std::array<std::uint32_t, kFieldCount>;

// Three u32 fields, little-endian, at offsets 0/4/8. Same values as the
// arity fixture (tests/unit/concolic/test_domain_arity.cpp) so the
// task-044 cell can be reproduced verbatim below. No byte is 0x00, 0x2A,
// 0x37 or 0x01, and no 4-byte window repeats.
constexpr Fields kFields = {0x11223344U, 0x55667788U, 0x99AABBCCU};

// Guard bound, gate magic and the two gate literals. None of them is
// findable in the seed and none is the sum of a field pair, so BindOperand
// can only ever make a kConst of them. FixtureConstantsAreNotFindable
// asserts this instead of trusting the comment.
constexpr std::uint32_t kLow = 0x01010101U;
constexpr std::uint32_t kMagic = 0x2A2A2A2AU;
constexpr std::uint32_t kLiteralLhs = 0x37373737U;
constexpr std::uint32_t kLiteralRhs = 0x2A2A2A2AU;

// The magic of the foreign, still-solvable k=2 record of task-044.
constexpr std::uint32_t kMagicForeign = 0x37373737U;

std::vector<std::uint8_t> SeedOfFields() {
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(kFieldBytes) * kFieldCount);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            seed[(kFieldBytes * i) + b] = static_cast<std::uint8_t>(kFields[i] >> (8U * b));
        }
    }
    return seed;
}

// Read the fields back out of a solved candidate under exactly the
// encoding the bindings used (u32, little-endian, offsets 0/4/8). This is
// the back-substitution the gate oracle runs on.
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

enum class Reason { kArity, kDifference, kLiteral };

const char* NameOf(Reason reason) {
    switch (reason) {
        case Reason::kArity:
            return "arity-k3";
        case Reason::kDifference:
            return "difference";
        case Reason::kLiteral:
            return "literal-both-sides";
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

const char* NameOf(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kAddVars:
            return "kAddVars";
        case Operand::Kind::kConst:
            return "kConst";
    }
    return "?";
}

// The value the runtime would log on the LHS of each gate form, computed
// on the seed with C wrap-around.
std::uint32_t LhsOnSeed(Reason reason) {
    switch (reason) {
        case Reason::kArity:
            return kFields[0] + kFields[1] + kFields[2];
        case Reason::kDifference:
            return kFields[0] - kFields[1];
        case Reason::kLiteral:
            return kLiteralLhs;
    }
    return 0;
}

std::uint32_t RhsOnSeed(Reason reason) {
    return reason == Reason::kLiteral ? kLiteralRhs : kMagic;
}

// The target gate record. Its site_id is deliberately the largest in the
// list so that, had it survived, BuildSystem would have elected it as the
// inversion target (it is appended last).
BranchReader::Record TargetRecord(Reason reason) {
    return {90, kEq, kWidth, LhsOnSeed(reason), RhsOnSeed(reason)};
}

// Is the TARGET gate satisfied by these field values? This is the oracle
// that separates "the solver returned something" from "the solver took
// the gate". For kLiteral neither side is a function of the input, so the
// gate's truth is whatever it was on the seed no matter what comes back —
// that is the measured fact of that row, not a shortcut in the harness.
bool GateHolds(Reason reason, const Fields& v) {
    switch (reason) {
        case Reason::kArity:
            return static_cast<std::uint32_t>(v[0] + v[1] + v[2]) == kMagic;
        case Reason::kDifference:
            return static_cast<std::uint32_t>(v[0] - v[1]) == kMagic;
        case Reason::kLiteral:
            return LhsOnSeed(Reason::kLiteral) == RhsOnSeed(Reason::kLiteral);
    }
    return false;
}

// `count` foreign records, each of which binds (so it survives pass 2) and
// is satisfiable when inverted (so it can carry a "success"):
//   * #1 `f0 >u f1`  — FALSE on the seed, both sides bind to fields;
//                      discovers vars 0 and 1.
//   * #2 `f2 >u LOW` — TRUE on the seed, LHS binds to a field, RHS is an
//                      unfindable constant; discovers var 2.
std::vector<BranchReader::Record> ForeignRecords(unsigned count) {
    std::vector<BranchReader::Record> out;
    if (count >= 1) {
        out.push_back({10, kUgt, kWidth, kFields[0], kFields[1]});
    }
    if (count >= 2) {
        out.push_back({11, kUgt, kWidth, kFields[2], kLow});
    }
    return out;
}

std::vector<BranchReader::Record> RecordsFor(Reason reason, unsigned foreign) {
    std::vector<BranchReader::Record> recs = ForeignRecords(foreign);
    recs.push_back(TargetRecord(reason));
    return recs;
}

// One measured cell of the grid.
struct Cell {
    Reason reason;
    unsigned foreign;       ///< foreign records submitted alongside the gate
    std::size_t num_vars;   ///< fields discovered in pass 1
    std::size_t path_size;  ///< records that survived into sys.path
    bool gate_survived;     ///< did the TARGET record reach sys.path?
    bool invertible;        ///< sys.invertible for the whole list
    SolveOutcome outcome;   ///< what SolveForCandidate reported
    bool has_candidate;     ///< did the call hand back an input?
    bool gate_on_seed;      ///< was the target gate taken on the seed?
    bool gate_taken;        ///< is it taken after back-substitution?
    bool false_success;     ///< candidate returned AND gate not taken
};

Cell Measure(Reason reason, unsigned foreign) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    const std::vector<BranchReader::Record> recs = RecordsFor(reason, foreign);
    const System sys = BuildSystem(seed, recs);

    Cell cell{};
    cell.reason = reason;
    cell.foreign = foreign;
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == recs.size();
    cell.invertible = sys.invertible;

    cell.outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, recs, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();

    Fields on_seed{};
    for (unsigned i = 0; i < kFieldCount; ++i) {
        on_seed[i] = kFields[i];
    }
    cell.gate_on_seed = GateHolds(reason, on_seed);
    cell.gate_taken = candidate.has_value() && GateHolds(reason, FieldsOfCandidate(*candidate));
    cell.false_success = cell.has_candidate && !cell.gate_taken;
    return cell;
}

// Read the Kind BindOperand gives one side of the target gate. A form
// whose two sides both collapse to kConst is dropped and leaves nothing to
// observe, so each side is probed on a system where the OTHER side is
// deliberately bindable; BindOperand classifies the sides independently
// (concolic.cpp:240-243), so the probe reports the Kind the real form
// produced.
Operand::Kind ProbeKind(Reason reason, bool want_lhs) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    std::vector<BranchReader::Record> probe = ForeignRecords(2);
    const std::uint64_t bindable = kFields[0];
    probe.push_back({91, kEq, kWidth, want_lhs ? LhsOnSeed(reason) : bindable,
                     want_lhs ? bindable : RhsOnSeed(reason)});
    const System sys = BuildSystem(seed, probe);
    if (sys.path.size() != probe.size()) {
        ADD_FAILURE() << "probe record was dropped for reason=" << NameOf(reason)
                      << " — the probe fixture itself is broken, the Kind is not measured";
        return Operand::Kind::kConst;
    }
    return want_lhs ? sys.path.back().lhs.kind : sys.path.back().rhs.kind;
}

constexpr std::array<Reason, 3> kReasons = {Reason::kArity, Reason::kDifference, Reason::kLiteral};

}  // namespace

// ---------------------------------------------------------------- fixture

// Not one constant of the fixture may be findable in the seed: a findable
// constant would bind through the DIRECT branch of BindOperand and forge
// an "in domain" verdict that has nothing to do with the axis under test.
// Both sides of the probe are the same unfindable value, so a bound
// constant would keep the record alive; seeing only the two foreign
// records proves the value bound to nothing.
TEST(FalseSuccess, FixtureConstantsAreNotFindable) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    for (const std::uint32_t value : {kLow, kMagic, kLiteralLhs, kLiteralRhs, kMagicForeign,
                                      LhsOnSeed(Reason::kArity), LhsOnSeed(Reason::kDifference)}) {
        SCOPED_TRACE(testing::Message() << "constant=" << value);
        std::vector<BranchReader::Record> probe = ForeignRecords(2);
        probe.push_back({92, kEq, kWidth, value, value});
        EXPECT_EQ(BuildSystem(seed, probe).path.size(), std::size_t{2});
    }
}

// The composition axis must move only ONE thing: how many foreign records
// are in the path. This pins what each column discovers, so a cell that
// reports "kConst" cannot be quietly explained away by a missing var.
TEST(FalseSuccess, FixtureDiscoversExpectedVars) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    const std::array<std::size_t, 3> expected = {0, 2, 3};
    for (unsigned foreign = 0; foreign <= 2; ++foreign) {
        SCOPED_TRACE(testing::Message() << "foreign=" << foreign);
        const System sys = BuildSystem(seed, ForeignRecords(foreign));
        EXPECT_EQ(sys.num_vars, expected[foreign]);
        EXPECT_EQ(sys.path.size(), std::size_t{foreign});
        for (std::size_t i = 0; i < sys.num_vars; ++i) {
            EXPECT_EQ(sys.vars[i].offset, kFieldBytes * i);
            EXPECT_EQ(sys.vars[i].bit_width, kWidth);
            EXPECT_FALSE(sys.vars[i].big_endian);
        }
    }
}

// Every foreign record must SURVIVE and be satisfiable when inverted;
// otherwise the composition axis measures the foreign records' own
// fragility rather than the gate's.
TEST(FalseSuccess, ForeignRecordsAreSolvableOnTheirOwn) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    for (unsigned foreign = 1; foreign <= 2; ++foreign) {
        SCOPED_TRACE(testing::Message() << "foreign=" << foreign);
        const std::vector<BranchReader::Record> recs = ForeignRecords(foreign);
        const System sys = BuildSystem(seed, recs);
        ASSERT_EQ(sys.path.size(), recs.size());
        EXPECT_TRUE(sys.invertible);
        SolveOutcome outcome = SolveOutcome::kError;
        const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
            SolveForCandidate(seed, recs, kTimeoutMs, &outcome);
        EXPECT_EQ(outcome, SolveOutcome::kCandidate);
        EXPECT_TRUE(candidate.has_value());
    }
}

// All three reasons must actually reach the SAME drop condition — both
// sides kConst (concolic.cpp:244-247) — or the axis is not what it claims.
TEST(FalseSuccess, EveryReasonCollapsesBothSidesToConst) {
    for (const Reason reason : kReasons) {
        const Operand::Kind lhs = ProbeKind(reason, true);
        const Operand::Kind rhs = ProbeKind(reason, false);
        SCOPED_TRACE(testing::Message() << "reason=" << NameOf(reason) << " lhs=" << NameOf(lhs)
                                        << " rhs=" << NameOf(rhs));
        EXPECT_EQ(lhs, Operand::Kind::kConst);
        EXPECT_EQ(rhs, Operand::Kind::kConst);
    }
}

// None of the three gates is taken on the seed. If one already held, its
// "gate not taken after solving" would be a statement about the fixture,
// not about the solver.
TEST(FalseSuccess, NoTargetGateHoldsOnTheSeed) {
    Fields on_seed{};
    for (unsigned i = 0; i < kFieldCount; ++i) {
        on_seed[i] = kFields[i];
    }
    for (const Reason reason : kReasons) {
        SCOPED_TRACE(testing::Message() << "reason=" << NameOf(reason));
        EXPECT_FALSE(GateHolds(reason, on_seed));
    }
}

// ------------------------------------------------------------- the 3x3 grid

// Column 0 — the CONTROL. With no foreign record the dropped gate leaves
// sys.path empty, sys.invertible is false and SolveForCandidate reports
// kNoBinding without a candidate. False success is impossible here by
// construction; if one appears, the harness is broken, not the mode wide.
TEST(FalseSuccess, ArityDropNoForeignRecords) {
    const Cell cell = Measure(Reason::kArity, 0);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 0U);
    EXPECT_FALSE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kNoBinding);
    EXPECT_FALSE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_FALSE(cell.false_success);
}

TEST(FalseSuccess, DifferenceDropNoForeignRecords) {
    const Cell cell = Measure(Reason::kDifference, 0);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 0U);
    EXPECT_FALSE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kNoBinding);
    EXPECT_FALSE(cell.has_candidate);
    EXPECT_FALSE(cell.false_success);
}

TEST(FalseSuccess, LiteralDropNoForeignRecords) {
    const Cell cell = Measure(Reason::kLiteral, 0);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 0U);
    EXPECT_FALSE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kNoBinding);
    EXPECT_FALSE(cell.has_candidate);
    EXPECT_FALSE(cell.false_success);
}

// Column 1 — one foreign record. The gate falls out, the foreign record is
// elected target by default, the call reports kCandidate, and the returned
// input does not satisfy the gate. This is the task-044 mode.
TEST(FalseSuccess, ArityDropOneForeignRecord) {
    const Cell cell = Measure(Reason::kArity, 1);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 1U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_TRUE(cell.false_success);
}

TEST(FalseSuccess, DifferenceDropOneForeignRecord) {
    const Cell cell = Measure(Reason::kDifference, 1);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 1U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_TRUE(cell.false_success);
}

TEST(FalseSuccess, LiteralDropOneForeignRecord) {
    const Cell cell = Measure(Reason::kLiteral, 1);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 1U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_TRUE(cell.false_success);
}

// Column 2 — two foreign records. Nothing about the gate changed; only the
// number of survivors did.
TEST(FalseSuccess, ArityDropTwoForeignRecords) {
    const Cell cell = Measure(Reason::kArity, 2);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.num_vars, 3U);  // all three addends ARE bound vars here
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_TRUE(cell.false_success);
}

TEST(FalseSuccess, DifferenceDropTwoForeignRecords) {
    const Cell cell = Measure(Reason::kDifference, 2);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_TRUE(cell.false_success);
}

TEST(FalseSuccess, LiteralDropTwoForeignRecords) {
    const Cell cell = Measure(Reason::kLiteral, 2);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
    EXPECT_TRUE(cell.false_success);
}

// ------------------------------------------------------------- the controls

// The oracle must be able to say YES. Same seed, same foreign records,
// same back-substitution — only the gate changes to `f0 == MAGIC`, which
// IS in domain (a direct field on the LHS). The gate survives, is elected
// as the target, and the returned candidate satisfies it.
TEST(FalseSuccess, PositiveControlGateTakenIsObservable) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    std::vector<BranchReader::Record> recs = ForeignRecords(2);
    recs.push_back({90, kEq, kWidth, kFields[0], kMagic});

    const System sys = BuildSystem(seed, recs);
    ASSERT_EQ(sys.path.size(), recs.size());  // the gate survived
    EXPECT_EQ(sys.path.back().lhs.kind, Operand::Kind::kVar);
    EXPECT_EQ(sys.path.back().rhs.kind, Operand::Kind::kConst);
    ASSERT_EQ(sys.target_index, sys.path.size() - 1U);

    SolveOutcome outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, recs, kTimeoutMs, &outcome);
    EXPECT_EQ(outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(candidate.has_value());
    EXPECT_EQ(FieldsOfCandidate(*candidate)[0], kMagic);
}

// The task-044 cell, rebuilt record for record (three guards, one solvable
// k=2 foreign record, the k=3 gate last) and measured with THIS file's
// oracle. Its outcome must agree with the accepted
// docs/experiments/solver-domain-arity/report.md:133
// (sat_on_foreign_constraint=yes): candidate returned, gate not taken.
TEST(FalseSuccess, ReproducesTask044ArityCell) {
    const std::vector<std::uint8_t> seed = SeedOfFields();
    std::vector<BranchReader::Record> recs;
    for (unsigned i = 0; i < kFieldCount; ++i) {
        recs.push_back({i, kUgt, kWidth, kFields[i], kLow});
    }
    recs.push_back(
        {3, kEq, kWidth, static_cast<std::uint64_t>(kFields[0] + kFields[1]), kMagicForeign});
    recs.push_back(
        {4, kEq, kWidth, static_cast<std::uint64_t>(kFields[0] + kFields[1] + kFields[2]), kMagic});

    const System sys = BuildSystem(seed, recs);
    ASSERT_EQ(sys.path.size(), recs.size() - 1U);  // the k=3 gate fell out
    EXPECT_TRUE(sys.invertible);
    EXPECT_EQ(sys.path[sys.target_index].rhs.const_value, kMagicForeign);

    SolveOutcome outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, recs, kTimeoutMs, &outcome);
    EXPECT_EQ(outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(candidate.has_value());
    const Fields solved = FieldsOfCandidate(*candidate);
    EXPECT_EQ(static_cast<std::uint32_t>(solved[0] + solved[1]), kMagicForeign);
    EXPECT_NE(static_cast<std::uint32_t>(solved[0] + solved[1] + solved[2]), kMagic);
}

// ------------------------------------------------------------------ table

// The whole grid in one place, so the report quotes measured lines instead
// of retyping them.
TEST(FalseSuccess, MeasuredTableIsEmitted) {
    unsigned candidate_returned = 0;
    unsigned gate_taken = 0;
    unsigned false_success = 0;
    unsigned no_candidate = 0;
    unsigned control_false_success = 0;

    std::cout << "reason             foreign vars path gate_survived outcome     "
                 "candidate gate_taken false_success\n";
    for (const Reason reason : kReasons) {
        for (unsigned foreign = 0; foreign <= 2; ++foreign) {
            const Cell cell = Measure(reason, foreign);
            candidate_returned += cell.has_candidate ? 1U : 0U;
            gate_taken += cell.gate_taken ? 1U : 0U;
            false_success += cell.false_success ? 1U : 0U;
            no_candidate += cell.has_candidate ? 0U : 1U;
            if (foreign == 0 && cell.false_success) {
                ++control_false_success;
            }
            std::cout << NameOf(reason) << " " << foreign << " " << cell.num_vars << " "
                      << cell.path_size << " " << (cell.gate_survived ? "yes" : "no") << " "
                      << NameOf(cell.outcome) << " " << (cell.has_candidate ? "yes" : "no") << " "
                      << (cell.gate_taken ? "yes" : "no") << " "
                      << (cell.false_success ? "yes" : "no") << "\n";
        }
    }

    const double rate = candidate_returned == 0 ? 0.0
                                                : static_cast<double>(false_success) /
                                                      static_cast<double>(candidate_returned);
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "TOTALS cells=9 candidate_returned=" << candidate_returned
              << " gate_taken=" << gate_taken << " false_success=" << false_success
              << " no_candidate=" << no_candidate << " false_success_rate=" << rate
              << " control_cells_clean=" << (control_false_success == 0 ? "yes" : "no") << "\n";

    EXPECT_EQ(candidate_returned, 6U);
    EXPECT_EQ(gate_taken, 0U);
    EXPECT_EQ(false_success, 6U);
    EXPECT_EQ(no_candidate, 3U);
    EXPECT_EQ(control_false_success, 0U);
}
