#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

// Predicate axis of the solver domain (task-052, ADR 0035 §2). Five axes
// of the domain map are already measured (form, width, endianness, arity,
// which side carries the literal) and every one of them describes the
// OPERANDS. This file measures the axis nobody touched: the comparison
// byte itself.
//
// What BuildSystem does with it. Each record is encoded as its AS-TAKEN
// path conjunct — the logged predicate is kept when the comparison was
// TRUE on the seed and replaced by its negation when it was FALSE
// (src/concolic/concolic.cpp:248-249). The negation is a ten-entry table
// over CmpKind (src/concolic/concolic.cpp:88-113); truth is decided by
// EvalPredicate, whose signed cases go through SignExtend
// (src/concolic/concolic.cpp:72-79). The whole series so far ran on kEq
// and kUlt — two predicates out of ten.
//
// The grid. Ten CmpKind values × two positions (comparison TRUE / FALSE
// on the seed) = 20 cells, plus two cells whose predicate byte is outside
// the ABI (10 and 255). Only the predicate byte and the truth position
// vary; the seed is one and the same eight bytes throughout.
//
// The truth position is set by choosing which fields the gate compares,
// never by changing the seed:
//   AB — gate is `a <op> b`,  a at offset 0, b at offset 4;
//   BA — gate is `b <op> a`,  the same two fields, swapped;
//   AA — gate is `a <op> a`,  both sides bind to the SAME variable.
// Swapping the operands flips all eight order predicates, which covers
// both positions for them on ONE operand pair. Equality is the exception:
// `a == b` is false in both orders, so kEq's TRUE cell (and kNe's FALSE
// cell) can only be produced by comparing a field with itself. That is
// not a fixture defect — an equality that already holds on the seed
// necessarily has the same value on both sides, and this binder maps
// equal values to one variable (BindOperand, src/concolic/concolic.cpp:185).
// The consequence is measured, not hidden: those cells encode `v0 == v0`,
// whose inversion is unsatisfiable by construction.
//
// The operands are chosen so that the signed and unsigned readings
// DISAGREE: a = 0x80000001 is a large unsigned value and a negative
// signed one. Comparing the kSlt/kSle/kSgt/kSge quadruple with the
// kUlt/kUle/kUgt/kUge quadruple on exactly these operands is what makes
// `signed_differs_from_unsigned` an answer rather than an absence of
// evidence.
//
// The oracles below (Truth, ExpectedNegation) are written out from the
// ABI (src/runtime/coverage/mlfuzzz3_branch.h:41-52) INDEPENDENTLY of the
// implementation, so a cell that agrees is a real agreement and not a
// tautology.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033; the enum in concolic.cpp is in an
// anonymous namespace and cannot be imported).
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

// Two predicate bytes the ABI does not define. 10 is the first free value
// (the "off by one past the end" mistake a future ABI extension would
// make); 255 is the saturated byte a corrupted log would carry.
enum : std::uint8_t { kOutOfAbiNext = 10, kOutOfAbiMax = 255 };

constexpr std::uint8_t kWidth = 32;
constexpr unsigned kTimeoutMs = 5000;
constexpr std::size_t kFieldBytes = 4;

// Field a has its top bit set: unsigned it is 2147483649, signed it is
// -2147483647. Field b is positive under both readings. Every signed
// order predicate therefore disagrees with its unsigned twin on this
// pair, which is exactly what the signed/unsigned comparison needs.
constexpr std::uint32_t kFieldA = 0x80000001U;
constexpr std::uint32_t kFieldB = 0x11223344U;

// Guard bound: below both fields under the UNSIGNED reading (the guards
// use kUgt) and absent from the seed, so it binds as a constant and never
// forges a third variable.
constexpr std::uint32_t kLow = 0x01010101U;

// Seed: a at offset 0, b at offset 4, both little-endian.
std::vector<std::uint8_t> Seed() {
    std::vector<std::uint8_t> seed(2 * kFieldBytes);
    for (unsigned k = 0; k < kFieldBytes; ++k) {
        seed[k] = static_cast<std::uint8_t>(kFieldA >> (8U * k));
        seed[kFieldBytes + k] = static_cast<std::uint8_t>(kFieldB >> (8U * k));
    }
    return seed;
}

std::uint32_t GetU32Le(const std::uint8_t* p) {
    std::uint32_t v = 0;
    for (unsigned k = 0; k < kFieldBytes; ++k) {
        v |= static_cast<std::uint32_t>(p[k]) << (8U * k);
    }
    return v;
}

// ORACLE 1 — truth of a comparison, written from the ABI. Signed cases
// read the 32-bit operands as int32_t; unknown predicates are reported as
// "not decidable", which is a different statement from "false" and keeps
// the out-of-ABI cells from being scored against a made-up expectation.
struct Truth {
    bool value;
    bool decidable;
};

Truth EvalOracle(std::uint8_t predicate, std::uint32_t l, std::uint32_t r) {
    const auto sl = static_cast<std::int32_t>(l);
    const auto sr = static_cast<std::int32_t>(r);
    switch (predicate) {
        case kEq:
            return {l == r, true};
        case kNe:
            return {l != r, true};
        case kUlt:
            return {l < r, true};
        case kUle:
            return {l <= r, true};
        case kUgt:
            return {l > r, true};
        case kUge:
            return {l >= r, true};
        case kSlt:
            return {sl < sr, true};
        case kSle:
            return {sl <= sr, true};
        case kSgt:
            return {sl > sr, true};
        case kSge:
            return {sl >= sr, true};
        default:
            return {false, false};
    }
}

// ORACLE 2 — the negation table, written from the ABI. For a predicate
// the ABI does not define there is no negation, so the oracle says so
// instead of inventing one.
struct Negation {
    std::uint8_t value;
    bool defined;
};

Negation ExpectedNegation(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return {kNe, true};
        case kNe:
            return {kEq, true};
        case kUlt:
            return {kUge, true};
        case kUle:
            return {kUgt, true};
        case kUgt:
            return {kUle, true};
        case kUge:
            return {kUlt, true};
        case kSlt:
            return {kSge, true};
        case kSle:
            return {kSgt, true};
        case kSgt:
            return {kSle, true};
        case kSge:
            return {kSlt, true};
        default:
            return {predicate, false};
    }
}

std::string PredicateName(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return "kEq";
        case kNe:
            return "kNe";
        case kUlt:
            return "kUlt";
        case kUle:
            return "kUle";
        case kUgt:
            return "kUgt";
        case kUge:
            return "kUge";
        case kSlt:
            return "kSlt";
        case kSle:
            return "kSle";
        case kSgt:
            return "kSgt";
        case kSge:
            return "kSge";
        default:
            return "OUT-OF-ABI";
    }
}

std::string PredicateLabel(std::uint8_t predicate) {
    return PredicateName(predicate) + "(" + std::to_string(static_cast<unsigned>(predicate)) + ")";
}

std::string OutcomeName(SolveOutcome outcome) {
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

// Which field slot each side of the gate reads: 0 = the field at offset
// 0, 1 = the field at offset 4.
struct Config {
    const char* name;
    unsigned lhs_slot;
    unsigned rhs_slot;
};

constexpr Config kAB{"AB", 0, 1};
constexpr Config kBA{"BA", 1, 0};
constexpr Config kAA{"AA", 0, 0};

std::uint32_t SlotValue(unsigned slot) {
    return slot == 0 ? kFieldA : kFieldB;
}

// One measured cell.
struct Cell {
    std::uint8_t predicate_in;
    const char* config;
    bool taken_on_seed;          ///< oracle truth of the gate on the seed
    bool gate_survived;          ///< did the gate record reach sys.path?
    std::size_t path_size;       ///< 2 guards + gate = 3 when it survives
    std::size_t target_index;    ///< which constraint the engine will invert
    std::uint8_t predicate_out;  ///< what landed in sys.path[target_index]
    std::uint8_t expected_out;   ///< what the negation oracle says should be there
    bool expectation_defined;    ///< false only for out-of-ABI bytes
    bool encoding_correct;       ///< predicate_out == expected_out
    SolveOutcome outcome;
    bool has_candidate;
    bool gate_on_seed;
    bool gate_on_candidate;
    bool gate_on_candidate_known;
    bool flipped;
};

// The two guards make both fields findable by offset, exactly as sites
// C1/C2 do in the real cov_xfield log; without them nothing in the log
// carries a verbatim field value and no variable is discovered at all
// (BuildSystem pass 1, src/concolic/concolic.cpp:225-228). Both guards
// are TRUE on the seed, so they contribute themselves unnegated and never
// compete with the gate for the target slot.
std::vector<BranchReader::Record> Guards() {
    return {
        {0, kUgt, kWidth, kFieldA, kLow},
        {1, kUgt, kWidth, kFieldB, kLow},
    };
}

Cell Measure(std::uint8_t predicate, const Config& cfg) {
    const std::vector<std::uint8_t> seed = Seed();
    const std::uint32_t lhs_value = SlotValue(cfg.lhs_slot);
    const std::uint32_t rhs_value = SlotValue(cfg.rhs_slot);

    std::vector<BranchReader::Record> records = Guards();
    records.push_back({2, predicate, kWidth, lhs_value, rhs_value});

    const System sys = BuildSystem(seed, records);

    Cell cell{};
    cell.predicate_in = predicate;
    cell.config = cfg.name;

    const Truth truth = EvalOracle(predicate, lhs_value, rhs_value);
    cell.taken_on_seed = truth.value;
    cell.gate_on_seed = truth.value;

    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == records.size();
    cell.target_index = sys.target_index;
    cell.predicate_out =
        sys.path.empty() ? static_cast<std::uint8_t>(0xFEU) : sys.path[sys.target_index].predicate;

    const Negation negation = ExpectedNegation(predicate);
    cell.expectation_defined = negation.defined;
    // Operational definition, fixed BEFORE the numbers: a cell is correct
    // when predicate_out equals predicate_in for a comparison that was
    // TRUE on the seed, and equals the negation-table entry when it was
    // FALSE. For a byte outside the ABI the oracle has no entry; such a
    // cell is scored separately and never counted as "correct".
    const std::uint8_t expected = truth.value ? predicate : negation.value;
    cell.expected_out = expected;
    cell.encoding_correct = negation.defined && truth.decidable && cell.predicate_out == expected;

    cell.outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();

    if (candidate.has_value() && candidate->size() >= seed.size()) {
        const std::array<std::uint32_t, 2> fields = {
            GetU32Le(candidate->data()),
            GetU32Le(candidate->data() + kFieldBytes),
        };
        const Truth after = EvalOracle(predicate, fields[cfg.lhs_slot], fields[cfg.rhs_slot]);
        cell.gate_on_candidate_known = after.decidable;
        cell.gate_on_candidate = after.value;
        cell.flipped = after.decidable && after.value != truth.value;
    }
    return cell;
}

const char* YesNo(bool v) {
    return v ? "yes" : "no";
}

void PrintHeader() {
    std::cout << "\n"
              << "GRID predicate-axis: seed=a@0=0x80000001,b@4=0x11223344 (u32 LE), "
                 "guards=[a >u 0x01010101, b >u 0x01010101]\n"
              << "cfg AB: gate is a <op> b | cfg BA: gate is b <op> a | cfg AA: gate is a <op> a\n";
}

void PrintCell(const Cell& cell) {
    std::cout << "CELL"
              << " pred_in=" << std::setw(11) << std::left << PredicateLabel(cell.predicate_in)
              << " cfg=" << cell.config << " taken_on_seed=" << std::setw(3) << std::left
              << YesNo(cell.taken_on_seed) << " pred_out=" << std::setw(11) << std::left
              << PredicateLabel(cell.predicate_out) << " expected=" << std::setw(11) << std::left
              << (cell.expectation_defined ? PredicateLabel(cell.expected_out)
                                           : std::string("none"))
              << " encoding_correct=" << std::setw(3) << std::left << YesNo(cell.encoding_correct)
              << " gate_survived=" << std::setw(3) << std::left << YesNo(cell.gate_survived)
              << " path_size=" << cell.path_size << " target_index=" << cell.target_index
              << " outcome=" << std::setw(10) << std::left << OutcomeName(cell.outcome)
              << " gate_on_seed=" << std::setw(3) << std::left << YesNo(cell.gate_on_seed)
              << " gate_on_candidate=" << std::setw(3) << std::left
              << (cell.gate_on_candidate_known ? YesNo(cell.gate_on_candidate) : std::string("n/a"))
              << " flipped=" << YesNo(cell.flipped) << "\n";
}

// The grid: for every predicate, the configuration that makes the
// comparison TRUE on the seed and the one that makes it FALSE. Derived
// from the oracle, and re-checked against it in the test below — a wrong
// entry here would silently turn a 10x2 grid into a 10x1 one.
struct Row {
    std::uint8_t predicate;
    Config when_true;
    Config when_false;
};

constexpr std::array<Row, 10> kGrid = {{
    {kEq, kAA, kAB},
    {kNe, kAB, kAA},
    {kUlt, kBA, kAB},
    {kUle, kBA, kAB},
    {kUgt, kAB, kBA},
    {kUge, kAB, kBA},
    {kSlt, kAB, kBA},
    {kSle, kAB, kBA},
    {kSgt, kBA, kAB},
    {kSge, kBA, kAB},
}};

}  // namespace

// Sanity for the fixture itself: the guards alone discover both fields at
// offsets 0 and 4, little-endian, 32 bits. If this breaks, every cell
// below measures something other than what it claims.
TEST(SolverPredicateAxis, FixtureBindsBothFields) {
    const System sys = BuildSystem(Seed(), Guards());
    ASSERT_EQ(sys.num_vars, 2U);
    ASSERT_EQ(sys.vars.size(), 2U);
    EXPECT_EQ(sys.vars[0].offset, 0U);
    EXPECT_EQ(sys.vars[1].offset, kFieldBytes);
    EXPECT_EQ(sys.vars[0].bit_width, kWidth);
    EXPECT_EQ(sys.vars[1].bit_width, kWidth);
    EXPECT_FALSE(sys.vars[0].big_endian);
    EXPECT_FALSE(sys.vars[1].big_endian);
    EXPECT_EQ(sys.path.size(), 2U);
}

// The 20 cells. Every predicate is measured in both positions; the run
// prints one CELL line per cell and the two SUMMARY lines the report
// quotes.
TEST(SolverPredicateAxis, TenPredicatesTwoPositions) {
    PrintHeader();

    unsigned cells = 0;
    unsigned encoding_correct = 0;
    unsigned flipped = 0;
    unsigned survived = 0;

    for (const Row& row : kGrid) {
        const std::array<Config, 2> configs = {row.when_true, row.when_false};
        const std::array<bool, 2> want = {true, false};
        for (unsigned i = 0; i < 2; ++i) {
            const Cell cell = Measure(row.predicate, configs[i]);
            PrintCell(cell);
            ++cells;

            // The grid table must really deliver the position it claims.
            EXPECT_EQ(cell.taken_on_seed, want[i])
                << "grid row " << PredicateName(row.predicate) << " config " << configs[i].name
                << " does not produce the intended truth position";

            // Both sides are verbatim fields, so no record is ever
            // dropped on this axis: the gate always reaches the path and
            // is always the target.
            EXPECT_TRUE(cell.gate_survived);
            EXPECT_EQ(cell.path_size, 3U);
            EXPECT_EQ(cell.target_index, 2U);
            if (cell.gate_survived) {
                ++survived;
            }

            // The as-taken encoding, measured against the independent
            // negation oracle.
            EXPECT_TRUE(cell.encoding_correct)
                << PredicateName(row.predicate) << "/" << configs[i].name
                << ": predicate_out=" << PredicateLabel(cell.predicate_out)
                << " expected=" << PredicateLabel(cell.expected_out);
            if (cell.encoding_correct) {
                ++encoding_correct;
            }
            if (cell.flipped) {
                ++flipped;
            }
        }
    }

    // The AA cells are the two that cannot flip, and the reason is
    // structural rather than predicate-specific: both sides of the gate
    // bind to the SAME variable, so the inverted target is v0 != v0.
    const Cell eq_true = Measure(kEq, kAA);
    EXPECT_EQ(eq_true.outcome, SolveOutcome::kUnsat);
    EXPECT_FALSE(eq_true.has_candidate);
    const Cell ne_false = Measure(kNe, kAA);
    EXPECT_EQ(ne_false.outcome, SolveOutcome::kUnsat);
    EXPECT_FALSE(ne_false.has_candidate);

    std::cout << "SUMMARY predicates=10 cells=" << cells << " gate_survived=" << survived << "/"
              << cells << " encoding_correct=" << encoding_correct << "/" << cells
              << " flipped=" << flipped << "/" << cells << "\n";

    EXPECT_EQ(cells, 20U);
    EXPECT_EQ(encoding_correct, 20U);
    EXPECT_EQ(survived, 20U);
    EXPECT_EQ(flipped, 18U);
}

// Does the domain split signed from unsigned? The four signed order
// predicates are compared with their unsigned twins on THE SAME operands
// (a = 0x80000001, b = 0x11223344), where the two readings genuinely
// disagree. Anything less than this would leave a "no" merely unrefuted.
TEST(SolverPredicateAxis, SignedVersusUnsignedOnTheSameOperands) {
    struct Pair {
        std::uint8_t unsigned_predicate;
        std::uint8_t signed_predicate;
    };
    constexpr std::array<Pair, 4> kPairs = {{
        {kUlt, kSlt},
        {kUle, kSle},
        {kUgt, kSgt},
        {kUge, kSge},
    }};

    unsigned truth_differs = 0;
    unsigned handling_differs = 0;

    for (const Pair& pair : kPairs) {
        const Cell u = Measure(pair.unsigned_predicate, kAB);
        const Cell s = Measure(pair.signed_predicate, kAB);
        std::cout << "PAIR " << PredicateLabel(pair.unsigned_predicate) << " vs "
                  << PredicateLabel(pair.signed_predicate) << " on a=0x80000001,b=0x11223344"
                  << " taken_u=" << YesNo(u.taken_on_seed) << " taken_s=" << YesNo(s.taken_on_seed)
                  << " encoding_correct_u=" << YesNo(u.encoding_correct)
                  << " encoding_correct_s=" << YesNo(s.encoding_correct)
                  << " outcome_u=" << OutcomeName(u.outcome)
                  << " outcome_s=" << OutcomeName(s.outcome) << " flipped_u=" << YesNo(u.flipped)
                  << " flipped_s=" << YesNo(s.flipped) << " survived_u=" << YesNo(u.gate_survived)
                  << " survived_s=" << YesNo(s.gate_survived) << "\n";

        // The operands do split the two readings — otherwise the pair
        // proves nothing.
        EXPECT_NE(u.taken_on_seed, s.taken_on_seed)
            << "operands do not separate signed from unsigned for "
            << PredicateName(pair.unsigned_predicate);
        if (u.taken_on_seed != s.taken_on_seed) {
            ++truth_differs;
        }

        // Handling differs only if the DOMAIN treats them differently:
        // survival, encoding correctness, outcome and flip are what the
        // domain decides; the truth value is the input, not the verdict.
        const bool differs = u.gate_survived != s.gate_survived ||
                             u.encoding_correct != s.encoding_correct || u.outcome != s.outcome ||
                             u.flipped != s.flipped;
        if (differs) {
            ++handling_differs;
        }
    }

    std::cout << "SUMMARY signed_pairs=4 truth_differs=" << truth_differs
              << "/4 handling_differs=" << handling_differs
              << "/4 signed_differs_from_unsigned=" << YesNo(handling_differs != 0) << "\n";

    EXPECT_EQ(truth_differs, 4U);
    EXPECT_EQ(handling_differs, 0U);
}

// The predicate byte is not validated anywhere: it arrives from the
// branch log (ADR 0033) and BuildSystem passes it through. For a byte
// above nine EvalPredicate returns false (src/concolic/concolic.cpp:80-82)
// and NegatePredicate returns the byte unchanged
// (src/concolic/concolic.cpp:110-112), so the unknown predicate enters
// sys.path verbatim and its as-taken encoding is silently wrong. What the
// engine then reports is measured here.
TEST(SolverPredicateAxis, PredicateBytesOutsideTheAbi) {
    unsigned enters_path = 0;

    for (const std::uint8_t predicate : {kOutOfAbiNext, kOutOfAbiMax}) {
        const Cell cell = Measure(predicate, kAB);
        PrintCell(cell);
        std::cout << "OUT-OF-ABI predicate=" << static_cast<unsigned>(predicate)
                  << " entered_path=" << YesNo(cell.gate_survived)
                  << " predicate_in_path=" << static_cast<unsigned>(cell.predicate_out)
                  << " verbatim=" << YesNo(cell.predicate_out == predicate)
                  << " outcome=" << OutcomeName(cell.outcome)
                  << " has_candidate=" << YesNo(cell.has_candidate)
                  << " flipped=" << YesNo(cell.flipped) << "\n";

        // The byte reaches the path unchanged — no validation, no drop.
        EXPECT_TRUE(cell.gate_survived);
        EXPECT_EQ(cell.path_size, 3U);
        EXPECT_EQ(cell.target_index, 2U);
        EXPECT_EQ(cell.predicate_out, predicate);
        if (cell.gate_survived && cell.predicate_out == predicate) {
            ++enters_path;
        }

        // No negation table entry exists, so the as-taken encoding cannot
        // be correct; the harness refuses to score it as correct.
        EXPECT_FALSE(cell.expectation_defined);
        EXPECT_FALSE(cell.encoding_correct);

        // The failure surfaces one layer down: MakePredicate has no case
        // for the byte and throws, SolveInverted maps the exception to
        // kError (src/solver/solver_facade.cpp:139-141, 209-211).
        EXPECT_EQ(cell.outcome, SolveOutcome::kError);
        EXPECT_FALSE(cell.has_candidate);
        EXPECT_FALSE(cell.flipped);
    }

    std::cout << "SUMMARY out_of_abi_cells=2 out_of_abi_enters_path=" << YesNo(enters_path == 2)
              << " out_of_abi_outcome=kError out_of_abi_flipped=0/2\n";
    EXPECT_EQ(enters_path, 2U);
}
