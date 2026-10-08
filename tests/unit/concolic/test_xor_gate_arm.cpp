#include <gtest/gtest.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// The solver arm on a gate that has NO solutions (task-039, ADR 0035 §2).
//
// What is measured. `docs/experiments/solver-xor-boundary/report.md:223`
// established by five independent methods that under the fixture's own
// MAGIC/HI the xor gate has zero solutions — and the same report names
// its untouched tail (`:193-195`): the solver arm itself, BuildSystem /
// SolveForCandidate, was never run on it. This file runs it. A gate with
// zero solutions is the hardest available test for silent loss: if the
// arm still answers kCandidate there, the outcome code cannot separate a
// useful candidate from one that cannot exist.
//
// Method. The records below reproduce the layout the fixture actually
// emits, taken off the instrumented object rather than read out of the
// .c by eye (`docs/experiments/solver-xor-arm/trace-layout.md:46-60` for
// the fields, `:71` for the order). Three of those fields are NOT
// legible in the source and are taken from that measurement: the band
// compares landed as kUge/kUle (not kUgt as in the sample harness
// tests/unit/concolic/test_domain_map.cpp:99-100), the length check is
// 64 bits wide, and nz32 stayed out-of-line so its four sites are logged
// once per operand — 13 sites, 17 records inside the guard.
//
// HONEST LIMIT. The records are synthesized from the fixture's SHAPE;
// they were not captured from a live run of the fixture under the
// runtime. This measures the arm on the form of the trace, not on a
// live trace. Nothing here runs the target binary: gate satisfaction is
// checked by pure arithmetic over the candidate bytes.
//
// The cell shape follows the domain-map harness
// (tests/unit/concolic/test_domain_map.cpp:96): the derived operand's
// Kind is read off a PROBE system whose gate record binds on its RHS, so
// the LHS classification stays observable even when the real form drops
// the gate record entirely.
//
// Boundaries. The fixture is not touched: MAGIC and HI are read here,
// never redefined. task-034 stays blocked; this file neither unblocks it
// nor recommends any of the owner's A/B/C/D variants.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033, fixed ABI —
// src/concolic/concolic.cpp:14-25).
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUge = 5 };

constexpr unsigned kTimeoutMs = 5000;

// Fixture constants. Read from the fixture, never redefined there.
constexpr std::uint32_t kMagic = 0xDEADBEEFU;  ///< tests/fixtures/xor_gate/xor_gate.c:16
constexpr std::uint32_t kLo = 0x01000000U;     ///< tests/fixtures/xor_gate/gate_guard.h:17
constexpr std::uint32_t kHi = 0x7F000000U;     ///< tests/fixtures/xor_gate/gate_guard.h:18
constexpr std::size_t kMinLen = 8;             ///< tests/fixtures/xor_gate/xor_gate.c:21

// Main cell: two in-band fields with every byte non-zero, so the guard
// holds and no derived value below aliases a field by accident.
constexpr std::uint32_t kFieldA = 0x11223344U;
constexpr std::uint32_t kFieldB = 0x55667788U;

// Alias cell: disjoint bits, so a ^ b == a + b and the pair-enumeration
// rule fires on a gate that is not a sum
// (tests/unit/concolic/test_domain_map.cpp:198-211). Unlike the
// domain-map witness (0x0F0F0F0F / 0xF0F0F0F0, whose second field is
// above HI), this pair is INSIDE the fixture's band, so the alias cell
// is reachable on the fixture's own guard — see
// AliasCellIsReachableUnlikeTheDomainMapWitness below.
constexpr std::uint32_t kAliasA = 0x0F0F0F0FU;
constexpr std::uint32_t kAliasB = 0x70F0F0F0U;

// nz32 of the fixture, verbatim (tests/fixtures/xor_gate/gate_guard.h:21).
constexpr bool Nz32(std::uint32_t v) {
    return ((v & 0xFFU) != 0U) && (((v >> 8U) & 0xFFU) != 0U) && (((v >> 16U) & 0xFFU) != 0U) &&
           (((v >> 24U) & 0xFFU) != 0U);
}

// guard of the fixture, verbatim (tests/fixtures/xor_gate/gate_guard.h:25).
constexpr bool GuardHolds(std::uint32_t a, std::uint32_t b) {
    return a >= kLo && a <= kHi && b >= kLo && b <= kHi && Nz32(a) && Nz32(b);
}

static_assert(GuardHolds(kFieldA, kFieldB), "main cell must reach the gate");
static_assert(GuardHolds(kAliasA, kAliasB), "alias cell must reach the gate");
static_assert((kAliasA & kAliasB) == 0U, "alias cell needs disjoint bits");
static_assert((kAliasA ^ kAliasB) == static_cast<std::uint32_t>(kAliasA + kAliasB));

std::vector<std::uint8_t> SeedOf(std::uint32_t lo, std::uint32_t hi) {
    std::vector<std::uint8_t> seed(kMinLen);
    for (unsigned k = 0; k < 4; ++k) {
        seed[k] = static_cast<std::uint8_t>(lo >> (8U * k));
        seed[4 + k] = static_cast<std::uint8_t>(hi >> (8U * k));
    }
    return seed;
}

std::uint32_t ReadU32Le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) | (static_cast<std::uint32_t>(p[3]) << 24U);
}

// The four nz32 byte compares for one operand, sites 9..12 — logged once
// per call because nz32 stayed out-of-line
// (docs/experiments/solver-xor-arm/trace-layout.md:31-33).
void AppendNz32Sites(std::vector<BranchReader::Record>& out, std::uint32_t v) {
    for (unsigned k = 0; k < 4; ++k) {
        out.push_back({9U + k, kNe, 32, (v >> (8U * k)) & 0xFFU, 0});
    }
}

// The 17 records the fixture emits on an input that passes the guard, in
// the order short-circuit && imposes
// (docs/experiments/solver-xor-arm/trace-layout.md:71):
//   0 -> 3 -> 4 -> 5 -> 6 -> [9..12] -> 7 -> [9..12] -> 8 -> 1 -> 2
// The last record is the gate. `gate_rhs` is what sits on its RHS.
std::vector<BranchReader::Record> TraceOf(std::uint32_t a, std::uint32_t b,
                                          std::uint64_t gate_rhs) {
    std::vector<BranchReader::Record> rec;
    rec.push_back({0, kUlt, 64, kMinLen, kMinLen});  // n < 8 — 64 bits wide
    rec.push_back({3, kUge, 32, a, kLo});
    rec.push_back({4, kUle, 32, a, kHi});
    rec.push_back({5, kUge, 32, b, kLo});
    rec.push_back({6, kUle, 32, b, kHi});
    AppendNz32Sites(rec, a);
    rec.push_back({7, kNe, 32, Nz32(a) ? 1U : 0U, 0});
    AppendNz32Sites(rec, b);
    rec.push_back({8, kNe, 32, Nz32(b) ? 1U : 0U, 0});
    rec.push_back({1, kNe, 32, GuardHolds(a, b) ? 1U : 0U, 0});
    rec.push_back({2, kEq, 32, static_cast<std::uint32_t>(a ^ b), gate_rhs});
    return rec;
}

// One measured cell of the arm.
struct Cell {
    Operand::Kind derived_kind;     ///< what BindOperand made of the gate's LHS (a ^ b)
    bool gate_survived;             ///< did the gate record reach the path at all?
    std::size_t path_size;          ///< surviving constraints
    SolveOutcome outcome;           ///< what SolveForCandidate reported
    bool has_candidate;             ///< did the call hand back an input?
    bool candidate_reaches_gate;    ///< does the candidate still pass the fixture's guard?
    bool candidate_satisfies_gate;  ///< does it satisfy a ^ b == MAGIC?
    std::uint32_t candidate_a;
    std::uint32_t candidate_b;
    std::size_t target_index;        ///< which surviving constraint the solver inverted
    Operand::Kind target_lhs_kind;   ///< and what its LHS bound to
    std::size_t target_lhs_var;      ///< kVar/kAddVars: first variable index
    std::uint64_t target_rhs_const;  ///< kConst RHS of the target, when it has one
};

const char* KindName(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kConst:
            return "kConst";
        case Operand::Kind::kAddVars:
            return "kAddVars";
    }
    return "kUnknown";
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
    return "kUnknown";
}

std::string Hex32(std::uint64_t v) {
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return os.str();
}

// Every measured field on one line, so the raw ctest -V log carries the
// numbers and not just PASSED.
void Dump(const char* cell_name, const Cell& cell) {
    std::cout << "MEASURED cell=" << cell_name << " derived_kind=" << KindName(cell.derived_kind)
              << " gate_survived=" << (cell.gate_survived ? "YES" : "NO")
              << " path_size=" << cell.path_size << " target_index=" << cell.target_index
              << " target_lhs=" << KindName(cell.target_lhs_kind) << "(v" << cell.target_lhs_var
              << ")"
              << " target_rhs=" << Hex32(cell.target_rhs_const)
              << " outcome=" << OutcomeName(cell.outcome)
              << " candidate=" << (cell.has_candidate ? "YES" : "NO")
              << " candidate_a=" << Hex32(cell.candidate_a)
              << " candidate_b=" << Hex32(cell.candidate_b)
              << " candidate_xor=" << Hex32(cell.candidate_a ^ cell.candidate_b)
              << " candidate_sum="
              << Hex32(static_cast<std::uint32_t>(cell.candidate_a + cell.candidate_b))
              << " reaches_gate=" << (cell.candidate_reaches_gate ? "YES" : "NO")
              << " satisfies_gate=" << (cell.candidate_satisfies_gate ? "YES" : "NO") << std::endl;
}

// Run the arm on the fixture-shaped trace for (a, b).
//
// The Kind of the gate's LHS is read off a PROBE trace whose gate record
// is `(a ^ b) == b`: BindOperand classifies each side independently
// (src/concolic/concolic.cpp:240-243), so the LHS classification is the
// same as in the real form, but the probe's RHS binds to a field, which
// keeps the record alive and makes the Kind directly observable instead
// of inferred from the drop.
Cell Measure(std::uint32_t a, std::uint32_t b) {
    const std::vector<std::uint8_t> seed = SeedOf(a, b);
    const std::vector<BranchReader::Record> form = TraceOf(a, b, kMagic);
    const std::vector<BranchReader::Record> probe = TraceOf(a, b, b);

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

    // The gate is the last record; it survived iff the last surviving
    // constraint is still the gate's own comparison. Every derived
    // record before it (nz32 bytes, nz32 results, guard result) is
    // const-vs-const and is dropped by design (concolic.cpp:244-247), so
    // path_size == form.size() would never hold here.
    cell.gate_survived = !form_sys.path.empty() &&
                         form_sys.path.back().lhs.kind != Operand::Kind::kConst &&
                         form_sys.path.back().rhs.kind == Operand::Kind::kConst &&
                         form_sys.path.back().rhs.const_value == kMagic;

    cell.target_index = form_sys.target_index;
    if (!form_sys.path.empty()) {
        const auto& target = form_sys.path[form_sys.target_index];
        cell.target_lhs_kind = target.lhs.kind;
        cell.target_lhs_var = target.lhs.var_index;
        cell.target_rhs_const = target.rhs.const_value;
    }

    cell.outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, form, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    if (candidate.has_value() && candidate->size() >= kMinLen) {
        cell.candidate_a = ReadU32Le(candidate->data());
        cell.candidate_b = ReadU32Le(candidate->data() + 4);
        cell.candidate_reaches_gate = GuardHolds(cell.candidate_a, cell.candidate_b);
        cell.candidate_satisfies_gate = (cell.candidate_a ^ cell.candidate_b) == kMagic;
    }
    return cell;
}

}  // namespace

// Sanity for the synthesized trace itself: 17 records, both fields
// discovered by offset from the band compares alone. If this breaks,
// every cell below measures something other than what it claims.
TEST(XorGateArm, FixtureShapedTraceBindsBothFields) {
    const std::vector<std::uint8_t> seed = SeedOf(kFieldA, kFieldB);
    const std::vector<BranchReader::Record> trace = TraceOf(kFieldA, kFieldB, kMagic);
    ASSERT_EQ(trace.size(), 17U);

    const System sys = BuildSystem(seed, trace);
    ASSERT_EQ(sys.num_vars, 2U);
    EXPECT_EQ(sys.vars[0].offset, 0U);
    EXPECT_EQ(sys.vars[1].offset, 4U);
    EXPECT_EQ(sys.vars[0].bit_width, 32);
    EXPECT_EQ(sys.vars[1].bit_width, 32);

    // Only the four band compares carry a bound operand; the length
    // check and every derived record are const-vs-const and drop.
    EXPECT_EQ(sys.path.size(), 4U);
}

// THE MEASUREMENT. The gate `a ^ b == MAGIC` on the fixture's own shape.
// xor of two fields is out of domain, MAGIC is a constant, so the gate
// record is dropped and the last surviving BAND compare silently becomes
// the target. The arm still reports kCandidate — for a branch that is
// not the gate.
TEST(XorGateArm, MainCellLosesTheGateYetStillReportsCandidate) {
    const Cell cell = Measure(kFieldA, kFieldB);
    Dump("main", cell);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 4U);

    // The hazard, in its sharpest form: a candidate IS produced for a
    // gate that has no solutions at all.
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.candidate_satisfies_gate);

    // Sharper still: name the branch that replaced the gate. It is the
    // last band compare, `b <= HI` (site 6), so inverting it drives the
    // candidate OUT of the guard band — the candidate cannot even reach
    // the gate site.
    EXPECT_EQ(cell.target_index, 3U);
    EXPECT_EQ(cell.target_lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.target_lhs_var, 1U);
    EXPECT_EQ(cell.target_rhs_const, kHi);
    EXPECT_FALSE(cell.candidate_reaches_gate);
    EXPECT_GT(cell.candidate_b, kHi);
}

// THE ALIAS CELL. Disjoint bits make a ^ b == a + b, the pair
// enumeration matches on the VALUE, and the gate is silently re-encoded
// as a sum (docs/experiments/solver-domain-map/report.md:138). Now the
// gate record SURVIVES and the solver targets it — and still hands back
// a candidate that does not satisfy the xor gate, because the sum it
// solved says nothing about disjointness.
TEST(XorGateArm, AliasCellKeepsTheGateAndStillYieldsAUselessCandidate) {
    const Cell cell = Measure(kAliasA, kAliasB);
    Dump("alias", cell);

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kAddVars);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);

    // Here the solver really does target the gate: the last constraint
    // is the gate record, and its LHS bound as a sum of both fields.
    EXPECT_EQ(cell.target_index, 4U);
    EXPECT_EQ(cell.target_lhs_kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.target_rhs_const, kMagic);

    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(cell.has_candidate);

    // What the candidate actually satisfies is the SUM, not the xor.
    EXPECT_EQ(static_cast<std::uint32_t>(cell.candidate_a + cell.candidate_b), kMagic);
    EXPECT_FALSE(cell.candidate_satisfies_gate);
}

// Why the gate has no solutions, by arithmetic rather than by citation.
// MAGIC's top byte is 0xDE, which has bit 7 set; the band caps both
// fields at HI = 0x7F000000, so both top bytes are <= 0x7F and their xor
// can never set bit 7. No in-band pair satisfies the gate — which is
// exactly why a kCandidate answer above is a loss and not a find.
// Independent corroboration of solver-xor-boundary/report.md:223; that
// report's status is not touched.
TEST(XorGateArm, NoInBandPairCanSatisfyTheGate) {
    constexpr std::uint32_t kMagicTop = kMagic >> 24U;
    constexpr std::uint32_t kHiTop = kHi >> 24U;
    ASSERT_EQ(kMagicTop, 0xDEU);
    ASSERT_EQ(kHiTop, 0x7FU);

    for (std::uint32_t top_a = 0; top_a <= kHiTop; ++top_a) {
        for (std::uint32_t top_b = 0; top_b <= kHiTop; ++top_b) {
            ASSERT_NE(top_a ^ top_b, kMagicTop) << "top bytes " << top_a << " ^ " << top_b;
        }
    }
}

// The alias cell is reachable on the fixture's own guard — the
// domain-map witness is not. 0xF0F0F0F0 is above HI, so a trace built on
// that witness would be counterfactual; the pair used above passes the
// guard, so the alias cell measured here is a shape the fixture can
// actually produce.
TEST(XorGateArm, AliasCellIsReachableUnlikeTheDomainMapWitness) {
    constexpr std::uint32_t kWitnessA = 0x0F0F0F0FU;  ///< test_domain_map.cpp:200
    constexpr std::uint32_t kWitnessB = 0xF0F0F0F0U;  ///< test_domain_map.cpp:201
    EXPECT_GT(kWitnessB, kHi);
    EXPECT_FALSE(GuardHolds(kWitnessA, kWitnessB));

    EXPECT_TRUE(GuardHolds(kAliasA, kAliasB));
    EXPECT_EQ(kAliasA & kAliasB, 0U);
}
