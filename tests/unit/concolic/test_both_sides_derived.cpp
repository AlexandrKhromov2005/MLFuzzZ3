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

// Solver domain map, BOTH-SIDES-DERIVED forms (task-045, ADR 0035 §2).
// Everything measured in this series so far used gates with a LITERAL on one
// side: `sum == MAGIC` (tests/unit/concolic/test_domain_map.cpp:138 form 1,
// tests/unit/concolic/test_domain_arity.cpp). The form where NEITHER side is
// a literal — `a + b == c + d` — has never been measured, even though
// BindOperand (src/concolic/concolic.cpp:185) is called independently for
// rec.lhs and rec.rhs (concolic.cpp:240-243) and both calls may return
// MakeAdd. This file MEASURES that form. It adds no rules and changes
// nothing under src/.
//
// Why this form matters for the project's main question: there is no literal
// anywhere in it, so there is nothing for an input-to-state substitution to
// copy. It is the strongest verbatim form the domain can express.
//
// The mechanism the measurement has to respect. BindOperand classifies by
// VALUE, not by expression: it is handed the u64 the runtime logged for a
// side and nothing else. So it (a) looks the value up verbatim in the seed
// (concolic.cpp:188-193), else (b) scans PAIRS of already-discovered fields
// `for i / for j = i` and returns the FIRST pair whose wrapped sum equals
// the value (concolic.cpp:195-205), else (c) makes a kConst
// (concolic.cpp:206). Two consequences drive the whole fixture below:
//
//   1. Which pair the scan returns is a property of the numbers, not of the
//      program. kFields is chosen so that all ten pair sums are DISTINCT,
//      and FixturePairsAreUnambiguous measures that instead of assuming it.
//      Without it "the side bound to (a,b)" would be an unchecked guess.
//   2. When the gate is ALREADY TRUE on the seed, both sides log the SAME
//      value, so both BindOperand calls take the same branch and return the
//      same pair. The second fixture (kEqualFields) exists to measure what
//      that does, and it is the sharpest result in the file.
//
// Fields are registered exactly as the reference harnesses do: each field
// gets a guard record `field >u LOW` that is TRUE on the seed, because pass 1
// (concolic.cpp:216-234) only discovers a field if some record LOGGED its
// value. A bare `a + b == c + d` record on its own discovers nothing — the
// sums are not in the seed — and that is a fact this file also measures
// (GateAloneDiscoversNothing).

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
constexpr unsigned kFieldCount = 4;
constexpr unsigned kFieldBytes = 4;
constexpr std::uint8_t kWidth = 32;

using Fields = std::array<std::uint32_t, kFieldCount>;

// Fixture A — the gate is FALSE on the seed, which is the direction the
// concolic engine is built for: the solver has to flip the branch.
//
// Search constraints these four numbers satisfy (all re-measured below, not
// trusted): every field is found by FindFirst at its OWN offset, little
// endian; all ten pair sums i<=j are pairwise distinct; no pair sum, no kLow
// and no kMagic occurs as a 4-byte window of the seed in either byte order.
constexpr Fields kFields = {0xEA7BAE6CU, 0x5DD86C83U, 0x54676FA2U, 0x35202910U};

// Fixture B — same properties, except that a + b EQUALS c + d by
// construction (both 0x01480F0C), so the gate is TRUE on the seed. The two
// intended pairs (0,1) and (2,3) therefore share a sum on purpose; every
// other pair sum is still unique, and (0,1) is the first the scan reaches.
constexpr Fields kEqualFields = {0x8BF6897BU, 0x75518591U, 0xDDD59875U, 0x23727697U};

// Guard bound: below every field of both fixtures, absent from both seeds.
constexpr std::uint32_t kLow = 0x01010101U;

// The control form's literal, carried over from the measured domain map
// (docs/experiments/solver-domain-map/report.md:138). Absent from the seed
// and not the sum of any field pair, so BindOperand can only make a kConst.
constexpr std::uint32_t kMagic = 0x2A2A2A2AU;

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

// One gate under test, described by which FIELDS each side is derived from
// rather than by the value that gets logged — the values are recomputed from
// the fields, both for the seed and for the candidate.
struct Form {
    const char* name;
    const Fields* fields;
    unsigned lhs_a;  ///< left side is fields[lhs_a] + fields[lhs_b]
    unsigned lhs_b;
    bool rhs_is_literal;  ///< true -> right side is the literal below
    unsigned rhs_a;       ///< right side is fields[rhs_a] + fields[rhs_b]
    unsigned rhs_b;
    std::uint32_t literal;
};

std::uint32_t LhsValue(const Form& form, const Fields& v) {
    return v[form.lhs_a] + v[form.lhs_b];
}

std::uint32_t RhsValue(const Form& form, const Fields& v) {
    return form.rhs_is_literal ? form.literal : v[form.rhs_a] + v[form.rhs_b];
}

bool GateHolds(const Form& form, const Fields& v) {
    return LhsValue(form, v) == RhsValue(form, v);
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

// Read a side's binding off a PROBE system rather than off the form itself.
// A form whose two sides both classify as kConst is dropped whole
// (concolic.cpp:244-247) and would leave nothing to observe, so each probe
// keeps the OTHER side pinned to a field. BindOperand classifies each side
// independently, so the probe reports the same Kind the real form produced —
// and the real form is cross-checked against it whenever it survives.
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
    const Operand& op = want_lhs ? sys.path.back().lhs : sys.path.back().rhs;
    return Side{op.kind, op.var_index, op.var_index2};
}

Cell Measure(const Form& form) {
    const Fields& fields = *form.fields;
    const std::vector<std::uint8_t> seed = SeedOf(fields);
    const auto lhs_value = static_cast<std::uint64_t>(LhsValue(form, fields));
    const auto rhs_value = static_cast<std::uint64_t>(RhsValue(form, fields));

    std::vector<BranchReader::Record> recs = GuardsFor(fields);
    recs.push_back({kFieldCount, kEq, kWidth, lhs_value, rhs_value});

    Cell cell{};
    // Probes pin the OTHER side to a field so the probed side is always
    // observable: for the left probe the right side is the last field
    // (kVar), for the right probe the left side is field 0 (kVar).
    cell.lhs = ProbeSide(fields, lhs_value, fields[kFieldCount - 1U], true);
    cell.rhs = ProbeSide(fields, fields[0], rhs_value, false);

    const System sys = BuildSystem(seed, recs);
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == recs.size();
    cell.invertible = sys.invertible;
    if (cell.gate_survived) {
        // The form itself must agree with the probes, otherwise the probe
        // method is measuring something else and every Kind below is void.
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

// The common sum of fixture B: a + b == c + d == 0x01480F0C.
constexpr std::uint32_t kEqualSum = 0x01480F0CU;

// The four cells the queue entry names, plus two already-true cells on
// fixture B that separate "both sides derived" from "both sides log the same
// value".
constexpr Form kDisjoint = {"a+b==c+d", &kFields, 0, 1, false, 2, 3, 0};
constexpr Form kOverlap = {"a+b==b+d", &kFields, 0, 1, false, 1, 3, 0};
constexpr Form kSharedLeft = {"a+b==a+c", &kFields, 0, 1, false, 0, 2, 0};
constexpr Form kControl = {"a+b==MAGIC", &kFields, 0, 1, true, 0, 0, kMagic};
constexpr Form kDisjointAlreadyTrue = {
    "a+b==c+d (true on seed)", &kEqualFields, 0, 1, false, 2, 3, 0};
constexpr Form kLiteralAlreadyTrue = {
    "a+b==LITERAL (true on seed)", &kEqualFields, 0, 1, true, 0, 0, kEqualSum};

constexpr std::array<const Form*, 6> kAllForms = {
    &kDisjoint, &kOverlap, &kSharedLeft, &kControl, &kDisjointAlreadyTrue, &kLiteralAlreadyTrue};

}  // namespace

// ---------------------------------------------------------------------------
// Fixture sanity. If any of these break, every cell below is measuring
// something other than what it claims.
// ---------------------------------------------------------------------------

// The guards alone must discover all four fields, at the offsets and in the
// order the back-substitution check assumes.
TEST(BothSidesDerived, FixtureBindsAllFields) {
    for (const Fields* fields : {&kFields, &kEqualFields}) {
        const System sys = BuildSystem(SeedOf(*fields), GuardsFor(*fields));
        ASSERT_EQ(sys.num_vars, kFieldCount);
        ASSERT_EQ(sys.vars.size(), kFieldCount);
        for (unsigned i = 0; i < kFieldCount; ++i) {
            SCOPED_TRACE(testing::Message() << "field=" << i);
            EXPECT_EQ(sys.vars[i].offset, kFieldBytes * i);
            EXPECT_EQ(sys.vars[i].bit_width, kWidth);
            EXPECT_FALSE(sys.vars[i].big_endian);
        }
        for (const auto& constraint : sys.path) {
            EXPECT_EQ(constraint.lhs.kind, Operand::Kind::kVar);
            EXPECT_EQ(constraint.rhs.kind, Operand::Kind::kConst);
        }
    }
}

// Which pair the scan returns is what the whole measurement rests on. For
// fixture A every one of the ten pair sums must come back as kAddVars with
// EXACTLY the pair it was built from — that is simultaneously proof that no
// sum is findable verbatim (it would be kVar) and that no earlier pair
// shadows a later one (it would be a different index pair).
TEST(BothSidesDerived, FixturePairsAreUnambiguous) {
    for (unsigned i = 0; i < kFieldCount; ++i) {
        for (unsigned j = i; j < kFieldCount; ++j) {
            SCOPED_TRACE(testing::Message() << "pair=(" << i << "," << j << ")");
            const auto sum = static_cast<std::uint64_t>(kFields[i] + kFields[j]);
            const Side side = ProbeSide(kFields, sum, kFields[kFieldCount - 1U], true);
            EXPECT_EQ(side.kind, Operand::Kind::kAddVars);
            EXPECT_EQ(side.var_index, i);
            EXPECT_EQ(side.var_index2, j);
        }
    }
}

// Fixture B is built so that (0,1) and (2,3) DO share a sum; every other pair
// stays unique and the scan reaches (0,1) first. That collision is the
// experiment, so it is measured here rather than assumed.
TEST(BothSidesDerived, EqualFixtureCollidesOnlyOnTheIntendedPair) {
    ASSERT_EQ(kEqualFields[0] + kEqualFields[1], kEqualFields[2] + kEqualFields[3]);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        for (unsigned j = i; j < kFieldCount; ++j) {
            SCOPED_TRACE(testing::Message() << "pair=(" << i << "," << j << ")");
            const auto sum = static_cast<std::uint64_t>(kEqualFields[i] + kEqualFields[j]);
            const Side side = ProbeSide(kEqualFields, sum, kEqualFields[kFieldCount - 1U], true);
            EXPECT_EQ(side.kind, Operand::Kind::kAddVars);
            const bool intended_collision = (i == 2 && j == 3);
            EXPECT_EQ(side.var_index, intended_collision ? 0U : i);
            EXPECT_EQ(side.var_index2, intended_collision ? 1U : j);
        }
    }
}

// Neither bound of the fixture may be reconstructible, or the guards and the
// control literal would stop being constants.
TEST(BothSidesDerived, FixtureBoundsAreConstants) {
    EXPECT_EQ(ProbeSide(kFields, kFields[0], kLow, false).kind, Operand::Kind::kConst);
    EXPECT_EQ(ProbeSide(kFields, kFields[0], kMagic, false).kind, Operand::Kind::kConst);
}

// A both-sides-derived gate carries no field VALUE, only two sums, so on its
// own it discovers nothing in pass 1 and is dropped in pass 2. This is why
// the guards are part of the fixture and not decoration: without them the
// form is out of the domain for a reason that has nothing to do with the
// form itself.
TEST(BothSidesDerived, GateAloneDiscoversNothing) {
    const std::vector<BranchReader::Record> only_gate = {
        {0, kEq, kWidth, static_cast<std::uint64_t>(LhsValue(kDisjoint, kFields)),
         static_cast<std::uint64_t>(RhsValue(kDisjoint, kFields))}};
    const System sys = BuildSystem(SeedOf(kFields), only_gate);
    EXPECT_EQ(sys.num_vars, 0U);
    EXPECT_TRUE(sys.path.empty());
    EXPECT_FALSE(sys.invertible);

    SolveOutcome outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(SeedOf(kFields), only_gate, kTimeoutMs, &outcome);
    EXPECT_FALSE(candidate.has_value());
    EXPECT_EQ(outcome, SolveOutcome::kNoBinding);
}

// ---------------------------------------------------------------------------
// The cells.
// ---------------------------------------------------------------------------

// Four DIFFERENT fields, no literal anywhere. Both sides bind as sums, the
// system carries all four variables, and the candidate really does take the
// gate — checked by substituting the model back into the seed, not by
// trusting kCandidate.
TEST(BothSidesDerived, DisjointFieldsAreInDomainAndSolvable) {
    const Cell cell = Measure(kDisjoint);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.var_index, 2U);
    EXPECT_EQ(cell.rhs.var_index2, 3U);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_FALSE(cell.gate_on_seed);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// Same form with the two inner fields collapsed into one (`b` and `c` are the
// same field): three distinct variables feed a four-operand gate.
TEST(BothSidesDerived, OverlappingFieldIsInDomainAndSolvable) {
    const Cell cell = Measure(kOverlap);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.var_index, 1U);
    EXPECT_EQ(cell.rhs.var_index2, 3U);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_FALSE(cell.gate_on_seed);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// `a + b == a + c` — the shared addend leads the scan on both sides.
TEST(BothSidesDerived, SharedLeftAddendIsInDomainAndSolvable) {
    const Cell cell = Measure(kSharedLeft);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.var_index, 0U);
    EXPECT_EQ(cell.rhs.var_index2, 2U);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_FALSE(cell.gate_on_seed);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// Control: the already-measured one-literal form, run on THIS fixture so the
// table is internally comparable. It must reproduce the domain map's verdict
// for `a + b == MAGIC` — kAddVars on the left, kConst on the right,
// SolveOutcome::kCandidate (docs/experiments/solver-domain-map/report.md:138).
// The fixture is not identical to the domain map's (four guarded fields here,
// two there), so what is compared is the Kind pair and the outcome.
TEST(BothSidesDerived, ControlOneLiteralSideMatchesDomainMap) {
    const Cell cell = Measure(kControl);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_FALSE(cell.gate_on_seed);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// The sharp edge of the form. When `a + b == c + d` is ALREADY TRUE on the
// seed, both sides log the same value, so both BindOperand calls run the same
// pair scan and return the SAME pair — (0,1) here, with (2,3) never reached.
// The gate becomes the tautology `v0+v1 == v0+v1`, SolveInverted negates it
// into `v0+v1 != v0+v1`, and the system is UNSAT — even though the branch is
// perfectly flippable in reality (any c,d with c+d != a+b). The literal-sided
// control on the same fixture does NOT degrade this way, which is what makes
// this specific to both-sides-derived forms.
TEST(BothSidesDerived, AlreadyTrueGateCollapsesToTautologyAndGoesUnsat) {
    const Cell cell = Measure(kDisjointAlreadyTrue);
    EXPECT_TRUE(cell.gate_on_seed);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kAddVars);
    // Both sides collapse onto the FIRST matching pair; (2,3) is lost.
    EXPECT_EQ(cell.lhs.var_index, 0U);
    EXPECT_EQ(cell.lhs.var_index2, 1U);
    EXPECT_EQ(cell.rhs.var_index, 0U);
    EXPECT_EQ(cell.rhs.var_index2, 1U);
    EXPECT_EQ(cell.num_vars, 4U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kUnsat);
    EXPECT_FALSE(cell.has_candidate);
    EXPECT_FALSE(cell.flipped);
}

// Attribution check for the cell above, and the reason it exists: BindOperand
// is handed a VALUE, never an expression, so it cannot know that the right
// side of `a + b == LITERAL` was written as a literal in the program. When
// that literal happens to equal a + b — which is exactly what "the equality
// is true on this seed" means — the literal is reconstructed as the same pair
// and the one-literal form collapses the same way. The kUnsat above is
// therefore a property of ALREADY-TRUE equalities over reconstructible
// values, not of two-sidedness; this cell is what makes that measurable
// instead of arguable.
TEST(BothSidesDerived, AlreadyTrueLiteralSidedGateCollapsesTheSameWay) {
    const Cell cell = Measure(kLiteralAlreadyTrue);
    EXPECT_TRUE(cell.gate_on_seed);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    // The literal is NOT a kConst here: its value is a reconstructible sum.
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.var_index, 0U);
    EXPECT_EQ(cell.rhs.var_index2, 1U);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kUnsat);
    EXPECT_FALSE(cell.has_candidate);
}

// The other half of the attribution: on the SAME fixture B seed, a gate that
// is FALSE on the seed and has a genuine literal on the right solves normally.
// So neither the fixture's numbers nor the seed explain the two kUnsat cells.
TEST(BothSidesDerived, FalseLiteralSidedGateOnEqualFixtureStaysSolvable) {
    constexpr Form false_literal = {
        "a+b==MAGIC (fixture B)", &kEqualFields, 0, 1, true, 0, 0, kMagic};
    const Cell cell = Measure(false_literal);
    EXPECT_FALSE(cell.gate_on_seed);
    EXPECT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_TRUE(cell.flipped);
}

// The table itself, emitted for the raw log so the report can pin numbers
// rather than restate them.
TEST(BothSidesDerived, MeasuredTableIsEmitted) {
    unsigned in_domain = 0;
    unsigned both_sides_bound = 0;
    unsigned solved = 0;
    unsigned gate_taken = 0;
    std::size_t num_vars_max = 0;
    for (const Form* form : kAllForms) {
        const Cell cell = Measure(*form);
        const bool both_derived = !form->rhs_is_literal;
        if (cell.gate_survived) {
            ++in_domain;
        }
        if (cell.gate_survived && cell.lhs.kind != Operand::Kind::kConst &&
            cell.rhs.kind != Operand::Kind::kConst) {
            ++both_sides_bound;
        }
        if (cell.outcome == SolveOutcome::kCandidate) {
            ++solved;
        }
        if (cell.flipped) {
            ++gate_taken;
        }
        num_vars_max = std::max(num_vars_max, cell.num_vars);
        std::cout << "CELL form=" << form->name << " both_sides_derived=" << both_derived
                  << " lhs=" << Describe(cell.lhs) << " rhs=" << Describe(cell.rhs)
                  << " num_vars=" << cell.num_vars << " path=" << cell.path_size
                  << " gate_survived=" << cell.gate_survived << " invertible=" << cell.invertible
                  << " outcome=" << NameOf(cell.outcome) << " gate_on_seed=" << cell.gate_on_seed
                  << " gate_on_candidate=" << cell.gate_on_candidate << " flipped=" << cell.flipped
                  << "\n";
    }
    std::cout << "SUMMARY: forms=" << kAllForms.size() << ", in_domain=" << in_domain
              << ", both_sides_bound=" << both_sides_bound << ", solved=" << solved
              << ", gate_taken=" << gate_taken << ", num_vars_max=" << num_vars_max << "\n";
    EXPECT_EQ(kAllForms.size(), 6U);
    EXPECT_EQ(in_domain, 6U);
    EXPECT_EQ(both_sides_bound, 5U);
    EXPECT_EQ(solved, 4U);
    EXPECT_EQ(gate_taken, 4U);
    EXPECT_EQ(num_vars_max, 4U);
}
