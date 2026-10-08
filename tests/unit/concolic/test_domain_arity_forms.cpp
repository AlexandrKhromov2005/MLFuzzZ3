#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

// Solver domain matrix, AREA 3 — arity 4 and 8 for the six forms other than
// `add` (task-069, ADR 0035). This file MEASURES; it adds no rule and
// changes nothing under src/.
//
// What the matrix said was missing, and why it matters. The coverage matrix
// (docs/experiments/solver-domain-coverage-matrix/report.md:132-134) names
// area 3: more than two addends was measured for `add` alone, so `sub`,
// `xor`, `and`, `mul`, `add-const` and `lt` at 4 and 8 operands were
// measured by nobody. The consequence is that `k_max_bound = 2`
// (docs/experiments/solver-domain-arity/report.md:75-77) is a property read
// off ONE form and used by the whole series as a property of reconstruction
// in general. This file extends the grid along exactly ONE axis — arity —
// and pins the other three to the base grid's cell: width w32, byte order
// LE, one literal side. Nothing else moves.
//
// Where the two halves come from. The forms and their arithmetic are taken
// unchanged from tests/unit/concolic/test_domain_form_width_endian.cpp
// (:157-231), whose 56 cells are the "arity 2" row of this same grid. The
// k-field seed layout, the per-field guard records and the probe technique
// for reading an operand Kind are taken from
// tests/unit/concolic/test_domain_arity.cpp (:97-190). Neither source file
// is modified. What is genuinely new here is only the field table: the
// arity harness stops at four fields (kMaxK = 4,
// tests/unit/concolic/test_domain_arity.cpp:58), so eight fields had to be
// chosen, and FixtureConstantsAreNotFindable below proves the choice is
// sound rather than assuming it.
//
// THE ARITY RULE, STATED BEFORE ANY RESULT. Arity k counts the OPERANDS OF
// THE GATE, not the fields on its left-hand side. For the five variadic
// forms the two coincide; for the two forms whose base-grid shape already
// spends an operand on something other than a folded field, they do not:
//
//   add / sub / xor / and / mul   fold(f0 .. f_{k-1})  ==  MAGIC
//   add-const                     sum(f0 .. f_{k-2}) + C  ==  MAGIC
//   lt                            sum(f0 .. f_{k-2})  <u  f_{k-1}
//
// The rule is chosen so that substituting k = 2 reproduces the base grid
// EXACTLY, form by form: `a + b == MAGIC`, `a - b == MAGIC`, ..., and the
// base grid's `a + C == MAGIC` and `a <u b`
// (test_domain_form_width_endian.cpp:199-231). Any rule that made
// add-const and lt fold k fields would silently redefine those two forms
// and make the arity-2 control unfalsifiable. That control is a separate
// unit; this file's job is to make it possible, and the rule is written
// here, above the measurements, so it cannot be fitted to them afterwards.
//
// Reading SolveOutcome alone is a trap, and this file pins the trap the
// same way its sources do. When both sides of the gate classify as kConst
// the record is DROPPED (src/concolic/concolic.cpp:244-247), the last
// surviving guard silently becomes the target and SolveForCandidate still
// reports kCandidate — for a branch that is NOT the gate
// (docs/experiments/solver-domain-map/report.md). So every cell records the
// operand Kind, whether the gate record survived, and num_vars, and not
// just the outcome.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033), restated from
// tests/unit/concolic/test_domain_form_width_endian.cpp:83.
enum : std::uint8_t { kEq = 0, kUlt = 2, kUgt = 4 };

constexpr unsigned kBits = 8;
constexpr unsigned kTimeoutMs = 5000;

// The three axes held fixed at the base grid's cell: w32, little endian,
// one literal side.
constexpr unsigned kWidth = 32;
constexpr bool kBigEndian = false;
constexpr std::uint8_t kWidthByte = 32;
constexpr unsigned kFieldBytes = kWidth / kBits;

// The axis that moves.
constexpr unsigned kMaxArity = 8;
constexpr std::array<unsigned, 2> kArities{{4U, 8U}};

// Eight u32 fields, little endian, at offsets 0, 4, ... 28. The first four
// are the arity harness's table unchanged
// (tests/unit/concolic/test_domain_arity.cpp:65-66) so the shared cells stay
// the same cells; four more continue it. Every byte is non-zero, no byte
// equals 0x2A or 0x01, and no 4-byte window repeats — so no derived value
// below can be found as a substring of the seed and forge a binding.
// FixtureConstantsAreNotFindable asserts this instead of trusting it.
constexpr std::array<std::uint32_t, kMaxArity> kFields = {0x11223344U, 0x55667788U, 0x99AABBCCU,
                                                          0xD1E2F304U, 0x2B3C4D5EU, 0x6F718293U,
                                                          0xA4B5C6D7U, 0xE8F91A2BU};

// Guard bound: below every field and absent from the seed.
constexpr std::uint32_t kLow = 0x01010101U;

// The gate's magic constant, absent from the seed and above kLow — both
// properties for the reasons pinned at
// tests/unit/concolic/test_domain_arity.cpp:71-81.
constexpr std::uint32_t kMagic = 0x2A2A2A2AU;

// The compile-time addend of the add-const form, pinned unchanged from
// tests/unit/concolic/test_domain_form_width_endian.cpp:155.
constexpr std::uint32_t kConstAddend = 0x00000010U;

enum class FormKind { kAdd, kSub, kXor, kAnd, kMul, kAddConst, kLt };

struct FormSpec {
    FormKind kind;
    const char* name;
};

// The six forms of area 3. `add` is deliberately absent: it is the one form
// arity was already measured on, and re-running it is the CONTROL, not a
// cell of this grid.
constexpr std::array<FormSpec, 6> kForms{{
    {FormKind::kSub, "sub"},
    {FormKind::kXor, "xor"},
    {FormKind::kAnd, "and"},
    {FormKind::kMul, "mul"},
    {FormKind::kAddConst, "add-const"},
    {FormKind::kLt, "lt"},
}};

// How many seed fields the gate's left-hand side folds at arity k. See THE
// ARITY RULE above: add-const spends one operand on the literal and lt
// spends one on the right-hand field, so both fold one field fewer.
unsigned FieldsFolded(FormKind form, unsigned k) {
    return (form == FormKind::kAddConst || form == FormKind::kLt) ? (k - 1U) : k;
}

// The value the runtime would log on the gate's left-hand side.
std::uint32_t DerivedOf(FormKind form, unsigned k) {
    const unsigned n = FieldsFolded(form, k);
    std::uint32_t acc = kFields[0];
    for (unsigned i = 1; i < n; ++i) {
        switch (form) {
            case FormKind::kSub:
                acc -= kFields[i];
                break;
            case FormKind::kXor:
                acc ^= kFields[i];
                break;
            case FormKind::kAnd:
                acc &= kFields[i];
                break;
            case FormKind::kMul:
                acc *= kFields[i];
                break;
            case FormKind::kAdd:
            case FormKind::kAddConst:
            case FormKind::kLt:
                acc += kFields[i];
                break;
        }
    }
    if (form == FormKind::kAddConst) {
        acc += kConstAddend;
    }
    return acc;
}

// The gate's right-hand side: the gate LITERAL for every form but `lt`, which
// orders the fold against the last field exactly as the base grid does. The
// literal is a PARAMETER, not kMagic, because the base-grid control at the
// foot of this file replays cells whose literal is 0x2A and not this file's
// 0x2A2A2A2A (tests/unit/concolic/test_domain_form_width_endian.cpp:253-257).
std::uint32_t RhsOf(FormKind form, unsigned k, std::uint32_t literal) {
    return form == FormKind::kLt ? kFields[k - 1U] : literal;
}

std::uint8_t PredicateOf(FormKind form) {
    return form == FormKind::kLt ? kUlt : kEq;
}

const char* NameOf(FormKind form) {
    for (const FormSpec& spec : kForms) {
        if (spec.kind == form) {
            return spec.name;
        }
    }
    return "add";
}

// k u32 fields, little endian, at offsets 4*i. Restated from
// tests/unit/concolic/test_domain_arity.cpp:97-105.
std::vector<std::uint8_t> SeedOf(unsigned k) {
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(kFieldBytes * k));
    for (unsigned i = 0; i < k; ++i) {
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            seed[(kFieldBytes * i) + b] = static_cast<std::uint8_t>(kFields[i] >> (kBits * b));
        }
    }
    return seed;
}

// One guard record per field, so pass 1 can discover all k of them.
// Restated from tests/unit/concolic/test_domain_arity.cpp:123-129.
std::vector<BranchReader::Record> GuardsFor(unsigned k) {
    std::vector<BranchReader::Record> guards;
    guards.reserve(k);
    for (unsigned i = 0; i < k; ++i) {
        guards.push_back({i, kUgt, kWidthByte, kFields[i], kLow});
    }
    return guards;
}

// Independent restatement of the substring search FindFirst performs
// (src/concolic/concolic.cpp:136), copied from
// tests/unit/concolic/test_domain_form_width_endian.cpp:123-146.
bool Occurs(const std::vector<std::uint8_t>& seed, std::uint32_t value) {
    if (seed.size() < kFieldBytes) {
        return false;
    }
    for (std::size_t off = 0; off + kFieldBytes <= seed.size(); ++off) {
        bool le = true;
        bool be = true;
        for (unsigned k = 0; k < kFieldBytes; ++k) {
            const std::uint8_t byte = seed[off + k];
            if (byte != static_cast<std::uint8_t>(value >> (kBits * k))) {
                le = false;
            }
            if (byte != static_cast<std::uint8_t>(value >> (kBits * (kFieldBytes - 1U - k)))) {
                be = false;
            }
        }
        if (le || be) {
            return true;
        }
    }
    return false;
}

// One measured cell of the arity sweep.
struct Cell {
    FormKind form = FormKind::kAdd;
    unsigned arity = 0;
    bool buildable = false;      ///< did the layout build at all (all k fields bound)?
    std::size_t records = 0;     ///< trace records submitted to BuildSystem
    std::size_t path_size = 0;   ///< constraints that survived binding
    std::size_t num_vars = 0;    ///< variables BuildSystem recovered from the seed
    bool gate_survived = false;  ///< did the gate record reach sys.path at all?
    bool invertible = false;     ///< sys.invertible for the whole form
    Operand::Kind derived_kind = Operand::Kind::kConst;  ///< what BindOperand made of the fold
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    std::uint32_t derived = 0;
    bool derived_findable = false;
    std::uint32_t literal = 0;  ///< the gate's right-hand literal for this cell
};

// BOUND means the derived operand reconstructed into something other than a
// constant. Same criterion as
// tests/unit/concolic/test_domain_form_width_endian.cpp:429.
bool IsBound(const Cell& cell) {
    return cell.derived_kind != Operand::Kind::kConst;
}

const char* ClassOf(const Cell& cell) {
    return IsBound(cell) ? "BOUND" : "NO-BINDING";
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

// The exact record set one cell submits: k guard records, then the gate.
// Split out of the measurement so the two controls at the foot of this file
// can assert field by field that the set they submit is the set the foreign
// harness submitted, instead of asserting that two numbers happen to agree.
std::vector<BranchReader::Record> RecordsFor(FormKind form, unsigned k, std::uint32_t literal) {
    std::vector<BranchReader::Record> records = GuardsFor(k);
    records.push_back(
        {k, PredicateOf(form), kWidthByte, DerivedOf(form, k), RhsOf(form, k, literal)});
    return records;
}

// Measure one cell.
//
// The derived operand's Kind is read off a PROBE system rather than off the
// form itself, because a form whose two sides both classify as kConst is
// dropped whole and would leave nothing to observe. BindOperand classifies
// each side independently (src/concolic/concolic.cpp:240-243), so a probe
// that keeps the OTHER side bound reports the same Kind the real form
// produced. Technique pinned from
// tests/unit/concolic/test_domain_arity.cpp:143-151.
Cell MeasureWithLiteral(FormKind form, unsigned k, std::uint32_t literal) {
    const std::vector<std::uint8_t> seed = SeedOf(k);
    const std::vector<BranchReader::Record> guards = GuardsFor(k);
    const std::uint32_t derived = DerivedOf(form, k);

    Cell cell{};
    cell.form = form;
    cell.arity = k;
    cell.derived = derived;
    cell.derived_findable = Occurs(seed, derived);
    cell.literal = literal;

    const std::vector<BranchReader::Record> records = RecordsFor(form, k, literal);

    // The probe pins the fold against a field, so the right-hand side always
    // binds and the fold's own Kind becomes observable.
    std::vector<BranchReader::Record> probe = guards;
    probe.push_back({k, kEq, kWidthByte, derived, kFields[k - 1U]});

    const System probe_sys = BuildSystem(seed, probe);
    if (probe_sys.path.size() != probe.size()) {
        ADD_FAILURE() << "probe record was dropped for form=" << NameOf(form) << " arity=" << k
                      << " — the probe fixture itself is broken, the Kind below is not measured";
        return cell;
    }
    cell.derived_kind = probe_sys.path.back().lhs.kind;

    const System sys = BuildSystem(seed, records);
    cell.records = records.size();
    cell.path_size = sys.path.size();
    cell.num_vars = sys.num_vars;
    cell.gate_survived = sys.path.size() == records.size();
    cell.invertible = sys.invertible;

    // A cell counts as BUILT only if the layout it claims to measure is the
    // layout BuildSystem actually saw: all k fields recovered, at the right
    // offsets, at w32, little endian. Anything else is reported as
    // unbuildable by name rather than filled in with a guess.
    cell.buildable = sys.num_vars == k;
    for (unsigned i = 0; i < k && cell.buildable; ++i) {
        cell.buildable = sys.vars[i].offset == (kFieldBytes * i) &&
                         sys.vars[i].bit_width == kWidth && sys.vars[i].big_endian == kBigEndian;
    }

    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    return cell;
}

// The twelve cells of the sweep use this file's own gate literal.
Cell Measure(FormKind form, unsigned k) {
    return MeasureWithLiteral(form, k, kMagic);
}

// The twelve cells, measured once and shared. Six forms x arity {4, 8}.
struct Grid {
    std::vector<Cell> cells;
};

const Grid& TheGrid() {
    static const Grid grid = [] {
        Grid built;
        built.cells.reserve(kForms.size() * kArities.size());
        for (const FormSpec& spec : kForms) {
            for (const unsigned k : kArities) {
                built.cells.push_back(Measure(spec.kind, k));
            }
        }
        return built;
    }();
    return grid;
}

}  // namespace

// ---------------------------------------------------------------------
// Fixture sanity. If any of these break, every cell below is measuring
// something other than what it claims.
// ---------------------------------------------------------------------

// All k fields are discovered by offset from the guards alone, at both
// arities of the sweep, at w32 and little endian.
TEST(DomainArityForms, FixtureBindsAllFields) {
    for (const unsigned k : kArities) {
        SCOPED_TRACE(testing::Message() << "arity=" << k);
        const System sys = BuildSystem(SeedOf(k), GuardsFor(k));
        ASSERT_EQ(sys.num_vars, k);
        ASSERT_EQ(sys.vars.size(), k);
        for (unsigned i = 0; i < k; ++i) {
            EXPECT_EQ(sys.vars[i].offset, kFieldBytes * i);
            EXPECT_EQ(sys.vars[i].bit_width, kWidth);
            EXPECT_FALSE(sys.vars[i].big_endian);
        }
    }
}

// Neither the constants nor any derived value may be findable in the seed.
// A findable value would bind DIRECT as a variable through the first branch
// of BindOperand and report "in domain" for a reason that has nothing to do
// with arity.
TEST(DomainArityForms, FixtureConstantsAreNotFindable) {
    const std::vector<std::uint8_t> seed = SeedOf(kMaxArity);
    for (const std::uint32_t value : {kMagic, kLow, kConstAddend}) {
        SCOPED_TRACE(testing::Message() << "constant=" << value);
        EXPECT_FALSE(Occurs(seed, value));
    }
    for (const Cell& cell : TheGrid().cells) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form) << " arity=" << cell.arity);
        EXPECT_FALSE(cell.derived_findable)
            << "derived value occurs in the seed — this cell would forge a binding";
    }
}

// The probe compares the fold against the last field. If the two were equal
// the probe would be degenerate and the Kind it reports would be an
// artefact of the fixture rather than of BindOperand.
TEST(DomainArityForms, FixtureProbeIsNotDegenerate) {
    for (const Cell& cell : TheGrid().cells) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form) << " arity=" << cell.arity);
        EXPECT_NE(cell.derived, kFields[cell.arity - 1U]);
    }
}

// ---------------------------------------------------------------------
// The twelve cells.
// ---------------------------------------------------------------------

// Exactly twelve cells, all of them actually built. A cell whose layout
// BuildSystem did not reproduce is named here rather than counted as a
// measurement.
TEST(DomainArityForms, TwelveCellsAreBuilt) {
    const Grid& grid = TheGrid();
    ASSERT_EQ(grid.cells.size(), std::size_t{12});
    for (const Cell& cell : grid.cells) {
        EXPECT_TRUE(cell.buildable)
            << "unbuildable cell: form=" << NameOf(cell.form) << " arity=" << cell.arity;
    }
}

// Every cell submits k guards plus one gate record, and BuildSystem
// recovers exactly k variables from the seed. Arity does not cost the
// fixture any discovery: whatever happens to the gate, the FIELDS are all
// there.
TEST(DomainArityForms, EveryCellRecoversAllVariables) {
    for (const Cell& cell : TheGrid().cells) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form) << " arity=" << cell.arity);
        EXPECT_EQ(cell.records, std::size_t{cell.arity} + 1U);
        EXPECT_EQ(cell.num_vars, std::size_t{cell.arity});
    }
}

// The measurement table, printed once so the raw sweep can be lifted out of
// the ctest log without re-deriving it. Kept deliberately flat: one line per
// cell, no paths, no timings, so the same run always prints the same bytes.
TEST(DomainArityForms, DumpTwelveCells) {
    std::cout << "# DOMAIN-ARITY-FORMS width=w32 endian=LE literal_side=one\n";
    std::cout << "# form arity records path num_vars binding kind gate_survived invertible "
                 "outcome has_candidate\n";
    for (const Cell& cell : TheGrid().cells) {
        std::cout << NameOf(cell.form) << ' ' << cell.arity << ' ' << cell.records << ' '
                  << cell.path_size << ' ' << cell.num_vars << ' ' << ClassOf(cell) << ' '
                  << KindName(cell.derived_kind) << ' ' << (cell.gate_survived ? "yes" : "no")
                  << ' ' << (cell.invertible ? "yes" : "no") << ' ' << OutcomeName(cell.outcome)
                  << ' ' << (cell.has_candidate ? "yes" : "no") << '\n';
    }
    std::cout << std::flush;
    SUCCEED();
}

// ---------------------------------------------------------------------
// The measured table, pinned cell by cell.
// ---------------------------------------------------------------------

namespace {

// One expected row per cell. Written down from the DumpTwelveCells output of
// the run these numbers came from, so a change in BuildSystem shows up here
// as a diff and not as a quietly different report.
struct Expected {
    FormKind form;
    unsigned arity;
    std::size_t path_size;
    bool gate_survived;
    Operand::Kind derived_kind;
    SolveOutcome outcome;
    bool has_candidate;
};

constexpr std::array<Expected, 12> kExpected{{
    {FormKind::kSub, 4, 4, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kSub, 8, 8, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kXor, 4, 4, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kXor, 8, 8, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kAnd, 4, 4, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kAnd, 8, 8, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kMul, 4, 4, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kMul, 8, 8, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kAddConst, 4, 4, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    {FormKind::kAddConst, 8, 8, false, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
    // `lt` is the one form whose right-hand side is a FIELD, not the literal.
    // That side binds, so the gate record is not dropped — and at arity 4 the
    // inverted system is genuinely UNSAT, which is why the outcome column of
    // this grid is not 12/12 kCandidate. See OrderingFormKeepsItsGate below.
    {FormKind::kLt, 4, 5, true, Operand::Kind::kConst, SolveOutcome::kUnsat, false},
    {FormKind::kLt, 8, 9, true, Operand::Kind::kConst, SolveOutcome::kCandidate, true},
}};

}  // namespace

// Every one of the twelve cells, named and pinned.
TEST(DomainArityForms, TwelveCellsMatchTheirPins) {
    const Grid& grid = TheGrid();
    ASSERT_EQ(grid.cells.size(), kExpected.size());
    for (std::size_t i = 0; i < kExpected.size(); ++i) {
        const Cell& cell = grid.cells[i];
        const Expected& want = kExpected[i];
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(want.form) << " arity=" << want.arity);
        ASSERT_EQ(cell.form, want.form);
        ASSERT_EQ(cell.arity, want.arity);
        EXPECT_EQ(cell.path_size, want.path_size);
        EXPECT_EQ(cell.gate_survived, want.gate_survived);
        EXPECT_EQ(cell.derived_kind, want.derived_kind);
        EXPECT_EQ(cell.outcome, want.outcome);
        EXPECT_EQ(cell.has_candidate, want.has_candidate);
    }
}

// THE RESULT OF THE SWEEP, against the rule stated at the top of the file:
// not one of the twelve cells reconstructed its fold. `k_max_bound = 2`,
// measured on `add` alone
// (docs/experiments/solver-domain-arity/report.md:75-77), holds for the six
// other forms too — it is a property of BindOperand's pair enumeration
// (src/concolic/concolic.cpp:195-205), not of addition.
TEST(DomainArityForms, NoCellBindsBeyondArityTwo) {
    std::size_t bound = 0;
    for (const Cell& cell : TheGrid().cells) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form) << " arity=" << cell.arity);
        EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst)
            << "a fold of " << FieldsFolded(cell.form, cell.arity)
            << " fields reconstructed — k_max_bound=2 does NOT hold for this form";
        if (IsBound(cell)) {
            ++bound;
        }
    }
    EXPECT_EQ(bound, std::size_t{0});
}

// The silent loss, swept over the ten cells whose literal side is the magic
// constant: both sides classify as kConst, the record is dropped
// (src/concolic/concolic.cpp:244-247), the last surviving GUARD becomes the
// target, and SolveOutcome still says kCandidate for a branch that is not
// the gate. Reading the outcome alone would call all ten a success.
TEST(DomainArityForms, LiteralSidedCellsReportCandidateForADroppedGate) {
    std::size_t dropped = 0;
    for (const Cell& cell : TheGrid().cells) {
        if (cell.form == FormKind::kLt) {
            continue;
        }
        ++dropped;
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form) << " arity=" << cell.arity);
        EXPECT_FALSE(cell.gate_survived);
        EXPECT_EQ(cell.path_size, std::size_t{cell.arity})
            << "the guards survive, the gate does not";
        EXPECT_TRUE(cell.invertible);
        EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate) << "outcome alone hides the loss";
        EXPECT_TRUE(cell.has_candidate);
    }
    EXPECT_EQ(dropped, std::size_t{10});
}

// `lt` is the exception and it is an exception about the FIXTURE, not about
// arity. Its right-hand side is field k-1, which binds as kVar, so the gate
// record survives with a kConst on the left. The fold is still not
// reconstructed — NoCellBindsBeyondArityTwo covers all twelve — but the
// system is now a real constraint on the last variable, and at arity 4 that
// constraint inverts to something UNSAT. This is why the grid's outcome
// column reads 11/12 kCandidate and not 12/12.
TEST(DomainArityForms, OrderingFormKeepsItsGate) {
    std::size_t seen = 0;
    for (const Cell& cell : TheGrid().cells) {
        if (cell.form != FormKind::kLt) {
            continue;
        }
        ++seen;
        SCOPED_TRACE(testing::Message() << "arity=" << cell.arity);
        EXPECT_TRUE(cell.gate_survived);
        EXPECT_EQ(cell.path_size, std::size_t{cell.arity} + 1U);
        EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    }
    EXPECT_EQ(seen, std::size_t{2});
}

// The outcome column as a fraction, so the deviation from 12/12 is an
// asserted number and not a remark. Ten literal-sided cells plus lt at
// arity 8 report kCandidate; lt at arity 4 reports kUnsat.
TEST(DomainArityForms, OutcomeIsElevenCandidatesAndOneUnsat) {
    std::size_t candidates = 0;
    std::size_t unsat = 0;
    for (const Cell& cell : TheGrid().cells) {
        if (cell.outcome == SolveOutcome::kCandidate) {
            ++candidates;
        }
        if (cell.outcome == SolveOutcome::kUnsat) {
            ++unsat;
        }
    }
    EXPECT_EQ(candidates, std::size_t{11});
    EXPECT_EQ(unsat, std::size_t{1});
    EXPECT_EQ(candidates + unsat, TheGrid().cells.size());
}

// ---------------------------------------------------------------------
// THE TWO CONTROLS.
//
// A grid that agrees with nothing is not a measurement, it is a table of
// numbers this file happened to print. Both controls below therefore do the
// same two things in the same order: FIRST assert that the records this
// harness submits are field-for-field the records the foreign harness
// submitted, and only THEN compare the measured cell against the number
// published for it. Agreement of outputs on different inputs would prove
// nothing; disagreement of inputs is caught before any number is read.
//
// Neither oracle file is modified, and neither is called. The fixtures are
// RESTATED here from their sources, with their own constants and their own
// arithmetic, so that a silent edit to an oracle shows up as a failing
// identity assertion rather than as two harnesses drifting together.
//
// THE NEGATIVE CONTROL, run before these tests were believed. Three
// mutations were applied to the restatements below and the suite re-run;
// each was caught, and by the test meant to catch it and no other:
//
//   kArityOracleMagic 0x2A2A2A2A -> 0x2A2A2A2B  ->  AddInputsAreTheArityOracleInputs
//   BaseGridDerived(kSub) a - b -> a + b        ->  ArityTwoInputsAreTheBaseGridInputs
//   kBaseExpected lt kVar/true/3 -> kConst/false/2 -> ArityTwoReproducesTheBaseGridRow
//
// Six of the nine control tests stayed green under all three, so the
// failures are the assertions biting and not the fixture collapsing.
// ---------------------------------------------------------------------

namespace {

// --- the arity oracle: tests/unit/concolic/test_domain_arity.cpp ---------

// Restated from tests/unit/concolic/test_domain_arity.cpp:65-66,69,81.
constexpr std::array<std::uint32_t, 4> kArityOracleFields = {0x11223344U, 0x55667788U, 0x99AABBCCU,
                                                             0xD1E2F304U};
constexpr std::uint32_t kArityOracleLow = 0x01010101U;
constexpr std::uint32_t kArityOracleMagic = 0x2A2A2A2AU;

// The oracle's axis STOPS at four addends (kMaxK = 4,
// tests/unit/concolic/test_domain_arity.cpp:58), and its report publishes
// exactly four cells (docs/experiments/solver-domain-arity/report.md:138).
// This is the reason control A is asymmetric: arity 4 is a reproduction,
// arity 8 is not, because there is nothing at arity 8 to reproduce.
constexpr unsigned kArityOracleMaxK = 4;
static_assert(kArityOracleMaxK < 8, "arity 8 must lie outside the oracle's axis");

// Seed of the arity oracle: k u32 fields, little endian, at 4*i.
// Restated from tests/unit/concolic/test_domain_arity.cpp:97-105.
std::vector<std::uint8_t> ArityOracleSeed(unsigned k) {
    std::vector<std::uint8_t> seed;
    for (unsigned i = 0; i < k; ++i) {
        for (unsigned b = 0; b < 4U; ++b) {
            seed.push_back(static_cast<std::uint8_t>(kArityOracleFields[i] >> (8U * b)));
        }
    }
    return seed;
}

// Records of the arity oracle: k guards, then `sum(f0..f_{k-1}) == MAGIC`.
// Restated from tests/unit/concolic/test_domain_arity.cpp:123-129,158.
std::vector<BranchReader::Record> ArityOracleRecords(unsigned k) {
    std::vector<BranchReader::Record> records;
    std::uint32_t sum = 0;
    for (unsigned i = 0; i < k; ++i) {
        records.push_back({i, kUgt, 32U, kArityOracleFields[i], kArityOracleLow});
        sum += kArityOracleFields[i];
    }
    records.push_back({k, kEq, 32U, sum, kArityOracleMagic});
    return records;
}

// --- the base grid: tests/unit/concolic/test_domain_form_width_endian.cpp -

// The w32 row of the base grid's constant table, restated from
// tests/unit/concolic/test_domain_form_width_endian.cpp:253-257. Note the
// literal: the base grid's MAGIC at w32 is 0x2A, NOT this file's
// 0x2A2A2A2A. The difference is the whole reason RhsOf takes a parameter.
constexpr std::uint32_t kBaseFieldA = 0x11223344U;
constexpr std::uint32_t kBaseFieldB = 0x55667788U;
constexpr std::uint32_t kBaseLow = 0x01010101U;
constexpr std::uint32_t kMagicBase = 0x0000002AU;

// Seed of the base grid at w32/LE: field_a at offset 0, field_b at offset 4.
// Restated from tests/unit/concolic/test_domain_form_width_endian.cpp:267-273.
std::vector<std::uint8_t> BaseGridSeed() {
    std::vector<std::uint8_t> seed;
    for (const std::uint32_t field : {kBaseFieldA, kBaseFieldB}) {
        for (unsigned b = 0; b < 4U; ++b) {
            seed.push_back(static_cast<std::uint8_t>(field >> (8U * b)));
        }
    }
    return seed;
}

// The base grid's left-hand side, computed by its OWN arithmetic rather
// than by DerivedOf, so the two are compared and not merely shared. At w32
// the base grid's Trunc is the identity on std::uint32_t, so the
// truncations of tests/unit/concolic/test_domain_form_width_endian.cpp:157-177
// are the plain operators here.
std::uint32_t BaseGridDerived(FormKind form) {
    switch (form) {
        case FormKind::kAdd:
            return kBaseFieldA + kBaseFieldB;
        case FormKind::kSub:
            return kBaseFieldA - kBaseFieldB;
        case FormKind::kXor:
            return kBaseFieldA ^ kBaseFieldB;
        case FormKind::kAnd:
            return kBaseFieldA & kBaseFieldB;
        case FormKind::kMul:
            return kBaseFieldA * kBaseFieldB;
        case FormKind::kAddConst:
            return kBaseFieldA + 0x00000010U;
        case FormKind::kLt:
            return kBaseFieldA;  // verbatim left-hand side, :175-177
    }
    return 0;
}

// Records of the base grid at w32/LE: two guards at site ids 0 and 1, then
// the gate at site id 2. Restated from
// tests/unit/concolic/test_domain_form_width_endian.cpp:319-325.
std::vector<BranchReader::Record> BaseGridRecords(FormKind form) {
    std::vector<BranchReader::Record> records;
    records.push_back({0U, kUgt, 32U, kBaseFieldA, kBaseLow});
    records.push_back({1U, kUgt, 32U, kBaseFieldB, kBaseLow});
    const std::uint8_t predicate = form == FormKind::kLt ? kUlt : kEq;
    const std::uint32_t rhs = form == FormKind::kLt ? kBaseFieldB : kMagicBase;
    records.push_back({2U, predicate, 32U, BaseGridDerived(form), rhs});
    return records;
}

// --- comparison of two record sets, field by field -----------------------

void ExpectSameRecords(const std::vector<BranchReader::Record>& got,
                       const std::vector<BranchReader::Record>& want) {
    ASSERT_EQ(got.size(), want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "record=" << i);
        EXPECT_EQ(got[i].site_id, want[i].site_id);
        EXPECT_EQ(got[i].predicate, want[i].predicate);
        EXPECT_EQ(got[i].bit_width, want[i].bit_width);
        EXPECT_EQ(got[i].lhs, want[i].lhs);
        EXPECT_EQ(got[i].rhs, want[i].rhs);
    }
}

// --- the measured control cells ------------------------------------------

// Control A: `add` at the arities of this file's sweep, with this file's
// own literal — which is also the arity oracle's literal.
const std::array<Cell, 2>& AddControl() {
    static const std::array<Cell, 2> cells = {Measure(FormKind::kAdd, 4U),
                                              Measure(FormKind::kAdd, 8U)};
    return cells;
}

// Control B: the six forms at arity 2, under the BASE GRID's literal.
const std::array<Cell, 6>& BaseControl() {
    static const std::array<Cell, 6> cells = {
        MeasureWithLiteral(FormKind::kSub, 2U, kMagicBase),
        MeasureWithLiteral(FormKind::kXor, 2U, kMagicBase),
        MeasureWithLiteral(FormKind::kAnd, 2U, kMagicBase),
        MeasureWithLiteral(FormKind::kMul, 2U, kMagicBase),
        MeasureWithLiteral(FormKind::kAddConst, 2U, kMagicBase),
        MeasureWithLiteral(FormKind::kLt, 2U, kMagicBase)};
    return cells;
}

// The same six cells under THIS file's literal, so the one fixture
// difference between the control and the twelve-cell sweep is measured
// rather than waved through.
const std::array<Cell, 6>& BaseControlOwnLiteral() {
    static const std::array<Cell, 6> cells = {MeasureWithLiteral(FormKind::kSub, 2U, kMagic),
                                              MeasureWithLiteral(FormKind::kXor, 2U, kMagic),
                                              MeasureWithLiteral(FormKind::kAnd, 2U, kMagic),
                                              MeasureWithLiteral(FormKind::kMul, 2U, kMagic),
                                              MeasureWithLiteral(FormKind::kAddConst, 2U, kMagic),
                                              MeasureWithLiteral(FormKind::kLt, 2U, kMagic)};
    return cells;
}

// The base grid's published w32/LE row, one entry per form, transcribed
// from docs/experiments/solver-domain-form-width-endian/report.md:182 (sub),
// :190 (xor), :198 (and), :206 (mul), :214 (add-const), :222 (lt).
struct BaseExpected {
    FormKind form;
    Operand::Kind kind;
    bool gate_survived;
    std::size_t path_size;
    SolveOutcome outcome;
};

constexpr std::array<BaseExpected, 6> kBaseExpected{{
    {FormKind::kSub, Operand::Kind::kConst, false, 2, SolveOutcome::kCandidate},
    {FormKind::kXor, Operand::Kind::kConst, false, 2, SolveOutcome::kCandidate},
    {FormKind::kAnd, Operand::Kind::kConst, false, 2, SolveOutcome::kCandidate},
    {FormKind::kMul, Operand::Kind::kConst, false, 2, SolveOutcome::kCandidate},
    {FormKind::kAddConst, Operand::Kind::kConst, false, 2, SolveOutcome::kCandidate},
    // The one BOUND cell of the row: `lt` compares a VERBATIM field against
    // another field, so both sides bind and the gate record survives.
    {FormKind::kLt, Operand::Kind::kVar, true, 3, SolveOutcome::kCandidate},
}};

}  // namespace

// ---------------------------------------------------------------------
// Control A — `add` against docs/experiments/solver-domain-arity/report.md
// ---------------------------------------------------------------------

// The inputs first. At arity 4 this harness must submit exactly what the
// arity oracle submits: the same seed bytes and the same five records. If
// this fails, the numbers below are numbers about a different experiment.
TEST(DomainArityFormsControl, AddInputsAreTheArityOracleInputs) {
    for (unsigned k = 1; k <= kArityOracleMaxK; ++k) {
        SCOPED_TRACE(testing::Message() << "arity=" << k);
        EXPECT_EQ(SeedOf(k), ArityOracleSeed(k));
        ExpectSameRecords(RecordsFor(FormKind::kAdd, k, kMagic), ArityOracleRecords(k));
    }
}

// The published cell. docs/experiments/solver-domain-arity/report.md:62 —
// `a+b+c+d == MAGIC` classifies kConst, the gate record does NOT survive
// (path 4 of 5), and SolveForCandidate still reports kCandidate;
// report.md:172-173 pins path_size = 4 and gate_taken = NO;
// report.md:49-50 pins num_vars = k.
TEST(DomainArityFormsControl, AddAtArityFourReproducesTheArityReport) {
    const Cell& cell = AddControl()[0];
    ASSERT_EQ(cell.arity, 4U);
    EXPECT_TRUE(cell.buildable);
    EXPECT_EQ(cell.num_vars, std::size_t{4});
    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, std::size_t{4});
    EXPECT_EQ(cell.records, std::size_t{5});
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    // Same fixture hygiene the sweep demands of its own cells.
    EXPECT_FALSE(cell.derived_findable);
    EXPECT_NE(cell.derived, kFields[3]);
}

// The honest half of control A. The arity oracle's axis ends at four
// addends, so `add` at arity 8 reproduces NOTHING: there is no published
// cell to agree with. What is asserted here is only that this file's own
// arity-8 measurement of `add` continues the shape the oracle established
// at k >= 3 — the fold classifies kConst, the gate is dropped, the guards
// survive alone. Read it as an extension of the oracle's axis by this file,
// not as a confirmation of the oracle.
TEST(DomainArityFormsControl, AddAtArityEightExtendsTheAxisBeyondTheOracle) {
    ASSERT_GT(8U, kArityOracleMaxK) << "arity 8 is not outside the oracle's axis after all";
    const Cell& cell = AddControl()[1];
    ASSERT_EQ(cell.arity, 8U);
    EXPECT_TRUE(cell.buildable);
    EXPECT_EQ(cell.num_vars, std::size_t{8});
    EXPECT_EQ(cell.derived_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, std::size_t{8});
    EXPECT_EQ(cell.records, std::size_t{9});
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.derived_findable);
    EXPECT_NE(cell.derived, kFields[7]);
}

// `add` is the form the twelve-cell sweep deliberately excludes, and this
// says why that exclusion costs nothing: at both arities of the sweep the
// control cell lands on the same class as all twelve — NO-BINDING. The
// sweep's verdict `k_max_bound = 2`
// (docs/experiments/solver-domain-arity/report.md:75) is therefore stated
// over seven forms, not six.
TEST(DomainArityFormsControl, AddControlAgreesWithTheSweepsClass) {
    for (const Cell& cell : AddControl()) {
        SCOPED_TRACE(testing::Message() << "arity=" << cell.arity);
        EXPECT_FALSE(IsBound(cell));
        EXPECT_STREQ(ClassOf(cell), "NO-BINDING");
    }
}

// ---------------------------------------------------------------------
// Control B — the six forms at arity 2 against
// docs/experiments/solver-domain-form-width-endian/report.md
// ---------------------------------------------------------------------

// The inputs first, again. THE ARITY RULE at the top of this file claims
// that substituting k = 2 reproduces the base grid form by form. That claim
// is checked here as record equality, not as prose: for each of the six
// forms, the records this harness submits at arity 2 under the base grid's
// literal must be the base grid's own records, computed by the base grid's
// own arithmetic.
TEST(DomainArityFormsControl, ArityTwoInputsAreTheBaseGridInputs) {
    EXPECT_EQ(SeedOf(2U), BaseGridSeed());
    for (const BaseExpected& want : kBaseExpected) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(want.form));
        ExpectSameRecords(RecordsFor(want.form, 2U, kMagicBase), BaseGridRecords(want.form));
    }
    // The rule holds for `add` too, which is the seventh form of the base
    // grid and the control of control A.
    ExpectSameRecords(RecordsFor(FormKind::kAdd, 2U, kMagicBase), BaseGridRecords(FormKind::kAdd));
}

// The six published cells, form by form.
TEST(DomainArityFormsControl, ArityTwoReproducesTheBaseGridRow) {
    const std::array<Cell, 6>& cells = BaseControl();
    ASSERT_EQ(cells.size(), kBaseExpected.size());
    for (std::size_t i = 0; i < kBaseExpected.size(); ++i) {
        const Cell& cell = cells[i];
        const BaseExpected& want = kBaseExpected[i];
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(want.form) << " arity=2");
        ASSERT_EQ(cell.form, want.form);
        ASSERT_EQ(cell.arity, 2U);
        EXPECT_TRUE(cell.buildable);
        EXPECT_EQ(cell.num_vars, std::size_t{2});
        EXPECT_EQ(cell.derived_kind, want.kind);
        EXPECT_EQ(cell.gate_survived, want.gate_survived);
        EXPECT_EQ(cell.path_size, want.path_size);
        EXPECT_EQ(cell.outcome, want.outcome);
        EXPECT_TRUE(cell.has_candidate);
    }
}

// One cell of the base row is BOUND and five are not, and the boundary is
// not an accident of arity: `lt` is the only form whose left-hand side is a
// field logged verbatim, so it is the only one FindFirst can locate in the
// seed. This is asserted as findability, which is the mechanism, and not
// only as the Kind, which is its consequence.
TEST(DomainArityFormsControl, ArityTwoBindsExactlyTheVerbatimForm) {
    std::size_t bound = 0;
    for (const Cell& cell : BaseControl()) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form));
        const bool verbatim = cell.form == FormKind::kLt;
        EXPECT_EQ(cell.derived_findable, verbatim);
        EXPECT_EQ(IsBound(cell), verbatim);
        if (IsBound(cell)) {
            ++bound;
        }
    }
    EXPECT_EQ(bound, std::size_t{1});
}

// The single fixture difference between control B and the twelve-cell sweep
// is the gate literal: 0x2A there, 0x2A2A2A2A here. Swapping it moves
// nothing — same Kind, same survival, same path, same outcome — so the
// sweep's cells are measured on the same footing as the base grid's, and
// the arity axis is the only axis that moved.
TEST(DomainArityFormsControl, ArityTwoIsInsensitiveToTheGateLiteral) {
    const std::array<Cell, 6>& base = BaseControl();
    const std::array<Cell, 6>& own = BaseControlOwnLiteral();
    ASSERT_NE(kMagicBase, kMagic) << "the two literals are the same — this control is vacuous";
    for (std::size_t i = 0; i < base.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(base[i].form));
        ASSERT_EQ(base[i].form, own[i].form);
        EXPECT_EQ(base[i].literal, kMagicBase);
        EXPECT_EQ(own[i].literal, kMagic);
        EXPECT_EQ(own[i].derived_kind, base[i].derived_kind);
        EXPECT_EQ(own[i].gate_survived, base[i].gate_survived);
        EXPECT_EQ(own[i].path_size, base[i].path_size);
        EXPECT_EQ(own[i].outcome, base[i].outcome);
        EXPECT_EQ(own[i].has_candidate, base[i].has_candidate);
    }
}

// The control table, printed the same flat way as the sweep's, so the two
// halves of the run can be lifted out of one ctest log side by side.
TEST(DomainArityFormsControl, DumpControlCells) {
    std::cout << "# DOMAIN-ARITY-FORMS-CONTROL width=w32 endian=LE literal_side=one\n";
    std::cout << "# control form arity literal records path num_vars binding kind gate_survived "
                 "outcome has_candidate\n";
    for (const Cell& cell : AddControl()) {
        std::cout << "arity-report " << NameOf(cell.form) << ' ' << cell.arity << " 0x" << std::hex
                  << cell.literal << std::dec << ' ' << cell.records << ' ' << cell.path_size << ' '
                  << cell.num_vars << ' ' << ClassOf(cell) << ' ' << KindName(cell.derived_kind)
                  << ' ' << (cell.gate_survived ? "yes" : "no") << ' ' << OutcomeName(cell.outcome)
                  << ' ' << (cell.has_candidate ? "yes" : "no") << '\n';
    }
    for (const Cell& cell : BaseControl()) {
        std::cout << "base-grid " << NameOf(cell.form) << ' ' << cell.arity << " 0x" << std::hex
                  << cell.literal << std::dec << ' ' << cell.records << ' ' << cell.path_size << ' '
                  << cell.num_vars << ' ' << ClassOf(cell) << ' ' << KindName(cell.derived_kind)
                  << ' ' << (cell.gate_survived ? "yes" : "no") << ' ' << OutcomeName(cell.outcome)
                  << ' ' << (cell.has_candidate ? "yes" : "no") << '\n';
    }
    std::cout << std::flush;
    SUCCEED();
}
