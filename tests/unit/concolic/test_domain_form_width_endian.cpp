#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Solver domain map in THREE axes: gate FORM x field WIDTH x BYTE ORDER
// (task-042, ADR 0035 §2). This file MEASURES what the existing
// reconstruction in src/concolic sees; it adds no rule and changes
// nothing under src/.
//
// What was already pinned, separately, on two one-dimensional slices:
//   * the FORM axis — seven algebraic forms, but only at u32/LE
//     (tests/unit/concolic/test_domain_map.cpp:141-277, verdict at
//     docs/experiments/solver-domain-map/report.md:138);
//   * the WIDTH x BYTE ORDER axis — u8/u16/u32/u64 x LE/BE, but only for
//     the single form `a + b == MAGIC`
//     (tests/unit/concolic/test_domain_width_map.cpp:300-358, verdict at
//     docs/experiments/solver-domain-map/width-endianness.md:186).
// Nobody had taken the CROSSING of the two, which is the only place the
// question "does a form keep its domain status when the encoding
// changes?" can be answered. This file takes it: 7 forms x 4 widths x 2
// byte orders = 56 cells, every cell measured, none left blank.
//
// Method, inherited cell-for-cell from the two files above so that the
// overlapping cells stay comparable:
//   * the seed of a cell carries exactly two fields of the cell's width
//     in the cell's byte order, at offsets 0 and width/8
//     (PutField/GetField/Trunc restated below from
//     test_domain_width_map.cpp:57-82 — those live in that file's
//     anonymous namespace and the file must stay byte-for-byte, so the
//     helpers are restated here rather than shared);
//   * two guard records (a >u LOW, b >u LOW, both TRUE on the seed) make
//     the fields findable, exactly as sites C1/C2 do in the real
//     cov_xfield log (test_concolic.cpp:40-41); without them nothing
//     carries a verbatim field value and no variable is ever discovered
//     (BuildSystem pass 1, src/concolic/concolic.cpp:225-228);
//   * the third record is the gate: the value the runtime would log for
//     the form on its LHS, the gate's constant (or the second field, for
//     the ordering form) on its RHS;
//   * the derived operand's Kind is read off a PROBE system whose gate
//     record is `derived <eq> b`, the trick from test_domain_map.cpp:96 —
//     BindOperand classifies each side independently
//     (src/concolic/concolic.cpp:240-243), so the probe's LHS Kind is the
//     real form's LHS Kind, but the probe's RHS binds to a field and keeps
//     the record from being dropped, which makes the Kind observable
//     instead of inferred from the drop.
//
// A cell records (i) the Operand::Kind of the derived operand, (ii) the
// SolveOutcome, and (iii) whether the candidate, re-read at the TRUE
// offsets in the cell's own byte order, actually FLIPS the gate. (iii) is
// the column that carries the finding: report.md:138 already pins that
// all seven forms return kCandidate, so SolveOutcome alone cannot tell an
// in-domain cell from an out-of-domain one. "Flips" and not "holds",
// because SolveForCandidate solves `{non-target} ∧ ¬target`: for the six
// equality forms the gate is FALSE on the seed and a working solver makes
// it true, while for the ordering form it is TRUE on the seed and a
// working solver makes it false. Both are the same event — the solver
// moved the gate — and only the flip formulation is uniform over the
// grid.
//
// NO-BINDING cells are findings, not failures: they are pinned exactly
// like BOUND ones.

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
constexpr unsigned kBits = 8;

// ---------------------------------------------------------------------
// Encoding helpers, restated from test_domain_width_map.cpp:57-82.
// ---------------------------------------------------------------------

std::uint64_t Trunc(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

void PutField(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint64_t value,
              unsigned bit_width, bool big_endian) {
    const unsigned n = bit_width / kBits;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBits * (n - 1U - k)) : (kBits * k);
        buf[offset + k] = static_cast<std::uint8_t>(value >> shift);
    }
}

std::uint64_t GetField(const std::uint8_t* bytes, std::size_t offset, unsigned bit_width,
                       bool big_endian) {
    const unsigned n = bit_width / kBits;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBits * (n - 1U - k)) : (kBits * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

// Independent restatement of the substring search FindFirst performs
// (src/concolic/concolic.cpp:136). A derived value that happens to occur
// in the seed would bind DIRECT as a variable and quietly turn a measured
// cell into a different measurement, so every cell records this flag.
bool Occurs(const std::vector<std::uint8_t>& seed, std::uint64_t value, unsigned bit_width) {
    const unsigned n = bit_width / kBits;
    if (n == 0U || seed.size() < n) {
        return false;
    }
    const std::uint64_t v = Trunc(value, bit_width);
    for (std::size_t off = 0; off + n <= seed.size(); ++off) {
        bool le = true;
        bool be = true;
        for (unsigned k = 0; k < n; ++k) {
            const std::uint8_t byte = seed[off + k];
            if (byte != static_cast<std::uint8_t>(v >> (kBits * k))) {
                le = false;
            }
            if (byte != static_cast<std::uint8_t>(v >> (kBits * (n - 1U - k)))) {
                be = false;
            }
        }
        if (le || be) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------
// Axis 1 — the seven gate forms (the same seven as
// test_domain_map.cpp:154-277), each as a per-form arithmetic helper
// parameterised by bit_width.
// ---------------------------------------------------------------------

// The compile-time addend of FORM 6, pinned from test_domain_map.cpp:245.
constexpr std::uint64_t kConstAddend = 0x00000010ULL;

std::uint64_t SumOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) + Trunc(b, w), w);
}
std::uint64_t DiffOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) - Trunc(b, w), w);
}
std::uint64_t XorOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) ^ Trunc(b, w), w);
}
std::uint64_t AndOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) & Trunc(b, w), w);
}
std::uint64_t MulOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) * Trunc(b, w), w);
}
std::uint64_t AddConstOf(std::uint64_t a, unsigned w) {
    return Trunc(Trunc(a, w) + Trunc(kConstAddend, w), w);
}
bool LessThanOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(a, w) < Trunc(b, w);
}

enum class FormKind { kAdd, kSub, kXor, kAnd, kMul, kAddConst, kLt };

struct FormSpec {
    FormKind kind;
    const char* name;
    bool lhs_is_verbatim;  ///< true only for `lt`, whose LHS IS a field
};

constexpr std::array<FormSpec, 7> kForms{{
    {FormKind::kAdd, "add", false},
    {FormKind::kSub, "sub", false},
    {FormKind::kXor, "xor", false},
    {FormKind::kAnd, "and", false},
    {FormKind::kMul, "mul", false},
    {FormKind::kAddConst, "add-const", false},
    {FormKind::kLt, "lt", true},
}};

// The value the runtime logs on the gate's LHS for this form. For the
// ordering form that value is the field itself.
std::uint64_t DerivedOf(FormKind form, std::uint64_t a, std::uint64_t b, unsigned w) {
    switch (form) {
        case FormKind::kAdd:
            return SumOf(a, b, w);
        case FormKind::kSub:
            return DiffOf(a, b, w);
        case FormKind::kXor:
            return XorOf(a, b, w);
        case FormKind::kAnd:
            return AndOf(a, b, w);
        case FormKind::kMul:
            return MulOf(a, b, w);
        case FormKind::kAddConst:
            return AddConstOf(a, w);
        case FormKind::kLt:
            break;
    }
    return Trunc(a, w);
}

// Does the gate hold for these two field values? Evaluated on the fields,
// not on the log, so it can be applied to a candidate as well as to the
// seed.
bool GateHolds(FormKind form, std::uint64_t a, std::uint64_t b, unsigned w, std::uint64_t magic) {
    if (form == FormKind::kLt) {
        return LessThanOf(a, b, w);
    }
    return DerivedOf(form, a, b, w) == Trunc(magic, w);
}

std::uint8_t PredicateOf(FormKind form) {
    return form == FormKind::kLt ? kUlt : kEq;
}

// ---------------------------------------------------------------------
// Axes 2 and 3 — width and byte order. The field/guard/magic constants
// per width are taken UNCHANGED from test_domain_width_map.cpp:128-180,
// and its u32 row is in turn the same fixture as
// test_domain_map.cpp:54-62, so the cells this grid shares with task-026
// and task-022 are the same cells and must produce the same values.
// ---------------------------------------------------------------------

struct WidthConst {
    unsigned bit_width;
    std::uint64_t field_a;
    std::uint64_t field_b;
    std::uint64_t low;    ///< guard bound, below both fields and absent from the seed
    std::uint64_t magic;  ///< the gate's constant, absent from the seed
};

constexpr WidthConst kW8{
    .bit_width = 8, .field_a = 0x11U, .field_b = 0x22U, .low = 0x05U, .magic = 0x2AU};
constexpr WidthConst kW16{
    .bit_width = 16, .field_a = 0x1122U, .field_b = 0x3344U, .low = 0x0101U, .magic = 0x002AU};
constexpr WidthConst kW32{.bit_width = 32,
                          .field_a = 0x11223344U,
                          .field_b = 0x55667788U,
                          .low = 0x01010101U,
                          .magic = 0x0000002AU};
constexpr WidthConst kW64{.bit_width = 64,
                          .field_a = 0x1122334455667788ULL,
                          .field_b = 0x99AABBCCDDEEFF11ULL,
                          .low = 0x0101010101010101ULL,
                          .magic = 0x000000000000002AULL};

constexpr std::array<WidthConst, 4> kWidths{{kW8, kW16, kW32, kW64}};
constexpr std::array<bool, 2> kByteOrders{{false, true}};

std::vector<std::uint8_t> SeedOf(const WidthConst& w, bool big_endian) {
    const unsigned n = w.bit_width / kBits;
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(2U * n));
    PutField(seed, 0, w.field_a, w.bit_width, big_endian);
    PutField(seed, n, w.field_b, w.bit_width, big_endian);
    return seed;
}

// ---------------------------------------------------------------------
// One measured cell of the 7 x 4 x 2 grid.
// ---------------------------------------------------------------------

struct Cell {
    bool measured = false;  ///< set by Measure; a false here is an EMPTY cell
    FormKind form = FormKind::kAdd;
    unsigned bit_width = 0;
    bool big_endian = false;

    Operand::Kind derived_kind = Operand::Kind::kConst;  ///< from the PROBE system
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    bool gate_survived = false;
    Operand::Kind gate_lhs_kind = Operand::Kind::kConst;
    Operand::Kind gate_rhs_kind = Operand::Kind::kConst;
    std::size_t offset_a = 0;
    std::size_t offset_b = 0;
    unsigned width_a = 0;
    unsigned width_b = 0;
    bool be_a = false;
    bool be_b = false;

    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    bool guards_hold_end_to_end = false;   ///< candidate re-read at TRUE offsets
    bool gate_flipped_end_to_end = false;  ///< candidate moves the gate off its seed value
    bool gate_taken_on_seed = false;       ///< what the gate evaluated to BEFORE solving

    // Why a cell binds, when it binds. Both are computed here, not read
    // from src/, so a BOUND cell is never a mystery.
    bool derived_findable = false;     ///< derived value occurs verbatim in the seed
    bool derived_is_pair_sum = false;  ///< derived value equals a+a, a+b or b+b
};

Cell Measure(FormKind form, const WidthConst& w, bool big_endian) {
    const unsigned bw = w.bit_width;
    const unsigned n = bw / kBits;
    const std::vector<std::uint8_t> seed = SeedOf(w, big_endian);
    const auto width_byte = static_cast<std::uint8_t>(bw);

    const std::uint64_t derived = DerivedOf(form, w.field_a, w.field_b, bw);
    const std::uint64_t rhs = form == FormKind::kLt ? Trunc(w.field_b, bw) : Trunc(w.magic, bw);

    const std::vector<BranchReader::Record> guards = {
        {0, kUgt, width_byte, w.field_a, w.low},
        {1, kUgt, width_byte, w.field_b, w.low},
    };

    std::vector<BranchReader::Record> records = guards;
    records.push_back({2, PredicateOf(form), width_byte, derived, rhs});

    std::vector<BranchReader::Record> probe = guards;
    probe.push_back({2, kEq, width_byte, derived, w.field_b});

    Cell cell{};
    cell.form = form;
    cell.bit_width = bw;
    cell.big_endian = big_endian;

    const System probe_sys = BuildSystem(seed, probe);
    if (probe_sys.path.empty()) {
        ADD_FAILURE() << "probe system kept no constraint — the probe fixture itself is broken";
    } else {
        cell.derived_kind = probe_sys.path.back().lhs.kind;
    }

    const System sys = BuildSystem(seed, records);
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == records.size();
    if (cell.gate_survived) {
        cell.gate_lhs_kind = sys.path.back().lhs.kind;
        cell.gate_rhs_kind = sys.path.back().rhs.kind;
    }
    if (sys.vars.size() >= 2U) {
        cell.offset_a = sys.vars[0].offset;
        cell.offset_b = sys.vars[1].offset;
        cell.width_a = sys.vars[0].bit_width;
        cell.width_b = sys.vars[1].bit_width;
        cell.be_a = sys.vars[0].big_endian;
        cell.be_b = sys.vars[1].big_endian;
    }

    cell.gate_taken_on_seed = GateHolds(form, w.field_a, w.field_b, bw, w.magic);

    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    if (candidate.has_value() && candidate->size() >= seed.size()) {
        const std::uint64_t a = GetField(candidate->data(), 0, bw, big_endian);
        const std::uint64_t b = GetField(candidate->data(), n, bw, big_endian);
        const std::uint64_t low = Trunc(w.low, bw);
        cell.guards_hold_end_to_end = a > low && b > low;
        cell.gate_flipped_end_to_end =
            GateHolds(form, a, b, bw, w.magic) != cell.gate_taken_on_seed;
    }

    cell.derived_findable = Occurs(seed, derived, bw);
    const std::uint64_t a_t = Trunc(w.field_a, bw);
    const std::uint64_t b_t = Trunc(w.field_b, bw);
    cell.derived_is_pair_sum = derived == Trunc(a_t + a_t, bw) || derived == Trunc(a_t + b_t, bw) ||
                               derived == Trunc(b_t + b_t, bw);

    cell.measured = true;
    return cell;
}

// ---------------------------------------------------------------------
// Rendering — the raw ctest log IS the table, so every cell prints one
// self-describing line and the grid prints its own VERDICT.
// ---------------------------------------------------------------------

const char* KindName(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kAddVars:
            return "kAddVars";
        case Operand::Kind::kConst:
            break;
    }
    return "kConst";
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
            break;
    }
    return "kError";
}

const char* NameOf(FormKind form) {
    for (const FormSpec& spec : kForms) {
        if (spec.kind == form) {
            return spec.name;
        }
    }
    return "?";
}

// The cell's verdict class: what a reader of the map must compare across
// axes. BOUND means the gate's derived operand reached the solver as
// something other than a constant; FLIP means the candidate actually
// moved the gate at the TRUE field offsets.
std::string ClassOf(const Cell& cell) {
    const bool bound = cell.derived_kind != Operand::Kind::kConst;
    std::string cls = bound ? "BOUND" : "NO-BINDING";
    cls += cell.gate_flipped_end_to_end ? "+FLIP" : "+NO-FLIP";
    return cls;
}

void PrintCell(const Cell& cell) {
    std::cout << "CELL form=" << NameOf(cell.form) << " width=u" << cell.bit_width
              << " endian=" << (cell.big_endian ? "BE" : "LE")
              << " derived_kind=" << KindName(cell.derived_kind)
              << " gate_survived=" << (cell.gate_survived ? 1 : 0) << " path=" << cell.path_size
              << "/3 lhs=" << KindName(cell.gate_lhs_kind)
              << " rhs=" << KindName(cell.gate_rhs_kind) << " outcome=" << OutcomeName(cell.outcome)
              << " candidate=" << (cell.has_candidate ? 1 : 0)
              << " guards_hold=" << (cell.guards_hold_end_to_end ? 1 : 0)
              << " gate_on_seed=" << (cell.gate_taken_on_seed ? 1 : 0)
              << " gate_flipped=" << (cell.gate_flipped_end_to_end ? 1 : 0)
              << " be_a=" << (cell.be_a ? 1 : 0) << " be_b=" << (cell.be_b ? 1 : 0)
              << " derived_findable=" << (cell.derived_findable ? 1 : 0)
              << " derived_is_pair_sum=" << (cell.derived_is_pair_sum ? 1 : 0)
              << " class=" << ClassOf(cell) << "\n";
}

// The whole grid, measured once and reused by every test below.
struct Grid {
    std::vector<Cell> cells;

    const Cell& At(FormKind form, unsigned bit_width, bool big_endian) const {
        for (const Cell& cell : cells) {
            if (cell.form == form && cell.bit_width == bit_width && cell.big_endian == big_endian) {
                return cell;
            }
        }
        ADD_FAILURE() << "grid has no cell for form=" << NameOf(form) << " width=" << bit_width
                      << " endian=" << (big_endian ? "BE" : "LE");
        return cells.at(0);
    }
};

const Grid& TheGrid() {
    static const Grid grid = [] {
        Grid g;
        for (const FormSpec& form : kForms) {
            for (const WidthConst& w : kWidths) {
                for (const bool be : kByteOrders) {
                    g.cells.push_back(Measure(form.kind, w, be));
                }
            }
        }
        return g;
    }();
    return grid;
}

}  // namespace

// Sanity for the fixtures themselves, one row per cell. If a magic, a
// guard bound or a derived value were findable in its own seed, the cell
// would bind that constant as a variable and the grid would be forged
// rather than measured. The ordering form is exempt from the derived
// check: its LHS is a field and MUST be findable — that is the form.
TEST(DomainFormWidthEndian, FixtureConstantsAreNotFindable) {
    for (const WidthConst& w : kWidths) {
        for (const bool be : kByteOrders) {
            SCOPED_TRACE(testing::Message() << "width=" << w.bit_width << " big_endian=" << be);
            const std::vector<std::uint8_t> seed = SeedOf(w, be);
            ASSERT_EQ(seed.size(), static_cast<std::size_t>(2U * (w.bit_width / kBits)));
            EXPECT_FALSE(Occurs(seed, w.magic, w.bit_width)) << "magic aliases onto the seed";
            EXPECT_FALSE(Occurs(seed, w.low, w.bit_width)) << "guard bound aliases onto the seed";
            for (const FormSpec& form : kForms) {
                const std::uint64_t derived =
                    DerivedOf(form.kind, w.field_a, w.field_b, w.bit_width);
                const bool findable = Occurs(seed, derived, w.bit_width);
                EXPECT_EQ(findable, form.lhs_is_verbatim)
                    << "form=" << form.name << ": a derived value that occurs in the seed binds "
                    << "DIRECT and the cell stops measuring reconstruction";
            }
        }
    }
}

// The grid itself. Prints the full table and the VERDICT line; the raw
// ctest log of this test is the artifact
// (docs/experiments/solver-domain-form-width-endian/raw-ctest.txt).
TEST(DomainFormWidthEndian, GridOfSevenFormsByFourWidthsByTwoByteOrders) {
    const Grid& grid = TheGrid();
    ASSERT_EQ(grid.cells.size(), kForms.size() * kWidths.size() * kByteOrders.size());

    std::size_t bound = 0;
    std::size_t no_binding = 0;
    std::size_t satisfies = 0;
    for (const Cell& cell : grid.cells) {
        // No blank cells: every cell of the grid was actually measured.
        ASSERT_TRUE(cell.measured)
            << "empty cell form=" << NameOf(cell.form) << " width=" << cell.bit_width;
        // The guards alone always bind, at every width and byte order, so
        // a NO-BINDING cell below never means "the log was opaque" — it
        // means the GATE fell out while the guards stayed.
        EXPECT_EQ(cell.num_vars, 2U) << "form=" << NameOf(cell.form) << " width=" << cell.bit_width;
        EXPECT_EQ(cell.offset_a, 0U);
        EXPECT_EQ(cell.offset_b, static_cast<std::size_t>(cell.bit_width / kBits));
        PrintCell(cell);
        if (cell.derived_kind == Operand::Kind::kConst) {
            ++no_binding;
        } else {
            ++bound;
        }
        if (cell.gate_flipped_end_to_end) {
            ++satisfies;
        }
    }
    EXPECT_EQ(bound + no_binding, grid.cells.size()) << "a cell was counted in neither column";

    // Which forms change verdict class along an axis. Empty lists are the
    // interesting outcome: they mean the form axis is INDEPENDENT of the
    // encoding axes over this grid.
    std::string width_dependent;
    std::string endian_dependent;
    for (const FormSpec& form : kForms) {
        bool by_width = false;
        for (const bool be : kByteOrders) {
            const std::string first = ClassOf(grid.At(form.kind, kWidths[0].bit_width, be));
            for (const WidthConst& w : kWidths) {
                if (ClassOf(grid.At(form.kind, w.bit_width, be)) != first) {
                    by_width = true;
                }
            }
        }
        bool by_endian = false;
        for (const WidthConst& w : kWidths) {
            if (ClassOf(grid.At(form.kind, w.bit_width, false)) !=
                ClassOf(grid.At(form.kind, w.bit_width, true))) {
                by_endian = true;
            }
        }
        if (by_width) {
            width_dependent += width_dependent.empty() ? "" : "+";
            width_dependent += form.name;
        }
        if (by_endian) {
            endian_dependent += endian_dependent.empty() ? "" : "+";
            endian_dependent += form.name;
        }
    }

    std::cout << "VERDICT: DOMAIN-3AXIS: cells=" << grid.cells.size() << ", bound=" << bound
              << ", no_binding=" << no_binding << ", candidate_satisfies=" << satisfies
              << ", width_dependent_forms=" << (width_dependent.empty() ? "none" : width_dependent)
              << ", endian_dependent_forms="
              << (endian_dependent.empty() ? "none" : endian_dependent) << ", grid=7x4x2\n";
}

// Cross-check A — the u32/LE column of this grid must reproduce the FORM
// axis pinned by task-022 (docs/experiments/solver-domain-map/report.md:138,
// tests/unit/concolic/test_domain_map.cpp:154-277). A mismatch here is a
// finding about one of the two measurements, not a rounding difference.
TEST(DomainFormWidthEndian, AgreesWithTask022FormAxisAtU32LittleEndian) {
    const Grid& grid = TheGrid();
    const std::array<std::pair<FormKind, Operand::Kind>, 7> pinned{{
        {FormKind::kAdd, Operand::Kind::kAddVars},     // report.md:65
        {FormKind::kSub, Operand::Kind::kConst},       // report.md:66
        {FormKind::kXor, Operand::Kind::kConst},       // report.md:67
        {FormKind::kAnd, Operand::Kind::kConst},       // report.md:69
        {FormKind::kMul, Operand::Kind::kConst},       // report.md:70
        {FormKind::kAddConst, Operand::Kind::kConst},  // report.md:71
        {FormKind::kLt, Operand::Kind::kVar},          // report.md:72
    }};
    for (const auto& [form, kind] : pinned) {
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(form));
        const Cell& cell = grid.At(form, 32, false);
        EXPECT_EQ(cell.derived_kind, kind) << "diverges from the task-022 pin at u32/LE";
        // report.md:138: all seven return kCandidate, which is exactly why
        // outcome alone cannot separate BOUND from NO-BINDING.
        EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
        EXPECT_EQ(cell.gate_survived, kind != Operand::Kind::kConst);
        EXPECT_EQ(cell.path_size, kind != Operand::Kind::kConst ? 3U : 2U);
    }
}

// Cross-check B — the `add` row of this grid must reproduce the WIDTH x
// BYTE ORDER axis pinned by task-026
// (docs/experiments/solver-domain-map/width-endianness.md:186,
// tests/unit/concolic/test_domain_width_map.cpp:300-358): all eight cells
// BOUND(kAddVars), candidate present, gate holding at the true offsets,
// and byte order observable at every width except 8.
TEST(DomainFormWidthEndian, AgreesWithTask026WidthEndianAxisForAdd) {
    const Grid& grid = TheGrid();
    for (const WidthConst& w : kWidths) {
        for (const bool be : kByteOrders) {
            SCOPED_TRACE(testing::Message() << "width=" << w.bit_width << " big_endian=" << be);
            const Cell& cell = grid.At(FormKind::kAdd, w.bit_width, be);
            EXPECT_EQ(cell.derived_kind, Operand::Kind::kAddVars);
            EXPECT_TRUE(cell.gate_survived) << "path kept " << cell.path_size << " of 3 records";
            EXPECT_EQ(cell.gate_lhs_kind, Operand::Kind::kAddVars);
            EXPECT_EQ(cell.gate_rhs_kind, Operand::Kind::kConst);
            EXPECT_EQ(cell.width_a, w.bit_width);
            EXPECT_EQ(cell.width_b, w.bit_width);
            EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
            EXPECT_TRUE(cell.has_candidate);
            EXPECT_TRUE(cell.guards_hold_end_to_end);
            EXPECT_FALSE(cell.gate_taken_on_seed) << "the sum equals the magic already on the seed";
            EXPECT_TRUE(cell.gate_flipped_end_to_end);
            // width-endianness.md:77: at width 8 the two encodings are the
            // same single byte and FindFirst tries little-endian first
            // (src/concolic/concolic.cpp:136), so a u8 field is never
            // reported big-endian.
            const bool observable = be && w.bit_width > 8U;
            EXPECT_EQ(cell.be_a, observable);
            EXPECT_EQ(cell.be_b, observable);
        }
    }
}

// The finding the crossing exists to expose: a form's domain status is
// not a property of the form alone. `xor` is NO-BINDING at u16/u32/u64
// but BOUND at u8 — because the u8 fixture's two fields share no bits, so
// a ^ b == a + b and the pair enumeration (src/concolic/concolic.cpp:195-205)
// matches on the VALUE. task-022 already pinned that aliasing as a hazard
// (test_domain_map.cpp:188-210) on a hand-built disjoint pair; here it
// falls out of the INHERITED u8 constants of task-026, i.e. it is reached
// by an ordinary narrow-field fixture rather than by a constructed one.
TEST(DomainFormWidthEndian, XorBindsAtU8OnlyBecauseTheNarrowFieldsAreBitDisjoint) {
    const Grid& grid = TheGrid();
    ASSERT_EQ(Trunc(kW8.field_a, 8) & Trunc(kW8.field_b, 8), 0U) << "u8 fields are not disjoint";
    ASSERT_NE(Trunc(kW16.field_a, 16) & Trunc(kW16.field_b, 16), 0U);
    ASSERT_NE(Trunc(kW32.field_a, 32) & Trunc(kW32.field_b, 32), 0U);
    ASSERT_NE(kW64.field_a & kW64.field_b, 0U);

    for (const bool be : kByteOrders) {
        SCOPED_TRACE(testing::Message() << "big_endian=" << be);
        const Cell& u8 = grid.At(FormKind::kXor, 8, be);
        EXPECT_EQ(u8.derived_kind, Operand::Kind::kAddVars) << "xor at u8 aliases the sum";
        EXPECT_TRUE(u8.derived_is_pair_sum);
        // The sharpest cell of the whole grid, and the one neither
        // one-dimensional slice could produce: the gate BINDS, the solver
        // returns kCandidate, the guards still hold on the candidate — and
        // the xor gate is STILL not satisfied, because what was solved was
        // `a + b == MAGIC`. A cell can be BOUND and lost at the same time.
        EXPECT_TRUE(u8.gate_survived);
        EXPECT_EQ(u8.outcome, SolveOutcome::kCandidate);
        EXPECT_TRUE(u8.has_candidate);
        EXPECT_TRUE(u8.guards_hold_end_to_end);
        EXPECT_FALSE(u8.gate_flipped_end_to_end)
            << "the candidate solves the SUM the alias re-encoded, not the xor gate";
        for (const unsigned width : {16U, 32U, 64U}) {
            const Cell& wide = grid.At(FormKind::kXor, width, be);
            EXPECT_EQ(wide.derived_kind, Operand::Kind::kConst) << "width=" << width;
            EXPECT_FALSE(wide.derived_is_pair_sum) << "width=" << width;
        }
    }
}

// The hazard column, swept over the whole grid: a NO-BINDING cell still
// returns kCandidate, because the gate record is dropped
// (src/concolic/concolic.cpp:244-247) and the last surviving GUARD becomes
// the target. Reading SolveOutcome alone would call every such cell a
// success at every width and byte order.
TEST(DomainFormWidthEndian, NoBindingCellsStillReportCandidateAtEveryEncoding) {
    const Grid& grid = TheGrid();
    std::size_t dropped = 0;
    for (const Cell& cell : grid.cells) {
        if (cell.derived_kind != Operand::Kind::kConst) {
            continue;
        }
        ++dropped;
        SCOPED_TRACE(testing::Message() << "form=" << NameOf(cell.form) << " width="
                                        << cell.bit_width << " big_endian=" << cell.big_endian);
        EXPECT_FALSE(cell.gate_survived);
        EXPECT_EQ(cell.path_size, 2U) << "the two guards survive, the gate does not";
        EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate) << "outcome alone hides the loss";
        EXPECT_FALSE(cell.gate_flipped_end_to_end) << "a dropped gate cannot have been moved";
    }
    EXPECT_GT(dropped, 0U) << "no NO-BINDING cell in the grid — the fixture changed meaning";
}
