// task-054, unit 1: the both-sides-literal grid of task-049 on all four
// widths and both byte orders.
//
// What this file measures, and how it differs from its two neighbours.
//
//   * task-049 (tests/unit/concolic/test_both_sides_literal.cpp) walks the
//     SAME seven gate forms — a code constant on EACH side — but at one
//     single coordinate of the encoding axes: u32, little-endian. That file
//     is not touched by this one; this grid re-measures its seven cells as a
//     control row and adds the other seven coordinates.
//   * DOMAIN-3AXIS (docs/experiments/solver-domain-form-width-endian/report.md)
//     walks four widths and both byte orders — but at the coordinate
//     "literal side = ONE". Here both coordinates are crossed: a literal on
//     BOTH sides, at every width and every byte order.
//
// So the grid is 7 forms x 4 widths x 2 byte orders = 56 cells, of which the
// seven u32/LE ones are the task-049 control row.
//
// The prediction under test. A side is only in the solver's domain when its
// VALUE is findable in the seed (src/concolic/concolic.cpp:136-166). A side
// built as `field OP literal` is meant to be unfindable, which is why
// task-049 saw kConst on both sides at u32. But the narrower the width, the
// smaller the value space: at w8 a side value is a single byte, and a single
// byte can easily coincide with a seed byte. Where that happens the side
// binds as kVar even though the form declares it literal-bearing — the cell
// stops being a "both sides literal" cell at all. That is recorded per side
// as literal_bound_as_var, together with the offset the value was found at.
//
// The fixture rule across widths. The u32 row IS the task-049 fixture, value
// for value, so its numbers are comparable by construction. The w16 and w8
// rows are those same constants truncated to the width (truncation is
// bitwise, so it preserves the bit-disjointness row 3b depends on). The w64
// row keeps the task-049 constant in the high half and its bitwise
// complement in the low half — with one documented exception: the two
// disjoint constants take a ZERO low half, because a complement low half
// would collide with the field's complement low half and destroy the very
// disjointness row 3b measures.
//
// src/ is not touched by this task. No fuzzing campaign is run: every number
// below comes from BuildSystem/SolveForCandidate on an in-memory fixture.

#include <gtest/gtest.h>

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
constexpr unsigned kBits = 8;
constexpr unsigned kFieldCount = 4;
constexpr std::size_t kNoOffset = static_cast<std::size_t>(-1);

using Fields = std::array<std::uint64_t, kFieldCount>;

// ---------------------------------------------------------------------------
// The width rows. kW32 is the task-049 fixture verbatim.
// ---------------------------------------------------------------------------

struct WidthConst {
    unsigned bit_width;
    Fields fields;
    std::uint64_t low;  ///< the guard bound: every field must be >u this
    std::uint64_t k1;
    std::uint64_t k2;
    std::uint64_t k1_disjoint;
    std::uint64_t k2_disjoint;
    std::uint64_t magic;
};

constexpr WidthConst kW8 = {8,    {0x6CU, 0x83U, 0xA2U, 0x10U}, 0x01U, 0xB9U, 0x77U, 0x81U, 0x24U,
                            0x2AU};

constexpr WidthConst kW16 = {
    16, {0xAE6CU, 0x6C83U, 0x6FA2U, 0x2910U}, 0x0101U, 0x79B9U, 0xCA77U, 0x0181U, 0x8124U, 0x2A2AU};

// Value for value the task-049 fixture (test_both_sides_literal.cpp:97-121).
constexpr WidthConst kW32 = {32,          {0xEA7BAE6CU, 0x5DD86C83U, 0x54676FA2U, 0x35202910U},
                             0x01010101U, 0x9E3779B9U,
                             0x85EBCA77U, 0x05840181U,
                             0xA0258124U, 0x2A2A2A2AU};

constexpr WidthConst kW64 = {
    64,
    {0xEA7BAE6C15845193ULL, 0x5DD86C83A227937CULL, 0x54676FA2AB98905DULL, 0x35202910CADFD6EFULL},
    0x01010101FEFEFEFEULL,
    0x9E3779B961C88646ULL,
    0x85EBCA777A143588ULL,
    0x0584018100000000ULL,  // zero low half on purpose
    0xA025812400000000ULL,  // (see the header comment)
    0x2A2A2A2AD5D5D5D5ULL};

constexpr std::array<const WidthConst*, 4> kWidths = {&kW8, &kW16, &kW32, &kW64};
constexpr std::array<bool, 2> kByteOrders = {false, true};

// ---------------------------------------------------------------------------
// Encoding helpers.
// ---------------------------------------------------------------------------

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

std::vector<std::uint8_t> SeedOf(const WidthConst& w, bool big_endian) {
    const unsigned n = w.bit_width / kBits;
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(kFieldCount) * n);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        PutField(seed, static_cast<std::size_t>(i) * n, w.fields[i], w.bit_width, big_endian);
    }
    return seed;
}

// Guards pin every field as a variable, exactly as task-049 does
// (test_both_sides_literal.cpp:133-140): field >u low, one record per field.
std::vector<BranchReader::Record> GuardsFor(const WidthConst& w) {
    std::vector<BranchReader::Record> guards;
    guards.reserve(kFieldCount);
    const auto width_byte = static_cast<std::uint8_t>(w.bit_width);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        guards.push_back({i, kUgt, width_byte, w.fields[i], w.low});
    }
    return guards;
}

Fields FieldsOfCandidate(const mlfuzzz3::mutation::FuzzInput& input, const WidthConst& w,
                         bool big_endian) {
    const unsigned n = w.bit_width / kBits;
    Fields out{};
    for (unsigned i = 0; i < kFieldCount; ++i) {
        out[i] = GetField(input.data(), static_cast<std::size_t>(i) * n, w.bit_width, big_endian);
    }
    return out;
}

// An independent scan of the seed for a value, used only to cross-check the
// offset the solver reports. Not a model of FindFirst's search order: both
// byte orders are reported separately so no order has to be assumed.
std::size_t FirstOccurrence(const std::vector<std::uint8_t>& seed, std::uint64_t value,
                            unsigned bit_width, bool big_endian) {
    const unsigned n = bit_width / kBits;
    if (seed.size() < n) {
        return kNoOffset;
    }
    for (std::size_t off = 0; off + n <= seed.size(); ++off) {
        if (GetField(seed.data(), off, bit_width, big_endian) == Trunc(value, bit_width)) {
            return off;
        }
    }
    return kNoOffset;
}

// ---------------------------------------------------------------------------
// The form table: the nine task-049 forms, with the literal named rather than
// spelled, so the same table instantiates at every width.
// ---------------------------------------------------------------------------

enum class Op : std::uint8_t { kAdd, kSub, kXor, kAnd, kMul, kNone };

enum class Lit : std::uint8_t { kK1, kK2, kK1Disjoint, kK2Disjoint, kMagic };

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
    Lit literal;
};

constexpr SideSpec FieldOpConst(Op op, unsigned a, Lit literal) {
    return SideSpec{SideKind::kFieldOpConst, op, a, 0, literal};
}

constexpr SideSpec FieldPair(unsigned a, unsigned b) {
    return SideSpec{SideKind::kFieldPair, Op::kNone, a, b, Lit::kMagic};
}

constexpr SideSpec LiteralSide(Lit literal) {
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

// The seven forms of task-049 (test_both_sides_literal.cpp:363-385), field
// indices and predicates unchanged.
constexpr Form kAddBoth = {"a+K1 == b+K2",
                           "1",
                           FieldOpConst(Op::kAdd, 0, Lit::kK1),
                           FieldOpConst(Op::kAdd, 1, Lit::kK2),
                           kEq,
                           false};
constexpr Form kSubBoth = {"a-K1 == b-K2",
                           "2",
                           FieldOpConst(Op::kSub, 0, Lit::kK1),
                           FieldOpConst(Op::kSub, 1, Lit::kK2),
                           kEq,
                           false};
constexpr Form kXorBoth = {"a^K1 == b^K2",
                           "3",
                           FieldOpConst(Op::kXor, 0, Lit::kK1),
                           FieldOpConst(Op::kXor, 1, Lit::kK2),
                           kEq,
                           false};
constexpr Form kXorDisjointBoth = {"a^K1d == b^K2d (disjoint bits)",
                                   "3b",
                                   FieldOpConst(Op::kXor, 0, Lit::kK1Disjoint),
                                   FieldOpConst(Op::kXor, 1, Lit::kK2Disjoint),
                                   kEq,
                                   false};
constexpr Form kAndBoth = {"a&K1 == b&K2",
                           "4",
                           FieldOpConst(Op::kAnd, 0, Lit::kK1),
                           FieldOpConst(Op::kAnd, 1, Lit::kK2),
                           kEq,
                           false};
constexpr Form kMulBoth = {"a*K1 == b*K2",
                           "5",
                           FieldOpConst(Op::kMul, 0, Lit::kK1),
                           FieldOpConst(Op::kMul, 1, Lit::kK2),
                           kEq,
                           false};
constexpr Form kLtBoth = {
    "b+K1 <u a+K2", "7",  FieldOpConst(Op::kAdd, 1, Lit::kK1), FieldOpConst(Op::kAdd, 0, Lit::kK2),
    kUlt,           false};

// The two task-049 controls (test_both_sides_literal.cpp:390-393). They are
// measured at u32/LE only, as the control row of that task — they are not
// part of the 56-cell grid.
constexpr Form kControlOneLiteralSide = {"a+b == MAGIC",
                                         "control/one-literal-side",
                                         FieldPair(0, 1),
                                         LiteralSide(Lit::kMagic),
                                         kEq,
                                         true};
constexpr Form kControlNoLiteralSide = {
    "a+b == c+d", "control/no-literal-side", FieldPair(0, 1), FieldPair(2, 3), kEq, true};

constexpr std::array<const Form*, 7> kLiteralForms = {
    &kAddBoth, &kSubBoth, &kXorBoth, &kXorDisjointBoth, &kAndBoth, &kMulBoth, &kLtBoth};
constexpr std::array<const Form*, 9> kTask049Forms = {&kAddBoth,
                                                      &kSubBoth,
                                                      &kXorBoth,
                                                      &kXorDisjointBoth,
                                                      &kAndBoth,
                                                      &kMulBoth,
                                                      &kLtBoth,
                                                      &kControlOneLiteralSide,
                                                      &kControlNoLiteralSide};

// ---------------------------------------------------------------------------
// Evaluating a form at a width.
// ---------------------------------------------------------------------------

std::uint64_t LiteralOf(const WidthConst& w, Lit literal) {
    switch (literal) {
        case Lit::kK1:
            return w.k1;
        case Lit::kK2:
            return w.k2;
        case Lit::kK1Disjoint:
            return w.k1_disjoint;
        case Lit::kK2Disjoint:
            return w.k2_disjoint;
        case Lit::kMagic:
            break;
    }
    return w.magic;
}

std::uint64_t Apply(Op op, std::uint64_t v, std::uint64_t k, unsigned bw) {
    switch (op) {
        case Op::kAdd:
            return Trunc(v + k, bw);
        case Op::kSub:
            return Trunc(v - k, bw);
        case Op::kXor:
            return Trunc(v ^ k, bw);
        case Op::kAnd:
            return Trunc(v & k, bw);
        case Op::kMul:
            return Trunc(v * k, bw);
        case Op::kNone:
            break;
    }
    return Trunc(v, bw);
}

std::uint64_t ValueOf(const SideSpec& side, const WidthConst& w, const Fields& v) {
    switch (side.kind) {
        case SideKind::kFieldOpConst:
            return Apply(side.op, v[side.a], LiteralOf(w, side.literal), w.bit_width);
        case SideKind::kFieldPair:
            return Trunc(v[side.a] + v[side.b], w.bit_width);
        case SideKind::kLiteral:
            break;
    }
    return Trunc(LiteralOf(w, side.literal), w.bit_width);
}

bool GateHolds(const Form& form, const WidthConst& w, const Fields& v) {
    const std::uint64_t lhs = ValueOf(form.lhs, w, v);
    const std::uint64_t rhs = ValueOf(form.rhs, w, v);
    return form.predicate == kUlt ? lhs < rhs : lhs == rhs;
}

// ---------------------------------------------------------------------------
// One cell of the grid.
// ---------------------------------------------------------------------------

struct Side {
    Operand::Kind kind;
    std::size_t var_index;
    std::size_t var_index2;
    std::size_t offset;  ///< byte offset of var_index, kNoOffset when unbound
    bool big_endian;     ///< byte order the solver bound var_index with
};

struct Cell {
    const Form* form;
    const WidthConst* width;
    bool big_endian;
    Side lhs;
    Side rhs;
    std::uint64_t lhs_value;
    std::uint64_t rhs_value;
    std::size_t num_vars;     ///< sys.num_vars for the whole form
    std::size_t path_size;    ///< surviving constraints (4 guards + gate = 5)
    bool gate_survived;       ///< did the gate record reach sys.path at all?
    bool dropped;             ///< the complement of gate_survived, named as the queue asks
    bool invertible;          ///< sys.invertible for the whole form
    SolveOutcome outcome;     ///< what SolveForCandidate reported
    bool has_candidate;       ///< did the call actually hand back an input?
    bool gate_on_seed;        ///< did the gate hold BEFORE solving?
    bool gate_on_candidate;   ///< does it hold on the returned candidate?
    bool flipped;             ///< candidate exists and inverted the gate
    bool lhs_literal_as_var;  ///< the literal-bearing lhs bound as a variable
    bool rhs_literal_as_var;  ///< the literal-bearing rhs bound as a variable
    std::size_t lhs_scan_le;  ///< independent LE scan of the seed for lhs_value
    std::size_t lhs_scan_be;
    std::size_t rhs_scan_le;
    std::size_t rhs_scan_be;
};

// task-049's false-binding test (test_both_sides_literal.cpp:260-262): a side
// declared literal-bearing that did NOT land in kConst is a literal that the
// solver bound as data — the cell is not the cell it claims to be.
bool IsLiteralBoundAsVar(const SideSpec& spec, const Side& side) {
    return spec.kind == SideKind::kFieldOpConst && side.kind != Operand::Kind::kConst;
}

// Reads one side's Kind without the record being dropped for having two
// constants: the OTHER side is a plain field value, which always binds, so
// the record survives and the side under test can be read off sys.path.
Side ProbeSide(const WidthConst& w, bool big_endian, std::uint64_t lhs_value,
               std::uint64_t rhs_value, bool want_lhs) {
    const std::vector<std::uint8_t> seed = SeedOf(w, big_endian);
    std::vector<BranchReader::Record> recs = GuardsFor(w);
    recs.push_back(
        {kFieldCount, kEq, static_cast<std::uint8_t>(w.bit_width), lhs_value, rhs_value});
    const System sys = BuildSystem(seed, recs);
    if (sys.path.size() != recs.size()) {
        ADD_FAILURE() << "probe record was dropped — the probe itself is broken, "
                         "the Kind reported here is not measured";
        return Side{Operand::Kind::kConst, 0, 0, kNoOffset, false};
    }
    const Operand& op = want_lhs ? sys.path.back().lhs : sys.path.back().rhs;
    Side side{op.kind, op.var_index, op.var_index2, kNoOffset, false};
    if (op.kind != Operand::Kind::kConst && op.var_index < sys.num_vars) {
        side.offset = sys.vars[op.var_index].offset;
        side.big_endian = sys.vars[op.var_index].big_endian;
    }
    return side;
}

Cell Measure(const Form& form, const WidthConst& w, bool big_endian) {
    const Fields& fields = w.fields;
    const std::vector<std::uint8_t> seed = SeedOf(w, big_endian);
    const std::uint64_t lhs_value = ValueOf(form.lhs, w, fields);
    const std::uint64_t rhs_value = ValueOf(form.rhs, w, fields);

    std::vector<BranchReader::Record> recs = GuardsFor(w);
    recs.push_back({kFieldCount, form.predicate, static_cast<std::uint8_t>(w.bit_width), lhs_value,
                    rhs_value});

    Cell cell{};
    cell.form = &form;
    cell.width = &w;
    cell.big_endian = big_endian;
    cell.lhs_value = lhs_value;
    cell.rhs_value = rhs_value;
    cell.lhs = ProbeSide(w, big_endian, lhs_value, fields[kFieldCount - 1U], true);
    cell.rhs = ProbeSide(w, big_endian, fields[0], rhs_value, false);
    cell.lhs_literal_as_var = IsLiteralBoundAsVar(form.lhs, cell.lhs);
    cell.rhs_literal_as_var = IsLiteralBoundAsVar(form.rhs, cell.rhs);
    cell.lhs_scan_le = FirstOccurrence(seed, lhs_value, w.bit_width, false);
    cell.lhs_scan_be = FirstOccurrence(seed, lhs_value, w.bit_width, true);
    cell.rhs_scan_le = FirstOccurrence(seed, rhs_value, w.bit_width, false);
    cell.rhs_scan_be = FirstOccurrence(seed, rhs_value, w.bit_width, true);

    const System sys = BuildSystem(seed, recs);
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == recs.size();
    cell.dropped = !cell.gate_survived;
    cell.invertible = sys.invertible;
    if (cell.gate_survived) {
        EXPECT_EQ(sys.path.back().lhs.kind, cell.lhs.kind) << form.name;
        EXPECT_EQ(sys.path.back().rhs.kind, cell.rhs.kind) << form.name;
    }

    cell.outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, recs, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    cell.gate_on_seed = GateHolds(form, w, fields);
    cell.gate_on_candidate =
        candidate.has_value() && GateHolds(form, w, FieldsOfCandidate(*candidate, w, big_endian));
    cell.flipped = candidate.has_value() && (cell.gate_on_candidate != cell.gate_on_seed);
    return cell;
}

// ---------------------------------------------------------------------------
// The grid, materialised once.
// ---------------------------------------------------------------------------

struct Grid {
    std::vector<Cell> cells;     ///< 7 forms x 4 widths x 2 byte orders
    std::vector<Cell> controls;  ///< the two task-049 controls at u32/LE

    const Cell& At(const char* form_name, unsigned bit_width, bool big_endian) const {
        for (const Cell& cell : cells) {
            if (std::string(cell.form->name) == form_name && cell.width->bit_width == bit_width &&
                cell.big_endian == big_endian) {
                return cell;
            }
        }
        ADD_FAILURE() << "no such cell: " << form_name << " u" << bit_width;
        return cells.front();
    }
};

const Grid& TheGrid() {
    static const Grid grid = [] {
        Grid g;
        for (const Form* form : kLiteralForms) {
            for (const WidthConst* w : kWidths) {
                for (const bool be : kByteOrders) {
                    g.cells.push_back(Measure(*form, *w, be));
                }
            }
        }
        g.controls.push_back(Measure(kControlOneLiteralSide, kW32, false));
        g.controls.push_back(Measure(kControlNoLiteralSide, kW32, false));
        return g;
    }();
    return grid;
}

// ---------------------------------------------------------------------------
// Printing.
// ---------------------------------------------------------------------------

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

std::string OffsetOf(std::size_t offset) {
    return offset == kNoOffset ? std::string("-") : std::to_string(offset);
}

std::string Hex(std::uint64_t value) {
    static const char* digits = "0123456789ABCDEF";
    std::string out = "0x";
    bool leading = true;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto nibble = static_cast<unsigned>((value >> shift) & 0xFU);
        if (nibble == 0 && leading && shift != 0) {
            continue;
        }
        leading = false;
        out += digits[nibble];
    }
    return out;
}

void PrintCell(const Cell& cell, const char* tag) {
    std::cout << tag << " form=" << cell.form->name << " map_row=" << cell.form->map_row
              << " width=u" << cell.width->bit_width
              << " endian=" << (cell.big_endian ? "BE" : "LE")
              << " control=" << (cell.form->is_control ? 1 : 0) << " lhs=" << Describe(cell.lhs)
              << " rhs=" << Describe(cell.rhs) << " lhs_value=" << Hex(cell.lhs_value)
              << " rhs_value=" << Hex(cell.rhs_value) << " num_vars=" << cell.num_vars
              << " path=" << cell.path_size << " dropped=" << (cell.dropped ? 1 : 0)
              << " gate_survived=" << (cell.gate_survived ? 1 : 0)
              << " invertible=" << (cell.invertible ? 1 : 0) << " outcome=" << NameOf(cell.outcome)
              << " candidate=" << (cell.has_candidate ? 1 : 0)
              << " gate_on_seed=" << (cell.gate_on_seed ? 1 : 0)
              << " gate_on_candidate=" << (cell.gate_on_candidate ? 1 : 0)
              << " flipped=" << (cell.flipped ? 1 : 0)
              << " lhs_literal_as_var=" << (cell.lhs_literal_as_var ? 1 : 0)
              << " lhs_bound_off=" << OffsetOf(cell.lhs.offset)
              << " rhs_literal_as_var=" << (cell.rhs_literal_as_var ? 1 : 0)
              << " rhs_bound_off=" << OffsetOf(cell.rhs.offset)
              << " lhs_scan_le=" << OffsetOf(cell.lhs_scan_le)
              << " lhs_scan_be=" << OffsetOf(cell.lhs_scan_be)
              << " rhs_scan_le=" << OffsetOf(cell.rhs_scan_le)
              << " rhs_scan_be=" << OffsetOf(cell.rhs_scan_be) << "\n";
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixture sanity. If these break, every cell below measures something other
// than what it claims.
// ---------------------------------------------------------------------------

// The guards alone must register exactly the four fields at every one of the
// eight encodings — no more (an unaligned window would add a fifth var and
// change the pair scan) and no fewer (an undiscovered field cannot be bound).
TEST(SolverBothSidesLiteralWidths, FixtureRegistersFourFieldsAtEveryEncoding) {
    for (const WidthConst* w : kWidths) {
        for (const bool be : kByteOrders) {
            SCOPED_TRACE(testing::Message() << "u" << w->bit_width << (be ? "/BE" : "/LE"));
            const std::vector<std::uint8_t> seed = SeedOf(*w, be);
            const std::vector<BranchReader::Record> guards = GuardsFor(*w);
            const System sys = BuildSystem(seed, guards);
            ASSERT_EQ(sys.num_vars, kFieldCount);
            ASSERT_EQ(sys.path.size(), guards.size());
            const unsigned n = w->bit_width / kBits;
            for (unsigned i = 0; i < kFieldCount; ++i) {
                std::cout << "FIXTURE width=u" << w->bit_width << " endian=" << (be ? "BE" : "LE")
                          << " var=" << i << " offset=" << sys.vars[i].offset
                          << " bit_width=" << static_cast<unsigned>(sys.vars[i].bit_width)
                          << " var_be=" << (sys.vars[i].big_endian ? 1 : 0) << "\n";
                EXPECT_EQ(sys.vars[i].offset, static_cast<std::size_t>(i) * n);
                EXPECT_EQ(sys.vars[i].bit_width, w->bit_width);
            }
        }
    }
}

// Row 3b only means anything if the disjoint constants really are bit-disjoint
// from their fields at every width — that is what makes `field ^ K` equal
// `field + K` and lets the row probe the kAddVars branch.
TEST(SolverBothSidesLiteralWidths, DisjointConstantsStayDisjointAtEveryWidth) {
    for (const WidthConst* w : kWidths) {
        SCOPED_TRACE(testing::Message() << "u" << w->bit_width);
        EXPECT_EQ(w->fields[0] & w->k1_disjoint, 0U);
        EXPECT_EQ(w->fields[1] & w->k2_disjoint, 0U);
        EXPECT_EQ(Trunc(w->fields[0] ^ w->k1_disjoint, w->bit_width),
                  Trunc(w->fields[0] + w->k1_disjoint, w->bit_width));
        EXPECT_EQ(Trunc(w->fields[1] ^ w->k2_disjoint, w->bit_width),
                  Trunc(w->fields[1] + w->k2_disjoint, w->bit_width));
    }
}

// Every field must clear the guard bound at every width, or a guard is false
// on the seed and the whole path is unsatisfiable for a reason that has
// nothing to do with the gate under test.
TEST(SolverBothSidesLiteralWidths, EveryGuardHoldsOnTheSeedAtEveryWidth) {
    for (const WidthConst* w : kWidths) {
        SCOPED_TRACE(testing::Message() << "u" << w->bit_width);
        for (unsigned i = 0; i < kFieldCount; ++i) {
            EXPECT_GT(w->fields[i], w->low) << "field " << i;
        }
    }
}

// The u32 row of this file must BE the task-049 fixture, not merely resemble
// it: the constants are pinned here value for value.
TEST(SolverBothSidesLiteralWidths, TheU32RowIsTheTask049Fixture) {
    EXPECT_EQ(kW32.fields[0], 0xEA7BAE6CU);
    EXPECT_EQ(kW32.fields[1], 0x5DD86C83U);
    EXPECT_EQ(kW32.fields[2], 0x54676FA2U);
    EXPECT_EQ(kW32.fields[3], 0x35202910U);
    EXPECT_EQ(kW32.low, 0x01010101U);
    EXPECT_EQ(kW32.k1, 0x9E3779B9U);
    EXPECT_EQ(kW32.k2, 0x85EBCA77U);
    EXPECT_EQ(kW32.k1_disjoint, 0x05840181U);
    EXPECT_EQ(kW32.k2_disjoint, 0xA0258124U);
    EXPECT_EQ(kW32.magic, 0x2A2A2A2AU);
    EXPECT_EQ(kW8.fields[0], kW32.fields[0] & 0xFFU);
    EXPECT_EQ(kW16.fields[0], kW32.fields[0] & 0xFFFFU);
    EXPECT_EQ(kW64.fields[0] >> 32U, kW32.fields[0]);
}

// ---------------------------------------------------------------------------
// The measurement.
// ---------------------------------------------------------------------------

// The grid: 7 forms x 4 widths x 2 byte orders, one printed row per cell,
// plus the two task-049 controls at u32/LE.
TEST(SolverBothSidesLiteralWidths, MeasuredGridIsEmitted) {
    const Grid& grid = TheGrid();
    ASSERT_EQ(grid.cells.size(), 56U);
    ASSERT_EQ(grid.controls.size(), 2U);

    unsigned dropped = 0;
    unsigned in_domain = 0;
    unsigned literal_as_var_sides = 0;
    unsigned literal_as_var_cells = 0;
    unsigned literal_as_kvar_sides = 0;
    unsigned literal_as_pairsum_sides = 0;
    unsigned solved = 0;
    unsigned gate_taken = 0;
    unsigned gate_true_on_seed = 0;
    for (const Cell& cell : grid.cells) {
        PrintCell(cell, "CELL");
        dropped += static_cast<unsigned>(cell.dropped);
        in_domain += static_cast<unsigned>(cell.gate_survived);
        literal_as_var_sides += static_cast<unsigned>(cell.lhs_literal_as_var);
        literal_as_var_sides += static_cast<unsigned>(cell.rhs_literal_as_var);
        literal_as_var_cells +=
            static_cast<unsigned>(cell.lhs_literal_as_var || cell.rhs_literal_as_var);
        literal_as_kvar_sides +=
            static_cast<unsigned>(cell.lhs_literal_as_var && cell.lhs.kind == Operand::Kind::kVar);
        literal_as_kvar_sides +=
            static_cast<unsigned>(cell.rhs_literal_as_var && cell.rhs.kind == Operand::Kind::kVar);
        literal_as_pairsum_sides += static_cast<unsigned>(cell.lhs_literal_as_var &&
                                                          cell.lhs.kind == Operand::Kind::kAddVars);
        literal_as_pairsum_sides += static_cast<unsigned>(cell.rhs_literal_as_var &&
                                                          cell.rhs.kind == Operand::Kind::kAddVars);
        solved += static_cast<unsigned>(cell.outcome == SolveOutcome::kCandidate);
        gate_taken += static_cast<unsigned>(cell.flipped);
        gate_true_on_seed += static_cast<unsigned>(cell.gate_on_seed);
    }
    for (const Cell& cell : grid.controls) {
        PrintCell(cell, "CONTROL");
    }

    // Does any w8 cell disagree with its u32/LE twin on the four facts that
    // decide whether the cell is a both-sides-literal cell at all?
    unsigned w8_differing = 0;
    for (const Cell& cell : grid.cells) {
        if (cell.width->bit_width != 8U) {
            continue;
        }
        const Cell& u32le = grid.At(cell.form->name, 32U, false);
        const bool same = cell.lhs.kind == u32le.lhs.kind && cell.rhs.kind == u32le.rhs.kind &&
                          cell.gate_survived == u32le.gate_survived &&
                          cell.lhs_literal_as_var == u32le.lhs_literal_as_var &&
                          cell.rhs_literal_as_var == u32le.rhs_literal_as_var;
        if (!same) {
            ++w8_differing;
            std::cout << "W8DIFF form=" << cell.form->name
                      << " endian=" << (cell.big_endian ? "BE" : "LE")
                      << " w8_lhs=" << Describe(cell.lhs) << " w8_rhs=" << Describe(cell.rhs)
                      << " u32_lhs=" << Describe(u32le.lhs) << " u32_rhs=" << Describe(u32le.rhs)
                      << " w8_gate_survived=" << (cell.gate_survived ? 1 : 0)
                      << " u32_gate_survived=" << (u32le.gate_survived ? 1 : 0) << "\n";
        }
    }

    std::cout << "SUMMARY: BOTH-SIDES-LITERAL-WIDTHS: forms=" << kLiteralForms.size()
              << ", widths=" << kWidths.size() << ", endians=" << kByteOrders.size()
              << ", cells=" << grid.cells.size() << ", dropped=" << dropped
              << ", in_domain=" << in_domain << ", literal_bound_as_var=" << literal_as_var_sides
              << ", literal_bound_as_var_cells=" << literal_as_var_cells
              << ", literal_bound_as_kvar=" << literal_as_kvar_sides
              << ", literal_bound_as_pair_sum=" << literal_as_pairsum_sides << ", solved=" << solved
              << ", gate_taken=" << gate_taken << ", gate_true_on_seed=" << gate_true_on_seed
              << ", w8_differing_cells=" << w8_differing
              << ", w8_differs=" << (w8_differing != 0U ? "yes" : "no")
              << ", task049_cells=7, src_modified=0, new_fuzzing_runs=0\n";

    EXPECT_EQ(grid.cells.size(), 56U);
}

// The control row: the seven u32/LE cells plus the two controls must
// reproduce the task-049 verdict number for number
// (docs/experiments/solver-both-sides-literal/report.md, VERDICT line quoted
// dropped_records=7, false_binding=0, width=u32, endian=LE, arity=2).
TEST(SolverBothSidesLiteralWidths, U32LittleEndianRowReproducesTask049) {
    const Grid& grid = TheGrid();
    unsigned in_domain = 0;
    unsigned dropped_records = 0;
    unsigned false_binding = 0;
    unsigned solved = 0;
    unsigned gate_taken = 0;
    for (const Form* form : kTask049Forms) {
        const Cell& cell = form->is_control ? (form == &kControlOneLiteralSide ? grid.controls[0]
                                                                               : grid.controls[1])
                                            : grid.At(form->name, 32U, false);
        PrintCell(cell, "TASK049");
        if (cell.gate_survived) {
            ++in_domain;
        } else {
            ++dropped_records;
        }
        false_binding += static_cast<unsigned>(cell.lhs_literal_as_var);
        false_binding += static_cast<unsigned>(cell.rhs_literal_as_var);
        solved += static_cast<unsigned>(cell.outcome == SolveOutcome::kCandidate);
        gate_taken += static_cast<unsigned>(cell.flipped);
    }
    std::cout << "TASK049-SUMMARY: forms=" << kLiteralForms.size()
              << ", cells=" << kTask049Forms.size() << ", in_domain=" << in_domain
              << ", dropped_records=" << dropped_records << ", false_binding=" << false_binding
              << ", solved=" << solved << ", gate_taken=" << gate_taken
              << ", width=u32, endian=LE, arity=2\n";
    EXPECT_EQ(in_domain, 2U);
    EXPECT_EQ(dropped_records, 7U);
    EXPECT_EQ(false_binding, 0U);
    EXPECT_EQ(solved, 9U);
    EXPECT_EQ(gate_taken, 2U);
}

// Above w8 the task-049 answer holds unchanged at every remaining coordinate:
// a code constant on each side leaves BOTH sides in kConst, the record is
// dropped at concolic.cpp:244-247, and the path keeps only the four guards.
// Forty-two cells, one answer.
TEST(SolverBothSidesLiteralWidths, NothingWiderThanW8ReachesTheDomain) {
    const Grid& grid = TheGrid();
    unsigned checked = 0;
    for (const Cell& cell : grid.cells) {
        if (cell.width->bit_width == 8U) {
            continue;
        }
        SCOPED_TRACE(testing::Message() << cell.form->name << " u" << cell.width->bit_width
                                        << (cell.big_endian ? "/BE" : "/LE"));
        EXPECT_EQ(cell.lhs.kind, Operand::Kind::kConst);
        EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
        EXPECT_TRUE(cell.dropped);
        EXPECT_EQ(cell.path_size, 4U);
        EXPECT_EQ(cell.num_vars, 4U);
        EXPECT_FALSE(cell.lhs_literal_as_var);
        EXPECT_FALSE(cell.rhs_literal_as_var);
        ++checked;
    }
    EXPECT_EQ(checked, 42U);
}

// The w8 exception, and the mechanism is NOT the one the task predicted.
//
// The prediction was that a one-byte literal side would be found verbatim in
// the seed and bind as kVar. It does not happen here: over all 56 cells no
// literal side binds as kVar, and the independent scan finds no side value in
// the seed at all (lhs_scan_le/lhs_scan_be are both absent on these very
// cells). What happens instead is the OTHER branch: at w8 the value space is
// 256 wide, and `a+K1` = 0x6C+0xB9 = 0x25 collides with the WRAPPED SUM of
// two unrelated fields, 0x83+0xA2 = 0x25 (mod 256). The kAddVars branch
// (concolic.cpp:195-205) binds the side as fields[1]+fields[2], the record
// survives, and the cell stops being a both-sides-literal cell — through
// aliasing arithmetic, not through a bytewise match.
TEST(SolverBothSidesLiteralWidths, AtW8TheLiteralSideIsAbsorbedByAPairSumNotAByteMatch) {
    const Grid& grid = TheGrid();
    for (const bool be : kByteOrders) {
        SCOPED_TRACE(testing::Message() << "u8" << (be ? "/BE" : "/LE"));
        const Cell& cell = grid.At(kAddBoth.name, 8U, be);
        ASSERT_EQ(cell.lhs.kind, Operand::Kind::kAddVars);
        EXPECT_EQ(cell.lhs.var_index, 1U);
        EXPECT_EQ(cell.lhs.var_index2, 2U);
        EXPECT_EQ(cell.rhs.kind, Operand::Kind::kConst);
        EXPECT_TRUE(cell.lhs_literal_as_var);
        EXPECT_FALSE(cell.rhs_literal_as_var);
        EXPECT_TRUE(cell.gate_survived);
        EXPECT_EQ(cell.path_size, 5U);

        // The alias is arithmetic, and it is exact.
        EXPECT_EQ(cell.lhs_value, Trunc(kW8.fields[0] + kW8.k1, 8));
        EXPECT_EQ(cell.lhs_value, Trunc(kW8.fields[1] + kW8.fields[2], 8));
        // ...and the value is nowhere in the seed, in either byte order, so
        // the kVar branch cannot be what bound it.
        EXPECT_EQ(cell.lhs_scan_le, kNoOffset);
        EXPECT_EQ(cell.lhs_scan_be, kNoOffset);
    }

    // No literal side anywhere in the grid binds as kVar: the predicted
    // "one byte is almost always in the input" mechanism did not fire on a
    // four-byte seed. Both absorbed sides are pair sums.
    unsigned as_kvar = 0;
    unsigned as_pair_sum = 0;
    for (const Cell& cell : grid.cells) {
        as_kvar +=
            static_cast<unsigned>(cell.lhs_literal_as_var && cell.lhs.kind == Operand::Kind::kVar);
        as_kvar +=
            static_cast<unsigned>(cell.rhs_literal_as_var && cell.rhs.kind == Operand::Kind::kVar);
        as_pair_sum += static_cast<unsigned>(cell.lhs_literal_as_var &&
                                             cell.lhs.kind == Operand::Kind::kAddVars);
        as_pair_sum += static_cast<unsigned>(cell.rhs_literal_as_var &&
                                             cell.rhs.kind == Operand::Kind::kAddVars);
    }
    EXPECT_EQ(as_kvar, 0U);
    EXPECT_EQ(as_pair_sum, 2U);
}

// Outcome separates nothing here either: all 56 cells report kCandidate and
// hand back an input, the 54 dropped ones exactly like the 2 that survived.
// A caller reading only the outcome cannot tell a solved gate from a gate
// that was never in the system.
TEST(SolverBothSidesLiteralWidths, OutcomeIsCandidateInAllFiftySixCells) {
    const Grid& grid = TheGrid();
    unsigned candidates = 0;
    unsigned dropped = 0;
    for (const Cell& cell : grid.cells) {
        SCOPED_TRACE(testing::Message() << cell.form->name << " u" << cell.width->bit_width
                                        << (cell.big_endian ? "/BE" : "/LE"));
        EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
        EXPECT_TRUE(cell.has_candidate);
        EXPECT_TRUE(cell.invertible);
        candidates += static_cast<unsigned>(cell.outcome == SolveOutcome::kCandidate);
        dropped += static_cast<unsigned>(cell.dropped);
    }
    EXPECT_EQ(candidates, 56U);
    EXPECT_EQ(dropped, 54U);
}

// Every gate flip in this grid happens with the gate OUT of the path. Six
// cells change the gate's truth value between seed and candidate, all six on
// row 7 (`<u`), all six with the record dropped — the solver was never asked
// about that gate, it only re-satisfied the four guards and the comparison
// moved as a side effect. The two cells that ARE in the domain (w8 row 1)
// never flip. "The gate was taken" and "the solver solved the gate" are
// different events, and on this grid they do not overlap once.
TEST(SolverBothSidesLiteralWidths, EveryFlipHappensWithTheGateOutOfThePath) {
    const Grid& grid = TheGrid();
    unsigned flips = 0;
    unsigned flips_with_dropped_gate = 0;
    unsigned flips_on_row_seven = 0;
    for (const Cell& cell : grid.cells) {
        if (!cell.flipped) {
            continue;
        }
        ++flips;
        flips_with_dropped_gate += static_cast<unsigned>(cell.dropped);
        flips_on_row_seven += static_cast<unsigned>(std::string(cell.form->map_row) == "7");
        std::cout << "FLIP form=" << cell.form->name << " width=u" << cell.width->bit_width
                  << " endian=" << (cell.big_endian ? "BE" : "LE")
                  << " dropped=" << (cell.dropped ? 1 : 0)
                  << " gate_on_seed=" << (cell.gate_on_seed ? 1 : 0)
                  << " gate_on_candidate=" << (cell.gate_on_candidate ? 1 : 0) << "\n";
    }
    EXPECT_EQ(flips, 6U);
    EXPECT_EQ(flips_with_dropped_gate, 6U);
    EXPECT_EQ(flips_on_row_seven, 6U);
    for (const bool be : kByteOrders) {
        EXPECT_FALSE(grid.At(kAddBoth.name, 8U, be).flipped);
    }
}

// The occupancy arithmetic for area 2 of the coverage matrix
// (docs/experiments/solver-domain-coverage-matrix/report.md:131-133: 168
// cells, "literal side = both"). The matrix itself is NOT edited by this
// task; the recount lives here and in the report.
//
//   new_cells       = measured_here - already_occupied_by_task049 - unreachable
//   area2_remaining = area2_total   - occupied_by_task049        - new_cells
//
// "unreachable" are the cells where a side declared literal-bearing was bound
// as data instead: they are not both-sides-literal cells at all, so they are
// not counted as newly occupied.
TEST(SolverBothSidesLiteralWidths, AreaTwoArithmeticIsEmitted) {
    const Grid& grid = TheGrid();
    const unsigned area2_total = 168;
    const unsigned occupied_by_task049 = 7;
    const auto measured_here = static_cast<unsigned>(grid.cells.size());
    const unsigned already_occupied = 7;  // the seven u32/LE cells of task-049
    unsigned unreachable = 0;
    for (const Cell& cell : grid.cells) {
        unreachable += static_cast<unsigned>(cell.lhs_literal_as_var || cell.rhs_literal_as_var);
    }
    const unsigned new_cells = measured_here - already_occupied - unreachable;
    const unsigned area2_remaining = area2_total - occupied_by_task049 - new_cells;

    std::cout << "AREA2: total=" << area2_total << ", occupied_by_task049=" << occupied_by_task049
              << ", measured_here=" << measured_here << ", already_occupied=" << already_occupied
              << ", unreachable=" << unreachable << ", new_cells=" << new_cells
              << ", area2_remaining=" << area2_remaining << "\n";
    EXPECT_EQ(measured_here, 56U);
    EXPECT_EQ(unreachable, 2U);
    EXPECT_EQ(new_cells, 47U);
    EXPECT_EQ(area2_remaining, 114U);
}
