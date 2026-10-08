#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// task-062. The residual error of the discriminator D on the WIDTH and
// BYTE-ORDER axes.
//
// task-037 moved one coordinate — the gate form at a single width — and
// found D separating seven forms without one disagreement
// (docs/experiments/solver-binding-discriminator/report.md:12). task-058
// moved another one — the class of false success at a single form. Neither
// touched width or byte order. task-042 has already published the labelled
// corpus for exactly that: the full 7 forms x 4 widths x 2 byte orders grid,
// cells=56, bound=18, no_binding=38
// (docs/experiments/solver-domain-form-width-endian/report.md:95), with all
// 56 cells named (report.md:164-225).
//
// This harness does NOT copy that table's verdict and declare D reproduces
// it. It rebuilds the same 56 cells by calling BuildSystem, SolveForCandidate
// and SolveInverted, reads derived_kind, outcome and gate_survived out of the
// run, applies D and P to them, and compares against the published label of
// each cell. The published labels are embedded below purely as the TRUTH
// COLUMN, and a separate control proves the grid built here is the same grid:
// the class computed from this run must equal the published class of every
// cell, otherwise this harness measures a DIFFERENT grid and the measurement
// is void.
//
// Both formulas are carried over verbatim from their originals, not restated:
// D from test_binding_discriminator.cpp:80-82 and P from
// test_discriminator_residual.cpp:673-679. Nothing under src/ is modified,
// no fuzzing campaign is run, and the harnesses and reports of task-037,
// task-042 and task-058 are not edited.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::VarBinding;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;
using mlfuzzz3::solver::SolveInverted;
using mlfuzzz3::solver::SolveResult;

// fuzzer_rt_cmp_kind values (ADR 0033), copied from
// test_discriminator_residual.cpp:77 (a superset of the three codes
// test_domain_form_width_endian.cpp:83 needs, same numbering).
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUgt = 4, kUge = 5 };

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kBits = 8;
constexpr unsigned kTimeoutMs = 5000;  ///< the constant of all three sources

// ---------------------------------------------------------------------
// THE DISCRIMINATOR D, copied from test_binding_discriminator.cpp:80-82.
// Not restated, not adapted to the axes measured below.
// ---------------------------------------------------------------------

bool Discriminator(Operand::Kind derived_kind, bool gate_survived) {
    return derived_kind != Operand::Kind::kConst && gate_survived;
}

const char* YesNo(bool value) {
    return value ? "yes" : "no";
}

const char* BoundName(bool bound) {
    return bound ? "bound" : "no_binding";
}

// ---------------------------------------------------------------------
// P's oracles, copied from test_discriminator_residual.cpp:139-234.
// ---------------------------------------------------------------------

std::uint64_t Truncate(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[var.offset + k]) << shift;
    }
    return value;
}

// The engine's write-back, replayed from the model returned by a direct
// SolveInverted call (mirrors src/concolic/concolic.cpp:303-317).
std::vector<std::uint8_t> WriteBackModel(const std::vector<std::uint8_t>& seed, const System& sys,
                                         const std::vector<std::uint64_t>& model) {
    std::vector<std::uint8_t> bytes = seed;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const VarBinding& var = sys.vars[k];
        const unsigned n = var.bit_width / kBitsPerByte;
        const std::uint64_t value = Truncate(model[k], var.bit_width);
        for (unsigned b = 0; b < n; ++b) {
            const unsigned shift =
                var.big_endian ? (kBitsPerByte * (n - 1U - b)) : (kBitsPerByte * b);
            bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
        }
    }
    return bytes;
}

std::uint8_t Negate(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return kNe;
        case kNe:
            return kEq;
        case kUlt:
            return kUge;
        case kUle:
            return kUgt;
        case kUgt:
            return kUle;
        case kUge:
            return kUlt;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return predicate;
    }
}

bool Eval(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs, unsigned bit_width) {
    const std::uint64_t l = Truncate(lhs, bit_width);
    const std::uint64_t r = Truncate(rhs, bit_width);
    switch (predicate) {
        case kEq:
            return l == r;
        case kNe:
            return l != r;
        case kUlt:
            return l < r;
        case kUle:
            return l <= r;
        case kUgt:
            return l > r;
        case kUge:
            return l >= r;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return false;
    }
}

std::uint64_t OperandValue(const Operand& op, const System& sys,
                           const std::vector<std::uint8_t>& bytes, unsigned bit_width) {
    switch (op.kind) {
        case Operand::Kind::kVar:
            return Truncate(ReadBinding(bytes, sys.vars[op.var_index]), bit_width);
        case Operand::Kind::kConst:
            return Truncate(op.const_value, bit_width);
        case Operand::Kind::kAddVars:
            return Truncate(Truncate(ReadBinding(bytes, sys.vars[op.var_index]), bit_width) +
                                Truncate(ReadBinding(bytes, sys.vars[op.var_index2]), bit_width),
                            bit_width);
    }
    ADD_FAILURE() << "unknown operand kind";
    return 0;
}

// ---------------------------------------------------------------------
// The grid of task-042, copied from test_domain_form_width_endian.cpp:
// encoding helpers (91-145), the seven forms (154-241), the four widths and
// two byte orders (241-272). Copied, not re-derived: if a single constant
// moved, this would be a different grid and the truth column below would not
// apply to it. The grid control test proves it did not move.
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
// (src/concolic/concolic.cpp:136).
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

bool GateHolds(FormKind form, std::uint64_t a, std::uint64_t b, unsigned w, std::uint64_t magic) {
    if (form == FormKind::kLt) {
        return LessThanOf(a, b, w);
    }
    return DerivedOf(form, a, b, w) == Trunc(magic, w);
}

std::uint8_t PredicateOf(FormKind form) {
    return form == FormKind::kLt ? kUlt : kEq;
}

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
// THE TRUTH COLUMN. The class published by task-042 for each of the 56
// cells, in the iteration order form-major, then width, then byte order —
// the same order the table of
// docs/experiments/solver-domain-form-width-endian/report.md:170-225 is
// printed in, so index k here is report.md line 170+k. These strings are
// the only thing taken from task-042 by hand; every other number below is
// produced by running the engine.
// ---------------------------------------------------------------------

constexpr std::size_t kCells = 56;
constexpr std::size_t kTruthFirstLine = 170;  ///< report.md line of index 0

constexpr std::array<const char*, kCells> kTruth{{
    // add — report.md:170-177
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    // sub — report.md:178-185
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // xor — report.md:186-193; the u8 pair is the crossroads cell of
    // report.md:111, BOUND and lost at the same time.
    "BOUND+NO-FLIP",
    "BOUND+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // and — report.md:194-201
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // mul — report.md:202-209
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // add-const — report.md:210-217
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // lt — report.md:218-225
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
}};

// The published label reduced to the one bit D and P predict: did the gate's
// derived operand reach the solver as something other than a constant.
// task-042 counts bound=18 = 16 BOUND+FLIP + 2 BOUND+NO-FLIP (report.md:95).
bool TruthBound(std::size_t index) {
    const std::string cls = kTruth[index];
    return cls.rfind("BOUND", 0) == 0;
}

// ---------------------------------------------------------------------
// One measured cell.
// ---------------------------------------------------------------------

struct Cell {
    std::size_t index = 0;
    FormKind form = FormKind::kAdd;
    unsigned bit_width = 0;
    bool big_endian = false;

    // Read out of the run, never assumed.
    Operand::Kind derived_kind = Operand::Kind::kConst;  ///< from the PROBE system
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    bool invertible = false;
    bool gate_survived = false;
    SolveOutcome outcome = SolveOutcome::kError;
    SolveResult::Status status = SolveResult::Status::kError;
    bool has_candidate = false;
    bool guards_hold_end_to_end = false;
    bool gate_flipped_end_to_end = false;
    bool gate_taken_on_seed = false;
    bool derived_findable = false;

    // The two predictions and the truth they are scored against.
    bool d = false;
    bool p = false;
    bool truth_bound = false;
    std::string built_class;  ///< the class recomputed here, for the grid control
};

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

const char* StatusName(SolveResult::Status status) {
    switch (status) {
        case SolveResult::Status::kSat:
            return "kSat";
        case SolveResult::Status::kUnsat:
            return "kUnsat";
        case SolveResult::Status::kTimeout:
            return "kTimeout";
        case SolveResult::Status::kError:
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

// The cell's class, recomputed exactly as task-042 computes it
// (test_domain_form_width_endian.cpp:426-431). This is the grid control:
// if this string differs from kTruth[index], the grid built here is not
// task-042's grid and no agreement number below means anything.
std::string ClassOf(const Cell& cell) {
    const bool bound = cell.derived_kind != Operand::Kind::kConst;
    std::string cls = bound ? "BOUND" : "NO-BINDING";
    cls += cell.gate_flipped_end_to_end ? "+FLIP" : "+NO-FLIP";
    return cls;
}

Cell Measure(std::size_t index, FormKind form, const WidthConst& w, bool big_endian) {
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
    cell.index = index;
    cell.form = form;
    cell.bit_width = bw;
    cell.big_endian = big_endian;

    // derived_kind comes from the PROBE system, the same way task-042 reads
    // it (test_domain_form_width_endian.cpp:336-340).
    const System probe_sys = BuildSystem(seed, probe);
    if (probe_sys.path.empty()) {
        ADD_FAILURE() << "probe system kept no constraint — the probe fixture itself is broken";
    } else {
        cell.derived_kind = probe_sys.path.back().lhs.kind;
    }

    const System sys = BuildSystem(seed, records);
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;
    cell.invertible = sys.invertible;
    cell.gate_survived = sys.path.size() == records.size();
    cell.gate_taken_on_seed = GateHolds(form, w.field_a, w.field_b, bw, w.magic);
    cell.derived_findable = Occurs(seed, derived, bw);

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

    // D — applied to what the run produced, not to what the table says.
    cell.d = Discriminator(cell.derived_kind, cell.gate_survived);

    // P, copied from test_discriminator_residual.cpp:646-679 together with
    // its two guards: without them P is false by construction.
    if (sys.invertible && !sys.path.empty()) {
        const SolveResult result =
            SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMs);
        cell.status = result.status;
        if (result.status == SolveResult::Status::kSat &&
            result.model_values.size() == sys.num_vars) {
            const std::vector<std::uint8_t> reread = WriteBackModel(seed, sys, result.model_values);
            // THE POST-CHECK P: the inverted target predicate on the values
            // RE-READ from the candidate, i.e. after the write-back rather
            // than before it.
            const unsigned target_width = sys.path[sys.target_index].bit_width;
            cell.p = Eval(Negate(sys.path[sys.target_index].predicate),
                          OperandValue(sys.path[sys.target_index].lhs, sys, reread, target_width),
                          OperandValue(sys.path[sys.target_index].rhs, sys, reread, target_width),
                          target_width);
        }
    }

    cell.truth_bound = TruthBound(index);
    cell.built_class = ClassOf(cell);
    return cell;
}

std::vector<Cell> BuildGrid() {
    std::vector<Cell> cells;
    cells.reserve(kCells);
    std::size_t index = 0;
    for (const FormSpec& spec : kForms) {
        for (const WidthConst& w : kWidths) {
            for (const bool big_endian : kByteOrders) {
                cells.push_back(Measure(index, spec.kind, w, big_endian));
                ++index;
            }
        }
    }
    return cells;
}

void PrintCell(const Cell& cell) {
    std::cout << "WE-CELL idx=" << cell.index << " form=" << NameOf(cell.form) << " width=u"
              << cell.bit_width << " endian=" << (cell.big_endian ? "BE" : "LE")
              << " derived_kind=" << KindName(cell.derived_kind)
              << " gate_survived=" << YesNo(cell.gate_survived) << " path=" << cell.path_size
              << "/3 num_vars=" << cell.num_vars << " target_index=" << cell.target_index
              << " invertible=" << YesNo(cell.invertible)
              << " outcome=" << OutcomeName(cell.outcome) << " status=" << StatusName(cell.status)
              << " candidate=" << YesNo(cell.has_candidate)
              << " guards_hold=" << YesNo(cell.guards_hold_end_to_end)
              << " gate_on_seed=" << YesNo(cell.gate_taken_on_seed)
              << " gate_flipped=" << YesNo(cell.gate_flipped_end_to_end)
              << " derived_findable=" << YesNo(cell.derived_findable) << " D=" << BoundName(cell.d)
              << " P=" << BoundName(cell.p) << " truth=" << BoundName(cell.truth_bound)
              << " D_agrees=" << YesNo(cell.d == cell.truth_bound)
              << " P_agrees=" << YesNo(cell.p == cell.truth_bound)
              << " built_class=" << cell.built_class << " truth_class=" << kTruth[cell.index]
              << " grid_matches=" << YesNo(cell.built_class == kTruth[cell.index])
              << " truth_pin=report.md:" << (kTruthFirstLine + cell.index) << "\n";
}

struct Tally {
    std::size_t agrees = 0;
    std::size_t false_bound = 0;       ///< predicted bound, published no_binding
    std::size_t false_no_binding = 0;  ///< predicted no_binding, published bound
};

Tally TallyOf(const std::vector<Cell>& cells, bool use_p) {
    Tally t;
    for (const Cell& cell : cells) {
        const bool prediction = use_p ? cell.p : cell.d;
        if (prediction == cell.truth_bound) {
            ++t.agrees;
        } else if (prediction) {
            ++t.false_bound;
        } else {
            ++t.false_no_binding;
        }
    }
    return t;
}

std::size_t DisagreementsWhere(const std::vector<Cell>& cells, bool use_p, unsigned bit_width,
                               bool has_width, bool big_endian, bool has_endian) {
    std::size_t n = 0;
    for (const Cell& cell : cells) {
        if (has_width && cell.bit_width != bit_width) {
            continue;
        }
        if (has_endian && cell.big_endian != big_endian) {
            continue;
        }
        const bool prediction = use_p ? cell.p : cell.d;
        if (prediction != cell.truth_bound) {
            ++n;
        }
    }
    return n;
}

std::string RateOf(std::size_t bad, std::size_t total) {
    if (total == 0U) {
        return "n/a";
    }
    const auto permille = static_cast<unsigned>((bad * 1000U + total / 2U) / total);
    std::string s = "0.";
    s += static_cast<char>('0' + static_cast<int>(permille / 100U % 10U));
    s += static_cast<char>('0' + static_cast<int>(permille / 10U % 10U));
    s += static_cast<char>('0' + static_cast<int>(permille % 10U));
    return s;
}

// The xor/u8 crossroads cell of report.md:111 — BOUND and lost at the same
// time. Its D and P are named on their own line so it can never dissolve
// into a percentage.
std::string XorU8Value(const std::vector<Cell>& cells, int which) {
    std::string le = "?";
    std::string be = "?";
    for (const Cell& cell : cells) {
        if (cell.form != FormKind::kXor || cell.bit_width != 8U) {
            continue;
        }
        const std::string v = which == 0   ? BoundName(cell.d)
                              : which == 1 ? BoundName(cell.p)
                                           : BoundName(cell.truth_bound);
        if (cell.big_endian) {
            be = v;
        } else {
            le = v;
        }
    }
    return le == be ? le : ("LE-" + le + "/BE-" + be);
}

}  // namespace

// The truth column must be the table it claims to be: 56 entries, and the
// bound/no_binding split task-042 published (report.md:95).
TEST(DiscriminatorWidthEndian, TruthColumnReproducesTask042Totals) {
    ASSERT_EQ(kTruth.size(), kCells);
    std::size_t bound = 0;
    std::size_t no_binding = 0;
    for (std::size_t k = 0; k < kCells; ++k) {
        if (TruthBound(k)) {
            ++bound;
        } else {
            ++no_binding;
        }
    }
    std::cout << "WE-TRUTH cells=" << kTruth.size() << " bound=" << bound
              << " no_binding=" << no_binding << " pin=report.md:95\n";
    EXPECT_EQ(bound, 18U);
    EXPECT_EQ(no_binding, 38U);
}

// THE GRID CONTROL. Not a finding: a precondition. If a single cell's class
// recomputed from this run differs from the class task-042 published, this
// harness builds a DIFFERENT grid and the acceptance is red.
TEST(DiscriminatorWidthEndian, BuiltGridIsTheSameGridAsTask042) {
    const std::vector<Cell> cells = BuildGrid();
    ASSERT_EQ(cells.size(), kCells);
    std::size_t matches = 0;
    for (const Cell& cell : cells) {
        std::cout << "WE-GRID idx=" << cell.index << " form=" << NameOf(cell.form) << " width=u"
                  << cell.bit_width << " endian=" << (cell.big_endian ? "BE" : "LE")
                  << " built_class=" << cell.built_class << " truth_class=" << kTruth[cell.index]
                  << " matches=" << YesNo(cell.built_class == kTruth[cell.index])
                  << " truth_pin=report.md:" << (kTruthFirstLine + cell.index) << "\n";
        if (cell.built_class == kTruth[cell.index]) {
            ++matches;
        }
        EXPECT_EQ(cell.built_class, std::string(kTruth[cell.index]))
            << "cell " << NameOf(cell.form) << "/u" << cell.bit_width << "/"
            << (cell.big_endian ? "BE" : "LE")
            << " does not match report.md:" << (kTruthFirstLine + cell.index);
    }
    std::cout << "WE-GRID-CONTROL cells=" << cells.size() << " matches=" << matches << "/" << kCells
              << " truth_table_matches_task042=" << YesNo(matches == kCells) << "\n";
    EXPECT_EQ(matches, kCells);
}

// The control line of task-037: seven forms at one width and one byte order.
// Its own numbers are not revised here — they enter as a control.
TEST(DiscriminatorWidthEndian, SevenFormControlLineStillHoldsAtU32LittleEndian) {
    const std::vector<Cell> cells = BuildGrid();
    std::size_t seen = 0;
    std::size_t agrees = 0;
    for (const Cell& cell : cells) {
        if (cell.bit_width != 32U || cell.big_endian) {
            continue;
        }
        ++seen;
        if (cell.d == cell.truth_bound) {
            ++agrees;
        }
        std::cout << "WE-CONTROL037 form=" << NameOf(cell.form)
                  << " derived_kind=" << KindName(cell.derived_kind)
                  << " gate_survived=" << YesNo(cell.gate_survived) << " D=" << BoundName(cell.d)
                  << " truth=" << BoundName(cell.truth_bound)
                  << " agrees=" << YesNo(cell.d == cell.truth_bound) << "\n";
    }
    std::cout << "WE-CONTROL037-LINE forms=" << seen << " D_agrees=" << agrees << "/" << seen
              << " control_7forms_matches_task037=" << YesNo(seen == 7U && agrees == 7U)
              << " pin=docs/experiments/solver-binding-discriminator/report.md:12\n";
    EXPECT_EQ(seen, 7U);
    EXPECT_EQ(agrees, 7U);
}

// A negative self-check: the truth column is not vacuous. Flipping every
// published label must make D disagree on every cell it currently agrees
// with, so a green agreement number cannot come from a constant oracle.
TEST(DiscriminatorWidthEndian, InvertedTruthColumnTurnsEveryAgreementIntoDisagreement) {
    const std::vector<Cell> cells = BuildGrid();
    const Tally real = TallyOf(cells, false);
    std::size_t inverted_agrees = 0;
    for (const Cell& cell : cells) {
        if (cell.d == !cell.truth_bound) {
            ++inverted_agrees;
        }
    }
    std::cout << "WE-NEGATIVE D_agrees=" << real.agrees << "/" << kCells
              << " D_agrees_on_inverted_truth=" << inverted_agrees << "/" << kCells
              << " sum=" << (real.agrees + inverted_agrees) << "\n";
    EXPECT_EQ(real.agrees + inverted_agrees, kCells);
    EXPECT_NE(real.agrees, inverted_agrees);
}

TEST(DiscriminatorWidthEndian, DiscriminatorAndPostCheckOnTheWidthAndByteOrderAxes) {
    const std::vector<Cell> cells = BuildGrid();
    ASSERT_EQ(cells.size(), kCells);

    for (const Cell& cell : cells) {
        PrintCell(cell);
    }

    const Tally d = TallyOf(cells, false);
    const Tally p = TallyOf(cells, true);

    // Both controls are recomputed here, not carried over as a claim: the
    // VERDICT line must not be able to say "yes" while the grid disagrees.
    std::size_t grid_matches = 0;
    for (const Cell& cell : cells) {
        if (cell.built_class == kTruth[cell.index]) {
            ++grid_matches;
        }
    }
    std::size_t control_forms = 0;
    std::size_t control_agrees = 0;
    for (const Cell& cell : cells) {
        if (cell.bit_width == 32U && !cell.big_endian) {
            ++control_forms;
            if (cell.d == cell.truth_bound) {
                ++control_agrees;
            }
        }
    }

    // The two axis definitions, fixed BEFORE the run (and before this table
    // was ever printed): the error depends on a coordinate if the number of
    // D's disagreements is NOT the same for every value of that coordinate,
    // all other coordinates left free.
    std::size_t width_lo = kCells;
    std::size_t width_hi = 0;
    for (const WidthConst& w : kWidths) {
        const std::size_t bad = DisagreementsWhere(cells, false, w.bit_width, true, false, false);
        std::cout << "WE-AXIS-WIDTH width=u" << w.bit_width << " cells=14 D_disagreements=" << bad
                  << "\n";
        width_lo = bad < width_lo ? bad : width_lo;
        width_hi = bad > width_hi ? bad : width_hi;
    }
    std::size_t endian_lo = kCells;
    std::size_t endian_hi = 0;
    for (const bool big_endian : kByteOrders) {
        const std::size_t bad = DisagreementsWhere(cells, false, 0, false, big_endian, true);
        std::cout << "WE-AXIS-ENDIAN endian=" << (big_endian ? "BE" : "LE")
                  << " cells=28 D_disagreements=" << bad << "\n";
        endian_lo = bad < endian_lo ? bad : endian_lo;
        endian_hi = bad > endian_hi ? bad : endian_hi;
    }
    const bool width_dependent = width_lo != width_hi;
    const bool endian_dependent = endian_lo != endian_hi;

    std::cout << "WE-XOR-U8 truth=" << XorU8Value(cells, 2) << " D=" << XorU8Value(cells, 0)
              << " P=" << XorU8Value(cells, 1) << " pin=report.md:111\n";

    std::cout << "VERDICT: DISCRIMINATOR-WIDTH-ENDIAN: cells=" << cells.size()
              << ", grid=7x4x2, truth_source=task-042, truth_table_matches_task042="
              << YesNo(grid_matches == kCells) << ", D_agrees=" << d.agrees << "/" << kCells
              << ", D_false_bound=" << d.false_bound
              << ", D_false_no_binding=" << d.false_no_binding
              << ", D_error_rate=" << RateOf(d.false_bound + d.false_no_binding, kCells)
              << ", P_agrees=" << p.agrees << "/" << kCells << ", P_false_bound=" << p.false_bound
              << ", P_false_no_binding=" << p.false_no_binding
              << ", P_error_rate=" << RateOf(p.false_bound + p.false_no_binding, kCells)
              << ", width_dependent_error=" << YesNo(width_dependent)
              << ", endian_dependent_error=" << YesNo(endian_dependent)
              << ", xor_u8_D=" << XorU8Value(cells, 0) << ", xor_u8_P=" << XorU8Value(cells, 1)
              << ", xor_u8_truth=" << XorU8Value(cells, 2) << ", control_7forms_matches_task037="
              << YesNo(control_forms == 7U && control_agrees == 7U)
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n";

    // The grid control is a precondition of every number on that line.
    for (const Cell& cell : cells) {
        EXPECT_EQ(cell.built_class, std::string(kTruth[cell.index]));
    }
    EXPECT_EQ(d.agrees + d.false_bound + d.false_no_binding, kCells);
    EXPECT_EQ(p.agrees + p.false_bound + p.false_no_binding, kCells);
}
