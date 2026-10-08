// task-057 (ADR 0035 §2) — how often does a literal get absorbed into the
// domain at w8?
//
// task-054 ran the "literal on both sides" grid over four widths and two byte
// orders and found exactly ONE crack, exactly at the predicted width w8 — but
// by a different mechanism than predicted. It predicted a byte-wise match of
// the literal-bearing side's value against the seed (the side would bind as
// kVar); it observed a NUMERIC match against the sum of two unrelated fields
// (the side bound as kAddVars). See
// docs/experiments/solver-both-sides-literal-widths/report.md:64-65 and its
// raw-widths.txt:58-59.
//
// That measurement used ONE seed per coordinate, and its own boundaries
// section says so verbatim: "Один сид на координату… Сколько таких совпадений
// даёт w8 в среднем, здесь не измерено"
// (docs/experiments/solver-both-sides-literal-widths/report.md:300-326). On a
// single seed a property of the WIDTH cannot be told apart from a property of
// that seed. This harness answers that with a frequency: the same seven forms,
// the same two byte orders, at w8 only, over 16 seeds spelled out as code
// constants — 7 * 2 * 16 = 224 runs.
//
// The two mechanisms are counted SEPARATELY and are never summed into one
// number; their difference is the whole content of task-054:
//   literal_bound_as_var        — the literal-bearing side bound as kVar
//                                 (the PREDICTED mechanism: byte-wise match);
//   literal_absorbed_as_addvars — the literal-bearing side bound as kAddVars
//                                 (the OBSERVED mechanism: numeric match with
//                                 the sum of two unrelated fields).
//
// Determinism: every seed and every constant is a literal in this file. No
// RNG, no clock, no addresses, no hashing of pointers. Two consecutive runs
// must produce byte-identical output.
//
// This harness does not change the accepted conclusion of task-054 and does
// not declare the domain area closed. It produces one number on which the
// owner can decide.
//
// src/ is not touched; no fuzzing campaign is run.

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
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

// The boundary threshold is fixed HERE, in source, BEFORE the measurement is
// run — a threshold chosen once the answer is known would be a red acceptance.
//
// 0.128 is not an invented number: it is the already-measured frequency of a
// false kAddVars composition at w8 with eight variable fields, 525 of 4096
// seeds, in the "both sides DERIVED" setting
// (docs/experiments/solver-addvars-false-composition/report.md:155, VERDICT at
// :226 as w8/v8=0.128174). That setting has no literal in it at all; it is the
// background rate at which w8 accidentally composes ANY operand out of a pair
// sum. If a literal-bearing side is absorbed at least as often as that
// background, the crack is not a property of one seed — w8 is the width at
// which the notion "literal" stops holding in the domain.
constexpr double kBoundaryThreshold = 0.128;

// ---------------------------------------------------------------------------
// The w8 row, once per seed. Everything except `fields` is the task-054 w8 row
// verbatim (test_both_sides_literal_widths.cpp:91-92): only the seed varies.
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

constexpr WidthConst W8Seed(Fields fields) {
    return WidthConst{8U, fields, 0x01U, 0xB9U, 0x77U, 0x81U, 0x24U, 0x2AU};
}

// The 16 seeds, spelled out. Index 0 is the task-054 w8 fixture VERBATIM
// (test_both_sides_literal_widths.cpp:91, reported as the bytes 6C 83 A2 10 in
// docs/experiments/solver-both-sides-literal-widths/report.md:144) — it is the
// control seed and must reproduce the crack. The other 15 are spread by hand
// over the byte range and deliberately include edges: smallest values that
// still satisfy the guard `field >u 0x01`, the top of the range, powers of
// two, nibble masks, and four seeds whose field pairs sum to a value that is
// itself an interesting constant (0x33, 0xFF, 0x00, 0x30) so that the kAddVars
// mechanism has honest chances to fire rather than being starved by
// construction.
constexpr std::array<WidthConst, 16> kSeeds = {
    W8Seed({0x6CU, 0x83U, 0xA2U, 0x10U}),  // 0: task-054 control seed
    W8Seed({0x02U, 0x03U, 0x05U, 0x07U}),  // 1: low edge, just above the guard
    W8Seed({0xFFU, 0xFEU, 0xFDU, 0xFCU}),  // 2: top of the range
    W8Seed({0x80U, 0x40U, 0x20U, 0x10U}),  // 3: powers of two
    W8Seed({0x11U, 0x22U, 0x33U, 0x44U}),  // 4: 0x11+0x22 == 0x33 (field 2)
    W8Seed({0xAAU, 0x55U, 0xFFU, 0x02U}),  // 5: 0xAA+0x55 == 0xFF (field 2)
    W8Seed({0x7FU, 0x81U, 0x02U, 0xC3U}),  // 6: 0x7F+0x81 == 0x00 mod 2^8
    W8Seed({0x10U, 0x20U, 0x30U, 0x90U}),  // 7: 0x10+0x20 == 0x30 (field 2)
    W8Seed({0xE3U, 0x1DU, 0x5AU, 0xA6U}),  // 8: 0xE3+0x1D == 0x00 mod 2^8
    W8Seed({0x3CU, 0xC3U, 0x0FU, 0xF0U}),  // 9: nibble masks
    W8Seed({0x9EU, 0x37U, 0x79U, 0xB9U}),  // 10: golden-ratio bytes
    W8Seed({0x85U, 0xEBU, 0xCAU, 0x77U}),  // 11: murmur bytes
    W8Seed({0x2AU, 0x2AU, 0x2AU, 0x2AU}),  // 12: all four fields equal
    W8Seed({0x05U, 0xFAU, 0x0BU, 0xF4U}),  // 13: both pairs sum to 0xFF
    W8Seed({0xD4U, 0x6BU, 0x17U, 0x8CU}),  // 14: spread, no engineered sum
    W8Seed({0x63U, 0x24U, 0x87U, 0xB9U}),  // 15: spread, no engineered sum
};

constexpr std::array<bool, 2> kByteOrders = {false, true};

// ---------------------------------------------------------------------------
// Encoding helpers (test_both_sides_literal_widths.cpp:119-193, unchanged).
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

// Guards pin every field as a variable, exactly as task-049/054 do: one
// `field >u low` record per field.
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

// An independent scan of the seed for a value. This is what makes the
// PREDICTED mechanism checkable rather than asserted: a side that bound as
// kVar is only a byte-wise match if the value really occurs in the seed.
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
// The seven task-049 forms, names and map rows unchanged
// (test_both_sides_literal_widths.cpp:241-294). The two task-049 CONTROL forms
// are deliberately absent: they carry no literal on both sides and are not
// part of this grid.
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

struct Form {
    const char* name;
    const char* map_row;  ///< row of docs/experiments/solver-domain-map/report.md
    SideSpec lhs;
    SideSpec rhs;
    std::uint8_t predicate;
};

constexpr Form kAddBoth = {"a+K1 == b+K2", "1", FieldOpConst(Op::kAdd, 0, Lit::kK1),
                           FieldOpConst(Op::kAdd, 1, Lit::kK2), kEq};
constexpr Form kSubBoth = {"a-K1 == b-K2", "2", FieldOpConst(Op::kSub, 0, Lit::kK1),
                           FieldOpConst(Op::kSub, 1, Lit::kK2), kEq};
constexpr Form kXorBoth = {"a^K1 == b^K2", "3", FieldOpConst(Op::kXor, 0, Lit::kK1),
                           FieldOpConst(Op::kXor, 1, Lit::kK2), kEq};
constexpr Form kXorDisjointBoth = {"a^K1d == b^K2d (disjoint bits)", "3b",
                                   FieldOpConst(Op::kXor, 0, Lit::kK1Disjoint),
                                   FieldOpConst(Op::kXor, 1, Lit::kK2Disjoint), kEq};
constexpr Form kAndBoth = {"a&K1 == b&K2", "4", FieldOpConst(Op::kAnd, 0, Lit::kK1),
                           FieldOpConst(Op::kAnd, 1, Lit::kK2), kEq};
constexpr Form kMulBoth = {"a*K1 == b*K2", "5", FieldOpConst(Op::kMul, 0, Lit::kK1),
                           FieldOpConst(Op::kMul, 1, Lit::kK2), kEq};
constexpr Form kLtBoth = {"b+K1 <u a+K2", "7", FieldOpConst(Op::kAdd, 1, Lit::kK1),
                          FieldOpConst(Op::kAdd, 0, Lit::kK2), kUlt};

constexpr std::array<const Form*, 7> kLiteralForms = {
    &kAddBoth, &kSubBoth, &kXorBoth, &kXorDisjointBoth, &kAndBoth, &kMulBoth, &kLtBoth};

// ---------------------------------------------------------------------------
// Evaluating a form on a seed.
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
// One run of the grid.
// ---------------------------------------------------------------------------

struct Side {
    Operand::Kind kind;
    std::size_t var_index;
    std::size_t var_index2;
    std::size_t offset;   ///< byte offset of var_index, kNoOffset when unbound
    std::size_t offset2;  ///< byte offset of var_index2 for kAddVars
    bool big_endian;
};

struct RunRow {
    const Form* form;
    std::size_t seed_index;
    bool big_endian;
    Side lhs;
    Side rhs;
    std::uint64_t lhs_value;
    std::uint64_t rhs_value;
    std::size_t num_vars;
    std::size_t path_size;
    bool dropped;  ///< the gate record did not reach sys.path
    bool invertible;
    SolveOutcome outcome;
    bool has_candidate;
    bool gate_on_seed;
    bool gate_on_candidate;
    bool flipped;
    // The two mechanisms, never merged.
    bool lhs_bound_as_var;         ///< literal-bearing lhs bound as kVar
    bool rhs_bound_as_var;         ///< literal-bearing rhs bound as kVar
    bool lhs_absorbed_as_addvars;  ///< literal-bearing lhs bound as kAddVars
    bool rhs_absorbed_as_addvars;  ///< literal-bearing rhs bound as kAddVars
    // Independent byte-wise confirmation of the PREDICTED mechanism.
    std::size_t lhs_scan_le;
    std::size_t lhs_scan_be;
    std::size_t rhs_scan_le;
    std::size_t rhs_scan_be;
};

bool BoundAsVar(const SideSpec& spec, const Side& side) {
    return spec.kind == SideKind::kFieldOpConst && side.kind == Operand::Kind::kVar;
}

bool AbsorbedAsAddVars(const SideSpec& spec, const Side& side) {
    return spec.kind == SideKind::kFieldOpConst && side.kind == Operand::Kind::kAddVars;
}

bool AnyBoundAsVar(const RunRow& r) {
    return r.lhs_bound_as_var || r.rhs_bound_as_var;
}

bool AnyAbsorbedAsAddVars(const RunRow& r) {
    return r.lhs_absorbed_as_addvars || r.rhs_absorbed_as_addvars;
}

bool Absorbed(const RunRow& r) {
    return AnyBoundAsVar(r) || AnyAbsorbedAsAddVars(r);
}

// A run where the PREDICTED mechanism fired AND the independent scan confirms
// the value really occurs in the seed byte-wise. task-054 predicted exactly
// this and never observed it.
bool PredictedMechanismConfirmed(const RunRow& r) {
    const bool lhs_ok =
        r.lhs_bound_as_var && (r.lhs_scan_le != kNoOffset || r.lhs_scan_be != kNoOffset);
    const bool rhs_ok =
        r.rhs_bound_as_var && (r.rhs_scan_le != kNoOffset || r.rhs_scan_be != kNoOffset);
    return lhs_ok || rhs_ok;
}

// Reads one side's Kind without the record being dropped for having two
// constants: the OTHER side is a plain field value, which always binds.
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
        return Side{Operand::Kind::kConst, 0, 0, kNoOffset, kNoOffset, false};
    }
    const Operand& op = want_lhs ? sys.path.back().lhs : sys.path.back().rhs;
    Side side{op.kind, op.var_index, op.var_index2, kNoOffset, kNoOffset, false};
    if (op.kind != Operand::Kind::kConst && op.var_index < sys.num_vars) {
        side.offset = sys.vars[op.var_index].offset;
        side.big_endian = sys.vars[op.var_index].big_endian;
    }
    if (op.kind == Operand::Kind::kAddVars && op.var_index2 < sys.num_vars) {
        side.offset2 = sys.vars[op.var_index2].offset;
    }
    return side;
}

RunRow Measure(const Form& form, std::size_t seed_index, bool big_endian) {
    const WidthConst& w = kSeeds[seed_index];
    const Fields& fields = w.fields;
    const std::vector<std::uint8_t> seed = SeedOf(w, big_endian);
    const std::uint64_t lhs_value = ValueOf(form.lhs, w, fields);
    const std::uint64_t rhs_value = ValueOf(form.rhs, w, fields);

    std::vector<BranchReader::Record> recs = GuardsFor(w);
    recs.push_back({kFieldCount, form.predicate, static_cast<std::uint8_t>(w.bit_width), lhs_value,
                    rhs_value});

    RunRow run{};
    run.form = &form;
    run.seed_index = seed_index;
    run.big_endian = big_endian;
    run.lhs_value = lhs_value;
    run.rhs_value = rhs_value;
    run.lhs = ProbeSide(w, big_endian, lhs_value, fields[kFieldCount - 1U], true);
    run.rhs = ProbeSide(w, big_endian, fields[0], rhs_value, false);
    run.lhs_bound_as_var = BoundAsVar(form.lhs, run.lhs);
    run.rhs_bound_as_var = BoundAsVar(form.rhs, run.rhs);
    run.lhs_absorbed_as_addvars = AbsorbedAsAddVars(form.lhs, run.lhs);
    run.rhs_absorbed_as_addvars = AbsorbedAsAddVars(form.rhs, run.rhs);
    run.lhs_scan_le = FirstOccurrence(seed, lhs_value, w.bit_width, false);
    run.lhs_scan_be = FirstOccurrence(seed, lhs_value, w.bit_width, true);
    run.rhs_scan_le = FirstOccurrence(seed, rhs_value, w.bit_width, false);
    run.rhs_scan_be = FirstOccurrence(seed, rhs_value, w.bit_width, true);

    const System sys = BuildSystem(seed, recs);
    run.num_vars = sys.num_vars;
    run.path_size = sys.path.size();
    run.dropped = sys.path.size() != recs.size();
    run.invertible = sys.invertible;

    run.outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, recs, kTimeoutMs, &run.outcome);
    run.has_candidate = candidate.has_value();
    run.gate_on_seed = GateHolds(form, w, fields);
    run.gate_on_candidate =
        candidate.has_value() && GateHolds(form, w, FieldsOfCandidate(*candidate, w, big_endian));
    run.flipped = candidate.has_value() && (run.gate_on_candidate != run.gate_on_seed);
    return run;
}

// ---------------------------------------------------------------------------
// The grid, materialised once. Order is fixed: form, then byte order, then
// seed index — so the raw dump is byte-identical across runs.
// ---------------------------------------------------------------------------

struct Grid {
    std::vector<RunRow> runs;
};

const Grid& TheGrid() {
    static const Grid* grid = [] {
        auto* g = new Grid();
        g->runs.reserve(kLiteralForms.size() * kByteOrders.size() * kSeeds.size());
        for (const Form* form : kLiteralForms) {
            for (const bool big_endian : kByteOrders) {
                for (std::size_t s = 0; s < kSeeds.size(); ++s) {
                    g->runs.push_back(Measure(*form, s, big_endian));
                }
            }
        }
        return g;
    }();
    return *grid;
}

// ---------------------------------------------------------------------------
// Deterministic formatting. Every number goes through an ostringstream so no
// stream flag ever leaks into the next field.
// ---------------------------------------------------------------------------

std::string HexByte(std::uint64_t value) {
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (value & 0xFFU);
    return os.str();
}

std::string SeedBytes(std::size_t seed_index, bool big_endian) {
    const std::vector<std::uint8_t> seed = SeedOf(kSeeds[seed_index], big_endian);
    std::string out;
    for (const std::uint8_t byte : seed) {
        out += HexByte(byte);
    }
    return out;
}

std::string OffsetOf(std::size_t offset) {
    return offset == kNoOffset ? std::string("-") : std::to_string(offset);
}

const char* NameOf(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kConst:
            return "kConst";
        case Operand::Kind::kAddVars:
            break;
    }
    return "kAddVars";
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
            break;
    }
    return "kError";
}

std::string AddVarsOffsets(const Side& side) {
    if (side.kind != Operand::Kind::kAddVars) {
        return "-";
    }
    return OffsetOf(side.offset) + "," + OffsetOf(side.offset2);
}

std::string Rate(std::size_t numerator, std::size_t denominator) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(4)
       << (denominator == 0 ? 0.0
                            : static_cast<double>(numerator) / static_cast<double>(denominator));
    return os.str();
}

void PrintRun(const RunRow& r, const char* tag) {
    std::cout << tag << " form=" << r.form->name << " map_row=" << r.form->map_row
              << " endian=" << (r.big_endian ? "BE" : "LE") << " seed=" << r.seed_index
              << " seed_bytes=" << SeedBytes(r.seed_index, r.big_endian)
              << " lhs_kind=" << NameOf(r.lhs.kind) << " rhs_kind=" << NameOf(r.rhs.kind)
              << " lhs_value=0x" << HexByte(r.lhs_value) << " rhs_value=0x" << HexByte(r.rhs_value)
              << " dropped=" << (r.dropped ? 1 : 0) << " num_vars=" << r.num_vars
              << " path=" << r.path_size << " invertible=" << (r.invertible ? 1 : 0)
              << " outcome=" << NameOf(r.outcome)
              << " literal_bound_as_var=" << (AnyBoundAsVar(r) ? 1 : 0)
              << " literal_absorbed_as_addvars=" << (AnyAbsorbedAsAddVars(r) ? 1 : 0)
              << " lhs_offset=" << OffsetOf(r.lhs.offset)
              << " rhs_offset=" << OffsetOf(r.rhs.offset)
              << " addvars_offsets=" << AddVarsOffsets(r.lhs) << "|" << AddVarsOffsets(r.rhs)
              << " lhs_scan_le=" << OffsetOf(r.lhs_scan_le)
              << " lhs_scan_be=" << OffsetOf(r.lhs_scan_be)
              << " rhs_scan_le=" << OffsetOf(r.rhs_scan_le)
              << " rhs_scan_be=" << OffsetOf(r.rhs_scan_be)
              << " gate_on_seed=" << (r.gate_on_seed ? 1 : 0)
              << " gate_on_candidate=" << (r.gate_on_candidate ? 1 : 0)
              << " flipped=" << (r.flipped ? 1 : 0) << "\n";
}

// The task-054 control cell: seed 0, form "a+K1 == b+K2" (map_row 1), both
// byte orders. raw-widths.txt:58-59 recorded lhs=kAddVars(1,2), rhs=kConst,
// num_vars=4, path=5, dropped=0, outcome=kCandidate, the absorbing pair
// starting at offset 1, and NO byte-wise occurrence (lhs_scan_le/be = "-").
bool ReproducesTask054(const RunRow& r) {
    return r.lhs.kind == Operand::Kind::kAddVars && r.rhs.kind == Operand::Kind::kConst &&
           r.num_vars == 4U && r.path_size == 5U && !r.dropped &&
           r.outcome == SolveOutcome::kCandidate && r.lhs.offset == 1U &&
           r.lhs_scan_le == kNoOffset && r.lhs_scan_be == kNoOffset;
}

bool IsControlRun(const RunRow& r) {
    return r.seed_index == 0U && std::string(r.form->map_row) == "1";
}

struct Totals {
    std::size_t runs = 0;
    std::size_t absorbed_runs = 0;
    std::size_t bound_as_var_runs = 0;
    std::size_t addvars_runs = 0;
    std::size_t predicted_confirmed_runs = 0;
    std::size_t in_domain = 0;
    std::size_t control_runs = 0;
    std::size_t control_reproducing = 0;
};

Totals Tally() {
    Totals t;
    for (const RunRow& r : TheGrid().runs) {
        ++t.runs;
        t.absorbed_runs += Absorbed(r) ? 1U : 0U;
        t.bound_as_var_runs += AnyBoundAsVar(r) ? 1U : 0U;
        t.addvars_runs += AnyAbsorbedAsAddVars(r) ? 1U : 0U;
        t.predicted_confirmed_runs += PredictedMechanismConfirmed(r) ? 1U : 0U;
        t.in_domain += (!r.dropped && r.invertible) ? 1U : 0U;
        if (IsControlRun(r)) {
            ++t.control_runs;
            t.control_reproducing += ReproducesTask054(r) ? 1U : 0U;
        }
    }
    return t;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. The raw dump: all 224 runs, one line each.
// ---------------------------------------------------------------------------
TEST(SolverW8LiteralAbsorption, RawGridDump) {
    const Grid& grid = TheGrid();
    ASSERT_EQ(grid.runs.size(), kLiteralForms.size() * kByteOrders.size() * kSeeds.size());
    EXPECT_EQ(grid.runs.size(), 224U);
    for (const RunRow& r : grid.runs) {
        PrintRun(r, "RUN");
    }
}

// ---------------------------------------------------------------------------
// 2. The control seed. Printed, not merely asserted: the numbers of the cell
//    task-054 observed the crack in are on the page next to their pins.
// ---------------------------------------------------------------------------
TEST(SolverW8LiteralAbsorption, ControlSeedReproducesTask054Crack) {
    std::size_t seen = 0;
    std::size_t reproducing = 0;
    for (const RunRow& r : TheGrid().runs) {
        if (!IsControlRun(r)) {
            continue;
        }
        ++seen;
        reproducing += ReproducesTask054(r) ? 1U : 0U;
        PrintRun(r, "CONTROL");
        std::cout << "CONTROL_CHECK: endian=" << (r.big_endian ? "BE" : "LE")
                  << " expected(task-054 raw-widths.txt:58-59)="
                     "lhs=kAddVars,rhs=kConst,num_vars=4,path=5,dropped=0,"
                     "outcome=kCandidate,lhs_off=1,lhs_scan=-"
                  << " observed=lhs=" << NameOf(r.lhs.kind) << ",rhs=" << NameOf(r.rhs.kind)
                  << ",num_vars=" << r.num_vars << ",path=" << r.path_size
                  << ",dropped=" << (r.dropped ? 1 : 0) << ",outcome=" << NameOf(r.outcome)
                  << ",lhs_off=" << OffsetOf(r.lhs.offset)
                  << ",lhs_scan_le=" << OffsetOf(r.lhs_scan_le)
                  << ",lhs_scan_be=" << OffsetOf(r.lhs_scan_be)
                  << " reproduces=" << (ReproducesTask054(r) ? "yes" : "no") << "\n";
    }
    EXPECT_EQ(seen, 2U) << "the control cell is seed 0 x map_row 1 x both byte orders";
    EXPECT_EQ(reproducing, seen) << "task-054 recorded this cell in raw-widths.txt:58-59; "
                                    "a mismatch is a legitimate outcome but must be explained, "
                                    "not silently absorbed into the frequency";
}

// ---------------------------------------------------------------------------
// 3. The two mechanisms stay separate. Merging them into one number is exactly
//    what task-054 forbids, so the harness proves they are disjoint per side.
// ---------------------------------------------------------------------------
TEST(SolverW8LiteralAbsorption, MechanismsAreCountedSeparately) {
    for (const RunRow& r : TheGrid().runs) {
        EXPECT_FALSE(r.lhs_bound_as_var && r.lhs_absorbed_as_addvars)
            << "a side cannot be kVar and kAddVars at once: " << r.form->name;
        EXPECT_FALSE(r.rhs_bound_as_var && r.rhs_absorbed_as_addvars)
            << "a side cannot be kVar and kAddVars at once: " << r.form->name;
        if (PredictedMechanismConfirmed(r)) {
            EXPECT_TRUE(AnyBoundAsVar(r));
        }
    }
    const Totals t = Tally();
    EXPECT_LE(t.bound_as_var_runs, t.absorbed_runs);
    EXPECT_LE(t.addvars_runs, t.absorbed_runs);
    EXPECT_LE(t.predicted_confirmed_runs, t.bound_as_var_runs);
    EXPECT_LE(t.absorbed_runs, t.bound_as_var_runs + t.addvars_runs);
    std::cout << "MECHANISM: literal_bound_as_var runs=" << t.bound_as_var_runs << "/" << t.runs
              << " rate=" << Rate(t.bound_as_var_runs, t.runs) << "\n";
    std::cout << "MECHANISM: literal_absorbed_as_addvars runs=" << t.addvars_runs << "/" << t.runs
              << " rate=" << Rate(t.addvars_runs, t.runs) << "\n";
    std::cout << "MECHANISM: predicted_confirmed_byte_wise runs=" << t.predicted_confirmed_runs
              << "/" << t.runs << " rate=" << Rate(t.predicted_confirmed_runs, t.runs) << "\n";
}

// ---------------------------------------------------------------------------
// 4. The verdict line. The threshold was fixed in source above, before the
//    measurement; this test only compares against it.
// ---------------------------------------------------------------------------
TEST(SolverW8LiteralAbsorption, Verdict) {
    const Totals t = Tally();
    ASSERT_EQ(t.runs, 224U);
    const double rate = static_cast<double>(t.absorbed_runs) / static_cast<double>(t.runs);
    const bool boundary = rate >= kBoundaryThreshold;
    const bool control_ok = t.control_runs > 0 && t.control_reproducing == t.control_runs;

    std::cout << "SEEDS:";
    for (std::size_t s = 0; s < kSeeds.size(); ++s) {
        std::cout << " " << s << "=" << HexByte(kSeeds[s].fields[0]) << HexByte(kSeeds[s].fields[1])
                  << HexByte(kSeeds[s].fields[2]) << HexByte(kSeeds[s].fields[3]);
    }
    std::cout << "\n";
    std::cout << "THRESHOLD: kBoundaryThreshold=" << Rate(128, 1000)
              << " source=docs/experiments/solver-addvars-false-composition/report.md:155"
                 " (w8/v8=0.128174, both-sides-DERIVED background rate); fixed in source"
                 " before the measurement\n";
    std::cout << "RATE_FRACTION: absorbed_runs/runs = " << t.absorbed_runs << "/" << t.runs << " = "
              << Rate(t.absorbed_runs, t.runs) << "\n";
    std::cout << "VERDICT: W8-LITERAL-ABSORPTION: forms=" << kLiteralForms.size()
              << ", endians=" << kByteOrders.size() << ", seeds=" << kSeeds.size()
              << ", runs=" << t.runs << ", absorbed_runs=" << t.absorbed_runs
              << ", absorption_rate=" << Rate(t.absorbed_runs, t.runs)
              << ", bound_as_var_runs=" << t.bound_as_var_runs
              << ", predicted_mechanism_runs=" << t.predicted_confirmed_runs
              << ", in_domain=" << t.in_domain
              << ", control_seed_reproduces=" << (control_ok ? "yes" : "no")
              << ", w8_is_boundary=" << (boundary ? "yes" : "no")
              << ", src_modified=0, new_fuzzing_runs=0\n";

    EXPECT_EQ(t.absorbed_runs <= t.runs, true);
    EXPECT_TRUE(control_ok) << "control seed must reproduce the task-054 cell";
}
