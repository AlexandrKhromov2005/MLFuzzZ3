#include <gtest/gtest.h>

#include <algorithm>
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

// Overlapping byte RANGES under the two layouts task-053 left unmeasured
// (task-056, ADR 0035 §2): reverse field order and big-endian bindings.
//
// What task-053 established and where it stopped. With two bindings whose
// byte ranges intersect, the engine reports kCandidate while the write-back
// destroys part of the model — nine cells out of nine
// (docs/experiments/solver-binding-overlap/report.md:274-276). Its own
// boundary section names the two coordinates it did not touch: "Он не
// проверяет обратный порядок (узкое поле раньше широкого)" and "Он не
// проверяет big-endian привязки"
// (docs/experiments/solver-binding-overlap/report.md:263-266).
//
// Why the two coordinates can change the answer. Fields are collected into a
// std::map keyed by byte OFFSET (src/concolic/concolic.cpp:216-224), so
// sys.vars is ordered by ascending offset, and the write-back walks that
// order (src/concolic/concolic.cpp:303-317). Which write survives is
// therefore decided by which field sits LOWER in the input, not by which
// record came first. Endianness decides which bytes of a value the shared
// range covers: FindFirst prefers little-endian at each offset and falls back
// to big-endian at the same offset (src/concolic/concolic.cpp:158-163), so a
// field bound big-endian keeps its byte order in the input reversed relative
// to its value.
//
// What this file measures. Twenty-seven cells: shift d in {1,2,3} x width
// pair in {u32+u16, u32+u8, u64+u32} x layout in {reverse LE, forward BE,
// reverse BE}. Plus two controls: three forward-LE cells that must reproduce
// task-053's numbers verbatim, and a disjoint-range cell in the new BE
// layout. Per cell: the bindings the engine actually made, the range
// arithmetic, the outcome, and — for every variable — its model value against
// the value RE-READ from the candidate through that same binding.
//
// How this differs from the two tests it borders on:
//   * task-053 (tests/unit/concolic/test_binding_overlap.cpp:498-651,
//     docs/experiments/solver-binding-overlap/report.md:96-106) keeps the
//     WIDE field at offset 0 in every cell and every binding little-endian
//     (be=no in all its VAR lines, report.md:116-133). Here the wide field
//     moves to the higher offset in eighteen of the twenty-seven cells, and
//     eighteen cells bind big-endian.
//   * WidthShadowing (tests/unit/concolic/test_width_shadowing.cpp:282-400)
//     puts BOTH records at one and the same offset and asks which width wins
//     the single binding: there the map key collides, num_vars drops to one,
//     and the ranges COINCIDE rather than intersect partially. Here the
//     offsets always differ, num_vars is two in every cell, and the shared
//     part is a proper subset of both ranges.
//
// src/ is not touched by this file, and no fuzzing campaign is run.

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

// fuzzer_rt_cmp_kind values used by this fixture (ADR 0033).
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUgt = 4, kUge = 5 };

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kTimeoutMs = 5000;
constexpr std::size_t kSeedSize = 16;

// The seed of task-053, byte for byte (raw-overlap.txt:7) — the control row
// can only reproduce its numbers if the input is identical. Sixteen pairwise
// distinct bytes, none adjacent in value to another, so every field pattern
// below occurs exactly once and the guard constants b-1 and b+1 are absent
// from the input and bind as constants.
constexpr std::array<std::uint8_t, kSeedSize> kSeed = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

// Target constants for the wide field, also taken from task-053. Their bytes
// are drawn from a range the seed does not use, so they are not findable and
// every byte an overwrite touches is guaranteed to differ from the model's.
constexpr std::uint64_t kTarget32 = 0x11223344ULL;
constexpr std::uint64_t kTarget64 = 0x1122334455667788ULL;

std::vector<std::uint8_t> Seed() {
    return {kSeed.begin(), kSeed.end()};
}

std::uint64_t Truncate(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

// Read n bytes at `offset` in the requested byte order; used to build the log
// records, which is what makes the fields findable in the first place. A
// one-byte field has the same encoding in both orders, so FindFirst always
// binds it little-endian (src/concolic/concolic.cpp:158-163) — that is an ABI
// fact this fixture records rather than fights.
std::uint64_t ReadSeedField(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n,
                            bool big_endian) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

// Read a field back through its own binding — the inverse of the write-back
// (mirrors ReadField, src/concolic/concolic.cpp:117-126).
std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    return ReadSeedField(bytes, var.offset, n, var.big_endian);
}

// The engine's write-back, replayed here from the model returned by a direct
// SolveInverted call (mirrors src/concolic/concolic.cpp:303-317). Every cell
// checks this replay against the engine's own candidate, so the mirror is
// verified rather than assumed.
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

// Negation and evaluation oracles, written out from the ABI independently of
// the implementation. Only the predicates this fixture uses are defined.
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

// Value of one constraint operand on a concrete byte string, resolving kVar
// through its binding — this is how the gate is evaluated on the candidate.
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

std::string Hex(std::uint64_t value, unsigned bit_width) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(static_cast<int>(2U * (bit_width / kBitsPerByte)))
        << Truncate(value, bit_width);
    return out.str();
}

const char* YesNo(bool value) {
    return value ? "yes" : "no";
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

const char* StatusName(SolveResult::Status status) {
    switch (status) {
        case SolveResult::Status::kSat:
            return "kSat";
        case SolveResult::Status::kUnsat:
            return "kUnsat";
        case SolveResult::Status::kTimeout:
            return "kTimeout";
        case SolveResult::Status::kError:
            return "kError";
    }
    return "kUnknown";
}

const char* PredicateLabel(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return "eq";
        case kNe:
            return "ne";
        case kUlt:
            return "ult";
        case kUle:
            return "ule";
        case kUgt:
            return "ugt";
        case kUge:
            return "uge";
        default:
            return "?";
    }
}

// Which bytes OF THE VALUE a binding exposes to the shared input range,
// counted from the least significant (index 0). For a little-endian binding
// the index equals the offset inside the field; for a big-endian one it is
// mirrored. This is the arithmetic the report needs in order to say WHICH
// part of a big-endian value the overlap eats, instead of the word
// "overlaps".
std::string SharedValueBytes(const VarBinding& var, std::size_t lo, std::size_t hi) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::string list;
    for (unsigned k = 0; k < n; ++k) {
        const std::size_t byte_offset = var.offset + k;
        if (byte_offset < lo || byte_offset >= hi) {
            continue;
        }
        const unsigned index = var.big_endian ? (n - 1U - k) : k;
        if (!list.empty()) {
            list += ",";
        }
        list += std::to_string(index);
    }
    return list.empty() ? std::string("-") : list;
}

// One measured variable: what the model said and what the candidate carries.
struct VarFact {
    std::size_t offset;
    std::uint8_t bit_width;
    bool big_endian;
    std::uint64_t model_value;
    std::uint64_t reread_value;
    bool matches;
    std::string shared_value_bytes;
};

// A layout is one point on the two coordinates task-053 left open.
struct Layout {
    const char* name;
    bool reverse;     // narrow field at the LOWER offset
    bool big_endian;  // fields requested through their big-endian encoding
};

struct Row {
    const char* name;
    unsigned wide_bits;
    unsigned narrow_bits;
};

struct Cell {
    std::string id;
    std::string layout;
    bool reverse = false;
    bool endian_requested_be = false;
    std::size_t shift = 0;
    unsigned wide_bits = 0;
    unsigned narrow_bits = 0;

    // Range arithmetic on the ACTUAL bindings the engine produced.
    std::size_t wide_offset = 0;
    std::size_t wide_len = 0;
    std::size_t narrow_offset = 0;
    std::size_t narrow_len = 0;
    std::size_t overlap_lo = 0;
    std::size_t overlap_hi = 0;
    std::size_t overlap_bytes = 0;
    bool overlapping = false;

    // System facts.
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    bool bindings_as_intended = false;
    std::size_t wide_var_index = 0;  // position of the wide field in sys.vars
    std::size_t narrow_var_index = 0;

    // Direct solve + replayed write-back.
    SolveResult::Status status = SolveResult::Status::kError;
    std::vector<VarFact> vars;
    unsigned mismatched_vars = 0;
    bool model_mismatch = false;
    bool wide_mismatch = false;
    bool narrow_mismatch = false;

    // Gate: the inverted target, evaluated on the candidate.
    std::uint8_t path_predicate = 0;
    std::uint8_t inverted_predicate = 0;
    bool astaken_holds_on_seed = false;
    bool gate_on_candidate = false;

    // The engine's own verdict on the same input.
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    bool engine_equals_replay = false;
};

// Two guards pinning the narrow field to its seed value, then the target on
// the wide field. The target is last, so it is the one the inversion flips
// (System::target_index, src/concolic/concolic.cpp:255). Both guards are
// TRUE on the seed and are kept as taken; together they admit exactly one
// value for the narrow field, so the model is unique and nothing below
// depends on Z3's freedom of choice.
std::vector<BranchReader::Record> MakeRecords(const Layout& layout, std::size_t shift,
                                              unsigned wide_bits, unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const unsigned wide_len = wide_bits / kBitsPerByte;
    const unsigned narrow_len = narrow_bits / kBitsPerByte;
    const std::size_t wide_offset = layout.reverse ? shift : 0U;
    const std::size_t narrow_offset = layout.reverse ? 0U : shift;
    const std::uint64_t a =
        ReadSeedField(seed, wide_offset, wide_len, layout.big_endian && wide_len > 1U);
    const std::uint64_t b =
        ReadSeedField(seed, narrow_offset, narrow_len, layout.big_endian && narrow_len > 1U);
    const std::uint64_t target = wide_bits == 64U ? kTarget64 : kTarget32;
    return {
        {.site_id = 1,
         .predicate = kUgt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b - 1U},
        {.site_id = 2,
         .predicate = kUlt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b + 1U},
        {.site_id = 3,
         .predicate = kEq,
         .bit_width = static_cast<std::uint8_t>(wide_bits),
         .lhs = a,
         .rhs = target},
    };
}

Cell Measure(const std::string& id, const Layout& layout, std::size_t shift, unsigned wide_bits,
             unsigned narrow_bits) {
    Cell cell;
    cell.id = id;
    cell.layout = layout.name;
    cell.reverse = layout.reverse;
    cell.endian_requested_be = layout.big_endian;
    cell.shift = shift;
    cell.wide_bits = wide_bits;
    cell.narrow_bits = narrow_bits;

    const std::vector<std::uint8_t> seed = Seed();
    const std::vector<BranchReader::Record> records =
        MakeRecords(layout, shift, wide_bits, narrow_bits);
    const System sys = BuildSystem(seed, records);

    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;

    // sys.vars is ordered by ascending offset (std::map key,
    // src/concolic/concolic.cpp:216-224), so the reverse layout puts the
    // narrow field first and the forward layout puts the wide one first.
    cell.wide_var_index = layout.reverse ? 1U : 0U;
    cell.narrow_var_index = layout.reverse ? 0U : 1U;

    // Range arithmetic is read off the bindings the engine actually made,
    // never off the intent: [offset, offset + bit_width/8).
    if (sys.vars.size() == 2U) {
        const VarBinding& wide = sys.vars[cell.wide_var_index];
        const VarBinding& narrow = sys.vars[cell.narrow_var_index];
        cell.wide_offset = wide.offset;
        cell.wide_len = wide.bit_width / kBitsPerByte;
        cell.narrow_offset = narrow.offset;
        cell.narrow_len = narrow.bit_width / kBitsPerByte;
        cell.overlap_lo = std::max(cell.wide_offset, cell.narrow_offset);
        cell.overlap_hi =
            std::min(cell.wide_offset + cell.wide_len, cell.narrow_offset + cell.narrow_len);
        cell.overlap_bytes =
            cell.overlap_hi > cell.overlap_lo ? cell.overlap_hi - cell.overlap_lo : 0U;
        cell.overlapping = cell.overlap_bytes > 0U;

        // A one-byte field has one and the same encoding in both orders, so
        // the ABI binds it little-endian even in a big-endian layout; the
        // fixture expects exactly that rather than pretending otherwise.
        const bool wide_be_expected = layout.big_endian && cell.wide_len > 1U;
        const bool narrow_be_expected = layout.big_endian && cell.narrow_len > 1U;
        cell.bindings_as_intended =
            wide.offset == (layout.reverse ? shift : 0U) &&
            narrow.offset == (layout.reverse ? 0U : shift) && wide.bit_width == wide_bits &&
            narrow.bit_width == narrow_bits && wide.big_endian == wide_be_expected &&
            narrow.big_endian == narrow_be_expected;
    }

    if (!sys.invertible) {
        return cell;
    }

    cell.path_predicate = sys.path[sys.target_index].predicate;
    cell.inverted_predicate = Negate(cell.path_predicate);
    const unsigned target_width = sys.path[sys.target_index].bit_width;
    cell.astaken_holds_on_seed = Eval(
        cell.path_predicate, OperandValue(sys.path[sys.target_index].lhs, sys, seed, target_width),
        OperandValue(sys.path[sys.target_index].rhs, sys, seed, target_width), target_width);

    const SolveResult result = SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMs);
    cell.status = result.status;
    if (result.status != SolveResult::Status::kSat || result.model_values.size() != sys.num_vars) {
        return cell;
    }

    const std::vector<std::uint8_t> candidate = WriteBackModel(seed, sys, result.model_values);
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const std::uint64_t model = Truncate(result.model_values[k], sys.vars[k].bit_width);
        const std::uint64_t reread = ReadBinding(candidate, sys.vars[k]);
        cell.vars.push_back({.offset = sys.vars[k].offset,
                             .bit_width = sys.vars[k].bit_width,
                             .big_endian = sys.vars[k].big_endian,
                             .model_value = model,
                             .reread_value = reread,
                             .matches = model == reread,
                             .shared_value_bytes =
                                 SharedValueBytes(sys.vars[k], cell.overlap_lo, cell.overlap_hi)});
        if (model != reread) {
            ++cell.mismatched_vars;
            if (k == cell.wide_var_index) {
                cell.wide_mismatch = true;
            }
            if (k == cell.narrow_var_index) {
                cell.narrow_mismatch = true;
            }
        }
    }
    cell.model_mismatch = cell.mismatched_vars > 0U;

    cell.gate_on_candidate = Eval(
        cell.inverted_predicate,
        OperandValue(sys.path[sys.target_index].lhs, sys, candidate, target_width),
        OperandValue(sys.path[sys.target_index].rhs, sys, candidate, target_width), target_width);

    // The engine's own path over the same seed and records.
    SolveOutcome outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> engine =
        SolveForCandidate(seed, records, kTimeoutMs, &outcome);
    cell.outcome = outcome;
    cell.has_candidate = engine.has_value();
    if (engine.has_value()) {
        const std::vector<std::uint8_t> engine_bytes(engine->data(),
                                                     engine->data() + engine->size());
        cell.engine_equals_replay = engine_bytes == candidate;
    }
    return cell;
}

void PrintCell(const char* tag, const Cell& cell) {
    std::cout << tag << " id=" << cell.id << " layout=" << cell.layout
              << " order=" << (cell.reverse ? "reverse" : "forward")
              << " endian=" << (cell.endian_requested_be ? "be" : "le") << " d=" << cell.shift
              << " widths=" << cell.wide_bits << "+" << cell.narrow_bits << " wide=["
              << cell.wide_offset << "," << cell.wide_offset + cell.wide_len << ") narrow=["
              << cell.narrow_offset << "," << cell.narrow_offset + cell.narrow_len
              << ") overlap=" << YesNo(cell.overlapping) << " overlap_range=[" << cell.overlap_lo
              << "," << (cell.overlapping ? cell.overlap_hi : cell.overlap_lo)
              << ") overlap_bytes=" << cell.overlap_bytes
              << " bindings_as_intended=" << YesNo(cell.bindings_as_intended)
              << " wide_var=" << cell.wide_var_index << " narrow_var=" << cell.narrow_var_index
              << " num_vars=" << cell.num_vars << " path=" << cell.path_size
              << " target=" << cell.target_index << " status=" << StatusName(cell.status)
              << " path_pred=" << PredicateLabel(cell.path_predicate)
              << " inverted_pred=" << PredicateLabel(cell.inverted_predicate)
              << " astaken_on_seed=" << YesNo(cell.astaken_holds_on_seed)
              << " outcome=" << OutcomeName(cell.outcome)
              << " has_candidate=" << YesNo(cell.has_candidate)
              << " engine_equals_replay=" << YesNo(cell.engine_equals_replay)
              << " mismatched_vars=" << cell.mismatched_vars
              << " model_mismatch=" << YesNo(cell.model_mismatch)
              << " wide_mismatch=" << YesNo(cell.wide_mismatch)
              << " narrow_mismatch=" << YesNo(cell.narrow_mismatch)
              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        const VarFact& var = cell.vars[k];
        std::cout << "VAR id=" << cell.id << " k=" << k << " off=" << var.offset
                  << " w=" << unsigned{var.bit_width} << " be=" << YesNo(var.big_endian)
                  << " role=" << (k == cell.wide_var_index ? "wide" : "narrow")
                  << " model=" << Hex(var.model_value, var.bit_width)
                  << " reread=" << Hex(var.reread_value, var.bit_width)
                  << " shared_value_bytes=" << var.shared_value_bytes
                  << " match=" << YesNo(var.matches) << "\n";
    }
}

constexpr std::array<Row, 3> kRows = {{
    {"u32+u16", 32U, 16U},
    {"u32+u8", 32U, 8U},
    {"u64+u32", 64U, 32U},
}};

constexpr std::array<std::size_t, 3> kShifts = {1U, 2U, 3U};

// The three layouts of the grid, and the forward-LE layout of task-053 kept
// only as a control.
constexpr Layout kReverseLe = {"rev-le", true, false};
constexpr Layout kForwardBe = {"fwd-be", false, true};
constexpr Layout kReverseBe = {"rev-be", true, true};
constexpr Layout kForwardLe = {"fwd-le", false, false};

constexpr std::array<Layout, 3> kLayouts = {{kReverseLe, kForwardBe, kReverseBe}};

// The controls: the same width pair as the first row, shifted one byte
// further than the wide field is long, so the ranges stop touching.
constexpr std::size_t kControlShift = 4U;

std::string CellId(const Layout& layout, const Row& row, std::size_t shift) {
    return std::string(layout.name) + "/" + row.name + "/d=" + std::to_string(shift);
}

// One expected cell of task-053, transcribed from its report so the control
// row is checked by the machine and not by the eye.
struct Task053Expectation {
    std::size_t shift;
    std::size_t overlap_bytes;
    std::uint64_t wide_model;
    std::uint64_t wide_reread;
    std::uint64_t narrow_model;
    std::uint64_t narrow_reread;
    unsigned mismatched_vars;
    bool gate_on_candidate;
};

// docs/experiments/solver-binding-overlap/report.md:98-100 (cells) and
// :116-121 (variables), width pair u32+u16.
constexpr std::array<Task053Expectation, 3> kTask053Row = {{
    {1U, 2U, 0x11223344ULL, 0x11543244ULL, 0x5432ULL, 0x5432ULL, 1U, false},
    {2U, 2U, 0x11223344ULL, 0x76543344ULL, 0x7654ULL, 0x7654ULL, 1U, false},
    {3U, 1U, 0x11223344ULL, 0x76223344ULL, 0x9876ULL, 0x9876ULL, 1U, false},
}};

// docs/experiments/solver-binding-overlap/report.md:144-146, the disjoint
// control of task-053.
constexpr Task053Expectation kTask053Control = {
    4U, 0U, 0x11223344ULL, 0x11223344ULL, 0xBA98ULL, 0xBA98ULL, 0U, true};

bool MatchesTask053(const Cell& cell, const Task053Expectation& want) {
    if (cell.vars.size() != 2U) {
        return false;
    }
    const VarFact& wide = cell.vars[cell.wide_var_index];
    const VarFact& narrow = cell.vars[cell.narrow_var_index];
    return cell.shift == want.shift && cell.overlap_bytes == want.overlap_bytes &&
           cell.num_vars == 2U && cell.outcome == SolveOutcome::kCandidate &&
           wide.model_value == want.wide_model && wide.reread_value == want.wide_reread &&
           narrow.model_value == want.narrow_model && narrow.reread_value == want.narrow_reread &&
           cell.mismatched_vars == want.mismatched_vars &&
           cell.gate_on_candidate == want.gate_on_candidate;
}

// Count of cells whose model did not survive the write-back, over one slice
// of the grid. The two dependence questions are answered by comparing such
// counts across slices that differ in exactly one coordinate.
unsigned MismatchCells(const Layout& layout, const Row* only_row, unsigned* overlapping_out) {
    unsigned mismatch = 0;
    unsigned overlapping = 0;
    for (const Row& row : kRows) {
        if (only_row != nullptr && std::string(row.name) != std::string(only_row->name)) {
            continue;
        }
        for (const std::size_t shift : kShifts) {
            const Cell cell =
                Measure(CellId(layout, row, shift), layout, shift, row.wide_bits, row.narrow_bits);
            if (cell.model_mismatch) {
                ++mismatch;
            }
            if (cell.overlapping) {
                ++overlapping;
            }
        }
    }
    if (overlapping_out != nullptr) {
        *overlapping_out = overlapping;
    }
    return mismatch;
}

}  // namespace

// Fixture sanity: the seed the whole grid stands on, byte for byte the seed
// of task-053 (docs/experiments/solver-binding-overlap/raw-overlap.txt:7).
// Sixteen distinct bytes, no two adjacent in value.
TEST(SolverBindingOverlapOrder, SeedIsDistinctAndNonAdjacent) {
    const std::vector<std::uint8_t> seed = Seed();
    ASSERT_EQ(seed.size(), kSeedSize);
    for (std::size_t i = 0; i < seed.size(); ++i) {
        for (std::size_t j = i + 1; j < seed.size(); ++j) {
            EXPECT_NE(seed[i], seed[j]) << "seed bytes " << i << " and " << j << " coincide";
            const int delta = static_cast<int>(seed[i]) - static_cast<int>(seed[j]);
            EXPECT_NE(delta, 1) << "seed bytes " << i << " and " << j << " are adjacent in value";
            EXPECT_NE(delta, -1) << "seed bytes " << i << " and " << j << " are adjacent in value";
        }
    }
    std::cout << "FIXTURE seed_size=" << seed.size() << " bytes=";
    for (const std::uint8_t byte : seed) {
        std::cout << Hex(byte, 8U) << ",";
    }
    std::cout << " target32=" << Hex(kTarget32, 32U) << " target64=" << Hex(kTarget64, 64U) << "\n";
}

// The endianness coordinate is only real where the encoding differs. A
// one-byte field encodes identically in both orders, so FindFirst matches it
// little-endian first (src/concolic/concolic.cpp:158-163) and no request can
// make it big-endian. Stated here as a measurement, because six cells of the
// grid (u32+u8 in both BE layouts) carry a little-endian narrow field by ABI.
TEST(SolverBindingOverlapOrder, OneByteFieldIsEndianNeutral) {
    unsigned be_cells = 0;
    unsigned be_narrow_bindings = 0;
    for (const Layout& layout : {kForwardBe, kReverseBe}) {
        for (const Row& row : kRows) {
            const Cell cell =
                Measure(CellId(layout, row, 1U), layout, 1U, row.wide_bits, row.narrow_bits);
            ASSERT_EQ(cell.vars.size(), 2U) << cell.id;
            ++be_cells;
            const VarFact& narrow = cell.vars[cell.narrow_var_index];
            const VarFact& wide = cell.vars[cell.wide_var_index];
            if (narrow.big_endian) {
                ++be_narrow_bindings;
            }
            std::cout << "ENDIAN id=" << cell.id << " narrow_w=" << unsigned{narrow.bit_width}
                      << " narrow_be=" << YesNo(narrow.big_endian)
                      << " wide_w=" << unsigned{wide.bit_width}
                      << " wide_be=" << YesNo(wide.big_endian) << "\n";
            EXPECT_TRUE(wide.big_endian) << cell.id;
            EXPECT_EQ(narrow.big_endian, row.narrow_bits > 8U) << cell.id;
        }
    }
    std::cout << "ENDIAN-SUMMARY be_cells=" << be_cells
              << " be_narrow_bindings=" << be_narrow_bindings << " expected=4\n";
    EXPECT_EQ(be_narrow_bindings, 4U);
}

// The grid: twenty-seven cells, three layouts by three width pairs by three
// shifts. One CELL line and two VAR lines per cell, then the SUMMARY line the
// report quotes.
TEST(SolverBindingOverlapOrder, TwentySevenCellsAcrossThreeLayouts) {
    unsigned cells = 0;
    unsigned overlapping = 0;
    unsigned candidates = 0;
    unsigned mismatch_cells = 0;
    unsigned mismatched_vars = 0;
    unsigned gate_taken = 0;
    unsigned silent = 0;
    unsigned replay_faithful = 0;
    unsigned wide_mismatches = 0;
    unsigned narrow_mismatches = 0;
    unsigned mismatch_among_overlapping = 0;

    for (const Layout& layout : kLayouts) {
        for (const Row& row : kRows) {
            for (const std::size_t shift : kShifts) {
                const Cell cell = Measure(CellId(layout, row, shift), layout, shift, row.wide_bits,
                                          row.narrow_bits);
                PrintCell("CELL", cell);
                ++cells;

                // The cell must measure what it claims: two variables, the
                // intended bindings, three constraints, the target last.
                EXPECT_EQ(cell.num_vars, 2U) << cell.id;
                EXPECT_TRUE(cell.bindings_as_intended) << cell.id;
                EXPECT_EQ(cell.path_size, 3U) << cell.id;
                EXPECT_EQ(cell.target_index, 2U) << cell.id;
                EXPECT_TRUE(cell.astaken_holds_on_seed) << cell.id;
                EXPECT_EQ(cell.status, SolveResult::Status::kSat) << cell.id;
                EXPECT_EQ(cell.vars.size(), 2U) << cell.id;

                // The replayed write-back is the engine's, byte for byte.
                EXPECT_TRUE(cell.engine_equals_replay) << cell.id;
                if (cell.engine_equals_replay) {
                    ++replay_faithful;
                }

                if (cell.overlapping) {
                    ++overlapping;
                    if (cell.model_mismatch) {
                        ++mismatch_among_overlapping;
                    }
                }
                if (cell.outcome == SolveOutcome::kCandidate) {
                    ++candidates;
                }
                if (cell.model_mismatch) {
                    ++mismatch_cells;
                }
                mismatched_vars += cell.mismatched_vars;
                if (cell.wide_mismatch) {
                    ++wide_mismatches;
                }
                if (cell.narrow_mismatch) {
                    ++narrow_mismatches;
                }
                if (cell.gate_on_candidate) {
                    ++gate_taken;
                }
                if (cell.model_mismatch && cell.outcome == SolveOutcome::kCandidate) {
                    ++silent;
                }

                // Range arithmetic, asserted rather than trusted: with the
                // narrow field first the shared part is narrow_len - d bytes
                // and vanishes as soon as d reaches narrow_len; with the wide
                // field first it is min(wide_len - d, narrow_len).
                const std::size_t narrow_len = cell.narrow_bits / kBitsPerByte;
                const std::size_t wide_len = cell.wide_bits / kBitsPerByte;
                const std::size_t predicted = cell.reverse
                                                  ? (narrow_len > shift ? narrow_len - shift : 0U)
                                                  : std::min(wide_len - shift, narrow_len);
                EXPECT_EQ(cell.overlap_bytes, predicted) << cell.id;
            }
        }
    }

    std::cout << "SUMMARY cells=" << cells << " overlapping_cells=" << overlapping
              << " candidates=" << candidates << " model_mismatch_cells=" << mismatch_cells
              << " mismatch_among_overlapping=" << mismatch_among_overlapping << "/" << overlapping
              << " mismatched_vars=" << mismatched_vars
              << " wide_mismatch_cells=" << wide_mismatches
              << " narrow_mismatch_cells=" << narrow_mismatches << " gate_taken=" << gate_taken
              << "/" << cells << " silent_mismatch_cells=" << silent
              << " silent_mismatch=" << YesNo(silent > 0U)
              << " engine_equals_replay=" << replay_faithful << "/" << cells << "\n";

    EXPECT_EQ(cells, 27U);
    EXPECT_EQ(replay_faithful, 27U);
}

// Control one: three forward-LE cells that must reproduce task-053 number for
// number. If they drift, this grid measures a different pipeline and nothing
// above may be compared with the earlier report.
TEST(SolverBindingOverlapOrder, ControlRowReproducesTask053) {
    unsigned checked = 0;
    unsigned reproduced = 0;
    for (const Task053Expectation& want : kTask053Row) {
        const Cell cell =
            Measure(std::string("control-053/") + CellId(kForwardLe, kRows[0], want.shift),
                    kForwardLe, want.shift, kRows[0].wide_bits, kRows[0].narrow_bits);
        PrintCell("CONTROL053", cell);
        ++checked;
        const bool same = MatchesTask053(cell, want);
        if (same) {
            ++reproduced;
        }
        std::cout << "CONTROL053-CHECK id=" << cell.id
                  << " want_overlap_bytes=" << want.overlap_bytes
                  << " got_overlap_bytes=" << cell.overlap_bytes
                  << " want_wide_reread=" << Hex(want.wide_reread, cell.wide_bits)
                  << " got_wide_reread="
                  << Hex(cell.vars.empty() ? 0U : cell.vars[cell.wide_var_index].reread_value,
                         cell.wide_bits)
                  << " want_mismatched_vars=" << want.mismatched_vars
                  << " got_mismatched_vars=" << cell.mismatched_vars
                  << " want_gate=" << YesNo(want.gate_on_candidate)
                  << " got_gate=" << YesNo(cell.gate_on_candidate) << " matches=" << YesNo(same)
                  << "\n";
        EXPECT_TRUE(same) << cell.id;
    }

    // The disjoint control of task-053 as well: it is the one cell there whose
    // model survived, and it must survive here too.
    const Cell disjoint =
        Measure(std::string("control-053/") + CellId(kForwardLe, kRows[0], kControlShift),
                kForwardLe, kControlShift, kRows[0].wide_bits, kRows[0].narrow_bits);
    PrintCell("CONTROL053", disjoint);
    const bool disjoint_same = MatchesTask053(disjoint, kTask053Control);
    ++checked;
    if (disjoint_same) {
        ++reproduced;
    }
    EXPECT_TRUE(disjoint_same) << disjoint.id;

    std::cout << "CONTROL053-SUMMARY checked=" << checked << " reproduced=" << reproduced
              << " control_matches_task053=" << YesNo(checked == reproduced) << "\n";
    EXPECT_EQ(reproduced, checked);
}

// Control two: the new layout with DISJOINT ranges. Same big-endian bindings,
// same guards, same target — only the overlap is gone. If the model survives
// here and only here, the grid measures overlap and not endianness.
TEST(SolverBindingOverlapOrder, ControlWithoutOverlapInBigEndianLayout) {
    const Cell cell =
        Measure(std::string("control-nooverlap/") + CellId(kForwardBe, kRows[0], kControlShift),
                kForwardBe, kControlShift, kRows[0].wide_bits, kRows[0].narrow_bits);
    PrintCell("CONTROL", cell);

    EXPECT_EQ(cell.num_vars, 2U);
    EXPECT_TRUE(cell.bindings_as_intended);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.target_index, 2U);
    EXPECT_FALSE(cell.overlapping);
    EXPECT_EQ(cell.overlap_bytes, 0U);
    EXPECT_EQ(cell.status, SolveResult::Status::kSat);
    EXPECT_TRUE(cell.engine_equals_replay);

    const bool matches_model = !cell.model_mismatch;
    std::cout << "CONTROL-NOOVERLAP id=" << cell.id
              << " endian=be overlap=" << YesNo(cell.overlapping)
              << " overlap_bytes=" << cell.overlap_bytes
              << " mismatched_vars=" << cell.mismatched_vars
              << " control_no_overlap_matches_model=" << YesNo(matches_model)
              << " outcome=" << OutcomeName(cell.outcome)
              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";

    // Without overlap the write-back must deliver the model verbatim and the
    // inverted gate must hold, big-endian bindings notwithstanding. A red
    // control invalidates the grid.
    EXPECT_TRUE(matches_model);
    EXPECT_EQ(cell.mismatched_vars, 0U);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// The question of the file, as an assertion rather than as prose. Both
// dependence flags are decided by one and the same operational rule, fixed
// BEFORE the run: a coordinate is `dependent` if model_mismatch_cells differs
// between two slices of the grid that differ in that coordinate ALONE.
//   order:  fwd-be (9 cells) vs rev-be (9 cells); and, at little-endian, the
//           forward-LE control row (3 cells) vs rev-le on the same width pair.
//   endian: rev-le (9) vs rev-be (9); and forward-LE control row (3) vs the
//           same three cells of fwd-be.
TEST(SolverBindingOverlapOrder, OrderAndEndianDependenceAndSilentMismatch) {
    unsigned overlap_fwd_be = 0;
    unsigned overlap_rev_be = 0;
    unsigned overlap_rev_le = 0;
    const unsigned mismatch_fwd_be = MismatchCells(kForwardBe, nullptr, &overlap_fwd_be);
    const unsigned mismatch_rev_be = MismatchCells(kReverseBe, nullptr, &overlap_rev_be);
    const unsigned mismatch_rev_le = MismatchCells(kReverseLe, nullptr, &overlap_rev_le);

    unsigned overlap_fwd_le_row = 0;
    unsigned overlap_rev_le_row = 0;
    unsigned overlap_fwd_be_row = 0;
    const unsigned mismatch_fwd_le_row = MismatchCells(kForwardLe, &kRows[0], &overlap_fwd_le_row);
    const unsigned mismatch_rev_le_row = MismatchCells(kReverseLe, &kRows[0], &overlap_rev_le_row);
    const unsigned mismatch_fwd_be_row = MismatchCells(kForwardBe, &kRows[0], &overlap_fwd_be_row);

    const bool order_dependent =
        mismatch_fwd_be != mismatch_rev_be || mismatch_fwd_le_row != mismatch_rev_le_row;
    const bool endian_dependent =
        mismatch_rev_le != mismatch_rev_be || mismatch_fwd_le_row != mismatch_fwd_be_row;

    std::cout << "DEPEND-ORDER fwd_be_mismatch=" << mismatch_fwd_be << "/9 (overlapping "
              << overlap_fwd_be << ") rev_be_mismatch=" << mismatch_rev_be << "/9 (overlapping "
              << overlap_rev_be << ") fwd_le_row_mismatch=" << mismatch_fwd_le_row << "/3 (over "
              << overlap_fwd_le_row << ") rev_le_row_mismatch=" << mismatch_rev_le_row
              << "/3 (over " << overlap_rev_le_row << ") order_dependent=" << YesNo(order_dependent)
              << "\n";
    std::cout << "DEPEND-ENDIAN rev_le_mismatch=" << mismatch_rev_le << "/9 (overlapping "
              << overlap_rev_le << ") rev_be_mismatch=" << mismatch_rev_be << "/9 (overlapping "
              << overlap_rev_be << ") fwd_le_row_mismatch=" << mismatch_fwd_le_row << "/3 (over "
              << overlap_fwd_le_row << ") fwd_be_row_mismatch=" << mismatch_fwd_be_row
              << "/3 (over " << overlap_fwd_be_row
              << ") endian_dependent=" << YesNo(endian_dependent) << "\n";

    // Silent mismatch, defined exactly as in task-053
    // (docs/experiments/solver-binding-overlap/report.md:65-67): a cell where
    // outcome == kCandidate while the re-read value disagrees with the model.
    unsigned silent = 0;
    unsigned gate_lost = 0;
    unsigned silent_with_gate = 0;
    for (const Layout& layout : kLayouts) {
        for (const Row& row : kRows) {
            for (const std::size_t shift : kShifts) {
                const Cell cell = Measure(CellId(layout, row, shift), layout, shift, row.wide_bits,
                                          row.narrow_bits);
                if (cell.model_mismatch && cell.outcome == SolveOutcome::kCandidate) {
                    ++silent;
                    if (cell.gate_on_candidate) {
                        ++silent_with_gate;
                    }
                    std::cout << "SILENT id=" << cell.id << " outcome=" << OutcomeName(cell.outcome)
                              << " mismatched_vars=" << cell.mismatched_vars
                              << " wide_mismatch=" << YesNo(cell.wide_mismatch)
                              << " narrow_mismatch=" << YesNo(cell.narrow_mismatch)
                              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";
                }
                if (cell.outcome == SolveOutcome::kCandidate && !cell.gate_on_candidate) {
                    ++gate_lost;
                }
            }
        }
    }

    std::cout << "SUMMARY-SILENT silent_cells=" << silent
              << "/27 silent_with_gate_taken=" << silent_with_gate << "/" << silent
              << " candidate_without_flip=" << gate_lost
              << "/27 silent_mismatch=" << YesNo(silent > 0U)
              << " order_dependent=" << YesNo(order_dependent)
              << " endian_dependent=" << YesNo(endian_dependent) << "\n";
}
