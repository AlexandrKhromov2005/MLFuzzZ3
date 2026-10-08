// task-059: does the ARITY and TOPOLOGY of binding overlap change the
// byte-clobbering picture?
//
// task-053 (tests/unit/concolic/test_binding_overlap.cpp) and task-056
// (tests/unit/concolic/test_binding_overlap_order.cpp) both measured exactly
// TWO overlapping byte ranges with num_vars=2. The task-056 report names the
// gap verbatim: "Он не проверяет три и более перекрывающихся поля: всюду ровно
// две привязки и num_vars=2" (docs/experiments/solver-binding-overlap-order/
// report.md:419-420).
//
// The mechanism under test is unchanged: the model write-back walks sys.vars
// in order and never checks whether a byte was already written
// (src/concolic/concolic.cpp:303-317). With THREE overlapping ranges the
// outcome must depend on HOW they intersect:
//   * chain  — A∩B and B∩C non-empty, A∩C empty: the last write clobbers one
//              neighbour only;
//   * star   — one byte shared by all three: the last write clobbers two;
//   * nested — C lies entirely inside A∩B.
// Whether the number of clobbered variables at k=3 continues the k=2 picture
// is not derivable; it is measured here.
//
// This is NOT DomainArity (task-044). DomainArity measures the arity of a SUM
// reconstructed by BindOperand, k_max_bound=2
// (docs/experiments/solver-domain-arity/report.md:133) — arity of an operand
// inside one record. Here the coordinate is the arity of the INTERSECTION of
// byte ranges in a layout. Different axes.
//
// src/ is not modified. No fuzzing campaigns are run. The task-053 and
// task-056 harnesses are not touched.
//
// Operational definition, fixed BEFORE the run:
//   topology_dependent = yes iff, changing ONLY the topology coordinate
//   (widths set and field order held fixed), mismatched_vars or
//   max_mismatched_vars_per_cell differs between cells.
//   silent_mismatch = yes iff at least one cell has outcome == kCandidate
//   while a re-read field value differs from its model value (same definition
//   as task-053).

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

enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUgt = 4, kUge = 5 };

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kTimeoutMs = 5000;
constexpr std::size_t kSeedSize = 16;

// The task-053 seed, byte for byte (tests/unit/concolic/test_binding_overlap.cpp:95-96):
// sixteen pairwise distinct, non-adjacent bytes. Reused verbatim so the k=2
// control row is comparable with the accepted task-053 numbers.
constexpr std::array<std::uint8_t, kSeedSize> kSeed = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

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

std::uint64_t ReadLe(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (kBitsPerByte * k);
    }
    return value;
}

// Inverse of the write-back (mirrors ReadField, src/concolic/concolic.cpp:117-126).
std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[var.offset + k]) << shift;
    }
    return value;
}

// The engine's write-back, replayed (mirrors src/concolic/concolic.cpp:303-317).
// `owner` records, per byte, the index of the LAST variable that wrote it —
// that array is the clobber chain.
std::vector<std::uint8_t> WriteBackModel(const std::vector<std::uint8_t>& seed, const System& sys,
                                         const std::vector<std::uint64_t>& model,
                                         std::vector<int>* owner) {
    std::vector<std::uint8_t> bytes = seed;
    if (owner != nullptr) {
        owner->assign(bytes.size(), -1);
    }
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const VarBinding& var = sys.vars[k];
        const unsigned n = var.bit_width / kBitsPerByte;
        const std::uint64_t value = Truncate(model[k], var.bit_width);
        for (unsigned b = 0; b < n; ++b) {
            const unsigned shift =
                var.big_endian ? (kBitsPerByte * (n - 1U - b)) : (kBitsPerByte * b);
            bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
            if (owner != nullptr) {
                (*owner)[var.offset + b] = static_cast<int>(k);
            }
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

// ---------------------------------------------------------------------------
// Layout: a field is (offset, width-in-bits). The FIRST field carries the
// target comparison; every other field is pinned by two guards.
// ---------------------------------------------------------------------------

struct Field {
    std::size_t offset;
    unsigned bits;
};

struct Layout {
    std::string id;
    std::string topology;  // chain | star | nested | k2 | none
    std::string widths;    // "u32+u16+u8"
    std::string order;     // direct | mirrored
    std::vector<Field> fields;
};

std::size_t EndOf(const Field& f) {
    return f.offset + f.bits / kBitsPerByte;
}

// Mirror the layout inside [0, L): offset -> L - offset - width. Preserves
// every pairwise intersection size while reversing the spatial order of the
// fields, which is the "обратный порядок" coordinate of task-056.
std::vector<Field> Mirror(const std::vector<Field>& fields) {
    std::size_t span = 0;
    for (const Field& f : fields) {
        span = std::max(span, EndOf(f));
    }
    std::vector<Field> out;
    out.reserve(fields.size());
    for (const Field& f : fields) {
        out.push_back({span - EndOf(f), f.bits});
    }
    return out;
}

// Two guards per non-target field, then the target on field 0 last, so the
// target is the constraint the inversion flips
// (System::target_index, src/concolic/concolic.cpp:253-254).
std::vector<BranchReader::Record> MakeRecords(const std::vector<Field>& fields) {
    const std::vector<std::uint8_t> seed = Seed();
    std::vector<BranchReader::Record> records;
    std::uint32_t site = 1;
    for (std::size_t i = 1; i < fields.size(); ++i) {
        const std::uint64_t v = ReadLe(seed, fields[i].offset, fields[i].bits / kBitsPerByte);
        records.push_back({.site_id = site++,
                           .predicate = kUgt,
                           .bit_width = static_cast<std::uint8_t>(fields[i].bits),
                           .lhs = v,
                           .rhs = v - 1U});
        records.push_back({.site_id = site++,
                           .predicate = kUlt,
                           .bit_width = static_cast<std::uint8_t>(fields[i].bits),
                           .lhs = v,
                           .rhs = v + 1U});
    }
    const std::uint64_t a = ReadLe(seed, fields[0].offset, fields[0].bits / kBitsPerByte);
    const std::uint64_t target = fields[0].bits == 64U ? kTarget64 : kTarget32;
    records.push_back({.site_id = site,
                       .predicate = kEq,
                       .bit_width = static_cast<std::uint8_t>(fields[0].bits),
                       .lhs = a,
                       .rhs = target});
    return records;
}

struct VarFact {
    std::size_t offset;
    std::uint8_t bit_width;
    bool big_endian;
    std::uint64_t model_value;
    std::uint64_t reread_value;
    bool matches;
};

struct PairFact {
    std::size_t i;
    std::size_t j;
    std::size_t lo;
    std::size_t hi;  // hi > lo == non-empty
};

struct ClobberFact {
    std::size_t victim;   // variable whose bytes were overwritten
    std::size_t culprit;  // variable that overwrote them (later in write order)
    std::size_t lo;
    std::size_t hi;
};

struct Cell {
    Layout layout;
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    bool bindings_as_intended = false;
    std::vector<PairFact> pairs;
    std::size_t common_lo = 0;
    std::size_t common_hi = 0;  // intersection of ALL ranges
    bool overlapping = false;

    SolveResult::Status status = SolveResult::Status::kError;
    std::vector<VarFact> vars;
    std::vector<ClobberFact> clobbers;
    unsigned mismatched_vars = 0;
    bool model_mismatch = false;

    std::uint8_t path_predicate = 0;
    std::uint8_t inverted_predicate = 0;
    bool astaken_holds_on_seed = false;
    bool gate_on_candidate = false;

    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    bool engine_equals_replay = false;
};

Cell Measure(const Layout& layout) {
    Cell cell;
    cell.layout = layout;

    const std::vector<std::uint8_t> seed = Seed();
    const std::vector<BranchReader::Record> records = MakeRecords(layout.fields);
    const System sys = BuildSystem(seed, records);

    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;

    // Range arithmetic is read off the bindings the engine ACTUALLY made,
    // never off the intent: [offset, offset + bit_width/8).
    for (std::size_t i = 0; i < sys.vars.size(); ++i) {
        for (std::size_t j = i + 1; j < sys.vars.size(); ++j) {
            const std::size_t lo = std::max(sys.vars[i].offset, sys.vars[j].offset);
            const std::size_t hi =
                std::min(sys.vars[i].offset + sys.vars[i].bit_width / kBitsPerByte,
                         sys.vars[j].offset + sys.vars[j].bit_width / kBitsPerByte);
            cell.pairs.push_back({i, j, lo, hi});
            if (hi > lo) {
                cell.overlapping = true;
            }
        }
    }
    if (!sys.vars.empty()) {
        cell.common_lo = 0;
        cell.common_hi = kSeedSize;
        for (const VarBinding& v : sys.vars) {
            cell.common_lo = std::max(cell.common_lo, v.offset);
            cell.common_hi = std::min(cell.common_hi, v.offset + v.bit_width / kBitsPerByte);
        }
        if (cell.common_hi < cell.common_lo) {
            cell.common_hi = cell.common_lo;
        }
    }

    cell.bindings_as_intended = sys.vars.size() == layout.fields.size();
    for (std::size_t k = 0; cell.bindings_as_intended && k < sys.vars.size(); ++k) {
        cell.bindings_as_intended = sys.vars[k].offset == layout.fields[k].offset &&
                                    sys.vars[k].bit_width == layout.fields[k].bits &&
                                    !sys.vars[k].big_endian;
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

    std::vector<int> owner;
    const std::vector<std::uint8_t> candidate =
        WriteBackModel(seed, sys, result.model_values, &owner);

    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const std::uint64_t model = Truncate(result.model_values[k], sys.vars[k].bit_width);
        const std::uint64_t reread = ReadBinding(candidate, sys.vars[k]);
        cell.vars.push_back({.offset = sys.vars[k].offset,
                             .bit_width = sys.vars[k].bit_width,
                             .big_endian = sys.vars[k].big_endian,
                             .model_value = model,
                             .reread_value = reread,
                             .matches = model == reread});
        if (model != reread) {
            ++cell.mismatched_vars;
        }
    }
    cell.model_mismatch = cell.mismatched_vars > 0U;

    // Clobber chain, by name: for every variable k, the maximal byte runs of
    // its own range that a LATER variable now owns.
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const std::size_t begin = sys.vars[k].offset;
        const std::size_t end = begin + sys.vars[k].bit_width / kBitsPerByte;
        std::size_t b = begin;
        while (b < end) {
            const int who = owner[b];
            if (who == static_cast<int>(k)) {
                ++b;
                continue;
            }
            const std::size_t run_lo = b;
            while (b < end && owner[b] == who) {
                ++b;
            }
            cell.clobbers.push_back({k, static_cast<std::size_t>(who), run_lo, b});
        }
    }

    cell.gate_on_candidate = Eval(
        cell.inverted_predicate,
        OperandValue(sys.path[sys.target_index].lhs, sys, candidate, target_width),
        OperandValue(sys.path[sys.target_index].rhs, sys, candidate, target_width), target_width);

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

void PrintCell(const Cell& cell) {
    std::cout << "CELL id=" << cell.layout.id << " topology=" << cell.layout.topology
              << " widths=" << cell.layout.widths << " order=" << cell.layout.order
              << " k=" << cell.layout.fields.size();
    for (std::size_t i = 0; i < cell.vars.size(); ++i) {
        std::cout << " r" << i << "=[" << cell.vars[i].offset << ","
                  << cell.vars[i].offset + cell.vars[i].bit_width / kBitsPerByte << ")";
    }
    std::cout << " overlap=" << YesNo(cell.overlapping) << " common=[" << cell.common_lo << ","
              << cell.common_hi << ")"
              << " common_bytes=" << (cell.common_hi - cell.common_lo)
              << " bindings_as_intended=" << YesNo(cell.bindings_as_intended)
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
              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";
    for (const PairFact& p : cell.pairs) {
        std::cout << "PAIR id=" << cell.layout.id << " i=" << p.i << " j=" << p.j << " inter=["
                  << p.lo << "," << (p.hi > p.lo ? p.hi : p.lo) << ")"
                  << " bytes=" << (p.hi > p.lo ? p.hi - p.lo : 0U)
                  << " overlap=" << YesNo(p.hi > p.lo) << "\n";
    }
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        const VarFact& var = cell.vars[k];
        std::cout << "VAR id=" << cell.layout.id << " k=" << k << " off=" << var.offset
                  << " w=" << unsigned{var.bit_width} << " be=" << YesNo(var.big_endian)
                  << " model=" << Hex(var.model_value, var.bit_width)
                  << " reread=" << Hex(var.reread_value, var.bit_width)
                  << " match=" << YesNo(var.matches) << "\n";
    }
    for (const ClobberFact& c : cell.clobbers) {
        std::cout << "CLOBBER id=" << cell.layout.id << " victim=v" << c.victim << " culprit=v"
                  << c.culprit << " bytes=[" << c.lo << "," << c.hi << ")"
                  << " n=" << (c.hi - c.lo) << "\n";
    }
}

// ---------------------------------------------------------------------------
// The grid. Topology arithmetic is spelled out per layout and re-verified
// from the produced bindings in the fixtures below.
// ---------------------------------------------------------------------------

Layout Make(const std::string& topology, const std::string& widths, const std::string& order,
            std::vector<Field> fields) {
    if (order == "mirrored") {
        fields = Mirror(fields);
    }
    return {topology + "/" + widths + "/" + order, topology, widths, order, fields};
}

std::vector<Layout> Grid() {
    std::vector<Layout> grid;
    for (const std::string& order : {std::string("direct"), std::string("mirrored")}) {
        // chain: A∩B and B∩C non-empty, A∩C EMPTY.
        // u32+u16+u8: A=[0,4) B=[3,5) C=[4,5) -> A∩B=[3,4), B∩C=[4,5), A∩C=∅.
        grid.push_back(Make("chain", "u32+u16+u8", order, {{0, 32}, {3, 16}, {4, 8}}));
        // u64+u32+u16: A=[0,8) B=[6,10) C=[8,10) -> A∩B=[6,8), B∩C=[8,10), A∩C=∅.
        grid.push_back(Make("chain", "u64+u32+u16", order, {{0, 64}, {6, 32}, {8, 16}}));
        // star: one byte shared by all three, and C is NOT contained in A∩B
        // (that is what separates star from nested).
        // u32+u16+u8: A=[0,4) B=[2,4) C=[3,5) -> A∩B=[2,4), A∩C=[3,4),
        // B∩C=[3,4), common=[3,4); C ⊄ A∩B.
        grid.push_back(Make("star", "u32+u16+u8", order, {{0, 32}, {2, 16}, {3, 8}}));
        // u64+u32+u16: A=[0,8) B=[4,8) C=[7,9) -> common=[7,8); C ⊄ A∩B=[4,8).
        grid.push_back(Make("star", "u64+u32+u16", order, {{0, 64}, {4, 32}, {7, 16}}));
        // nested: C entirely inside A∩B, at an offset shared with neither.
        // u32+u16+u8: A=[0,4) B=[1,3) -> A∩B=[1,3); C=[2,3) ⊂ [1,3).
        grid.push_back(Make("nested", "u32+u16+u8", order, {{0, 32}, {1, 16}, {2, 8}}));
        // u64+u32+u16: A=[0,8) B=[2,6) -> A∩B=[2,6); C=[3,5) ⊂ [2,6).
        grid.push_back(Make("nested", "u64+u32+u16", order, {{0, 64}, {2, 32}, {3, 16}}));
    }
    return grid;
}

// Control row 1: three k=2 cells, direct order, LE — the task-053 u32+u16
// cells at d=1,2,3, which must reproduce its accepted numbers.
std::vector<Layout> ControlK2() {
    std::vector<Layout> rows;
    for (std::size_t d = 1; d <= 3; ++d) {
        rows.push_back(
            {"k2/u32+u16/d=" + std::to_string(d), "k2", "u32+u16", "direct", {{0, 32}, {d, 16}}});
    }
    return rows;
}

// Control row 2: three fields, pairwise DISJOINT. The model must survive the
// write-back intact; if it does not, the grid measures something else.
Layout ControlNoOverlap() {
    return {"none/u32+u16+u8/disjoint", "none", "u32+u16+u8", "direct", {{0, 32}, {4, 16}, {6, 8}}};
}

}  // namespace

TEST(SolverBindingOverlapArity, SeedMatchesTask053) {
    const std::vector<std::uint8_t> seed = Seed();
    std::cout << "FIXTURE seed_size=" << seed.size() << " bytes=";
    for (std::size_t i = 0; i < seed.size(); ++i) {
        std::cout << (i == 0 ? "" : ",") << Hex(seed[i], 8);
    }
    std::cout << " target32=" << Hex(kTarget32, 32) << " target64=" << Hex(kTarget64, 64) << "\n";
    for (std::size_t i = 0; i < seed.size(); ++i) {
        for (std::size_t j = i + 1; j < seed.size(); ++j) {
            EXPECT_NE(seed[i], seed[j]) << i << "," << j;
        }
    }
}

TEST(SolverBindingOverlapArity, TwelveCellsThreeTopologies) {
    const std::vector<Layout> grid = Grid();
    ASSERT_EQ(grid.size(), 12U);

    unsigned overlapping_cells = 0;
    unsigned cells_with_three_bindings = 0;
    unsigned cells_sat = 0;
    unsigned candidates = 0;
    unsigned model_mismatch_cells = 0;
    unsigned mismatched_vars = 0;
    unsigned max_mismatched_vars_per_cell = 0;
    unsigned gate_taken = 0;
    bool silent = false;

    // mismatched_vars per (widths, order) triple, keyed by topology — the
    // operational test for topology_dependent.
    std::vector<std::string> keys;
    std::vector<unsigned> per_cell;

    for (const Layout& layout : grid) {
        const Cell cell = Measure(layout);
        PrintCell(cell);

        // Whether the engine actually produced three distinct variables is a
        // MEASURED fact of this grid, not an assumption: a layout in which two
        // fields collapse onto one variable is itself a k=3 result. It is
        // counted, printed and reported, never asserted away.
        if (cell.num_vars == 3U && cell.bindings_as_intended) {
            ++cells_with_three_bindings;
        }
        if (cell.status == SolveResult::Status::kSat) {
            ++cells_sat;
        }

        if (cell.overlapping) {
            ++overlapping_cells;
        }
        if (cell.outcome == SolveOutcome::kCandidate) {
            ++candidates;
        }
        if (cell.model_mismatch) {
            ++model_mismatch_cells;
        }
        mismatched_vars += cell.mismatched_vars;
        max_mismatched_vars_per_cell = std::max(max_mismatched_vars_per_cell, cell.mismatched_vars);
        if (cell.gate_on_candidate) {
            ++gate_taken;
        }
        if (cell.model_mismatch && cell.outcome == SolveOutcome::kCandidate) {
            silent = true;
        }
        keys.push_back(cell.layout.widths + "/" + cell.layout.order);
        per_cell.push_back(cell.mismatched_vars);
    }

    // topology_dependent: fixing widths and order, does mismatched_vars differ
    // across topologies?
    bool topology_dependent = false;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        for (std::size_t j = i + 1; j < keys.size(); ++j) {
            if (keys[i] == keys[j] && per_cell[i] != per_cell[j]) {
                topology_dependent = true;
            }
        }
    }

    std::cout << "SUMMARY cells=" << grid.size() << " topologies=3 k=3"
              << " cells_with_three_bindings=" << cells_with_three_bindings
              << " cells_sat=" << cells_sat << " overlapping_cells=" << overlapping_cells
              << " candidates=" << candidates << " model_mismatch_cells=" << model_mismatch_cells
              << " mismatched_vars=" << mismatched_vars
              << " max_mismatched_vars_per_cell=" << max_mismatched_vars_per_cell
              << " gate_taken=" << gate_taken << "/" << grid.size()
              << " silent_mismatch=" << YesNo(silent)
              << " topology_dependent=" << YesNo(topology_dependent) << "\n";
}

TEST(SolverBindingOverlapArity, ControlK2ReproducesTask053) {
    unsigned matches = 0;
    for (const Layout& layout : ControlK2()) {
        const Cell cell = Measure(layout);
        PrintCell(cell);
        // task-053 accepted numbers for these three cells
        // (docs/experiments/solver-binding-overlap/report.md:277-279):
        // num_vars=2, outcome=kCandidate, mismatched_vars=1, gate_on_candidate=no.
        const bool same = cell.num_vars == 2U && cell.outcome == SolveOutcome::kCandidate &&
                          cell.mismatched_vars == 1U && !cell.gate_on_candidate;
        std::cout << "K2CONTROL id=" << cell.layout.id << " num_vars=" << cell.num_vars
                  << " outcome=" << OutcomeName(cell.outcome)
                  << " mismatched_vars=" << cell.mismatched_vars
                  << " gate_on_candidate=" << YesNo(cell.gate_on_candidate)
                  << " matches_task053=" << YesNo(same) << "\n";
        if (same) {
            ++matches;
        }
        EXPECT_TRUE(same) << cell.layout.id;
    }
    std::cout << "SUMMARY-K2 cells=3 k2_control_matches_task053=" << YesNo(matches == 3U) << "\n";
}

TEST(SolverBindingOverlapArity, ControlWithoutOverlapMatchesModel) {
    const Cell cell = Measure(ControlNoOverlap());
    PrintCell(cell);
    EXPECT_EQ(cell.num_vars, 3U);
    EXPECT_FALSE(cell.overlapping);
    EXPECT_EQ(cell.mismatched_vars, 0U);
    EXPECT_TRUE(cell.clobbers.empty());
    std::cout << "SUMMARY-CONTROL id=" << cell.layout.id << " overlap=" << YesNo(cell.overlapping)
              << " mismatched_vars=" << cell.mismatched_vars
              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate)
              << " outcome=" << OutcomeName(cell.outcome)
              << " control_no_overlap_matches_model=" << YesNo(cell.mismatched_vars == 0U) << "\n";
}
