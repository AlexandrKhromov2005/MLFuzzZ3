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

// Overlapping byte RANGES of two bindings (task-053, ADR 0035 §2).
//
// The gap. Findable fields are collected into a std::map keyed by the byte
// OFFSET (src/concolic/concolic.cpp:216-224), so two fields at different
// offsets are always two different variables — nothing checks whether their
// byte ranges intersect. A u32 at offset 0 owns bytes [0,4) and a u16 at
// offset 1 owns bytes [1,3): two independent variables in the solver, one
// shared pair of bytes in the input. The write-back walks sys.vars in order
// and copies each model value to its own offset (src/concolic/concolic.cpp:
// 303-317), so the later variable overwrites part of the earlier one. If the
// model gave the shared bytes different values, the candidate no longer
// carries the model — while the engine still reports kCandidate.
//
// What this file measures. Nine cells (shift d of the second field ∈ {1,2,3}
// × width pair ∈ {u32+u16, u32+u8, u64+u32}) plus one control cell with the
// SAME width pair as the first row and d = 4, where the ranges are disjoint.
// Per cell: the bindings, the range arithmetic, the outcome, and — for every
// variable — its model value against the value RE-READ from the candidate
// through that same binding. A disagreement is arithmetic, not judgement.
//
// Why the model is unique here (so nothing depends on Z3's freedom of
// choice). The narrow field b is pinned by two guards, `b >u b-1` and
// `b <u b+1`, both TRUE on the seed, hence kept as-is by the as-taken
// encoding (src/concolic/concolic.cpp:248-249); together they admit exactly
// one value. The wide field a is pinned by the target `a == K`, FALSE on the
// seed, hence stored negated as `a != K` and flipped back to `a == K` by the
// inversion. So model = {a = K, b = b_seed} with no other solution, and both
// SolveInverted calls in this file must return it.
//
// How this differs from the three tests it borders on:
//   * WidthShadowing (tests/unit/concolic/test_width_shadowing.cpp:282-400)
//     puts BOTH records at one and the same offset 0 and asks which width
//     wins the single binding. There the second field is not a second
//     variable at all — the map key collides. Here the offsets differ, both
//     fields become variables (num_vars == 2), and the collision is between
//     two write-backs, not between two candidate bindings.
//   * BothSidesDerived.OverlappingFieldIsInDomainAndSolvable
//     (tests/unit/concolic/test_both_sides_derived.cpp:415) reuses ONE
//     variable (the field at offset 4) on both sides of a kAddVars gate.
//     "Overlapping" there means one variable appearing twice in one
//     constraint; the four fields sit at 0/4/8/12 and their byte ranges are
//     disjoint. Here the ranges themselves intersect.
//   * UnsatAnatomy.AliasedOffsetsMakeIndependentRecordsContradictory
//     (tests/unit/concolic/test_unsat_anatomy.cpp:326) puts the same VALUE
//     at two disjoint windows (bytes 0-3 and 4-7), so FindFirst collapses
//     both records onto offset 0 and num_vars drops to 1. The bytes there
//     never overlap; the aliasing is a product of value search. Here the
//     values differ, the search finds two distinct offsets, and the overlap
//     is physical.
// None of the three has different offsets AND different widths AND
// intersecting byte ranges at the same time; that cell is this file's.

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

// Sixteen pairwise distinct bytes, none of which is adjacent in value to
// another (no x and x±1 both present). The distinctness makes every field
// pattern below occur exactly once, so FindFirst binds it at the intended
// offset; the non-adjacency keeps the guard constants b-1 and b+1 absent
// from the seed, so they bind as constants and never forge a third variable.
constexpr std::array<std::uint8_t, kSeedSize> kSeed = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

// Target constants for the wide field. Their little-endian bytes are drawn
// from a value range the seed does not use at all, so (a) they are not
// findable and bind as constants, and (b) every byte the narrow field
// overwrites is guaranteed to differ from the model's byte — the mismatch
// cannot be masked by a lucky coincidence.
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

// Little-endian read straight from the seed; used to build the log records,
// which is what makes the fields findable in the first place.
std::uint64_t ReadLe(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (kBitsPerByte * k);
    }
    return value;
}

// Read a field back through its own binding — the inverse of the write-back
// (mirrors ReadField, src/concolic/concolic.cpp:117-126).
std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[var.offset + k]) << shift;
    }
    return value;
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
// the implementation. Only the predicates this fixture uses are defined; a
// predicate outside that set is a fixture error, not a measurement.
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

// One measured variable: what the model said and what the candidate carries.
struct VarFact {
    std::size_t offset;
    std::uint8_t bit_width;
    bool big_endian;
    std::uint64_t model_value;
    std::uint64_t reread_value;
    bool matches;
};

struct Cell {
    std::string id;
    std::size_t shift = 0;
    unsigned wide_bits = 0;
    unsigned narrow_bits = 0;

    // Range arithmetic on the ACTUAL bindings the engine produced.
    std::size_t a_offset = 0;
    std::size_t a_len = 0;
    std::size_t b_offset = 0;
    std::size_t b_len = 0;
    std::size_t overlap_bytes = 0;
    bool overlapping = false;

    // System facts.
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    bool bindings_as_intended = false;

    // Direct solve + replayed write-back.
    SolveResult::Status status = SolveResult::Status::kError;
    std::vector<VarFact> vars;
    unsigned mismatched_vars = 0;
    bool model_mismatch = false;

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
// (System::target_index, src/concolic/concolic.cpp:253-254).
std::vector<BranchReader::Record> MakeRecords(std::size_t shift, unsigned wide_bits,
                                              unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const std::uint64_t a = ReadLe(seed, 0, wide_bits / kBitsPerByte);
    const std::uint64_t b = ReadLe(seed, shift, narrow_bits / kBitsPerByte);
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

Cell Measure(const std::string& id, std::size_t shift, unsigned wide_bits, unsigned narrow_bits) {
    Cell cell;
    cell.id = id;
    cell.shift = shift;
    cell.wide_bits = wide_bits;
    cell.narrow_bits = narrow_bits;

    const std::vector<std::uint8_t> seed = Seed();
    const std::vector<BranchReader::Record> records = MakeRecords(shift, wide_bits, narrow_bits);
    const System sys = BuildSystem(seed, records);

    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;

    // Range arithmetic is read off the bindings the engine actually made,
    // never off the intent: [offset, offset + bit_width/8).
    if (sys.vars.size() == 2U) {
        cell.a_offset = sys.vars[0].offset;
        cell.a_len = sys.vars[0].bit_width / kBitsPerByte;
        cell.b_offset = sys.vars[1].offset;
        cell.b_len = sys.vars[1].bit_width / kBitsPerByte;
        const std::size_t lo = std::max(cell.a_offset, cell.b_offset);
        const std::size_t hi = std::min(cell.a_offset + cell.a_len, cell.b_offset + cell.b_len);
        cell.overlap_bytes = hi > lo ? hi - lo : 0U;
        cell.overlapping = cell.overlap_bytes > 0U;
        cell.bindings_as_intended = cell.a_offset == 0U && cell.b_offset == shift &&
                                    sys.vars[0].bit_width == wide_bits &&
                                    sys.vars[1].bit_width == narrow_bits &&
                                    !sys.vars[0].big_endian && !sys.vars[1].big_endian;
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
                             .matches = model == reread});
        if (model != reread) {
            ++cell.mismatched_vars;
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

void PrintCell(const Cell& cell) {
    std::cout << "CELL id=" << cell.id << " d=" << cell.shift << " widths=" << cell.wide_bits << "+"
              << cell.narrow_bits << " a=[" << cell.a_offset << "," << cell.a_offset + cell.a_len
              << ") b=[" << cell.b_offset << "," << cell.b_offset + cell.b_len
              << ") overlap=" << YesNo(cell.overlapping) << " overlap_bytes=" << cell.overlap_bytes
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
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        const VarFact& var = cell.vars[k];
        std::cout << "VAR id=" << cell.id << " k=" << k << " off=" << var.offset
                  << " w=" << unsigned{var.bit_width} << " be=" << YesNo(var.big_endian)
                  << " model=" << Hex(var.model_value, var.bit_width)
                  << " reread=" << Hex(var.reread_value, var.bit_width)
                  << " match=" << YesNo(var.matches) << "\n";
    }
}

struct Row {
    const char* name;
    unsigned wide_bits;
    unsigned narrow_bits;
};

constexpr std::array<Row, 3> kRows = {{
    {"u32+u16", 32U, 16U},
    {"u32+u8", 32U, 8U},
    {"u64+u32", 64U, 32U},
}};

constexpr std::array<std::size_t, 3> kShifts = {1U, 2U, 3U};

// The control: same width pair as the first row, shifted one byte further so
// the ranges stop touching — [0,4) and [4,6). Everything else is identical,
// which is what makes overlap the only variable of the comparison.
constexpr std::size_t kControlShift = 4U;

std::string CellId(const Row& row, std::size_t shift) {
    return std::string(row.name) + "/d=" + std::to_string(shift);
}

}  // namespace

// Fixture sanity: the seed the whole grid stands on. Sixteen distinct bytes,
// no two of them adjacent in value. If this breaks, the bindings below can
// land somewhere other than where the grid claims.
TEST(SolverBindingOverlap, SeedIsDistinctAndNonAdjacent) {
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

// The grid: nine overlapping cells. One CELL line and two VAR lines per cell,
// then the SUMMARY line the report quotes.
TEST(SolverBindingOverlap, NineOverlappingCells) {
    unsigned cells = 0;
    unsigned overlapping = 0;
    unsigned candidates = 0;
    unsigned mismatch_cells = 0;
    unsigned mismatched_vars = 0;
    unsigned gate_taken = 0;
    unsigned silent = 0;
    unsigned replay_faithful = 0;

    for (const Row& row : kRows) {
        for (const std::size_t shift : kShifts) {
            const Cell cell = Measure(CellId(row, shift), shift, row.wide_bits, row.narrow_bits);
            PrintCell(cell);
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
            }
            if (cell.outcome == SolveOutcome::kCandidate) {
                ++candidates;
            }
            if (cell.model_mismatch) {
                ++mismatch_cells;
            }
            mismatched_vars += cell.mismatched_vars;
            if (cell.gate_on_candidate) {
                ++gate_taken;
            }
            if (cell.model_mismatch && cell.outcome == SolveOutcome::kCandidate) {
                ++silent;
            }
        }
    }

    std::cout << "SUMMARY cells=" << cells << " overlapping_cells=" << overlapping
              << " candidates=" << candidates << " model_mismatch_cells=" << mismatch_cells
              << " mismatched_vars=" << mismatched_vars << " gate_taken=" << gate_taken << "/"
              << cells << " silent_mismatch_cells=" << silent
              << " silent_mismatch=" << YesNo(silent > 0U)
              << " engine_equals_replay=" << replay_faithful << "/" << cells << "\n";

    EXPECT_EQ(cells, 9U);
    EXPECT_EQ(overlapping, 9U);
    EXPECT_EQ(replay_faithful, 9U);
}

// The control: identical in every respect except that the two ranges are
// disjoint. If the model survives here and only here, the grid measures
// overlap and not something else.
TEST(SolverBindingOverlap, ControlWithoutOverlap) {
    const Cell cell = Measure(std::string("control/") + CellId(kRows[0], kControlShift),
                              kControlShift, kRows[0].wide_bits, kRows[0].narrow_bits);
    PrintCell(cell);

    EXPECT_EQ(cell.num_vars, 2U);
    EXPECT_TRUE(cell.bindings_as_intended);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_EQ(cell.target_index, 2U);
    EXPECT_FALSE(cell.overlapping);
    EXPECT_EQ(cell.overlap_bytes, 0U);
    EXPECT_EQ(cell.status, SolveResult::Status::kSat);
    EXPECT_TRUE(cell.engine_equals_replay);

    const bool matches_model = !cell.model_mismatch;
    std::cout << "CONTROL overlap=" << YesNo(cell.overlapping)
              << " overlap_bytes=" << cell.overlap_bytes
              << " mismatched_vars=" << cell.mismatched_vars
              << " control_matches_model=" << YesNo(matches_model)
              << " outcome=" << OutcomeName(cell.outcome)
              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";

    // Without overlap the write-back must deliver the model verbatim and the
    // inverted gate must hold. A red control invalidates the grid.
    EXPECT_TRUE(matches_model);
    EXPECT_EQ(cell.mismatched_vars, 0U);
    EXPECT_TRUE(cell.gate_on_candidate);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
}

// The point of the whole file, stated as an assertion rather than as prose:
// is there a cell where the engine reports kCandidate while the candidate
// disagrees with the model it was built from? The count is printed either
// way — a zero here would be the result "range overlap does not hurt".
TEST(SolverBindingOverlap, SilentMismatchIsWhatTheOutcomeHides) {
    unsigned silent = 0;
    unsigned mismatch_cells = 0;
    unsigned gate_lost = 0;

    for (const Row& row : kRows) {
        for (const std::size_t shift : kShifts) {
            const Cell cell = Measure(CellId(row, shift), shift, row.wide_bits, row.narrow_bits);
            if (cell.model_mismatch) {
                ++mismatch_cells;
            }
            if (cell.model_mismatch && cell.outcome == SolveOutcome::kCandidate) {
                ++silent;
                std::cout << "SILENT id=" << cell.id << " outcome=" << OutcomeName(cell.outcome)
                          << " mismatched_vars=" << cell.mismatched_vars
                          << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";
            }
            if (cell.outcome == SolveOutcome::kCandidate && !cell.gate_on_candidate) {
                ++gate_lost;
            }
        }
    }

    // The control proves the same pipeline does deliver the model when the
    // ranges are disjoint, so a mismatch here is caused by the overlap.
    const Cell control = Measure(std::string("control/") + CellId(kRows[0], kControlShift),
                                 kControlShift, kRows[0].wide_bits, kRows[0].narrow_bits);

    std::cout << "SUMMARY-SILENT mismatch_cells=" << mismatch_cells << "/9 silent_cells=" << silent
              << "/9 candidate_without_flip=" << gate_lost
              << "/9 control_matches_model=" << YesNo(!control.model_mismatch) << "\n";

    EXPECT_FALSE(control.model_mismatch);
}
