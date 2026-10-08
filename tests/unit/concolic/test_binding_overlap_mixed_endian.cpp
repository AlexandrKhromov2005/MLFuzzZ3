// task-060: mixed byte order inside ONE system on overlapping binding ranges.
//
// task-056 measured overlapping bindings across three layouts and reported
// `endian_dependent=no`
// (docs/experiments/solver-binding-overlap-order/report.md:412). That "no" was
// measured with the byte order requested EQUAL for both fields of a cell; its
// own boundary section says so
// (docs/experiments/solver-binding-overlap-order/report.md:421-424). The
// write-back lays a value out byte by byte and takes the direction from
// `var.big_endian` of EACH variable separately
// (src/concolic/concolic.cpp:310-315), so with opposite directions the two
// fields put opposite-significance digits on the bytes they share. This
// fixture measures that case and nothing else.
//
// Grid: shift d in {1,2,3} x width pair in {u32+u16, u32+u8, u64+u32} x mixed
// layout in {first LE / second BE, first BE / second LE} = 18 cells; plus a
// three-cell homogeneous control that must reproduce task-056's accepted
// numbers, plus one control without overlap. Byte order is never asserted:
// it is FOUND by BuildSystem from the seed encoding and read back off
// `System::vars`, so intended and found order are reported separately and a
// field whose width makes the order indistinguishable is named as such.
//
// Nothing here builds a target, runs a campaign, or touches src/.

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

// fuzzer_rt_cmp_kind values used by this fixture (ADR 0033).
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUgt = 4, kUge = 5 };

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kTimeoutMs = 5000;
constexpr std::size_t kSeedSize = 16;

// The seed of task-053/task-056, byte for byte
// (docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:9). The
// homogeneous control can only reproduce the accepted numbers if the input is
// identical; the mixed cells are only comparable to them for the same reason.
constexpr std::array<std::uint8_t, kSeedSize> kSeed = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

// Target constants for the wide field, also from task-056. Their bytes are
// drawn from a range the seed does not use, so they are not findable and every
// byte an overwrite touches differs from the model's.
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

std::uint64_t ReadSeedField(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n,
                            bool big_endian) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    return ReadSeedField(bytes, var.offset, var.bit_width / kBitsPerByte, var.big_endian);
}

// The orchestrator's own write-back, replayed (src/concolic/concolic.cpp:302-317):
// variables in `System::vars` order, each laid out in ITS OWN direction.
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

const char* Order(bool big_endian) {
    return big_endian ? "be" : "le";
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
    return "?";
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

// Which value-bytes of `var` fall on the shared range [lo, hi): index 0 is the
// least significant byte of the VALUE, so the same physical byte carries a
// different index for the two opposite directions. Same format as task-056
// (docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:20).
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

// The same fact spelled out per physical byte: `offset:bLO-HI` says which BIT
// range of this value the byte at `offset` carries. This is the arithmetic the
// report quotes for "which digits land on the shared bytes".
std::string SharedBitMap(const VarBinding& var, std::size_t lo, std::size_t hi) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::string list;
    for (unsigned k = 0; k < n; ++k) {
        const std::size_t byte_offset = var.offset + k;
        if (byte_offset < lo || byte_offset >= hi) {
            continue;
        }
        const unsigned index = var.big_endian ? (n - 1U - k) : k;
        if (!list.empty()) {
            list += ";";
        }
        list += std::to_string(byte_offset) + ":b" + std::to_string(kBitsPerByte * index) + "-" +
                std::to_string(kBitsPerByte * index + kBitsPerByte - 1U);
    }
    return list.empty() ? std::string("-") : list;
}

struct Row {
    const char* name;
    unsigned wide_bits;
    unsigned narrow_bits;
};

// Byte order is requested PER FIELD. `wide_be` is the field at the lower
// offset (offset 0, "first"), `narrow_be` the one at offset d ("second").
struct Layout {
    const char* name;
    bool wide_be;
    bool narrow_be;
};

constexpr std::array<Row, 3> kRows = {{
    {"u32+u16", 32U, 16U},
    {"u32+u8", 32U, 8U},
    {"u64+u32", 64U, 32U},
}};

constexpr std::array<std::size_t, 3> kShifts = {1U, 2U, 3U};

constexpr Layout kMixLeBe = {"mix-le-be", false, true};
constexpr Layout kMixBeLe = {"mix-be-le", true, false};
constexpr Layout kHomLe = {"hom-le", false, false};

constexpr std::array<Layout, 2> kMixedLayouts = {{kMixLeBe, kMixBeLe}};

// d = 4 pushes the narrow field past the end of the u32 wide field, so the
// ranges do not meet. Same control shift as task-056
// (docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:121).
constexpr std::size_t kControlShift = 4U;

struct VarFact {
    std::size_t offset;
    std::uint8_t bit_width;
    bool intended_be;
    bool found_be;
    bool order_indistinguishable;  ///< one-byte field: both directions encode alike
    std::uint64_t model_value;
    std::uint64_t reread_value;
    bool matches;
    std::string shared_value_bytes;
    std::string shared_bits;
};

struct Cell {
    std::string id;
    std::string layout;
    bool wide_be_intended = false;
    bool narrow_be_intended = false;
    std::size_t shift = 0;
    unsigned wide_bits = 0;
    unsigned narrow_bits = 0;

    std::size_t wide_offset = 0;
    std::size_t wide_len = 0;
    std::size_t narrow_offset = 0;
    std::size_t narrow_len = 0;
    std::size_t overlap_lo = 0;
    std::size_t overlap_hi = 0;
    std::size_t overlap_bytes = 0;
    bool overlapping = false;

    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    bool bindings_as_intended = false;   ///< offset and width as placed
    bool intended_endian_found = false;  ///< BOTH found orders equal the intent
    bool abi_forced = false;             ///< some field's order is indistinguishable
    bool mixed_realized = false;         ///< the two FOUND orders actually differ
    std::size_t wide_var_index = 0;
    std::size_t narrow_var_index = 1;

    SolveResult::Status status = SolveResult::Status::kError;
    std::vector<VarFact> vars;
    unsigned mismatched_vars = 0;
    bool model_mismatch = false;
    bool wide_mismatch = false;
    bool narrow_mismatch = false;

    std::uint8_t path_predicate = 0;
    std::uint8_t inverted_predicate = 0;
    bool astaken_holds_on_seed = false;
    bool gate_on_candidate = false;

    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    bool engine_equals_replay = false;
};

// Three records, exactly task-056's shape
// (tests/unit/concolic/test_binding_overlap_order.cpp:375-404): two guards
// that pin the narrow field to its seed value and one equality on the wide
// field that becomes the inverted target. The only change is that the two
// field values are read in INDEPENDENT byte orders.
std::vector<BranchReader::Record> MakeRecords(const Layout& layout, std::size_t shift,
                                              unsigned wide_bits, unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const unsigned wide_len = wide_bits / kBitsPerByte;
    const unsigned narrow_len = narrow_bits / kBitsPerByte;
    const std::uint64_t a = ReadSeedField(seed, 0U, wide_len, layout.wide_be && wide_len > 1U);
    const std::uint64_t b =
        ReadSeedField(seed, shift, narrow_len, layout.narrow_be && narrow_len > 1U);
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
    cell.wide_be_intended = layout.wide_be;
    cell.narrow_be_intended = layout.narrow_be;
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

    // sys.vars is ordered by ascending offset (src/concolic/concolic.cpp:216-224)
    // and this fixture is forward only, so the wide field is var 0.
    cell.wide_var_index = 0U;
    cell.narrow_var_index = 1U;

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

        cell.bindings_as_intended = wide.offset == 0U && narrow.offset == shift &&
                                    wide.bit_width == wide_bits && narrow.bit_width == narrow_bits;

        // A one-byte field has one encoding in both directions, so FindFirst
        // matches it little-endian (src/concolic/concolic.cpp:155-162) and no
        // request can make it big-endian. Recorded, not hidden.
        const bool wide_neutral = cell.wide_len == 1U;
        const bool narrow_neutral = cell.narrow_len == 1U;
        cell.abi_forced = wide_neutral || narrow_neutral;
        cell.intended_endian_found =
            wide.big_endian == layout.wide_be && narrow.big_endian == layout.narrow_be;
        cell.mixed_realized = wide.big_endian != narrow.big_endian;
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
        const VarBinding& var = sys.vars[k];
        const std::uint64_t model = Truncate(result.model_values[k], var.bit_width);
        const std::uint64_t reread = ReadBinding(candidate, var);
        const bool intended = k == cell.wide_var_index ? layout.wide_be : layout.narrow_be;
        cell.vars.push_back(
            {.offset = var.offset,
             .bit_width = var.bit_width,
             .intended_be = intended,
             .found_be = var.big_endian,
             .order_indistinguishable = var.bit_width == kBitsPerByte,
             .model_value = model,
             .reread_value = reread,
             .matches = model == reread,
             .shared_value_bytes = SharedValueBytes(var, cell.overlap_lo, cell.overlap_hi),
             .shared_bits = SharedBitMap(var, cell.overlap_lo, cell.overlap_hi)});
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

std::string CellId(const Layout& layout, const Row& row, std::size_t shift) {
    return std::string(layout.name) + "/" + row.name + "/d=" + std::to_string(shift);
}

void PrintCell(const char* tag, const Cell& cell) {
    std::cout << tag << " id=" << cell.id << " layout=" << cell.layout
              << " intended=" << Order(cell.wide_be_intended) << "+"
              << Order(cell.narrow_be_intended) << " d=" << cell.shift
              << " widths=" << cell.wide_bits << "+" << cell.narrow_bits << " wide=["
              << cell.wide_offset << "," << cell.wide_offset + cell.wide_len << ") narrow=["
              << cell.narrow_offset << "," << cell.narrow_offset + cell.narrow_len
              << ") overlap=" << YesNo(cell.overlapping) << " overlap_range=[" << cell.overlap_lo
              << "," << (cell.overlapping ? cell.overlap_hi : cell.overlap_lo)
              << ") overlap_bytes=" << cell.overlap_bytes
              << " bindings_as_intended=" << YesNo(cell.bindings_as_intended)
              << " intended_endian_found=" << YesNo(cell.intended_endian_found)
              << " abi_forced=" << YesNo(cell.abi_forced)
              << " mixed_realized=" << YesNo(cell.mixed_realized) << " num_vars=" << cell.num_vars
              << " path=" << cell.path_size << " target=" << cell.target_index
              << " status=" << StatusName(cell.status)
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
                  << " w=" << unsigned{var.bit_width} << " intended=" << Order(var.intended_be)
                  << " found=" << Order(var.found_be)
                  << " order_indistinguishable=" << YesNo(var.order_indistinguishable)
                  << " role=" << (k == cell.wide_var_index ? "wide" : "narrow")
                  << " model=" << Hex(var.model_value, var.bit_width)
                  << " reread=" << Hex(var.reread_value, var.bit_width)
                  << " shared_value_bytes=" << var.shared_value_bytes
                  << " shared_bits=" << var.shared_bits << " match=" << YesNo(var.matches) << "\n";
    }
}

// Common per-cell invariants: the cell must measure what it claims before any
// number it produces is worth reading.
void CheckCellShape(const Cell& cell) {
    EXPECT_EQ(cell.num_vars, 2U) << cell.id;
    EXPECT_EQ(cell.vars.size(), 2U) << cell.id;
    EXPECT_TRUE(cell.bindings_as_intended) << cell.id;
    EXPECT_EQ(cell.path_size, 3U) << cell.id;
    EXPECT_EQ(cell.target_index, 2U) << cell.id;
    EXPECT_EQ(cell.status, SolveResult::Status::kSat) << cell.id;
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate) << cell.id;
    EXPECT_TRUE(cell.has_candidate) << cell.id;
    EXPECT_TRUE(cell.engine_equals_replay) << cell.id;
    EXPECT_EQ(cell.path_predicate, kNe) << cell.id;
    EXPECT_EQ(cell.inverted_predicate, kEq) << cell.id;
}

}  // namespace

// The fixture is only comparable to task-056 if the input is the same input.
TEST(SolverBindingOverlapMixedEndian, SeedIsTheTask056Seed) {
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

// Where the width makes the two directions encode alike, the order is not a
// coordinate at all. Measured, then excluded from the dependence denominator
// by name rather than silently.
TEST(SolverBindingOverlapMixedEndian, OneByteFieldOrderIsIndistinguishable) {
    unsigned neutral_bindings = 0;
    unsigned intent_lost = 0;
    for (const Layout& layout : kMixedLayouts) {
        for (const Row& row : kRows) {
            const Cell cell =
                Measure(CellId(layout, row, 1U), layout, 1U, row.wide_bits, row.narrow_bits);
            ASSERT_EQ(cell.vars.size(), 2U) << cell.id;
            for (const VarFact& var : cell.vars) {
                if (var.order_indistinguishable) {
                    ++neutral_bindings;
                    EXPECT_FALSE(var.found_be) << cell.id << " w=" << unsigned{var.bit_width};
                    if (var.intended_be) {
                        ++intent_lost;
                    }
                }
            }
            std::cout << "ABI id=" << cell.id << " narrow_w=" << cell.narrow_bits
                      << " narrow_intended=" << Order(cell.narrow_be_intended)
                      << " narrow_found=" << Order(cell.vars[cell.narrow_var_index].found_be)
                      << " abi_forced=" << YesNo(cell.abi_forced) << "\n";
        }
    }
    std::cout << "ABI-SUMMARY neutral_bindings=" << neutral_bindings
              << " intent_lost=" << intent_lost << " expected_neutral=2 expected_intent_lost=1\n";
    EXPECT_EQ(neutral_bindings, 2U);
    EXPECT_EQ(intent_lost, 1U);
}

// The grid: eighteen cells, two mixed layouts by three width pairs by three
// shifts. One CELL line and two VAR lines per cell, then the SUMMARY line the
// report quotes.
TEST(SolverBindingOverlapMixedEndian, EighteenMixedEndianCells) {
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
    unsigned intended_found_bindings = 0;
    unsigned abi_forced_cells = 0;
    unsigned mixed_realized_cells = 0;
    unsigned mismatch_among_overlapping = 0;

    for (const Layout& layout : kMixedLayouts) {
        for (const Row& row : kRows) {
            for (const std::size_t shift : kShifts) {
                const Cell cell = Measure(CellId(layout, row, shift), layout, shift, row.wide_bits,
                                          row.narrow_bits);
                PrintCell("CELL", cell);
                ++cells;
                CheckCellShape(cell);

                // Every cell of the grid overlaps by construction: the wide
                // field starts at 0 and d < wide_len for all three rows.
                EXPECT_TRUE(cell.overlapping) << cell.id;
                EXPECT_EQ(cell.overlap_lo, shift) << cell.id;
                EXPECT_EQ(cell.overlap_hi,
                          std::min<std::size_t>(cell.wide_len, shift + cell.narrow_len))
                    << cell.id;

                if (cell.overlapping) {
                    ++overlapping;
                }
                if (cell.outcome == SolveOutcome::kCandidate) {
                    ++candidates;
                }
                if (cell.engine_equals_replay) {
                    ++replay_faithful;
                }
                if (cell.model_mismatch) {
                    ++mismatch_cells;
                    if (cell.overlapping) {
                        ++mismatch_among_overlapping;
                    }
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
                if (cell.outcome == SolveOutcome::kCandidate && cell.model_mismatch) {
                    ++silent;
                }
                for (const VarFact& var : cell.vars) {
                    if (var.intended_be == var.found_be) {
                        ++intended_found_bindings;
                    }
                }
                if (cell.abi_forced) {
                    ++abi_forced_cells;
                }
                if (cell.mixed_realized) {
                    ++mixed_realized_cells;
                }
            }
        }
    }

    std::cout << "SUMMARY cells=" << cells << " layouts=" << kMixedLayouts.size()
              << " overlapping_cells=" << overlapping << " candidates=" << candidates
              << " model_mismatch_cells=" << mismatch_cells
              << " mismatch_among_overlapping=" << mismatch_among_overlapping << "/" << overlapping
              << " mismatched_vars=" << mismatched_vars
              << " wide_mismatch_cells=" << wide_mismatches
              << " narrow_mismatch_cells=" << narrow_mismatches << " gate_taken=" << gate_taken
              << "/" << cells << " silent_mismatch_cells=" << silent
              << " silent_mismatch=" << YesNo(silent > 0U)
              << " intended_endian_found=" << intended_found_bindings << "/" << 2U * cells
              << " abi_forced_cells=" << abi_forced_cells
              << " mixed_realized_cells=" << mixed_realized_cells
              << " engine_equals_replay=" << replay_faithful << "/" << cells << "\n";

    EXPECT_EQ(cells, 18U);
    EXPECT_EQ(overlapping, 18U);
    EXPECT_EQ(candidates, 18U);
    EXPECT_EQ(replay_faithful, 18U);
    // Six cells carry a one-byte field (u32+u8 in both layouts); in three of
    // them the request was big-endian and the ABI overrode it.
    EXPECT_EQ(abi_forced_cells, 6U);
    EXPECT_EQ(intended_found_bindings, 33U);
}

// Control one: three cells of HOMOGENEOUS order that must reproduce the
// accepted numbers of task-056, byte for byte. The want_* constants below are
// task-056's own, quoted from its raw log.
TEST(SolverBindingOverlapMixedEndian, HomogeneousControlReproducesTask056) {
    struct Want {
        std::size_t shift;
        std::size_t overlap_bytes;
        std::uint64_t wide_reread;
        std::uint64_t narrow_model;
        unsigned mismatched_vars;
        bool gate;
    };
    // docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:106,110,114
    // (CONTROL053-CHECK) and :104-105,108-109,112-113 (VAR).
    constexpr std::array<Want, 3> kWant = {{
        {1U, 2U, 0x11543244ULL, 0x5432ULL, 1U, false},
        {2U, 2U, 0x76543344ULL, 0x7654ULL, 1U, false},
        {3U, 1U, 0x76223344ULL, 0x9876ULL, 1U, false},
    }};

    unsigned checked = 0;
    unsigned reproduced = 0;
    for (const Want& want : kWant) {
        const Cell cell =
            Measure(std::string("control-056/") + CellId(kHomLe, kRows[0], want.shift), kHomLe,
                    want.shift, kRows[0].wide_bits, kRows[0].narrow_bits);
        PrintCell("CONTROL056", cell);
        ++checked;
        CheckCellShape(cell);
        ASSERT_EQ(cell.vars.size(), 2U) << cell.id;

        const VarFact& wide = cell.vars[cell.wide_var_index];
        const VarFact& narrow = cell.vars[cell.narrow_var_index];
        const bool matches =
            cell.overlap_bytes == want.overlap_bytes && wide.reread_value == want.wide_reread &&
            narrow.model_value == want.narrow_model &&
            cell.mismatched_vars == want.mismatched_vars && cell.gate_on_candidate == want.gate;
        if (matches) {
            ++reproduced;
        }
        std::cout << "CONTROL056-CHECK id=" << cell.id
                  << " want_overlap_bytes=" << want.overlap_bytes
                  << " got_overlap_bytes=" << cell.overlap_bytes
                  << " want_wide_reread=" << Hex(want.wide_reread, 32U)
                  << " got_wide_reread=" << Hex(wide.reread_value, 32U)
                  << " want_narrow_model=" << Hex(want.narrow_model, 16U)
                  << " got_narrow_model=" << Hex(narrow.model_value, 16U)
                  << " want_mismatched_vars=" << want.mismatched_vars
                  << " got_mismatched_vars=" << cell.mismatched_vars
                  << " want_gate=" << YesNo(want.gate)
                  << " got_gate=" << YesNo(cell.gate_on_candidate) << " matches=" << YesNo(matches)
                  << "\n";
        EXPECT_TRUE(matches) << cell.id;
        // Homogeneous means homogeneous in the FOUND order too.
        EXPECT_FALSE(cell.mixed_realized) << cell.id;
        EXPECT_TRUE(cell.intended_endian_found) << cell.id;
    }
    std::cout << "CONTROL056-SUMMARY checked=" << checked << " reproduced=" << reproduced
              << " homogeneous_control_matches_task056="
              << YesNo(checked == reproduced && checked == 3U) << "\n";
    EXPECT_EQ(checked, 3U);
    EXPECT_EQ(reproduced, 3U);
}

// Control two: same mixed order, ranges pushed apart. If the model survives
// here, the mismatch above belongs to the overlap and not to the mixed order.
TEST(SolverBindingOverlapMixedEndian, ControlWithoutOverlapUnderMixedEndian) {
    unsigned checked = 0;
    unsigned matched = 0;
    const Cell cell =
        Measure(std::string("control-nooverlap/") + CellId(kMixLeBe, kRows[0], kControlShift),
                kMixLeBe, kControlShift, kRows[0].wide_bits, kRows[0].narrow_bits);
    PrintCell("CONTROL", cell);
    CheckCellShape(cell);
    ++checked;
    const bool ok = !cell.overlapping && cell.overlap_bytes == 0U && cell.mismatched_vars == 0U &&
                    !cell.model_mismatch && cell.gate_on_candidate;
    if (ok) {
        ++matched;
    }
    std::cout << "CONTROL-NOOVERLAP id=" << cell.id << " intended=" << Order(cell.wide_be_intended)
              << "+" << Order(cell.narrow_be_intended)
              << " mixed_realized=" << YesNo(cell.mixed_realized)
              << " overlap=" << YesNo(cell.overlapping) << " overlap_bytes=" << cell.overlap_bytes
              << " mismatched_vars=" << cell.mismatched_vars
              << " outcome=" << OutcomeName(cell.outcome)
              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate)
              << " control_no_overlap_matches_model=" << YesNo(ok) << "\n";
    EXPECT_EQ(checked, 1U);
    EXPECT_EQ(matched, 1U);
    EXPECT_TRUE(cell.mixed_realized) << cell.id;
}

// The verdict numbers. `mixed_endian_dependent` is defined BEFORE the run and
// stated in the report the same way: yes iff, among the cells where the mixed
// order is actually realized (both fields multi-byte, found order == intent),
// the count of model_mismatch cells differs from the count at the SAME
// coordinates (d, width pair) under homogeneous order. The homogeneous
// baseline is task-056's accepted `fwd-be` row,
// docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:46-52,64-70
// — six coordinates, all model_mismatch=yes, so the baseline is 12/12 over the
// twelve mixed cells that sit on them.
TEST(SolverBindingOverlapMixedEndian, MixedEndianDependenceAndSilentMismatch) {
    constexpr unsigned kHomogeneousMismatchAtSameCoordinates = 12U;

    unsigned realizable_cells = 0;
    unsigned realizable_mismatch = 0;
    unsigned abi_cells = 0;
    unsigned abi_mismatch = 0;
    unsigned silent_cells = 0;
    unsigned silent_with_gate = 0;
    unsigned candidate_without_flip = 0;

    for (const Layout& layout : kMixedLayouts) {
        for (const Row& row : kRows) {
            for (const std::size_t shift : kShifts) {
                const Cell cell = Measure(CellId(layout, row, shift), layout, shift, row.wide_bits,
                                          row.narrow_bits);
                if (cell.abi_forced) {
                    ++abi_cells;
                    if (cell.model_mismatch) {
                        ++abi_mismatch;
                    }
                    std::cout << "ABI-EXCLUDED id=" << cell.id << " narrow_w=" << cell.narrow_bits
                              << " reason=one_byte_field_order_indistinguishable"
                              << " intended=" << Order(cell.wide_be_intended) << "+"
                              << Order(cell.narrow_be_intended)
                              << " found=" << Order(cell.vars[cell.wide_var_index].found_be) << "+"
                              << Order(cell.vars[cell.narrow_var_index].found_be)
                              << " model_mismatch=" << YesNo(cell.model_mismatch) << "\n";
                } else {
                    ++realizable_cells;
                    if (cell.model_mismatch) {
                        ++realizable_mismatch;
                    }
                }
                if (cell.outcome == SolveOutcome::kCandidate && cell.model_mismatch) {
                    ++silent_cells;
                    std::cout << "SILENT id=" << cell.id << " outcome=" << OutcomeName(cell.outcome)
                              << " mismatched_vars=" << cell.mismatched_vars
                              << " wide_mismatch=" << YesNo(cell.wide_mismatch)
                              << " narrow_mismatch=" << YesNo(cell.narrow_mismatch)
                              << " gate_on_candidate=" << YesNo(cell.gate_on_candidate) << "\n";
                    if (cell.gate_on_candidate) {
                        ++silent_with_gate;
                    }
                }
                if (cell.outcome == SolveOutcome::kCandidate && !cell.gate_on_candidate) {
                    ++candidate_without_flip;
                }
            }
        }
    }

    const bool dependent = realizable_mismatch != kHomogeneousMismatchAtSameCoordinates;
    std::cout << "DEPEND-MIXED realizable_cells=" << realizable_cells
              << " realizable_mismatch=" << realizable_mismatch << "/" << realizable_cells
              << " homogeneous_baseline=" << kHomogeneousMismatchAtSameCoordinates << "/"
              << kHomogeneousMismatchAtSameCoordinates << " abi_forced_cells=" << abi_cells
              << " abi_forced_mismatch=" << abi_mismatch << "/" << abi_cells
              << " mixed_endian_dependent=" << YesNo(dependent) << "\n";
    std::cout << "SUMMARY-SILENT silent_cells=" << silent_cells << "/18"
              << " silent_with_gate_taken=" << silent_with_gate << "/" << silent_cells
              << " candidate_without_flip=" << candidate_without_flip << "/18"
              << " silent_mismatch=" << YesNo(silent_cells > 0U)
              << " mixed_endian_dependent=" << YesNo(dependent) << "\n";

    EXPECT_EQ(realizable_cells, 12U);
    EXPECT_EQ(abi_cells, 6U);
}
