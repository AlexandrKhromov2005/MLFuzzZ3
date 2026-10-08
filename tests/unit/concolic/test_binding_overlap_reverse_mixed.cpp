// task-065: REVERSE field order and MIXED byte order in one and the same
// system. A splice of two measurements that each moved one coordinate only.
//
// task-056 measured the reverse layout — the narrow field at offset 0, the
// wide field at offset d — with the byte order EQUAL for both fields
// (docs/experiments/solver-binding-overlap-order/report.md:412,
// raw-overlap-order.txt:19-27,73-97). task-060 measured opposite byte orders
// for the two fields with the WIDE field always at offset 0
// (docs/experiments/solver-binding-overlap-mixed-endian/raw-mixed-endian.txt:19-27,73).
// Neither touched the corner where both coordinates move at once, and the two
// are not independent by construction: fields are collected into a std::map
// keyed by byte offset (src/concolic/concolic.cpp:216-224), so the field that
// sits LOWER in the input is written back FIRST, while the direction of each
// write is taken from `var.big_endian` of that variable alone
// (src/concolic/concolic.cpp:310-315). Reversing the field order swaps who
// overwrites whom; mixing the byte order swaps WHICH digits of the loser land
// under the winner. This fixture measures that corner and nothing else.
//
// Grid: byte order in {mix-le-be, mix-be-le} x width pair in {u32+u16, u32+u8,
// u64+u32} x shift d in {1,2,3} = 18 cells, field order reverse in every one
// of them. Note that reverse order makes the shared range narrow_len - d
// rather than min(wide_len - d, narrow_len), so several cells of the grid do
// NOT overlap at all; the count is reported, never assumed.
//
// Controls: three homogeneous-order reverse cells that must reproduce
// task-056's accepted numbers, three forward-order mixed cells that must
// reproduce task-060's, and one reverse-mixed cell with the ranges pushed
// apart. Byte order is never asserted into existence: it is FOUND by
// BuildSystem from the seed encoding and read back off `System::vars`, so
// intended and found order are reported separately and a one-byte field, whose
// two encodings coincide, is named as such instead of being hidden.
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

// Every name below carries the RevMix suffix: all files of tests/unit/concolic
// link into one binary, and the two fixtures this one splices already own the
// unsuffixed names.

// fuzzer_rt_cmp_kind values used by this fixture (ADR 0033).
enum : std::uint8_t {
    kEqRevMix = 0,
    kNeRevMix = 1,
    kUltRevMix = 2,
    kUleRevMix = 3,
    kUgtRevMix = 4,
    kUgeRevMix = 5
};

constexpr unsigned kBitsPerByteRevMix = 8;
constexpr unsigned kTimeoutMsRevMix = 5000;
constexpr std::size_t kSeedSizeRevMix = 16;

// The seed of task-053/056/060, byte for byte
// (docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:9). The
// controls can only reproduce the accepted numbers if the input is identical,
// and the grid is only comparable to them for the same reason.
constexpr std::array<std::uint8_t, kSeedSizeRevMix> kSeedRevMix = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

// Target constants for the wide field, also from task-056. Their bytes are
// drawn from a range the seed does not use, so they are not findable and every
// byte an overwrite touches differs from the model's.
constexpr std::uint64_t kTarget32RevMix = 0x11223344ULL;
constexpr std::uint64_t kTarget64RevMix = 0x1122334455667788ULL;

std::vector<std::uint8_t> SeedRevMix() {
    return {kSeedRevMix.begin(), kSeedRevMix.end()};
}

std::uint64_t TruncateRevMix(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

std::uint64_t ReadSeedFieldRevMix(const std::vector<std::uint8_t>& bytes, std::size_t offset,
                                  unsigned n, bool big_endian) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift =
            big_endian ? (kBitsPerByteRevMix * (n - 1U - k)) : (kBitsPerByteRevMix * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

std::uint64_t ReadBindingRevMix(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    return ReadSeedFieldRevMix(bytes, var.offset, var.bit_width / kBitsPerByteRevMix,
                               var.big_endian);
}

// The orchestrator's own write-back, replayed (src/concolic/concolic.cpp:302-317):
// variables in `System::vars` order — that is, by ascending offset — each laid
// out in ITS OWN direction. Every cell checks this replay against the engine's
// candidate, so the mirror is verified rather than assumed.
std::vector<std::uint8_t> WriteBackModelRevMix(const std::vector<std::uint8_t>& seed,
                                               const System& sys,
                                               const std::vector<std::uint64_t>& model) {
    std::vector<std::uint8_t> bytes = seed;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const VarBinding& var = sys.vars[k];
        const unsigned n = var.bit_width / kBitsPerByteRevMix;
        const std::uint64_t value = TruncateRevMix(model[k], var.bit_width);
        for (unsigned b = 0; b < n; ++b) {
            const unsigned shift =
                var.big_endian ? (kBitsPerByteRevMix * (n - 1U - b)) : (kBitsPerByteRevMix * b);
            bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
        }
    }
    return bytes;
}

std::uint8_t NegateRevMix(std::uint8_t predicate) {
    switch (predicate) {
        case kEqRevMix:
            return kNeRevMix;
        case kNeRevMix:
            return kEqRevMix;
        case kUltRevMix:
            return kUgeRevMix;
        case kUleRevMix:
            return kUgtRevMix;
        case kUgtRevMix:
            return kUleRevMix;
        case kUgeRevMix:
            return kUltRevMix;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return predicate;
    }
}

bool EvalRevMix(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs, unsigned bit_width) {
    const std::uint64_t l = TruncateRevMix(lhs, bit_width);
    const std::uint64_t r = TruncateRevMix(rhs, bit_width);
    switch (predicate) {
        case kEqRevMix:
            return l == r;
        case kNeRevMix:
            return l != r;
        case kUltRevMix:
            return l < r;
        case kUleRevMix:
            return l <= r;
        case kUgtRevMix:
            return l > r;
        case kUgeRevMix:
            return l >= r;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return false;
    }
}

std::uint64_t OperandValueRevMix(const Operand& op, const System& sys,
                                 const std::vector<std::uint8_t>& bytes, unsigned bit_width) {
    switch (op.kind) {
        case Operand::Kind::kVar:
            return TruncateRevMix(ReadBindingRevMix(bytes, sys.vars[op.var_index]), bit_width);
        case Operand::Kind::kConst:
            return TruncateRevMix(op.const_value, bit_width);
        case Operand::Kind::kAddVars:
            return TruncateRevMix(
                TruncateRevMix(ReadBindingRevMix(bytes, sys.vars[op.var_index]), bit_width) +
                    TruncateRevMix(ReadBindingRevMix(bytes, sys.vars[op.var_index2]), bit_width),
                bit_width);
    }
    ADD_FAILURE() << "unknown operand kind";
    return 0;
}

std::string HexRevMix(std::uint64_t value, unsigned bit_width) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(static_cast<int>(2U * (bit_width / kBitsPerByteRevMix)))
        << TruncateRevMix(value, bit_width);
    return out.str();
}

const char* YesNoRevMix(bool value) {
    return value ? "yes" : "no";
}

const char* OrderRevMix(bool big_endian) {
    return big_endian ? "be" : "le";
}

const char* FieldOrderRevMix(bool reverse) {
    return reverse ? "reverse" : "forward";
}

const char* OutcomeNameRevMix(SolveOutcome outcome) {
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

const char* StatusNameRevMix(SolveResult::Status status) {
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

const char* PredicateLabelRevMix(std::uint8_t predicate) {
    switch (predicate) {
        case kEqRevMix:
            return "eq";
        case kNeRevMix:
            return "ne";
        case kUltRevMix:
            return "ult";
        case kUleRevMix:
            return "ule";
        case kUgtRevMix:
            return "ugt";
        case kUgeRevMix:
            return "uge";
        default:
            return "?";
    }
}

// Which value-bytes of `var` fall on the shared range [lo, hi): index 0 is the
// least significant byte of the VALUE, so the same physical byte carries a
// different index for the two opposite directions. Same format as task-056 and
// task-060.
std::string SharedValueBytesRevMix(const VarBinding& var, std::size_t lo, std::size_t hi) {
    const unsigned n = var.bit_width / kBitsPerByteRevMix;
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

// The same fact per physical byte: `offset:bLO-HI` says which BIT range of this
// value the byte at `offset` carries.
std::string SharedBitMapRevMix(const VarBinding& var, std::size_t lo, std::size_t hi) {
    const unsigned n = var.bit_width / kBitsPerByteRevMix;
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
        list += std::to_string(byte_offset) + ":b" + std::to_string(kBitsPerByteRevMix * index) +
                "-" + std::to_string(kBitsPerByteRevMix * index + kBitsPerByteRevMix - 1U);
    }
    return list.empty() ? std::string("-") : list;
}

struct RowRevMix {
    const char* name;
    unsigned wide_bits;
    unsigned narrow_bits;
};

// Field order and byte order are independent coordinates here: `reverse` puts
// the NARROW field at offset 0 and the wide one at offset d, `wide_be` and
// `narrow_be` request the direction of each field separately.
struct LayoutRevMix {
    const char* name;
    bool reverse;
    bool wide_be;
    bool narrow_be;
};

constexpr std::array<RowRevMix, 3> kRowsRevMix = {{
    {"u32+u16", 32U, 16U},
    {"u32+u8", 32U, 8U},
    {"u64+u32", 64U, 32U},
}};

constexpr std::array<std::size_t, 3> kShiftsRevMix = {1U, 2U, 3U};

// The two grid layouts: reverse field order, opposite byte orders.
constexpr LayoutRevMix kRevMixLeBe = {"rev-mix-le-be", true, false, true};
constexpr LayoutRevMix kRevMixBeLe = {"rev-mix-be-le", true, true, false};
constexpr std::array<LayoutRevMix, 2> kGridLayoutsRevMix = {{kRevMixLeBe, kRevMixBeLe}};

// Control layouts: one coordinate moved back at a time.
constexpr LayoutRevMix kRevHomLeRevMix = {"rev-hom-le", true, false, false};
constexpr LayoutRevMix kFwdMixLeBeRevMix = {"fwd-mix-le-be", false, false, true};

// d = 4 pushes the wide field past the end of the narrow one in the reverse
// layout, so the ranges do not meet. Same control shift as task-056/060.
constexpr std::size_t kControlShiftRevMix = 4U;

struct VarFactRevMix {
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

struct CellRevMix {
    std::string id;
    std::string layout;
    bool reverse = false;
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
    std::vector<VarFactRevMix> vars;
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

// Three records, exactly the shape of task-056 and task-060: two guards that
// pin the narrow field to its seed value and one equality on the wide field
// that becomes the inverted target. The only changes are WHERE each field sits
// and that the two are read in INDEPENDENT byte orders.
std::vector<BranchReader::Record> MakeRecordsRevMix(const LayoutRevMix& layout, std::size_t shift,
                                                    unsigned wide_bits, unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = SeedRevMix();
    const unsigned wide_len = wide_bits / kBitsPerByteRevMix;
    const unsigned narrow_len = narrow_bits / kBitsPerByteRevMix;
    const std::size_t wide_offset = layout.reverse ? shift : 0U;
    const std::size_t narrow_offset = layout.reverse ? 0U : shift;
    const std::uint64_t a =
        ReadSeedFieldRevMix(seed, wide_offset, wide_len, layout.wide_be && wide_len > 1U);
    const std::uint64_t b =
        ReadSeedFieldRevMix(seed, narrow_offset, narrow_len, layout.narrow_be && narrow_len > 1U);
    const std::uint64_t target = wide_bits == 64U ? kTarget64RevMix : kTarget32RevMix;
    return {
        {.site_id = 1,
         .predicate = kUgtRevMix,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b - 1U},
        {.site_id = 2,
         .predicate = kUltRevMix,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b + 1U},
        {.site_id = 3,
         .predicate = kEqRevMix,
         .bit_width = static_cast<std::uint8_t>(wide_bits),
         .lhs = a,
         .rhs = target},
    };
}

CellRevMix MeasureRevMix(const std::string& id, const LayoutRevMix& layout, std::size_t shift,
                         unsigned wide_bits, unsigned narrow_bits) {
    CellRevMix cell;
    cell.id = id;
    cell.layout = layout.name;
    cell.reverse = layout.reverse;
    cell.wide_be_intended = layout.wide_be;
    cell.narrow_be_intended = layout.narrow_be;
    cell.shift = shift;
    cell.wide_bits = wide_bits;
    cell.narrow_bits = narrow_bits;

    const std::vector<std::uint8_t> seed = SeedRevMix();
    const std::vector<BranchReader::Record> records =
        MakeRecordsRevMix(layout, shift, wide_bits, narrow_bits);
    const System sys = BuildSystem(seed, records);

    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;

    // sys.vars is ordered by ascending offset (src/concolic/concolic.cpp:216-224),
    // so the reverse layout puts the NARROW field first.
    cell.wide_var_index = layout.reverse ? 1U : 0U;
    cell.narrow_var_index = layout.reverse ? 0U : 1U;

    if (sys.vars.size() == 2U) {
        const VarBinding& wide = sys.vars[cell.wide_var_index];
        const VarBinding& narrow = sys.vars[cell.narrow_var_index];
        cell.wide_offset = wide.offset;
        cell.wide_len = wide.bit_width / kBitsPerByteRevMix;
        cell.narrow_offset = narrow.offset;
        cell.narrow_len = narrow.bit_width / kBitsPerByteRevMix;
        cell.overlap_lo = std::max(cell.wide_offset, cell.narrow_offset);
        cell.overlap_hi =
            std::min(cell.wide_offset + cell.wide_len, cell.narrow_offset + cell.narrow_len);
        cell.overlap_bytes =
            cell.overlap_hi > cell.overlap_lo ? cell.overlap_hi - cell.overlap_lo : 0U;
        cell.overlapping = cell.overlap_bytes > 0U;

        cell.bindings_as_intended = wide.offset == (layout.reverse ? shift : 0U) &&
                                    narrow.offset == (layout.reverse ? 0U : shift) &&
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
    cell.inverted_predicate = NegateRevMix(cell.path_predicate);
    const unsigned target_width = sys.path[sys.target_index].bit_width;
    cell.astaken_holds_on_seed = EvalRevMix(
        cell.path_predicate,
        OperandValueRevMix(sys.path[sys.target_index].lhs, sys, seed, target_width),
        OperandValueRevMix(sys.path[sys.target_index].rhs, sys, seed, target_width), target_width);

    const SolveResult result =
        SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMsRevMix);
    cell.status = result.status;
    if (result.status != SolveResult::Status::kSat || result.model_values.size() != sys.num_vars) {
        return cell;
    }

    const std::vector<std::uint8_t> candidate =
        WriteBackModelRevMix(seed, sys, result.model_values);
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const VarBinding& var = sys.vars[k];
        const std::uint64_t model = TruncateRevMix(result.model_values[k], var.bit_width);
        const std::uint64_t reread = ReadBindingRevMix(candidate, var);
        const bool intended = k == cell.wide_var_index ? layout.wide_be : layout.narrow_be;
        cell.vars.push_back(
            {.offset = var.offset,
             .bit_width = var.bit_width,
             .intended_be = intended,
             .found_be = var.big_endian,
             .order_indistinguishable = var.bit_width == kBitsPerByteRevMix,
             .model_value = model,
             .reread_value = reread,
             .matches = model == reread,
             .shared_value_bytes = SharedValueBytesRevMix(var, cell.overlap_lo, cell.overlap_hi),
             .shared_bits = SharedBitMapRevMix(var, cell.overlap_lo, cell.overlap_hi)});
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

    cell.gate_on_candidate =
        EvalRevMix(cell.inverted_predicate,
                   OperandValueRevMix(sys.path[sys.target_index].lhs, sys, candidate, target_width),
                   OperandValueRevMix(sys.path[sys.target_index].rhs, sys, candidate, target_width),
                   target_width);

    // The engine's own path over the same seed and records.
    SolveOutcome outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> engine =
        SolveForCandidate(seed, records, kTimeoutMsRevMix, &outcome);
    cell.outcome = outcome;
    cell.has_candidate = engine.has_value();
    if (engine.has_value()) {
        const std::vector<std::uint8_t> engine_bytes(engine->data(),
                                                     engine->data() + engine->size());
        cell.engine_equals_replay = engine_bytes == candidate;
    }
    return cell;
}

std::string CellIdRevMix(const LayoutRevMix& layout, const RowRevMix& row, std::size_t shift) {
    return std::string(layout.name) + "/" + row.name + "/d=" + std::to_string(shift);
}

void PrintCellRevMix(const char* tag, const CellRevMix& cell) {
    std::cout << tag << " id=" << cell.id << " layout=" << cell.layout
              << " field_order=" << FieldOrderRevMix(cell.reverse)
              << " intended=" << OrderRevMix(cell.wide_be_intended) << "+"
              << OrderRevMix(cell.narrow_be_intended) << " d=" << cell.shift
              << " widths=" << cell.wide_bits << "+" << cell.narrow_bits << " wide=["
              << cell.wide_offset << "," << cell.wide_offset + cell.wide_len << ") narrow=["
              << cell.narrow_offset << "," << cell.narrow_offset + cell.narrow_len
              << ") overlap=" << YesNoRevMix(cell.overlapping) << " overlap_range=["
              << cell.overlap_lo << "," << (cell.overlapping ? cell.overlap_hi : cell.overlap_lo)
              << ") overlap_bytes=" << cell.overlap_bytes
              << " bindings_as_intended=" << YesNoRevMix(cell.bindings_as_intended)
              << " intended_endian_found=" << YesNoRevMix(cell.intended_endian_found)
              << " abi_forced=" << YesNoRevMix(cell.abi_forced)
              << " mixed_realized=" << YesNoRevMix(cell.mixed_realized)
              << " wide_var=" << cell.wide_var_index << " narrow_var=" << cell.narrow_var_index
              << " num_vars=" << cell.num_vars << " path=" << cell.path_size
              << " target=" << cell.target_index << " status=" << StatusNameRevMix(cell.status)
              << " path_pred=" << PredicateLabelRevMix(cell.path_predicate)
              << " inverted_pred=" << PredicateLabelRevMix(cell.inverted_predicate)
              << " astaken_on_seed=" << YesNoRevMix(cell.astaken_holds_on_seed)
              << " outcome=" << OutcomeNameRevMix(cell.outcome)
              << " has_candidate=" << YesNoRevMix(cell.has_candidate)
              << " engine_equals_replay=" << YesNoRevMix(cell.engine_equals_replay)
              << " mismatched_vars=" << cell.mismatched_vars
              << " model_mismatch=" << YesNoRevMix(cell.model_mismatch)
              << " wide_mismatch=" << YesNoRevMix(cell.wide_mismatch)
              << " narrow_mismatch=" << YesNoRevMix(cell.narrow_mismatch)
              << " gate_on_candidate=" << YesNoRevMix(cell.gate_on_candidate) << "\n";
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        const VarFactRevMix& var = cell.vars[k];
        std::cout << "VAR id=" << cell.id << " k=" << k << " off=" << var.offset
                  << " w=" << unsigned{var.bit_width}
                  << " intended=" << OrderRevMix(var.intended_be)
                  << " found=" << OrderRevMix(var.found_be)
                  << " order_indistinguishable=" << YesNoRevMix(var.order_indistinguishable)
                  << " role=" << (k == cell.wide_var_index ? "wide" : "narrow")
                  << " model=" << HexRevMix(var.model_value, var.bit_width)
                  << " reread=" << HexRevMix(var.reread_value, var.bit_width)
                  << " shared_value_bytes=" << var.shared_value_bytes
                  << " shared_bits=" << var.shared_bits << " match=" << YesNoRevMix(var.matches)
                  << "\n";
    }
}

// Common per-cell invariants: the cell must measure what it claims before any
// number it produces is worth reading.
void CheckCellShapeRevMix(const CellRevMix& cell) {
    EXPECT_EQ(cell.num_vars, 2U) << cell.id;
    EXPECT_EQ(cell.vars.size(), 2U) << cell.id;
    EXPECT_TRUE(cell.bindings_as_intended) << cell.id;
    EXPECT_EQ(cell.path_size, 3U) << cell.id;
    EXPECT_EQ(cell.target_index, 2U) << cell.id;
    EXPECT_TRUE(cell.astaken_holds_on_seed) << cell.id;
    EXPECT_EQ(cell.status, SolveResult::Status::kSat) << cell.id;
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate) << cell.id;
    EXPECT_TRUE(cell.has_candidate) << cell.id;
    EXPECT_TRUE(cell.engine_equals_replay) << cell.id;
    EXPECT_EQ(cell.path_predicate, kNeRevMix) << cell.id;
    EXPECT_EQ(cell.inverted_predicate, kEqRevMix) << cell.id;
}

// One expected cell of an earlier task, transcribed so the control is checked
// by the machine and not by the eye.
struct WantRevMix {
    std::size_t shift;
    std::size_t overlap_bytes;
    std::uint64_t wide_reread;
    std::uint64_t narrow_model;
    std::uint64_t narrow_reread;
    unsigned mismatched_vars;
    bool gate;
};

// task-056, reverse layout with HOMOGENEOUS little-endian order, width pair
// u32+u16 (docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:19-27).
constexpr std::array<WantRevMix, 3> kTask056ReverseRow = {{
    {1U, 1U, 0x11223344ULL, 0x3210ULL, 0x4410ULL, 1U, true},
    {2U, 0U, 0x11223344ULL, 0x3210ULL, 0x3210ULL, 0U, true},
    {3U, 0U, 0x11223344ULL, 0x3210ULL, 0x3210ULL, 0U, true},
}};

// task-060, FORWARD layout with mixed order le+be, width pair u32+u16
// (docs/experiments/solver-binding-overlap-mixed-endian/raw-mixed-endian.txt:19-27).
constexpr std::array<WantRevMix, 3> kTask060ForwardRow = {{
    {1U, 2U, 0x11543244ULL, 0x3254ULL, 0x3254ULL, 1U, false},
    {2U, 2U, 0x76543344ULL, 0x5476ULL, 0x5476ULL, 1U, false},
    {3U, 1U, 0x76223344ULL, 0x7698ULL, 0x7698ULL, 1U, false},
}};

bool MatchesWantRevMix(const CellRevMix& cell, const WantRevMix& want) {
    if (cell.vars.size() != 2U) {
        return false;
    }
    const VarFactRevMix& wide = cell.vars[cell.wide_var_index];
    const VarFactRevMix& narrow = cell.vars[cell.narrow_var_index];
    return cell.shift == want.shift && cell.overlap_bytes == want.overlap_bytes &&
           cell.num_vars == 2U && cell.outcome == SolveOutcome::kCandidate &&
           wide.reread_value == want.wide_reread && narrow.model_value == want.narrow_model &&
           narrow.reread_value == want.narrow_reread &&
           cell.mismatched_vars == want.mismatched_vars && cell.gate_on_candidate == want.gate;
}

// Runs one three-cell control row and returns how many cells reproduced their
// reference numbers. `verbose` prints the raw the report quotes; the verdict
// test re-runs the same rows silently.
unsigned ReproducedRowRevMix(const char* tag, const LayoutRevMix& layout,
                             const std::array<WantRevMix, 3>& wants, bool verbose) {
    unsigned reproduced = 0;
    for (const WantRevMix& want : wants) {
        const CellRevMix cell =
            MeasureRevMix(std::string(tag) + "/" + CellIdRevMix(layout, kRowsRevMix[0], want.shift),
                          layout, want.shift, kRowsRevMix[0].wide_bits, kRowsRevMix[0].narrow_bits);
        const bool matches = MatchesWantRevMix(cell, want);
        if (matches) {
            ++reproduced;
        }
        if (verbose) {
            PrintCellRevMix(tag, cell);
            CheckCellShapeRevMix(cell);
            std::cout << tag << "-CHECK id=" << cell.id
                      << " want_overlap_bytes=" << want.overlap_bytes
                      << " got_overlap_bytes=" << cell.overlap_bytes
                      << " want_wide_reread=" << HexRevMix(want.wide_reread, cell.wide_bits)
                      << " got_wide_reread="
                      << HexRevMix(
                             cell.vars.empty() ? 0U : cell.vars[cell.wide_var_index].reread_value,
                             cell.wide_bits)
                      << " want_narrow_model=" << HexRevMix(want.narrow_model, cell.narrow_bits)
                      << " got_narrow_model="
                      << HexRevMix(
                             cell.vars.empty() ? 0U : cell.vars[cell.narrow_var_index].model_value,
                             cell.narrow_bits)
                      << " want_mismatched_vars=" << want.mismatched_vars
                      << " got_mismatched_vars=" << cell.mismatched_vars
                      << " want_gate=" << YesNoRevMix(want.gate)
                      << " got_gate=" << YesNoRevMix(cell.gate_on_candidate)
                      << " matches=" << YesNoRevMix(matches) << "\n";
            EXPECT_TRUE(matches) << cell.id;
        }
    }
    return reproduced;
}

// The disjoint-range control in the grid's own layout: same mixed order, same
// reverse field order, ranges pushed apart. If the model survives here, the
// mismatches of the grid belong to the overlap and not to the corner itself.
bool NoOverlapControlHoldsRevMix(bool verbose) {
    const CellRevMix cell = MeasureRevMix(
        std::string("control-nooverlap/") +
            CellIdRevMix(kRevMixLeBe, kRowsRevMix[0], kControlShiftRevMix),
        kRevMixLeBe, kControlShiftRevMix, kRowsRevMix[0].wide_bits, kRowsRevMix[0].narrow_bits);
    const bool ok = !cell.overlapping && cell.overlap_bytes == 0U && cell.mismatched_vars == 0U &&
                    !cell.model_mismatch && cell.gate_on_candidate &&
                    cell.outcome == SolveOutcome::kCandidate;
    if (verbose) {
        PrintCellRevMix("CONTROL", cell);
        CheckCellShapeRevMix(cell);
        std::cout << "CONTROL-NOOVERLAP id=" << cell.id
                  << " field_order=" << FieldOrderRevMix(cell.reverse)
                  << " intended=" << OrderRevMix(cell.wide_be_intended) << "+"
                  << OrderRevMix(cell.narrow_be_intended)
                  << " mixed_realized=" << YesNoRevMix(cell.mixed_realized)
                  << " overlap=" << YesNoRevMix(cell.overlapping)
                  << " overlap_bytes=" << cell.overlap_bytes
                  << " mismatched_vars=" << cell.mismatched_vars
                  << " outcome=" << OutcomeNameRevMix(cell.outcome)
                  << " gate_on_candidate=" << YesNoRevMix(cell.gate_on_candidate)
                  << " control_no_overlap_matches_model=" << YesNoRevMix(ok) << "\n";
        EXPECT_TRUE(cell.mixed_realized) << cell.id;
    }
    return ok;
}

// Everything the eighteen cells produce, in one pass.
struct GridStatsRevMix {
    unsigned cells = 0;
    unsigned overlapping = 0;
    unsigned candidates = 0;
    unsigned mismatch_cells = 0;
    unsigned mismatched_vars = 0;
    unsigned gate_taken = 0;
    unsigned silent = 0;
    unsigned silent_with_gate = 0;
    unsigned candidate_without_flip = 0;
    unsigned replay_faithful = 0;
    unsigned wide_mismatches = 0;
    unsigned narrow_mismatches = 0;
    unsigned intended_found_bindings = 0;
    unsigned abi_forced_cells = 0;
    unsigned abi_forced_mismatch = 0;
    unsigned mixed_realized_cells = 0;
    unsigned mismatch_among_overlapping = 0;
    unsigned realizable_cells = 0;
    unsigned realizable_mismatch = 0;
    unsigned reverse_cells = 0;
};

GridStatsRevMix RunGridRevMix(bool verbose) {
    GridStatsRevMix s;
    for (const LayoutRevMix& layout : kGridLayoutsRevMix) {
        for (const RowRevMix& row : kRowsRevMix) {
            for (const std::size_t shift : kShiftsRevMix) {
                const CellRevMix cell = MeasureRevMix(CellIdRevMix(layout, row, shift), layout,
                                                      shift, row.wide_bits, row.narrow_bits);
                ++s.cells;
                if (verbose) {
                    PrintCellRevMix("CELL", cell);
                    CheckCellShapeRevMix(cell);

                    // Range arithmetic, asserted rather than trusted: with the
                    // narrow field first the shared part is narrow_len - d and
                    // vanishes as soon as d reaches narrow_len.
                    const std::size_t narrow_len = cell.narrow_bits / kBitsPerByteRevMix;
                    const std::size_t predicted = narrow_len > shift ? narrow_len - shift : 0U;
                    EXPECT_EQ(cell.overlap_bytes, predicted) << cell.id;
                }
                if (cell.reverse) {
                    ++s.reverse_cells;
                }
                if (cell.overlapping) {
                    ++s.overlapping;
                    if (cell.model_mismatch) {
                        ++s.mismatch_among_overlapping;
                    }
                }
                if (cell.outcome == SolveOutcome::kCandidate) {
                    ++s.candidates;
                }
                if (cell.engine_equals_replay) {
                    ++s.replay_faithful;
                }
                if (cell.model_mismatch) {
                    ++s.mismatch_cells;
                }
                s.mismatched_vars += cell.mismatched_vars;
                if (cell.wide_mismatch) {
                    ++s.wide_mismatches;
                }
                if (cell.narrow_mismatch) {
                    ++s.narrow_mismatches;
                }
                if (cell.gate_on_candidate) {
                    ++s.gate_taken;
                }
                if (cell.outcome == SolveOutcome::kCandidate && cell.model_mismatch) {
                    ++s.silent;
                    if (cell.gate_on_candidate) {
                        ++s.silent_with_gate;
                    }
                    if (verbose) {
                        std::cout << "SILENT id=" << cell.id
                                  << " outcome=" << OutcomeNameRevMix(cell.outcome)
                                  << " mismatched_vars=" << cell.mismatched_vars
                                  << " wide_mismatch=" << YesNoRevMix(cell.wide_mismatch)
                                  << " narrow_mismatch=" << YesNoRevMix(cell.narrow_mismatch)
                                  << " gate_on_candidate=" << YesNoRevMix(cell.gate_on_candidate)
                                  << "\n";
                    }
                }
                if (cell.outcome == SolveOutcome::kCandidate && !cell.gate_on_candidate) {
                    ++s.candidate_without_flip;
                }
                for (const VarFactRevMix& var : cell.vars) {
                    if (var.intended_be == var.found_be) {
                        ++s.intended_found_bindings;
                    }
                }
                if (cell.abi_forced) {
                    ++s.abi_forced_cells;
                    if (cell.model_mismatch) {
                        ++s.abi_forced_mismatch;
                    }
                } else {
                    ++s.realizable_cells;
                    if (cell.model_mismatch) {
                        ++s.realizable_mismatch;
                    }
                }
                if (cell.mixed_realized) {
                    ++s.mixed_realized_cells;
                }
            }
        }
    }
    return s;
}

}  // namespace

// The fixture is only comparable to task-056 and task-060 if the input is the
// same input (raw-overlap-order.txt:9). Sixteen pairwise distinct bytes, none
// adjacent in value to another, so every field pattern occurs exactly once and
// the guard constants b-1 and b+1 are absent from the input.
TEST(SolverBindingOverlapReverseMixed, SeedIsTheTask056Seed) {
    const std::vector<std::uint8_t> seed = SeedRevMix();
    ASSERT_EQ(seed.size(), kSeedSizeRevMix);
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
        std::cout << HexRevMix(byte, 8U) << ",";
    }
    std::cout << " target32=" << HexRevMix(kTarget32RevMix, 32U)
              << " target64=" << HexRevMix(kTarget64RevMix, 64U) << "\n";
}

// The grid: eighteen cells, two mixed byte orders by three width pairs by
// three shifts, reverse field order in every one. One CELL line and two VAR
// lines per cell, then the SUMMARY line the report quotes.
TEST(SolverBindingOverlapReverseMixed, EighteenReverseMixedCells) {
    const GridStatsRevMix s = RunGridRevMix(true);

    std::cout << "SUMMARY cells=" << s.cells << " field_order=reverse"
              << " endians=" << kGridLayoutsRevMix.size() << " width_pairs=" << kRowsRevMix.size()
              << " shifts=" << kShiftsRevMix.size() << " overlapping_cells=" << s.overlapping
              << " candidates=" << s.candidates << " model_mismatch_cells=" << s.mismatch_cells
              << " mismatch_among_overlapping=" << s.mismatch_among_overlapping << "/"
              << s.overlapping << " mismatched_vars=" << s.mismatched_vars
              << " wide_mismatch_cells=" << s.wide_mismatches
              << " narrow_mismatch_cells=" << s.narrow_mismatches << " gate_taken=" << s.gate_taken
              << "/" << s.cells << " silent_mismatch_cells=" << s.silent
              << " silent_mismatch=" << YesNoRevMix(s.silent > 0U)
              << " intended_endian_found=" << s.intended_found_bindings << "/" << 2U * s.cells
              << " abi_forced_cells=" << s.abi_forced_cells
              << " mixed_realized_cells=" << s.mixed_realized_cells
              << " engine_equals_replay=" << s.replay_faithful << "/" << s.cells << "\n";

    EXPECT_EQ(s.cells, 18U);
    EXPECT_EQ(s.reverse_cells, 18U);
    EXPECT_EQ(s.candidates, 18U);
    EXPECT_EQ(s.replay_faithful, 18U);
    // Six cells carry a one-byte field (u32+u8 in both layouts); in three of
    // them the request was big-endian and the ABI overrode it.
    EXPECT_EQ(s.abi_forced_cells, 6U);
}

// Control one: the byte order moved back to homogeneous, the reverse field
// order kept. Must reproduce task-056's accepted numbers cell for cell; if it
// drifts, this grid measures a different pipeline.
TEST(SolverBindingOverlapReverseMixed, HomogeneousOrderControlMatchesTask056) {
    const unsigned reproduced =
        ReproducedRowRevMix("CONTROL056", kRevHomLeRevMix, kTask056ReverseRow, true);
    std::cout << "CONTROL056-SUMMARY checked=3 reproduced=" << reproduced
              << " control_order_matches_task056=" << YesNoRevMix(reproduced == 3U) << "\n";
    EXPECT_EQ(reproduced, 3U);
}

// Control two: the field order moved back to forward, the mixed byte order
// kept. Must reproduce task-060's accepted numbers cell for cell.
TEST(SolverBindingOverlapReverseMixed, ForwardOrderControlMatchesTask060) {
    const unsigned reproduced =
        ReproducedRowRevMix("CONTROL060", kFwdMixLeBeRevMix, kTask060ForwardRow, true);
    std::cout << "CONTROL060-SUMMARY checked=3 reproduced=" << reproduced
              << " control_mixed_matches_task060=" << YesNoRevMix(reproduced == 3U) << "\n";
    EXPECT_EQ(reproduced, 3U);
}

// Control three: the grid's own corner with the ranges pushed apart.
TEST(SolverBindingOverlapReverseMixed, ControlWithoutOverlapUnderReverseMixed) {
    const bool ok = NoOverlapControlHoldsRevMix(true);
    EXPECT_TRUE(ok);
}

// The verdict numbers. `reverse_mixed_dependent` is defined BEFORE the run and
// stated in the report the same way: yes iff, among the cells where the mixed
// order is realizable at all (both fields multi-byte, so neither is forced by
// the ABI), the count of model_mismatch cells differs from the count at the
// SAME coordinates (field order reverse, same width pair, same d) under
// HOMOGENEOUS byte order. That baseline is task-056's accepted rev-le and
// rev-be rows over the twelve matching coordinates —
// docs/experiments/solver-binding-overlap-order/raw-overlap-order.txt:19,22,25
// and :37,40,43 (rev-le) plus :73,76,79 and :91,94,97 (rev-be) — where
// model_mismatch=yes stands on eight of the twelve.
TEST(SolverBindingOverlapReverseMixed, ReverseMixedDependenceAndVerdict) {
    constexpr unsigned kHomogeneousReverseMismatchAtSameCoordinates = 8U;

    const GridStatsRevMix s = RunGridRevMix(false);
    const unsigned reproduced056 =
        ReproducedRowRevMix("VERDICT056", kRevHomLeRevMix, kTask056ReverseRow, false);
    const unsigned reproduced060 =
        ReproducedRowRevMix("VERDICT060", kFwdMixLeBeRevMix, kTask060ForwardRow, false);
    const bool control_no_overlap = NoOverlapControlHoldsRevMix(false);

    const bool dependent = s.realizable_mismatch != kHomogeneousReverseMismatchAtSameCoordinates;

    std::cout << "DEPEND-REVERSE-MIXED realizable_cells=" << s.realizable_cells
              << " realizable_mismatch=" << s.realizable_mismatch << "/" << s.realizable_cells
              << " homogeneous_reverse_baseline=" << kHomogeneousReverseMismatchAtSameCoordinates
              << "/12 abi_forced_cells=" << s.abi_forced_cells
              << " abi_forced_mismatch=" << s.abi_forced_mismatch << "/" << s.abi_forced_cells
              << " reverse_mixed_dependent=" << YesNoRevMix(dependent) << "\n";
    std::cout << "SUMMARY-SILENT silent_cells=" << s.silent << "/18"
              << " silent_with_gate_taken=" << s.silent_with_gate << "/" << s.silent
              << " candidate_without_flip=" << s.candidate_without_flip << "/18"
              << " silent_mismatch=" << YesNoRevMix(s.silent > 0U)
              << " reverse_mixed_dependent=" << YesNoRevMix(dependent) << "\n";

    EXPECT_EQ(s.cells, 18U);
    EXPECT_EQ(s.realizable_cells, 12U);
    EXPECT_EQ(s.abi_forced_cells, 6U);

    std::cout << "VERDICT: BINDING-OVERLAP-REVERSE-MIXED: cells=" << s.cells
              << ", field_order=reverse, endians=" << kGridLayoutsRevMix.size()
              << ", width_pairs=" << kRowsRevMix.size() << ", shifts=" << kShiftsRevMix.size()
              << ", overlapping_cells=" << s.overlapping << ", candidates=" << s.candidates
              << ", model_mismatch_cells=" << s.mismatch_cells
              << ", mismatched_vars=" << s.mismatched_vars << ", gate_taken=" << s.gate_taken
              << "/18, silent_mismatch=" << YesNoRevMix(s.silent > 0U)
              << ", intended_endian_found=" << s.intended_found_bindings << "/" << 2U * s.cells
              << ", abi_forced_cells=" << s.abi_forced_cells
              << ", reverse_mixed_dependent=" << YesNoRevMix(dependent)
              << ", control_order_matches_task056=" << YesNoRevMix(reproduced056 == 3U)
              << ", control_mixed_matches_task060=" << YesNoRevMix(reproduced060 == 3U)
              << ", control_no_overlap_matches_model=" << YesNoRevMix(control_no_overlap)
              << ", matrix_cells_filled=18/18, matrix_recomputed=no, src_modified=0"
              << ", new_fuzzing_runs=0, reports_modified=0\n";
}
