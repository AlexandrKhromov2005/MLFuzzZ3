#include <gtest/gtest.h>

#include <cstdint>
#include <iostream>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Mixed widths on ONE offset (task-029, ADR 0035 §2). This file MEASURES
// what the existing reconstruction in src/concolic does when two records
// of the same trace resolve to the SAME byte offset with DIFFERENT
// widths (or different byte order). It adds no rules and changes no
// policy: the width-selection policy is the encoding of ADR-0035 and the
// owner's call.
//
// The mechanism under measurement. Pass 1 of BuildSystem accumulates
// fields as `fields.try_emplace(m->offset, VarBinding{...})`
// (src/concolic/concolic.cpp:218-221) into a `std::map` KEYED ON OFFSET
// ALONE. `try_emplace` does not overwrite, so the record that comes
// FIRST in the trace fixes `bit_width` and `big_endian` for that offset
// forever. A later record of another width lands on the same offset,
// finds it in `offset_to_index`, and BindOperand (:188-192) hands back
// `MakeVar` on the SAME variable — so a constraint of width W2 is
// attached to a variable whose byte binding says W1. Z3 then sizes that
// variable as max(W1, W2) (src/solver/solver_facade.cpp:69-78), but the
// write-back in SolveForCandidate (:303-317) emits only
// `var.bit_width / 8` bytes — the FIRST record's width.
//
// Method. One seed, one shared offset 0, exactly two records per cell:
//   rec1 = `field(W1) <u HIGH`  — TRUE on the seed. It is what DISCOVERS
//          the offset, so it is what fixes the binding.
//   rec2 = `field(W2) == MAGIC` — FALSE on the seed, hence the last
//          entry of the path and the target SolveForCandidate inverts.
// The target being an EQUALITY is deliberate: it pins the model to a
// single value, so every cell below is a determinate measurement and not
// a hostage to which model Z3 happens to return.
//
// Per cell we record num_vars, the whole VarBinding, the Operand::Kind
// of BOTH sides of BOTH records, SolveOutcome, the byte-level diff of
// the candidate against the seed, and — the end-to-end check that no
// counter inside the solver can fake — whether BOTH records' predicates
// actually come out right when the fields are re-read from the candidate
// AT THEIR REAL POSITIONS AND REAL WIDTHS: rec1 must still hold, rec2
// must now be satisfied (that is what the inversion asked for).

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUlt = 2 };

constexpr unsigned kTimeoutMs = 5000;
constexpr std::size_t kSharedOffset = 0;

// Eight bytes, all DISTINCT and none of them 0x00, 0x2A or 0x80. The
// distinctness keeps every value used below findable at exactly one
// offset; the three excluded byte values are what the guard and magic
// constants are built from, so no constant is ever accidentally findable
// and no cell grows a second variable behind our back.
constexpr std::uint8_t kSeedBytes[] = {0x44, 0x33, 0x22, 0x11, 0x99, 0xAA, 0xBB, 0xCC};

// The one field, read off kSharedOffset at three widths and two byte
// orders. These are the values the runtime would log.
constexpr std::uint64_t kFieldU32Le = 0x11223344U;
constexpr std::uint64_t kFieldU32Be = 0x44332211U;
constexpr std::uint64_t kFieldU16Le = 0x3344U;
constexpr std::uint64_t kFieldU8 = 0x44U;

// Guard bound for rec1, per width. Above every reading of the field, so
// `field <u HIGH` is TRUE on the seed; built from 0x80 bytes, so absent
// from the seed at every width and in both byte orders.
constexpr std::uint64_t kHigh32 = 0x80808080U;
constexpr std::uint64_t kHigh16 = 0x8080U;
constexpr std::uint64_t kHigh8 = 0x80U;

// rec2's magic. Absent from the seed at every width (bytes 0x2A / 0x00),
// not equal to the field at any width, and not twice any field reading —
// so it never binds, neither as kVar nor as kAddVars.
constexpr std::uint64_t kMagic = 0x2AU;

std::vector<std::uint8_t> Seed() {
    return {std::begin(kSeedBytes), std::end(kSeedBytes)};
}

// Where a record's operand REALLY lives in the input — ground truth we
// state here, independent of anything BuildSystem infers. The end-to-end
// check below reads through this, not through sys.vars.
struct Field {
    std::size_t offset;
    unsigned bit_width;
    bool big_endian;
};

std::uint64_t Truncate(std::uint64_t value, unsigned bit_width) {
    return bit_width >= 64U ? value : (value & ((std::uint64_t{1} << bit_width) - 1U));
}

std::uint64_t ReadAt(const std::vector<std::uint8_t>& bytes, const Field& field) {
    const unsigned n = field.bit_width / 8U;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = field.big_endian ? (8U * (n - 1U - k)) : (8U * k);
        value |= static_cast<std::uint64_t>(bytes[field.offset + k]) << shift;
    }
    return value;
}

// One measured cell.
struct Cell {
    std::size_t num_vars = 0;
    // The single VarBinding, verbatim (offset / bit_width / big_endian).
    std::size_t var_offset = 0;
    unsigned var_bit_width = 0;
    bool var_big_endian = false;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    // Operand::Kind of both sides of both records, in trace order.
    Operand::Kind first_lhs = Operand::Kind::kConst;
    Operand::Kind first_rhs = Operand::Kind::kConst;
    Operand::Kind second_lhs = Operand::Kind::kConst;
    Operand::Kind second_rhs = Operand::Kind::kConst;
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    // Byte-level diff of the candidate against the seed.
    std::size_t diff_bytes = 0;
    std::size_t diff_lowest = 0;
    std::size_t diff_highest = 0;
    // End-to-end, read at the REAL positions and widths of both records.
    bool first_holds = false;     ///< rec1 `field(W1) <u HIGH` still true?
    bool second_flipped = false;  ///< rec2 `field(W2) == MAGIC` now true?
};

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
        case SolveOutcome::kError:
        default:
            return "kError";
    }
}

const char* KindName(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kAddVars:
            return "kAddVars";
        case Operand::Kind::kConst:
        default:
            return "kConst";
    }
}

// Build the two-record trace of a cell. `first` discovers the offset;
// `second` collides with it at another width or byte order.
std::vector<BranchReader::Record> Trace(std::uint64_t first_value, unsigned first_width,
                                        std::uint64_t high, std::uint64_t second_value,
                                        unsigned second_width) {
    return {
        {0, kUlt, static_cast<std::uint8_t>(first_width), first_value, high},
        {1, kEq, static_cast<std::uint8_t>(second_width), second_value, kMagic},
    };
}

Cell Measure(const char* id, const std::vector<BranchReader::Record>& records,
             const Field& first_field, const Field& second_field) {
    const std::vector<std::uint8_t> seed = Seed();
    const System sys = BuildSystem(seed, records);

    Cell cell;
    cell.num_vars = sys.num_vars;
    if (sys.num_vars == 1) {
        cell.var_offset = sys.vars[0].offset;
        cell.var_bit_width = sys.vars[0].bit_width;
        cell.var_big_endian = sys.vars[0].big_endian;
    } else {
        ADD_FAILURE() << "cell " << id << ": expected exactly one variable, got " << sys.num_vars
                      << " — the fixture is measuring something other than one shared offset";
    }
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;
    if (sys.path.size() == 2) {
        cell.first_lhs = sys.path[0].lhs.kind;
        cell.first_rhs = sys.path[0].rhs.kind;
        cell.second_lhs = sys.path[1].lhs.kind;
        cell.second_rhs = sys.path[1].rhs.kind;
    } else {
        ADD_FAILURE() << "cell " << id << ": expected both records to survive, path is "
                      << sys.path.size();
    }

    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    if (cell.has_candidate) {
        const std::vector<std::uint8_t> bytes(candidate->data(),
                                              candidate->data() + candidate->size());
        if (bytes.size() != seed.size()) {
            ADD_FAILURE() << "cell " << id << ": candidate resized the input";
        } else {
            bool seen = false;
            for (std::size_t i = 0; i < seed.size(); ++i) {
                if (bytes[i] == seed[i]) {
                    continue;
                }
                ++cell.diff_bytes;
                cell.diff_highest = i;
                if (!seen) {
                    cell.diff_lowest = i;
                    seen = true;
                }
            }
            // rec1 is a kept path constraint: `<u` must still hold.
            // rec2 is the target: the inversion asked for `==` to hold.
            cell.first_holds = Truncate(ReadAt(bytes, first_field), first_field.bit_width) <
                               Truncate(records[0].rhs, records[0].bit_width);
            cell.second_flipped = Truncate(ReadAt(bytes, second_field), second_field.bit_width) ==
                                  Truncate(records[1].rhs, records[1].bit_width);
        }
    }

    std::cout << "WIDTH-SHADOWING-CELL cell=" << id << " vars=" << cell.num_vars
              << " binding_offset=" << cell.var_offset << " binding_width=" << cell.var_bit_width
              << " binding_be=" << (cell.var_big_endian ? 1 : 0) << " path=" << cell.path_size
              << " target=" << cell.target_index << " rec1_lhs=" << KindName(cell.first_lhs)
              << " rec1_rhs=" << KindName(cell.first_rhs)
              << " rec2_lhs=" << KindName(cell.second_lhs)
              << " rec2_rhs=" << KindName(cell.second_rhs)
              << " outcome=" << OutcomeName(cell.outcome)
              << " candidate=" << (cell.has_candidate ? 1 : 0) << " diff_bytes=" << cell.diff_bytes
              << " diff_lowest=" << cell.diff_lowest << " diff_highest=" << cell.diff_highest
              << " rec1_holds=" << (cell.first_holds ? 1 : 0)
              << " rec2_flipped=" << (cell.second_flipped ? 1 : 0) << '\n';
    return cell;
}

// Every cell shares this: one variable at the shared offset, both
// records survive with (kVar, kConst) on each side, the second record is
// the target, and a candidate IS produced. Asserting it here is what
// makes the per-cell differences below attributable to width/byte-order
// shadowing and to nothing else — and it is also the finding: none of
// these observables distinguishes a shadowed cell from the control.
void ExpectSharedShape(const Cell& cell) {
    EXPECT_EQ(cell.num_vars, 1U);
    EXPECT_EQ(cell.var_offset, kSharedOffset);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_EQ(cell.target_index, 1U);
    EXPECT_EQ(cell.first_lhs, Operand::Kind::kVar);
    EXPECT_EQ(cell.first_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.second_lhs, Operand::Kind::kVar);
    EXPECT_EQ(cell.second_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
}

constexpr Field kFieldAsU32Le{.offset = kSharedOffset, .bit_width = 32, .big_endian = false};
constexpr Field kFieldAsU32Be{.offset = kSharedOffset, .bit_width = 32, .big_endian = true};
constexpr Field kFieldAsU16Le{.offset = kSharedOffset, .bit_width = 16, .big_endian = false};
constexpr Field kFieldAsU8{.offset = kSharedOffset, .bit_width = 8, .big_endian = false};

}  // namespace

// CONTROL — no mixing: both records are u32 little-endian on offset 0.
// Same two-record shape, same predicates, same magic as every cell
// below; the ONLY difference is that nothing shadows anything. The
// candidate rewrites all four bytes of the field and BOTH predicates
// come out right. This is the yardstick.
TEST(WidthShadowing, ControlSameWidthSameEndianness) {
    const Cell cell = Measure("control", Trace(kFieldU32Le, 32, kHigh32, kFieldU32Le, 32),
                              kFieldAsU32Le, kFieldAsU32Le);
    ExpectSharedShape(cell);
    EXPECT_EQ(cell.var_bit_width, 32U);
    EXPECT_FALSE(cell.var_big_endian);
    // Four bytes written back, all four differ from the seed.
    EXPECT_EQ(cell.diff_bytes, 4U);
    EXPECT_EQ(cell.diff_lowest, 0U);
    EXPECT_EQ(cell.diff_highest, 3U);
    EXPECT_TRUE(cell.first_holds);
    EXPECT_TRUE(cell.second_flipped);
}

// CELL u32_then_u8 — WIDE FIRST. The binding is u32, so the write-back
// emits all four bytes; the narrow record only ever reads the low byte,
// which little-endian write-back puts exactly where Z3's extract(7,0)
// says it is. Shadowing happens (the u8 record does NOT get its own
// variable) but it is HARMLESS here: both predicates hold.
TEST(WidthShadowing, U32ThenU8KeepsTheWideBinding) {
    const Cell cell = Measure("u32_then_u8", Trace(kFieldU32Le, 32, kHigh32, kFieldU8, 8),
                              kFieldAsU32Le, kFieldAsU8);
    ExpectSharedShape(cell);
    EXPECT_EQ(cell.var_bit_width, 32U);
    EXPECT_FALSE(cell.var_big_endian);
    EXPECT_EQ(cell.diff_bytes, 4U);
    EXPECT_EQ(cell.diff_highest, 3U);
    EXPECT_TRUE(cell.first_holds);
    EXPECT_TRUE(cell.second_flipped);
}

// CELL u32_then_u16 — WIDE FIRST, same story as above one width up.
TEST(WidthShadowing, U32ThenU16KeepsTheWideBinding) {
    const Cell cell = Measure("u32_then_u16", Trace(kFieldU32Le, 32, kHigh32, kFieldU16Le, 16),
                              kFieldAsU32Le, kFieldAsU16Le);
    ExpectSharedShape(cell);
    EXPECT_EQ(cell.var_bit_width, 32U);
    EXPECT_FALSE(cell.var_big_endian);
    EXPECT_EQ(cell.diff_bytes, 4U);
    EXPECT_EQ(cell.diff_highest, 3U);
    EXPECT_TRUE(cell.first_holds);
    EXPECT_TRUE(cell.second_flipped);
}

// CELL u8_then_u32 — NARROW FIRST. The sharpest cell of the file. The
// binding is u8, so the write-back emits ONE byte, while Z3 solved for a
// 32-bit variable (its width is the max over the constraints). The three
// high bytes of the field keep their seed values, so the u32 record
// reads 0x1122332A instead of the 0x0000002A the model promised: the
// target predicate is NOT flipped. Nothing in the outcome says so — the
// call reports kCandidate exactly as the control does.
TEST(WidthShadowing, U8ThenU32TruncatesTheWriteBackAndTheFlipIsLost) {
    const Cell cell = Measure("u8_then_u32", Trace(kFieldU8, 8, kHigh8, kFieldU32Le, 32),
                              kFieldAsU8, kFieldAsU32Le);
    ExpectSharedShape(cell);
    // The FIRST record's width won, though the trace also carries a u32
    // use of the same offset.
    EXPECT_EQ(cell.var_bit_width, 8U);
    EXPECT_FALSE(cell.var_big_endian);
    // One byte written back where the target needed four.
    EXPECT_EQ(cell.diff_bytes, 1U);
    EXPECT_EQ(cell.diff_lowest, 0U);
    EXPECT_EQ(cell.diff_highest, 0U);
    // The kept constraint survives (it is the narrow one, and the narrow
    // byte IS written) — so this is not a broken solve, it is a
    // half-applied one.
    EXPECT_TRUE(cell.first_holds);
    // MEASURED DEFECT: the branch the solver was asked to flip does not
    // flip on the real input.
    EXPECT_FALSE(cell.second_flipped);
}

// CELL u16_then_u32 — NARROW FIRST, two bytes instead of one. Same
// defect, scaled: two of the four bytes are written, the field reads
// 0x1122002A, the flip is lost.
TEST(WidthShadowing, U16ThenU32TruncatesTheWriteBackAndTheFlipIsLost) {
    const Cell cell = Measure("u16_then_u32", Trace(kFieldU16Le, 16, kHigh16, kFieldU32Le, 32),
                              kFieldAsU16Le, kFieldAsU32Le);
    ExpectSharedShape(cell);
    EXPECT_EQ(cell.var_bit_width, 16U);
    EXPECT_FALSE(cell.var_big_endian);
    EXPECT_EQ(cell.diff_bytes, 2U);
    EXPECT_EQ(cell.diff_lowest, 0U);
    EXPECT_EQ(cell.diff_highest, 1U);
    EXPECT_TRUE(cell.first_holds);
    EXPECT_FALSE(cell.second_flipped);
}

// CELL le_then_be — SAME WIDTH, MIXED BYTE ORDER. Both records are u32
// on offset 0, but the second logs the big-endian reading of those same
// four bytes. FindFirst finds it (concolic.cpp:158-161 tries LE then BE
// at each offset), lands on the offset already claimed by the
// little-endian record, and BindOperand returns the SAME variable: the
// two readings are silently identified. The write-back then uses the
// FIRST record's byte order, so the model value 0x0000002A reaches the
// input as 2A 00 00 00 and the big-endian record reads 0x2A000000. Four
// bytes changed — the full width — and the flip is still lost. Byte
// order shadowing is therefore NOT a truncation effect: it is a distinct
// failure that width alone does not explain.
TEST(WidthShadowing, LittleEndianThenBigEndianAliasesBothReadings) {
    const Cell cell = Measure("le_then_be", Trace(kFieldU32Le, 32, kHigh32, kFieldU32Be, 32),
                              kFieldAsU32Le, kFieldAsU32Be);
    ExpectSharedShape(cell);
    EXPECT_EQ(cell.var_bit_width, 32U);
    // The FIRST record's byte order won.
    EXPECT_FALSE(cell.var_big_endian);
    EXPECT_EQ(cell.diff_bytes, 4U);
    EXPECT_EQ(cell.diff_lowest, 0U);
    EXPECT_EQ(cell.diff_highest, 3U);
    EXPECT_TRUE(cell.first_holds);
    EXPECT_FALSE(cell.second_flipped);
}

// The verdict, asserted rather than left to the report: every cell —
// shadowed or not, flip preserved or lost — reports the SAME
// SolveOutcome, so an orchestrator that reads the outcome cannot tell
// them apart. This is the "silent" half of the finding and the reason
// the loss shows up as unsat/no-progress far downstream instead of here.
TEST(WidthShadowing, OutcomeCannotDistinguishShadowedCellsFromTheControl) {
    const Cell control =
        Measure("verdict_control", Trace(kFieldU32Le, 32, kHigh32, kFieldU32Le, 32), kFieldAsU32Le,
                kFieldAsU32Le);
    const Cell narrow_first =
        Measure("verdict_u8_then_u32", Trace(kFieldU8, 8, kHigh8, kFieldU32Le, 32), kFieldAsU8,
                kFieldAsU32Le);
    const Cell mixed_order =
        Measure("verdict_le_then_be", Trace(kFieldU32Le, 32, kHigh32, kFieldU32Be, 32),
                kFieldAsU32Le, kFieldAsU32Be);

    EXPECT_EQ(control.outcome, narrow_first.outcome);
    EXPECT_EQ(control.outcome, mixed_order.outcome);
    EXPECT_EQ(control.num_vars, narrow_first.num_vars);
    EXPECT_EQ(control.num_vars, mixed_order.num_vars);
    // ...while the thing that actually matters DOES differ.
    EXPECT_TRUE(control.second_flipped);
    EXPECT_FALSE(narrow_first.second_flipped);
    EXPECT_FALSE(mixed_order.second_flipped);
}
