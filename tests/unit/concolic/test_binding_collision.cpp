// Binding-collision characterisation for the concolic front-end
// (task-025, ADR 0035 recon). Two measurements, zero production change:
//
//   (A) DETERMINISTIC HIJACK. A seed that carries a byte-identical copy
//       of the gate field ahead of the field itself. FindFirst
//       (src/concolic/concolic.cpp:136) returns the FIRST match by
//       ascending offset (little-endian before big-endian at each
//       offset), so the variable binds to the decoy. The cell records
//       where the VarBinding landed, what SolveForCandidate reported,
//       and — the point of the exercise — whether the produced candidate
//       still flips the gate when the predicate is re-evaluated at the
//       field's REAL offset.
//   (B) FREQUENCY. How often a binding lands off the true field on
//       pseudo-random filler as the seed grows (16/64/256/1024 bytes),
//       for 8/16/32-bit fields. The generator seed and the run count are
//       compile-time constants and std::mt19937's sequence is specified
//       by the standard, so the counts are reproducible byte-for-byte.
//
// Everything below pins MEASURED behaviour, not a quality threshold: the
// offset-selection rule is ADR 0035 encoding and stays untouched.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::VarBinding;
using mlfuzzz3::coverage::BranchReader;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0 };

constexpr unsigned kTimeoutMs = 5000;

void PutU32(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t value, bool big_endian) {
    for (unsigned k = 0; k < 4; ++k) {
        const unsigned shift = big_endian ? (8U * (3U - k)) : (8U * k);
        buf[off + k] = static_cast<std::uint8_t>(value >> shift);
    }
}

std::uint32_t GetU32(const std::uint8_t* p, bool big_endian) {
    std::uint32_t value = 0;
    for (unsigned k = 0; k < 4; ++k) {
        const unsigned shift = big_endian ? (8U * (3U - k)) : (8U * k);
        value |= static_cast<std::uint32_t>(p[k]) << shift;
    }
    return value;
}

const char* OutcomeName(SolveOutcome outcome) {
    switch (outcome) {
        case SolveOutcome::kCandidate:
            return "candidate";
        case SolveOutcome::kNoBinding:
            return "no_binding";
        case SolveOutcome::kUnsat:
            return "unsat";
        case SolveOutcome::kTimeout:
            return "timeout";
        default:  // kError и kWidthOverflow (ADR 0049): здесь недостижим
            return "error";
    }
    return "?";
}

// ---------------------------------------------------------------------
// Measurement A: a single gate `field == kMagic` over a 16-byte seed.
// ---------------------------------------------------------------------

constexpr std::uint32_t kFieldA = 0x11223344U;  // the value the gate reads
constexpr std::uint32_t kMagic = 0xDEADBEEFU;   // the constant it is compared to
constexpr std::size_t kSeedSize = 16;
constexpr std::size_t kRealOffset = 8;   // where the gate actually reads the field
constexpr std::size_t kDecoyOffset = 0;  // where the copy of its bytes sits
constexpr std::uint8_t kFiller = 0xEE;   // matches neither kFieldA nor kMagic

std::vector<BranchReader::Record> GateRecords() {
    return {
        {0, kEq, 32, kFieldA, kMagic},
    };
}

enum class Decoy { kNone, kLittleEndian, kBigEndian };

std::vector<std::uint8_t> HijackSeed(Decoy decoy) {
    std::vector<std::uint8_t> seed(kSeedSize, kFiller);
    PutU32(seed, kRealOffset, kFieldA, /*big_endian=*/false);
    if (decoy != Decoy::kNone) {
        PutU32(seed, kDecoyOffset, kFieldA, /*big_endian=*/decoy == Decoy::kBigEndian);
    }
    return seed;
}

struct CellResult {
    std::size_t num_vars = 0;
    std::size_t binding_offset = 0;
    bool binding_big_endian = false;
    bool bound_to_real_field = false;
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    std::uint32_t real_field_after = 0;
    bool gate_holds_on_real_field = false;
};

CellResult RunCell(const char* id, Decoy decoy) {
    const std::vector<std::uint8_t> seed = HijackSeed(decoy);
    const std::vector<BranchReader::Record> records = GateRecords();

    CellResult cell;
    const System sys = BuildSystem(seed, records);
    cell.num_vars = sys.num_vars;
    if (!sys.vars.empty()) {
        const VarBinding& var = sys.vars.front();
        cell.binding_offset = var.offset;
        cell.binding_big_endian = var.big_endian;
        cell.bound_to_real_field = var.offset == kRealOffset;
    }

    SolveOutcome outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &outcome);
    cell.outcome = outcome;
    cell.has_candidate = candidate.has_value();
    if (candidate.has_value() && candidate->size() >= kRealOffset + 4) {
        // Re-evaluate the gate where the target really reads its field.
        cell.real_field_after = GetU32(candidate->data() + kRealOffset, /*big_endian=*/false);
        cell.gate_holds_on_real_field = cell.real_field_after == kMagic;
    }

    std::cout << "BINDING-COLLISION-CELL cell=" << id << " vars=" << cell.num_vars
              << " binding_offset=" << cell.binding_offset
              << " binding_be=" << (cell.binding_big_endian ? 1 : 0)
              << " real_offset=" << kRealOffset
              << " bound_to_real_field=" << (cell.bound_to_real_field ? 1 : 0)
              << " outcome=" << OutcomeName(cell.outcome)
              << " candidate=" << (cell.has_candidate ? 1 : 0) << std::hex << " real_field_after=0x"
              << cell.real_field_after << std::dec
              << " gate_holds_on_real_field=" << (cell.gate_holds_on_real_field ? 1 : 0) << '\n';
    return cell;
}

// ---------------------------------------------------------------------
// Measurement B: hijack frequency over pseudo-random filler.
// ---------------------------------------------------------------------

constexpr std::uint32_t kRngSeed = 0x5EEDC0DEU;  // fixed; no std::random_device anywhere
constexpr int kRunsPerCell = 2000;               // fixed; the sweep is fully deterministic
constexpr std::size_t kSizes[] = {16, 64, 256, 1024};
constexpr unsigned kWidths[] = {32, 16, 8};

struct FreqResult {
    int runs = 0;
    int hijacked = 0;  // >=1 VarBinding.offset off both true field offsets
    int aliased = 0;   // the two fields collapsed onto one variable
    int not_invertible = 0;
};

// Two fields of `width` bits sit at the tail of the seed; everything in
// front of them is pseudo-random filler, so the number of offsets that
// can steal the binding grows with the seed size.
FreqResult RunFrequencyCell(std::size_t size, unsigned width) {
    const std::size_t n = width / 8U;
    const std::size_t off_a = size - (2U * n);
    const std::size_t off_b = size - n;
    // Derive a per-cell stream from the fixed constant, so each cell is
    // independent yet reproducible.
    std::mt19937 rng(kRngSeed ^ (static_cast<std::uint32_t>(size) * 1000003U) ^ (width * 7919U));

    FreqResult res;
    res.runs = kRunsPerCell;
    for (int run = 0; run < kRunsPerCell; ++run) {
        std::vector<std::uint8_t> seed(size);
        for (std::size_t i = 0; i < size; ++i) {
            seed[i] = static_cast<std::uint8_t>(rng() & 0xFFU);
        }
        const std::uint64_t mask =
            width >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << width) - 1U);
        const std::uint64_t va = static_cast<std::uint64_t>(rng()) & mask;
        const std::uint64_t vb = static_cast<std::uint64_t>(rng()) & mask;
        for (std::size_t k = 0; k < n; ++k) {
            seed[off_a + k] = static_cast<std::uint8_t>(va >> (8U * k));
            seed[off_b + k] = static_cast<std::uint8_t>(vb >> (8U * k));
        }

        const std::vector<BranchReader::Record> records = {
            {0, kEq, static_cast<std::uint8_t>(width), va, vb},
        };
        const System sys = BuildSystem(seed, records);
        if (!sys.invertible) {
            ++res.not_invertible;
        }
        bool hijacked = false;
        for (const VarBinding& var : sys.vars) {
            if (var.offset != off_a && var.offset != off_b) {
                hijacked = true;
            }
        }
        if (hijacked) {
            ++res.hijacked;
        }
        if (sys.num_vars < 2) {
            ++res.aliased;
        }
    }

    const double rate = static_cast<double>(res.hijacked) / static_cast<double>(res.runs);
    std::cout << "BINDING-COLLISION-FREQ width=" << width << " size=" << size << " off_a=" << off_a
              << " off_b=" << off_b << " runs=" << res.runs << " hijacked=" << res.hijacked
              << " aliased=" << res.aliased << " not_invertible=" << res.not_invertible
              << " rate=" << rate << '\n';
    return res;
}

}  // namespace

// === (A) deterministic hijack =========================================

TEST(BindingCollision, LittleEndianDecoyAheadOfTheFieldStealsTheBinding) {
    const CellResult cell = RunCell("A1-le-decoy", Decoy::kLittleEndian);

    // FindFirst scans offsets ascending: the copy at 0 wins over the
    // field at 8.
    EXPECT_EQ(cell.num_vars, 1U);
    EXPECT_EQ(cell.binding_offset, kDecoyOffset);
    EXPECT_FALSE(cell.binding_big_endian);
    EXPECT_FALSE(cell.bound_to_real_field);
}

TEST(BindingCollision, BigEndianDecoyAheadOfTheFieldStealsTheBinding) {
    // "LE before BE" is decided WITHIN one offset; a big-endian match at
    // a lower offset still beats a little-endian match at a higher one.
    const CellResult cell = RunCell("A2-be-decoy", Decoy::kBigEndian);

    EXPECT_EQ(cell.num_vars, 1U);
    EXPECT_EQ(cell.binding_offset, kDecoyOffset);
    EXPECT_TRUE(cell.binding_big_endian);
    EXPECT_FALSE(cell.bound_to_real_field);
}

TEST(BindingCollision, HijackedCandidateDoesNotFlipTheGateAtTheRealOffset) {
    const CellResult le = RunCell("A3-le-effect", Decoy::kLittleEndian);
    const CellResult be = RunCell("A4-be-effect", Decoy::kBigEndian);

    // The solver writes kMagic into the decoy; the byte range the gate
    // really reads is left untouched, so the gate stays closed.
    ASSERT_TRUE(le.has_candidate);
    ASSERT_TRUE(be.has_candidate);
    EXPECT_EQ(le.real_field_after, kFieldA);
    EXPECT_EQ(be.real_field_after, kFieldA);
    EXPECT_FALSE(le.gate_holds_on_real_field);
    EXPECT_FALSE(be.gate_holds_on_real_field);
}

TEST(BindingCollision, TheHijackIsSilentTheOutcomeIsStillCandidate) {
    // src/concolic/concolic.cpp:307 only bounds-checks `offset + n`
    // against the input size; it never re-reads the field, so a binding
    // on foreign bytes is reported as a perfectly good candidate.
    const CellResult le = RunCell("A5-le-silence", Decoy::kLittleEndian);
    const CellResult be = RunCell("A6-be-silence", Decoy::kBigEndian);

    EXPECT_EQ(le.outcome, SolveOutcome::kCandidate);
    EXPECT_EQ(be.outcome, SolveOutcome::kCandidate);
    EXPECT_NE(le.outcome, SolveOutcome::kError);
    EXPECT_NE(be.outcome, SolveOutcome::kError);
}

TEST(BindingCollision, WithoutADecoyTheBindingLandsOnTheFieldAndTheGateFlips) {
    // Control: the same gate, the same offsets, no copy in front. Proves
    // the harness detects a WORKING candidate, so the three cells above
    // measure the hijack and not a broken fixture.
    const CellResult cell = RunCell("A0-control", Decoy::kNone);

    EXPECT_EQ(cell.num_vars, 1U);
    EXPECT_EQ(cell.binding_offset, kRealOffset);
    EXPECT_TRUE(cell.bound_to_real_field);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(cell.has_candidate);
    EXPECT_EQ(cell.real_field_after, kMagic);
    EXPECT_TRUE(cell.gate_holds_on_real_field);
}

// === (B) hijack frequency vs seed size ================================

TEST(BindingCollision, HijackFrequencyBySeedSizeAndFieldWidth) {
    // Pinned MEASURED counts (kRngSeed / kRunsPerCell above). Row order
    // is kWidths x kSizes. These are observations, not targets: if the
    // constants change the numbers change with them.
    static constexpr int kExpectedHijacked[3][4] = {
        {0, 0, 0, 0},            // width 32: never observed at these sizes
        {15, 13, 44, 137},       // width 16
        {206, 763, 1731, 2000},  // width 8: certain at 1024 bytes
    };

    for (std::size_t w = 0; w < 3; ++w) {
        for (std::size_t s = 0; s < 4; ++s) {
            const FreqResult res = RunFrequencyCell(kSizes[s], kWidths[w]);
            EXPECT_EQ(res.runs, kRunsPerCell);
            EXPECT_EQ(res.not_invertible, 0);
            EXPECT_EQ(res.hijacked, kExpectedHijacked[w][s])
                << "width=" << kWidths[w] << " size=" << kSizes[s];
        }
    }
}
