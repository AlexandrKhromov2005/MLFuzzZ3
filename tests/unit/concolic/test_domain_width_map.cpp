#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Solver domain map by field WIDTH and BYTE ORDER (task-026, ADR 0035 §2).
//
// task-022 mapped the domain of the reconstruction in src/concolic over
// ALGEBRAIC forms, but it did so on one fixed cell of the encoding space:
// two verbatim u32 fields, little-endian
// (tests/unit/concolic/test_domain_map.cpp:141-277). Real formats keep
// their length/offset fields in u16 and u64, and network- and
// TIFF-shaped formats keep them big-endian. This file measures the OTHER
// axis: the same gate form `a + b == MAGIC`, held fixed because task-022
// already established it is in the domain at u32/LE
// (SolverDomainMap.AddVarsIsInDomain, test_domain_map.cpp:154), swept
// across widths {8, 16, 32, 64} x byte order {LE, BE}.
//
// Method. Each cell builds its own seed carrying exactly two fields of
// the cell's width, encoded in the cell's byte order, at offsets 0 and
// width/8. Two guard records (a >u LOW, b >u LOW, both TRUE on the seed)
// make the fields findable, exactly as in test_domain_map.cpp; the third
// record is the gate, logging `a + b` on its LHS and MAGIC on its RHS.
//
// A cell records (i) the Operand::Kind the gate's derived operand got,
// (ii) the SolveOutcome, (iii) the VarBinding offset/width/big_endian of
// both fields, and (iv) the END-TO-END check: apply the candidate and
// re-read the fields at their TRUE offsets in the format's own byte
// order, then evaluate the gate there. Without (iv) "in the domain"
// would mean only "solve returned SAT" — and
// DomainWidthMap.U8FirstOccurrenceWinsOverTrueField below is a measured
// cell where exactly that gap opens up.
//
// Nothing here changes src/concolic or src/solver: the encoding is the
// subject of measurement, not of edits (ADR 0035 is the owner's call).

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr unsigned kBits = 8;

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
// (src/concolic/concolic.cpp:136). Used ONLY by the fixture sanity test:
// a constant that happens to occur in the seed would bind as a VARIABLE
// and quietly turn a measured cell into a different measurement.
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

// One cell of the width x byte-order sweep.
struct Form {
    unsigned bit_width;
    bool big_endian;
    std::uint64_t field_a;
    std::uint64_t field_b;
    std::uint64_t low;    ///< guard bound, below both fields and absent from the seed
    std::uint64_t magic;  ///< the gate's constant, absent from the seed
};

// Field values per width. Every byte is non-zero and the two fields share
// no byte window, so neither field aliases onto the other and neither the
// guard bound nor the magic (both of which contain zero bytes at widths
// >= 16) can be found in the seed. FixtureConstantsAreNotFindable pins
// all of that instead of trusting it.
constexpr std::uint64_t kA8 = 0x11U;
constexpr std::uint64_t kB8 = 0x22U;
constexpr std::uint64_t kLow8 = 0x05U;
constexpr std::uint64_t kMagic8 = 0x2AU;

constexpr Form kU8Le{.bit_width = 8,
                     .big_endian = false,
                     .field_a = kA8,
                     .field_b = kB8,
                     .low = kLow8,
                     .magic = kMagic8};
constexpr Form kU8Be{.bit_width = 8,
                     .big_endian = true,
                     .field_a = kA8,
                     .field_b = kB8,
                     .low = kLow8,
                     .magic = kMagic8};
constexpr Form kU16Le{.bit_width = 16,
                      .big_endian = false,
                      .field_a = 0x1122U,
                      .field_b = 0x3344U,
                      .low = 0x0101U,
                      .magic = 0x002AU};
constexpr Form kU16Be{.bit_width = 16,
                      .big_endian = true,
                      .field_a = 0x1122U,
                      .field_b = 0x3344U,
                      .low = 0x0101U,
                      .magic = 0x002AU};
constexpr Form kU32Le{.bit_width = 32,
                      .big_endian = false,
                      .field_a = 0x11223344U,
                      .field_b = 0x55667788U,
                      .low = 0x01010101U,
                      .magic = 0x0000002AU};
constexpr Form kU32Be{.bit_width = 32,
                      .big_endian = true,
                      .field_a = 0x11223344U,
                      .field_b = 0x55667788U,
                      .low = 0x01010101U,
                      .magic = 0x0000002AU};
constexpr Form kU64Le{.bit_width = 64,
                      .big_endian = false,
                      .field_a = 0x1122334455667788ULL,
                      .field_b = 0x99AABBCCDDEEFF11ULL,
                      .low = 0x0101010101010101ULL,
                      .magic = 0x000000000000002AULL};
constexpr Form kU64Be{.bit_width = 64,
                      .big_endian = true,
                      .field_a = 0x1122334455667788ULL,
                      .field_b = 0x99AABBCCDDEEFF11ULL,
                      .low = 0x0101010101010101ULL,
                      .magic = 0x000000000000002AULL};

std::vector<Form> AllForms() {
    return {kU8Le, kU8Be, kU16Le, kU16Be, kU32Le, kU32Be, kU64Le, kU64Be};
}

std::uint64_t SumOf(const Form& form) {
    return Trunc(Trunc(form.field_a, form.bit_width) + Trunc(form.field_b, form.bit_width),
                 form.bit_width);
}

std::vector<std::uint8_t> SeedOf(const Form& form) {
    const unsigned n = form.bit_width / kBits;
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(2U * n));
    PutField(seed, 0, form.field_a, form.bit_width, form.big_endian);
    PutField(seed, n, form.field_b, form.bit_width, form.big_endian);
    return seed;
}

std::vector<BranchReader::Record> RecordsOf(const Form& form) {
    const auto w = static_cast<std::uint8_t>(form.bit_width);
    return {
        {0, kUgt, w, form.field_a, form.low},
        {1, kUgt, w, form.field_b, form.low},
        {2, kEq, w, SumOf(form), form.magic},
    };
}

// Everything measured for one cell. NO-BINDING cells are findings, not
// failures: they are pinned exactly like BOUND ones.
struct Cell {
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    bool gate_survived = false;
    Operand::Kind gate_lhs_kind = Operand::Kind::kConst;
    Operand::Kind gate_rhs_kind = Operand::Kind::kConst;
    std::size_t offset_a = 0;
    std::size_t offset_b = 0;
    unsigned width_a = 0;
    unsigned width_b = 0;
    bool be_a = false;
    bool be_b = false;
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    bool guards_hold_end_to_end = false;  ///< candidate re-read at TRUE offsets
    bool gate_holds_end_to_end = false;   ///< ditto; SAT alone does not imply this
};

Cell Measure(const Form& form) {
    const std::vector<std::uint8_t> seed = SeedOf(form);
    const std::vector<BranchReader::Record> records = RecordsOf(form);

    const System sys = BuildSystem(seed, records);
    Cell cell{};
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.gate_survived = sys.path.size() == records.size();
    if (cell.gate_survived) {
        cell.gate_lhs_kind = sys.path.back().lhs.kind;
        cell.gate_rhs_kind = sys.path.back().rhs.kind;
    }
    if (sys.vars.size() >= 2U) {
        cell.offset_a = sys.vars[0].offset;
        cell.offset_b = sys.vars[1].offset;
        cell.width_a = sys.vars[0].bit_width;
        cell.width_b = sys.vars[1].bit_width;
        cell.be_a = sys.vars[0].big_endian;
        cell.be_b = sys.vars[1].big_endian;
    }

    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    const unsigned n = form.bit_width / kBits;
    if (candidate.has_value() && candidate->size() >= seed.size()) {
        const std::uint64_t a = GetField(candidate->data(), 0, form.bit_width, form.big_endian);
        const std::uint64_t b = GetField(candidate->data(), n, form.bit_width, form.big_endian);
        const std::uint64_t low = Trunc(form.low, form.bit_width);
        cell.guards_hold_end_to_end = a > low && b > low;
        cell.gate_holds_end_to_end =
            Trunc(a + b, form.bit_width) == Trunc(form.magic, form.bit_width);
    }
    return cell;
}

// The shape every BOUND cell must have. Anything else means the cell is
// no longer measuring `a + b == MAGIC` over two whole fields.
void ExpectBoundShape(const Cell& cell, const Form& form) {
    ASSERT_EQ(cell.num_vars, 2U);
    EXPECT_EQ(cell.offset_a, 0U);
    EXPECT_EQ(cell.offset_b, static_cast<std::size_t>(form.bit_width / kBits));
    EXPECT_EQ(cell.width_a, form.bit_width);
    EXPECT_EQ(cell.width_b, form.bit_width);
    EXPECT_TRUE(cell.gate_survived) << "path kept " << cell.path_size << " of 3 records";
    EXPECT_EQ(cell.gate_lhs_kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.gate_rhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_TRUE(cell.guards_hold_end_to_end);
    EXPECT_TRUE(cell.gate_holds_end_to_end);
}

}  // namespace

// Sanity for the fixtures themselves. If a magic, a guard bound or the
// logged sum were findable in its own seed, the cell below it would bind
// that constant as a variable and the map would be forged rather than
// measured.
TEST(DomainWidthMap, FixtureConstantsAreNotFindable) {
    for (const Form& form : AllForms()) {
        SCOPED_TRACE(testing::Message()
                     << "width=" << form.bit_width << " big_endian=" << form.big_endian);
        const std::vector<std::uint8_t> seed = SeedOf(form);
        ASSERT_EQ(seed.size(), static_cast<std::size_t>(2U * (form.bit_width / kBits)));
        EXPECT_FALSE(Occurs(seed, form.magic, form.bit_width)) << "magic aliases onto the seed";
        EXPECT_FALSE(Occurs(seed, form.low, form.bit_width)) << "guard bound aliases onto the seed";
        EXPECT_FALSE(Occurs(seed, SumOf(form), form.bit_width))
            << "the logged sum is findable, so it would bind DIRECT instead of as kAddVars";
    }
}

TEST(DomainWidthMap, U8LittleEndian) {
    const Cell cell = Measure(kU8Le);
    ExpectBoundShape(cell, kU8Le);
    EXPECT_FALSE(cell.be_a);
    EXPECT_FALSE(cell.be_b);
}

// At width 8 the two encodings are the same single byte, and FindFirst
// tries little-endian first (src/concolic/concolic.cpp:136). So a u8
// field is never reported big-endian: byte order is not an observable of
// this width, which is a property of the METHOD, not of the format.
TEST(DomainWidthMap, U8BigEndianIsIndistinguishableFromLittle) {
    const Cell cell = Measure(kU8Be);
    ExpectBoundShape(cell, kU8Be);
    EXPECT_FALSE(cell.be_a) << "width 8 cannot carry a byte-order observation";
    EXPECT_FALSE(cell.be_b);
}

TEST(DomainWidthMap, U16LittleEndian) {
    const Cell cell = Measure(kU16Le);
    ExpectBoundShape(cell, kU16Le);
    EXPECT_FALSE(cell.be_a);
    EXPECT_FALSE(cell.be_b);
}

TEST(DomainWidthMap, U16BigEndian) {
    const Cell cell = Measure(kU16Be);
    ExpectBoundShape(cell, kU16Be);
    EXPECT_TRUE(cell.be_a);
    EXPECT_TRUE(cell.be_b);
}

TEST(DomainWidthMap, U32LittleEndian) {
    const Cell cell = Measure(kU32Le);
    ExpectBoundShape(cell, kU32Le);
    EXPECT_FALSE(cell.be_a);
    EXPECT_FALSE(cell.be_b);
}

TEST(DomainWidthMap, U32BigEndian) {
    const Cell cell = Measure(kU32Be);
    ExpectBoundShape(cell, kU32Be);
    EXPECT_TRUE(cell.be_a);
    EXPECT_TRUE(cell.be_b);
}

TEST(DomainWidthMap, U64LittleEndian) {
    const Cell cell = Measure(kU64Le);
    ExpectBoundShape(cell, kU64Le);
    EXPECT_FALSE(cell.be_a);
    EXPECT_FALSE(cell.be_b);
}

TEST(DomainWidthMap, U64BigEndian) {
    const Cell cell = Measure(kU64Be);
    ExpectBoundShape(cell, kU64Be);
    EXPECT_TRUE(cell.be_a);
    EXPECT_TRUE(cell.be_b);
}

// Boundary pinning for ByteWidthValid (src/concolic/concolic.cpp:37): a
// width that is not a multiple of 8 binds NOTHING — even when the field
// bytes are present in the seed under a byte-aligned reading, which the
// control at the end of this test demonstrates on the same seed.
TEST(DomainWidthMap, NonByteAlignedWidthBindsNothing) {
    const std::vector<std::uint8_t> seed = {0xBC, 0x0A, 0xEF, 0x0D};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 12, 0x0ABCU, 0x005U},
        {1, kUgt, 12, 0x0DEFU, 0x005U},
        {2, kEq, 12, (0x0ABCU + 0x0DEFU) & 0xFFFU, 0x02AU},
    };

    const System sys = BuildSystem(seed, records);
    EXPECT_EQ(sys.num_vars, 0U);
    EXPECT_TRUE(sys.path.empty());
    EXPECT_FALSE(sys.invertible);

    SolveOutcome outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &outcome);
    EXPECT_FALSE(candidate.has_value());
    EXPECT_EQ(outcome, SolveOutcome::kNoBinding);

    // Control: the same two values over the same seed at width 16 DO
    // bind, so the refusal above is the width rule and not the fixture.
    const std::vector<BranchReader::Record> control = {
        {0, kUgt, 16, 0x0ABCU, 0x0005U},
        {1, kUgt, 16, 0x0DEFU, 0x0005U},
    };
    EXPECT_EQ(BuildSystem(seed, control).num_vars, 2U);
}

// The u8 noise boundary the width sweep cannot show on its own. Here the
// gate's real fields sit at offsets 2 and 3, but the same two byte VALUES
// also occur at offsets 0 and 1; FindFirst scans ascending
// (src/concolic/concolic.cpp:136), so both variables bind to the earlier
// occurrences. Solve still returns kCandidate — and the gate over the
// REAL field positions is left exactly as it was. This is the category
// "SAT but the gate does not hold", not "in the domain".
TEST(DomainWidthMap, U8FirstOccurrenceWinsOverTrueField) {
    const std::vector<std::uint8_t> seed = {0x11, 0x22, 0x11, 0x22};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 8, kA8, kLow8},
        {1, kUgt, 8, kB8, kLow8},
        {2, kEq, 8, (kA8 + kB8) & 0xFFU, kMagic8},
    };

    const System sys = BuildSystem(seed, records);
    ASSERT_EQ(sys.num_vars, 2U);
    EXPECT_EQ(sys.vars[0].offset, 0U) << "bound to the decoy, not to the field at offset 2";
    EXPECT_EQ(sys.vars[1].offset, 1U) << "bound to the decoy, not to the field at offset 3";

    SolveOutcome outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &outcome);
    ASSERT_TRUE(candidate.has_value());
    EXPECT_EQ(outcome, SolveOutcome::kCandidate);
    ASSERT_GE(candidate->size(), 4U);

    const std::uint64_t a = GetField(candidate->data(), 2, 8, false);
    const std::uint64_t b = GetField(candidate->data(), 3, 8, false);
    EXPECT_EQ(a, kA8) << "the real field was not touched";
    EXPECT_EQ(b, kB8);
    EXPECT_NE((a + b) & 0xFFU, kMagic8) << "gate holds by accident — the cell proves nothing";
}
