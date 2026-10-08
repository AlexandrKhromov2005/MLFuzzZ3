#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// FALSE composition of kAddVars (task-027, ADR 0035 §2).
//
// When the direct value-match fails, BindOperand
// (src/concolic/concolic.cpp:185-206) walks every pair of already
// findable fields and returns MakeAdd(i, j) for the FIRST pair whose
// truncated sum equals the operand (concolic.cpp:195-204). That search
// establishes that the NUMBERS agree; it does not establish that the
// program computed a sum. Nothing downstream re-checks the origin, so a
// numeric coincidence is encoded as `v_i + v_j` and Z3 then faithfully
// solves a system the program does not contain.
//
// This file pins that gap on one deterministic pair of cells built to be
// identical in everything the pipeline can observe:
//
//   * "xor coincidence" — the gate operand is `a ^ b`, with a & b == 0 in
//     the seed, so `a ^ b` and `a + b` are the same NUMBER on this seed
//     while the program's operation is XOR, not addition;
//   * "true sum" — the same shape with a genuine `a + b` (carries present,
//     so xor and sum differ) as the control.
//
// Both cells log the same guards, the same gate predicate and the same
// magic; the only difference is where the third operand came from. What
// the cells measure is (i) the Operand::Kind the gate's derived operand
// gets, (ii) the SolveOutcome, and (iii) the END-TO-END check that
// task-022 showed SolveOutcome cannot stand in for: apply the candidate,
// re-read the fields at their TRUE offsets, and evaluate the gate under
// the semantics the PROGRAM has (XOR for the false cell), not under the
// semantics the encoding assumed (addition).
//
// Part (B) then asks how OFTEN that coincidence happens by itself. Over a
// grid of bit width x number of findable fields it runs BuildSystem on
// deterministically generated seeds whose gate operand the modelled
// program never obtained by adding anything, and counts the share of runs
// in which the pair search nevertheless returned kAddVars.
//
// Everything here is a measurement: the tests assert the OBSERVED values,
// including the negative ones. Nothing in src/concolic or src/solver is
// touched — checking operand origin would extend the ADR 0035 encoding
// and is the owner's call, not this file's.

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
constexpr unsigned kWidth = 32;  ///< both cells are u32/LE (task-026 maps the width axis)
constexpr unsigned kBytes = kWidth / kBits;

std::uint64_t TruncTo(std::uint64_t value, unsigned bit_width) {
    return bit_width >= 64U ? value : value & ((std::uint64_t{1} << bit_width) - 1U);
}

std::uint64_t Trunc(std::uint64_t value) {
    return TruncTo(value, kWidth);
}

void PutField(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint64_t value,
              unsigned bit_width = kWidth) {
    for (unsigned k = 0; k < bit_width / kBits; ++k) {
        buf[offset + k] = static_cast<std::uint8_t>(value >> (kBits * k));
    }
}

std::uint64_t GetField(const std::uint8_t* bytes, std::size_t offset) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < kBytes; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (kBits * k);
    }
    return value;
}

// Independent restatement of the substring search FindFirst performs
// (src/concolic/concolic.cpp:136), including its tie-break: ascending
// offset, little-endian before big-endian at the same offset. Used ONLY
// by the fixture checks — an operand that is findable verbatim binds
// DIRECT as kVar and the pair search under measurement never runs.
struct SeedMatch {
    std::size_t offset;
    bool big_endian;
};

std::optional<SeedMatch> FirstMatch(const std::vector<std::uint8_t>& seed, std::uint64_t value,
                                    unsigned bit_width = kWidth) {
    const unsigned n = bit_width / kBits;
    if (seed.size() < n) {
        return std::nullopt;
    }
    const std::uint64_t v = TruncTo(value, bit_width);
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
        if (le) {
            return SeedMatch{.offset = off, .big_endian = false};
        }
        if (be) {
            return SeedMatch{.offset = off, .big_endian = true};
        }
    }
    return std::nullopt;
}

bool Occurs(const std::vector<std::uint8_t>& seed, std::uint64_t value,
            unsigned bit_width = kWidth) {
    return FirstMatch(seed, value, bit_width).has_value();
}

// What the PROGRAM does to produce the gate's third operand. The encoding
// has no way to tell these apart: it only ever sees the resulting number.
enum class Origin { kXorCoincidence, kTrueSum };

std::uint64_t Compose(Origin origin, std::uint64_t a, std::uint64_t b) {
    return origin == Origin::kTrueSum ? Trunc(Trunc(a) + Trunc(b)) : Trunc(Trunc(a) ^ Trunc(b));
}

struct Form {
    Origin origin;
    std::uint64_t field_a;
    std::uint64_t field_b;
    std::uint64_t low;    ///< guard bound, below both fields and absent from the seed
    std::uint64_t magic;  ///< the gate's constant, absent from the seed
};

// a & b == 0, so `a ^ b` == `a + b` as a number while the operation is XOR.
constexpr Form kXorCell{.origin = Origin::kXorCoincidence,
                        .field_a = 0x0F0F0F0FU,
                        .field_b = 0x30303030U,
                        .low = 0x01010101U,
                        .magic = 0xDEADBEEFU};

// Carries present (a & b != 0), so here the number really is a sum and
// nothing else explains it.
constexpr Form kSumCell{.origin = Origin::kTrueSum,
                        .field_a = 0x11223344U,
                        .field_b = 0x55667788U,
                        .low = 0x01010101U,
                        .magic = 0xDEADBEEFU};

std::uint64_t GateOperand(const Form& form) {
    return Compose(form.origin, form.field_a, form.field_b);
}

std::vector<std::uint8_t> SeedOf(const Form& form) {
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(2U * kBytes));
    PutField(seed, 0, form.field_a);
    PutField(seed, kBytes, form.field_b);
    return seed;
}

// Two guards make `a` and `b` findable (both TRUE on the seed), exactly
// as in test_domain_map.cpp; the third record is the gate.
std::vector<BranchReader::Record> RecordsOf(const Form& form) {
    const auto w = static_cast<std::uint8_t>(kWidth);
    return {
        {0, kUgt, w, form.field_a, form.low},
        {1, kUgt, w, form.field_b, form.low},
        {2, kEq, w, GateOperand(form), form.magic},
    };
}

// Everything one cell exposes. The first block is what the pipeline can
// observe about itself; the last two lines are the ground truth it has no
// access to.
struct Cell {
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    bool gate_survived = false;
    Operand::Kind gate_lhs_kind = Operand::Kind::kConst;
    Operand::Kind gate_rhs_kind = Operand::Kind::kConst;
    std::size_t add_i = 0;  ///< pair the search picked, valid iff lhs is kAddVars
    std::size_t add_j = 0;
    std::size_t offset_a = 0;
    std::size_t offset_b = 0;
    unsigned width_a = 0;
    unsigned width_b = 0;
    bool be_a = false;
    bool be_b = false;
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    std::uint64_t candidate_a = 0;
    std::uint64_t candidate_b = 0;
    bool guards_hold_end_to_end = false;  ///< candidate re-read at TRUE offsets
    bool gate_holds_as_encoded = false;   ///< a + b == MAGIC, i.e. what Z3 was asked for
    bool gate_holds_in_program = false;   ///< Compose(origin, a, b) == MAGIC, the REAL gate
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
        cell.add_i = sys.path.back().lhs.var_index;
        cell.add_j = sys.path.back().lhs.var_index2;
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
    if (candidate.has_value() && candidate->size() >= seed.size()) {
        const std::uint64_t a = GetField(candidate->data(), 0);
        const std::uint64_t b = GetField(candidate->data(), kBytes);
        cell.candidate_a = a;
        cell.candidate_b = b;
        const std::uint64_t low = Trunc(form.low);
        cell.guards_hold_end_to_end = a > low && b > low;
        cell.gate_holds_as_encoded = Trunc(a + b) == Trunc(form.magic);
        cell.gate_holds_in_program = Compose(form.origin, a, b) == Trunc(form.magic);
    }
    return cell;
}

const char* KindName(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kConst:
            return "kConst";
        case Operand::Kind::kAddVars:
            return "kAddVars";
    }
    return "?";
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

// The raw ctest log is the evidence for the report, so every cell prints
// what it measured and not merely whether it passed.
void PrintCell(const char* id, const Cell& cell) {
    std::cout << "ADDVARS-FALSE-COMPOSITION-CELL cell=" << id << " vars=" << cell.num_vars
              << " path=" << cell.path_size << " gate_lhs=" << KindName(cell.gate_lhs_kind)
              << " pair=(" << cell.add_i << "," << cell.add_j << ")"
              << " gate_rhs=" << KindName(cell.gate_rhs_kind)
              << " outcome=" << OutcomeName(cell.outcome) << " candidate_a=" << cell.candidate_a
              << " candidate_b=" << cell.candidate_b << " guards=" << cell.guards_hold_end_to_end
              << " gate_as_encoded=" << cell.gate_holds_as_encoded
              << " gate_in_program=" << cell.gate_holds_in_program << std::endl;
}

// The shape both cells share. This is precisely the set of signals the
// pipeline exposes; the point of the pair is that it is the SAME here.
void ExpectAddVarsShape(const Cell& cell) {
    ASSERT_EQ(cell.num_vars, 2U);
    EXPECT_EQ(cell.offset_a, 0U);
    EXPECT_EQ(cell.offset_b, static_cast<std::size_t>(kBytes));
    EXPECT_EQ(cell.width_a, kWidth);
    EXPECT_EQ(cell.width_b, kWidth);
    EXPECT_FALSE(cell.be_a);
    EXPECT_FALSE(cell.be_b);
    EXPECT_TRUE(cell.gate_survived) << "path kept " << cell.path_size << " of 3 records";
    EXPECT_EQ(cell.gate_lhs_kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.gate_rhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.add_i, 0U);
    EXPECT_EQ(cell.add_j, 1U);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_TRUE(cell.guards_hold_end_to_end);
    EXPECT_TRUE(cell.gate_holds_as_encoded);
}

// ===========================================================================
// (B) FREQUENCY (task-027 unit B).
//
// Unit A shows that ONE hand-built coincidence is encoded as a sum. That
// says nothing about how often the pair search produces such a sum on its
// own, and that rate is what decides how much of the kAddVars niche is
// actually worth anything.
//
// The modelled program here contains NO addition at all. It logs `v`
// guards over `v` findable fields and one gate whose operand it obtained
// some other way — a table lookup, a checksum, a hash, an XOR — modelled
// as an independent draw from the same deterministic stream. So EVERY
// kAddVars the pair search returns in this experiment is false by
// construction: it is the search finding two fields whose truncated sum
// happens to hit that number.
//
// The grid is bit width 8/16/32 x 2/4/8 fields, i.e. v(v+1)/2 = 3/10/36
// candidate pairs against a 2^w-wide value space. Seed and trial count
// are compile-time constants and every field value is drawn from a
// splitmix64 stream keyed by the cell, so the numbers below are a
// property of this file and not of the machine or the run order.
// ===========================================================================

// The stream key. Mixed per cell so that adding, dropping or reordering a
// grid cell cannot move another cell's numbers.
constexpr std::uint64_t kGeneratorSeed = 0x0027'0035ULL;  ///< task-027, ADR 0035
constexpr unsigned kTrials = 4096;                        ///< BuildSystem runs per cell
constexpr unsigned kMaxRedraws = 4096;                    ///< cap on fixture-invalid draws
constexpr unsigned kPinTolerance = 2;  ///< counts; the pipeline is integer-deterministic

// The gate's constant and the guard bound. Both must stay unfindable in
// the seed (checked per draw): either one that aliased onto the seed
// would become an extra variable in pass 1 and silently change the pair
// count the cell is supposed to hold fixed.
constexpr std::uint64_t kFreqMagic = 0xDEADBEEFULL;
constexpr std::uint64_t kFreqLow = 1;

// splitmix64. Reproduced here rather than taken from <random>, whose
// engines are portable but whose distributions are not.
class SplitMix64 {
   public:
    explicit SplitMix64(std::uint64_t seed) : state_(seed) {}

    std::uint64_t Next() {
        state_ += 0x9E37'79B9'7F4A'7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30U)) * 0xBF58'476D'1CE4'E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D0'49BB'1331'11EBULL;
        return z ^ (z >> 31U);
    }

   private:
    std::uint64_t state_;
};

struct GridCell {
    unsigned width;
    unsigned vars;
};

constexpr GridCell kGrid[] = {
    {.width = 8, .vars = 2},  {.width = 8, .vars = 4},  {.width = 8, .vars = 8},
    {.width = 16, .vars = 2}, {.width = 16, .vars = 4}, {.width = 16, .vars = 8},
    {.width = 32, .vars = 2}, {.width = 32, .vars = 4}, {.width = 32, .vars = 8},
};

std::uint64_t StreamSeed(const GridCell& cell) {
    return kGeneratorSeed ^ (static_cast<std::uint64_t>(cell.width) << 32U) ^
           (static_cast<std::uint64_t>(cell.vars) << 8U);
}

// One grid cell's tally. add_vars is the measurement; the rest exists so
// the raw log can show that the cell counted what it claims to count.
struct Frequency {
    unsigned width = 0;
    unsigned vars = 0;
    unsigned trials = 0;
    unsigned add_vars = 0;    ///< gate operand bound kAddVars — false by construction
    unsigned self_pair = 0;   ///< ... of those, the "sum" is one field added to itself
    unsigned direct_var = 0;  ///< operand was findable verbatim -> kVar, no pair search
    unsigned lhs_const = 0;   ///< operand bound kConst, yet the record survived: see magic_composed
    unsigned gate_dropped = 0;    ///< kConst on both sides -> the gate left the path entirely
    unsigned magic_composed = 0;  ///< the gate CONSTANT was itself bound as a sum of fields
    unsigned redraws = 0;         ///< fixture-invalid draws discarded (see DrawFields)
    unsigned coincidence_ok = 0;  ///< self-check: the picked pair really does sum to the operand
    bool fixture_ok = true;       ///< false if a draw could not be made valid within kMaxRedraws

    [[nodiscard]] unsigned pairs() const {
        return vars * (vars + 1U) / 2U;
    }
    [[nodiscard]] double rate() const {
        return trials == 0 ? 0.0 : static_cast<double>(add_vars) / static_cast<double>(trials);
    }
};

// Draw `cell.vars` field values into a fresh seed. A draw is discarded and
// retaken from the SAME stream when it would not give the cell the shape
// it is named for: a field that is not first-findable at its own offset
// binds to somebody else's variable (the task-025 effect) and a findable
// magic or guard bound adds a variable nobody asked for. Discarding is
// about fixture validity, not about the phenomenon under measurement —
// nothing here inspects the operand.
bool DrawFields(SplitMix64& rng, const GridCell& cell, std::vector<std::uint64_t>& fields,
                std::vector<std::uint8_t>& seed) {
    const unsigned bytes = cell.width / kBits;
    const std::uint64_t magic = TruncTo(kFreqMagic, cell.width);
    fields.assign(cell.vars, 0);
    seed.assign(static_cast<std::size_t>(cell.vars) * bytes, 0);
    for (unsigned i = 0; i < cell.vars; ++i) {
        fields[i] = TruncTo(rng.Next(), cell.width);
        PutField(seed, static_cast<std::size_t>(i) * bytes, fields[i], cell.width);
    }
    for (unsigned i = 0; i < cell.vars; ++i) {
        if (fields[i] <= kFreqLow) {
            return false;  // the guard would not hold on the seed
        }
        const std::optional<SeedMatch> m = FirstMatch(seed, fields[i], cell.width);
        if (!m.has_value() || m->big_endian || m->offset != static_cast<std::size_t>(i) * bytes) {
            return false;  // field i is not the first thing found at its own offset
        }
    }
    return !Occurs(seed, kFreqLow, cell.width) && !Occurs(seed, magic, cell.width);
}

std::vector<BranchReader::Record> FreqRecords(const GridCell& cell,
                                              const std::vector<std::uint64_t>& fields,
                                              std::uint64_t operand) {
    const auto w = static_cast<std::uint8_t>(cell.width);
    std::vector<BranchReader::Record> records;
    records.reserve(fields.size() + 1U);
    for (std::size_t i = 0; i < fields.size(); ++i) {
        records.push_back({.site_id = static_cast<std::uint32_t>(i),
                           .predicate = kUgt,
                           .bit_width = w,
                           .lhs = fields[i],
                           .rhs = kFreqLow});
    }
    records.push_back({.site_id = static_cast<std::uint32_t>(fields.size()),
                       .predicate = kEq,
                       .bit_width = w,
                       .lhs = operand,
                       .rhs = TruncTo(kFreqMagic, cell.width)});
    return records;
}

Frequency MeasureFrequency(const GridCell& cell) {
    Frequency out{.width = cell.width, .vars = cell.vars, .trials = kTrials};
    SplitMix64 rng(StreamSeed(cell));
    std::vector<std::uint64_t> fields;
    std::vector<std::uint8_t> seed;

    for (unsigned t = 0; t < kTrials; ++t) {
        unsigned attempts = 0;
        while (!DrawFields(rng, cell, fields, seed)) {
            ++out.redraws;
            if (++attempts >= kMaxRedraws) {
                out.fixture_ok = false;
                return out;
            }
        }
        // The operand the program handed to the gate. It is NOT computed
        // from the fields by any addition — that is the whole premise.
        const std::uint64_t operand = TruncTo(rng.Next(), cell.width);
        const std::vector<BranchReader::Record> records = FreqRecords(cell, fields, operand);

        const System sys = BuildSystem(seed, records);
        if (sys.path.size() != records.size()) {
            // Both sides const -> BuildSystem drops the gate (boundary "B").
            ++out.gate_dropped;
            continue;
        }
        // The pair search runs on BOTH sides of the record, so the gate's
        // constant can be falsely composed too — and when it is, the gate
        // survives even though the operand itself bound kConst.
        if (sys.path.back().rhs.kind == Operand::Kind::kAddVars) {
            ++out.magic_composed;
        }
        const Operand& lhs = sys.path.back().lhs;
        switch (lhs.kind) {
            case Operand::Kind::kAddVars:
                ++out.add_vars;
                if (lhs.var_index == lhs.var_index2) {
                    ++out.self_pair;
                }
                // With the operand not findable, pass 1 discovered exactly
                // the fields, in offset order, so var_index indexes `fields`.
                if (sys.num_vars == fields.size() && lhs.var_index < fields.size() &&
                    lhs.var_index2 < fields.size() &&
                    TruncTo(fields[lhs.var_index] + fields[lhs.var_index2], cell.width) ==
                        operand) {
                    ++out.coincidence_ok;
                }
                break;
            case Operand::Kind::kVar:
                ++out.direct_var;
                break;
            case Operand::Kind::kConst:
                ++out.lhs_const;
                break;
        }
    }
    return out;
}

// The raw ctest log is the evidence behind the report, so each cell prints
// its full tally and not merely whether the pin held.
void PrintFrequency(const Frequency& f) {
    std::cout << "ADDVARS-FALSE-COMPOSITION-FREQ w" << f.width << "/v" << f.vars
              << " trials=" << f.trials << " pairs=" << f.pairs() << " addvars=" << f.add_vars
              << " rate=" << std::fixed << std::setprecision(6) << f.rate() << std::defaultfloat
              << " self_pair=" << f.self_pair << " direct_var=" << f.direct_var
              << " lhs_const=" << f.lhs_const << " gate_dropped=" << f.gate_dropped
              << " magic_composed=" << f.magic_composed << " redraws=" << f.redraws
              << " coincidence_ok=" << f.coincidence_ok << std::endl;
}

// The MEASURED counts, read off the run and pinned here. These are not
// targets: a change in either direction means BindOperand's pair search
// now behaves differently and the report's numbers are stale.
struct Pin {
    unsigned width;
    unsigned vars;
    unsigned add_vars;
};

constexpr Pin kPins[] = {
    {.width = 8, .vars = 2, .add_vars = 47},  {.width = 8, .vars = 4, .add_vars = 163},
    {.width = 8, .vars = 8, .add_vars = 525}, {.width = 16, .vars = 2, .add_vars = 0},
    {.width = 16, .vars = 4, .add_vars = 1},  {.width = 16, .vars = 8, .add_vars = 3},
    {.width = 32, .vars = 2, .add_vars = 0},  {.width = 32, .vars = 4, .add_vars = 0},
    {.width = 32, .vars = 8, .add_vars = 0},
};

}  // namespace

// Sanity for the fixtures themselves. If the gate operand, the magic or
// the guard bound were findable in the seed, the cell below would measure
// a DIRECT binding instead of the pair search, and the "coincidence" of
// the false cell would not be a coincidence at all.
TEST(AddVarsFalseComposition, FixtureConstantsAreNotFindable) {
    for (const Form& form : {kXorCell, kSumCell}) {
        SCOPED_TRACE(testing::Message()
                     << "origin=" << (form.origin == Origin::kTrueSum ? "sum" : "xor"));
        const std::vector<std::uint8_t> seed = SeedOf(form);
        ASSERT_EQ(seed.size(), static_cast<std::size_t>(2U * kBytes));
        EXPECT_TRUE(Occurs(seed, form.field_a));
        EXPECT_TRUE(Occurs(seed, form.field_b));
        EXPECT_FALSE(Occurs(seed, form.magic)) << "magic aliases onto the seed";
        EXPECT_FALSE(Occurs(seed, form.low)) << "guard bound aliases onto the seed";
        EXPECT_FALSE(Occurs(seed, GateOperand(form)))
            << "the gate operand is findable, so it would bind DIRECT, not through the pair search";
    }
}

// The premise of the false cell: on THIS seed the XOR and the sum are the
// same number, which is exactly the coincidence the pair search cannot
// tell from a real addition. The control cell must not have it.
TEST(AddVarsFalseComposition, FixtureCoincidenceHoldsOnlyInTheFalseCell) {
    EXPECT_EQ(kXorCell.field_a & kXorCell.field_b, 0U) << "carries would break the coincidence";
    EXPECT_EQ(GateOperand(kXorCell), Trunc(kXorCell.field_a + kXorCell.field_b));
    EXPECT_NE(kSumCell.field_a & kSumCell.field_b, 0U);
    EXPECT_NE(GateOperand(kSumCell), Trunc(kSumCell.field_a ^ kSumCell.field_b));
}

// MEASURED: an operand the program produced with XOR is encoded as
// `v0 + v1`, solved as such, and the candidate that comes back does NOT
// satisfy the gate the program actually has.
TEST(AddVarsFalseComposition, XorCoincidenceIsEncodedAsAddVars) {
    const Cell cell = Measure(kXorCell);
    PrintCell("xor-coincidence", cell);
    ExpectAddVarsShape(cell);

    // The end-to-end check under the PROGRAM's semantics. This is the
    // whole finding: nothing above this line differs from the control.
    EXPECT_FALSE(cell.gate_holds_in_program)
        << "candidate a=" << cell.candidate_a << " b=" << cell.candidate_b
        << " xor=" << (cell.candidate_a ^ cell.candidate_b) << " magic=" << kXorCell.magic;
}

// Control: the same shape over an operand that really is a sum. Here the
// encoding is right, so the candidate flips the real gate.
TEST(AddVarsFalseComposition, TrueSumIsEncodedAsAddVars) {
    const Cell cell = Measure(kSumCell);
    PrintCell("true-sum", cell);
    ExpectAddVarsShape(cell);
    EXPECT_TRUE(cell.gate_holds_in_program)
        << "candidate a=" << cell.candidate_a << " b=" << cell.candidate_b
        << " magic=" << kSumCell.magic;
}

// The pair standing side by side: every signal the pipeline exposes is
// identical, and the only thing that separates them is the ground truth
// it never looks at. This is what "silent" means for the report.
TEST(AddVarsFalseComposition, FalseAndTrueCompositionAreObservationallyEqual) {
    const Cell wrong = Measure(kXorCell);
    const Cell right = Measure(kSumCell);

    EXPECT_EQ(wrong.num_vars, right.num_vars);
    EXPECT_EQ(wrong.path_size, right.path_size);
    EXPECT_EQ(wrong.gate_survived, right.gate_survived);
    EXPECT_EQ(wrong.gate_lhs_kind, right.gate_lhs_kind);
    EXPECT_EQ(wrong.gate_rhs_kind, right.gate_rhs_kind);
    EXPECT_EQ(wrong.add_i, right.add_i);
    EXPECT_EQ(wrong.add_j, right.add_j);
    EXPECT_EQ(wrong.offset_a, right.offset_a);
    EXPECT_EQ(wrong.offset_b, right.offset_b);
    EXPECT_EQ(wrong.width_a, right.width_a);
    EXPECT_EQ(wrong.width_b, right.width_b);
    EXPECT_EQ(wrong.outcome, right.outcome);
    EXPECT_EQ(wrong.has_candidate, right.has_candidate);
    EXPECT_EQ(wrong.guards_hold_end_to_end, right.guards_hold_end_to_end);
    EXPECT_EQ(wrong.gate_holds_as_encoded, right.gate_holds_as_encoded);

    // ... and the one place they differ is not observable from inside.
    EXPECT_NE(wrong.gate_holds_in_program, right.gate_holds_in_program);

    std::cout << "ADDVARS-FALSE-COMPOSITION-SILENT observable signals identical (kind="
              << KindName(wrong.gate_lhs_kind) << ", outcome=" << OutcomeName(wrong.outcome)
              << "); gate_in_program xor-cell=" << wrong.gate_holds_in_program
              << " sum-cell=" << right.gate_holds_in_program << std::endl;
}

// MEASURED: how often the pair search returns a sum for an operand the
// modelled program never produced by adding anything. Every kAddVars
// counted here is a false composition by construction; the assertion pins
// the observed count per cell, with a tolerance of a couple of counts out
// of kTrials, because a pinned measurement is the only thing that makes a
// later change in this rate visible at all.
TEST(AddVarsFalseComposition, PairSearchInventsSumsTheProgramNeverComputed) {
    ASSERT_EQ(std::size(kGrid), std::size(kPins));
    for (std::size_t c = 0; c < std::size(kGrid); ++c) {
        const GridCell& cell = kGrid[c];
        const Pin& pin = kPins[c];
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        ASSERT_EQ(cell.width, pin.width);
        ASSERT_EQ(cell.vars, pin.vars);

        const Frequency f = MeasureFrequency(cell);
        PrintFrequency(f);

        ASSERT_TRUE(f.fixture_ok) << "no valid draw within " << kMaxRedraws << " attempts";
        // Nothing is unaccounted for: every trial ended in exactly one of
        // the three bindings the encoding can produce.
        EXPECT_EQ(f.add_vars + f.direct_var + f.lhs_const + f.gate_dropped, kTrials);
        // Harness self-check: whenever the search claimed a pair, that
        // pair really does sum to the operand. If this ever falls short of
        // add_vars, the count above is measuring something else.
        EXPECT_EQ(f.coincidence_ok, f.add_vars);

        EXPECT_NEAR(static_cast<double>(f.add_vars), static_cast<double>(pin.add_vars),
                    static_cast<double>(kPinTolerance))
            << "false-composition count moved: pinned " << pin.add_vars << ", measured "
            << f.add_vars << " of " << kTrials;
    }
}

// The generator is the load-bearing part of the claim above: if it were
// not reproducible, the pinned counts would be noise. Two independent
// measurements of the same cell must agree exactly, count for count.
TEST(AddVarsFalseComposition, FrequencyGridIsReproducible) {
    for (const GridCell& cell : kGrid) {
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        const Frequency first = MeasureFrequency(cell);
        const Frequency again = MeasureFrequency(cell);
        EXPECT_EQ(first.add_vars, again.add_vars);
        EXPECT_EQ(first.direct_var, again.direct_var);
        EXPECT_EQ(first.gate_dropped, again.gate_dropped);
        EXPECT_EQ(first.magic_composed, again.magic_composed);
        EXPECT_EQ(first.self_pair, again.self_pair);
        EXPECT_EQ(first.redraws, again.redraws);
    }
}
