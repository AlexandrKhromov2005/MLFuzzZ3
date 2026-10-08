#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Binding discriminator D (task-037, ADR 0035). This file MEASURES how far
// one caller-side predicate over the ALREADY BUILT system reproduces the
// hand-written solver domain map. It changes nothing in src/, adds no rule
// and does not extend SolveOutcome — the decision whether to adopt the
// predicate is the owner's.
//
//     D(records) = (derived_kind != Operand::Kind::kConst) && gate_survived
//
// Both inputs already fall out of BuildSystem: `gate_survived` is
// `sys.path.size() == records.size()` (the shape pinned by
// tests/unit/concolic/test_domain_map.cpp:120) and `derived_kind` is the
// Kind BindOperand gave the gate's derived operand — each side of a record
// is classified independently (src/concolic/concolic.cpp:240-243).
// Operand::Kind has exactly three values (src/solver/solver_facade.h:31),
// so `!= kConst` reads as "tied to input bytes": either a verbatim field
// (kVar) or a pair recovered by the sum enumeration (kAddVars).
//
// Two corpora, because D has two different errors and the domain map can
// only show one of them:
//
//   CORPUS A — the seven gate forms of the domain map (task-022). D is
//   asked for COMPLETENESS: does the mechanical predicate reproduce the
//   2 BOUND / 5 NO-BINDING classification pinned in
//   docs/experiments/solver-domain-map/report.md:138 (per-form cells at
//   :65-72)?
//
//   CORPUS B — the false-composition grid (task-027) replayed with the
//   same kGeneratorSeed and kTrials as
//   tests/unit/concolic/test_addvars_false_composition.cpp:344-345. There
//   the truth is known BY CONSTRUCTION — the gate operand is drawn from
//   the stream, so it is the sum of no field pair — and D is asked for its
//   RESIDUAL ERROR: how often it says "bound" about an operand the program
//   never derived from the input.
//
// What this file does NOT claim. This is a separation in the ENCODING
// domain. No number here is coverage won on a real program; the same
// caveat is §8 of
// docs/experiments/solver-addvars-width-threshold/report.md:227-245.
//
// Existing tests are not modified: test_domain_map.cpp and
// test_addvars_false_composition.cpp stay byte-for-byte and the helpers
// below are private copies. The concolic unit tests have no shared header
// and SplitMix64 already exists here in three independent copies; a fourth
// follows the settled local practice rather than deciding anything new.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUlt = 2, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr unsigned kBits = 8;
constexpr unsigned kWidth = 32;

// THE DISCRIMINATOR. A pure function of the built system and nothing else;
// every line below only feeds it or tallies its answers.
bool Discriminator(Operand::Kind derived_kind, bool gate_survived) {
    return derived_kind != Operand::Kind::kConst && gate_survived;
}

std::uint64_t TruncTo(std::uint64_t value, unsigned bit_width) {
    return bit_width >= 64U ? value : value & ((std::uint64_t{1} << bit_width) - 1U);
}

void PutField(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint64_t value,
              unsigned bit_width = kWidth) {
    for (unsigned k = 0; k < bit_width / kBits; ++k) {
        buf[offset + k] = static_cast<std::uint8_t>(value >> (kBits * k));
    }
}

// Independent restatement of the substring search FindFirst performs
// (src/concolic/concolic.cpp:136), including its tie-break: ascending
// offset, little-endian before big-endian at the same offset. Copied from
// test_addvars_false_composition.cpp:105-137 so corpus B rejects exactly
// the same draws the pinned run rejected.
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

// ---------------------------------------------------------------------
// CORPUS A — the seven forms of the solver domain map.
// Fixture constants are those of test_domain_map.cpp:45-62.
// ---------------------------------------------------------------------

constexpr std::uint32_t kFieldA = 0x11223344U;
constexpr std::uint32_t kFieldB = 0x55667788U;
constexpr std::uint32_t kLow = 0x01010101U;
constexpr std::uint32_t kMagic = 0x0000002AU;

std::vector<std::uint8_t> SeedOf(std::uint32_t lo, std::uint32_t hi) {
    std::vector<std::uint8_t> seed(8);
    for (unsigned k = 0; k < 4; ++k) {
        seed[k] = static_cast<std::uint8_t>(lo >> (8U * k));
        seed[4 + k] = static_cast<std::uint8_t>(hi >> (8U * k));
    }
    return seed;
}

std::vector<std::uint8_t> Seed() {
    return SeedOf(kFieldA, kFieldB);
}

struct FormCell {
    Operand::Kind derived_kind;
    bool gate_survived;
    std::size_t path_size;
    SolveOutcome outcome;
    bool discriminator;
};

// Same method as test_domain_map.cpp:96-125, PROBE system included. The
// probe is not decoration: when both sides of the gate classify as kConst
// the record is dropped and the LHS Kind has nothing left to be read off
// (test_domain_map.cpp:88-95). Measuring corpus A without the probe would
// make D agree with the map by accident instead of reproducing it.
FormCell MeasureForm(const std::vector<std::uint8_t>& seed, std::uint32_t field_a,
                     std::uint32_t field_b, std::uint64_t derived, std::uint64_t rhs,
                     std::uint8_t predicate) {
    const std::vector<BranchReader::Record> guards = {
        {0, kUgt, 32, field_a, kLow},
        {1, kUgt, 32, field_b, kLow},
    };

    std::vector<BranchReader::Record> form = guards;
    form.push_back({2, predicate, 32, derived, rhs});

    std::vector<BranchReader::Record> probe = guards;
    probe.push_back({2, kEq, 32, derived, field_b});

    const System probe_sys = BuildSystem(seed, probe);
    const System form_sys = BuildSystem(seed, form);

    FormCell cell{};
    if (probe_sys.path.empty()) {
        ADD_FAILURE() << "probe system kept no constraint — the probe fixture itself is broken";
        cell.derived_kind = Operand::Kind::kConst;
    } else {
        cell.derived_kind = probe_sys.path.back().lhs.kind;
    }
    cell.path_size = form_sys.path.size();
    cell.gate_survived = form_sys.path.size() == form.size();
    cell.outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, form, kTimeoutMs, &cell.outcome);
    static_cast<void>(candidate);
    cell.discriminator = Discriminator(cell.derived_kind, cell.gate_survived);
    return cell;
}

// One row of corpus A. `expect_bound` is the CLASSIFICATION QUOTED from
// docs/experiments/solver-domain-map/report.md:65-72 — BOUND ⇔ D must be
// true — not a value measured here.
struct Form {
    const char* name;
    std::uint64_t derived;
    std::uint64_t rhs;
    std::uint8_t predicate;
    bool expect_bound;
};

std::vector<Form> Forms() {
    return {
        {"1:a+b==K", static_cast<std::uint32_t>(kFieldA + kFieldB), kMagic, kEq, true},
        {"2:a-b==K", static_cast<std::uint32_t>(kFieldA - kFieldB), kMagic, kEq, false},
        {"3:a^b==K", static_cast<std::uint32_t>(kFieldA ^ kFieldB), kMagic, kEq, false},
        {"4:a&b==K", static_cast<std::uint32_t>(kFieldA & kFieldB), kMagic, kEq, false},
        {"5:a*b==K", static_cast<std::uint32_t>(kFieldA * kFieldB), kMagic, kEq, false},
        {"6:a+C==K", static_cast<std::uint32_t>(kFieldA + 0x00000010U), kMagic, kEq, false},
        {"7:a<u b", kFieldA, kFieldB, kUlt, true},
    };
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
        case SolveOutcome::kUnsat:
            return "kUnsat";
        case SolveOutcome::kTimeout:
            return "kTimeout";
        case SolveOutcome::kNoBinding:
            return "kNoBinding";
        default:  // kError и kWidthOverflow (ADR 0049): здесь недостижим
            return "kError";
    }
    return "?";
}

// ---------------------------------------------------------------------
// CORPUS B — the false-composition grid, replayed verbatim.
// Constants and stream order are those of
// test_addvars_false_composition.cpp:344-462; any inserted or skipped
// rng.Next() would shift the whole tail of a cell and make the share
// incomparable with the pinned task-027 numbers.
// ---------------------------------------------------------------------

constexpr std::uint64_t kGeneratorSeed = 0x0027'0035ULL;
constexpr unsigned kTrials = 4096;
constexpr unsigned kMaxRedraws = 4096;
constexpr unsigned kPinTolerance = 2;  ///< counts; the pipeline is integer-deterministic
constexpr std::uint64_t kFreqMagic = 0xDEADBEEFULL;
constexpr std::uint64_t kFreqLow = 1;

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

// The add_vars counts MEASURED by task-027 and pinned in
// docs/experiments/solver-addvars-false-composition/report.md:153-161,226.
// Quoted here as the check that this replay really is the same stream: a
// divergence is a finding to be named in the report, not a licence to edit
// the other report.
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

// One cell of corpus B: the same tally the sample harness keeps, plus the
// D column. `d_true == add_vars + direct_var` by construction, and the
// test below asserts it rather than trusting the arithmetic.
struct CellTally {
    unsigned width = 0;
    unsigned vars = 0;
    unsigned trials = 0;
    unsigned add_vars = 0;      ///< false composition: a sum the program never computed
    unsigned direct_var = 0;    ///< verbatim collision: the drawn operand was in the seed
    unsigned lhs_const = 0;     ///< operand stayed constant, record survived anyway
    unsigned gate_dropped = 0;  ///< kConst on both sides — the gate left the path
    unsigned d_true = 0;        ///< D said "bound"; every one of them is wrong here
    unsigned redraws = 0;
    unsigned coincidence_ok = 0;  ///< the picked pair really does sum to the operand
    bool fixture_ok = true;

    [[nodiscard]] double d_rate() const {
        return trials == 0 ? 0.0 : static_cast<double>(d_true) / static_cast<double>(trials);
    }
    [[nodiscard]] double addvars_rate() const {
        return trials == 0 ? 0.0 : static_cast<double>(add_vars) / static_cast<double>(trials);
    }
};

// Copied from test_addvars_false_composition.cpp:421-441. The redraw rule
// is part of the stream: a rejected draft is re-drawn FROM THE SAME
// stream, so changing the rule changes every later trial of the cell.
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

// Copied from test_addvars_false_composition.cpp:443-462.
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

CellTally MeasureCell(const GridCell& cell) {
    CellTally out{.width = cell.width, .vars = cell.vars, .trials = kTrials};
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
        // from the fields by any addition — that is the whole premise, and
        // it is what makes every "bound" answer of D below an error.
        const std::uint64_t operand = TruncTo(rng.Next(), cell.width);
        const std::vector<BranchReader::Record> records = FreqRecords(cell, fields, operand);

        const System sys = BuildSystem(seed, records);
        const bool gate_survived = sys.path.size() == records.size();

        // When the gate is dropped its LHS Kind is not observable at all
        // (the record is gone); D is false through its second conjunct
        // whatever that Kind was, so the stand-in below cannot change the
        // answer. This is the corpus-B counterpart of the probe system
        // corpus A needs.
        const Operand::Kind derived_kind =
            gate_survived ? sys.path.back().lhs.kind : Operand::Kind::kConst;

        if (Discriminator(derived_kind, gate_survived)) {
            ++out.d_true;
        }

        if (!gate_survived) {
            ++out.gate_dropped;
            continue;
        }
        switch (derived_kind) {
            case Operand::Kind::kAddVars: {
                ++out.add_vars;
                const Operand& lhs = sys.path.back().lhs;
                if (sys.num_vars == fields.size() && lhs.var_index < fields.size() &&
                    lhs.var_index2 < fields.size() &&
                    TruncTo(fields[lhs.var_index] + fields[lhs.var_index2], cell.width) ==
                        operand) {
                    ++out.coincidence_ok;
                }
                break;
            }
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

void PrintCell(const CellTally& c) {
    std::cout << "BINDING-DISCRIMINATOR-B w" << c.width << "/v" << c.vars << " trials=" << c.trials
              << " d_true=" << c.d_true << " d_rate=" << std::fixed << std::setprecision(6)
              << c.d_rate() << std::defaultfloat << " add_vars=" << c.add_vars
              << " addvars_rate=" << std::fixed << std::setprecision(6) << c.addvars_rate()
              << std::defaultfloat << " direct_var=" << c.direct_var << " lhs_const=" << c.lhs_const
              << " gate_dropped=" << c.gate_dropped << " redraws=" << c.redraws
              << " coincidence_ok=" << c.coincidence_ok << std::endl;
}

}  // namespace

// CORPUS A. D is computed on all seven forms of the domain map and
// compared with the pinned classification. Every form prints its own line
// so the raw ctest log carries the table, not just the verdict.
TEST(BindingDiscriminator, ReproducesDomainMapOnSevenForms) {
    const std::vector<std::uint8_t> seed = Seed();
    unsigned separated = 0;
    unsigned bound_expected = 0;
    std::string disagreements;

    for (const Form& form : Forms()) {
        const FormCell cell =
            MeasureForm(seed, kFieldA, kFieldB, form.derived, form.rhs, form.predicate);
        const bool agrees = cell.discriminator == form.expect_bound;
        if (agrees) {
            ++separated;
        } else {
            disagreements += std::string(disagreements.empty() ? "" : ",") + form.name;
        }
        if (form.expect_bound) {
            ++bound_expected;
        }

        std::cout << "BINDING-DISCRIMINATOR-A form=" << form.name
                  << " derived_kind=" << KindName(cell.derived_kind)
                  << " gate_survived=" << (cell.gate_survived ? "true" : "false")
                  << " path_size=" << cell.path_size << " outcome=" << OutcomeName(cell.outcome)
                  << " D=" << (cell.discriminator ? "true" : "false")
                  << " pinned=" << (form.expect_bound ? "BOUND" : "NO-BINDING")
                  << " agrees=" << (agrees ? "true" : "false") << std::endl;

        // SolveOutcome is uniform across the whole map — that is exactly
        // why a discriminator is needed at all
        // (docs/experiments/solver-domain-map/report.md:138).
        EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate) << form.name;
    }

    std::cout << "BINDING-DISCRIMINATOR-A forms_separated=" << separated << "/7"
              << " disagreements=" << (disagreements.empty() ? "none" : disagreements)
              << " bound_expected=" << bound_expected << std::endl;

    EXPECT_EQ(bound_expected, 2U) << "corpus A must quote 2 BOUND / 5 NO-BINDING";
    EXPECT_EQ(separated, 7U) << "disagreeing forms: " << disagreements;
}

// The cell that is not a form. With disjoint bits xor IS the sum
// numerically, so form 3 splits in two (test_domain_map.cpp:200-209,
// docs/experiments/solver-domain-map/report.md:68). D calls this case
// "bound" — the first known cell where the mechanical predicate answers
// yes on a gate the hand-written map keeps out of the domain. It is a
// case inside form 3, so it is NOT part of the n/7 denominator.
TEST(BindingDiscriminator, XorWithDisjointBitsIsCalledBound) {
    constexpr std::uint32_t kDisjointA = 0x0F0F0F0FU;
    constexpr std::uint32_t kDisjointB = 0xF0F0F0F0U;
    static_assert((kDisjointA & kDisjointB) == 0U);

    const std::vector<std::uint8_t> disjoint_seed = SeedOf(kDisjointA, kDisjointB);
    const auto aliased = static_cast<std::uint32_t>(kDisjointA ^ kDisjointB);
    const FormCell cell = MeasureForm(disjoint_seed, kDisjointA, kDisjointB, aliased, kMagic, kEq);

    std::cout << "BINDING-DISCRIMINATOR-A form=3b:a^b(disjoint)"
              << " derived_kind=" << KindName(cell.derived_kind)
              << " gate_survived=" << (cell.gate_survived ? "true" : "false")
              << " D=" << (cell.discriminator ? "true" : "false")
              << " pinned=NO-BINDING(form 3) in_denominator=false" << std::endl;

    EXPECT_EQ(cell.derived_kind, Operand::Kind::kAddVars);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_TRUE(cell.discriminator);
}

// CORPUS B. The residual error: on this grid nothing is truly composed,
// so every "bound" answer of D is wrong by construction. The two ways it
// can be wrong are counted apart — add_vars is the false sum task-027
// measures, direct_var is the verbatim collision (mechanism M3,
// docs/experiments/solver-silent-loss-map/report.md:49).
TEST(BindingDiscriminator, FalseCompositionResidualError) {
    ASSERT_EQ(std::size(kGrid), std::size(kPins));

    unsigned d_by_width[3] = {0, 0, 0};
    unsigned trials_by_width[3] = {0, 0, 0};
    const unsigned widths[3] = {8, 16, 32};

    for (std::size_t i = 0; i < std::size(kGrid); ++i) {
        const GridCell& cell = kGrid[i];
        const Pin& pin = kPins[i];
        ASSERT_EQ(cell.width, pin.width);
        ASSERT_EQ(cell.vars, pin.vars);

        const CellTally c = MeasureCell(cell);
        PrintCell(c);

        ASSERT_TRUE(c.fixture_ok) << "w" << cell.width << "/v" << cell.vars
                                  << ": could not draw a valid seed within kMaxRedraws";

        // Accounting: nothing is lost between the four outcomes, and D is
        // exactly the union of the two that mean "tied to input bytes".
        EXPECT_EQ(c.add_vars + c.direct_var + c.lhs_const + c.gate_dropped, kTrials);
        EXPECT_EQ(c.d_true, c.add_vars + c.direct_var);
        // Every pair the search picked really does sum to the operand, so
        // add_vars is a genuine false composition and not a bookkeeping
        // slip (same self-check as
        // test_addvars_false_composition.cpp:666).
        EXPECT_EQ(c.coincidence_ok, c.add_vars);
        // The replay is the same stream as task-027's: if this diverges,
        // the divergence is the finding.
        EXPECT_NEAR(static_cast<double>(c.add_vars), static_cast<double>(pin.add_vars),
                    kPinTolerance)
            << "w" << cell.width << "/v" << cell.vars << " diverges from the pinned task-027 count";

        for (std::size_t w = 0; w < 3; ++w) {
            if (widths[w] == cell.width) {
                d_by_width[w] += c.d_true;
                trials_by_width[w] += c.trials;
            }
        }
    }

    // The verdict line asks for three numbers per width while the grid has
    // nine cells; both forms are printed, and the aggregate is explicitly
    // a mix of three different field counts.
    std::cout << "BINDING-DISCRIMINATOR-B false_bound_by_width";
    for (std::size_t w = 0; w < 3; ++w) {
        const double rate = trials_by_width[w] == 0 ? 0.0
                                                    : static_cast<double>(d_by_width[w]) /
                                                          static_cast<double>(trials_by_width[w]);
        std::cout << " w" << widths[w] << "=" << std::fixed << std::setprecision(6) << rate
                  << std::defaultfloat << "(" << d_by_width[w] << "/" << trials_by_width[w] << ")";
    }
    std::cout << " trials_per_cell=" << kTrials << std::endl;
}
