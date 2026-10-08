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

// The COST of a bit-width threshold on kAddVars (task-031, ADR 0035 §2).
//
// task-027 measured the harm: over a grid of bit width x number of
// findable fields it ran BuildSystem on programs that never added
// anything and counted how often the pair search
// (src/concolic/concolic.cpp:195-205) invented a sum anyway
// (docs/experiments/solver-addvars-false-composition/report.md:151-162).
// Its remedy list proposes, among others, refusing to compose narrow
// operands — "Цена — потеря истинных сумм на 8/16 битах, объём которой не
// измерен" (report.md:261-264) — and refusing the FIRST satisfying pair
// when more than one satisfies it (report.md:269-272). Those two are the
// variants this file weighs; they live in that report, not in the ADR.
//
// This file is the mirror image of task-027's part (B). Same grid, same
// generator, same trial count, same gate; ONE thing differs, and it is the
// premise: the gate operand IS the truncated sum of two seed fields whose
// indices the harness knows in advance. Whatever the pair search binds
// here is a connection the program really contains, so every kAddVars
// counted below is what a width threshold would DESTROY, and the split
// between the intended pair and some other pair is what refusing an
// ambiguous choice would cost.
//
// Five outcomes, not two. A true sum can itself occur verbatim in the
// seed, and then BindOperand's direct branch (concolic.cpp:188-193) binds
// kVar before the pair search ever runs: no composition, but no loss from
// a threshold either. That is its own cell of the tally, not a failure to
// compose. The count of pairs that SATISFY the operand is not recoverable
// from `System` — BindOperand returns the first hit and keeps no
// candidate list (concolic.cpp:201-203) — so it is recomputed here by an
// independent loop over the public `System::vars` (src/concolic/concolic.h:41),
// replicating BindOperand's own truncation formula. Nothing in
// src/concolic or src/solver is touched: which variant of the remedy to
// adopt is the owner's call, and this file only supplies the second half
// of the scales.
//
// The two halves are NOT drawn from the same population: task-027's
// operand is random, this one is a true sum, so the gate survives here
// almost always and was dropped there almost always. The counts are
// comparable because the grid, the generator and kTrials are identical;
// the RATES are not probabilities of the same event and must not be
// combined into one accuracy figure.
//
// Everything here is a measurement: the tests assert the OBSERVED values,
// including the negative ones. A cell where the intended pair always wins
// is a measured result, not a failure.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::VarBinding;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUgt = 4 };

constexpr unsigned kBits = 8;

std::uint64_t TruncTo(std::uint64_t value, unsigned bit_width) {
    return bit_width >= 64U ? value : value & ((std::uint64_t{1} << bit_width) - 1U);
}

void PutField(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint64_t value,
              unsigned bit_width) {
    for (unsigned k = 0; k < bit_width / kBits; ++k) {
        buf[offset + k] = static_cast<std::uint8_t>(value >> (kBits * k));
    }
}

// Independent restatement of the substring search FindFirst performs
// (src/concolic/concolic.cpp:136-166), including its tie-break: ascending
// offset, little-endian before big-endian at the same offset. Used ONLY
// by the fixture checks.
struct SeedMatch {
    std::size_t offset;
    bool big_endian;
};

std::optional<SeedMatch> FirstMatch(const std::vector<std::uint8_t>& seed, std::uint64_t value,
                                    unsigned bit_width) {
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

bool Occurs(const std::vector<std::uint8_t>& seed, std::uint64_t value, unsigned bit_width) {
    return FirstMatch(seed, value, bit_width).has_value();
}

// Restatement of ReadField (src/concolic/concolic.cpp:117-126). The
// independent pair count MUST read a field exactly as BindOperand does —
// at the binding's own width and endianness, not at the comparison's —
// or it would count pairs the search never considered.
std::uint64_t ReadBoundField(const std::vector<std::uint8_t>& seed, const VarBinding& field) {
    const unsigned n = field.bit_width / kBits;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = field.big_endian ? (kBits * (n - 1U - k)) : (kBits * k);
        value |= static_cast<std::uint64_t>(seed[field.offset + k]) << shift;
    }
    return value;
}

// ===========================================================================
// The grid. Carried over from task-027 unchanged
// (tests/unit/concolic/test_addvars_false_composition.cpp:336-388,
// :414-462) so that the two measurements sit on one scale: same widths,
// same field counts, same splitmix64 stream shape, same trial count, same
// fixture rejection rule. Only the stream KEY differs, so that the two
// files do not draw identical seeds and accidentally look correlated.
// ===========================================================================

constexpr std::uint64_t kGeneratorSeed = 0x0031'0035ULL;  ///< task-031, ADR 0035
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

// One grid cell's tally. The measurement is the split of kAddVars into
// the intended pair and some other pair; the rest exists so the raw log
// can show that the cell counted what it claims to count.
struct Cost {
    unsigned width = 0;
    unsigned vars = 0;
    unsigned trials = 0;
    unsigned add_vars = 0;      ///< gate operand bound kAddVars — a TRUE sum, by construction
    unsigned true_pair = 0;     ///< ... of those, the pair the harness put there
    unsigned wrong_pair = 0;    ///< ... of those, a different pair that also satisfies: variant (3)
    unsigned self_pair = 0;     ///< ... of the wrong ones, a field added to itself (i == j)
    unsigned unindexed = 0;     ///< kAddVars whose indices do not index `fields`: see index_ok
    unsigned direct_var = 0;    ///< the sum occurred verbatim in the seed -> kVar, no pair search
    unsigned lhs_const = 0;     ///< no composition at all, yet the record survived
    unsigned gate_dropped = 0;  ///< kConst on both sides -> the gate left the path entirely
    unsigned magic_composed = 0;    ///< the gate CONSTANT was itself bound as a sum of fields
    unsigned redraws = 0;           ///< fixture-invalid draws discarded (see DrawFields)
    unsigned ambiguous = 0;         ///< trials where more than one pair satisfies the operand
    std::uint64_t pairs_total = 0;  ///< sum over trials of the independent pair count
    unsigned coincidence_ok = 0;    ///< self-check: the picked pair really sums to the operand
    unsigned index_ok = 0;          ///< self-check: pass 1 opened exactly the fields
    bool fixture_ok = true;         ///< false if a draw stayed invalid through kMaxRedraws

    [[nodiscard]] unsigned pairs() const {
        return vars * (vars + 1U) / 2U;
    }
    /// What a width threshold below `width` would remove: the pair search
    /// goes away whole, so a wrong pick is lost together with a right one.
    [[nodiscard]] unsigned lost_to_threshold() const {
        return true_pair + wrong_pair;
    }
    [[nodiscard]] double rate(unsigned count) const {
        return trials == 0 ? 0.0 : static_cast<double>(count) / static_cast<double>(trials);
    }
    [[nodiscard]] double mean_pairs() const {
        return trials == 0 ? 0.0 : static_cast<double>(pairs_total) / static_cast<double>(trials);
    }
};

// Draw `cell.vars` field values into a fresh seed. Carried over from
// task-027 (test_addvars_false_composition.cpp:414-441) unchanged: a draw
// is discarded and retaken from the SAME stream when it would not give
// the cell the shape it is named for. Discarding is about fixture
// validity, not about the phenomenon under measurement — nothing here
// inspects the operand or the chosen pair.
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

// The trace the modelled program logs: one guard per field, then the gate
// whose left side is the operand under study. Identical to task-027's
// FreqRecords (test_addvars_false_composition.cpp:443-462) — the trace
// shape must not be what distinguishes the two measurements.
std::vector<BranchReader::Record> CostRecords(const GridCell& cell,
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

// The pair the modelled program really added. Drawn from the same stream
// that task-027 spent on its random operand, so the two files consume the
// generator at the same rate. Only i < j is drawn: kAddVars exists to
// carry a CROSS-FIELD link (ADR 0035), and it is the cross-field link
// whose loss the owner is pricing. Self-pairs stay in BindOperand's
// candidate space and can still win as the WRONG pair — that is variant
// (3)'s subject and must not be defined away. For vars == 2 the pair is
// the only one there is, (0, 1).
struct FieldPair {
    std::size_t p;
    std::size_t q;
};

FieldPair PickPair(SplitMix64& rng, unsigned vars) {
    const unsigned count = vars * (vars - 1U) / 2U;
    unsigned index = static_cast<unsigned>(rng.Next() % count);
    for (unsigned i = 0; i < vars; ++i) {
        for (unsigned j = i + 1U; j < vars; ++j) {
            if (index == 0) {
                return FieldPair{.p = i, .q = j};
            }
            --index;
        }
    }
    return FieldPair{.p = 0, .q = 1};  // unreachable: index < count
}

// How many pairs satisfy the operand at all. `System` cannot answer this
// — BindOperand returns on the first hit and keeps no candidate list
// (concolic.cpp:201-203) — so the loop is repeated here over the public
// bindings, with BindOperand's own truncation formula
// (concolic.cpp:195-200) including j starting at i.
unsigned PairsSatisfying(const std::vector<std::uint8_t>& seed, const std::vector<VarBinding>& vars,
                         unsigned bit_width, std::uint64_t operand) {
    const std::uint64_t target = TruncTo(operand, bit_width);
    unsigned found = 0;
    for (std::size_t i = 0; i < vars.size(); ++i) {
        for (std::size_t j = i; j < vars.size(); ++j) {
            const std::uint64_t sum = TruncTo(TruncTo(ReadBoundField(seed, vars[i]), bit_width) +
                                                  TruncTo(ReadBoundField(seed, vars[j]), bit_width),
                                              bit_width);
            if (sum == target) {
                ++found;
            }
        }
    }
    return found;
}

Cost MeasureCost(const GridCell& cell) {
    Cost out{.width = cell.width, .vars = cell.vars, .trials = kTrials};
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
        // The operand the program handed to the gate. Here it IS computed
        // by adding two fields — that is the whole premise, and the exact
        // mirror of task-027, where it deliberately was not
        // (test_addvars_false_composition.cpp:481).
        const FieldPair pair = PickPair(rng, cell.vars);
        const std::uint64_t operand = TruncTo(fields[pair.p] + fields[pair.q], cell.width);
        const std::vector<BranchReader::Record> records = CostRecords(cell, fields, operand);

        const System sys = BuildSystem(seed, records);
        // Counted on every trial, whether or not the gate survived: it is
        // a property of the seed and the operand, not of the binding.
        const unsigned satisfying = PairsSatisfying(seed, sys.vars, cell.width, operand);
        out.pairs_total += satisfying;
        if (satisfying > 1U) {
            ++out.ambiguous;
        }
        if (sys.path.size() != records.size()) {
            // Both sides const -> BuildSystem drops the gate (boundary "B").
            ++out.gate_dropped;
            continue;
        }
        if (sys.path.back().rhs.kind == Operand::Kind::kAddVars) {
            ++out.magic_composed;
        }
        const Operand& lhs = sys.path.back().lhs;
        switch (lhs.kind) {
            case Operand::Kind::kAddVars: {
                ++out.add_vars;
                // Pass 1 walks offsets in ascending order, so var_index
                // indexes `fields` only when it opened exactly the fields
                // and nothing else. Checked rather than assumed: an
                // operand findable at a straddling offset would open an
                // extra variable and silently shift every index.
                const bool indexed = sys.num_vars == fields.size() &&
                                     lhs.var_index < fields.size() &&
                                     lhs.var_index2 < fields.size();
                if (!indexed) {
                    ++out.unindexed;
                    break;
                }
                ++out.index_ok;
                if (TruncTo(fields[lhs.var_index] + fields[lhs.var_index2], cell.width) ==
                    operand) {
                    ++out.coincidence_ok;
                }
                // BindOperand always returns i <= j, and the drawn pair is
                // p < q, so comparing the two ordered pairs compares the
                // UNORDERED pairs the two sides mean.
                if (lhs.var_index == pair.p && lhs.var_index2 == pair.q) {
                    ++out.true_pair;
                } else {
                    ++out.wrong_pair;
                    if (lhs.var_index == lhs.var_index2) {
                        ++out.self_pair;
                    }
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

// The raw ctest log is the evidence behind the report, so each cell prints
// its full tally and not merely whether the pin held.
void PrintCost(const Cost& c) {
    std::cout << "ADDVARS-WIDTH-THRESHOLD-COST w" << c.width << "/v" << c.vars
              << " trials=" << c.trials << " pairs=" << c.pairs() << " add_vars=" << c.add_vars
              << " true_pair=" << c.true_pair << " wrong_pair=" << c.wrong_pair
              << " self_pair=" << c.self_pair << " direct_var=" << c.direct_var
              << " lhs_const=" << c.lhs_const << " gate_dropped=" << c.gate_dropped
              << " magic_composed=" << c.magic_composed << " unindexed=" << c.unindexed
              << " ambiguous=" << c.ambiguous << " redraws=" << c.redraws << std::fixed
              << std::setprecision(6) << " true_rate=" << c.rate(c.true_pair)
              << " wrong_rate=" << c.rate(c.wrong_pair) << " lost=" << c.lost_to_threshold()
              << " lost_rate=" << c.rate(c.lost_to_threshold()) << " mean_pairs=" << c.mean_pairs()
              << std::defaultfloat << '\n';
}

// The measured tally per cell. These are OBSERVATIONS of the encoding as
// it stands today (ADR 0035, no width threshold anywhere: the only width
// check in the file is ByteWidthValid, concolic.cpp:37-39, and it guards
// FindFirst, not the pair search). Pinning them is what makes a later
// change in the encoding visible at all; a cell where the intended pair
// always wins is pinned on the same footing as one where it does not.
struct Pin {
    unsigned width;
    unsigned vars;
    unsigned true_pair;
    unsigned wrong_pair;
    unsigned direct_var;
    unsigned ambiguous;
};

constexpr Pin kPins[] = {
    {.width = 8, .vars = 2, .true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
    {.width = 8, .vars = 4, .true_pair = 4057, .wrong_pair = 13, .direct_var = 26, .ambiguous = 45},
    {.width = 8,
     .vars = 8,
     .true_pair = 3843,
     .wrong_pair = 142,
     .direct_var = 111,
     .ambiguous = 331},
    {.width = 16, .vars = 2, .true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
    {.width = 16, .vars = 4, .true_pair = 4094, .wrong_pair = 0, .direct_var = 2, .ambiguous = 0},
    {.width = 16, .vars = 8, .true_pair = 4094, .wrong_pair = 2, .direct_var = 0, .ambiguous = 3},
    {.width = 32, .vars = 2, .true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
    {.width = 32, .vars = 4, .true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
    {.width = 32, .vars = 8, .true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
};

// MEASURED: on programs that DO compute the gate operand by adding two
// fields, how much of that true cross-field structure a width threshold
// would take away. Every kAddVars counted here is a real connection, so
// the loss for a threshold W is the raw count over the cells narrower
// than W — the pair search is removed whole, taking the wrong picks with
// the right ones. The split into true_pair / wrong_pair is the separate
// price of variant (3), and `ambiguous` is how many trials that variant
// would refuse outright.
TEST(AddVarsWidthThresholdCost, WidthThresholdRemovesTrueCrossFieldSums) {
    ASSERT_EQ(std::size(kGrid), std::size(kPins));
    unsigned loss_thr16 = 0;
    unsigned loss_thr32 = 0;
    unsigned kept_thr32 = 0;
    for (std::size_t c = 0; c < std::size(kGrid); ++c) {
        const GridCell& cell = kGrid[c];
        const Pin& pin = kPins[c];
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        ASSERT_EQ(cell.width, pin.width);
        ASSERT_EQ(cell.vars, pin.vars);

        const Cost cost = MeasureCost(cell);
        PrintCost(cost);

        ASSERT_TRUE(cost.fixture_ok) << "no valid draw within " << kMaxRedraws << " attempts";
        // Nothing is unaccounted for: every trial ended in exactly one of
        // the five outcomes the encoding can produce for a true sum.
        EXPECT_EQ(
            cost.true_pair + cost.wrong_pair + cost.direct_var + cost.lhs_const + cost.gate_dropped,
            kTrials);
        // Harness self-checks. Pass 1 must have opened exactly the fields
        // whenever the pair search won, or the index comparison that
        // separates true_pair from wrong_pair would be comparing indices
        // into different things; and whatever pair the search claimed must
        // really sum to the operand.
        EXPECT_EQ(cost.unindexed, 0U);
        EXPECT_EQ(cost.index_ok, cost.add_vars);
        EXPECT_EQ(cost.coincidence_ok, cost.add_vars);
        EXPECT_EQ(cost.true_pair + cost.wrong_pair, cost.add_vars);
        // Structural, and the sharpest contrast with task-027: the drawn
        // pair satisfies the operand by construction, so the pair search
        // can never fall through to kConst on the left side, and the gate
        // can never be dropped for having two constant sides. Where
        // task-027 lost the gate in 3058-4096 of 4096 trials per cell
        // (report.md:151-162), here it survives every time. This is why
        // the two halves of the trade-off table share a numerator scale
        // and not a denominator.
        EXPECT_EQ(cost.lhs_const, 0U);
        EXPECT_EQ(cost.gate_dropped, 0U);

        EXPECT_NEAR(static_cast<double>(cost.true_pair), static_cast<double>(pin.true_pair),
                    static_cast<double>(kPinTolerance))
            << "true-pair count moved: pinned " << pin.true_pair << ", measured " << cost.true_pair
            << " of " << kTrials;
        EXPECT_NEAR(static_cast<double>(cost.wrong_pair), static_cast<double>(pin.wrong_pair),
                    static_cast<double>(kPinTolerance))
            << "wrong-pair count moved: pinned " << pin.wrong_pair << ", measured "
            << cost.wrong_pair << " of " << kTrials;
        EXPECT_NEAR(static_cast<double>(cost.direct_var), static_cast<double>(pin.direct_var),
                    static_cast<double>(kPinTolerance))
            << "verbatim-binding count moved: pinned " << pin.direct_var << ", measured "
            << cost.direct_var << " of " << kTrials;
        EXPECT_NEAR(static_cast<double>(cost.ambiguous), static_cast<double>(pin.ambiguous),
                    static_cast<double>(kPinTolerance))
            << "ambiguous-operand count moved: pinned " << pin.ambiguous << ", measured "
            << cost.ambiguous << " of " << kTrials;

        if (cell.width < 16U) {
            loss_thr16 += cost.lost_to_threshold();
        }
        if (cell.width < 32U) {
            loss_thr32 += cost.lost_to_threshold();
        } else {
            kept_thr32 += cost.lost_to_threshold();
        }
    }
    // The right-hand side of the trade-off table, in RAW counts out of the
    // same kTrials per cell that task-027 used. The left-hand side (the
    // false compositions the same threshold removes) is quoted from
    // docs/experiments/solver-addvars-false-composition/report.md:151-162
    // and is deliberately NOT recomputed here: the two halves are drawn
    // from different populations and only the counts are comparable.
    std::cout << "ADDVARS-WIDTH-THRESHOLD-LOSS"
              << " loss_thr16=" << loss_thr16 << " loss_thr32=" << loss_thr32
              << " kept_thr32=" << kept_thr32 << " cells_below16=3 cells_below32=6"
              << " trials_per_cell=" << kTrials << '\n';
}

// The generator is the load-bearing part of the counts above: if it were
// not reproducible, the pins would be noise. Two independent measurements
// of the same cell must agree exactly, count for count.
TEST(AddVarsWidthThresholdCost, CostGridIsReproducible) {
    for (const GridCell& cell : kGrid) {
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        const Cost first = MeasureCost(cell);
        const Cost again = MeasureCost(cell);
        EXPECT_EQ(first.true_pair, again.true_pair);
        EXPECT_EQ(first.wrong_pair, again.wrong_pair);
        EXPECT_EQ(first.direct_var, again.direct_var);
        EXPECT_EQ(first.gate_dropped, again.gate_dropped);
        EXPECT_EQ(first.magic_composed, again.magic_composed);
        EXPECT_EQ(first.ambiguous, again.ambiguous);
        EXPECT_EQ(first.pairs_total, again.pairs_total);
        EXPECT_EQ(first.redraws, again.redraws);
    }
}

// The premise itself, stated as a test rather than left to the comment:
// the pair the harness draws really does satisfy the operand it builds,
// on every cell. If this ever fails, the "true sum" in every count above
// was not a true sum and the whole measurement means nothing.
TEST(AddVarsWidthThresholdCost, DrawnPairAlwaysSatisfiesTheOperand) {
    for (const GridCell& cell : kGrid) {
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        SplitMix64 rng(StreamSeed(cell));
        std::vector<std::uint64_t> fields;
        std::vector<std::uint8_t> seed;
        ASSERT_TRUE(DrawFields(rng, cell, fields, seed));
        const FieldPair pair = PickPair(rng, cell.vars);
        ASSERT_LT(pair.p, pair.q);
        ASSERT_LT(pair.q, fields.size());
        const std::uint64_t operand = TruncTo(fields[pair.p] + fields[pair.q], cell.width);
        const std::vector<BranchReader::Record> records = CostRecords(cell, fields, operand);
        const System sys = BuildSystem(seed, records);
        ASSERT_EQ(sys.num_vars, fields.size());
        // At least the drawn pair satisfies it, by construction.
        EXPECT_GE(PairsSatisfying(seed, sys.vars, cell.width, operand), 1U);
    }
}

}  // namespace
