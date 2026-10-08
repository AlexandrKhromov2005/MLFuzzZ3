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

// The COST of variant §7(2) on kAddVars — "не композировать константу"
// (task-035, ADR 0035 §2).
//
// task-031 weighed the four variants of narrowing kAddVars listed in
// docs/experiments/solver-addvars-false-composition/report.md:255-278 and
// closed three of them. Variant (2) — "Запретить перебор пар для стороны,
// которая на исходной записи была константой сравнения" (:265-268) — it
// could only half-close, and it named the reason verbatim
// (docs/experiments/solver-addvars-width-threshold/report.md:219): there
// the true sum stands on `lhs`, `lhs` was never the comparison constant
// (`lhs_const == 0`), so the price of (2) in true sums is identically
// zero BY CONSTRUCTION of that harness and not by measurement. "Мерить
// (2) надо харнесом, где истинная сумма стоит на стороне, которая могла
// быть константой." This file is that harness.
//
// ONE thing differs from tests/unit/concolic/test_addvars_width_threshold_cost.cpp:
// the SIDE the true sum sits on. Grid, generator, generator KEY, kTrials,
// redraw cap, guard trace and gate constant are carried over byte for
// byte, so the two files draw the same seeds and the same operands and
// the only free variable left is the side. The gate there is
// `operand == MAGIC` (:..., lhs = true sum, rhs = the literal); here it
// is `MAGIC == operand` — the true sum now occupies the slot that the
// comparison constant occupied, which is the slot rule (2) refuses to
// compose.
//
// What rule (2) can actually see. `BranchReader::Record` carries two
// VALUES and no mark saying which of them was a literal in the source
// (src/coverage/branch_reader.h), and BindOperand is a pure function of
// (seed, value, width) with no idea of the side it is binding
// (src/concolic/concolic.cpp:180-207). So an implementable (2) has to
// pick the constant side by POSITION — the C convention `if (x == MAGIC)`
// puts the literal on the right — and that is the reading measured here:
// the pair search is refused for the rhs slot, the direct find
// (concolic.cpp:181-187) is not. A true sum that also occurs verbatim in
// the seed therefore still binds kVar and costs nothing; only kAddVars is
// destroyed.
//
// Two prices, because the rule has two clauses. Clause 1 downgrades the
// constant-slot operand to kConst — counted as `add_vars` below, every
// one of which is a genuinely true sum. Clause 2 ("Запись, где обе
// стороны связались только через перебор, отбрасывать") removes the
// record whole — counted as `both_composed`, which costs the constraint
// and not merely the connection.
//
// And the finding this harness exists to make visible: with the true sum
// on the constant slot, the literal MAGIC moves to the other slot, where
// a positional rule no longer reaches it. `magic_composed` below is the
// benefit of (2) that this placement DENIES it — the very false
// compositions (534 / 3 / 0 by width in task-031,
// docs/experiments/solver-addvars-width-threshold/report.md:222) it was
// invented to stop. Benefit and cost of (2) both follow the side, in
// opposite directions.
//
// Nothing in src/concolic or src/solver is touched: this measures the
// price of variant (2), it does not implement it. Which variant to adopt
// is the owner's call.

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

// Restatement of ReadField (src/concolic/concolic.cpp:117-126) at the
// binding's own width and endianness, as BindOperand reads it.
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
// The grid. Carried over from task-031
// (tests/unit/concolic/test_addvars_width_threshold_cost.cpp:160-186)
// WITHOUT the change of stream key that file made against task-027: the
// price of (2) is only comparable to the price of (1) if both are read
// off the same draws, so here the key stays 0x0031'0035 and the seeds are
// literally the same ones. That identity is not assumed, it is asserted —
// see ConstSideMirrorsTheLhsHarnessCountForCount.
// ===========================================================================

constexpr std::uint64_t kGeneratorSeed = 0x0031'0035ULL;  ///< task-031's key, kept on purpose
constexpr unsigned kTrials = 4096;                        ///< BuildSystem runs per cell
constexpr unsigned kMaxRedraws = 4096;                    ///< cap on fixture-invalid draws
constexpr unsigned kPinTolerance = 2;  ///< counts; the pipeline is integer-deterministic

constexpr std::uint64_t kFreqMagic = 0xDEADBEEFULL;
constexpr std::uint64_t kFreqLow = 1;

// splitmix64, reproduced rather than taken from <random>.
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

// One grid cell's tally. `add_vars` is the price of clause 1 and
// `both_composed` the price of clause 2; `magic_composed` is the benefit
// the placement takes away from the rule.
struct Cost {
    unsigned width = 0;
    unsigned vars = 0;
    unsigned trials = 0;
    unsigned add_vars = 0;        ///< constant slot bound kAddVars — a TRUE sum: clause 1's price
    unsigned true_pair = 0;       ///< ... of those, the pair the harness put there
    unsigned wrong_pair = 0;      ///< ... of those, a different pair that also satisfies
    unsigned self_pair = 0;       ///< ... of the wrong ones, a field added to itself (i == j)
    unsigned unindexed = 0;       ///< kAddVars whose indices do not index `fields`: see index_ok
    unsigned direct_var = 0;      ///< the sum occurred verbatim -> kVar; clause 1 does not touch it
    unsigned rhs_const = 0;       ///< constant slot composed nothing at all
    unsigned gate_dropped = 0;    ///< kConst on both sides -> gate left the path already today
    unsigned magic_composed = 0;  ///< the LITERAL, now off the constant slot, composed falsely
    unsigned both_composed = 0;   ///< both slots came from the pair search: clause 2's price
    unsigned redraws = 0;         ///< fixture-invalid draws discarded (see DrawFields)
    unsigned ambiguous = 0;       ///< trials where more than one pair satisfies the operand
    std::uint64_t pairs_total = 0;  ///< sum over trials of the independent pair count
    unsigned coincidence_ok = 0;    ///< self-check: the picked pair really sums to the operand
    unsigned index_ok = 0;          ///< self-check: pass 1 opened exactly the fields
    bool fixture_ok = true;         ///< false if a draw stayed invalid through kMaxRedraws

    [[nodiscard]] unsigned pairs() const {
        return vars * (vars + 1U) / 2U;
    }
    /// What clause 1 removes: every kAddVars on the constant slot, and by
    /// construction each of them binds a sum the program really computed.
    [[nodiscard]] unsigned lost_to_rule() const {
        return add_vars;
    }
    [[nodiscard]] double rate(unsigned count) const {
        return trials == 0 ? 0.0 : static_cast<double>(count) / static_cast<double>(trials);
    }
    [[nodiscard]] double mean_pairs() const {
        return trials == 0 ? 0.0 : static_cast<double>(pairs_total) / static_cast<double>(trials);
    }
};

// Draw `cell.vars` field values into a fresh seed. Carried over unchanged
// from task-031 (test_addvars_width_threshold_cost.cpp:266-290), itself
// carried from task-027: a draw is discarded and retaken from the SAME
// stream when it would not give the cell the shape it is named for.
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

// The trace the modelled program logs. The guards are task-031's
// (test_addvars_width_threshold_cost.cpp:292-311) unchanged; the gate is
// the same gate with its two sides EXCHANGED — `MAGIC == operand` instead
// of `operand == MAGIC`, so the true sum stands where the comparison
// constant stood and the literal stands where the derived operand stood.
// That exchange is the whole experiment.
std::vector<BranchReader::Record> ConstSideRecords(const GridCell& cell,
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
                       .lhs = TruncTo(kFreqMagic, cell.width),
                       .rhs = operand});
    return records;
}

struct FieldPair {
    std::size_t p;
    std::size_t q;
};

// Unchanged from task-031 (test_addvars_width_threshold_cost.cpp:322-334):
// only i < j is drawn, so every operand carries a CROSS-FIELD link, and
// self-pairs stay in BindOperand's candidate space where they can still
// win as the wrong pair.
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
// bindings with BindOperand's own truncation formula, j starting at i.
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
        const FieldPair pair = PickPair(rng, cell.vars);
        const std::uint64_t operand = TruncTo(fields[pair.p] + fields[pair.q], cell.width);
        const std::vector<BranchReader::Record> records = ConstSideRecords(cell, fields, operand);

        const System sys = BuildSystem(seed, records);
        const unsigned satisfying = PairsSatisfying(seed, sys.vars, cell.width, operand);
        out.pairs_total += satisfying;
        if (satisfying > 1U) {
            ++out.ambiguous;
        }
        if (sys.path.size() != records.size()) {
            ++out.gate_dropped;
            continue;
        }
        // The literal now sits on the LEFT. When it composes, that is the
        // false composition rule (2) exists to stop — and a positional
        // rule watching the constant SLOT does not see it here.
        const Operand& lit = sys.path.back().lhs;
        if (lit.kind == Operand::Kind::kAddVars) {
            ++out.magic_composed;
        }
        // The constant SLOT, which in this harness holds the true sum.
        const Operand& rhs = sys.path.back().rhs;
        if (lit.kind == Operand::Kind::kAddVars && rhs.kind == Operand::Kind::kAddVars) {
            ++out.both_composed;  // clause 2 would drop the record whole
        }
        switch (rhs.kind) {
            case Operand::Kind::kAddVars: {
                ++out.add_vars;
                const bool indexed = sys.num_vars == fields.size() &&
                                     rhs.var_index < fields.size() &&
                                     rhs.var_index2 < fields.size();
                if (!indexed) {
                    ++out.unindexed;
                    break;
                }
                ++out.index_ok;
                if (TruncTo(fields[rhs.var_index] + fields[rhs.var_index2], cell.width) ==
                    operand) {
                    ++out.coincidence_ok;
                }
                if (rhs.var_index == pair.p && rhs.var_index2 == pair.q) {
                    ++out.true_pair;
                } else {
                    ++out.wrong_pair;
                    if (rhs.var_index == rhs.var_index2) {
                        ++out.self_pair;
                    }
                }
                break;
            }
            case Operand::Kind::kVar:
                ++out.direct_var;
                break;
            case Operand::Kind::kConst:
                ++out.rhs_const;
                break;
        }
    }
    return out;
}

void PrintCost(const Cost& c) {
    std::cout << "ADDVARS-CONST-SIDE-COST w" << c.width << "/v" << c.vars << " trials=" << c.trials
              << " pairs=" << c.pairs() << " add_vars=" << c.add_vars
              << " true_pair=" << c.true_pair << " wrong_pair=" << c.wrong_pair
              << " self_pair=" << c.self_pair << " direct_var=" << c.direct_var
              << " rhs_const=" << c.rhs_const << " gate_dropped=" << c.gate_dropped
              << " magic_composed=" << c.magic_composed << " both_composed=" << c.both_composed
              << " unindexed=" << c.unindexed << " ambiguous=" << c.ambiguous
              << " redraws=" << c.redraws << std::fixed << std::setprecision(6)
              << " true_rate=" << c.rate(c.true_pair) << " wrong_rate=" << c.rate(c.wrong_pair)
              << " lost=" << c.lost_to_rule() << " lost_rate=" << c.rate(c.lost_to_rule())
              << " mean_pairs=" << c.mean_pairs() << std::defaultfloat << '\n';
}

// The measured tally per cell, pinned so that a later change of the
// encoding becomes visible. `true_pair`, `wrong_pair`, `direct_var` and
// `ambiguous` are ALSO the pins of task-031
// (test_addvars_width_threshold_cost.cpp:409-424): same key, same draws,
// and BindOperand is side-blind, so they must land on the same numbers.
// `magic_composed` and `both_composed` are this harness's own.
struct Pin {
    unsigned width;
    unsigned vars;
    unsigned true_pair;
    unsigned wrong_pair;
    unsigned direct_var;
    unsigned ambiguous;
    unsigned magic_composed;
    unsigned both_composed;
};

constexpr Pin kPins[] = {
    {.width = 8,
     .vars = 2,
     .true_pair = 4096,
     .wrong_pair = 0,
     .direct_var = 0,
     .ambiguous = 0,
     .magic_composed = 16,
     .both_composed = 16},
    {.width = 8,
     .vars = 4,
     .true_pair = 4057,
     .wrong_pair = 13,
     .direct_var = 26,
     .ambiguous = 45,
     .magic_composed = 84,
     .both_composed = 84},
    {.width = 8,
     .vars = 8,
     .true_pair = 3843,
     .wrong_pair = 142,
     .direct_var = 111,
     .ambiguous = 331,
     .magic_composed = 434,
     .both_composed = 420},
    {.width = 16,
     .vars = 2,
     .true_pair = 4096,
     .wrong_pair = 0,
     .direct_var = 0,
     .ambiguous = 0,
     .magic_composed = 1,
     .both_composed = 1},
    {.width = 16,
     .vars = 4,
     .true_pair = 4094,
     .wrong_pair = 0,
     .direct_var = 2,
     .ambiguous = 0,
     .magic_composed = 1,
     .both_composed = 1},
    {.width = 16,
     .vars = 8,
     .true_pair = 4094,
     .wrong_pair = 2,
     .direct_var = 0,
     .ambiguous = 3,
     .magic_composed = 1,
     .both_composed = 1},
    {.width = 32,
     .vars = 2,
     .true_pair = 4096,
     .wrong_pair = 0,
     .direct_var = 0,
     .ambiguous = 0,
     .magic_composed = 0,
     .both_composed = 0},
    {.width = 32,
     .vars = 4,
     .true_pair = 4096,
     .wrong_pair = 0,
     .direct_var = 0,
     .ambiguous = 0,
     .magic_composed = 0,
     .both_composed = 0},
    {.width = 32,
     .vars = 8,
     .true_pair = 4096,
     .wrong_pair = 0,
     .direct_var = 0,
     .ambiguous = 0,
     .magic_composed = 0,
     .both_composed = 0},
};

// MEASURED: with the true sum standing on the slot that used to hold the
// comparison constant, how much true cross-field structure variant §7(2)
// destroys. Every kAddVars counted here binds a sum the modelled program
// really computed, so clause 1's price is the raw `add_vars` count and
// clause 2's price is `both_composed` on top of it. `magic_composed` is
// the benefit the rule forfeits at this placement.
TEST(AddVarsConstSideCost, ConstSideRuleRemovesTrueCrossFieldSums) {
    ASSERT_EQ(std::size(kGrid), std::size(kPins));
    unsigned lost_w8 = 0;
    unsigned lost_w16 = 0;
    unsigned lost_w32 = 0;
    unsigned fires_w8 = 0;
    unsigned fires_w16 = 0;
    unsigned fires_w32 = 0;
    unsigned missed_magic_w8 = 0;
    unsigned missed_magic_w16 = 0;
    unsigned missed_magic_w32 = 0;
    for (std::size_t c = 0; c < std::size(kGrid); ++c) {
        const GridCell& cell = kGrid[c];
        const Pin& pin = kPins[c];
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        ASSERT_EQ(cell.width, pin.width);
        ASSERT_EQ(cell.vars, pin.vars);

        const Cost cost = MeasureCost(cell);
        PrintCost(cost);

        ASSERT_TRUE(cost.fixture_ok) << "no valid draw within " << kMaxRedraws << " attempts";
        // Every trial ended in exactly one of the outcomes the encoding
        // can produce for a true sum on the constant slot.
        EXPECT_EQ(
            cost.true_pair + cost.wrong_pair + cost.direct_var + cost.rhs_const + cost.gate_dropped,
            kTrials);
        EXPECT_EQ(cost.unindexed, 0U);
        EXPECT_EQ(cost.index_ok, cost.add_vars);
        EXPECT_EQ(cost.coincidence_ok, cost.add_vars);
        EXPECT_EQ(cost.true_pair + cost.wrong_pair, cost.add_vars);
        // Structural: the drawn pair satisfies the operand by
        // construction, so the constant slot never falls through to
        // kConst and the gate is never dropped for two constant sides.
        EXPECT_EQ(cost.rhs_const, 0U);
        EXPECT_EQ(cost.gate_dropped, 0U);
        // Clause 2 can only fire where clause 1 already did.
        EXPECT_LE(cost.both_composed, cost.add_vars);
        EXPECT_LE(cost.both_composed, cost.magic_composed);

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
        EXPECT_NEAR(static_cast<double>(cost.magic_composed),
                    static_cast<double>(pin.magic_composed), static_cast<double>(kPinTolerance))
            << "literal-composition count moved: pinned " << pin.magic_composed << ", measured "
            << cost.magic_composed << " of " << kTrials;
        EXPECT_NEAR(static_cast<double>(cost.both_composed), static_cast<double>(pin.both_composed),
                    static_cast<double>(kPinTolerance))
            << "both-sides-composed count moved: pinned " << pin.both_composed << ", measured "
            << cost.both_composed << " of " << kTrials;

        if (cell.width == 8U) {
            lost_w8 += cost.lost_to_rule();
            fires_w8 += cost.lost_to_rule();
            missed_magic_w8 += cost.magic_composed;
        } else if (cell.width == 16U) {
            lost_w16 += cost.lost_to_rule();
            fires_w16 += cost.lost_to_rule();
            missed_magic_w16 += cost.magic_composed;
        } else {
            lost_w32 += cost.lost_to_rule();
            fires_w32 += cost.lost_to_rule();
            missed_magic_w32 += cost.magic_composed;
        }
    }
    // The price of variant (2), in RAW counts out of the same kTrials per
    // cell that task-027 and task-031 used. On this harness every firing
    // of the rule destroys a true sum — the rule fires exactly as often
    // as it costs — while on task-031's placement it fired 534/3/0 times
    // at zero cost
    // (docs/experiments/solver-addvars-width-threshold/report.md:222).
    std::cout << "ADDVARS-CONST-SIDE-LOSS"
              << " true_pair_lost_w8=" << lost_w8 << " true_pair_lost_w16=" << lost_w16
              << " true_pair_lost_w32=" << lost_w32 << " rule_fires_w8=" << fires_w8
              << " rule_fires_w16=" << fires_w16 << " rule_fires_w32=" << fires_w32
              << " missed_magic_w8=" << missed_magic_w8 << " missed_magic_w16=" << missed_magic_w16
              << " missed_magic_w32=" << missed_magic_w32 << " cells=9 trials_per_cell=" << kTrials
              << " grid_trials=" << 9U * kTrials << '\n';
}

// The generator is the load-bearing part of the counts above: two
// independent measurements of the same cell must agree count for count.
TEST(AddVarsConstSideCost, ConstSideGridIsReproducible) {
    for (const GridCell& cell : kGrid) {
        SCOPED_TRACE(testing::Message() << "cell w" << cell.width << "/v" << cell.vars);
        const Cost first = MeasureCost(cell);
        const Cost again = MeasureCost(cell);
        EXPECT_EQ(first.true_pair, again.true_pair);
        EXPECT_EQ(first.wrong_pair, again.wrong_pair);
        EXPECT_EQ(first.direct_var, again.direct_var);
        EXPECT_EQ(first.gate_dropped, again.gate_dropped);
        EXPECT_EQ(first.magic_composed, again.magic_composed);
        EXPECT_EQ(first.both_composed, again.both_composed);
        EXPECT_EQ(first.ambiguous, again.ambiguous);
        EXPECT_EQ(first.pairs_total, again.pairs_total);
        EXPECT_EQ(first.redraws, again.redraws);
    }
}

// The premise, stated as a test: the pair the harness draws really does
// satisfy the operand it builds, on every cell, and the gate really does
// survive with the true sum on the constant slot.
TEST(AddVarsConstSideCost, DrawnPairAlwaysSatisfiesTheConstSlotOperand) {
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
        const std::vector<BranchReader::Record> records = ConstSideRecords(cell, fields, operand);
        const System sys = BuildSystem(seed, records);
        ASSERT_EQ(sys.num_vars, fields.size());
        ASSERT_EQ(sys.path.size(), records.size());
        EXPECT_GE(PairsSatisfying(seed, sys.vars, cell.width, operand), 1U);
        // The true sum is on the rhs — the slot the constant held in
        // task-031's gate — and it is what the pair search bound there.
        EXPECT_NE(sys.path.back().rhs.kind, Operand::Kind::kConst);
    }
}

// The experiment isolates ONE factor, so that has to be checkable: with
// the same key and the same draws, exchanging the two sides of the gate
// must move the binding to the other slot and change nothing else.
// BindOperand takes no side argument (src/concolic/concolic.cpp:180-183),
// so the counts here have to reproduce task-031's pins exactly — not
// within tolerance, count for count. If this test ever fails, the price
// of (2) below is not measured on the same population as the price of (1)
// and the two are not comparable.
TEST(AddVarsConstSideCost, ConstSideMirrorsTheLhsHarnessCountForCount) {
    // task-031's pins, quoted from
    // tests/unit/concolic/test_addvars_width_threshold_cost.cpp:409-424.
    struct LhsPin {
        unsigned true_pair;
        unsigned wrong_pair;
        unsigned direct_var;
        unsigned ambiguous;
    };
    constexpr LhsPin kLhsPins[] = {
        {.true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
        {.true_pair = 4057, .wrong_pair = 13, .direct_var = 26, .ambiguous = 45},
        {.true_pair = 3843, .wrong_pair = 142, .direct_var = 111, .ambiguous = 331},
        {.true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
        {.true_pair = 4094, .wrong_pair = 0, .direct_var = 2, .ambiguous = 0},
        {.true_pair = 4094, .wrong_pair = 2, .direct_var = 0, .ambiguous = 3},
        {.true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
        {.true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
        {.true_pair = 4096, .wrong_pair = 0, .direct_var = 0, .ambiguous = 0},
    };
    ASSERT_EQ(std::size(kGrid), std::size(kLhsPins));
    unsigned magic[3] = {0, 0, 0};
    for (std::size_t c = 0; c < std::size(kGrid); ++c) {
        SCOPED_TRACE(testing::Message() << "cell w" << kGrid[c].width << "/v" << kGrid[c].vars);
        const Cost cost = MeasureCost(kGrid[c]);
        EXPECT_EQ(cost.true_pair, kLhsPins[c].true_pair);
        EXPECT_EQ(cost.wrong_pair, kLhsPins[c].wrong_pair);
        EXPECT_EQ(cost.direct_var, kLhsPins[c].direct_var);
        EXPECT_EQ(cost.ambiguous, kLhsPins[c].ambiguous);
        magic[kGrid[c].width == 8U ? 0 : (kGrid[c].width == 16U ? 1 : 2)] += cost.magic_composed;
    }
    // The literal's own false compositions are side-blind too: task-031
    // counted them on the rhs slot and reported 534 / 3 / 0 by width
    // (docs/experiments/solver-addvars-width-threshold/report.md:222);
    // with the literal moved to the lhs slot the same three totals come
    // back. This is what makes "the rule no longer reaches them" a
    // statement about the RULE and not about a different population.
    EXPECT_EQ(magic[0], 534U);
    EXPECT_EQ(magic[1], 3U);
    EXPECT_EQ(magic[2], 0U);
}

}  // namespace
