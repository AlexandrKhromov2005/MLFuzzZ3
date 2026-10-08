// Attribution of `kUnsat` to its two remaining forms, from the caller's side.
//
// The anatomy of `kUnsat` (task-024) left exactly two forms that can produce
// the observed profile: `aliased-offset` (cell (e),
// tests/unit/concolic/test_unsat_anatomy.cpp:326) and `width-overflow`
// (cell (f), tests/unit/concolic/test_unsat_anatomy.cpp:370). The open
// question is not their frequency on a live target — that needs counters
// nobody has — but whether the two are separable AT ALL by something the
// caller can already compute. This file answers that on a corpus where the
// form is known by construction.
//
// Ground truth is behavioural and is NEVER the feature under test. A cell is
// `aliased-offset` iff the same record shapes over a seed whose two fields
// hold DIFFERENT values solve, while over the aliased seed they do not. A
// cell is `width-overflow` iff the same record shapes with the bound moved
// one step inside the width solve, while at the width boundary they do not.
// Both definitions use only `SolveOutcome`; neither uses `num_vars`,
// `path.size()` or any operand width, so a discriminator built from those
// cannot be confirming its own premise.
//
// Three discriminators are measured, differing in ONE feature each:
//   W  — the inverted target demand is empty at the target's bit width.
//   A1 — `num_vars < path.size()`: some variable carries more than one
//        constraint (the observables named in the task statement).
//   A2 — the target variable's value occurs more than once in the seed, so
//        FindFirst (src/concolic/concolic.cpp:136-166) had a choice to get
//        wrong.
//   D1 = (W, A1), D2 = (W, A2), D3 = (W, A1 && A2).
//
// Zero edits to src/: every input of every feature is either a field of the
// `System` that BuildSystem already returns or the seed the caller itself
// passed in.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::VarBinding;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Constraint;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033), same three the anatomy uses.
enum : std::uint8_t { kEq = 0, kUle = 3, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;

// Determinism. Both corpora are drawn from this seed, this many accepted
// draws per cell. Changing either changes every ratio below, so both are
// constants of the file and are quoted in the report.
constexpr std::uint64_t kCorpusSeed = 0x5EED0040ULL;
constexpr unsigned kTrialsPerCell = 64;
constexpr unsigned kMaxDrawsPerTrial = 512;

// splitmix64: three lines, no library dependence, identical on every host.
class Prng {
   public:
    explicit Prng(std::uint64_t seed) : state_(seed) {}

    std::uint64_t Next() {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31U);
    }

    // Uniform on [lo, hi]; hi - lo + 1 never overflows here because the
    // widest cell is 32 bits.
    std::uint64_t InRange(std::uint64_t lo, std::uint64_t hi) {
        return lo + Next() % (hi - lo + 1ULL);
    }

   private:
    std::uint64_t state_;
};

std::uint64_t MaskOf(std::uint8_t bit_width) {
    return bit_width >= 64U ? ~0ULL : (1ULL << bit_width) - 1ULL;
}

std::uint64_t ReadAt(const std::vector<std::uint8_t>& buf, std::size_t at, std::uint8_t bit_width,
                     bool big_endian) {
    const unsigned bytes = bit_width / 8U;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < bytes; ++k) {
        const unsigned shift = big_endian ? 8U * (bytes - 1U - k) : 8U * k;
        value |= static_cast<std::uint64_t>(buf[at + k]) << shift;
    }
    return value;
}

void PutAt(std::vector<std::uint8_t>& buf, std::size_t at, std::uint64_t value,
           std::uint8_t bit_width) {
    for (unsigned k = 0; k < bit_width / 8U; ++k) {
        buf[at + k] = static_cast<std::uint8_t>(value >> (8U * k));
    }
}

// How many byte positions of `buf` read as `value` at `bit_width`, in either
// endianness. Both are counted because a binding carries `big_endian`
// (src/concolic/concolic.h:30-34) and either occurrence is a place FindFirst
// could have stopped.
std::size_t CountOccurrences(const std::vector<std::uint8_t>& buf, std::uint64_t value,
                             std::uint8_t bit_width) {
    const unsigned bytes = bit_width / 8U;
    if (buf.size() < bytes) {
        return 0;
    }
    std::size_t count = 0;
    for (std::size_t at = 0; at + bytes <= buf.size(); ++at) {
        if (ReadAt(buf, at, bit_width, false) == value ||
            ReadAt(buf, at, bit_width, true) == value) {
            ++count;
        }
    }
    return count;
}

// ---------------------------------------------------------------- feature W

std::int64_t SignExtend(std::uint64_t value, std::uint8_t bit_width) {
    if (bit_width >= 64U) {
        return static_cast<std::int64_t>(value);
    }
    const std::uint64_t sign = 1ULL << (bit_width - 1U);
    return static_cast<std::int64_t>((value ^ sign) - sign);
}

// The runtime ABI has ten comparison kinds (src/runtime/coverage/
// mlfuzzz3_branch.h:41-52). All ten are evaluated here, not only the three
// this corpus draws: an unknown predicate falling into a `default: return
// false` would make every demand look empty and forge the width signal.
bool KnownPredicate(std::uint8_t predicate) {
    return predicate <= 9U;
}

// Mirrors EvalPredicate (src/concolic/concolic.cpp:55-83). It has to: the
// path stores the predicate already turned to its as-taken direction
// (src/concolic/concolic.cpp:248-249), so a feature that read it any other
// way would be speaking about a different system.
bool Holds(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs, std::uint8_t bit_width) {
    const std::int64_t signed_lhs = SignExtend(lhs, bit_width);
    const std::int64_t signed_rhs = SignExtend(rhs, bit_width);
    switch (predicate) {
        case 0:
            return lhs == rhs;
        case 1:
            return lhs != rhs;
        case 2:
            return lhs < rhs;
        case 3:
            return lhs <= rhs;
        case 4:
            return lhs > rhs;
        case 5:
            return lhs >= rhs;
        case 6:
            return signed_lhs < signed_rhs;
        case 7:
            return signed_lhs <= signed_rhs;
        case 8:
            return signed_lhs > signed_rhs;
        case 9:
            return signed_lhs >= signed_rhs;
        default:
            return false;
    }
}

// Is {x in [0, mask] : Holds(...) == required} empty?
//
// For the three predicates used here the satisfying set is an interval, a
// point, or the complement of a point, so probing the five boundary
// candidates decides emptiness exactly — no 2^32 enumeration.
bool DemandIsEmpty(std::uint8_t predicate, std::uint64_t konst, bool var_on_lhs,
                   std::uint8_t bit_width, bool required) {
    if (!KnownPredicate(predicate)) {
        return false;
    }
    const std::uint64_t mask = MaskOf(bit_width);
    const std::uint64_t k = konst & mask;
    const std::uint64_t sign_min = bit_width >= 64U ? (1ULL << 63U) : (1ULL << (bit_width - 1U));
    const std::uint64_t candidates[] = {
        0ULL,
        mask,
        k,
        (k == 0ULL ? mask : k - 1ULL),
        ((k + 1ULL) & mask),
        sign_min,
        sign_min - 1ULL,
    };
    for (const std::uint64_t x : candidates) {
        const bool holds =
            var_on_lhs ? Holds(predicate, x, k, bit_width) : Holds(predicate, k, x, bit_width);
        if (holds == required) {
            return false;
        }
    }
    return true;
}

// W: inverting the target asks for a value the target's own width cannot
// hold. A pure function of the built constraint — predicate, bit width and
// the constant operand — and of nothing else.
bool InvertedTargetRangeIsEmpty(const Constraint& target) {
    const bool lhs_var = target.lhs.kind == Operand::Kind::kVar;
    const bool rhs_var = target.rhs.kind == Operand::Kind::kVar;
    if (lhs_var == rhs_var) {
        return false;  // not the var-vs-const shape this feature speaks about
    }
    const std::uint64_t konst = lhs_var ? target.rhs.const_value : target.lhs.const_value;
    // The path already carries the as-taken direction, so inverting the
    // target means demanding that this very predicate be FALSE. Asking the
    // question in both directions (as an earlier revision did) makes W fire
    // on every `x != k` gate and destroys the separation.
    return DemandIsEmpty(target.predicate, konst, lhs_var, target.bit_width, false);
}

// ------------------------------------------------------------- the features

struct Features {
    std::size_t num_records = 0;
    std::size_t path_size = 0;
    std::size_t dropped = 0;
    std::size_t num_vars = 0;
    std::uint8_t target_width = 0;
    bool width_demand_empty = false;      ///< W
    bool var_reuse = false;               ///< A1: num_vars < path.size()
    std::size_t target_multiplicity = 0;  ///< A2
    bool target_is_var_vs_const = false;  ///< domain precondition, not a feature
};

Features Extract(const System& sys, const std::vector<std::uint8_t>& seed,
                 std::size_t num_records) {
    Features features;
    features.num_records = num_records;
    features.path_size = sys.path.size();
    features.dropped = num_records - sys.path.size();
    features.num_vars = sys.num_vars;
    features.var_reuse = sys.num_vars < sys.path.size();
    if (sys.path.empty() || sys.target_index >= sys.path.size()) {
        return features;
    }
    const Constraint& target = sys.path[sys.target_index];
    features.target_width = target.bit_width;
    const bool lhs_var = target.lhs.kind == Operand::Kind::kVar;
    const bool rhs_var = target.rhs.kind == Operand::Kind::kVar;
    features.target_is_var_vs_const = lhs_var != rhs_var;
    features.width_demand_empty = InvertedTargetRangeIsEmpty(target);

    const Operand& var = lhs_var ? target.lhs : target.rhs;
    if (var.kind == Operand::Kind::kVar && var.var_index < sys.vars.size()) {
        const VarBinding& binding = sys.vars[var.var_index];
        if (binding.offset + binding.bit_width / 8U <= seed.size()) {
            const std::uint64_t value =
                ReadAt(seed, binding.offset, binding.bit_width, binding.big_endian);
            features.target_multiplicity = CountOccurrences(seed, value, binding.bit_width);
        }
    }
    return features;
}

enum class Form { kAliased, kWidthOverflow, kAmbiguous, kNeither };

const char* FormName(Form form) {
    switch (form) {
        case Form::kAliased:
            return "aliased";
        case Form::kWidthOverflow:
            return "width";
        case Form::kAmbiguous:
            return "ambiguous";
        case Form::kNeither:
            return "neither";
    }
    return "?";
}

Form Decide(bool width_signal, bool alias_signal) {
    if (width_signal && alias_signal) {
        return Form::kAmbiguous;
    }
    if (width_signal) {
        return Form::kWidthOverflow;
    }
    if (alias_signal) {
        return Form::kAliased;
    }
    return Form::kNeither;
}

Form D1(const Features& f) {
    return Decide(f.width_demand_empty, f.var_reuse);
}
Form D2(const Features& f) {
    return Decide(f.width_demand_empty, f.target_multiplicity > 1);
}
Form D3(const Features& f) {
    return Decide(f.width_demand_empty, f.var_reuse && f.target_multiplicity > 1);
}

// ------------------------------------------------------------------ corpora

// A1/A2 are aliased-offset shapes, B1..B4 width-overflow shapes. B2 exists to
// break A1 (one field, two constraints) and B4 to break A2 (a repeated value
// that is NOT the cause). Without those two variants the corpus would only
// show that a feature agrees with the family it was drawn for.
enum class Variant { kA1, kA2, kB1, kB2, kB3, kB4 };

struct Draw {
    std::vector<std::uint8_t> seed;
    std::vector<BranchReader::Record> records;
    std::vector<std::uint8_t> control_seed;
    std::vector<BranchReader::Record> control_records;
};

bool Absent(const std::vector<std::uint8_t>& seed, std::uint64_t value, std::uint8_t width) {
    return CountOccurrences(seed, value, width) == 0;
}

// Draws one trial of `variant` at `width`. Returns false when the draw
// violates a corpus invariant (a constant that would accidentally bind, a
// field multiplicity other than the intended one); the caller redraws and
// counts the rejection, so no rejection is silent.
bool BuildDraw(Variant variant, std::uint8_t width, Prng& prng, Draw& out) {
    const unsigned bytes = width / 8U;
    const std::uint64_t mask = MaskOf(width);
    // Field slots are spaced by two field widths. Adjacent placement makes
    // the big-endian window that straddles the two copies read as the field
    // itself at width 16, so the intended multiplicity of 2 could never be
    // drawn.
    const std::size_t slot1 = 2U * bytes;
    const std::size_t slot2 = 4U * bytes;
    const std::size_t len = 6U * bytes + 4U;
    const std::uint64_t width_max = mask;
    const std::uint64_t in_range = mask - 1ULL;

    const std::uint64_t field = prng.InRange(8ULL, mask - 4ULL);
    const std::uint64_t other = prng.InRange(8ULL, mask - 4ULL);
    const std::uint64_t third = prng.InRange(8ULL, mask - 4ULL);
    const std::uint64_t guard = prng.InRange(4ULL, field - 1ULL);
    const std::uint64_t gate = prng.InRange(0ULL, guard);
    const std::uint64_t low = prng.InRange(0ULL, third - 1ULL);
    if (other == field || third == field || third == other || other == gate) {
        return false;
    }

    std::vector<std::uint8_t> seed(len);
    for (std::size_t i = 0; i < len; ++i) {
        seed[i] = static_cast<std::uint8_t>(prng.InRange(1ULL, 250ULL));
    }

    const bool aliased = variant == Variant::kA1 || variant == Variant::kA2;
    const bool repeats = aliased || variant == Variant::kB4;
    const bool uses_third = variant == Variant::kA2 || variant == Variant::kB3;

    PutAt(seed, 0, field, width);
    if (repeats) {
        PutAt(seed, slot1, field, width);
    }
    if (uses_third) {
        PutAt(seed, variant == Variant::kA2 ? slot2 : slot1, third, width);
    }

    // For the width family the control runs over the SAME seed — only the
    // bound moves. That is what makes b4 a real stress: the repetition is
    // present in both runs, so it cannot be what the control removes.
    std::vector<std::uint8_t> control = seed;
    if (aliased) {
        // The aliased control differs in exactly one field: the second copy
        // holds a distinct value, so FindFirst has no choice left to get
        // wrong.
        PutAt(control, slot1, other, width);
    }

    const std::size_t want_field = repeats ? 2U : 1U;
    if (CountOccurrences(seed, field, width) != want_field) {
        return false;
    }
    if (aliased && (CountOccurrences(control, field, width) != 1U ||
                    CountOccurrences(control, other, width) != 1U)) {
        return false;
    }
    if (!aliased && CountOccurrences(control, field, width) != want_field) {
        return false;
    }
    if (uses_third && (CountOccurrences(seed, third, width) != 1U ||
                       CountOccurrences(control, third, width) != 1U)) {
        return false;
    }
    for (const std::uint64_t konst : {guard, gate, low, width_max, in_range}) {
        if (!Absent(seed, konst, width) || !Absent(control, konst, width)) {
            return false;
        }
    }

    out.seed = seed;
    out.control_seed = control;
    out.records.clear();
    out.control_records.clear();

    switch (variant) {
        case Variant::kA1:
            // guard on field 0 (true), gate on field 1 (false). Field 1 holds
            // the same value, so both bind to offset 0 and the guard forbids
            // what inverting the gate demands.
            out.records = {{0, kUgt, width, field, guard}, {1, kEq, width, field, gate}};
            out.control_records = {{0, kUgt, width, field, guard}, {1, kEq, width, other, gate}};
            break;
        case Variant::kA2:
            out.records = {{0, kUgt, width, field, guard},
                           {1, kUgt, width, third, low},
                           {2, kEq, width, field, gate}};
            out.control_records = {{0, kUgt, width, field, guard},
                                   {1, kUgt, width, third, low},
                                   {2, kEq, width, other, gate}};
            break;
        case Variant::kB1:
            out.records = {{0, kUle, width, field, width_max}};
            out.control_records = {{0, kUle, width, field, in_range}};
            break;
        case Variant::kB2:
            // One field, two constraints: num_vars < path.size() without any
            // aliasing at all.
            out.records = {{0, kUgt, width, field, guard}, {1, kUle, width, field, width_max}};
            out.control_records = {{0, kUgt, width, field, guard},
                                   {1, kUle, width, field, in_range}};
            break;
        case Variant::kB3:
            out.records = {{0, kUgt, width, third, low}, {1, kUle, width, field, width_max}};
            out.control_records = {{0, kUgt, width, third, low}, {1, kUle, width, field, in_range}};
            break;
        case Variant::kB4:
            // The value repeats, but the repetition is not the cause: the
            // control over the SAME seed solves.
            out.records = {{0, kUle, width, field, width_max}};
            out.control_records = {{0, kUle, width, field, in_range}};
            break;
    }
    return true;
}

// ------------------------------------------------------------- measurement

struct Tally {
    unsigned correct = 0;
    unsigned said_aliased = 0;
    unsigned said_width = 0;
    unsigned said_ambiguous = 0;
    unsigned said_neither = 0;

    void Add(Form said, Form truth) {
        if (said == truth) {
            ++correct;
        }
        switch (said) {
            case Form::kAliased:
                ++said_aliased;
                break;
            case Form::kWidthOverflow:
                ++said_width;
                break;
            case Form::kAmbiguous:
                ++said_ambiguous;
                break;
            case Form::kNeither:
                ++said_neither;
                break;
        }
    }
};

struct CellStats {
    std::string id;
    Form truth = Form::kNeither;
    std::uint8_t width = 0;
    unsigned trials = 0;
    unsigned rejected_draws = 0;
    unsigned ground_truth_ok = 0;  ///< main kUnsat AND control kCandidate
    unsigned domain_ok = 0;        ///< target is var-vs-const, nothing dropped
    unsigned main_not_unsat = 0;
    unsigned control_not_candidate = 0;
    Tally tally[3];
    Features first;
};

CellStats RunCell(const std::string& id, Variant variant, std::uint8_t width, Form truth,
                  std::uint64_t stream_seed) {
    Prng prng(stream_seed);
    CellStats cell;
    cell.id = id;
    cell.truth = truth;
    cell.width = width;

    while (cell.ground_truth_ok < kTrialsPerCell) {
        Draw draw;
        unsigned draws = 0;
        while (!BuildDraw(variant, width, prng, draw)) {
            ++cell.rejected_draws;
            if (++draws >= kMaxDrawsPerTrial) {
                return cell;  // starved: reported as trials < kTrialsPerCell
            }
        }
        ++cell.trials;
        if (cell.trials > kTrialsPerCell * kMaxDrawsPerTrial) {
            return cell;
        }

        SolveOutcome main_outcome = SolveOutcome::kError;
        const bool main_candidate =
            SolveForCandidate(draw.seed, draw.records, kTimeoutMs, &main_outcome).has_value();
        SolveOutcome control_outcome = SolveOutcome::kError;
        const bool control_candidate =
            SolveForCandidate(draw.control_seed, draw.control_records, kTimeoutMs, &control_outcome)
                .has_value();

        const bool main_unsat = main_outcome == SolveOutcome::kUnsat && !main_candidate;
        const bool control_solves =
            control_outcome == SolveOutcome::kCandidate && control_candidate;
        if (!main_unsat) {
            ++cell.main_not_unsat;
        }
        if (!control_solves) {
            ++cell.control_not_candidate;
        }
        if (!main_unsat || !control_solves) {
            continue;  // not a member of the corpus: its form is not established
        }
        ++cell.ground_truth_ok;

        const System sys = BuildSystem(draw.seed, draw.records);
        const Features features = Extract(sys, draw.seed, draw.records.size());
        if (cell.ground_truth_ok == 1U) {
            cell.first = features;
        }
        if (features.target_is_var_vs_const && features.dropped == 0U) {
            ++cell.domain_ok;
        }
        cell.tally[0].Add(D1(features), truth);
        cell.tally[1].Add(D2(features), truth);
        cell.tally[2].Add(D3(features), truth);
    }
    return cell;
}

double Ratio(unsigned part, unsigned whole) {
    return whole == 0U ? 0.0 : static_cast<double>(part) / static_cast<double>(whole);
}

std::vector<CellStats> RunAllCells() {
    struct Spec {
        const char* id;
        Variant variant;
        Form truth;
    };
    const Spec specs[] = {
        {"a1", Variant::kA1, Form::kAliased},       {"a2", Variant::kA2, Form::kAliased},
        {"b1", Variant::kB1, Form::kWidthOverflow}, {"b2", Variant::kB2, Form::kWidthOverflow},
        {"b3", Variant::kB3, Form::kWidthOverflow}, {"b4", Variant::kB4, Form::kWidthOverflow},
    };
    const std::uint8_t widths[] = {8, 16, 32};

    std::vector<CellStats> cells;
    std::uint64_t stream = kCorpusSeed;
    for (const Spec& spec : specs) {
        for (const std::uint8_t width : widths) {
            const std::string id = std::string(spec.id) + "-w" + std::to_string(width);
            cells.push_back(RunCell(id, spec.variant, width, spec.truth, stream));
            stream += 0x1000193ULL;
        }
    }

    for (const CellStats& cell : cells) {
        std::cout << "UNSAT-ATTR-CELL cell=" << cell.id << " truth=" << FormName(cell.truth)
                  << " width=" << static_cast<unsigned>(cell.width) << " trials=" << cell.trials
                  << " rejected_draws=" << cell.rejected_draws
                  << " ground_truth_ok=" << cell.ground_truth_ok
                  << " main_not_unsat=" << cell.main_not_unsat
                  << " control_not_candidate=" << cell.control_not_candidate
                  << " domain_ok=" << cell.domain_ok << " records=" << cell.first.num_records
                  << " path=" << cell.first.path_size << " dropped=" << cell.first.dropped
                  << " vars=" << cell.first.num_vars
                  << " W=" << (cell.first.width_demand_empty ? 1 : 0)
                  << " A1=" << (cell.first.var_reuse ? 1 : 0)
                  << " A2mult=" << cell.first.target_multiplicity
                  << " d1_correct=" << cell.tally[0].correct << '/' << cell.ground_truth_ok
                  << " d2_correct=" << cell.tally[1].correct << '/' << cell.ground_truth_ok
                  << " d3_correct=" << cell.tally[2].correct << '/' << cell.ground_truth_ok << '\n';
    }
    return cells;
}

const std::vector<CellStats>& Corpus() {
    static const std::vector<CellStats> cells = RunAllCells();
    return cells;
}

struct Summary {
    unsigned cells_separated = 0;
    unsigned cells_total = 0;
    unsigned trials_aliased = 0;
    unsigned trials_width = 0;
    unsigned width_called_aliased = 0;
    unsigned aliased_called_width = 0;
    unsigned ambiguous = 0;
    unsigned trials_total = 0;
};

Summary Aggregate(const std::vector<CellStats>& cells, unsigned which) {
    Summary summary;
    for (const CellStats& cell : cells) {
        const Tally& tally = cell.tally[which];
        ++summary.cells_total;
        if (cell.ground_truth_ok > 0U && tally.correct == cell.ground_truth_ok) {
            ++summary.cells_separated;
        }
        summary.trials_total += cell.ground_truth_ok;
        summary.ambiguous += tally.said_ambiguous;
        if (cell.truth == Form::kAliased) {
            summary.trials_aliased += cell.ground_truth_ok;
            summary.aliased_called_width += tally.said_width;
        } else {
            summary.trials_width += cell.ground_truth_ok;
            summary.width_called_aliased += tally.said_aliased;
        }
    }
    return summary;
}

void PrintSummary(const char* name, const Summary& summary) {
    std::cout << std::fixed << std::setprecision(6) << "UNSAT-ATTR-SUMMARY discriminator=" << name
              << " forms_separated=" << summary.cells_separated << '/' << summary.cells_total
              << " fp_aliased=" << Ratio(summary.width_called_aliased, summary.trials_width)
              << " fp_width=" << Ratio(summary.aliased_called_width, summary.trials_aliased)
              << " ambiguous=" << Ratio(summary.ambiguous, summary.trials_total)
              << " trials_per_cell=" << kTrialsPerCell << " trials=" << summary.trials_total
              << '\n';
}

}  // namespace

// The corpus is only a corpus if every cell really carries the form it
// claims, and that claim is behavioural: main unsat, control solvable. A cell
// that fails this proves nothing about any discriminator, so it is checked
// first and separately.
TEST(UnsatAttribution, BothCorporaCarryTheFormTheyClaimByConstruction) {
    const std::vector<CellStats>& cells = Corpus();
    ASSERT_EQ(cells.size(), 18U);
    for (const CellStats& cell : cells) {
        EXPECT_GE(cell.trials, kTrialsPerCell) << cell.id << ": draw starved";
        EXPECT_EQ(cell.ground_truth_ok, kTrialsPerCell)
            << cell.id << ": main_not_unsat=" << cell.main_not_unsat
            << " control_not_candidate=" << cell.control_not_candidate;
        EXPECT_EQ(cell.domain_ok, cell.ground_truth_ok)
            << cell.id << ": target is not the var-vs-const shape, or records were dropped";
    }
}

// The observable the task statement names first — the number of dropped
// records — is constant across BOTH forms here, so it carries no attribution
// at all. Stated as a test rather than as prose because it is the reason the
// discriminator had to be built from the other three.
TEST(UnsatAttribution, DroppedRecordCountIsConstantAcrossBothForms) {
    for (const CellStats& cell : Corpus()) {
        EXPECT_EQ(cell.first.dropped, 0U) << cell.id;
    }
}

// The measurement. Each discriminator is scored on the same trials.
TEST(UnsatAttribution, DiscriminatorSeparatesTheTwoFormsOfUnsat) {
    const std::vector<CellStats>& cells = Corpus();
    const Summary d1 = Aggregate(cells, 0);
    const Summary d2 = Aggregate(cells, 1);
    const Summary d3 = Aggregate(cells, 2);
    PrintSummary("D1-named-observables", d1);
    PrintSummary("D2-seed-multiplicity", d2);
    PrintSummary("D3-conjunction", d3);

    EXPECT_EQ(d3.cells_separated, d3.cells_total);
    EXPECT_EQ(d3.width_called_aliased, 0U);
    EXPECT_EQ(d3.aliased_called_width, 0U);
    EXPECT_EQ(d3.ambiguous, 0U);
}

// Negative control. A discriminator that is never wrong on the corpus it was
// drawn for has not been tested. B2 (one field, two constraints) breaks A1
// and B4 (a repeated value that is not the cause) breaks A2 — each on cells
// whose ground truth is width-overflow either way. Without these two cells
// the 18/18 above would be an artefact of the corpus, not a result.
TEST(UnsatAttribution, EachSingleAliasFeatureIsBrokenByAConstructedCell) {
    const std::vector<CellStats>& cells = Corpus();
    unsigned b2_cells = 0;
    unsigned b4_cells = 0;
    for (const CellStats& cell : cells) {
        if (cell.id.rfind("b2-", 0) == 0) {
            ++b2_cells;
            EXPECT_TRUE(cell.first.var_reuse) << cell.id << ": A1 was supposed to fire here";
            EXPECT_EQ(cell.first.target_multiplicity, 1U) << cell.id;
            EXPECT_EQ(cell.tally[0].correct, 0U) << cell.id << ": D1 was supposed to fail here";
            EXPECT_EQ(cell.tally[0].said_ambiguous, cell.ground_truth_ok) << cell.id;
            EXPECT_EQ(cell.tally[1].correct, cell.ground_truth_ok) << cell.id;
        }
        if (cell.id.rfind("b4-", 0) == 0) {
            ++b4_cells;
            EXPECT_FALSE(cell.first.var_reuse) << cell.id;
            EXPECT_EQ(cell.first.target_multiplicity, 2U)
                << cell.id << ": A2 was supposed to fire here";
            EXPECT_EQ(cell.tally[1].correct, 0U) << cell.id << ": D2 was supposed to fail here";
            EXPECT_EQ(cell.tally[1].said_ambiguous, cell.ground_truth_ok) << cell.id;
            EXPECT_EQ(cell.tally[0].correct, cell.ground_truth_ok) << cell.id;
        }
    }
    EXPECT_EQ(b2_cells, 3U);
    EXPECT_EQ(b4_cells, 3U);
}
