// task-066: where the third variable is lost when the field order is mirrored.
//
// task-059 measured binding arity on a twelve-cell grid and recorded, without
// explaining it, that five of the six MIRRORED cells collapsed: BuildSystem
// returned two variables (once one) where three fields were intended
// (docs/experiments/solver-binding-overlap-arity/report.md:191-193; the grid
// number is cells_with_three_bindings=7 of 12 at report.md:104).
//
// This harness does not re-measure the collapse — that fact is already on
// record. It locates the STEP at which the third variable disappears. Per cell
// it prints the three INTENDED bindings with their byte ranges, how each pair
// of them intersects, how many trace records were built and how many survived
// into System::path, the resulting num_vars, and — for every intended field
// left without a binding of its own — the variable it merged into and the
// feature by which it merged.
//
// The rule under test is COMPUTED from the layout, never read off task-059's
// table: num_vars == |{ distinct starting offsets of the intended fields }|.
// Its justification is the binding contract itself — a variable index
// "corresponds to the byte OFFSET (not the value)" (src/concolic/concolic.h:26-28)
// — so two intended fields that start at the same offset are indistinguishable
// to the binder and share one variable whatever their widths. Every cell
// asserts the prediction against the observation, so a wrong rule fails here
// instead of being narrated in a report.
//
// Layouts come from tests/unit/concolic/test_binding_overlap_arity.cpp:553-575
// (Grid()) through Mirror() (:284-295), copied here with the Collapse suffix:
// that file is neither modified nor included, and all files of
// tests/unit/concolic link into one binary.
//
// src/ is not modified. The task explains BuildSystem; changing its behaviour
// is the owner's decision, and none is proposed here.

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
using mlfuzzz3::solver::SolveInverted;
using mlfuzzz3::solver::SolveResult;

enum : std::uint8_t {
    kEqCollapse = 0,
    kNeCollapse = 1,
    kUltCollapse = 2,
    kUleCollapse = 3,
    kUgtCollapse = 4,
    kUgeCollapse = 5
};

constexpr unsigned kBitsPerByteCollapse = 8;
constexpr unsigned kTimeoutMsCollapse = 5000;
constexpr std::size_t kSeedSizeCollapse = 16;
constexpr std::size_t kArityCollapse = 3;

// The task-053 seed, byte for byte, as task-059 used it
// (tests/unit/concolic/test_binding_overlap_arity.cpp:78-79). Reused verbatim
// so every number here is comparable with the accepted task-059 numbers.
constexpr std::array<std::uint8_t, kSeedSizeCollapse> kSeedCollapse = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

constexpr std::uint64_t kTarget32Collapse = 0x11223344ULL;
constexpr std::uint64_t kTarget64Collapse = 0x1122334455667788ULL;

std::vector<std::uint8_t> SeedCollapse() {
    return {kSeedCollapse.begin(), kSeedCollapse.end()};
}

std::uint64_t ReadLeCollapse(const std::vector<std::uint8_t>& bytes, std::size_t offset,
                             unsigned n) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (kBitsPerByteCollapse * k);
    }
    return value;
}

const char* YesNoCollapse(bool value) {
    return value ? "yes" : "no";
}

const char* StatusNameCollapse(SolveResult::Status status) {
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
    return "kUnknown";
}

const char* OutcomeNameCollapse(SolveOutcome outcome) {
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
    return "kUnknown";
}

std::string RangeCollapse(std::size_t lo, std::size_t hi) {
    std::ostringstream out;
    out << "[" << lo << "," << hi << ")";
    return out.str();
}

// ---------------------------------------------------------------------------
// Layout, verbatim from test_binding_overlap_arity.cpp:262-295 with the
// Collapse suffix. A field is (offset, width-in-bits); the FIRST field carries
// the target comparison, every other field is pinned by two guards.
// ---------------------------------------------------------------------------

struct FieldCollapse {
    std::size_t offset;
    unsigned bits;
};

struct LayoutCollapse {
    std::string id;
    std::string topology;  // chain | star | nested
    std::string widths;    // "u32+u16+u8"
    std::string order;     // direct | mirrored
    std::vector<FieldCollapse> fields;
};

std::size_t EndOfCollapse(const FieldCollapse& f) {
    return f.offset + f.bits / kBitsPerByteCollapse;
}

// Mirror the layout inside [0, L): offset -> L - offset - width. Preserves
// every pairwise intersection SIZE while reversing the spatial order of the
// fields. Note what it does not preserve: distinct starting offsets. That is
// the whole subject of this file.
std::vector<FieldCollapse> MirrorCollapse(const std::vector<FieldCollapse>& fields) {
    std::size_t span = 0;
    for (const FieldCollapse& f : fields) {
        span = std::max(span, EndOfCollapse(f));
    }
    std::vector<FieldCollapse> out;
    out.reserve(fields.size());
    for (const FieldCollapse& f : fields) {
        out.push_back({span - EndOfCollapse(f), f.bits});
    }
    return out;
}

// Two guards per non-target field, then the target on field 0 last, so the
// target is the constraint the inversion flips
// (test_binding_overlap_arity.cpp:297-325).
std::vector<BranchReader::Record> MakeRecordsCollapse(const std::vector<FieldCollapse>& fields) {
    const std::vector<std::uint8_t> seed = SeedCollapse();
    std::vector<BranchReader::Record> records;
    std::uint32_t site = 1;
    for (std::size_t i = 1; i < fields.size(); ++i) {
        const std::uint64_t v =
            ReadLeCollapse(seed, fields[i].offset, fields[i].bits / kBitsPerByteCollapse);
        records.push_back({.site_id = site++,
                           .predicate = kUgtCollapse,
                           .bit_width = static_cast<std::uint8_t>(fields[i].bits),
                           .lhs = v,
                           .rhs = v - 1U});
        records.push_back({.site_id = site++,
                           .predicate = kUltCollapse,
                           .bit_width = static_cast<std::uint8_t>(fields[i].bits),
                           .lhs = v,
                           .rhs = v + 1U});
    }
    const std::uint64_t a =
        ReadLeCollapse(seed, fields[0].offset, fields[0].bits / kBitsPerByteCollapse);
    const std::uint64_t target = fields[0].bits == 64U ? kTarget64Collapse : kTarget32Collapse;
    records.push_back({.site_id = site,
                       .predicate = kEqCollapse,
                       .bit_width = static_cast<std::uint8_t>(fields[0].bits),
                       .lhs = a,
                       .rhs = target});
    return records;
}

LayoutCollapse MakeCollapse(const std::string& topology, const std::string& widths,
                            const std::string& order, std::vector<FieldCollapse> fields) {
    if (order == "mirrored") {
        fields = MirrorCollapse(fields);
    }
    return {topology + "/" + widths + "/" + order, topology, widths, order, std::move(fields)};
}

// The task-059 grid, verbatim (test_binding_overlap_arity.cpp:553-575): six
// layouts in each of the two field orders.
std::vector<LayoutCollapse> GridCollapse() {
    std::vector<LayoutCollapse> grid;
    for (const std::string& order : {std::string("direct"), std::string("mirrored")}) {
        grid.push_back(MakeCollapse("chain", "u32+u16+u8", order, {{0, 32}, {3, 16}, {4, 8}}));
        grid.push_back(MakeCollapse("chain", "u64+u32+u16", order, {{0, 64}, {6, 32}, {8, 16}}));
        grid.push_back(MakeCollapse("star", "u32+u16+u8", order, {{0, 32}, {2, 16}, {3, 8}}));
        grid.push_back(MakeCollapse("star", "u64+u32+u16", order, {{0, 64}, {4, 32}, {7, 16}}));
        grid.push_back(MakeCollapse("nested", "u32+u16+u8", order, {{0, 32}, {1, 16}, {2, 8}}));
        grid.push_back(MakeCollapse("nested", "u64+u32+u16", order, {{0, 64}, {2, 32}, {3, 16}}));
    }
    return grid;
}

std::vector<LayoutCollapse> OrderCollapse(const std::string& order) {
    std::vector<LayoutCollapse> rows;
    for (const LayoutCollapse& layout : GridCollapse()) {
        if (layout.order == order) {
            rows.push_back(layout);
        }
    }
    return rows;
}

// ---------------------------------------------------------------------------
// What one cell records. Everything below is measured off the INTENDED fields
// on one side and off System::vars on the other; nothing is assumed to agree.
// ---------------------------------------------------------------------------

struct IntendedPairCollapse {
    std::size_t i;
    std::size_t j;
    std::size_t lo;
    std::size_t hi;  // hi > lo == non-empty
    std::string relation;
};

struct IntendedFieldCollapse {
    std::size_t i;
    std::size_t offset;
    unsigned bits;
    bool bound;
    std::size_t var;  // meaningful only when bound
};

struct LostCollapse {
    std::size_t i;
    std::size_t offset;
    unsigned bits;
    bool merged_named;
    std::size_t merged_with;  // index of the intended field that kept the variable
    std::size_t merged_var;
    std::string reason;
};

struct CellCollapse {
    LayoutCollapse layout;
    std::size_t records_built = 0;
    std::size_t records_seen = 0;  // == System::path.size()
    std::size_t num_vars = 0;
    std::size_t target_index = 0;
    bool invertible = false;
    std::size_t distinct_offsets = 0;
    std::size_t rule_predicts = 0;
    bool rule_matches = false;
    bool collapse = false;
    std::size_t vars_lost = 0;
    SolveResult::Status status = SolveResult::Status::kError;
    SolveOutcome outcome = SolveOutcome::kNoBinding;
    bool has_candidate = false;
    std::vector<IntendedPairCollapse> pairs;
    std::vector<IntendedFieldCollapse> fields;
    std::vector<LostCollapse> lost;
    std::vector<VarBinding> vars;
};

// How two intended ranges meet. same_offset is checked FIRST and on purpose:
// it is the feature the collapse rule is built on, and it must not be hidden
// behind the coarser "nested" or "identical" labels.
std::string RelationCollapse(const FieldCollapse& a, const FieldCollapse& b) {
    const std::size_t a_hi = EndOfCollapse(a);
    const std::size_t b_hi = EndOfCollapse(b);
    if (a.offset == b.offset) {
        return a_hi == b_hi ? "identical" : "same_offset";
    }
    const std::size_t lo = std::max(a.offset, b.offset);
    const std::size_t hi = std::min(a_hi, b_hi);
    if (hi <= lo) {
        return hi == lo ? "touching" : "disjoint";
    }
    if ((a.offset <= b.offset && b_hi <= a_hi) || (b.offset <= a.offset && a_hi <= b_hi)) {
        return "nested";
    }
    return "partial";
}

CellCollapse MeasureCollapse(const LayoutCollapse& layout) {
    CellCollapse cell;
    cell.layout = layout;

    const std::vector<std::uint8_t> seed = SeedCollapse();
    const std::vector<BranchReader::Record> records = MakeRecordsCollapse(layout.fields);
    const System sys = BuildSystem(seed, records);

    cell.records_built = records.size();
    cell.records_seen = sys.path.size();
    cell.num_vars = sys.num_vars;
    cell.target_index = sys.target_index;
    cell.invertible = sys.invertible;
    cell.vars = sys.vars;

    // The rule, computed from the layout alone — before a single variable of
    // the system is looked at.
    std::vector<std::size_t> offsets;
    for (const FieldCollapse& f : layout.fields) {
        if (std::find(offsets.begin(), offsets.end(), f.offset) == offsets.end()) {
            offsets.push_back(f.offset);
        }
    }
    cell.distinct_offsets = offsets.size();
    cell.rule_predicts = offsets.size();
    cell.rule_matches = cell.rule_predicts == cell.num_vars;
    cell.collapse = cell.num_vars < layout.fields.size();

    for (std::size_t i = 0; i < layout.fields.size(); ++i) {
        for (std::size_t j = i + 1; j < layout.fields.size(); ++j) {
            const std::size_t lo = std::max(layout.fields[i].offset, layout.fields[j].offset);
            const std::size_t hi =
                std::min(EndOfCollapse(layout.fields[i]), EndOfCollapse(layout.fields[j]));
            cell.pairs.push_back(
                {i, j, lo, std::max(lo, hi), RelationCollapse(layout.fields[i], layout.fields[j])});
        }
    }

    // An intended field is bound only when a variable carries BOTH its offset
    // and its width; a variable at the same offset with another width is a
    // different field's variable, and this field merged into it.
    for (std::size_t i = 0; i < layout.fields.size(); ++i) {
        IntendedFieldCollapse fact{i, layout.fields[i].offset, layout.fields[i].bits, false, 0};
        for (std::size_t k = 0; k < sys.vars.size(); ++k) {
            if (sys.vars[k].offset == layout.fields[i].offset &&
                sys.vars[k].bit_width == layout.fields[i].bits) {
                fact.bound = true;
                fact.var = k;
                break;
            }
        }
        cell.fields.push_back(fact);
    }

    for (const IntendedFieldCollapse& fact : cell.fields) {
        if (fact.bound) {
            continue;
        }
        ++cell.vars_lost;
        LostCollapse lost{fact.i, fact.offset, fact.bits, false, 0, 0, "unexplained"};
        for (std::size_t k = 0; k < sys.vars.size(); ++k) {
            if (sys.vars[k].offset != fact.offset) {
                continue;
            }
            // Name the sibling that kept the variable, not just the variable.
            for (const IntendedFieldCollapse& other : cell.fields) {
                if (other.bound && other.var == k) {
                    lost.merged_named = true;
                    lost.merged_with = other.i;
                    lost.merged_var = k;
                    lost.reason = "same_offset_different_width";
                    break;
                }
            }
            break;
        }
        cell.lost.push_back(lost);
    }

    if (sys.invertible) {
        const SolveResult result =
            SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMsCollapse);
        cell.status = result.status;
    }
    SolveOutcome outcome = SolveOutcome::kNoBinding;
    const std::optional<mlfuzzz3::mutation::FuzzInput> engine =
        SolveForCandidate(seed, records, kTimeoutMsCollapse, &outcome);
    cell.outcome = outcome;
    cell.has_candidate = engine.has_value();
    return cell;
}

void PrintCellCollapse(const char* tag, const CellCollapse& cell) {
    std::cout << tag << " id=" << cell.layout.id << " topology=" << cell.layout.topology
              << " widths=" << cell.layout.widths << " order=" << cell.layout.order
              << " k=" << cell.layout.fields.size();
    for (std::size_t i = 0; i < cell.layout.fields.size(); ++i) {
        std::cout << " intended" << i << "="
                  << RangeCollapse(cell.layout.fields[i].offset,
                                   EndOfCollapse(cell.layout.fields[i]))
                  << "/w" << cell.layout.fields[i].bits;
    }
    std::cout << " distinct_offsets=" << cell.distinct_offsets
              << " rule_predicts_vars=" << cell.rule_predicts << " num_vars=" << cell.num_vars
              << " vars_lost=" << cell.vars_lost << " records_built=" << cell.records_built
              << " records_seen=" << cell.records_seen << " target=" << cell.target_index
              << " invertible=" << YesNoCollapse(cell.invertible) << " status="
              << (cell.invertible ? StatusNameCollapse(cell.status) : "kNotInvertible")
              << " outcome=" << OutcomeNameCollapse(cell.outcome)
              << " has_candidate=" << YesNoCollapse(cell.has_candidate)
              << " collapse=" << YesNoCollapse(cell.collapse)
              << " rule_matches=" << YesNoCollapse(cell.rule_matches) << "\n";

    for (const IntendedPairCollapse& pair : cell.pairs) {
        std::cout << "IPAIR id=" << cell.layout.id << " i=" << pair.i << " j=" << pair.j
                  << " inter=" << RangeCollapse(pair.lo, pair.hi)
                  << " bytes=" << (pair.hi - pair.lo) << " relation=" << pair.relation << "\n";
    }
    for (const IntendedFieldCollapse& fact : cell.fields) {
        std::cout << "IFIELD id=" << cell.layout.id << " i=" << fact.i << " off=" << fact.offset
                  << " w=" << fact.bits << " range="
                  << RangeCollapse(fact.offset, fact.offset + fact.bits / kBitsPerByteCollapse)
                  << " bound=" << YesNoCollapse(fact.bound) << " bound_var=";
        if (fact.bound) {
            std::cout << fact.var;
        } else {
            std::cout << "-";
        }
        std::cout << "\n";
    }
    for (const LostCollapse& lost : cell.lost) {
        std::cout << "LOST id=" << cell.layout.id << " i=" << lost.i << " off=" << lost.offset
                  << " w=" << lost.bits << " merged_with_field=";
        if (lost.merged_named) {
            std::cout << lost.merged_with << " merged_var=" << lost.merged_var;
        } else {
            std::cout << "- merged_var=-";
        }
        std::cout << " reason=" << lost.reason << "\n";
    }
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        std::cout << "VAR id=" << cell.layout.id << " k=" << k << " off=" << cell.vars[k].offset
                  << " w=" << static_cast<unsigned>(cell.vars[k].bit_width)
                  << " be=" << YesNoCollapse(cell.vars[k].big_endian) << "\n";
    }
}

struct StatsCollapse {
    std::size_t cells = 0;
    std::size_t collapsed = 0;
    std::size_t num_vars_1 = 0;
    std::size_t num_vars_2 = 0;
    std::size_t num_vars_3 = 0;
    std::size_t lost_bindings = 0;
    std::size_t lost_named = 0;
    std::size_t rule_predicts = 0;
    std::size_t records_built = 0;
    std::size_t records_seen = 0;
};

StatsCollapse RunOrderCollapse(const std::string& order, bool verbose) {
    StatsCollapse s;
    for (const LayoutCollapse& layout : OrderCollapse(order)) {
        const CellCollapse cell = MeasureCollapse(layout);
        ++s.cells;
        s.records_built += cell.records_built;
        s.records_seen += cell.records_seen;
        s.lost_bindings += cell.vars_lost;
        for (const LostCollapse& lost : cell.lost) {
            if (lost.merged_named) {
                ++s.lost_named;
            }
        }
        if (cell.collapse) {
            ++s.collapsed;
        }
        if (cell.rule_matches) {
            ++s.rule_predicts;
        }
        if (cell.num_vars == 1U) {
            ++s.num_vars_1;
        } else if (cell.num_vars == 2U) {
            ++s.num_vars_2;
        } else if (cell.num_vars == 3U) {
            ++s.num_vars_3;
        }
        if (verbose) {
            PrintCellCollapse("CELL", cell);
        }
        // The prediction is checked cell by cell, not only in aggregate: a rule
        // that is right on the count and wrong on the cells is not a mechanism.
        EXPECT_EQ(cell.num_vars, cell.rule_predicts) << cell.layout.id;
        EXPECT_EQ(cell.vars_lost, cell.layout.fields.size() - cell.num_vars) << cell.layout.id;
        EXPECT_EQ(cell.layout.fields.size(), kArityCollapse) << cell.layout.id;
    }
    return s;
}

}  // namespace

// The fixture is the task-059 fixture: same seed, same targets. Without this
// the numbers below would not be comparable with report.md:104.
TEST(SolverBindingCollapseMirrored, SeedMatchesTask059) {
    const std::vector<std::uint8_t> seed = SeedCollapse();
    std::cout << "FIXTURE seed_size=" << seed.size() << " bytes=";
    for (std::size_t i = 0; i < seed.size(); ++i) {
        std::cout << (i == 0 ? "" : ",") << "0x" << std::hex << std::uppercase << std::setfill('0')
                  << std::setw(2) << static_cast<unsigned>(seed[i]) << std::dec;
    }
    std::cout << " target32=0x11223344 target64=0x1122334455667788\n";

    ASSERT_EQ(seed.size(), kSeedSizeCollapse);
    EXPECT_EQ(seed.front(), 0x10U);
    EXPECT_EQ(seed.back(), 0xEFU);
    EXPECT_EQ(kTarget32Collapse, 0x11223344ULL);
    EXPECT_EQ(kTarget64Collapse, 0x1122334455667788ULL);
}

// The six mirrored cells, one CELL line plus IPAIR/IFIELD/LOST/VAR lines each,
// then the SUMMARY line the report quotes.
TEST(SolverBindingCollapseMirrored, SixMirroredCellsAtK3) {
    const StatsCollapse mirrored = RunOrderCollapse("mirrored", true);
    const StatsCollapse direct = RunOrderCollapse("direct", false);

    const bool mechanism_named = mirrored.rule_predicts == mirrored.cells;
    const bool control_no_collapse = direct.collapsed == 0U;

    std::cout << "SUMMARY cells=" << mirrored.cells << " k=" << kArityCollapse
              << " field_order=mirrored collapsed_cells=" << mirrored.collapsed << "/"
              << mirrored.cells << " num_vars_1=" << mirrored.num_vars_1
              << " num_vars_2=" << mirrored.num_vars_2 << " num_vars_3=" << mirrored.num_vars_3
              << " records_built=" << mirrored.records_built
              << " records_seen=" << mirrored.records_seen
              << " lost_bindings=" << mirrored.lost_bindings
              << " lost_binding_named=" << mirrored.lost_named << "/" << mirrored.lost_bindings
              << " distinct_offset_rule_predicts=" << mirrored.rule_predicts << "/"
              << mirrored.cells << " mechanism_named=" << YesNoCollapse(mechanism_named)
              << " control_direct_order_no_collapse=" << YesNoCollapse(control_no_collapse) << "\n";

    EXPECT_EQ(mirrored.cells, 6U);
    // Records are NOT dropped on the way in: whatever is lost is lost at
    // binding time, not at record time. Five records per cell, six cells.
    EXPECT_EQ(mirrored.records_built, mirrored.records_seen);
    EXPECT_EQ(mirrored.lost_named, mirrored.lost_bindings);
    EXPECT_EQ(mirrored.collapsed + mirrored.num_vars_3, mirrored.cells);
}

// Control: the same six layouts in DIRECT field order. If they also collapsed,
// the collapse would have nothing to do with mirroring.
TEST(SolverBindingCollapseMirrored, ControlDirectOrderKeepsThreeVars) {
    const StatsCollapse direct = RunOrderCollapse("direct", true);

    std::cout << "CONTROL order=direct cells=" << direct.cells
              << " collapsed_cells=" << direct.collapsed << "/" << direct.cells
              << " num_vars_3=" << direct.num_vars_3 << " lost_bindings=" << direct.lost_bindings
              << " distinct_offset_rule_predicts=" << direct.rule_predicts << "/" << direct.cells
              << "\n";

    EXPECT_EQ(direct.cells, 6U);
    EXPECT_EQ(direct.num_vars_3, 6U);
    EXPECT_EQ(direct.collapsed, 0U);
    EXPECT_EQ(direct.lost_bindings, 0U);
}

// The rule as a rule: distinct starting offsets predict num_vars in every one
// of the six mirrored cells. mechanism_named is yes only at 6/6.
TEST(SolverBindingCollapseMirrored, CollapseRulePredictsEveryCell) {
    const StatsCollapse mirrored = RunOrderCollapse("mirrored", false);

    std::cout << "RULE formula=num_vars==|{distinct field offsets}| predicts="
              << mirrored.rule_predicts << "/" << mirrored.cells
              << " mechanism_named=" << YesNoCollapse(mirrored.rule_predicts == mirrored.cells)
              << " basis=src/concolic/concolic.h:26-28\n";

    EXPECT_EQ(mirrored.rule_predicts, 6U);
    EXPECT_EQ(mirrored.rule_predicts, mirrored.cells);
}
