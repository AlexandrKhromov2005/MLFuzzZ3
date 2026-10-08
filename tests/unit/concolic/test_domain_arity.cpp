#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

// Solver domain map, ARITY axis (task-044, ADR 0035 §2). Three axes of the
// binding domain have been measured on gates over exactly TWO verbatim
// fields — algebraic form (tests/unit/concolic/test_domain_map.cpp), width
// x byte order (tests/unit/concolic/test_domain_width_map.cpp) and all
// three together (tests/unit/concolic/test_domain_form_width_endian.cpp).
// The NUMBER OF ADDENDS was never an axis. This file MEASURES it; it adds
// no rules and changes nothing under src/.
//
// What the code does today, read off the source. BindOperand
// (src/concolic/concolic.cpp:185) tries a direct field match first, then
// enumerates PAIRS (`for i` / `for j = i`, concolic.cpp:195-205) and builds
// MakeAdd(i, j); if no pair sums to the target it returns MakeConst(target).
// There is no third loop and no arity constant to grep for: the bound is
// structural, because solver::Operand (src/solver/solver_facade.h:30-34)
// physically holds var_index and var_index2 and nothing else.
//
// Method. For k = 1..4 the seed carries k verbatim u32 fields, little
// endian, at offsets 0, 4, ... Each field gets a guard record (field >u
// LOW, TRUE on the seed) so pass 1 can discover it, exactly as the
// reference harness does. The gate under test is `sum(k fields) == MAGIC`:
// its LHS is the value the runtime would log for the sum, its RHS the
// magic constant.
//
// Reading SolveOutcome alone is a trap and this file pins the trap. When
// both sides of the gate classify as kConst the record is DROPPED
// (concolic.cpp:244-247), the last surviving guard silently becomes the
// target (concolic.cpp:253-254) and SolveForCandidate reports kCandidate
// for a branch that is NOT the gate. So every cell also records whether the
// gate record survived and whether the returned candidate actually
// satisfies the gate.

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
constexpr unsigned kMaxK = 4;

// Four u32 fields, little-endian, offsets 0/4/8/12. Every byte is non-zero
// and no 4-byte window repeats, so no sum below is accidentally findable as
// a substring of the seed (that would alias a derived operand onto a field
// and forge an in-domain verdict). FixtureConstantsAreNotFindable asserts
// this instead of trusting it.
constexpr std::array<std::uint32_t, kMaxK> kFields = {0x11223344U, 0x55667788U, 0x99AABBCCU,
                                                      0xD1E2F304U};

// Guard bound: below every field and absent from the seed.
constexpr std::uint32_t kLow = 0x01010101U;

// The gate's magic constant. Absent from the seed (no seed byte is 0x2A)
// and not the sum of any field pair, so BindOperand can only make a kConst
// of it.
//
// It must also stay ABOVE kLow, and that is a fixture requirement, not a
// decoration: at k = 1 the inverted target is `a == MAGIC` while the guard
// `a >u LOW` still holds, so a magic below the bound makes the system UNSAT
// for a reason that has nothing to do with arity (measured: kUnsat with
// kMagic = 0x2A). From k = 2 on the sum can wrap and the guards no longer
// constrain the magic, which would silently turn k = 1 into the odd cell.
constexpr std::uint32_t kMagic = 0x2A2A2A2AU;

// A second magic for the FOREIGN, still-solvable k=2 record used by the
// silent-loss scenario. Same properties as kMagic.
constexpr std::uint32_t kMagicForeign = 0x37373737U;

// The value the runtime logs on the LHS of the k-addend gate: the u32 sum
// of the first k fields, wrapping exactly as C would.
std::uint32_t SumOfFirst(unsigned k) {
    std::uint32_t sum = 0;
    for (unsigned i = 0; i < k; ++i) {
        sum += kFields[i];
    }
    return sum;
}

std::vector<std::uint8_t> SeedOf(unsigned k) {
    std::vector<std::uint8_t> seed(4U * k);
    for (unsigned i = 0; i < k; ++i) {
        for (unsigned b = 0; b < 4; ++b) {
            seed[(4U * i) + b] = static_cast<std::uint8_t>(kFields[i] >> (8U * b));
        }
    }
    return seed;
}

// Read back the k fields of a solved candidate under the same encoding the
// bindings used (u32, little-endian, offsets 0/4/...) and sum them. This is
// what decides whether the gate was actually TAKEN, as opposed to
// SolveForCandidate merely returning something.
std::uint32_t SumOfCandidate(const mlfuzzz3::mutation::FuzzInput& input, unsigned k) {
    std::uint32_t sum = 0;
    for (unsigned i = 0; i < k; ++i) {
        std::uint32_t field = 0;
        for (unsigned b = 0; b < 4; ++b) {
            field |= static_cast<std::uint32_t>(input.data()[(4U * i) + b]) << (8U * b);
        }
        sum += field;
    }
    return sum;
}

std::vector<BranchReader::Record> GuardsFor(unsigned k) {
    std::vector<BranchReader::Record> guards;
    for (unsigned i = 0; i < k; ++i) {
        guards.push_back({i, kUgt, 32, kFields[i], kLow});
    }
    return guards;
}

// One measured cell of the arity sweep.
struct Cell {
    Operand::Kind lhs_kind;  ///< what BindOperand made of the k-addend sum
    Operand::Kind rhs_kind;  ///< what BindOperand made of the magic constant
    bool gate_survived;      ///< did the gate record reach sys.path at all?
    std::size_t path_size;   ///< surviving constraints (k guards + gate = k+1)
    bool invertible;         ///< sys.invertible for the whole form
    SolveOutcome outcome;    ///< what SolveForCandidate reported
    bool has_candidate;      ///< did the call actually hand back an input?
    bool gate_taken;         ///< does that candidate satisfy sum == MAGIC?
};

// Measure the cell for k addends.
//
// Both operand Kinds are read off PROBE systems rather than off the form
// itself, because a form whose two sides both classify as kConst is dropped
// and would leave nothing to observe. BindOperand classifies each side
// independently (concolic.cpp:240-243), so a probe that keeps the OTHER
// side bound reports the same Kind the real form produced:
//   * lhs probe: `sum == field[k-1]` — RHS binds to a field, LHS Kind shows;
//   * rhs probe: `field[0] == MAGIC` — LHS binds to a field, RHS Kind shows.
Cell Measure(unsigned k) {
    const std::vector<std::uint8_t> seed = SeedOf(k);
    const std::vector<BranchReader::Record> guards = GuardsFor(k);
    const auto sum = static_cast<std::uint64_t>(SumOfFirst(k));

    std::vector<BranchReader::Record> form = guards;
    form.push_back({k, kEq, 32, sum, kMagic});

    std::vector<BranchReader::Record> lhs_probe = guards;
    lhs_probe.push_back({k, kEq, 32, sum, kFields[k - 1U]});

    std::vector<BranchReader::Record> rhs_probe = guards;
    rhs_probe.push_back({k, kEq, 32, kFields[0], kMagic});

    const System lhs_sys = BuildSystem(seed, lhs_probe);
    const System rhs_sys = BuildSystem(seed, rhs_probe);
    const System form_sys = BuildSystem(seed, form);

    Cell cell{};
    cell.lhs_kind = Operand::Kind::kConst;
    cell.rhs_kind = Operand::Kind::kConst;
    if (lhs_sys.path.size() != lhs_probe.size() || rhs_sys.path.size() != rhs_probe.size()) {
        ADD_FAILURE() << "probe record was dropped for k=" << k
                      << " — the probe fixture itself is broken, Kinds below are not measured";
    } else {
        cell.lhs_kind = lhs_sys.path.back().lhs.kind;
        cell.rhs_kind = rhs_sys.path.back().rhs.kind;
    }

    cell.path_size = form_sys.path.size();
    cell.gate_survived = form_sys.path.size() == form.size();
    cell.invertible = form_sys.invertible;
    cell.outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, form, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    cell.gate_taken = candidate.has_value() && SumOfCandidate(*candidate, k) == kMagic;
    return cell;
}

}  // namespace

// Sanity for the fixture itself: the k fields are discovered by offset from
// the guards alone, for every k in the sweep. If this breaks, every cell
// below is measuring something other than what it claims.
TEST(DomainArity, FixtureBindsAllFields) {
    for (unsigned k = 1; k <= kMaxK; ++k) {
        SCOPED_TRACE(testing::Message() << "k=" << k);
        const System sys = BuildSystem(SeedOf(k), GuardsFor(k));
        ASSERT_EQ(sys.num_vars, k);
        for (unsigned i = 0; i < k; ++i) {
            EXPECT_EQ(sys.vars[i].offset, 4U * i);
            EXPECT_EQ(sys.vars[i].bit_width, 32U);
            EXPECT_FALSE(sys.vars[i].big_endian);
        }
    }
}

// Neither the magic constants nor any k-addend sum may be findable in the
// seed: a findable sum would bind as kVar through the DIRECT branch of
// BindOperand and report "in domain" for a reason that has nothing to do
// with arity. The guard bound must be unfindable for the same reason.
TEST(DomainArity, FixtureConstantsAreNotFindable) {
    const std::vector<std::uint8_t> seed = SeedOf(kMaxK);
    const std::vector<BranchReader::Record> guards = GuardsFor(kMaxK);

    for (const std::uint32_t value : {kMagic, kMagicForeign, kLow}) {
        SCOPED_TRACE(testing::Message() << "constant=" << value);
        std::vector<BranchReader::Record> probe = guards;
        probe.push_back({kMaxK, kEq, 32, value, value});
        // Both sides are the same unfindable constant, so the record is
        // dropped whole: seeing kMaxK constraints (guards only) proves the
        // value bound to nothing.
        EXPECT_EQ(BuildSystem(seed, probe).path.size(), std::size_t{kMaxK});
    }

    for (unsigned k = 3; k <= kMaxK; ++k) {
        SCOPED_TRACE(testing::Message() << "sum k=" << k);
        std::vector<BranchReader::Record> probe = GuardsFor(k);
        const auto sum = static_cast<std::uint64_t>(SumOfFirst(k));
        probe.push_back({k, kEq, 32, sum, sum});
        EXPECT_EQ(BuildSystem(SeedOf(k), probe).path.size(), std::size_t{k});
    }
}

// k = 1 — `a == MAGIC`. The logged value IS a field, so the DIRECT match in
// BindOperand (concolic.cpp:189-194) binds it. IN DOMAIN, gate taken.
TEST(DomainArity, K1IsInDomain) {
    const Cell cell = Measure(1);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kVar);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 2U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.gate_taken);
}

// k = 2 — `a + b == MAGIC`. Not findable directly; binds only through the
// pair enumeration (concolic.cpp:195-205). IN DOMAIN, gate taken. This is
// the widest arity the current reconstruction can express at all.
TEST(DomainArity, K2IsInDomain) {
    const Cell cell = Measure(2);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_TRUE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 3U);
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.gate_taken);
}

// k = 3 — `a + b + c == MAGIC`. THE BOUND. No pair sums to the target, so
// BindOperand falls back to MakeConst (concolic.cpp:206); the RHS is a
// constant too, so the gate record is dropped whole (concolic.cpp:244-247).
// The loss is SILENT: sys.invertible stays true on the surviving guards,
// the last guard becomes the target, and SolveForCandidate reports
// kCandidate for a branch that is not the gate.
TEST(DomainArity, K3FallsOutOfDomainSilently) {
    const Cell cell = Measure(3);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 3U);  // three guards, gate gone
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);  // success reported, gate NOT satisfied
}

// k = 4 — same wall, one addend further out. Pinned separately so the
// verdict says "k >= 3", not "k == 3".
TEST(DomainArity, K4FallsOutOfDomainSilently) {
    const Cell cell = Measure(4);
    EXPECT_EQ(cell.lhs_kind, Operand::Kind::kConst);
    EXPECT_EQ(cell.rhs_kind, Operand::Kind::kConst);
    EXPECT_FALSE(cell.gate_survived);
    EXPECT_EQ(cell.path_size, 4U);  // four guards, gate gone
    EXPECT_TRUE(cell.invertible);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_taken);
}

// The silent-loss scenario stated as its own experiment: the TARGET gate is
// the k=3 one (logged last, so BuildSystem would elect it), and a solvable
// k=2 record sits before it. The k=3 record is dropped, the k=2 record
// becomes the target by default, and SolveForCandidate reports success on
// that FOREIGN constraint — satisfying `a + b == MAGIC_FOREIGN` while the
// gate the caller was inverting for stays unsatisfied. Nothing in the
// return value distinguishes this from a real hit.
TEST(DomainArity, K3GateDroppedSolveSucceedsOnForeignConstraint) {
    const unsigned k = 3;
    const std::vector<std::uint8_t> seed = SeedOf(k);
    const auto foreign_sum = static_cast<std::uint64_t>(kFields[0] + kFields[1]);
    const auto target_sum = static_cast<std::uint64_t>(SumOfFirst(k));

    std::vector<BranchReader::Record> records = GuardsFor(k);
    records.push_back({k, kEq, 32, foreign_sum, kMagicForeign});  // solvable, k=2
    records.push_back({k + 1U, kEq, 32, target_sum, kMagic});     // the target, k=3

    const System sys = BuildSystem(seed, records);
    ASSERT_EQ(sys.path.size(), records.size() - 1U);  // the k=3 record fell out
    EXPECT_TRUE(sys.invertible);
    // The elected target is now the foreign k=2 record, not the k=3 gate.
    ASSERT_EQ(sys.target_index, sys.path.size() - 1U);
    EXPECT_EQ(sys.path[sys.target_index].lhs.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(sys.path[sys.target_index].rhs.const_value, kMagicForeign);

    SolveOutcome outcome = SolveOutcome::kError;
    const std::optional<mlfuzzz3::mutation::FuzzInput> candidate =
        SolveForCandidate(seed, records, kTimeoutMs, &outcome);
    EXPECT_EQ(outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(candidate.has_value());
    // Success is real — for the wrong branch.
    EXPECT_EQ(SumOfCandidate(*candidate, 2), kMagicForeign);
    EXPECT_NE(SumOfCandidate(*candidate, k), kMagic);
}
