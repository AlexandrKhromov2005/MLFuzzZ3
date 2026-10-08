#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

// RESIDUAL ERROR of the binding discriminator D on the three already
// measured classes of SILENT FALSE SUCCESS (task-058, ADR 0035).
//
// D is the caller-side predicate of task-037
// (tests/unit/concolic/test_binding_discriminator.cpp:80-82):
//
//     D = (derived_kind != Operand::Kind::kConst) && gate_survived
//
// task-037 measured D against the domain map (completeness) and against a
// grid where nothing is composed (residual error on encoding-domain
// draws). It never asked D about the three modes the later sessions
// measured, each of which returns kCandidate while the gate the caller
// wanted is NOT taken:
//
//   * task-048 (tests/unit/concolic/test_false_success.cpp) — the target
//     record is DROPPED (both sides kConst) and a foreign record silently
//     becomes the target: 9 cells, 6 of them candidate-returning, 0 with
//     the gate taken.
//   * task-053 (tests/unit/concolic/test_binding_overlap.cpp) — two
//     bindings whose byte RANGES intersect, so the write-back overwrites
//     part of the model: 9 cells, all 9 with a model mismatch, 0 with the
//     gate taken.
//   * task-056 (tests/unit/concolic/test_binding_overlap_order.cpp) — the
//     same overlap over order and endianness: 27 cells, 17 with a model
//     mismatch, 18 with the gate taken.
//
// This file MEASURES two things on those 45 cells and changes nothing
// under src/:
//   * D itself — how often the mechanical predicate says "bound" about a
//     run whose gate is not taken (D_false_positive);
//   * a POST-CHECK P — the inverted target predicate re-evaluated on the
//     bytes actually written back, i.e. after the write-back rather than
//     before the solve. P is not a rule and is not adopted anywhere; the
//     question is only whether it catches the cells D gets wrong.
//
// The truth column (`gate_taken`) is never redefined here: each class
// keeps the oracle of its own source file, quoted at the three call sites
// below. The seven control forms of task-037 are replayed verbatim so a
// divergence in D itself would show up as a broken control instead of
// being absorbed into the residual numbers.
//
// The helpers of the four source harnesses live in anonymous namespaces
// and cannot be reused; they are copied here so the cells coincide with
// their sources byte for byte. No source file is modified and no fuzzing
// campaign is run.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::VarBinding;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;
using mlfuzzz3::solver::SolveInverted;
using mlfuzzz3::solver::SolveResult;

// fuzzer_rt_cmp_kind values (ADR 0033). Same numbering as every source
// harness copied from below.
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUgt = 4, kUge = 5 };

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kTimeoutMs = 5000;  ///< the constant of all four sources

// THE DISCRIMINATOR, copied from test_binding_discriminator.cpp:80-82. Not
// restated, not adapted to the classes measured below.
bool Discriminator(Operand::Kind derived_kind, bool gate_survived) {
    return derived_kind != Operand::Kind::kConst && gate_survived;
}

const char* YesNo(bool value) {
    return value ? "yes" : "no";
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

const char* StatusName(SolveResult::Status status) {
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

// ---------------------------------------------------------------------
// Shared oracles, copied from test_binding_overlap.cpp:110-220 (identical
// in test_binding_overlap_order.cpp:103-212).
// ---------------------------------------------------------------------

std::uint64_t Truncate(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

// Read a field back through its own binding — the inverse of the write-back
// (mirrors ReadField, src/concolic/concolic.cpp:117-126).
std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[var.offset + k]) << shift;
    }
    return value;
}

// The engine's write-back, replayed from the model returned by a direct
// SolveInverted call (mirrors src/concolic/concolic.cpp:303-317).
std::vector<std::uint8_t> WriteBackModel(const std::vector<std::uint8_t>& seed, const System& sys,
                                         const std::vector<std::uint64_t>& model) {
    std::vector<std::uint8_t> bytes = seed;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const VarBinding& var = sys.vars[k];
        const unsigned n = var.bit_width / kBitsPerByte;
        const std::uint64_t value = Truncate(model[k], var.bit_width);
        for (unsigned b = 0; b < n; ++b) {
            const unsigned shift =
                var.big_endian ? (kBitsPerByte * (n - 1U - b)) : (kBitsPerByte * b);
            bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
        }
    }
    return bytes;
}

std::uint8_t Negate(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return kNe;
        case kNe:
            return kEq;
        case kUlt:
            return kUge;
        case kUle:
            return kUgt;
        case kUgt:
            return kUle;
        case kUge:
            return kUlt;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return predicate;
    }
}

bool Eval(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs, unsigned bit_width) {
    const std::uint64_t l = Truncate(lhs, bit_width);
    const std::uint64_t r = Truncate(rhs, bit_width);
    switch (predicate) {
        case kEq:
            return l == r;
        case kNe:
            return l != r;
        case kUlt:
            return l < r;
        case kUle:
            return l <= r;
        case kUgt:
            return l > r;
        case kUge:
            return l >= r;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return false;
    }
}

// Value of one constraint operand on a concrete byte string, resolving kVar
// through its binding — this is how the gate is evaluated on the candidate.
std::uint64_t OperandValue(const Operand& op, const System& sys,
                           const std::vector<std::uint8_t>& bytes, unsigned bit_width) {
    switch (op.kind) {
        case Operand::Kind::kVar:
            return Truncate(ReadBinding(bytes, sys.vars[op.var_index]), bit_width);
        case Operand::Kind::kConst:
            return Truncate(op.const_value, bit_width);
        case Operand::Kind::kAddVars:
            return Truncate(Truncate(ReadBinding(bytes, sys.vars[op.var_index]), bit_width) +
                                Truncate(ReadBinding(bytes, sys.vars[op.var_index2]), bit_width),
                            bit_width);
    }
    ADD_FAILURE() << "unknown operand kind";
    return 0;
}

// ---------------------------------------------------------------------
// CONTROL — the seven forms of task-037, replayed verbatim from
// test_binding_discriminator.cpp:144-229.
// ---------------------------------------------------------------------

namespace control {

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

// test_binding_discriminator.cpp:175-206, PROBE system included: when both
// sides of the gate classify as kConst the record is dropped and the LHS
// Kind has nothing left to be read off.
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

// `expect_bound` is the classification QUOTED from
// docs/experiments/solver-domain-map/report.md:65-72 — BOUND <=> D must be
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

}  // namespace control

// ---------------------------------------------------------------------
// CLASS task048 — copied from test_false_success.cpp:76-231.
// ---------------------------------------------------------------------

namespace t048 {

constexpr unsigned kWidth = 32;
constexpr unsigned kFieldCount = 3;
constexpr unsigned kFieldBytes = 4;

using Fields = std::array<std::uint32_t, kFieldCount>;

constexpr Fields kFields = {0x11223344U, 0x55667788U, 0x99AABBCCU};

constexpr std::uint32_t kLow = 0x01010101U;
constexpr std::uint32_t kMagic = 0x2A2A2A2AU;
constexpr std::uint32_t kLiteralLhs = 0x37373737U;
constexpr std::uint32_t kLiteralRhs = 0x2A2A2A2AU;

std::vector<std::uint8_t> SeedOfFields() {
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(kFieldBytes) * kFieldCount);
    for (unsigned i = 0; i < kFieldCount; ++i) {
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            seed[(kFieldBytes * i) + b] = static_cast<std::uint8_t>(kFields[i] >> (8U * b));
        }
    }
    return seed;
}

// Read the fields back out of a solved candidate under exactly the encoding
// the bindings used (u32, little-endian, offsets 0/4/8).
Fields FieldsOfCandidate(const mlfuzzz3::mutation::FuzzInput& input) {
    Fields out{};
    for (unsigned i = 0; i < kFieldCount; ++i) {
        std::uint32_t field = 0;
        for (unsigned b = 0; b < kFieldBytes; ++b) {
            field |= static_cast<std::uint32_t>(input.data()[(kFieldBytes * i) + b]) << (8U * b);
        }
        out[i] = field;
    }
    return out;
}

enum class Reason { kArity, kDifference, kLiteral };

// The cell-id stem of this class (task-058 log format).
const char* IdOf(Reason reason) {
    switch (reason) {
        case Reason::kArity:
            return "arity";
        case Reason::kDifference:
            return "difference";
        case Reason::kLiteral:
            return "literal";
    }
    return "?";
}

std::uint32_t LhsOnSeed(Reason reason) {
    switch (reason) {
        case Reason::kArity:
            return kFields[0] + kFields[1] + kFields[2];
        case Reason::kDifference:
            return kFields[0] - kFields[1];
        case Reason::kLiteral:
            return kLiteralLhs;
    }
    return 0;
}

std::uint32_t RhsOnSeed(Reason reason) {
    return reason == Reason::kLiteral ? kLiteralRhs : kMagic;
}

BranchReader::Record TargetRecord(Reason reason) {
    return {90, kEq, kWidth, LhsOnSeed(reason), RhsOnSeed(reason)};
}

// The oracle of task-048: is the TARGET gate satisfied by these field
// values? (test_false_success.cpp:198-208.)
bool GateHolds(Reason reason, const Fields& v) {
    switch (reason) {
        case Reason::kArity:
            return static_cast<std::uint32_t>(v[0] + v[1] + v[2]) == kMagic;
        case Reason::kDifference:
            return static_cast<std::uint32_t>(v[0] - v[1]) == kMagic;
        case Reason::kLiteral:
            return LhsOnSeed(Reason::kLiteral) == RhsOnSeed(Reason::kLiteral);
    }
    return false;
}

std::vector<BranchReader::Record> ForeignRecords(unsigned count) {
    std::vector<BranchReader::Record> out;
    if (count >= 1) {
        out.push_back({10, kUgt, kWidth, kFields[0], kFields[1]});
    }
    if (count >= 2) {
        out.push_back({11, kUgt, kWidth, kFields[2], kLow});
    }
    return out;
}

std::vector<BranchReader::Record> RecordsFor(Reason reason, unsigned foreign) {
    std::vector<BranchReader::Record> recs = ForeignRecords(foreign);
    recs.push_back(TargetRecord(reason));
    return recs;
}

constexpr std::array<Reason, 3> kReasons = {Reason::kArity, Reason::kDifference, Reason::kLiteral};

}  // namespace t048

// ---------------------------------------------------------------------
// CLASSES task053 / task056 — copied from test_binding_overlap.cpp:86-482
// and test_binding_overlap_order.cpp:81-579.
// ---------------------------------------------------------------------

namespace overlap {

constexpr std::size_t kSeedSize = 16;

constexpr std::array<std::uint8_t, kSeedSize> kSeed = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

constexpr std::uint64_t kTarget32 = 0x11223344ULL;
constexpr std::uint64_t kTarget64 = 0x1122334455667788ULL;

std::vector<std::uint8_t> Seed() {
    return {kSeed.begin(), kSeed.end()};
}

// Little-endian read straight from the seed (test_binding_overlap.cpp:119).
std::uint64_t ReadLe(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (kBitsPerByte * k);
    }
    return value;
}

// The order-aware read of task-056 (test_binding_overlap_order.cpp:115).
std::uint64_t ReadSeedField(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n,
                            bool big_endian) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

struct Row {
    const char* name;
    unsigned wide_bits;
    unsigned narrow_bits;
};

constexpr std::array<Row, 3> kRows = {{
    {"u32+u16", 32U, 16U},
    {"u32+u8", 32U, 8U},
    {"u64+u32", 64U, 32U},
}};

constexpr std::array<std::size_t, 3> kShifts = {1U, 2U, 3U};

// A layout is one point on the two coordinates task-053 left open.
struct Layout {
    const char* name;
    bool reverse;     // narrow field at the LOWER offset
    bool big_endian;  // fields requested through their big-endian encoding
};

constexpr Layout kReverseLe = {"rev-le", true, false};
constexpr Layout kForwardBe = {"fwd-be", false, true};
constexpr Layout kReverseBe = {"rev-be", true, true};

constexpr std::array<Layout, 3> kLayouts = {{kReverseLe, kForwardBe, kReverseBe}};

// test_binding_overlap.cpp:334-357 — the task-053 records.
std::vector<BranchReader::Record> MakeRecords053(std::size_t shift, unsigned wide_bits,
                                                 unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const std::uint64_t a = ReadLe(seed, 0, wide_bits / kBitsPerByte);
    const std::uint64_t b = ReadLe(seed, shift, narrow_bits / kBitsPerByte);
    const std::uint64_t target = wide_bits == 64U ? kTarget64 : kTarget32;
    return {
        {.site_id = 1,
         .predicate = kUgt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b - 1U},
        {.site_id = 2,
         .predicate = kUlt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b + 1U},
        {.site_id = 3,
         .predicate = kEq,
         .bit_width = static_cast<std::uint8_t>(wide_bits),
         .lhs = a,
         .rhs = target},
    };
}

// test_binding_overlap_order.cpp:375-404 — the task-056 records.
std::vector<BranchReader::Record> MakeRecords056(const Layout& layout, std::size_t shift,
                                                 unsigned wide_bits, unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const unsigned wide_len = wide_bits / kBitsPerByte;
    const unsigned narrow_len = narrow_bits / kBitsPerByte;
    const std::size_t wide_offset = layout.reverse ? shift : 0U;
    const std::size_t narrow_offset = layout.reverse ? 0U : shift;
    const std::uint64_t a =
        ReadSeedField(seed, wide_offset, wide_len, layout.big_endian && wide_len > 1U);
    const std::uint64_t b =
        ReadSeedField(seed, narrow_offset, narrow_len, layout.big_endian && narrow_len > 1U);
    const std::uint64_t target = wide_bits == 64U ? kTarget64 : kTarget32;
    return {
        {.site_id = 1,
         .predicate = kUgt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b - 1U},
        {.site_id = 2,
         .predicate = kUlt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b + 1U},
        {.site_id = 3,
         .predicate = kEq,
         .bit_width = static_cast<std::uint8_t>(wide_bits),
         .lhs = a,
         .rhs = target},
    };
}

}  // namespace overlap

// ---------------------------------------------------------------------
// The residual measurement itself.
// ---------------------------------------------------------------------

struct VarFact {
    std::size_t offset = 0;
    std::uint8_t bit_width = 0;
    bool big_endian = false;
    std::uint64_t model_value = 0;
    std::uint64_t reread_value = 0;
    bool matches = false;
};

struct ResidualCell {
    std::string cls;
    std::string id;

    Operand::Kind derived_kind = Operand::Kind::kConst;
    bool gate_survived = false;
    bool d = false;

    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    SolveResult::Status status = SolveResult::Status::kError;

    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;

    std::vector<VarFact> vars;
    unsigned mismatched_vars = 0;
    bool model_mismatch = false;

    bool p = false;
    bool gate_taken = false;
    bool d_false_positive = false;
    bool p_false_positive = false;
};

// Everything a cell needs that is not the class-specific truth column: the
// built system, the engine's own candidate and the replayed write-back the
// post-check P is evaluated on.
struct Probe {
    ResidualCell cell;
    System sys;
    std::vector<std::uint8_t> candidate;
    bool candidate_ok = false;
    std::optional<mlfuzzz3::mutation::FuzzInput> engine;
};

Probe MeasureResidual(const char* cls, const std::string& id, const std::vector<std::uint8_t>& seed,
                      const std::vector<BranchReader::Record>& recs) {
    Probe probe;
    ResidualCell& cell = probe.cell;
    cell.cls = cls;
    cell.id = id;

    const System sys = BuildSystem(seed, recs);
    probe.sys = sys;
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;

    // D, exactly as task-037 states it. The kConst stand-in on the
    // "gate did not survive" branch is the one of
    // test_binding_discriminator.cpp:195, so D is false there through its
    // second conjunct whatever the dropped record's Kind was.
    cell.gate_survived = sys.path.size() == recs.size();
    cell.derived_kind =
        cell.gate_survived ? sys.path[sys.target_index].lhs.kind : Operand::Kind::kConst;
    cell.d = Discriminator(cell.derived_kind, cell.gate_survived);

    // The engine's own verdict, taken for EVERY cell of the corpus.
    cell.outcome = SolveOutcome::kError;
    probe.engine = SolveForCandidate(seed, recs, kTimeoutMs, &cell.outcome);
    cell.has_candidate = probe.engine.has_value();

    if (!sys.invertible || sys.path.empty()) {
        return probe;  // status stays kError, P stays false
    }

    const SolveResult result = SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMs);
    cell.status = result.status;
    if (result.status != SolveResult::Status::kSat || result.model_values.size() != sys.num_vars) {
        return probe;  // P stays false
    }

    probe.candidate = WriteBackModel(seed, sys, result.model_values);
    probe.candidate_ok = true;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const std::uint64_t model = Truncate(result.model_values[k], sys.vars[k].bit_width);
        const std::uint64_t reread = ReadBinding(probe.candidate, sys.vars[k]);
        cell.vars.push_back({.offset = sys.vars[k].offset,
                             .bit_width = sys.vars[k].bit_width,
                             .big_endian = sys.vars[k].big_endian,
                             .model_value = model,
                             .reread_value = reread,
                             .matches = model == reread});
        if (model != reread) {
            ++cell.mismatched_vars;
        }
    }
    cell.model_mismatch = cell.mismatched_vars > 0U;

    // THE POST-CHECK P: the inverted target predicate on the values RE-READ
    // from the candidate, i.e. after the write-back rather than before it.
    const unsigned target_width = sys.path[sys.target_index].bit_width;
    cell.p = Eval(Negate(sys.path[sys.target_index].predicate),
                  OperandValue(sys.path[sys.target_index].lhs, sys, probe.candidate, target_width),
                  OperandValue(sys.path[sys.target_index].rhs, sys, probe.candidate, target_width),
                  target_width);
    return probe;
}

void FinishCell(ResidualCell& cell) {
    cell.d_false_positive = cell.d && !cell.gate_taken;
    cell.p_false_positive = cell.p && !cell.gate_taken;
}

// The inverted target evaluated on the replayed candidate — the truth
// column of task-053/task-056 (test_binding_overlap.cpp:424-427).
bool GateOnCandidate(const Probe& probe) {
    if (!probe.candidate_ok) {
        return false;
    }
    const System& sys = probe.sys;
    const unsigned target_width = sys.path[sys.target_index].bit_width;
    return Eval(Negate(sys.path[sys.target_index].predicate),
                OperandValue(sys.path[sys.target_index].lhs, sys, probe.candidate, target_width),
                OperandValue(sys.path[sys.target_index].rhs, sys, probe.candidate, target_width),
                target_width);
}

std::vector<ResidualCell> CollectTask048() {
    std::vector<ResidualCell> cells;
    const std::vector<std::uint8_t> seed = t048::SeedOfFields();
    for (const t048::Reason reason : t048::kReasons) {
        for (unsigned foreign = 0; foreign <= 2; ++foreign) {
            const std::string id = std::string(t048::IdOf(reason)) + "-f" + std::to_string(foreign);
            const std::vector<BranchReader::Record> recs = t048::RecordsFor(reason, foreign);
            Probe probe = MeasureResidual("task048", id, seed, recs);
            // Truth column of task-048, test_false_success.cpp:271.
            probe.cell.gate_taken = probe.engine.has_value() &&
                                    t048::GateHolds(reason, t048::FieldsOfCandidate(*probe.engine));
            FinishCell(probe.cell);
            cells.push_back(probe.cell);
        }
    }
    return cells;
}

std::vector<ResidualCell> CollectTask053() {
    std::vector<ResidualCell> cells;
    const std::vector<std::uint8_t> seed = overlap::Seed();
    for (const overlap::Row& row : overlap::kRows) {
        for (const std::size_t shift : overlap::kShifts) {
            const std::string id = std::string(row.name) + "-d" + std::to_string(shift);
            const std::vector<BranchReader::Record> recs =
                overlap::MakeRecords053(shift, row.wide_bits, row.narrow_bits);
            Probe probe = MeasureResidual("task053", id, seed, recs);
            // Truth column of task-053, test_binding_overlap.cpp:424-427.
            probe.cell.gate_taken = GateOnCandidate(probe);
            FinishCell(probe.cell);
            cells.push_back(probe.cell);
        }
    }
    return cells;
}

std::vector<ResidualCell> CollectTask056() {
    std::vector<ResidualCell> cells;
    const std::vector<std::uint8_t> seed = overlap::Seed();
    for (const overlap::Layout& layout : overlap::kLayouts) {
        for (const overlap::Row& row : overlap::kRows) {
            for (const std::size_t shift : overlap::kShifts) {
                const std::string id =
                    std::string(layout.name) + "-" + row.name + "-d" + std::to_string(shift);
                const std::vector<BranchReader::Record> recs =
                    overlap::MakeRecords056(layout, shift, row.wide_bits, row.narrow_bits);
                Probe probe = MeasureResidual("task056", id, seed, recs);
                // Truth column of task-056, the oracle of
                // test_binding_overlap_order.cpp:501-504.
                probe.cell.gate_taken = GateOnCandidate(probe);
                FinishCell(probe.cell);
                cells.push_back(probe.cell);
            }
        }
    }
    return cells;
}

void PrintCell(const ResidualCell& cell) {
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        const VarFact& var = cell.vars[k];
        std::cout << "RESIDUAL-VAR class=" << cell.cls << " id=" << cell.id << " k=" << k
                  << " offset=" << var.offset << " bit_width=" << unsigned{var.bit_width}
                  << " big_endian=" << YesNo(var.big_endian) << " model_value=" << var.model_value
                  << " reread_value=" << var.reread_value << " matches=" << YesNo(var.matches)
                  << "\n";
    }
    std::cout << "RESIDUAL-CELL class=" << cell.cls << " id=" << cell.id
              << " derived_kind=" << KindName(cell.derived_kind)
              << " gate_survived=" << YesNo(cell.gate_survived) << " D=" << YesNo(cell.d)
              << " outcome=" << OutcomeName(cell.outcome) << " status=" << StatusName(cell.status)
              << " num_vars=" << cell.num_vars << " path_size=" << cell.path_size
              << " target_index=" << cell.target_index
              << " mismatched_vars=" << cell.mismatched_vars
              << " model_mismatch=" << YesNo(cell.model_mismatch) << " P=" << YesNo(cell.p)
              << " gate_taken=" << YesNo(cell.gate_taken)
              << " D_false_positive=" << YesNo(cell.d_false_positive)
              << " P_false_positive=" << YesNo(cell.p_false_positive) << "\n";
}

struct ClassTotals {
    std::string cls;
    unsigned cells = 0;
    unsigned d_true = 0;
    unsigned gate_taken = 0;
    unsigned model_mismatch_cells = 0;
    unsigned candidate_returned = 0;
    unsigned d_false_positive = 0;
    unsigned p_true = 0;
    unsigned p_false_positive = 0;
    unsigned p_catches = 0;  ///< D_false_positive cells that P also rejects
};

ClassTotals TallyClass(const std::string& cls, const std::vector<ResidualCell>& cells) {
    ClassTotals totals;
    totals.cls = cls;
    for (const ResidualCell& cell : cells) {
        ++totals.cells;
        totals.d_true += cell.d ? 1U : 0U;
        totals.gate_taken += cell.gate_taken ? 1U : 0U;
        totals.model_mismatch_cells += cell.model_mismatch ? 1U : 0U;
        totals.candidate_returned += cell.has_candidate ? 1U : 0U;
        totals.d_false_positive += cell.d_false_positive ? 1U : 0U;
        totals.p_true += cell.p ? 1U : 0U;
        totals.p_false_positive += cell.p_false_positive ? 1U : 0U;
        totals.p_catches += (cell.d_false_positive && !cell.p) ? 1U : 0U;
    }
    return totals;
}

void PrintClass(const ClassTotals& totals) {
    std::cout << "RESIDUAL-CLASS class=" << totals.cls << " cells=" << totals.cells
              << " D_true=" << totals.d_true << " gate_taken=" << totals.gate_taken
              << " model_mismatch_cells=" << totals.model_mismatch_cells
              << " candidate_returned=" << totals.candidate_returned
              << " D_false_positive=" << totals.d_false_positive << " P_true=" << totals.p_true
              << " P_false_positive=" << totals.p_false_positive << "\n";
}

// The seven control forms, measured without printing — the TOTALS line
// needs their verdict, the CONTROL lines are printed by the first test.
bool ControlMatchesTask037() {
    const std::vector<std::uint8_t> seed = control::Seed();
    for (const control::Form& form : control::Forms()) {
        const control::FormCell cell = control::MeasureForm(
            seed, control::kFieldA, control::kFieldB, form.derived, form.rhs, form.predicate);
        if (cell.discriminator != form.expect_bound) {
            return false;
        }
    }
    return true;
}

}  // namespace

// The control. D is recomputed on the seven forms of the domain map with
// the task-037 fixture verbatim; if this disagrees, the residual numbers
// below are measuring a different predicate and nothing else in the file
// can be read.
TEST(DiscriminatorResidual, ControlFormsReproduceTask037) {
    const std::vector<std::uint8_t> seed = control::Seed();
    unsigned agreed = 0;
    unsigned bound_expected = 0;

    for (const control::Form& form : control::Forms()) {
        const control::FormCell cell = control::MeasureForm(
            seed, control::kFieldA, control::kFieldB, form.derived, form.rhs, form.predicate);
        const bool agrees = cell.discriminator == form.expect_bound;
        agreed += agrees ? 1U : 0U;
        bound_expected += form.expect_bound ? 1U : 0U;

        std::cout << "RESIDUAL-CONTROL form=" << form.name
                  << " derived_kind=" << KindName(cell.derived_kind)
                  << " gate_survived=" << YesNo(cell.gate_survived)
                  << " D=" << YesNo(cell.discriminator) << " outcome=" << OutcomeName(cell.outcome)
                  << " pinned=" << (form.expect_bound ? "BOUND" : "NO-BINDING")
                  << " agrees=" << YesNo(agrees) << "\n";
    }

    EXPECT_EQ(bound_expected, 2U) << "the control must quote 2 BOUND / 5 NO-BINDING";
    EXPECT_EQ(agreed, 7U) << "D no longer reproduces the task-037 classification";
}

// The residual table: 45 cells of three already measured classes, each with
// D, the post-check P and the truth column of its own source.
TEST(DiscriminatorResidual, ResidualTableIsEmitted) {
    const std::vector<ResidualCell> cells048 = CollectTask048();
    const std::vector<ResidualCell> cells053 = CollectTask053();
    const std::vector<ResidualCell> cells056 = CollectTask056();

    for (const ResidualCell& cell : cells048) {
        PrintCell(cell);
    }
    for (const ResidualCell& cell : cells053) {
        PrintCell(cell);
    }
    for (const ResidualCell& cell : cells056) {
        PrintCell(cell);
    }

    const ClassTotals t048_totals = TallyClass("task048", cells048);
    const ClassTotals t053_totals = TallyClass("task053", cells053);
    const ClassTotals t056_totals = TallyClass("task056", cells056);
    PrintClass(t048_totals);
    PrintClass(t053_totals);
    PrintClass(t056_totals);

    const unsigned cells = t048_totals.cells + t053_totals.cells + t056_totals.cells;
    const unsigned d_true = t048_totals.d_true + t053_totals.d_true + t056_totals.d_true;
    const unsigned gate_taken =
        t048_totals.gate_taken + t053_totals.gate_taken + t056_totals.gate_taken;
    const unsigned d_fp =
        t048_totals.d_false_positive + t053_totals.d_false_positive + t056_totals.d_false_positive;
    const unsigned p_true = t048_totals.p_true + t053_totals.p_true + t056_totals.p_true;
    const unsigned p_fp =
        t048_totals.p_false_positive + t053_totals.p_false_positive + t056_totals.p_false_positive;
    const unsigned p_catches =
        t048_totals.p_catches + t053_totals.p_catches + t056_totals.p_catches;

    const double d_fp_rate = static_cast<double>(d_fp) / 45.0;
    const bool class_totals_match_sources =
        t048_totals.candidate_returned == 6U && t048_totals.gate_taken == 0U &&
        t053_totals.gate_taken == 0U && t053_totals.model_mismatch_cells == 9U &&
        t056_totals.gate_taken == 18U && t056_totals.model_mismatch_cells == 17U;

    std::cout << "RESIDUAL-TOTALS cells=" << cells << " classes=3 control_cells=7"
              << " D_true=" << d_true << " gate_taken=" << gate_taken
              << " D_false_positive=" << d_fp << " D_false_positive_rate=" << std::fixed
              << std::setprecision(4) << d_fp_rate << std::defaultfloat << " P_true=" << p_true
              << " P_false_positive=" << p_fp << " P_catches_D_errors=" << p_catches << "/" << d_fp
              << " control_matches_task037=" << YesNo(ControlMatchesTask037())
              << " class_totals_match_sources=" << YesNo(class_totals_match_sources)
              << " src_modified=0 new_fuzzing_runs=0\n";

    EXPECT_EQ(cells, 45U);
    // The numbers of the three sources, reproduced rather than restated.
    EXPECT_EQ(t048_totals.candidate_returned, 6U);  // test_false_success.cpp:585
    EXPECT_EQ(t048_totals.gate_taken, 0U);          // test_false_success.cpp:586
    EXPECT_EQ(t053_totals.gate_taken, 0U);          // docs/experiments/solver-binding-overlap
    EXPECT_EQ(t053_totals.model_mismatch_cells, 9U);
    EXPECT_EQ(t056_totals.gate_taken, 18U);  // docs/experiments/solver-binding-overlap-order
    EXPECT_EQ(t056_totals.model_mismatch_cells, 17U);
}
