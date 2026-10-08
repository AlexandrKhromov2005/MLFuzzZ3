// task-028 (ADR 0035 §2): which constraint do we actually invert?
//
// BuildSystem picks the target by POSITION, not by identity:
//   sys.target_index = sys.invertible ? sys.path.size() - 1 : 0
// (src/concolic/concolic.cpp:255), and that index is what reaches
// solver::SolveInverted (src/concolic/concolic.cpp:293). Nothing checks
// that the last surviving record is the gate the caller cares about.
//
// Every existing concolic harness puts the gate LAST by construction
// (test_domain_map.cpp:82-140, test_unsat_anatomy.cpp,
// test_binding_collision.cpp), so the assumption is baked into the
// measurement itself. These cells vary the gate's POSITION in the trace and
// pin, per cell: sys.path.size(), the computed target_index, the predicate
// and Operand::Kind of both sides of the record that became the target,
// SolveOutcome, and the END-TO-END check — apply the candidate to the seed
// and re-evaluate the ORIGINAL gate predicate at the real field offsets.
//
// The encoding is NOT changed here: this file only reads BuildSystem /
// SolveForCandidate.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
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
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

// fuzzer_rt_cmp_kind values (ADR 0033, fixed ABI) — see
// src/concolic/concolic.cpp:13-25.
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUgt = 4 };

constexpr unsigned kTimeoutMs = 5000;
constexpr unsigned kWidth = 32;
constexpr std::uint64_t kMod32 = std::uint64_t{1} << 32;

// Seed with 28 pairwise-distinct bytes, so every 4-byte window is uniquely
// identified by its offset and FindFirst (concolic.cpp:136-166) cannot
// alias two fields. Six little-endian 32-bit fields at 0/4/8/12/16/20.
constexpr std::uint8_t kSeedBytes[] = {
    0x44, 0x33, 0x22, 0x11,  // A = 0x11223344 @ 0
    0x88, 0x77, 0x66, 0x55,  // B = 0x55667788 @ 4
    0xCC, 0xBB, 0xAA, 0x99,  // C = 0x99AABBCC @ 8
    0x01, 0xFF, 0xEE, 0xDD,  // D = 0xDDEEFF01 @ 12
    0x05, 0x04, 0x03, 0x02,  // E = 0x02030405 @ 16
    0x09, 0x08, 0x07, 0x06,  // F = 0x06070809 @ 20
    0x0A, 0x0B, 0x0C, 0x0D,  // filler
};

constexpr std::uint64_t kA = 0x11223344;
constexpr std::uint64_t kB = 0x55667788;
constexpr std::uint64_t kC = 0x99AABBCC;
constexpr std::uint64_t kD = 0xDDEEFF01;
constexpr std::uint64_t kE = 0x02030405;
constexpr std::uint64_t kF = 0x06070809;

constexpr std::size_t kOffsetA = 0;
constexpr std::size_t kOffsetB = 4;
constexpr std::size_t kOffsetD = 12;
constexpr std::size_t kOffsetE = 16;

// The gate under study: `A + B == kGateConst`, false on the seed, so its
// as-taken conjunct is kNe and inverting it demands A + B == kGateConst.
// kGateConst is neither a substring of the seed nor any pair sum of the six
// fields, so it binds as kConst; kGateSum is not a substring either, so it
// binds through the pair search as kAddVars(A, B).
constexpr std::uint64_t kGateConst = 0x0BADF00D;
constexpr std::uint64_t kGateSum = (kA + kB) % kMod32;  // 0x6688AACC

// A second AddVars-vs-Const record of exactly the same SHAPE as the gate,
// over two other fields: `D + E == kForeignConst`, also false on the seed.
constexpr std::uint64_t kForeignConst = 0x0BADF00E;
constexpr std::uint64_t kForeignSum = (kD + kE) % kMod32;  // 0xDFF20306

// Guard constants: unreachable upper bounds, so every guard is TRUE on the
// seed and keeps its logged predicate.
constexpr std::uint64_t kTopC = 0xFFFFFFFF;
constexpr std::uint64_t kTopD = 0xFFFFFFFF;
constexpr std::uint64_t kTopE = 0xFFFFFFFE;
constexpr std::uint64_t kTopF = 0xFFFFFFFD;

std::vector<std::uint8_t> Seed() {
    return {std::begin(kSeedBytes), std::end(kSeedBytes)};
}

BranchReader::Record Rec(std::uint32_t site, std::uint8_t predicate, std::uint64_t lhs,
                         std::uint64_t rhs) {
    return {site, predicate, static_cast<std::uint8_t>(kWidth), lhs, rhs};
}

// Preamble that makes A, B and C findable fields: an operand is only
// collected as a variable when its OWN value occurs in the seed
// (concolic.cpp:216-225), and the gate only logs the SUM A+B.
std::vector<BranchReader::Record> Preamble() {
    return {
        Rec(0, kUgt, kA, 1),
        Rec(1, kUgt, kB, 2),
        Rec(2, kUlt, kC, kTopC),
    };
}

BranchReader::Record Gate() {
    return Rec(10, kEq, kGateSum, kGateConst);
}

// Same record shape as Gate(), but with both sides unfindable and not
// expressible as a pair sum -> kConst vs kConst -> silently dropped
// (concolic.cpp:244-247).
BranchReader::Record DroppedGate() {
    return Rec(10, kEq, 0xDEADBEEF, kGateConst);
}

std::uint64_t ReadLe32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < 4; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (8U * k);
    }
    return value;
}

const char* KindName(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "Var";
        case Operand::Kind::kAddVars:
            return "AddVars";
        case Operand::Kind::kConst:
            return "Const";
    }
    return "?";
}

const char* PredName(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return "eq";
        case kNe:
            return "ne";
        case kUlt:
            return "ult";
        case kUgt:
            return "ugt";
        default:
            return "other";
    }
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

// Is `c` the encoded gate — AddVars over the fields bound at offsets 0 and
// 4, compared for as-taken inequality against kGateConst?
bool IsGate(const System& sys, const mlfuzzz3::solver::Constraint& c) {
    if (c.predicate != kNe || c.lhs.kind != Operand::Kind::kAddVars ||
        c.rhs.kind != Operand::Kind::kConst || c.rhs.const_value != kGateConst) {
        return false;
    }
    if (c.lhs.var_index >= sys.vars.size() || c.lhs.var_index2 >= sys.vars.size()) {
        return false;
    }
    return sys.vars[c.lhs.var_index].offset == kOffsetA &&
           sys.vars[c.lhs.var_index2].offset == kOffsetB;
}

struct Cell {
    const char* id = "";
    std::size_t records = 0;
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    std::uint8_t target_predicate = 0;
    Operand::Kind target_lhs = Operand::Kind::kConst;
    Operand::Kind target_rhs = Operand::Kind::kConst;
    std::uint64_t target_rhs_const = 0;
    bool target_is_gate = false;
    bool gate_in_path = false;
    SolveOutcome outcome = SolveOutcome::kError;
    bool has_candidate = false;
    bool gate_holds = false;  ///< A + B == kGateConst read back at offsets 0 / 4
    std::uint64_t candidate_a = 0;
    std::uint64_t candidate_b = 0;
    System sys;
};

Cell Measure(const char* id, const std::vector<BranchReader::Record>& records) {
    const std::vector<std::uint8_t> seed = Seed();

    Cell cell;
    cell.id = id;
    cell.records = records.size();
    cell.sys = BuildSystem(seed, records);
    cell.num_vars = cell.sys.num_vars;
    cell.path_size = cell.sys.path.size();
    cell.target_index = cell.sys.target_index;

    for (const mlfuzzz3::solver::Constraint& c : cell.sys.path) {
        if (IsGate(cell.sys, c)) {
            cell.gate_in_path = true;
        }
    }
    if (cell.sys.invertible && cell.target_index < cell.path_size) {
        const mlfuzzz3::solver::Constraint& target = cell.sys.path[cell.target_index];
        cell.target_predicate = target.predicate;
        cell.target_lhs = target.lhs.kind;
        cell.target_rhs = target.rhs.kind;
        cell.target_rhs_const = target.rhs.const_value;
        cell.target_is_gate = IsGate(cell.sys, target);
    }

    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    if (cell.has_candidate) {
        const std::vector<std::uint8_t> bytes(candidate->data(),
                                              candidate->data() + candidate->size());
        cell.candidate_a = ReadLe32(bytes, kOffsetA);
        cell.candidate_b = ReadLe32(bytes, kOffsetB);
        cell.gate_holds = ((cell.candidate_a + cell.candidate_b) % kMod32) == kGateConst;
    }
    return cell;
}

void Report(const Cell& cell) {
    std::cout << "[cell] " << cell.id << " records=" << cell.records << " path=" << cell.path_size
              << " vars=" << cell.num_vars << " target_index=" << cell.target_index << " target={"
              << PredName(cell.target_predicate) << " " << KindName(cell.target_lhs) << " vs "
              << KindName(cell.target_rhs) << " const=0x" << std::hex << cell.target_rhs_const
              << std::dec << "}"
              << " target_is_gate=" << (cell.target_is_gate ? "GATE" : "OTHER")
              << " gate_in_path=" << (cell.gate_in_path ? "yes" : "no")
              << " outcome=" << OutcomeName(cell.outcome)
              << " candidate=" << (cell.has_candidate ? "yes" : "no") << " A'=0x" << std::hex
              << cell.candidate_a << " B'=0x" << cell.candidate_b << " A'+B'=0x"
              << ((cell.candidate_a + cell.candidate_b) % kMod32) << std::dec
              << " gate_holds=" << (cell.gate_holds ? "YES" : "NO") << "\n";
}

// --- cell traces ---------------------------------------------------------

// (i) control: the gate is last, exactly the shape every existing harness
// builds.
std::vector<BranchReader::Record> TraceGateLast() {
    std::vector<BranchReader::Record> records = Preamble();
    records.push_back(Gate());
    return records;
}

// (ii) one SURVIVING record after the gate.
std::vector<BranchReader::Record> TraceGatePlusOne() {
    std::vector<BranchReader::Record> records = TraceGateLast();
    records.push_back(Rec(20, kUlt, kD, kTopD));
    return records;
}

// (iii) three SURVIVING records after the gate.
std::vector<BranchReader::Record> TraceGatePlusThree() {
    std::vector<BranchReader::Record> records = TraceGatePlusOne();
    records.push_back(Rec(21, kUlt, kE, kTopE));
    records.push_back(Rec(22, kUlt, kF, kTopF));
    return records;
}

// (iv) three records after the gate that are DROPPED as const-const.
std::vector<BranchReader::Record> TraceTrailingDropped() {
    std::vector<BranchReader::Record> records = TraceGateLast();
    records.push_back(Rec(30, kUlt, 0xDEADBEEF, 0xFEEDFACE));
    records.push_back(Rec(31, kUlt, 0xCAFEBABE, 0xB16B00B5));
    records.push_back(Rec(32, kUlt, 0x8BADF00D, 0xDEADC0DE));
    return records;
}

// (v) the GATE itself is dropped (both sides const) and the trailing
// records survive.
std::vector<BranchReader::Record> TraceGateDropped() {
    std::vector<BranchReader::Record> records = Preamble();
    records.push_back(DroppedGate());
    records.push_back(Rec(20, kUlt, kD, kTopD));
    records.push_back(Rec(21, kUlt, kE, kTopE));
    records.push_back(Rec(22, kUlt, kF, kTopF));
    return records;
}

// (vi) extra cell, not in the five positional cells: the record after the
// gate has exactly the same ENCODED SHAPE as the gate (AddVars vs Const,
// as-taken kNe) over two other fields.
std::vector<BranchReader::Record> TraceForeignSameShape() {
    std::vector<BranchReader::Record> records = Preamble();
    records.push_back(Rec(3, kUlt, kD, kTopD));
    records.push_back(Rec(4, kUlt, kE, kTopE));
    records.push_back(Gate());
    records.push_back(Rec(23, kEq, kForeignSum, kForeignConst));
    return records;
}

}  // namespace

// --- (i) control ---------------------------------------------------------

TEST(TargetSelection, GateLastIsTheControlAndTheTargetIsTheGate) {
    const Cell cell = Measure("gate_last", TraceGateLast());
    Report(cell);

    ASSERT_TRUE(cell.sys.invertible);
    EXPECT_EQ(cell.path_size, 4U);
    EXPECT_EQ(cell.target_index, 3U);
    EXPECT_TRUE(cell.gate_in_path);
    EXPECT_TRUE(cell.target_is_gate);
    EXPECT_EQ(cell.target_predicate, kNe);
    EXPECT_EQ(cell.target_lhs, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.target_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    // End-to-end: the candidate really flips the gate at the real offsets.
    EXPECT_TRUE(cell.gate_holds);
}

// --- (ii) / (iii) surviving trailing records -----------------------------

TEST(TargetSelection, OneSurvivingRecordAfterTheGateMovesTheTargetOffTheGate) {
    const Cell cell = Measure("gate_plus1", TraceGatePlusOne());
    Report(cell);

    ASSERT_TRUE(cell.sys.invertible);
    EXPECT_EQ(cell.path_size, 5U);
    EXPECT_EQ(cell.target_index, 4U);
    // The gate is still in the system — it is just no longer the target.
    EXPECT_TRUE(cell.gate_in_path);
    EXPECT_FALSE(cell.target_is_gate);
    EXPECT_EQ(cell.target_predicate, kUlt);
    EXPECT_EQ(cell.target_lhs, Operand::Kind::kVar);
    EXPECT_EQ(cell.target_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.target_rhs_const, kTopD);
    // kCandidate all the same: the caller is told the call succeeded.
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(cell.has_candidate);
    // The gate's as-taken conjunct (kNe) is ASSERTED, not flipped, so the
    // candidate provably keeps the gate on its original side.
    EXPECT_FALSE(cell.gate_holds);
}

TEST(TargetSelection, ThreeSurvivingRecordsAfterTheGateMoveTheTargetOffTheGate) {
    const Cell cell = Measure("gate_plus3", TraceGatePlusThree());
    Report(cell);

    ASSERT_TRUE(cell.sys.invertible);
    EXPECT_EQ(cell.path_size, 7U);
    EXPECT_EQ(cell.target_index, 6U);
    EXPECT_TRUE(cell.gate_in_path);
    EXPECT_FALSE(cell.target_is_gate);
    EXPECT_EQ(cell.target_predicate, kUlt);
    EXPECT_EQ(cell.target_lhs, Operand::Kind::kVar);
    EXPECT_EQ(cell.target_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.target_rhs_const, kTopF);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_holds);
}

// --- (iv) dropped trailing records ---------------------------------------

TEST(TargetSelection, ConstConstTrailingRecordsAreDroppedAndTheGateStaysTheTarget) {
    const Cell cell = Measure("trailing_dropped", TraceTrailingDropped());
    Report(cell);

    ASSERT_TRUE(cell.sys.invertible);
    EXPECT_EQ(cell.records, 7U);
    EXPECT_EQ(cell.path_size, 4U);  // three records vanished
    EXPECT_EQ(cell.target_index, 3U);
    EXPECT_TRUE(cell.gate_in_path);
    EXPECT_TRUE(cell.target_is_gate);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(cell.gate_holds);
}

TEST(TargetSelection, DroppedRecordsLeaveNoTraceInTheSystem) {
    const Cell control = Measure("gate_last", TraceGateLast());
    const Cell dropped = Measure("trailing_dropped", TraceTrailingDropped());

    // Three records were dropped and the System carries no counter, no flag
    // and no SolveOutcome difference — the two systems are identical.
    EXPECT_NE(control.records, dropped.records);
    ASSERT_EQ(control.path_size, dropped.path_size);
    EXPECT_EQ(control.num_vars, dropped.num_vars);
    EXPECT_EQ(control.target_index, dropped.target_index);
    EXPECT_EQ(control.outcome, dropped.outcome);
    for (std::size_t i = 0; i < control.path_size; ++i) {
        const auto& a = control.sys.path[i];
        const auto& b = dropped.sys.path[i];
        EXPECT_EQ(a.predicate, b.predicate) << "at " << i;
        EXPECT_EQ(a.bit_width, b.bit_width) << "at " << i;
        EXPECT_EQ(a.lhs.kind, b.lhs.kind) << "at " << i;
        EXPECT_EQ(a.rhs.kind, b.rhs.kind) << "at " << i;
        EXPECT_EQ(a.rhs.const_value, b.rhs.const_value) << "at " << i;
    }
    std::cout << "[drop-trace] records " << control.records << " -> " << dropped.records
              << ", path identical, no counter exposed\n";
}

// --- (v) the gate itself is dropped --------------------------------------

TEST(TargetSelection, DroppedGateMakesAForeignConstraintTheTarget) {
    const Cell cell = Measure("gate_dropped", TraceGateDropped());
    Report(cell);

    ASSERT_TRUE(cell.sys.invertible);
    EXPECT_EQ(cell.records, 7U);
    EXPECT_EQ(cell.path_size, 6U);  // the gate itself vanished
    EXPECT_EQ(cell.target_index, 5U);
    // The gate is not in the system at all, yet a candidate is returned.
    EXPECT_FALSE(cell.gate_in_path);
    EXPECT_FALSE(cell.target_is_gate);
    EXPECT_EQ(cell.target_predicate, kUlt);
    EXPECT_EQ(cell.target_lhs, Operand::Kind::kVar);
    EXPECT_EQ(cell.target_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.target_rhs_const, kTopF);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(cell.has_candidate);
    // gate_holds is REPORTED, not asserted: with the gate absent from the
    // system the candidate is unconstrained with respect to it, so the
    // value is the solver's model, not a logical consequence. The measured
    // value goes into the report as-is.
    std::cout << "[cell-v] gate absent from the path; measured gate_holds="
              << (cell.gate_holds ? "YES" : "NO") << "\n";
}

// --- (vi) foreign constraint of the same shape ---------------------------

TEST(TargetSelection, ForeignConstraintOfTheSameShapeBecomesTheTarget) {
    const Cell cell = Measure("foreign_same_shape", TraceForeignSameShape());
    Report(cell);

    ASSERT_TRUE(cell.sys.invertible);
    EXPECT_EQ(cell.path_size, 7U);
    EXPECT_EQ(cell.target_index, 6U);
    EXPECT_TRUE(cell.gate_in_path);
    EXPECT_FALSE(cell.target_is_gate);
    // Same encoded shape as the gate: as-taken kNe, AddVars vs Const. The
    // System exposes nothing that tells the two apart except the constant.
    EXPECT_EQ(cell.target_predicate, kNe);
    EXPECT_EQ(cell.target_lhs, Operand::Kind::kAddVars);
    EXPECT_EQ(cell.target_rhs, Operand::Kind::kConst);
    EXPECT_EQ(cell.target_rhs_const, kForeignConst);
    ASSERT_LT(cell.sys.path[6].lhs.var_index, cell.sys.vars.size());
    ASSERT_LT(cell.sys.path[6].lhs.var_index2, cell.sys.vars.size());
    EXPECT_EQ(cell.sys.vars[cell.sys.path[6].lhs.var_index].offset, kOffsetD);
    EXPECT_EQ(cell.sys.vars[cell.sys.path[6].lhs.var_index2].offset, kOffsetE);
    EXPECT_EQ(cell.outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(cell.has_candidate);
    EXPECT_FALSE(cell.gate_holds);
}

// --- "silently": nothing downstream separates the cells ------------------

TEST(TargetSelection, OutcomeCannotDistinguishASubstitutedTargetFromTheControl) {
    const Cell control = Measure("gate_last", TraceGateLast());
    const Cell plus1 = Measure("gate_plus1", TraceGatePlusOne());
    const Cell plus3 = Measure("gate_plus3", TraceGatePlusThree());
    const Cell dropped_tail = Measure("trailing_dropped", TraceTrailingDropped());
    const Cell dropped_gate = Measure("gate_dropped", TraceGateDropped());
    const Cell same_shape = Measure("foreign_same_shape", TraceForeignSameShape());

    for (const Cell* cell : {&control, &plus1, &plus3, &dropped_tail, &dropped_gate, &same_shape}) {
        EXPECT_EQ(cell->outcome, SolveOutcome::kCandidate) << cell->id;
        EXPECT_TRUE(cell->has_candidate) << cell->id;
    }
    // Cells whose target is NOT the gate are reported exactly like the
    // control: same SolveOutcome, candidate present. The orchestrator's
    // metric counts all of them as successful concolic calls.
    EXPECT_FALSE(plus1.target_is_gate);
    EXPECT_FALSE(plus3.target_is_gate);
    EXPECT_FALSE(dropped_gate.target_is_gate);
    EXPECT_FALSE(same_shape.target_is_gate);
    EXPECT_TRUE(control.target_is_gate);
    EXPECT_TRUE(dropped_tail.target_is_gate);

    std::cout << "[silent] outcome identical (kCandidate) across all six cells; "
                 "gate reached only in gate_last / trailing_dropped\n";
}
