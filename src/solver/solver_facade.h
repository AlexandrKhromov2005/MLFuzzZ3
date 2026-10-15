// SolverFacade — thin Z3 boundary for the Phase 3 concolic slice
// (ADR 0035 "Решение §1"; supersedes the single-variable ADR 0034 v1).
// The only consumer of z3++.h in the project besides self_check; Z3 stays
// an implementation detail of this layer (PRIVATE-linked libz3) and is
// never exposed on this public surface — this header uses standard types
// only.
//
// The facade reconstructs bit-vector comparison constraints from
// branch-value log records (ADR 0033) over a small set of symbolic
// variables (one per findable input value), supports cross-field links
// between two variables (ordering, sum-with-overflow), negates one target
// constraint, and solves the resulting system.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace mlfuzzz3::solver {

/// One side of a constraint. A side is either a symbolic variable
/// (`kVar`, identified by `var_index`), a concrete constant from the log
/// (`kConst`, truncated to the constraint's `bit_width`), or the sum of
/// two variables (`kAddVars`, `var_index + var_index2`) — the single
/// arithmetic link the MVP needs for the cross-field sum-with-overflow
/// constraint (ADR 0035). `kAddVars` is defined only for operands of the
/// same width; the addition is a bit-vector add that wraps modulo
/// 2^bit_width, exactly as `uint32_t` overflow in C.
struct Operand {
    enum class Kind { kVar, kConst, kAddVars } kind;
    std::size_t var_index;      ///< kVar/kAddVars: index of the first variable.
    std::size_t var_index2;     ///< kAddVars: index of the second variable.
    std::uint64_t const_value;  ///< kConst: concrete constant, truncated to bit_width.
};

/// One comparison constraint `lhs <predicate> rhs`, both sides `Operand`,
/// evaluated at `bit_width` (ADR 0033 `fuzzer_rt_branch_record`).
///
/// Operand-side convention (ADR 0035 "Решение §1" — the contract the
/// concolic orchestrator in session B must honour): which side is a
/// variable vs a constant is decided by input-to-state findability, NOT
/// by position. The LLVM operand order `icmp <pred>, lhs, rhs` is
/// preserved here (the predicate and operand order are taken verbatim
/// from the log), which matters for the asymmetric `<`/`>` predicates.
/// Both operands are sign/zero-extended to 64 bits in the log; the facade
/// truncates each to `bit_width` before use.
struct Constraint {
    std::uint8_t predicate;  ///< fuzzer_rt_cmp_kind: Eq=0 .. Sge=9.
    std::uint8_t bit_width;  ///< operand width in bits: 8/16/32/64.
    Operand lhs;
    Operand rhs;
};

/// Outcome of a solve. `model_values` is populated only for kSat and is
/// indexed by `var_index` (entry i is the satisfying value of variable i).
struct SolveResult {
    enum class Status { kSat, kUnsat, kTimeout, kError } status;
    std::vector<std::uint64_t> model_values;
};

/// Optional cooperative cancellation and remaining wall-time for campaign calls.
/// Empty callbacks preserve offline solver behavior.
struct SolverControl {
    std::function<bool()> cancelled = nullptr;
    std::function<unsigned()> remaining_timeout = nullptr;
};

/// Solve `{ path[i] : i != target_index } ∧ ¬path[target_index]` over
/// `num_vars` bit-vector variables and return a satisfying value for each
/// variable — input field values that keep every non-target comparison on
/// its observed side while flipping the target comparison.
///
/// Each variable's width is the maximum `bit_width` of the constraints
/// that reference it; a narrower constraint uses the LOW `bit_width` bits
/// of the variable (extract). Constants are truncated to their
/// constraint's `bit_width`. `kAddVars` adds the two variables at the
/// constraint's `bit_width` (wrapping bit-vector addition).
///
/// Returns kError on an empty path, an out-of-range `target_index`, an
/// invalid `bit_width` (0 or >64), or an operand referencing a variable
/// index >= `num_vars`; kTimeout when Z3 returns `unknown` (including
/// exhausting the `timeout_ms` budget); kError on any Z3 exception.
///
/// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): order fixed by ADR 0035 §1.
SolveResult SolveInverted(std::size_t num_vars, const std::vector<Constraint>& path,
                          std::size_t target_index, unsigned timeout_ms,
                          const SolverControl& control = {});

}  // namespace mlfuzzz3::solver
