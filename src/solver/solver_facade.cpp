// SolverFacade implementation (ADR 0035 "Решение §1"; supersedes ADR 0034
// v1). z3++.h is included here only — it must not leak through
// solver_facade.h.

#include "solver_facade.h"

#include <z3++.h>

#include <algorithm>
#include <string>

namespace mlfuzzz3::solver {

namespace {

// Mirror of fuzzer_rt_cmp_kind (src/runtime/coverage/mlfuzzz3_branch.h).
// Restated as local constants so the solver layer does not pull a
// runtime C header into its translation unit; the ABI values are fixed
// (ADR 0033, "do not renumber or reorder").
enum CmpKind : std::uint8_t {
    kEq = 0,
    kNe = 1,
    kUlt = 2,
    kUle = 3,
    kUgt = 4,
    kUge = 5,
    kSlt = 6,
    kSle = 7,
    kSgt = 8,
    kSge = 9,
};

constexpr unsigned kMaxBvWidth = 64;

// Default width for a variable that no constraint references (it is
// otherwise unconstrained; the model assigns it an arbitrary value).
constexpr unsigned kUnreferencedVarWidth = 8;

// Keep the low `bit_width` bits of `value`. Branch-log operands are
// sign/zero-extended to 64 bits (ADR 0035 "Что показала разведка"); a
// constant must be reduced to its real width before becoming a bv_val,
// otherwise a sign-extended negative literal would not match a
// `bit_width`-wide field, and the encoding would silently widen.
std::uint64_t TruncateToWidth(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= kMaxBvWidth) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

bool WidthValid(unsigned bit_width) {
    return bit_width != 0 && bit_width <= kMaxBvWidth;
}

bool OperandValid(const Operand& op, std::size_t num_vars) {
    switch (op.kind) {
        case Operand::Kind::kConst:
            return true;
        case Operand::Kind::kVar:
            return op.var_index < num_vars;
        case Operand::Kind::kAddVars:
            return op.var_index < num_vars && op.var_index2 < num_vars;
    }
    return false;
}

// Fold this operand's referenced variables into the per-variable width
// table: a variable is as wide as the widest constraint touching it.
void AccumulateWidths(const Operand& op, unsigned bit_width, std::vector<unsigned>& widths) {
    switch (op.kind) {
        case Operand::Kind::kConst:
            break;
        case Operand::Kind::kVar:
            widths[op.var_index] = std::max(widths[op.var_index], bit_width);
            break;
        case Operand::Kind::kAddVars:
            widths[op.var_index] = std::max(widths[op.var_index], bit_width);
            widths[op.var_index2] = std::max(widths[op.var_index2], bit_width);
            break;
    }
}

// Reduce a variable to exactly `bit_width` bits. A variable is always at
// least `bit_width` wide (its width is the max over its constraints), so
// this is the identity or a low-bit extract; the zext branch is a
// defensive no-op for the unreachable narrower case.
z3::expr ToWidth(const z3::expr& var, unsigned bit_width) {
    const unsigned var_width = var.get_sort().bv_size();
    if (var_width == bit_width) {
        return var;
    }
    if (var_width > bit_width) {
        return var.extract(bit_width - 1U, 0U);
    }
    return z3::zext(var, bit_width - var_width);
}

// Build the z3 expression for one operand at the constraint's bit_width.
z3::expr MakeOperand(z3::context& ctx, const std::vector<z3::expr>& vars, const Operand& op,
                     unsigned bit_width) {
    switch (op.kind) {
        case Operand::Kind::kConst:
            return ctx.bv_val(TruncateToWidth(op.const_value, bit_width), bit_width);
        case Operand::Kind::kVar:
            return ToWidth(vars[op.var_index], bit_width);
        case Operand::Kind::kAddVars:
            // Bit-vector add at the field width wraps mod 2^bit_width —
            // exactly C unsigned overflow (ADR 0035 SMT-encoding invariants).
            return ToWidth(vars[op.var_index], bit_width) + ToWidth(vars[op.var_index2], bit_width);
    }
    throw z3::exception("unknown operand kind");
}

// Build the BV predicate for one constraint. Operand order is preserved
// (lhs <pred> rhs), which matters for the asymmetric relations.
z3::expr MakePredicate(z3::context& ctx, const std::vector<z3::expr>& vars, const Constraint& c) {
    const z3::expr lhs = MakeOperand(ctx, vars, c.lhs, c.bit_width);
    const z3::expr rhs = MakeOperand(ctx, vars, c.rhs, c.bit_width);
    switch (c.predicate) {
        case kEq:
            return lhs == rhs;
        case kNe:
            return lhs != rhs;
        case kUlt:
            return z3::ult(lhs, rhs);
        case kUle:
            return z3::ule(lhs, rhs);
        case kUgt:
            return z3::ugt(lhs, rhs);
        case kUge:
            return z3::uge(lhs, rhs);
        case kSlt:
            return z3::slt(lhs, rhs);
        case kSle:
            return z3::sle(lhs, rhs);
        case kSgt:
            return z3::sgt(lhs, rhs);
        case kSge:
            return z3::sge(lhs, rhs);
        default:
            throw z3::exception("unknown comparison predicate");
    }
}

SolveResult Error() {
    return {.status = SolveResult::Status::kError, .model_values = {}};
}

}  // namespace

// Parameter order is fixed by the ADR 0035 §1 contract; target_index and
// timeout_ms are unavoidably convertible.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
SolveResult SolveInverted(std::size_t num_vars, const std::vector<Constraint>& path,
                          std::size_t target_index, unsigned timeout_ms) {
    // NOLINTEND(bugprone-easily-swappable-parameters)
    if (path.empty() || target_index >= path.size()) {
        return Error();
    }

    // Validate every constraint and fold variable widths in one pass.
    std::vector<unsigned> widths(num_vars, 0U);
    for (const Constraint& c : path) {
        if (!WidthValid(c.bit_width) || !OperandValid(c.lhs, num_vars) ||
            !OperandValid(c.rhs, num_vars)) {
            return Error();
        }
        AccumulateWidths(c.lhs, c.bit_width, widths);
        AccumulateWidths(c.rhs, c.bit_width, widths);
    }

    try {
        z3::context ctx;

        std::vector<z3::expr> vars;
        vars.reserve(num_vars);
        for (std::size_t i = 0; i < num_vars; ++i) {
            const unsigned width = widths[i] != 0U ? widths[i] : kUnreferencedVarWidth;
            vars.push_back(ctx.bv_const(("v" + std::to_string(i)).c_str(), width));
        }

        z3::solver solver(ctx);
        z3::params params(ctx);
        params.set("timeout", timeout_ms);
        solver.set(params);

        for (std::size_t i = 0; i < path.size(); ++i) {
            const z3::expr predicate = MakePredicate(ctx, vars, path[i]);
            // The target constraint is negated (branch inversion); every
            // other constraint is kept on its observed side.
            solver.add(i == target_index ? !predicate : predicate);
        }

        switch (solver.check()) {
            case z3::sat: {
                const z3::model model = solver.get_model();
                std::vector<std::uint64_t> values;
                values.reserve(num_vars);
                for (const z3::expr& var : vars) {
                    values.push_back(model.eval(var, true).get_numeral_uint64());
                }
                return {.status = SolveResult::Status::kSat, .model_values = std::move(values)};
            }
            case z3::unsat:
                return {.status = SolveResult::Status::kUnsat, .model_values = {}};
            case z3::unknown:
            default:
                return {.status = SolveResult::Status::kTimeout, .model_values = {}};
        }
    } catch (const z3::exception&) {
        return Error();
    }
}

}  // namespace mlfuzzz3::solver
