#include "self_check.h"

#include <z3++.h>

namespace mlfuzzz3::solver {

namespace {

// Width of the self-check bit-vectors. 32 bits exercises a typical
// machine-word comparison and comfortably holds the unsigned literals
// below.
constexpr unsigned kSelfCheckBvWidth = 32;

// SAT query bounds: 5 < x < 10 (solutions 6..9 exist).
constexpr unsigned kSatLowerExclusive = 5;
constexpr unsigned kSatUpperExclusive = 10;

// UNSAT query bounds: x > 7 AND x < 3 (no value satisfies both).
constexpr unsigned kUnsatLowerExclusive = 7;
constexpr unsigned kUnsatUpperExclusive = 3;

// CheckBounds returns the solver verdict for the unsigned bit-vector
// conjunction (x > lower) AND (x < upper). The unsigned relations
// ugt/ult pin the query to the bit-vector theory rather than integer
// arithmetic.
z3::check_result CheckBounds(z3::context& ctx, unsigned lower, unsigned upper) {
    z3::solver solver(ctx);
    const z3::expr x = ctx.bv_const("x", kSelfCheckBvWidth);
    solver.add(z3::ugt(x, ctx.bv_val(lower, kSelfCheckBvWidth)));
    solver.add(z3::ult(x, ctx.bv_val(upper, kSelfCheckBvWidth)));
    return solver.check();
}

}  // namespace

bool SelfCheck() {
    try {
        z3::context ctx;
        const bool sat_ok = CheckBounds(ctx, kSatLowerExclusive, kSatUpperExclusive) == z3::sat;
        const bool unsat_ok =
            CheckBounds(ctx, kUnsatLowerExclusive, kUnsatUpperExclusive) == z3::unsat;
        return sat_ok && unsat_ok;
    } catch (const z3::exception&) {
        return false;
    }
}

}  // namespace mlfuzzz3::solver
