#include <gtest/gtest.h>

#include "self_check.h"

// Proof that the bundled Z3 links into a project target and reasons
// over bit-vectors from our own code (ADR 0034 prep). SelfCheck runs a
// satisfiable and an unsatisfiable fixed-width query and returns true
// only if both verdicts match.
TEST(SolverSelfCheck, LinksAndReasonsOverBitvectors) {
    EXPECT_TRUE(mlfuzzz3::solver::SelfCheck());
}
