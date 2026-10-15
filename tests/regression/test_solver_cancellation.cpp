// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <vector>

#include "binding_provider.h"
#include "concolic.h"
#include "solver_facade.h"
namespace mlfuzzz3 {
TEST(SolverCancellationRegression, LinearBindingSearchCanBeCancelled) {
    const std::vector<std::uint8_t> seed(100000, 1);
    unsigned checks = 0;
    concolic::Fixes fixes;
    fixes.cancelled = [&checks] { return ++checks >= 3; };
    const concolic::ValueMatchBinding provider;
    const auto session = provider.Open(seed, fixes);
    EXPECT_FALSE(session->Locate(2, 8));
    EXPECT_GE(checks, 3U);
}
TEST(SolverCancellationRegression, CancellationCannotBecomeSatOrUnsat) {
    const solver::Operand variable{
        .kind = solver::Operand::Kind::kVar, .var_index = 0, .var_index2 = 0, .const_value = 0};
    const solver::Operand constant{
        .kind = solver::Operand::Kind::kConst, .var_index = 0, .var_index2 = 0, .const_value = 1};
    const std::vector<solver::Constraint> path{
        {.predicate = 0, .bit_width = 8, .lhs = variable, .rhs = constant}};
    const auto result = solver::SolveInverted(1, path, 0, 1000, {.cancelled = [] { return true; }});
    EXPECT_EQ(result.status, solver::SolveResult::Status::kTimeout);
    EXPECT_TRUE(result.model_values.empty());
}
TEST(SolverCancellationRegression, ExpiredDeadlineIsRecheckedAfterAstConstruction) {
    const solver::Operand variable{
        .kind = solver::Operand::Kind::kVar, .var_index = 0, .var_index2 = 0, .const_value = 0};
    const solver::Operand constant{
        .kind = solver::Operand::Kind::kConst, .var_index = 0, .var_index2 = 0, .const_value = 1};
    const std::vector<solver::Constraint> path{
        {.predicate = 0, .bit_width = 8, .lhs = variable, .rhs = constant}};
    const auto result =
        solver::SolveInverted(1, path, 0, 1000, {.remaining_timeout = [] { return 0U; }});
    EXPECT_EQ(result.status, solver::SolveResult::Status::kTimeout);
}
TEST(SolverCancellationRegression, CancelledReconstructionIsNotMisreportedAsMissingBinding) {
    const std::vector<std::uint8_t> seed{1};
    const std::vector<coverage::BranchReader::Record> records{{0, 0, 8, 1, 2}};
    concolic::Fixes fixes;
    fixes.cancelled = [] { return true; };
    concolic::SolveOutcome outcome = concolic::SolveOutcome::kCandidate;
    const auto candidate = concolic::SolveForCandidate(seed, records, 1000, &outcome, fixes);
    EXPECT_FALSE(candidate);
    EXPECT_EQ(outcome, concolic::SolveOutcome::kTimeout);
}
}  // namespace mlfuzzz3
