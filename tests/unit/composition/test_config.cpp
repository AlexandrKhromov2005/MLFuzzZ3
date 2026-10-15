// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <stdexcept>

#include "composition_config.h"
namespace mlfuzzz3::composition {
TEST(CompositionConfig, LegacyAndMutationDefaultsAreExplicit) {
    const auto legacy = parse_composition("");
    EXPECT_EQ(legacy.profile, "legacy");
    EXPECT_EQ(legacy.components.mutator, "havoc");
    const auto mutation = parse_composition("schema_version: 1\nprofile: mutation-only");
    EXPECT_FALSE(mutation.campaign.concolic_enabled);
    EXPECT_EQ(mutation.stages, (std::vector<std::string>{"deterministic", "mutation"}));
}
TEST(CompositionConfig, NestedCompositionLeavesSharedLogSemanticsAlone) {
    const auto config = parse_composition(
        "log: {level: debug, future: value}\ncomposition:\n  schema_version: 1\n  profile: "
        "mutation-only\n  seed: 37\n  seed_scheduler: {type: round-robin}");
    EXPECT_EQ(config.components.seed, 37U);
    EXPECT_EQ(config.components.seed_scheduler, "round-robin");
    validate_composition(config);
}
TEST(CompositionConfig, UnknownFieldsAndInvalidVersionFail) {
    for (const auto* yaml :
         {"composition: {schema_version: 1, typo: true}", "composition: {typo: true}",
          "schema_version: 2", "schema_version: 1\nseed_scheduler: {type: random, typo: 1}",
          "schema_version: 1\nstages: [{type: mutation, typo: true}]"}) {
        EXPECT_THROW((void)parse_composition(yaml), std::runtime_error) << yaml;
    }
}
TEST(CompositionConfig, RejectsUnknownModulesDuplicateStagesAndMissingFallback) {
    for (const auto* yaml : {"schema_version: 1\nstages: [{type: missing}]",
                             "schema_version: 1\nstages: [{type: mutation}, {type: mutation}]",
                             "schema_version: 1\nstages: [{type: deterministic}]",
                             "schema_version: 1\nseed_scheduler: {type: missing}",
                             "schema_version: 1\nstrategy_policy: {type: missing}"}) {
        EXPECT_THROW(validate_composition(parse_composition(yaml)), std::runtime_error) << yaml;
    }
}
TEST(CompositionConfig, ResolvedConfigurationRoundTrips) {
    const auto first = parse_composition(
        "schema_version: 1\nprofile: mutation-only\nseed: 37\nstages: [{type: mutation, mutator: "
        "byteflip}]\ncampaign: {max_iterations: 7, max_det_steps: 0}");
    const auto second = parse_composition(resolved_yaml(first));
    EXPECT_EQ(resolved_yaml(first), resolved_yaml(second));
}
TEST(CompositionConfig, RejectsInvalidBudgetsAndLearningParameters) {
    for (const auto* yaml :
         {"schema_version: 1\ncampaign: {max_seconds: -.inf}",
          "schema_version: 1\ncampaign: {max_seconds: -1}",
          "schema_version: 1\nstrategy_policy: {type: legacy, epsilon: 2}",
          "schema_version: 1\nstrategy_policy: {type: legacy, learning_rate: 0}"}) {
        EXPECT_THROW(validate_composition(parse_composition(yaml)), std::runtime_error) << yaml;
    }
}
TEST(CompositionConfig, OptionalModulesMustBeAvailable) {
    const auto yaml = "schema_version: 1\nprofile: hybrid-heuristic";
    if (solver_stage_available() && i2s_stage_available()) {
        EXPECT_NO_THROW(validate_composition(parse_composition(yaml)));
    } else {
        EXPECT_THROW(validate_composition(parse_composition(yaml)), std::runtime_error);
    }
}
}  // namespace mlfuzzz3::composition

namespace mlfuzzz3::composition {
TEST(CompositionConfig, RoundTripPreservesSolverFixesEvenWhenSolverDisabled) {
    const auto config = parse_composition(
        "schema_version: 1\nprofile: mutation-only\ncampaign: {fix_findfirst_index: true, "
        "fix_addvars: true, fix_writeback_width: true, system_form: 2}");
    const auto restored = parse_composition(resolved_yaml(config));
    EXPECT_TRUE(restored.campaign.concolic_fix_findfirst_index);
    EXPECT_TRUE(restored.campaign.concolic_fix_addvars);
    EXPECT_TRUE(restored.campaign.concolic_fix_writeback_width);
    EXPECT_EQ(restored.campaign.concolic_system_form, 2U);
}
TEST(CompositionConfig, ProfileNamesCannotMislabelAnUnrelatedPolicy) {
    EXPECT_THROW(validate_composition(parse_composition(
                     "schema_version: 1\nprofile: hybrid-ml\nstrategy_policy: {type: stagnation}")),
                 std::runtime_error);
}
}  // namespace mlfuzzz3::composition

namespace mlfuzzz3::composition {
TEST(CompositionConfig, OperatorMenuIsResolvedAndRejectsUnsupportedNames) {
    const auto config = parse_composition(
        "schema_version: 1\nprofile: mutation-only\nstages: [{type: mutation, mutator: havoc, "
        "operators: [byte, flip1]}]");
    ASSERT_TRUE(config.components.havoc_operators);
    EXPECT_EQ(*config.components.havoc_operators, (std::vector<std::string>{"byte", "flip1"}));
    EXPECT_NO_THROW(validate_composition(config));
    EXPECT_EQ(resolved_yaml(config), resolved_yaml(parse_composition(resolved_yaml(config))));
    EXPECT_THROW(validate_composition(parse_composition(
                     "schema_version: 1\nstages: [{type: mutation, operators: [missing]}]")),
                 std::invalid_argument);
    EXPECT_THROW(validate_composition(parse_composition(
                     "schema_version: 1\nstages: [{type: mutation, operators: []}]")),
                 std::invalid_argument);
}
}  // namespace mlfuzzz3::composition

namespace mlfuzzz3::composition {
TEST(CompositionConfig, NestedLogAndUnversionedSeedCannotBeSilentlyIgnored) {
    EXPECT_THROW((void)parse_composition("composition: {schema_version: 1, log: {level: debug}}"),
                 std::runtime_error);
    EXPECT_THROW((void)parse_composition("seed: 37"), std::runtime_error);
}
}  // namespace mlfuzzz3::composition
