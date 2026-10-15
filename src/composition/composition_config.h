// SPDX-License-Identifier: MIT
#pragma once
#include <optional>
#include <string>
#include <vector>

#include "campaign_types.h"
#include "components.h"
namespace mlfuzzz3::composition {
inline constexpr double kDefaultLearningRate = 0.1;
inline constexpr double kDefaultExploration = 0.1;
struct CompositionConfig {
    unsigned schema_version = 1;
    std::string profile = "legacy";
    ComponentConfig components;
    core::CampaignConfig campaign;
    std::string strategy = "legacy";
    std::vector<std::string> stages;
    bool i2s_allow_incomplete = false;
    bool smt_allow_incomplete = true;
    double epsilon = kDefaultExploration;
    double learning_rate = kDefaultLearningRate;
};
[[nodiscard]] CompositionConfig parse_composition(
    const std::string& yaml, const std::optional<std::string>& profile_override = std::nullopt);
[[nodiscard]] CompositionConfig load_composition(
    const std::string& path, const std::optional<std::string>& profile_override = std::nullopt);
void validate_composition(const CompositionConfig& config);
[[nodiscard]] std::string resolved_yaml(const CompositionConfig& config);
[[nodiscard]] bool solver_stage_available();
[[nodiscard]] bool i2s_stage_available();
}  // namespace mlfuzzz3::composition
