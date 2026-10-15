// SPDX-License-Identifier: MIT
#pragma once
#include <memory>

#include "campaign_types.h"
#include "stage.h"
namespace mlfuzzz3::composition {
std::unique_ptr<core::Stage> make_solver_stage(const core::CampaignConfig& config);
std::unique_ptr<core::AdaptiveBudget> make_solver_budget(bool enabled);
}  // namespace mlfuzzz3::composition
