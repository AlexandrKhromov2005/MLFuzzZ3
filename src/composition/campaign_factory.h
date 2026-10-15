// SPDX-License-Identifier: MIT
#pragma once
#include "campaign.h"
#include "composition_config.h"
namespace mlfuzzz3::composition {
core::CampaignParts make_campaign(core::Runner& runner, const mutation::Mutator& mutator,
                                  core::SeedScheduler& scheduler,
                                  const CompositionConfig& resolved);
core::CampaignParts make_legacy_campaign(core::Runner& runner, const mutation::Mutator& mutator,
                                         core::SeedScheduler& scheduler,
                                         core::CampaignConfig config);
}  // namespace mlfuzzz3::composition
