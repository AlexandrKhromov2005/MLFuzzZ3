// SPDX-License-Identifier: MIT
// A solver-disabled campaign owns no throttle requiring an out-of-line destructor.
#include <type_traits>

#include "campaign.h"

#ifndef MLFUZZZ3_WITH_CONCOLIC
static_assert(std::is_destructible_v<mlfuzzz3::core::CampaignLoop>);
#endif
