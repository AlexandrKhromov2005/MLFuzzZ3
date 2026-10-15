// SPDX-License-Identifier: MIT
// Copying an execution service would duplicate mutable global/local budget counters.
#include <type_traits>

#include "execution.h"
static_assert(!std::is_copy_constructible_v<mlfuzzz3::core::ExecutionService>);
static_assert(!std::is_copy_assignable_v<mlfuzzz3::core::ExecutionService>);
static_assert(!std::is_move_constructible_v<mlfuzzz3::core::ExecutionService>);
static_assert(!std::is_move_assignable_v<mlfuzzz3::core::ExecutionService>);
