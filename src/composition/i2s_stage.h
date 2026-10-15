// SPDX-License-Identifier: MIT
#pragma once
#include <memory>

#include "stage.h"
namespace mlfuzzz3::composition {
std::unique_ptr<core::Stage> make_i2s_stage(bool allow_partial);
}  // namespace mlfuzzz3::composition
