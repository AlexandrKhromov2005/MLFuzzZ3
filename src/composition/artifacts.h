// SPDX-License-Identifier: MIT
#pragma once
#include <filesystem>
#include <memory>
#include <string>

#include "campaign.h"
#include "composition_config.h"
namespace mlfuzzz3::composition {
struct RunIdentity {
    std::string revision;
    std::string run_id;
    std::string target;
    std::string target_args;
    std::string coverage_library;
    std::string seed_directory;
};
std::unique_ptr<core::EventSink> write_artifacts(const std::filesystem::path& directory,
                                                 const CompositionConfig& config,
                                                 const RunIdentity& identity,
                                                 core::Capabilities capabilities);
}  // namespace mlfuzzz3::composition
