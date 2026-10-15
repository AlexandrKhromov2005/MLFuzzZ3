// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "artifacts.h"
namespace mlfuzzz3::composition {
TEST(CompositionArtifacts, SavesResolvedConfigIdentityAndOwnedRunIds) {
    const auto directory =
        std::filesystem::path(::testing::TempDir()) / "composition_artifacts_test";
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto config = parse_composition("schema_version: 1\nprofile: mutation-only\nseed: 19");
    const RunIdentity identity{.revision = "revision",
                               .run_id = "run-1",
                               .target = "/target",
                               .target_args = "--flag",
                               .coverage_library = "/coverage",
                               .seed_directory = "/seeds"};
    auto sink = write_artifacts(directory, config, identity, {.comparisons = true});
    sink->on_decision({.id = 1});
    core::ExecutionResult result;
    result.run_id = 1;
    result.transport_run_id = 0;
    result.decision_id = 1;
    sink->on_execution(result, core::RunPurpose::kCandidate);
    sink->on_outcome({.id = 1}, core::StageOutcome::kCancelled, {});
    sink.reset();
    const auto manifest = YAML::LoadFile((directory / "run-manifest.yaml").string());
    EXPECT_EQ(manifest["run_id"].as<std::string>(), "run-1");
    EXPECT_EQ(manifest["seed"].as<unsigned>(), 19U);
    EXPECT_EQ(manifest["execution"]["target_args"].as<std::string>(), "--flag");
    std::ifstream input(directory / "events.jsonl");
    std::string line;
    unsigned count = 0;
    while (std::getline(input, line)) {
        EXPECT_TRUE(YAML::Load(line)["event"]);
        ++count;
    }
    EXPECT_EQ(count, 3U);
    std::filesystem::remove_all(directory);
}
}  // namespace mlfuzzz3::composition
