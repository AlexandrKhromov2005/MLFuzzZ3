// SPDX-License-Identifier: MIT
#include "artifacts.h"

#include <yaml-cpp/yaml.h>

#include <fstream>
#include <stdexcept>
namespace mlfuzzz3::composition {
namespace {
class FileEvents final : public core::EventSink {
   public:
    explicit FileEvents(const std::filesystem::path& path) : output_(path) {
        if (!output_) {
            throw std::runtime_error("cannot create campaign event stream");
        }
        output_.exceptions(std::ios::badbit | std::ios::failbit);
    }
    void on_decision(const core::Decision& decision) override {
        output_ << R"({"event":"decision","decision_id":)" << decision.id << R"(,"seed_index":)"
                << decision.seed_index << R"(,"stage":)" << static_cast<int>(decision.stage)
                << R"(,"timeout_ms":)" << decision.timeout_ms << R"(,"max_executions":)"
                << decision.max_executions << R"(,"context_bin":)" << decision.context_bin
                << R"(,"action_index":)" << decision.action_index << "}\n";
    }
    void on_execution(const core::ExecutionResult& result, core::RunPurpose purpose) override {
        output_ << R"({"event":"execution","decision_id":)" << result.decision_id << R"(,"run_id":)"
                << result.run_id << R"(,"transport_run_id":)" << result.transport_run_id
                << R"(,"purpose":)" << static_cast<int>(purpose) << R"(,"status":)"
                << static_cast<int>(result.status) << R"(,"new_edges":)" << result.new_edges
                << R"(,"wall_seconds":)" << result.wall_seconds << R"(,"process_cpu_seconds":)"
                << result.cpu_seconds << R"(,"comparisons_available":)"
                << (result.comparisons_available ? "true" : "false")
                << R"(,"comparisons_complete":)" << (result.comparisons_complete ? "true" : "false")
                << "}\n";
    }
    void on_outcome(const core::Decision& decision, core::StageOutcome outcome,
                    const core::DecisionFeedback& feedback) override {
        output_ << R"({"event":"outcome","decision_id":)" << decision.id << R"(,"outcome":)"
                << static_cast<int>(outcome) << R"(,"execs":)" << feedback.execs
                << R"(,"new_edges":)" << feedback.new_edges << R"(,"findings":)"
                << feedback.findings << R"(,"wall_seconds":)" << feedback.wall_seconds
                << R"(,"process_cpu_seconds":)" << feedback.process_cpu_seconds << "}\n";
    }

   private:
    std::ofstream output_;
};
void write_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream output(path);
    output.exceptions(std::ios::badbit | std::ios::failbit);
    output << text << '\n';
}
}  // namespace
std::unique_ptr<core::EventSink> write_artifacts(const std::filesystem::path& directory,
                                                 const CompositionConfig& config,
                                                 const RunIdentity& identity,
                                                 core::Capabilities capabilities) {
    write_file(directory / "resolved.yaml", resolved_yaml(config));
    YAML::Node manifest;
    manifest["schema_version"] = 1;
    manifest["revision"] = identity.revision;
    manifest["run_id"] = identity.run_id;
    manifest["execution"]["target"] = identity.target;
    manifest["execution"]["target_args"] = identity.target_args;
    manifest["execution"]["coverage_library"] = identity.coverage_library;
    manifest["execution"]["seed_directory"] = identity.seed_directory;
    manifest["seed"] = config.components.seed;
    manifest["capabilities"]["execution"] = capabilities.execution;
    manifest["capabilities"]["coverage"] = capabilities.coverage;
    manifest["capabilities"]["comparisons"] = capabilities.comparisons;
    manifest["cpu_scope"] = "controller process; excludes child target and server";
    manifest["modules"]["seed_scheduler"]["name"] = config.components.seed_scheduler;
    manifest["modules"]["seed_scheduler"]["version"] = 1;
    manifest["modules"]["mutator"]["name"] = config.components.mutator;
    manifest["modules"]["mutator"]["version"] = 1;
    manifest["modules"]["strategy"]["name"] = config.strategy;
    manifest["modules"]["strategy"]["version"] = 1;
    for (const auto& name : config.stages) {
        YAML::Node stage;
        stage["name"] = name;
        stage["version"] = 1;
        stage["required"]["execution"] = true;
        stage["required"]["coverage"] = true;
        stage["required"]["comparisons"] = name == "i2s" || name == "i2s_smt";
        manifest["stages"].push_back(stage);
    }
    write_file(directory / "run-manifest.yaml", YAML::Dump(manifest));
    return std::make_unique<FileEvents>(directory / "events.jsonl");
}
}  // namespace mlfuzzz3::composition
