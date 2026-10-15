// SPDX-License-Identifier: MIT
#include "composition_config.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cmath>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
namespace mlfuzzz3::composition {
namespace {
void check_fields(const YAML::Node& node, std::initializer_list<std::string_view> allowed) {
    if (!node.IsMap()) {
        throw std::runtime_error("composition section must be a map");
    }
    for (const auto& field : node) {
        const auto key = field.first.as<std::string>();
        if (std::ranges::find(allowed, key) == allowed.end()) {
            throw std::runtime_error("unknown composition field: " + key);
        }
    }
}
void parse_policy_fields(const YAML::Node& node, CompositionConfig& config) {
    const auto& policy = node;
    check_fields(policy, {"type", "epsilon", "learning_rate"});
    config.strategy = policy["type"].as<std::string>();
    if (policy["epsilon"]) {
        config.epsilon = policy["epsilon"].as<double>();
    }
    if (policy["learning_rate"]) {
        config.learning_rate = policy["learning_rate"].as<double>();
    }
}
CompositionConfig make_profile_defaults(const std::string& name) {
    CompositionConfig config;
    config.profile = name;
    config.stages = {"deterministic", "mutation"};
    if (name == "legacy") {
        if (solver_stage_available()) {
            config.stages.emplace_back("i2s_smt");
        }
    } else if (name == "mutation-only") {
        config.campaign.concolic_enabled = false;
    } else if (name == "hybrid-heuristic" || name == "hybrid-ml") {
        config.campaign.legacy_preparation = false;
        config.strategy = name == "hybrid-ml" ? "contextual_bandit" : "stagnation";
        config.stages.emplace_back("i2s");
        config.stages.emplace_back("i2s_smt");
        config.i2s_allow_incomplete = false;
        config.smt_allow_incomplete = false;
    } else {
        throw std::runtime_error("unknown composition profile: " + name);
    }
    return config;
}
void parse_campaign_fields(const YAML::Node& node, CompositionConfig& config) {
    check_fields(
        node, {"max_iterations", "max_seconds", "metrics_interval", "max_det_steps",
               "run_seeds_first", "stagnation_threshold", "min_exec_interval", "adaptive_throttle",
               "fix_findfirst_index", "fix_addvars", "fix_writeback_width", "system_form"});
    auto& out = config.campaign;
    if (node["max_iterations"]) {
        out.max_iterations = node["max_iterations"].as<std::uint64_t>();
    }
    if (node["max_seconds"]) {
        out.max_seconds = node["max_seconds"].as<double>();
    }
    if (node["metrics_interval"]) {
        out.metrics_interval = node["metrics_interval"].as<std::uint64_t>();
    }
    if (node["max_det_steps"]) {
        out.max_det_steps = node["max_det_steps"].as<std::uint64_t>();
    }
    if (node["run_seeds_first"]) {
        out.run_seeds_first = node["run_seeds_first"].as<bool>();
    }
    if (node["stagnation_threshold"]) {
        out.concolic_stagnation_threshold = node["stagnation_threshold"].as<std::uint32_t>();
    }
    if (node["min_exec_interval"]) {
        out.concolic_min_exec_interval = node["min_exec_interval"].as<std::uint64_t>();
    }
    if (node["adaptive_throttle"]) {
        out.concolic_adaptive_throttle = node["adaptive_throttle"].as<bool>();
    }
    if (node["fix_findfirst_index"]) {
        out.concolic_fix_findfirst_index = node["fix_findfirst_index"].as<bool>();
    }
    if (node["fix_addvars"]) {
        out.concolic_fix_addvars = node["fix_addvars"].as<bool>();
    }
    if (node["fix_writeback_width"]) {
        out.concolic_fix_writeback_width = node["fix_writeback_width"].as<bool>();
    }
    if (node["system_form"]) {
        out.concolic_system_form = node["system_form"].as<unsigned>();
    }
}
void parse_comparison_stage_fields(const YAML::Node& node, const std::string& type,
                                   CompositionConfig& config) {
    if (type == "i2s") {
        check_fields(node, {"type", "binding", "allow_incomplete"});
    } else {
        check_fields(node, {"type", "binding", "solver", "timeout_ms", "allow_incomplete"});
    }
    if (node["binding"] && node["binding"].as<std::string>() != "value_match") {
        throw std::runtime_error("unknown binding provider");
    }
    if (node["solver"] && node["solver"].as<std::string>() != "z3") {
        throw std::runtime_error("unknown solver");
    }
    if (node["timeout_ms"]) {
        config.campaign.concolic_timeout_ms = node["timeout_ms"].as<unsigned>();
    }
    if (node["allow_incomplete"]) {
        if (type == "i2s") {
            config.i2s_allow_incomplete = node["allow_incomplete"].as<bool>();
        } else {
            config.smt_allow_incomplete = node["allow_incomplete"].as<bool>();
        }
    }
}
void parse_stage_fields(const YAML::Node& nodes, CompositionConfig& config) {
    if (!nodes.IsSequence()) {
        throw std::runtime_error("stages must be a sequence");
    }
    config.stages.clear();
    for (const auto& node : nodes) {
        const auto type = node["type"].as<std::string>();
        if (type == "mutation") {
            check_fields(node, {"type", "mutator", "operators"});
            if (node["mutator"]) {
                config.components.mutator = node["mutator"].as<std::string>();
            }
            if (node["operators"]) {
                config.components.havoc_operators =
                    node["operators"].as<std::vector<std::string>>();
            }
        } else if (type == "i2s" || type == "i2s_smt") {
            parse_comparison_stage_fields(node, type, config);
        } else {
            check_fields(node, {"type"});
        }
        config.stages.push_back(type);
    }
}
void validate_parameters(const CompositionConfig& config) {
    if (config.campaign.rng_seed != config.components.seed) {
        throw std::runtime_error("inconsistent composition RNG seeds");
    }
    if (config.schema_version != 1 || config.campaign.concolic_system_form > 2) {
        throw std::runtime_error("unsupported composition version or system form");
    }
    if (config.profile == "hybrid-ml" && config.strategy != "contextual_bandit") {
        throw std::runtime_error("hybrid-ml requires contextual_bandit");
    }
    if (config.profile == "hybrid-heuristic" && config.strategy != "stagnation") {
        throw std::runtime_error("hybrid-heuristic requires stagnation");
    }
    if (!std::isfinite(config.campaign.max_seconds) || config.campaign.max_seconds < 0 ||
        config.campaign.concolic_timeout_ms == 0 || !std::isfinite(config.epsilon) ||
        !std::isfinite(config.learning_rate) || config.epsilon < 0 || config.epsilon > 1 ||
        config.learning_rate <= 0 || config.learning_rate > 1) {
        throw std::runtime_error("invalid composition budget or learning parameters");
    }
    if (config.strategy != "legacy" && config.strategy != "stagnation" &&
        config.strategy != "contextual_bandit") {
        throw std::runtime_error("unknown strategy policy");
    }
    if ((config.profile == "legacy" || config.profile == "mutation-only") &&
        config.strategy != "legacy") {
        throw std::runtime_error("legacy profiles require legacy strategy policy");
    }
}
}  // namespace
bool i2s_stage_available() {
#ifdef MLFUZZZ3_WITH_I2S
    return true;
#else
    return false;
#endif
}
bool solver_stage_available() {
#ifdef MLFUZZZ3_WITH_CONCOLIC
    return true;
#else
    return false;
#endif
}
CompositionConfig parse_composition(const std::string& yaml,
                                    const std::optional<std::string>& profile_override) {
    const auto root = YAML::Load(yaml);
    const auto node = root && root.IsMap() && root["composition"] ? root["composition"] : root;
    const bool nested = root && root.IsMap() && static_cast<bool>(root["composition"]);
    const bool has_composition =
        nested ||
        (node && node.IsMap() &&
         (node["schema_version"] || node["profile"] || node["stages"] || node["strategy_policy"] ||
          node["seed_scheduler"] || node["admission"] || node["campaign"] || node["seed"]));
    std::string profile = "legacy";
    if (has_composition && node["profile"]) {
        profile = node["profile"].as<std::string>();
    }
    if (profile_override) {
        profile = *profile_override;
    }
    auto config = make_profile_defaults(profile);
    if (!has_composition) {
        return config;
    }
    if (nested && node["log"]) {
        throw std::runtime_error("log must be outside composition");
    }
    check_fields(node, {"schema_version", "profile", "seed_scheduler", "strategy_policy", "stages",
                        "admission", "campaign", "seed", "log"});
    if (!node["schema_version"] || node["schema_version"].as<unsigned>() != 1) {
        throw std::runtime_error("composition requires schema_version: 1");
    }
    if (node["seed"]) {
        config.components.seed = node["seed"].as<std::uint64_t>();
    }
    if (node["seed_scheduler"]) {
        check_fields(node["seed_scheduler"], {"type"});
        config.components.seed_scheduler = node["seed_scheduler"]["type"].as<std::string>();
    }
    if (node["strategy_policy"]) {
        parse_policy_fields(node["strategy_policy"], config);
    }
    if (node["stages"]) {
        parse_stage_fields(node["stages"], config);
    }
    if (node["admission"]) {
        check_fields(node["admission"], {"type"});
        if (node["admission"]["type"].as<std::string>() != "coverage_novelty") {
            throw std::runtime_error("unknown admission policy");
        }
    }
    if (node["campaign"]) {
        parse_campaign_fields(node["campaign"], config);
    }
    config.campaign.rng_seed = config.components.seed;
    config.campaign.concolic_enabled =
        std::ranges::find(config.stages, "i2s_smt") != config.stages.end();
    return config;
}
CompositionConfig load_composition(const std::string& path,
                                   const std::optional<std::string>& profile_override) {
    if (path.empty()) {
        return parse_composition("", profile_override);
    }
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open composition config: " + path);
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    return parse_composition(contents.str(), profile_override);
}
void validate_composition(const CompositionConfig& config) {
    validate_parameters(config);
    std::set<std::string> seen;
    for (const auto& stage : config.stages) {
        if (!seen.insert(stage).second) {
            throw std::runtime_error("duplicate stage: " + stage);
        }
        if (stage != "deterministic" && stage != "mutation" && stage != "i2s" &&
            stage != "i2s_smt") {
            throw std::runtime_error("unknown stage: " + stage);
        }
        if (stage == "i2s" && !i2s_stage_available()) {
            throw std::runtime_error("i2s requires I2S-enabled build");
        }
        if (stage == "i2s_smt" && !solver_stage_available()) {
            throw std::runtime_error("i2s_smt requires solver-enabled build");
        }
    }
    if (config.profile == "mutation-only" && (seen.contains("i2s") || seen.contains("i2s_smt"))) {
        throw std::runtime_error("mutation-only profile cannot contain comparison stages");
    }
    if (!seen.contains("mutation")) {
        throw std::runtime_error("mutation fallback stage is required");
    }
    if (config.strategy != "legacy" && !seen.contains("i2s")) {
        throw std::runtime_error("hybrid strategy requires i2s stage");
    }
    if (config.strategy == "legacy" && seen.contains("i2s")) {
        throw std::runtime_error("legacy strategy does not schedule i2s");
    }
    (void)Registry{}.Build(config.components);
}
std::string resolved_yaml(const CompositionConfig& config) {
    YAML::Node node;
    node["schema_version"] = config.schema_version;
    node["profile"] = config.profile;
    node["seed"] = config.components.seed;
    node["seed_scheduler"]["type"] = config.components.seed_scheduler;
    node["strategy_policy"]["type"] = config.strategy;
    node["strategy_policy"]["epsilon"] = config.epsilon;
    node["strategy_policy"]["learning_rate"] = config.learning_rate;
    for (const auto& type : config.stages) {
        YAML::Node stage;
        stage["type"] = type;
        if (type == "mutation") {
            stage["mutator"] = config.components.mutator;
            if (config.components.havoc_operators) {
                stage["operators"] = *config.components.havoc_operators;
            }
        }
        if (type == "i2s" || type == "i2s_smt") {
            stage["binding"] = "value_match";
            stage["allow_incomplete"] =
                type == "i2s" ? config.i2s_allow_incomplete : config.smt_allow_incomplete;
        }
        if (type == "i2s_smt") {
            stage["solver"] = "z3";
            stage["timeout_ms"] = config.campaign.concolic_timeout_ms;
        }
        node["stages"].push_back(stage);
    }
    node["admission"]["type"] = "coverage_novelty";
    auto campaign = node["campaign"];
    campaign["max_iterations"] = config.campaign.max_iterations;
    campaign["max_seconds"] = config.campaign.max_seconds;
    campaign["metrics_interval"] = config.campaign.metrics_interval;
    campaign["max_det_steps"] = config.campaign.max_det_steps;
    campaign["run_seeds_first"] = config.campaign.run_seeds_first;
    campaign["stagnation_threshold"] = config.campaign.concolic_stagnation_threshold;
    campaign["min_exec_interval"] = config.campaign.concolic_min_exec_interval;
    campaign["adaptive_throttle"] = config.campaign.concolic_adaptive_throttle;
    campaign["fix_findfirst_index"] = config.campaign.concolic_fix_findfirst_index;
    campaign["fix_addvars"] = config.campaign.concolic_fix_addvars;
    campaign["fix_writeback_width"] = config.campaign.concolic_fix_writeback_width;
    campaign["system_form"] = config.campaign.concolic_system_form;
    return YAML::Dump(node);
}
}  // namespace mlfuzzz3::composition
