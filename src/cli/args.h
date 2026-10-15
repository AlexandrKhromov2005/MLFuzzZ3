#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <set>
#include <span>
#include <string>

#include "campaign.h"  // mlfuzzz3::core::kDefaultMaxDetSteps
#include "composition_config.h"

// Command-line surface of the fuzzer binary, factored out of main.cpp so
// the parser is unit-testable in isolation (ADR 0040 §Тестирование).

namespace mlfuzzz3::cli {

inline constexpr std::uint64_t kDefaultMetricsInterval = 1000;

struct Args {
    std::set<std::string> explicit_flags;
    std::string profile;
    std::string config_path;
    bool show_help = false;
    bool show_version = false;

    // Campaign mode (ADR 0029). Active when exec_server is non-empty.
    std::string exec_server;
    std::string target;
    std::string cov_library;
    std::string out_dir;
    std::string seed_dir;
    std::uint64_t max_iterations = 0;  // 0 = unbounded
    double max_seconds = 0.0;          // 0 = unbounded
    std::uint64_t metrics_interval = kDefaultMetricsInterval;
    std::uint64_t seed = 0;
    std::string seed_scheduler = "random";
    std::string mutator = "havoc";  // havoc | bitflip | byteflip
    // Per-seed deterministic-stage cap (ADR 0031). 0 disables the
    // deterministic stage entirely (0 det-execs, ADR 0032).
    std::uint64_t max_det_steps = mlfuzzz3::core::kDefaultMaxDetSteps;
    // --run-seeds-first: run every corpus seed once, unmutated, before the
    // deterministic stage and havoc (CampaignConfig::run_seeds_first).
    // Default false = unchanged loop.
    bool run_seeds_first = false;
    // Whitespace-separated arguments forwarded to the target on every
    // run (ADR 0040). Empty leaves the target argv unchanged; the input
    // is still delivered on stdin. Forwarded verbatim to the exec-server
    // -target-args flag, which splits it on whitespace.
    std::string target_args;
    // ADR 0036 experimental switch: --no-concolic disarms the concolic arm
    // for this run of THIS binary (no rebuild, no FUZZER_BUILD_Z3=OFF), so
    // the same build can be compared with the arm and without it. Default
    // true = unchanged 0036 behavior.
    bool concolic_enabled = true;
    // ADR 0049: четыре починки солверной руки, каждая за своим флагом.
    // Умолчания воспроизводят поведение до ADR 0049; включение — предмет
    // развёртки docs/experiments/solver-fix-ladder/, а не удобства.
    bool concolic_fix_findfirst_index = false;  // --concolic-fix-findfirst-index
    bool concolic_fix_addvars = false;          // --concolic-fix-addvars
    bool concolic_fix_writeback_width = false;  // --concolic-fix-writeback-width
    // --concolic-system-form=all-but-target|prefix|optimistic
    unsigned concolic_system_form = 0;
};

// Parses argv into Args. Throws std::runtime_error on an unknown flag or a
// value-taking flag missing its value. argv_view[0] is treated as the
// program name and skipped.
[[nodiscard]] Args ParseArgs(std::span<const char* const> argv_view);

// Builds the campaign configuration from parsed flags. The single place
// where CLI fields reach core::CampaignConfig, so the seam (e.g.
// --no-concolic -> concolic_enabled) is unit-testable without a campaign.
[[nodiscard]] mlfuzzz3::core::CampaignConfig MakeCampaignConfig(const Args& args);

[[nodiscard]] mlfuzzz3::composition::CompositionConfig resolve_composition(const Args& args);

// Writes the usage / options text to out.
void PrintUsage(std::ostream& out);

}  // namespace mlfuzzz3::cli
