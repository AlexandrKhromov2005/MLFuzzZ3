#include <fuzzer/version.h>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <utility>

#include "args.h"
#include "artifacts.h"
#include "campaign.h"
#include "campaign_factory.h"
#include "components.h"
#include "config.h"
#include "corpus.h"
#include "exec_server_process.h"
#include "fnv.h"
#include "log.h"
#include "metrics.h"
#include "mutator.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"

// Short git revision baked in at configure time for the metrics run id.
// Falls back to "unknown" when the build was configured outside a git
// checkout.
#ifndef MLFUZZZ3_GIT_SHA
#define MLFUZZZ3_GIT_SHA "unknown"
#endif

namespace {

using mlfuzzz3::cli::Args;

// Per-run target timeout (ms). cov_stdin and similar single-syscall
// fixtures finish instantly; the headroom guards against a slow CI host.
constexpr std::uint64_t kDefaultRunTimeoutMs = 5000;

std::string MakeRunId(const Args& args, const mlfuzzz3::composition::CompositionConfig& resolved) {
    const auto timestamp = static_cast<std::uint64_t>(std::time(nullptr));
    const std::string config_str = args.target + "|" + args.cov_library + "|" + args.seed_dir +
                                   "|" + std::to_string(args.seed) + "|" +
                                   std::to_string(args.max_iterations) + "|" +
                                   mlfuzzz3::composition::resolved_yaml(resolved);
    const std::uint64_t config_hash = mlfuzzz3::core::FnvHash(config_str);
    std::ostringstream run_id;
    run_id << timestamp << "-" << MLFUZZZ3_GIT_SHA << "-" << std::hex << config_hash;
    return run_id.str();
}

int RunCampaign(const Args& args) {
    if (args.target.empty() || args.cov_library.empty() || args.out_dir.empty()) {
        LOG_ERROR("campaign mode requires --target, --cov-library and --out-dir");
        return 2;
    }

    // Validate component names before spawning the execution server.
    const auto resolved = mlfuzzz3::cli::resolve_composition(args);
    const auto components = mlfuzzz3::composition::Registry{}.Build(resolved.components);

    auto proc = mlfuzzz3::cli::ExecServerProcess::Spawn(
        args.exec_server, args.target, args.cov_library, args.target_args, kDefaultRunTimeoutMs);
    if (!proc) {
        LOG_ERROR("failed to spawn exec-server: {}", proc.error());
        return 1;
    }

    mlfuzzz3::ipc::Conn conn(proc->TakeClientFd());
    // Two channels per worker since ADR 0033: the edge-coverage memfd
    // and the branch-value memfd. The campaign runs a single worker,
    // so the server announces exactly one of each.
    auto session = mlfuzzz3::ipc::ClientSession::Dial(
        std::move(conn), mlfuzzz3::ipc::ClientConfig{.run_timeout_ms = kDefaultRunTimeoutMs,
                                                     .expected_channels = 2});
    if (!session) {
        LOG_ERROR("exec-server handshake failed ({})", static_cast<int>(session.error()));
        return 1;
    }

    auto corpus = mlfuzzz3::core::Corpus::Create(args.out_dir);
    if (!corpus) {
        LOG_ERROR("failed to create corpus under {}", args.out_dir);
        return 1;
    }
    auto bootstrapped = corpus->Bootstrap(args.seed_dir);
    if (!bootstrapped) {
        LOG_ERROR("corpus bootstrap failed");
        return 1;
    }
    LOG_INFO("corpus bootstrapped with {} input(s)", *bootstrapped);

    const std::filesystem::path metrics_path =
        std::filesystem::path(args.out_dir) / "metrics.jsonl";
    auto metrics = mlfuzzz3::core::MetricsEmitter::Create(metrics_path, MakeRunId(args, resolved));
    if (!metrics) {
        LOG_ERROR("failed to open metrics file {}", metrics_path.string());
        return 1;
    }

    mlfuzzz3::core::SessionRunner runner(*session);
    auto parts = mlfuzzz3::composition::make_campaign(runner, *components.mutator,
                                                      *components.seed_scheduler, resolved);
    parts.events = mlfuzzz3::composition::write_artifacts(args.out_dir, resolved,
                                                          {.revision = MLFUZZZ3_GIT_SHA,
                                                           .run_id = metrics->run_id(),
                                                           .target = args.target,
                                                           .target_args = args.target_args,
                                                           .coverage_library = args.cov_library,
                                                           .seed_directory = args.seed_dir},
                                                          parts.backend->capabilities());
    mlfuzzz3::core::CampaignLoop loop(std::move(parts), *corpus, *metrics, resolved.campaign);

    LOG_INFO("campaign starting (run_id={}, mutator={}, seed_scheduler={})", metrics->run_id(),
             components.mutator->name(), components.seed_scheduler->name());
    const mlfuzzz3::core::CampaignStats stats = loop.Run();
    LOG_INFO(
        "campaign done: execs={} accepted={} edges={} crashes={} hangs={} ipc_errors={} "
        "aborted={}",
        stats.execs, stats.accepted, stats.edges, stats.crashes, stats.hangs, stats.ipc_errors,
        stats.aborted);

    if (auto shutdown = session->Shutdown(); !shutdown) {
        LOG_WARN("exec-server shutdown was not clean ({})", static_cast<int>(shutdown.error()));
    }
    return stats.aborted ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::span<const char* const> argv_view(argv, static_cast<std::size_t>(argc));
        auto args = mlfuzzz3::cli::ParseArgs(argv_view);

        if (args.show_help) {
            mlfuzzz3::cli::PrintUsage(std::cout);
            return 0;
        }
        if (args.show_version) {
            std::cout << "fuzzer v" << fuzzer::kVersion << '\n';
            return 0;
        }

        const auto cfg = args.config_path.empty() ? fuzzer::config::Defaults()
                                                  : fuzzer::config::LoadFromFile(args.config_path);

        fuzzer::log::Init(cfg.log);

        LOG_INFO("fuzzer v{} started", fuzzer::kVersion);

        if (!args.exec_server.empty()) {
            return RunCampaign(args);
        }

        LOG_INFO("config: log.level={} log.format={}", fuzzer::config::LogLevelName(cfg.log.level),
                 fuzzer::config::LogFormatName(cfg.log.format));
        LOG_INFO("no --exec-server given; nothing to do (see --help for campaign mode)");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 2;
    }
}
