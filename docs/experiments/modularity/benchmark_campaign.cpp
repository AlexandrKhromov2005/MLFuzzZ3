// SPDX-License-Identifier: MIT
// Controller-only comparison with a deterministic in-memory execution backend.
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>

#include "campaign.h"
#include "mutators/havoc.h"
#include "runner.h"
#ifdef MODULAR_BENCHMARK
#include "artifacts.h"
#include "campaign_factory.h"
#endif
namespace {
class Backend final : public mlfuzzz3::core::Runner {
   public:
    tl::expected<mlfuzzz3::ipc::v1::RunResponse, mlfuzzz3::ipc::IpcError> Run(
        std::span<const std::uint8_t> input) override {
        checksum += input.size() + (input.empty() ? 0 : input.front());
        mlfuzzz3::ipc::v1::RunResponse response;
        response.set_status(mlfuzzz3::ipc::v1::EXEC_STATUS_OK);
        return response;
    }
    std::vector<mlfuzzz3::coverage::BranchReader::Record> LastBranchRecords() const override {
        return {};
    }
    std::uint64_t checksum = 0;
};
}  // namespace
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const std::filesystem::path output(argv[1]);
    const bool journal = std::string_view(argv[2]) == "journal";
    auto corpus = mlfuzzz3::core::Corpus::Create(output);
    auto metrics = mlfuzzz3::core::MetricsEmitter::Create(output / "metrics.jsonl", "benchmark");
    if (!corpus || !metrics) return 3;
    std::vector<std::uint8_t> bytes(32);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::uint8_t>(i);
    if (!corpus->Add(mlfuzzz3::mutation::FuzzInput(bytes), 0)) return 4;
    Backend backend;
    mlfuzzz3::mutation::HavocMutator mutator;
    mlfuzzz3::core::RandomScheduler scheduler(1234);
    mlfuzzz3::core::CampaignConfig config;
    config.rng_seed = 1234;
    config.max_iterations = 100000;
    config.max_det_steps = 0;
    config.metrics_interval = 0;
    config.concolic_enabled = false;
    const auto cpu_start = std::clock();
    const auto start = std::chrono::steady_clock::now();
    std::uint64_t executed = 0;
    {
#ifdef MODULAR_BENCHMARK
        mlfuzzz3::composition::CompositionConfig resolved;
        resolved.profile = "mutation-only";
        resolved.components.seed = 1234;
        resolved.campaign = config;
        resolved.stages = {"mutation"};
        auto parts = mlfuzzz3::composition::make_campaign(backend, mutator, scheduler, resolved);
        if (journal) {
            parts.events = mlfuzzz3::composition::write_artifacts(output, resolved,
                                                                  {.revision = "benchmark",
                                                                   .run_id = "benchmark",
                                                                   .target = "in-memory",
                                                                   .target_args = {},
                                                                   .coverage_library = "",
                                                                   .seed_directory = ""},
                                                                  parts.backend->capabilities());
        }
        mlfuzzz3::core::CampaignLoop loop(std::move(parts), *corpus, *metrics, config);
#else
        if (journal) return 5;
        mlfuzzz3::core::CampaignLoop loop(backend, mutator, scheduler, *corpus, *metrics, config);
#endif
        executed = loop.Run().execs;
    }
    std::cout << std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count()
              << ' ' << static_cast<double>(std::clock() - cpu_start) / CLOCKS_PER_SEC << ' '
              << backend.checksum << ' ' << executed << '\n';
}
