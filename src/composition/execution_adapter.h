// SPDX-License-Identifier: MIT
#pragma once
#include "execution.h"
#include "runner.h"
namespace mlfuzzz3::composition {
class RunnerBackend final : public core::ExecutionBackend {
   public:
    explicit RunnerBackend(core::Runner& runner) : runner_(&runner) {}
    core::ExecutionResult execute(std::span<const std::uint8_t> input,
                                  core::RunPurpose purpose) override;
    [[nodiscard]] core::Capabilities capabilities() const override {
        return {.coverage = runner_->has_coverage_channel(),
                .comparisons = runner_->has_comparison_channel()};
    }

   private:
    core::Runner* runner_;
};
}  // namespace mlfuzzz3::composition
