// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <optional>
#include <random>
#include <span>
#include <string_view>

#include "campaign_types.h"
#include "corpus.h"
#include "execution.h"
#include "fuzz_input.h"
namespace mlfuzzz3::core {
enum class StageKind { kDeterministic, kMutation, kI2s, kI2sSmt };
enum class StageOutcome {
    kCandidate,
    kExhausted,
    kNotApplicable,
    kNoBinding,
    kUnsat,
    kTimeout,
    kSolverError,
    kInfrastructureError,
    kCancelled
};
struct StageResult {
    StageOutcome outcome = StageOutcome::kExhausted;
    std::optional<mutation::FuzzInput> candidate = std::nullopt;
    std::uint64_t preparation_ms = 0;
    std::uint64_t solve_ms = 0;
    std::uint64_t build_us = 0;
    std::uint64_t solve_us = 0;
    bool solver_called = false;
    bool legacy_width_overflow = false;
    std::optional<DetState> progress = std::nullopt;
};
struct StageContext {
    std::span<const std::uint8_t> seed;
    std::uint64_t cursor = 0;
    std::uint64_t decision_id = 0;
    unsigned timeout_ms = kDefaultConcolicTimeoutMs;
    const mutation::FuzzInput* original = nullptr;  // borrowed for this generate call only
};
class Stage {
   public:
    Stage() = default;
    Stage(const Stage&) = delete;
    Stage& operator=(const Stage&) = delete;
    Stage(Stage&&) = delete;
    Stage& operator=(Stage&&) = delete;
    virtual ~Stage() = default;
    [[nodiscard]] virtual std::string_view name() const = 0;
    [[nodiscard]] virtual StageKind kind() const = 0;
    [[nodiscard]] virtual Capabilities required() const {
        return {};
    }
    virtual StageResult generate(const StageContext& context, ExecutionService& execution,
                                 std::mt19937_64& rng) = 0;
};
class AdaptiveBudget {
   public:
    AdaptiveBudget() = default;
    AdaptiveBudget(const AdaptiveBudget&) = delete;
    AdaptiveBudget& operator=(const AdaptiveBudget&) = delete;
    AdaptiveBudget(AdaptiveBudget&&) = delete;
    AdaptiveBudget& operator=(AdaptiveBudget&&) = delete;
    virtual ~AdaptiveBudget() = default;
    virtual void observe(StageOutcome outcome) = 0;
    [[nodiscard]] virtual std::uint64_t interval() const = 0;
    [[nodiscard]] virtual std::uint64_t engagements() const = 0;
};
}  // namespace mlfuzzz3::core
