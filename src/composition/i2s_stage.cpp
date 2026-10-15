// SPDX-License-Identifier: MIT
#include "i2s_stage.h"

#include <array>
#include <cstdint>
#include <ranges>
#include <utility>
#include <vector>

#include "binding_provider.h"
namespace mlfuzzz3::composition {
namespace {
constexpr unsigned kByteBits = 8;
constexpr unsigned kMaxWidth = 64;
constexpr unsigned kMaxPredicate = 9;
std::optional<mutation::FuzzInput> patch(const core::StageContext& context,
                                         const core::Comparison& record,
                                         const concolic::BindingProvider::Session& binding,
                                         bool left) {
    const auto location = binding.Locate(left ? record.lhs : record.rhs, record.bit_width);
    if (!location) {
        return std::nullopt;
    }
    const auto other = left ? record.rhs : record.lhs;
    const std::uint64_t mask =
        record.bit_width == kMaxWidth ? UINT64_MAX : (std::uint64_t{1} << record.bit_width) - 1;
    const std::array<std::uint64_t, 5> values{other & mask, (other + 1) & mask, (other - 1) & mask,
                                              0, mask};
    const bool before =
        concolic::evaluate_comparison(record.predicate, record.lhs, record.rhs, record.bit_width);
    for (const auto value : values) {
        if (concolic::evaluate_comparison(record.predicate, left ? value : record.lhs,
                                          left ? record.rhs : value, record.bit_width) == before) {
            continue;
        }
        std::vector<std::uint8_t> bytes(context.seed.begin(), context.seed.end());
        const auto width = static_cast<std::size_t>(location->bit_width / kByteBits);
        for (std::size_t byte = 0; byte < width; ++byte) {
            const auto shift = (location->big_endian ? width - byte - 1 : byte) * kByteBits;
            bytes.at(location->offset + byte) = static_cast<std::uint8_t>(value >> shift);
        }
        return mutation::FuzzInput(std::move(bytes));
    }
    return std::nullopt;
}
core::StageResult search(const core::StageContext& context, core::ExecutionService& execution,
                         const std::vector<core::Comparison>& records) {
    const concolic::ValueMatchBinding provider;
    concolic::Fixes fixes;
    fixes.cancelled = [&execution] { return execution.exhausted(); };
    const auto binding = provider.Open(context.seed, fixes);
    for (const auto& record : records | std::views::reverse) {
        if (execution.exhausted()) {
            return {.outcome = core::StageOutcome::kCancelled};
        }
        if (record.predicate > kMaxPredicate || record.bit_width == 0 ||
            record.bit_width > kMaxWidth || record.bit_width % kByteBits != 0) {
            continue;
        }
        for (const bool left : {true, false}) {
            if (auto candidate = patch(context, record, *binding, left)) {
                return {.outcome = core::StageOutcome::kCandidate,
                        .candidate = std::move(candidate)};
            }
        }
    }
    return {.outcome = execution.exhausted() ? core::StageOutcome::kCancelled
                                             : core::StageOutcome::kNoBinding};
}
class I2sStage final : public core::Stage {
   public:
    explicit I2sStage(bool allow_partial) : allow_partial_(allow_partial) {}
    [[nodiscard]] std::string_view name() const override {
        return "i2s";
    }
    [[nodiscard]] core::StageKind kind() const override {
        return core::StageKind::kI2s;
    }
    [[nodiscard]] core::Capabilities required() const override {
        return {.comparisons = true};
    }
    core::StageResult generate(const core::StageContext& context, core::ExecutionService& execution,
                               std::mt19937_64& /*rng*/) override {
        auto observed =
            execution.execute(context.seed, core::RunPurpose::kComparisons, context.decision_id);
        if (!observed) {
            return {.outcome = core::StageOutcome::kCancelled};
        }
        if (observed->status == core::ExecutionStatus::kInfrastructureError) {
            return {.outcome = core::StageOutcome::kInfrastructureError};
        }
        if (!observed->comparisons_available || observed->status != core::ExecutionStatus::kOk ||
            (!allow_partial_ && !observed->comparisons_complete)) {
            return {.outcome = core::StageOutcome::kNotApplicable};
        }
        return search(context, execution, observed->comparisons);
    }

   private:
    bool allow_partial_;
};
}  // namespace
std::unique_ptr<core::Stage> make_i2s_stage(bool allow_partial) {
    return std::make_unique<I2sStage>(allow_partial);
}
}  // namespace mlfuzzz3::composition
