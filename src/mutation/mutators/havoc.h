#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <vector>

#include "../fuzz_input.h"
#include "../mutator.h"

namespace mlfuzzz3::mutation {

// Upper bound on the output length of a single HavocMutator::mutate
// (ADR 0030). Length-changing operations are gated by this cap so block
// insertions cannot grow an input without bound.
inline constexpr std::size_t kHavocMaxLen = 65536;

struct MutationOperator {
    std::string name;
    std::function<void(std::vector<std::uint8_t>&, std::mt19937_64&)> apply;
};
class OperatorSelector {
   public:
    OperatorSelector() = default;
    OperatorSelector(const OperatorSelector&) = delete;
    OperatorSelector& operator=(const OperatorSelector&) = delete;
    OperatorSelector(OperatorSelector&&) = delete;
    OperatorSelector& operator=(OperatorSelector&&) = delete;
    virtual ~OperatorSelector() = default;
    [[nodiscard]] virtual std::size_t choose(std::span<const MutationOperator> operators,
                                             std::mt19937_64& rng) const = 0;
};
class StackingPolicy {
   public:
    StackingPolicy() = default;
    StackingPolicy(const StackingPolicy&) = delete;
    StackingPolicy& operator=(const StackingPolicy&) = delete;
    StackingPolicy(StackingPolicy&&) = delete;
    StackingPolicy& operator=(StackingPolicy&&) = delete;
    virtual ~StackingPolicy() = default;
    [[nodiscard]] virtual std::size_t count(std::mt19937_64& rng) const = 0;
};
class UniformOperatorSelector final : public OperatorSelector {
   public:
    [[nodiscard]] std::size_t choose(std::span<const MutationOperator> operators,
                                     std::mt19937_64& rng) const override;
};
class LegacyStacking final : public StackingPolicy {
   public:
    [[nodiscard]] std::size_t count(std::mt19937_64& rng) const override;
};
[[nodiscard]] std::vector<MutationOperator> legacy_havoc_operators();

// HavocMutator (ADR 0030) — the mutation-engine workhorse. Per call it
// applies a random stack of AFL-style operations (bit/byte flips,
// arithmetic, "interesting" boundary values, block insert/duplicate/
// delete) so each execution explores further than the single-edit
// bit/byte flips of ADR 0027.
//
// Pure stateless function of (input, rng): same input + same initial
// RNG state ⇒ bit-identical output (replay invariant). Empty input ⇒
// empty output. For a non-empty input the output length stays in
// [1, kHavocMaxLen]. All randomness flows through the seeded RNG; no
// other entropy source is consulted.
class HavocMutator final : public Mutator {
   public:
    HavocMutator();
    HavocMutator(std::vector<MutationOperator> operators,
                 std::unique_ptr<OperatorSelector> selector,
                 std::unique_ptr<StackingPolicy> stacking);
    [[nodiscard]] FuzzInput mutate(const FuzzInput& input, std::mt19937_64& rng) const override;
    [[nodiscard]] const char* name() const noexcept override {
        return "havoc";
    }

   private:
    std::vector<MutationOperator> operators_;
    std::unique_ptr<OperatorSelector> selector_;
    std::unique_ptr<StackingPolicy> stacking_;
};

}  // namespace mlfuzzz3::mutation
