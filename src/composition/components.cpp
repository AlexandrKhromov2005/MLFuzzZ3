// SPDX-License-Identifier: MIT
#include "components.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include "mutators/bit_flip.h"
#include "mutators/byte_flip.h"
#include "mutators/havoc.h"

namespace mlfuzzz3::composition {

Registry::Registry() {
    RegisterMutator("havoc", [](const ComponentConfig& config) {
        auto all = mutation::legacy_havoc_operators();
        std::vector<mutation::MutationOperator> selected;
        if (config.havoc_operators) {
            for (const auto& name : *config.havoc_operators) {
                const auto found = std::ranges::find(all, name, &mutation::MutationOperator::name);
                if (found == all.end()) {
                    throw std::invalid_argument("unknown havoc operator: " + name);
                }
                selected.push_back(*found);
            }
        } else {
            selected = std::move(all);
        }
        return std::make_unique<mutation::HavocMutator>(
            std::move(selected), std::make_unique<mutation::UniformOperatorSelector>(),
            std::make_unique<mutation::LegacyStacking>());
    });
    RegisterMutator("bitflip", [] { return std::make_unique<mutation::BitFlipMutator>(); });
    RegisterMutator("byteflip", [] { return std::make_unique<mutation::ByteFlipMutator>(); });
    RegisterScheduler(
        "random", [](std::uint64_t seed) { return std::make_unique<core::RandomScheduler>(seed); });
    RegisterScheduler("round-robin",
                      [](std::uint64_t) { return std::make_unique<core::RoundRobinScheduler>(); });
}

void Registry::RegisterMutator(std::string name, MutatorFactory factory) {
    if (name.empty() || !factory ||
        !mutators_.emplace(std::move(name), std::move(factory)).second) {
        throw std::invalid_argument("invalid or duplicate mutator registration");
    }
}

void Registry::RegisterMutator(std::string name, SimpleMutatorFactory factory) {
    if (!factory) {
        throw std::invalid_argument("empty mutator factory");
    }
    RegisterMutator(std::move(name), [factory = std::move(factory)](
                                         const ComponentConfig& /*config*/) { return factory(); });
}

void Registry::RegisterScheduler(std::string name, SchedulerFactory factory) {
    if (name.empty() || !factory ||
        !schedulers_.emplace(std::move(name), std::move(factory)).second) {
        throw std::invalid_argument("invalid or duplicate seed scheduler registration");
    }
}

Components Registry::Build(const ComponentConfig& config) const {
    const auto mutator = mutators_.find(config.mutator);
    if (mutator == mutators_.end()) {
        throw std::runtime_error("unknown --mutator: " + config.mutator);
    }
    const auto scheduler = schedulers_.find(config.seed_scheduler);
    if (scheduler == schedulers_.end()) {
        throw std::runtime_error("unknown --seed-scheduler: " + config.seed_scheduler);
    }
    if (config.havoc_operators && config.mutator != "havoc") {
        throw std::invalid_argument("operator menu requires havoc mutator");
    }
    Components components{.mutator = mutator->second(config),
                          .seed_scheduler = scheduler->second(config.seed)};
    if (!components.mutator || !components.seed_scheduler) {
        throw std::runtime_error("component factory returned no component");
    }
    return components;
}

}  // namespace mlfuzzz3::composition
