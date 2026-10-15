// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "mutator.h"
#include "seed_scheduler.h"

namespace mlfuzzz3::composition {

struct ComponentConfig {
    std::string mutator = "havoc";
    std::string seed_scheduler = "random";
    std::uint64_t seed = 0;
    std::optional<std::vector<std::string>> havoc_operators = std::nullopt;
};

struct Components {
    std::unique_ptr<mutation::Mutator> mutator;
    std::unique_ptr<core::SeedScheduler> seed_scheduler;
};

// Per-composition typed factories; registration never mutates global state.
class Registry {
   public:
    using MutatorFactory =
        std::function<std::unique_ptr<mutation::Mutator>(const ComponentConfig&)>;
    using SimpleMutatorFactory = std::function<std::unique_ptr<mutation::Mutator>()>;
    using SchedulerFactory = std::function<std::unique_ptr<core::SeedScheduler>(std::uint64_t)>;

    Registry();
    void RegisterMutator(std::string name, MutatorFactory factory);
    void RegisterMutator(std::string name, SimpleMutatorFactory factory);
    void RegisterScheduler(std::string name, SchedulerFactory factory);
    [[nodiscard]] Components Build(const ComponentConfig& config) const;

   private:
    std::map<std::string, MutatorFactory, std::less<>> mutators_;
    std::map<std::string, SchedulerFactory, std::less<>> schedulers_;
};

}  // namespace mlfuzzz3::composition
