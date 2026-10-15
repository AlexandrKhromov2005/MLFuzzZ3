// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>

#include "corpus.h"
#include "deterministic_stage.h"
namespace mlfuzzz3::core {
struct SeedMetadata {
    std::uint64_t id = 0;
    std::size_t byte_size = 0;
    std::uint32_t new_edges = 0;
    DetState det;
    std::uint64_t deterministic_length = 0;
};
// Scheduling gets metadata only, never mutable corpus or finding storage.
class CorpusView {
   public:
    explicit CorpusView(const Corpus& corpus) : corpus_(&corpus) {}
    [[nodiscard]] std::size_t size() const {
        return corpus_->size();
    }
    [[nodiscard]] SeedMetadata at(std::size_t index) const {
        const auto& seed = corpus_->at(index);
        return {.id = seed.id,
                .byte_size = seed.input.size(),
                .new_edges = seed.new_edges,
                .det = seed.det,
                .deterministic_length = mutation::DeterministicStage::length(seed.input)};
    }

   private:
    const Corpus* corpus_;
};
struct SeedFeedback {
    std::uint64_t execs = 0;
    std::uint64_t new_edges = 0;
    std::uint64_t findings = 0;
};
}  // namespace mlfuzzz3::core
