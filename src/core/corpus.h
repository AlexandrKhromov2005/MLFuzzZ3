#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <tl/expected.hpp>
#include <vector>

#include "fuzz_input.h"

// Phase 2 MVP fuzzing loop (ADR 0029). Corpus is the in-memory working
// set of inputs with disk write-through (Развилка 2, вариант 1).
// Accepted inputs are written under <base>/corpus/, crashes under
// <base>/crashes/, hangs (timeouts) under <base>/hangs/. No culling,
// minimization, power schedules, or resume — those are named follow-ups
// in ADR 0029. Acceptance policy lives in the campaign loop (an input is
// accepted iff new_edges > 0); Corpus only stores and persists.

namespace mlfuzzz3::core {

enum class CorpusError {
    // create_directories failed for corpus/, crashes/, or hangs/.
    kDirectoryCreateFailed,
    // A regular file under the seed directory could not be read.
    kSeedReadFailed,
    // Write-through of an accepted input or a finding failed.
    kWriteFailed,
};

// Deterministic-stage phase of a seed (ADR 0031). A seed starts in the
// Deterministic phase and transitions to Havoc once its positional sweep
// is exhausted (or capped); the transition is one-way.
enum class SeedPhase : std::uint8_t {
    kDeterministic,  // the seed still has unfinished deterministic steps
    kHavoc,          // the deterministic sweep is done; havoc fuzzes the seed
};

// Per-seed deterministic-stage progress (ADR 0031). In-memory only: it is
// not written to the corpus/ files, so a restarted campaign re-runs the
// deterministic stage (consistent with "no resume", ADR 0029). The
// campaign loop owns the transition logic; Corpus only stores the value.
struct DetState {
    SeedPhase phase = SeedPhase::kDeterministic;
    std::uint64_t cursor = 0;  // next deterministic step for this seed
};

// One corpus entry: the owned bytes plus minimal metadata (ADR 0029) and
// the deterministic-stage progress (ADR 0031). Lineage, parent tracking,
// and richer scoring are deliberately out of scope for the MVP and will
// be added additively.
struct CorpusEntry {
    std::uint64_t id = 0;         // assignment order, stable within a run
    mutation::FuzzInput input;    // owned bytes
    std::uint32_t new_edges = 0;  // coverage contribution recorded at acceptance
    DetState det{};               // deterministic-stage phase + cursor (ADR 0031)
};

// Not thread-safe; the MVP loop is single-threaded (ADR 0029 Развилка 3).
class Corpus {
   public:
    // Create roots the corpus at base_dir and creates the corpus/,
    // crashes/, and hangs/ subdirectories. Returns
    // kDirectoryCreateFailed if any cannot be created.
    [[nodiscard]] static tl::expected<Corpus, CorpusError> Create(
        const std::filesystem::path& base_dir);

    Corpus(const Corpus&) = delete;
    Corpus& operator=(const Corpus&) = delete;
    Corpus(Corpus&&) = default;
    Corpus& operator=(Corpus&&) = default;
    ~Corpus() = default;

    // Bootstrap seeds the working set. If seed_dir is non-empty and a
    // readable directory, every regular file under it is loaded as an
    // input. If the working set is still empty afterward (no seed dir,
    // or it held no usable files), one trivial single-byte input is
    // added so the loop has something to mutate (ADR 0029). Returns the
    // entry count after bootstrap (>= 1), or an error.
    [[nodiscard]] tl::expected<std::size_t, CorpusError> Bootstrap(
        const std::filesystem::path& seed_dir);

    // Add appends input as a new entry and write-throughs it to corpus/.
    // The caller owns the interest decision (the loop adds iff
    // new_edges > 0, ADR 0029). On write failure the working set is left
    // unchanged. Returns the new entry id.
    [[nodiscard]] tl::expected<std::uint64_t, CorpusError> Add(mutation::FuzzInput input,
                                                               std::uint32_t new_edges);

    // SetDetState overwrites the deterministic-stage progress of entry
    // `index`. It is the only mutating accessor on Corpus and touches
    // ONLY the DetState field (ADR 0031); the id, bytes, and coverage of
    // an entry are immutable once added. Precondition: index < size().
    void SetDetState(std::size_t index, DetState state);

    // SaveCrash / SaveHang write input to crashes/ resp. hangs/ without
    // adding it to the working set. File names are content-addressed
    // (FNV-1a hash), so identical findings collapse to one file and
    // names are deterministic (ADR 0029 replay).
    [[nodiscard]] tl::expected<void, CorpusError> SaveCrash(const mutation::FuzzInput& input);
    [[nodiscard]] tl::expected<void, CorpusError> SaveHang(const mutation::FuzzInput& input);

    [[nodiscard]] std::size_t size() const noexcept {
        return entries_.size();
    }
    [[nodiscard]] bool empty() const noexcept {
        return entries_.empty();
    }
    [[nodiscard]] const CorpusEntry& at(std::size_t index) const {
        return entries_.at(index);
    }

    [[nodiscard]] const std::filesystem::path& corpus_dir() const noexcept {
        return corpus_dir_;
    }
    [[nodiscard]] const std::filesystem::path& crashes_dir() const noexcept {
        return crashes_dir_;
    }
    [[nodiscard]] const std::filesystem::path& hangs_dir() const noexcept {
        return hangs_dir_;
    }

   private:
    Corpus(std::filesystem::path corpus_dir, std::filesystem::path crashes_dir,
           std::filesystem::path hangs_dir)
        : corpus_dir_(std::move(corpus_dir)),
          crashes_dir_(std::move(crashes_dir)),
          hangs_dir_(std::move(hangs_dir)) {}

    std::filesystem::path corpus_dir_;
    std::filesystem::path crashes_dir_;
    std::filesystem::path hangs_dir_;
    std::vector<CorpusEntry> entries_;
    std::uint64_t next_id_ = 0;
};

}  // namespace mlfuzzz3::core
