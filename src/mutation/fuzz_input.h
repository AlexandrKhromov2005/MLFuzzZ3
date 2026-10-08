#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

// Phase 2 mutation foundation (ADR 0027). FuzzInput is the owning byte
// buffer that travels through the mutation pipeline. It is intentionally
// minimal: a vector<uint8_t> with size/data accessors and the canonical
// Rule of Five. Corpus metadata, parent/lineage tracking, and on-disk
// serialization are deliberately out of scope for this slice — they
// will be added additively (new fields, not signature changes) once
// corpus management is designed.

namespace mlfuzzz3::mutation {

class FuzzInput {
   public:
    FuzzInput() noexcept = default;

    // Take ownership of an existing byte vector. Use this when the
    // caller already has a vector and wants to avoid an extra copy.
    explicit FuzzInput(std::vector<std::uint8_t> bytes) noexcept : bytes_(std::move(bytes)) {}

    // Copy `size` bytes from `data`. `data` may be nullptr iff size == 0
    // (std::span(nullptr, 0) is valid and yields begin() == end(), so no
    // pointer is dereferenced). May throw std::bad_alloc on allocation
    // failure.
    FuzzInput(const std::uint8_t* data, std::size_t size) {
        const std::span<const std::uint8_t> view(data, size);
        bytes_.assign(view.begin(), view.end());
    }

    FuzzInput(const FuzzInput&) = default;
    FuzzInput& operator=(const FuzzInput&) = default;
    FuzzInput(FuzzInput&&) noexcept = default;
    FuzzInput& operator=(FuzzInput&&) noexcept = default;
    ~FuzzInput() = default;

    [[nodiscard]] std::size_t size() const noexcept {
        return bytes_.size();
    }
    [[nodiscard]] const std::uint8_t* data() const noexcept {
        return bytes_.data();
    }
    [[nodiscard]] std::uint8_t* data() noexcept {
        return bytes_.data();
    }

   private:
    std::vector<std::uint8_t> bytes_;
};

}  // namespace mlfuzzz3::mutation
