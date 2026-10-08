#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <tl/expected.hpp>
#include <vector>

// Phase 3 branch-value channel (ADR 0033). BranchReader maps the
// branch-value memfd received from the execution server (via
// SCM_RIGHTS on the ChannelAnnouncement) and exposes the appended
// comparison records plus the run-level summary (count + overflow).
//
// Like CoverageReader it is a pure SHM-layout consumer: it reads and
// counts, it does not reset or interpret. The concolic interpretation
// of these records lands in a later ADR (0034+).
//
// The segment layout mirrors the runtime ABI in
// src/runtime/coverage/mlfuzzz3_branch.h and the Go mirror in
// exec-server/internal/coverage/branch.go. As with the edge channel's
// 64 KiB constant, the layout is mirrored per-language (not shared as
// one header) and pinned by static_assert below.

namespace mlfuzzz3::coverage {

// kBranchSegmentSize is the branch segment byte size — must match
// exec-server's coverage.BranchSegmentSize (ADR 0033). The runtime
// derives record capacity from this physical size.
inline constexpr std::size_t kBranchSegmentSize = 1U << 20;

// On-wire layout constants (little-endian). Mirror the runtime header.
inline constexpr std::size_t kBranchHeaderSize = 16;
inline constexpr std::size_t kBranchRecordSize = 24;

// Header field byte offsets.
inline constexpr std::size_t kBranchOffCount = 0;
inline constexpr std::size_t kBranchOffCapacity = 4;
inline constexpr std::size_t kBranchOffOverflow = 8;

// Record field byte offsets.
inline constexpr std::size_t kRecOffSiteId = 0;
inline constexpr std::size_t kRecOffPredicate = 4;
inline constexpr std::size_t kRecOffBitWidth = 5;
inline constexpr std::size_t kRecOffLhs = 8;
inline constexpr std::size_t kRecOffRhs = 16;

enum class BranchReaderError {
    // Requested size disagrees with kBranchSegmentSize (layout drift).
    kSizeMismatch,
    // mmap(PROT_READ, MAP_SHARED) on the borrowed fd failed.
    kMmapFailed,
};

// SiteOccurrences numbers the repeats of each comparison site within one
// run. occurrence[i] is the count of records before index i that carry
// the same site_id as record i (0 for the first hit of a site), so the
// pair (site_id, occurrence) names a record independently of its
// position in the append-only log.
//
// reliable is false when the runtime set overflow_flag: records past the
// segment capacity were dropped, so the log no longer matches the
// execution and the numbers must not be used to pair records across
// runs. The numbers are still returned (they index the surviving
// prefix), but the caller is required to check reliable first.
struct SiteOccurrences {
    std::vector<std::uint32_t> occurrence;
    bool reliable = true;
};

// BranchReader holds a read-only mmap of the branch-value memfd. The
// fd is borrowed from ClientSession; the reader never closes it.
// Munmap runs in the destructor (RAII). Move-only. Not thread-safe.
class BranchReader {
   public:
    // One decoded comparison record. Predicate values follow
    // enum fuzzer_rt_cmp_kind in the runtime ABI.
    struct Record {
        std::uint32_t site_id;
        std::uint8_t predicate;
        std::uint8_t bit_width;
        std::uint64_t lhs;
        std::uint64_t rhs;
    };

    // Create maps `size` bytes of `borrowed_fd` read-only. `size` must
    // equal kBranchSegmentSize. `borrowed_fd` is not closed and must
    // outlive the reader (held by ClientSession).
    [[nodiscard]] static tl::expected<BranchReader, BranchReaderError> Create(int borrowed_fd,
                                                                              std::size_t size);

    BranchReader(const BranchReader&) = delete;
    BranchReader& operator=(const BranchReader&) = delete;
    BranchReader(BranchReader&& other) noexcept;
    BranchReader& operator=(BranchReader&& other) noexcept;
    ~BranchReader();

    // RecordCount returns the number of records the runtime appended
    // (the segment header count). Read freshly from the mapping.
    [[nodiscard]] std::uint32_t RecordCount() const noexcept;

    // Overflow returns true if the runtime dropped records because the
    // segment filled up (header overflow flag). The log is then
    // truncated.
    [[nodiscard]] bool Overflow() const noexcept;

    // Records decodes the appended records. The count is clamped to the
    // segment capacity and the physical mapping so a corrupt header can
    // never read out of bounds.
    [[nodiscard]] std::vector<Record> Records() const;

    // Occurrences numbers the repeats of each site over Records() in one
    // pass and checks the header overflow flag explicitly: on overflow
    // the result is marked unreliable (see SiteOccurrences).
    [[nodiscard]] SiteOccurrences Occurrences() const;

    [[nodiscard]] std::size_t size() const noexcept {
        return size_;
    }

   private:
    BranchReader(void* map, std::size_t size) noexcept : map_(map), size_(size) {}

    void Munmap() noexcept;

    void* map_ = nullptr;
    std::size_t size_ = 0;
};

// NumberSiteOccurrences is the pure single-pass numbering behind
// BranchReader::Occurrences(). `overflow` is the segment header's
// overflow flag; when set, the result is marked unreliable.
[[nodiscard]] SiteOccurrences NumberSiteOccurrences(std::span<const BranchReader::Record> records,
                                                    bool overflow);

}  // namespace mlfuzzz3::coverage
