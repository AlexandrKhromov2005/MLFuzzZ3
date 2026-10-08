#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <tl/expected.hpp>
#include <vector>

// Phase 2 coverage bridge (ADR 0028 part B). CoverageReader maps
// the edge-coverage memfd received from the execution server
// (via SCM_RIGHTS on the ChannelAnnouncement) and exposes a
// snapshot read of the bitmap. The reader is a pure SHM-layout
// consumer: it does not reset, interpret, or bucketize bytes —
// that policy lives in the execution server (resets) and in the
// future corpus / loop layers (interpretation).

namespace mlfuzzz3::coverage {

// kMapSize is the canonical edge-coverage bitmap size in bytes
// (64 KiB). Symmetric to exec-server's coverage.MapSize and to
// COV_MAP_SIZE in src/runtime/coverage/mlfuzzz3_cov.c — all
// three values must agree per ADR 0017. CoverageReader::Create
// rejects any size that disagrees with this constant.
inline constexpr std::size_t kMapSize = 1U << 16;

// CountScheme selects how a raw hit count is presented to a
// caller that asks for the configured scheme. kRaw is the
// project default and the only scheme Read() has ever used;
// kLog2Buckets mirrors the ADR 0021 ladder that the execution
// server applies server-side (exec-server
// internal/coverage/bucketizer.go). The mirror exists so the
// client read path can be measured under both schemes without
// touching the server; it is experimental and changes no
// default. Read() is deliberately left alone: the switch lives
// in ReadWithConfiguredScheme() below, so a caller that does
// not opt in cannot observe any difference at all.
enum class CountScheme {
    kRaw,
    kLog2Buckets,
};

// kCountSchemeEnvVar names the experimental switch. Only the
// exact value "log2" selects bucketization; unset, empty, and
// every other value keep kRaw. Selecting the scheme through the
// environment rather than through CLI or CMake keeps the switch
// out of the shipped interface: nothing in src/ reads it on the
// campaign path, and no build configuration changes with it.
inline constexpr const char* kCountSchemeEnvVar = "MLFUZZZ3_COVERAGE_COUNT_SCHEME";

// The ADR 0021 bucket bits and the upper bound of every bucket
// that has one. Named rather than spelled inline so the ladder
// below reads as the decision record does and so clang-tidy's
// readability-magic-numbers has nothing to object to. Bit i
// stands for the i-th category of ADR 0021 §Решение, counting
// from the "exactly one hit" category.
inline constexpr std::uint8_t kBucketNoHits = 0x00;
inline constexpr std::uint8_t kBucketOneHit = 0x01;
inline constexpr std::uint8_t kBucketTwoHits = 0x02;
inline constexpr std::uint8_t kBucketThreeHits = 0x04;
inline constexpr std::uint8_t kBucketFourToSeven = 0x08;
inline constexpr std::uint8_t kBucketEightToFifteen = 0x10;
inline constexpr std::uint8_t kBucketSixteenToThirtyOne = 0x20;
inline constexpr std::uint8_t kBucketThirtyTwoToOneTwentySeven = 0x40;
inline constexpr std::uint8_t kBucketOneTwentyEightAndAbove = 0x80;

inline constexpr std::uint8_t kOneHit = 1;
inline constexpr std::uint8_t kTwoHits = 2;
inline constexpr std::uint8_t kThreeHits = 3;
inline constexpr std::uint8_t kSevenHits = 7;
inline constexpr std::uint8_t kFifteenHits = 15;
inline constexpr std::uint8_t kThirtyOneHits = 31;
inline constexpr std::uint8_t kOneTwentySevenHits = 127;

// Log2Bucket maps a raw hit count (0..255) to its ADR 0021
// bucket bit. The ladder is stated in
// docs/DECISIONS/0021-coverage-bucketization-stage1.md §Решение:
// 0 hits is the empty bitset, then 1, 2, 3, 4..7, 8..15, 16..31,
// 32..127, 128..255 map to bits 0..7. This is a C++ mirror of
// bucketLUT in exec-server/internal/coverage/bucketizer.go; the
// two must agree, and tests/unit/coverage/test_count_scheme.cpp
// checks all 256 values against the ladder written out by hand.
[[nodiscard]] constexpr std::uint8_t Log2Bucket(std::uint8_t count) noexcept {
    if (count == 0) {
        return kBucketNoHits;
    }
    if (count == kOneHit) {
        return kBucketOneHit;
    }
    if (count == kTwoHits) {
        return kBucketTwoHits;
    }
    if (count == kThreeHits) {
        return kBucketThreeHits;
    }
    if (count <= kSevenHits) {
        return kBucketFourToSeven;
    }
    if (count <= kFifteenHits) {
        return kBucketEightToFifteen;
    }
    if (count <= kThirtyOneHits) {
        return kBucketSixteenToThirtyOne;
    }
    if (count <= kOneTwentySevenHits) {
        return kBucketThirtyTwoToOneTwentySeven;
    }
    return kBucketOneTwentyEightAndAbove;
}

// SchemeFromEnvironment reads kCountSchemeEnvVar and returns the
// selected scheme. Absent, empty, or unrecognized values return
// kRaw — the default must survive a typo, not fail open into a
// different measurement.
[[nodiscard]] inline CountScheme SchemeFromEnvironment() noexcept {
    const char* raw = std::getenv(kCountSchemeEnvVar);
    if (raw == nullptr) {
        return CountScheme::kRaw;
    }
    if (std::strcmp(raw, "log2") == 0) {
        return CountScheme::kLog2Buckets;
    }
    return CountScheme::kRaw;
}

// Bucketize returns a copy of `counters` with every byte mapped
// through Log2Bucket. Kept free-standing so the transform can be
// checked against expected values without a live mapping.
[[nodiscard]] inline std::vector<std::uint8_t> Bucketize(
    const std::vector<std::uint8_t>& counters) {
    std::vector<std::uint8_t> out(counters.size());
    for (std::size_t i = 0; i < counters.size(); ++i) {
        out[i] = Log2Bucket(counters[i]);
    }
    return out;
}

enum class CoverageReaderError {
    // Requested size does not match kMapSize. The descriptor
    // is authoritative (it travels in EdgeCoverageDescriptor),
    // but a mismatch with the project-wide invariant indicates
    // a layout drift that the reader must not silently accept.
    kSizeMismatch,

    // mmap(PROT_READ, MAP_SHARED) on the borrowed fd failed
    // (ENOMEM, EINVAL, EBADF, ...).
    kMmapFailed,
};

// CoverageReader holds a read-only mmap of the edge-coverage
// memfd. The fd is borrowed from ClientSession; the reader
// never closes it. Munmap runs in the destructor (RAII).
//
// Construction is via Create() so mmap failures surface as a
// recoverable tl::expected error rather than a constructor
// throw (ADR 0009 error-handling policy). Reader instances are
// move-only.
//
// Not thread-safe: callers must serialize Read() against any
// reuse; concurrent reads of a stable mapping are safe at the
// kernel level but the class does not enforce it.
class CoverageReader {
   public:
    // Create maps `size` bytes of `borrowed_fd` read-only and
    // returns a reader on success. `borrowed_fd` is not closed
    // and must outlive the returned reader (held by Session).
    [[nodiscard]] static tl::expected<CoverageReader, CoverageReaderError> Create(int borrowed_fd,
                                                                                  std::size_t size);

    CoverageReader(const CoverageReader&) = delete;
    CoverageReader& operator=(const CoverageReader&) = delete;
    CoverageReader(CoverageReader&& other) noexcept;
    CoverageReader& operator=(CoverageReader&& other) noexcept;
    ~CoverageReader();

    // Read returns a fresh copy of the current bitmap. The
    // copy semantics match the Go side (coverage.Channel.Read)
    // and shield callers from concurrent target writes between
    // successive Run invocations. No interpretation happens
    // here — bytes are passed through as raw counters.
    [[nodiscard]] std::vector<std::uint8_t> Read() const;

    // ReadWithConfiguredScheme returns Read()'s bytes under the
    // scheme selected by kCountSchemeEnvVar. With the variable
    // unset the return value is Read()'s vector unchanged — not
    // an equivalent copy, the same bytes, because no transform
    // runs at all. Opt-in only: Read() keeps its old contract for
    // every existing caller.
    [[nodiscard]] std::vector<std::uint8_t> ReadWithConfiguredScheme() const {
        std::vector<std::uint8_t> out = Read();
        if (SchemeFromEnvironment() == CountScheme::kLog2Buckets) {
            for (auto& byte : out) {
                byte = Log2Bucket(byte);
            }
        }
        return out;
    }

    // size returns the bitmap size in bytes (== kMapSize on
    // success). Useful for callers that want to assert the
    // expected layout without going through Read().
    [[nodiscard]] std::size_t size() const noexcept {
        return size_;
    }

   private:
    CoverageReader(void* map, std::size_t size) noexcept : map_(map), size_(size) {}

    void Munmap() noexcept;

    void* map_ = nullptr;
    std::size_t size_ = 0;
};

}  // namespace mlfuzzz3::coverage
