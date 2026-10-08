#include <gtest/gtest.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "branch_reader.h"

// Hostile-header regression for the branch-value reader (Phase 3 Шаг 0,
// ahead of ADR 0034). The branch segment's header (count/capacity/
// overflow) is written by the *target* process into shared memory, so
// BranchReader must treat every field as untrusted: a corrupt header may
// never cause an out-of-bounds read. These tests build a segment by hand
// via a memfd the test fully controls (no exec-server), lay down valid
// and adversarial headers, hand the same fd to BranchReader::Create, and
// assert reads stay safe and clamp correctly. Run under ASAN+UBSAN, the
// hostile cases are the actual guard; the clamp lives at
// branch_reader.cpp:100-103.

namespace mlfuzzz3::coverage {
namespace {

// Record capacity the physical segment can hold, derived from the public
// layout constants (kept off any magic number).
constexpr std::size_t kPhysicalCapacity =
    (kBranchSegmentSize - kBranchHeaderSize) / kBranchRecordSize;

// MemfdCreate wraps memfd_create via raw syscall, matching
// tests/unit/coverage/test_coverage_reader.cpp (project conventions: no new
// dependency to paper over a glibc version difference).
int MemfdCreate(const char* name) {
#ifdef __NR_memfd_create
    return static_cast<int>(::syscall(__NR_memfd_create, name, 0));
#else
    return static_cast<int>(::syscall(319, name, 0));
#endif
}

// MakeBranchSegment returns a memfd-backed, kBranchSegmentSize-byte,
// zero-filled fd, or -1 on failure. The caller closes it after the reader
// is destroyed (borrow semantics, like BranchReader's production fd).
int MakeBranchSegment() {
    int fd = MemfdCreate("branch-reader-test");
    EXPECT_GE(fd, 0) << "memfd_create errno=" << errno;
    if (fd < 0) {
        return -1;
    }
    EXPECT_EQ(::ftruncate(fd, static_cast<off_t>(kBranchSegmentSize)), 0)
        << "ftruncate errno=" << errno;
    return fd;
}

// ScopedWritableMap is a temporary writable view of the segment used to
// lay down crafted bytes before the same fd is handed to
// BranchReader::Create, which re-maps it read-only. Writes go through the
// shared memfd, so they persist after this mapping is torn down. The
// segment ABI is little-endian (mlfuzzz3_branch.h), matching the host, so
// raw memcpy of host integers yields the on-wire layout.
class ScopedWritableMap {
   public:
    explicit ScopedWritableMap(int fd)
        : map_(::mmap(nullptr, kBranchSegmentSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) {}
    ScopedWritableMap(const ScopedWritableMap&) = delete;
    ScopedWritableMap& operator=(const ScopedWritableMap&) = delete;
    ScopedWritableMap(ScopedWritableMap&&) = delete;
    ScopedWritableMap& operator=(ScopedWritableMap&&) = delete;
    ~ScopedWritableMap() {
        if (map_ != MAP_FAILED) {
            ::munmap(map_, kBranchSegmentSize);
        }
    }

    [[nodiscard]] bool ok() const {
        return map_ != MAP_FAILED;
    }

    void PutU8(std::size_t off, std::uint8_t value) {
        Put(off, &value, sizeof(value));
    }
    void PutU16(std::size_t off, std::uint16_t value) {
        Put(off, &value, sizeof(value));
    }
    void PutU32(std::size_t off, std::uint32_t value) {
        Put(off, &value, sizeof(value));
    }
    void PutU64(std::size_t off, std::uint64_t value) {
        Put(off, &value, sizeof(value));
    }

   private:
    void Put(std::size_t off, const void* src, std::size_t n) {
        std::memcpy(static_cast<std::uint8_t*>(map_) + off, src, n);
    }

    void* map_;
};

// Plain record image the test writes and reads back.
struct Rec {
    std::uint32_t site_id;
    std::uint8_t predicate;
    std::uint8_t bit_width;
    std::uint64_t lhs;
    std::uint64_t rhs;
};

void WriteHeader(ScopedWritableMap& seg, std::uint32_t count, std::uint32_t capacity,
                 std::uint32_t overflow) {
    seg.PutU32(kBranchOffCount, count);
    seg.PutU32(kBranchOffCapacity, capacity);
    seg.PutU32(kBranchOffOverflow, overflow);
}

void WriteRecord(ScopedWritableMap& seg, std::uint32_t index, const Rec& rec) {
    const std::size_t base =
        kBranchHeaderSize + (static_cast<std::size_t>(index) * kBranchRecordSize);
    seg.PutU32(base + kRecOffSiteId, rec.site_id);
    seg.PutU8(base + kRecOffPredicate, rec.predicate);
    seg.PutU8(base + kRecOffBitWidth, rec.bit_width);
    seg.PutU64(base + kRecOffLhs, rec.lhs);
    seg.PutU64(base + kRecOffRhs, rec.rhs);
}

// ----- correct headers (behaviour contract) -------------------------------

TEST(BranchReader, EmptyLogReadsNothing) {
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, /*count=*/0, /*capacity=*/static_cast<std::uint32_t>(kPhysicalCapacity),
                    /*overflow=*/0);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value()) << "Create failed: " << static_cast<int>(reader.error());
    EXPECT_EQ(reader->size(), kBranchSegmentSize);
    EXPECT_EQ(reader->RecordCount(), 0U);
    EXPECT_FALSE(reader->Overflow());
    EXPECT_TRUE(reader->Records().empty());

    ::close(fd);
}

TEST(BranchReader, ValidRecordsDecodeByteForByte) {
    const std::vector<Rec> expected = {
        Rec{.site_id = 0, .predicate = 4, .bit_width = 32, .lhs = 0x1122334455667788ULL, .rhs = 7},
        Rec{.site_id = 1, .predicate = 2, .bit_width = 64, .lhs = 0, .rhs = 0xDEADBEEFCAFEBABEULL},
        Rec{.site_id = 42, .predicate = 8, .bit_width = 8, .lhs = 0xFFFFFFFFFFFFFFFFULL, .rhs = 1},
    };

    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, static_cast<std::uint32_t>(expected.size()),
                    static_cast<std::uint32_t>(kPhysicalCapacity), /*overflow=*/0);
        for (std::uint32_t i = 0; i < expected.size(); ++i) {
            WriteRecord(seg, i, expected[i]);
        }
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    EXPECT_EQ(reader->RecordCount(), expected.size());

    const std::vector<BranchReader::Record> got = reader->Records();
    ASSERT_EQ(got.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(got[i].site_id, expected[i].site_id) << "record " << i;
        EXPECT_EQ(got[i].predicate, expected[i].predicate) << "record " << i;
        EXPECT_EQ(got[i].bit_width, expected[i].bit_width) << "record " << i;
        EXPECT_EQ(got[i].lhs, expected[i].lhs) << "record " << i;
        EXPECT_EQ(got[i].rhs, expected[i].rhs) << "record " << i;
    }

    ::close(fd);
}

TEST(BranchReader, OverflowFlagIsReportedAndLogStillReadable) {
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, /*count=*/2, static_cast<std::uint32_t>(kPhysicalCapacity),
                    /*overflow=*/1);
        WriteRecord(seg, 0, Rec{.site_id = 5, .predicate = 0, .bit_width = 16, .lhs = 9, .rhs = 9});
        WriteRecord(seg, 1, Rec{.site_id = 6, .predicate = 1, .bit_width = 16, .lhs = 1, .rhs = 2});
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    EXPECT_TRUE(reader->Overflow());
    EXPECT_EQ(reader->Records().size(), 2U);

    ::close(fd);
}

// ----- hostile headers (ASAN/UBSAN regression: clamp, never OOB) -----------

TEST(BranchReader, CountAndCapacityMaxClampToPhysical) {
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, /*count=*/0xFFFFFFFFU, /*capacity=*/0xFFFFFFFFU, /*overflow=*/0);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    // Records() must clamp to what the mapping physically holds — reading
    // every clamped record stays inside the mmap (ASAN/UBSAN-clean).
    EXPECT_EQ(reader->Records().size(), kPhysicalCapacity);

    ::close(fd);
}

TEST(BranchReader, CountExceedsCapacityClampsToCapacity) {
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, /*count=*/1000, /*capacity=*/5, /*overflow=*/0);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    EXPECT_EQ(reader->Records().size(), 5U);

    ::close(fd);
}

TEST(BranchReader, CapacityExceedsPhysicalButSmallCountReadsCount) {
    constexpr std::uint32_t kCount = 10;
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, kCount, /*capacity=*/0xFFFFFFFFU, /*overflow=*/0);
        for (std::uint32_t i = 0; i < kCount; ++i) {
            WriteRecord(seg, i,
                        Rec{.site_id = i, .predicate = 0, .bit_width = 32, .lhs = i, .rhs = i});
        }
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    const std::vector<BranchReader::Record> got = reader->Records();
    ASSERT_EQ(got.size(), kCount);
    for (std::uint32_t i = 0; i < kCount; ++i) {
        EXPECT_EQ(got[i].site_id, i);
        EXPECT_EQ(got[i].lhs, i);
    }

    ::close(fd);
}

TEST(BranchReader, ZeroCapacityClampsToEmpty) {
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, /*count=*/7, /*capacity=*/0, /*overflow=*/0);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    EXPECT_TRUE(reader->Records().empty());

    ::close(fd);
}

TEST(BranchReader, GarbageReservedFieldsAreIgnored) {
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, /*count=*/2, static_cast<std::uint32_t>(kPhysicalCapacity),
                    /*overflow=*/0);
        // Header reserved word (offset 12) and each record's reserved
        // halfword (offset 6) set to garbage; the reader must ignore them.
        constexpr std::size_t kHeaderReservedOff = 12;
        seg.PutU32(kHeaderReservedOff, 0xDEADBEEFU);
        const Rec a{.site_id = 11, .predicate = 6, .bit_width = 32, .lhs = 0xAAAA, .rhs = 0xBBBB};
        const Rec b{.site_id = 22, .predicate = 9, .bit_width = 64, .lhs = 0xCCCC, .rhs = 0xDDDD};
        WriteRecord(seg, 0, a);
        WriteRecord(seg, 1, b);
        constexpr std::size_t kRecReservedOff = 6;
        seg.PutU16(kBranchHeaderSize + kRecReservedOff, 0xBEEF);
        seg.PutU16(kBranchHeaderSize + kBranchRecordSize + kRecReservedOff, 0xBEEF);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    const std::vector<BranchReader::Record> got = reader->Records();
    ASSERT_EQ(got.size(), 2U);
    EXPECT_EQ(got[0].site_id, 11U);
    EXPECT_EQ(got[0].predicate, 6U);
    EXPECT_EQ(got[0].rhs, 0xBBBBU);
    EXPECT_EQ(got[1].site_id, 22U);
    EXPECT_EQ(got[1].bit_width, 64U);
    EXPECT_EQ(got[1].lhs, 0xCCCCU);

    ::close(fd);
}

// ----- site occurrence numbering (read-side, runtime ABI unchanged) ------

// WriteSites lays down one record per site id with otherwise fixed fields.
void WriteSites(ScopedWritableMap& seg, const std::vector<std::uint32_t>& sites) {
    for (std::uint32_t i = 0; i < sites.size(); ++i) {
        WriteRecord(seg, i,
                    Rec{.site_id = sites[i], .predicate = 0, .bit_width = 32, .lhs = i, .rhs = 0});
    }
}

TEST(BranchReaderOccurrences, NoOverflowNumbersRepeatsAndIsReliable) {
    const std::vector<std::uint32_t> sites = {7, 3, 7, 7, 3, 9};
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, static_cast<std::uint32_t>(sites.size()),
                    static_cast<std::uint32_t>(kPhysicalCapacity), /*overflow=*/0);
        WriteSites(seg, sites);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    const SiteOccurrences occ = reader->Occurrences();
    EXPECT_TRUE(occ.reliable);
    EXPECT_EQ(occ.occurrence, (std::vector<std::uint32_t>{0, 0, 1, 2, 1, 0}));

    ::close(fd);
}

TEST(BranchReaderOccurrences, OverflowFlagMarksNumbersUnreliable) {
    const std::vector<std::uint32_t> sites = {5, 5, 6};
    int fd = MakeBranchSegment();
    ASSERT_GE(fd, 0);
    {
        ScopedWritableMap seg(fd);
        ASSERT_TRUE(seg.ok());
        WriteHeader(seg, static_cast<std::uint32_t>(sites.size()),
                    static_cast<std::uint32_t>(kPhysicalCapacity), /*overflow=*/1);
        WriteSites(seg, sites);
    }

    auto reader = BranchReader::Create(fd, kBranchSegmentSize);
    ASSERT_TRUE(reader.has_value());
    const SiteOccurrences occ = reader->Occurrences();
    EXPECT_FALSE(occ.reliable);
    // The surviving prefix is still numbered; only its validity changes.
    EXPECT_EQ(occ.occurrence, (std::vector<std::uint32_t>{0, 1, 0}));

    ::close(fd);
}

TEST(BranchReaderOccurrences, RepeatedSitesNumberedInOnePass) {
    // Interleaved repeats: each site counts only its own earlier hits,
    // including the extreme site ids 0 and UINT32_MAX.
    const std::vector<std::uint32_t> sites = {0, 0xFFFFFFFFU, 0, 1, 0xFFFFFFFFU, 0, 1, 1, 1};
    std::vector<BranchReader::Record> records;
    records.reserve(sites.size());
    for (const std::uint32_t site : sites) {
        records.push_back(BranchReader::Record{
            .site_id = site, .predicate = 0, .bit_width = 8, .lhs = 0, .rhs = 0});
    }

    const SiteOccurrences occ = NumberSiteOccurrences(records, /*overflow=*/false);
    EXPECT_TRUE(occ.reliable);
    EXPECT_EQ(occ.occurrence, (std::vector<std::uint32_t>{0, 0, 1, 0, 1, 2, 1, 2, 3}));

    EXPECT_TRUE(NumberSiteOccurrences({}, /*overflow=*/false).occurrence.empty());
    EXPECT_FALSE(NumberSiteOccurrences(records, /*overflow=*/true).reliable);
}

}  // namespace
}  // namespace mlfuzzz3::coverage
