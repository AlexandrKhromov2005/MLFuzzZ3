#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "coverage_reader.h"

namespace mlfuzzz3::coverage {
namespace {

// MemfdCreate wraps memfd_create via raw syscall to match the
// approach used in tests/unit/ipc/test_scm_rights.cpp. See
// project conventions: no new dependency just to paper over a
// glibc version difference.
int MemfdCreate(const char* name) {
#ifdef __NR_memfd_create
    return static_cast<int>(syscall(__NR_memfd_create, name, 0));
#else
    return static_cast<int>(syscall(319, name, 0));
#endif
}

// MakeCoverageMemfd creates a 64 KiB memfd-backed region
// containing `pattern`, repeated to fill the bitmap. The fd
// is returned to the caller; the caller is responsible for
// closing it after the reader is destroyed (borrow semantics).
int MakeCoverageMemfd(std::uint8_t pattern) {
    int fd = MemfdCreate("cov-reader-test");
    EXPECT_GE(fd, 0) << "memfd_create errno=" << errno;
    if (fd < 0) {
        return -1;
    }
    EXPECT_EQ(::ftruncate(fd, static_cast<off_t>(kMapSize)), 0) << "ftruncate errno=" << errno;
    std::vector<std::uint8_t> buf(kMapSize, pattern);
    EXPECT_EQ(::pwrite(fd, buf.data(), buf.size(), 0), static_cast<ssize_t>(buf.size()))
        << "pwrite errno=" << errno;
    return fd;
}

TEST(CoverageReader, ReadCopiesBitmap) {
    constexpr std::uint8_t kPattern = 0xAB;
    int fd = MakeCoverageMemfd(kPattern);
    ASSERT_GE(fd, 0);

    auto reader = CoverageReader::Create(fd, kMapSize);
    ASSERT_TRUE(reader.has_value()) << "Create failed: " << static_cast<int>(reader.error());
    EXPECT_EQ(reader->size(), kMapSize);

    auto snapshot = reader->Read();
    ASSERT_EQ(snapshot.size(), kMapSize);
    for (std::size_t i = 0; i < snapshot.size(); ++i) {
        ASSERT_EQ(snapshot[i], kPattern) << "mismatch at index " << i;
    }

    ::close(fd);
}

TEST(CoverageReader, ReflectsWritesThroughSharedMapping) {
    // PROT_READ MAP_SHARED reads reflect writes by other
    // owners of the same memfd — this is what makes the
    // server-resets-target-writes-client-reads pipeline work.
    int fd = MakeCoverageMemfd(0x00);
    ASSERT_GE(fd, 0);

    auto reader = CoverageReader::Create(fd, kMapSize);
    ASSERT_TRUE(reader.has_value());

    // Drop a recognizable signature at two arbitrary offsets.
    constexpr std::size_t kOffsetA = 7;
    constexpr std::size_t kOffsetB = 12345;
    constexpr std::uint8_t kValueA = 0x42;
    constexpr std::uint8_t kValueB = 0xEF;
    std::uint8_t a = kValueA;
    std::uint8_t b = kValueB;
    ASSERT_EQ(::pwrite(fd, &a, 1, static_cast<off_t>(kOffsetA)), 1);
    ASSERT_EQ(::pwrite(fd, &b, 1, static_cast<off_t>(kOffsetB)), 1);

    auto snapshot = reader->Read();
    EXPECT_EQ(snapshot[kOffsetA], kValueA);
    EXPECT_EQ(snapshot[kOffsetB], kValueB);

    ::close(fd);
}

TEST(CoverageReader, BorrowsFdAcrossDestructor) {
    // The reader maps the fd but must never close it — the
    // session owns the fd. After destruction the fd must
    // remain valid so the session can hand it to another
    // reader (or itself outlive a transient reader).
    int fd = MakeCoverageMemfd(0x11);
    ASSERT_GE(fd, 0);

    {
        auto reader = CoverageReader::Create(fd, kMapSize);
        ASSERT_TRUE(reader.has_value());
    }

    struct stat st{};
    EXPECT_EQ(::fstat(fd, &st), 0) << "fstat errno=" << errno;
    EXPECT_EQ(static_cast<std::size_t>(st.st_size), kMapSize);

    ::close(fd);
}

TEST(CoverageReader, RejectsSizeMismatch) {
    int fd = MakeCoverageMemfd(0x00);
    ASSERT_GE(fd, 0);

    auto reader = CoverageReader::Create(fd, kMapSize / 2);
    ASSERT_FALSE(reader.has_value());
    EXPECT_EQ(reader.error(), CoverageReaderError::kSizeMismatch);

    ::close(fd);
}

TEST(CoverageReader, MmapFailsOnInvalidFd) {
    // -1 is not a valid fd and mmap rejects it with EBADF.
    auto reader = CoverageReader::Create(-1, kMapSize);
    ASSERT_FALSE(reader.has_value());
    EXPECT_EQ(reader.error(), CoverageReaderError::kMmapFailed);
}

TEST(CoverageReader, MoveTransfersMapping) {
    int fd = MakeCoverageMemfd(0x7F);
    ASSERT_GE(fd, 0);

    auto first = CoverageReader::Create(fd, kMapSize);
    ASSERT_TRUE(first.has_value());

    CoverageReader moved = std::move(*first);
    EXPECT_EQ(moved.size(), kMapSize);
    EXPECT_EQ(first->size(), 0U);  // NOLINT(bugprone-use-after-move)

    auto snapshot = moved.Read();
    ASSERT_EQ(snapshot.size(), kMapSize);
    EXPECT_EQ(snapshot[0], 0x7F);

    ::close(fd);
}

}  // namespace
}  // namespace mlfuzzz3::coverage
