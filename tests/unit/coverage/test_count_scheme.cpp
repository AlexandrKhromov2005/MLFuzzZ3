#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "coverage_reader.h"

namespace mlfuzzz3::coverage {
namespace {

// MemfdCreate wraps memfd_create via raw syscall, same approach as
// tests/unit/coverage/test_coverage_reader.cpp (project conventions: no
// new dependency to paper over a glibc version difference).
int MemfdCreate(const char* name) {
#ifdef __NR_memfd_create
    return static_cast<int>(syscall(__NR_memfd_create, name, 0));
#else
    return static_cast<int>(syscall(319, name, 0));
#endif
}

// kCounters is the single counter set both schemes are checked on.
// It holds one value from the interior of every ADR 0021 bucket and
// both endpoints of every bucket that has two, so no bucket boundary
// is left unprobed.
const std::vector<std::uint8_t> kCounters = {0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 127, 128, 255};

// kExpectedRaw and kExpectedBucketed are written out by hand and
// independently of each other and of kCounters. Neither scheme is
// checked against the other: a transform that silently degenerated
// into the identity would still have to match kExpectedBucketed.
const std::vector<std::uint8_t> kExpectedRaw = {0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 127, 128, 255};
const std::vector<std::uint8_t> kExpectedBucketed = {0x00, 0x01, 0x02, 0x04, 0x08, 0x08, 0x10,
                                                     0x10, 0x20, 0x20, 0x40, 0x40, 0x80, 0x80};

// ScopedEnv sets kCountSchemeEnvVar for the body of one test and
// restores the previous state (including "was unset") afterwards.
// Without the restore, test order would decide the default, and the
// default is exactly what these tests are about.
class ScopedEnv {
   public:
    explicit ScopedEnv(const char* value) {
        const char* previous = std::getenv(kCountSchemeEnvVar);
        if (previous != nullptr) {
            had_previous_ = true;
            previous_ = previous;
        }
        if (value == nullptr) {
            ::unsetenv(kCountSchemeEnvVar);
        } else {
            ::setenv(kCountSchemeEnvVar, value, 1);
        }
    }

    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

    ~ScopedEnv() {
        if (had_previous_) {
            ::setenv(kCountSchemeEnvVar, previous_.c_str(), 1);
        } else {
            ::unsetenv(kCountSchemeEnvVar);
        }
    }

   private:
    bool had_previous_ = false;
    std::string previous_;
};

// MakeCoverageMemfd creates a 64 KiB memfd whose first
// kCounters.size() bytes are kCounters and whose remaining bytes are
// zero. The fd is borrowed by the reader; the caller closes it.
int MakeCoverageMemfd() {
    int fd = MemfdCreate("cov-count-scheme-test");
    EXPECT_GE(fd, 0) << "memfd_create errno=" << errno;
    if (fd < 0) {
        return -1;
    }
    EXPECT_EQ(::ftruncate(fd, static_cast<off_t>(kMapSize)), 0) << "ftruncate errno=" << errno;
    std::vector<std::uint8_t> buf(kMapSize, 0);
    for (std::size_t i = 0; i < kCounters.size(); ++i) {
        buf[i] = kCounters[i];
    }
    EXPECT_EQ(::pwrite(fd, buf.data(), buf.size(), 0), static_cast<ssize_t>(buf.size()))
        << "pwrite errno=" << errno;
    return fd;
}

// Prefix returns the first kCounters.size() bytes of a full-size
// read, which is the window the expected vectors describe.
std::vector<std::uint8_t> Prefix(const std::vector<std::uint8_t>& full) {
    return std::vector<std::uint8_t>(full.begin(),
                                     full.begin() + static_cast<std::ptrdiff_t>(kCounters.size()));
}

TEST(CoverageCountScheme, LadderMatchesAdr0021ForAllTwoHundredFiftySixValues) {
    // The ranges below are transcribed from ADR 0021 §Решение, not
    // computed from Log2Bucket, so the test fails if the ladder in
    // the header drifts from the decision record.
    for (int value = 0; value <= 255; ++value) {
        const auto count = static_cast<std::uint8_t>(value);
        std::uint8_t expected = 0x00;
        if (value == 0) {
            expected = 0x00;
        } else if (value == 1) {
            expected = 0x01;
        } else if (value == 2) {
            expected = 0x02;
        } else if (value == 3) {
            expected = 0x04;
        } else if (value >= 4 && value <= 7) {
            expected = 0x08;
        } else if (value >= 8 && value <= 15) {
            expected = 0x10;
        } else if (value >= 16 && value <= 31) {
            expected = 0x20;
        } else if (value >= 32 && value <= 127) {
            expected = 0x40;
        } else {
            expected = 0x80;
        }
        EXPECT_EQ(Log2Bucket(count), expected) << "hit count " << value;
    }
}

TEST(CoverageCountScheme, DefaultSchemeIsRawWhenVariableIsUnset) {
    ScopedEnv env(nullptr);
    EXPECT_EQ(SchemeFromEnvironment(), CountScheme::kRaw);
}

TEST(CoverageCountScheme, OnlyTheExactValueLogTwoSelectsBucketization) {
    {
        ScopedEnv env("log2");
        EXPECT_EQ(SchemeFromEnvironment(), CountScheme::kLog2Buckets);
    }
    // Empty, misspelled, and "truthy but not the scheme name" all
    // keep the default: a typo must not silently change what a
    // campaign measures.
    for (const char* value : {"", "1", "raw", "LOG2", "log2 ", "yes"}) {
        ScopedEnv env(value);
        EXPECT_EQ(SchemeFromEnvironment(), CountScheme::kRaw) << "value \"" << value << "\"";
    }
}

TEST(CoverageCountScheme, RawSchemeYieldsTheExpectedRawCounters) {
    ScopedEnv env(nullptr);
    int fd = MakeCoverageMemfd();
    ASSERT_GE(fd, 0);

    auto reader = CoverageReader::Create(fd, kMapSize);
    ASSERT_TRUE(reader.has_value()) << "Create failed: " << static_cast<int>(reader.error());

    EXPECT_EQ(Prefix(reader->ReadWithConfiguredScheme()), kExpectedRaw);

    ::close(fd);
}

TEST(CoverageCountScheme, BucketedSchemeYieldsTheExpectedBucketValues) {
    ScopedEnv env("log2");
    int fd = MakeCoverageMemfd();
    ASSERT_GE(fd, 0);

    auto reader = CoverageReader::Create(fd, kMapSize);
    ASSERT_TRUE(reader.has_value()) << "Create failed: " << static_cast<int>(reader.error());

    EXPECT_EQ(Prefix(reader->ReadWithConfiguredScheme()), kExpectedBucketed);

    ::close(fd);
}

TEST(CoverageCountScheme, ReadIsByteForByteUnchangedUnderBothSchemes) {
    // Read() is the pre-existing entry point and the one every
    // current caller uses. The switch must not reach it: the same
    // 64 KiB come back whether the variable is set or not, and they
    // equal the bytes that were written to the memfd.
    int fd = MakeCoverageMemfd();
    ASSERT_GE(fd, 0);

    auto reader = CoverageReader::Create(fd, kMapSize);
    ASSERT_TRUE(reader.has_value()) << "Create failed: " << static_cast<int>(reader.error());

    std::vector<std::uint8_t> expected_full(kMapSize, 0);
    for (std::size_t i = 0; i < kCounters.size(); ++i) {
        expected_full[i] = kCounters[i];
    }

    {
        ScopedEnv env(nullptr);
        EXPECT_EQ(reader->Read(), expected_full);
    }
    {
        ScopedEnv env("log2");
        EXPECT_EQ(reader->Read(), expected_full);
    }

    ::close(fd);
}

TEST(CoverageCountScheme, BucketizeMapsAStandaloneCounterSetToExpectedValues) {
    // Same counter set, no mapping involved: pins the free-standing
    // transform independently of mmap and of the environment.
    EXPECT_EQ(Bucketize(kCounters), kExpectedBucketed);
}

}  // namespace
}  // namespace mlfuzzz3::coverage
