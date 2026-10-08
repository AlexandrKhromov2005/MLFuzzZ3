// Unit test for the branch-value channel of libmlfuzzz3_cov.so
// (ADR 0033 Шаг 2): runtime hook fuzzer_rt_log_branch_cmp +
// SHM segment append/overflow semantics.
//
// The runtime initializes the branch segment from a
// constructor that reads MLFUZZZ3_BRANCH_FD exactly once at
// load time. To exercise that constructor fresh per scenario,
// each case forks and dlopens the library in the CHILD; the
// parent never loads it (a parent load would be inherited
// across fork and suppress the child constructor). The segment
// is a shared mmap-backed temp file the child writes and the
// parent inspects afterwards.

#include <dlfcn.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mlfuzzz3_branch.h"

namespace {

#ifndef MLFUZZZ3_COV_LIB_PATH
#error "MLFUZZZ3_COV_LIB_PATH must be defined at compile time"
#endif

// Child exit codes, distinct from a 0 success so the parent
// can pinpoint where the child failed.
constexpr int kChildDlopenFailed = 10;
constexpr int kChildDlsymFailed = 11;

using LogBranchFn = void (*)(uint32_t, uint64_t, uint64_t, uint8_t, uint8_t);

// One comparison to log, mirroring the runtime hook arguments.
struct Call {
    uint32_t site_id;
    uint64_t lhs;
    uint64_t rhs;
    uint8_t predicate;
    uint8_t bit_width;
};

// Creates an anonymous-but-fd-backed segment of seg_size bytes
// (mkstemp + immediate unlink: cleaned up on close, survives
// fork). Returns the fd, or -1 on failure.
int MakeSegment(size_t seg_size) {
    char path[] = "/tmp/mlfuzzz3_branch_test_XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    (void)unlink(path);
    if (ftruncate(fd, static_cast<off_t>(seg_size)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

// Runs the logging scenario in a forked child: sets (or clears)
// MLFUZZZ3_BRANCH_FD, dlopens the library so its constructor
// maps `fd`, then issues each call. Returns the child's exit
// code (0 = success). `set_env == false` exercises the inert
// no-op path.
int RunChild(int fd, bool set_env, const std::vector<Call> &calls) {
    const pid_t pid = fork();
    if (pid == 0) {
        if (set_env) {
            const std::string fd_str = std::to_string(fd);
            setenv("MLFUZZZ3_BRANCH_FD", fd_str.c_str(), 1);
        } else {
            unsetenv("MLFUZZZ3_BRANCH_FD");
        }
        void *handle = dlopen(MLFUZZZ3_COV_LIB_PATH, RTLD_NOW | RTLD_LOCAL);
        if (handle == nullptr) {
            _exit(kChildDlopenFailed);
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto log_fn = reinterpret_cast<LogBranchFn>(dlsym(handle, "fuzzer_rt_log_branch_cmp"));
        if (log_fn == nullptr) {
            _exit(kChildDlsymFailed);
        }
        for (const Call &c : calls) {
            log_fn(c.site_id, c.lhs, c.rhs, c.predicate, c.bit_width);
        }
        _exit(0);
    }
    int status = 0;
    EXPECT_EQ(waitpid(pid, &status, 0), pid);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;  // signalled / abnormal
}

// Maps the segment read-only in the parent and copies out the
// header. The record pointer remains valid only while `map`
// (returned via out-param) is mapped.
struct MappedSegment {
    void *base;
    size_t size;
};

MappedSegment MapSegment(int fd, size_t seg_size) {
    void *base = mmap(nullptr, seg_size, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        return {nullptr, 0};
    }
    return {base, seg_size};
}

const fuzzer_rt_branch_header *HeaderOf(const MappedSegment &m) {
    return static_cast<const fuzzer_rt_branch_header *>(m.base);
}

const fuzzer_rt_branch_record *RecordsOf(const MappedSegment &m) {
    return reinterpret_cast<const fuzzer_rt_branch_record *>(static_cast<const uint8_t *>(m.base) +
                                                             sizeof(fuzzer_rt_branch_header));
}

size_t SegmentSize(uint32_t capacity) {
    return sizeof(fuzzer_rt_branch_header) +
           static_cast<size_t>(capacity) * sizeof(fuzzer_rt_branch_record);
}

// Without MLFUZZZ3_BRANCH_FD the hook must be a no-op: the
// child must not crash, and the zero-initialized segment must
// stay empty.
TEST(MlFuzzz3BranchTest, NoEnvIsNoOp) {
    const uint32_t capacity = 4;
    const int fd = MakeSegment(SegmentSize(capacity));
    ASSERT_GE(fd, 0);

    const std::vector<Call> calls = {
        {1, 2, 3, kFuzzerRtCmpEq, 32},
        {4, 5, 6, kFuzzerRtCmpUlt, 64},
    };
    EXPECT_EQ(RunChild(fd, /*set_env=*/false, calls), 0);

    const MappedSegment m = MapSegment(fd, SegmentSize(capacity));
    ASSERT_NE(m.base, nullptr);
    EXPECT_EQ(HeaderOf(m)->count, 0u);
    EXPECT_EQ(HeaderOf(m)->overflow_flag, 0u);
    EXPECT_EQ(munmap(m.base, m.size), 0);
    EXPECT_EQ(close(fd), 0);
}

// With the fd set, N calls produce exactly N records with the
// fields preserved byte-for-byte — a format check of the
// writer side. Signed vs unsigned predicates and differing bit
// widths are distinguishable.
TEST(MlFuzzz3BranchTest, RecordsWrittenWithFd) {
    const uint32_t capacity = 8;
    const int fd = MakeSegment(SegmentSize(capacity));
    ASSERT_GE(fd, 0);

    const std::vector<Call> calls = {
        {10, 0x1122334455667788ULL, 0xAABBCCDDEEFF0011ULL, kFuzzerRtCmpUlt, 64},
        {20, 5, 7, kFuzzerRtCmpSgt, 32},
        {30, 0, 0, kFuzzerRtCmpEq, 8},
    };
    ASSERT_EQ(RunChild(fd, /*set_env=*/true, calls), 0);

    const MappedSegment m = MapSegment(fd, SegmentSize(capacity));
    ASSERT_NE(m.base, nullptr);
    const fuzzer_rt_branch_header *hdr = HeaderOf(m);
    EXPECT_EQ(hdr->count, calls.size());
    EXPECT_EQ(hdr->capacity, capacity);
    EXPECT_EQ(hdr->overflow_flag, 0u);

    const fuzzer_rt_branch_record *rec = RecordsOf(m);
    for (size_t i = 0; i < calls.size(); ++i) {
        EXPECT_EQ(rec[i].site_id, calls[i].site_id) << "i=" << i;
        EXPECT_EQ(rec[i].lhs, calls[i].lhs) << "i=" << i;
        EXPECT_EQ(rec[i].rhs, calls[i].rhs) << "i=" << i;
        EXPECT_EQ(rec[i].predicate, calls[i].predicate) << "i=" << i;
        EXPECT_EQ(rec[i].bit_width, calls[i].bit_width) << "i=" << i;
    }
    EXPECT_EQ(munmap(m.base, m.size), 0);
    EXPECT_EQ(close(fd), 0);
}

// More calls than capacity: count saturates at capacity, the
// overflow flag is set, the first `capacity` records survive,
// and (since the child did not crash writing past the exactly
// sized mapping) no out-of-bounds write occurred.
TEST(MlFuzzz3BranchTest, OverflowSetsFlag) {
    const uint32_t capacity = 2;
    const int fd = MakeSegment(SegmentSize(capacity));
    ASSERT_GE(fd, 0);

    const std::vector<Call> calls = {
        {100, 11, 12, kFuzzerRtCmpNe, 16},
        {101, 13, 14, kFuzzerRtCmpUge, 32},
        {102, 15, 16, kFuzzerRtCmpSlt, 64},
        {103, 17, 18, kFuzzerRtCmpEq, 8},
    };
    ASSERT_EQ(RunChild(fd, /*set_env=*/true, calls), 0);

    const MappedSegment m = MapSegment(fd, SegmentSize(capacity));
    ASSERT_NE(m.base, nullptr);
    const fuzzer_rt_branch_header *hdr = HeaderOf(m);
    EXPECT_EQ(hdr->count, capacity);
    EXPECT_EQ(hdr->overflow_flag, 1u);

    const fuzzer_rt_branch_record *rec = RecordsOf(m);
    EXPECT_EQ(rec[0].site_id, calls[0].site_id);
    EXPECT_EQ(rec[1].site_id, calls[1].site_id);
    EXPECT_EQ(munmap(m.base, m.size), 0);
    EXPECT_EQ(close(fd), 0);
}

}  // namespace
