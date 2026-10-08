#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>

// Cross-field Z3-necessary fixture smoke test (ADR 0035).
//
// cov_xfield_target aborts only when the two 4-byte little-endian input
// fields x (bytes 0..3) and y (bytes 4..7) jointly satisfy a system that
// LINKS them (see cov_xfield_target.c):
//
//   x > 0x10000000  AND  y > 0x10000000  AND  x < y  AND  (x + y) == 5 (u32 wrap)
//
// Reaching the crash needs a constraint solver over BOTH fields at once;
// the satisfying pair below was found by hand and is hard-coded so this
// test does not itself depend on a solver:
//
//   x = 0x40000000, y = 0xC0000005
//     -> 0x40000000 > 0x10000000, 0xC0000005 > 0x10000000, x < y,
//        x + y = 0x100000005, wrapped u32 = 5.
//
// Z3-necessity is demonstrated directly: substituting a single observed
// operand (0x10000000 or 5) into one field does NOT crash, because it
// breaks a lower bound or the wrapping sum. No single-operand
// (RedQueen / input-to-state) substitution reaches the crash — only the
// jointly solved pair does:
//   (0x10000000, 0x10000000) -> x not > 0x10000000        (no crash)
//   (5, 5)                    -> x not > 0x10000000        (no crash)
//   (0x40000000, 5)          -> y not > 0x10000000        (no crash)
//   (0x10000000, 0xC0000005) -> x not > 0x10000000        (no crash)
//
// The fixture is instrumented with the edge + branch passes. The edge
// pass emits an inline write into __mlfuzzz3_cov_map, which is NULL unless
// MLFUZZZ3_COV_FD points at a mapped bitmap — so, exactly like the
// exec-server harness, the test hands the child a throwaway bitmap fd on
// fd 3. The branch channel is left inert (MLFUZZZ3_BRANCH_FD unset); its
// logging hook is a NULL-checked call, so that is safe. With coverage
// satisfied, only the constraint logic decides crash vs clean exit.

namespace {

constexpr const char* kFixtureBin = COV_XFIELD_BIN;

// Edge bitmap size — must match the runtime's COV_MAP_SIZE (1u << 16,
// ADR 0017). The throwaway fd only has to be at least this large for the
// inline instrumentation's mmap to succeed.
constexpr std::size_t kCovMapSize = 1U << 16;

// Child fd for the edge bitmap, mirroring the exec-server contract
// (MLFUZZZ3_COV_FD=3).
constexpr int kCovChildFd = 3;

// Two 4-byte little-endian fields.
constexpr std::size_t kInputSize = 8;

// RunResult captures how the child process terminated.
struct RunResult {
    bool spawned = false;
    bool signaled = false;
    int term_signal = 0;
    int exit_code = -1;
};

// MakeCovFd returns a writable, mapping-sized anonymous fd for the edge
// bitmap, or -1 on failure.
int MakeCovFd() {
    const int fd = static_cast<int>(::syscall(SYS_memfd_create, "mlfuzzz3_cov_xfield", 0U));
    if (fd < 0) {
        return -1;
    }
    if (::ftruncate(fd, static_cast<off_t>(kCovMapSize)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// RunFixture pipes the eight input bytes to the fixture's stdin, hands it
// a throwaway coverage bitmap on fd 3, waits for it, and reports how it
// terminated.
RunResult RunFixture(const std::array<std::uint8_t, kInputSize>& input) {
    RunResult result;

    const int cov_fd = MakeCovFd();
    if (cov_fd < 0) {
        return result;
    }

    std::array<int, 2> in_pipe{-1, -1};
    if (::pipe(in_pipe.data()) != 0) {
        ::close(cov_fd);
        return result;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(cov_fd);
        ::close(in_pipe[0]);
        ::close(in_pipe[1]);
        return result;
    }
    if (pid == 0) {
        // Child: stdin from the pipe, the bitmap on fd 3, std{out,err}
        // discarded.
        ::dup2(in_pipe[0], 0);
        if (cov_fd != kCovChildFd) {
            ::dup2(cov_fd, kCovChildFd);
        }
        const int flags = ::fcntl(kCovChildFd, F_GETFD);
        if (flags >= 0) {
            (void)::fcntl(kCovChildFd, F_SETFD, flags & ~FD_CLOEXEC);
        }
        ::setenv("MLFUZZZ3_COV_FD", "3", 1);

        ::close(in_pipe[0]);
        ::close(in_pipe[1]);
        if (cov_fd != kCovChildFd) {
            ::close(cov_fd);
        }
        const int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, 1);
            ::dup2(devnull, 2);
            if (devnull > 2) {
                ::close(devnull);
            }
        }
        const char* argv[] = {kFixtureBin, nullptr};
        ::execv(kFixtureBin, const_cast<char* const*>(argv));
        ::_exit(127);
    }

    // Parent: write the input, close everything, reap the child.
    ::close(cov_fd);
    ::close(in_pipe[0]);
    const ssize_t written = ::write(in_pipe[1], input.data(), input.size());
    (void)written;
    ::close(in_pipe[1]);

    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) {
        return result;
    }
    result.spawned = true;
    if (WIFSIGNALED(status)) {
        result.signaled = true;
        result.term_signal = WTERMSIG(status);
    } else if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

bool FixtureExists() {
    return ::access(kFixtureBin, X_OK) == 0;
}

// LeBytes encodes two uint32 fields as their little-endian input bytes
// (x at offset 0, y at offset 4).
std::array<std::uint8_t, kInputSize> LeBytes(std::uint32_t x, std::uint32_t y) {
    return {
        static_cast<std::uint8_t>(x & 0xFFu),         static_cast<std::uint8_t>((x >> 8) & 0xFFu),
        static_cast<std::uint8_t>((x >> 16) & 0xFFu), static_cast<std::uint8_t>((x >> 24) & 0xFFu),
        static_cast<std::uint8_t>(y & 0xFFu),         static_cast<std::uint8_t>((y >> 8) & 0xFFu),
        static_cast<std::uint8_t>((y >> 16) & 0xFFu), static_cast<std::uint8_t>((y >> 24) & 0xFFu),
    };
}

TEST(CovXfieldSmoke, SatisfyingPairCrashes) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "cov_xfield_target missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture(LeBytes(0x40000000u, 0xC0000005u));
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_TRUE(r.signaled) << "expected a crash, got exit code " << r.exit_code;
    EXPECT_EQ(r.term_signal, SIGABRT);
}

TEST(CovXfieldSmoke, NeutralInputDoesNotCrash) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "cov_xfield_target missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture(LeBytes(0x00000000u, 0x00000000u));
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_FALSE(r.signaled) << "neutral input unexpectedly crashed with signal " << r.term_signal;
    EXPECT_EQ(r.exit_code, 0);
}

// Z3-necessity demonstration: no single observed operand, substituted into
// one field, reaches the crash. Each pair below breaks a lower bound or
// the wrapping sum — only the jointly solved pair (above) crashes.
TEST(CovXfieldSmoke, SingleOperandSubstitutionDoesNotCrash) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "cov_xfield_target missing: " << kFixtureBin;
    }
    const std::array<std::array<std::uint32_t, 2>, 4> probes = {{
        {0x10000000u, 0x10000000u},  // x not > 0x10000000
        {0x00000005u, 0x00000005u},  // x not > 0x10000000
        {0x40000000u, 0x00000005u},  // y not > 0x10000000
        {0x10000000u, 0xC0000005u},  // x not > 0x10000000
    }};
    for (const auto& probe : probes) {
        const RunResult r = RunFixture(LeBytes(probe[0], probe[1]));
        ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
        EXPECT_FALSE(r.signaled) << "single-operand substitution unexpectedly crashed: x="
                                 << probe[0] << " y=" << probe[1];
        EXPECT_EQ(r.exit_code, 0);
    }
}

}  // namespace
