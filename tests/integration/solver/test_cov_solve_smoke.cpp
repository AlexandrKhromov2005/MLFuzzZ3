#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>

// Solver-necessary fixture smoke test (ADR 0034 prep — PROVISIONAL).
//
// cov_solve_target aborts only when the 4-byte little-endian input word x
// satisfies a system of four constraints at once (see cov_solve_target.c).
// Reaching the crash needs a constraint solver; the satisfying value below
// was found by brute force and is hard-coded so this test does not itself
// depend on a solver:
//
//   x = 0x10000001  ->  > 0x10000000, < 0x20000000, %7 == 3,
//                       ((x ^ 0x5A5A5A5A) & 0xFFFF) = 0x5A5B > 0x4000.
//
// The fixture is instrumented with the edge + branch passes. The edge
// pass emits an inline write into __mlfuzzz3_cov_map, which is NULL unless
// MLFUZZZ3_COV_FD points at a mapped bitmap — so, exactly like the
// exec-server harness, the test hands the child a throwaway bitmap fd on
// fd 3. The branch channel is left inert (MLFUZZZ3_BRANCH_FD unset); its
// logging hook is a NULL-checked call, so that is safe. With coverage
// satisfied, only the constraint logic decides crash vs clean exit.

namespace {

constexpr const char* kFixtureBin = COV_SOLVE_BIN;

// Edge bitmap size — must match the runtime's COV_MAP_SIZE (1u << 16,
// ADR 0017). The throwaway fd only has to be at least this large for the
// inline instrumentation's mmap to succeed.
constexpr std::size_t kCovMapSize = 1U << 16;

// Child fd for the edge bitmap, mirroring the exec-server contract
// (MLFUZZZ3_COV_FD=3).
constexpr int kCovChildFd = 3;

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
    const int fd = static_cast<int>(::syscall(SYS_memfd_create, "mlfuzzz3_cov_smoke", 0U));
    if (fd < 0) {
        return -1;
    }
    if (::ftruncate(fd, static_cast<off_t>(kCovMapSize)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// RunFixture pipes the four input bytes to the fixture's stdin, hands it a
// throwaway coverage bitmap on fd 3, waits for it, and reports how it
// terminated.
RunResult RunFixture(const std::array<std::uint8_t, 4>& input) {
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

// LeBytes encodes a uint32 as its four little-endian input bytes.
std::array<std::uint8_t, 4> LeBytes(std::uint32_t v) {
    return {static_cast<std::uint8_t>(v & 0xFFu), static_cast<std::uint8_t>((v >> 8) & 0xFFu),
            static_cast<std::uint8_t>((v >> 16) & 0xFFu),
            static_cast<std::uint8_t>((v >> 24) & 0xFFu)};
}

TEST(CovSolveSmoke, SatisfyingInputCrashes) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "cov_solve_target missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture(LeBytes(0x10000001u));
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_TRUE(r.signaled) << "expected a crash, got exit code " << r.exit_code;
    EXPECT_EQ(r.term_signal, SIGABRT);
}

TEST(CovSolveSmoke, NeutralInputDoesNotCrash) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "cov_solve_target missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture(LeBytes(0x00000000u));
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_FALSE(r.signaled) << "neutral input unexpectedly crashed with signal " << r.term_signal;
    EXPECT_EQ(r.exit_code, 0);
}

}  // namespace
