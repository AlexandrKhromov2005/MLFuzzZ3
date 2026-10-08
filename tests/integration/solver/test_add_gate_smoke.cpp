#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>

// Cross-field addition gate fixture smoke test (ADR 0036).
//
// add_gate aborts only when the two 4-byte little-endian input fields
// a (bytes 0..3) and b (bytes 4..7) satisfy, jointly (see add_gate.c and
// gate_guard.h):
//
//   guard(a, b)  AND  (a + b) == 0xDEADBEEF  (u32)
//   guard(a, b) := LO <= a <= HI && LO <= b <= HI && nz32(a) && nz32(b)
//   LO = 0x01000000, HI = 0x7F000000, nz32(v) := all four bytes of v != 0
//
// The sum is what the gate compares, and the sum is NOT present in the
// input — neither operand of the winning comparison can be copied out of
// the input, which is why AFL++ cmplog does not take this gate (task-012:
// 0 crashes in 9.1M execs) while the concolic arm does.
//
// This test does not depend on a solver: the satisfying pair below was
// found by hand and is hard-coded.
//
//   a = 0x70B1C2D3, b = 0x6DFBFC1C
//     -> both inside [LO, HI], all eight bytes non-zero,
//        a + b = 0xDEADBEEF exactly (no u32 wrap).
//
// What guard() buys is demonstrated directly: every degenerate family that
// also sums to 0xDEADBEEF is rejected, so a crash here cannot be reached
// by pasting the magic token (or a byte-aligned slice of it) into a field.
// Those probes are listed in GuardRejectsDegenerateSums below.
//
// The fixture is instrumented with the branch + edge passes. The edge pass
// emits an inline write into __mlfuzzz3_cov_map, which is NULL unless
// MLFUZZZ3_COV_FD points at a mapped bitmap — so, exactly like the
// exec-server harness (and like test_cov_xfield_smoke.cpp), the test hands
// the child a throwaway bitmap fd on fd 3. The branch channel is left
// inert (MLFUZZZ3_BRANCH_FD unset); its logging hook is a NULL-checked
// call, so that is safe. With coverage satisfied, only the gate logic
// decides crash vs clean exit.

namespace {

constexpr const char* kFixtureBin = ADD_GATE_BIN;

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
    const int fd = static_cast<int>(::syscall(SYS_memfd_create, "mlfuzzz3_add_gate", 0U));
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
// (a at offset 0, b at offset 4).
std::array<std::uint8_t, kInputSize> LeBytes(std::uint32_t a, std::uint32_t b) {
    return {
        static_cast<std::uint8_t>(a & 0xFFu),         static_cast<std::uint8_t>((a >> 8) & 0xFFu),
        static_cast<std::uint8_t>((a >> 16) & 0xFFu), static_cast<std::uint8_t>((a >> 24) & 0xFFu),
        static_cast<std::uint8_t>(b & 0xFFu),         static_cast<std::uint8_t>((b >> 8) & 0xFFu),
        static_cast<std::uint8_t>((b >> 16) & 0xFFu), static_cast<std::uint8_t>((b >> 24) & 0xFFu),
    };
}

TEST(AddGateSmoke, SolvedPairCrashes) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "add_gate missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture(LeBytes(0x70B1C2D3u, 0x6DFBFC1Cu));
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_TRUE(r.signaled) << "expected a crash, got exit code " << r.exit_code;
    EXPECT_EQ(r.term_signal, SIGABRT);
}

// The seed the kaddvars solver arm starts from
// (docs/experiments/kaddvars-solver-arm/run.sh:37): both fields inside the
// guard band, sum 0x6E5E4E3E != MAGIC. It must not crash, or the arm's
// "execs to first crash" numbers would measure nothing.
TEST(AddGateSmoke, ArmSeedDoesNotCrash) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "add_gate missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture(LeBytes(0x44332211u, 0x2A2B2C2Du));
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_FALSE(r.signaled) << "arm seed unexpectedly crashed with signal " << r.term_signal;
    EXPECT_EQ(r.exit_code, 0);
}

// Input shorter than the two fields is rejected before the gate
// (add_gate.c:17), so it can never be a crash.
TEST(AddGateSmoke, ShortInputDoesNotCrash) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "add_gate missing: " << kFixtureBin;
    }
    const RunResult r = RunFixture({0x01u, 0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u});
    ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
    EXPECT_FALSE(r.signaled) << "short input unexpectedly crashed with signal " << r.term_signal;
    EXPECT_EQ(r.exit_code, 0);
}

// What the guard is for. Every pair below sums to exactly 0xDEADBEEF and
// is still rejected, so none of the cheap ways to "hit" the gate without
// composing two fields reaches the crash. If guard() ever stops excluding
// these, this fixture stops being solver-requiring and the e2e oracles
// built on it would start passing for the wrong reason.
TEST(AddGateSmoke, GuardRejectsDegenerateSums) {
    if (!FixtureExists()) {
        GTEST_SKIP() << "add_gate missing: " << kFixtureBin;
    }
    const std::array<std::array<std::uint32_t, 2>, 5> probes = {{
        // Byte-aligned split of the magic token across the two fields:
        // both halves carry zero bytes, and a is below LO.
        {0x0000BEEFu, 0xDEAD0000u},
        // The whole token verbatim in one field, the other zeroed — what a
        // dictionary/cmplog substitution would produce.
        {0xDEADBEEFu, 0x00000000u},
        // Wrap-around family ("b = -small"): a near 2^32, sum wraps to
        // MAGIC. Excluded by the upper band bound.
        {0xFFFFFFFFu, 0xDEADBEF0u},
        // a one past the upper band bound — the band is closed at HI.
        {0x7F000001u, 0x5FADBEEEu},
        // Both fields inside the band, but a has a zero byte: rejected by
        // nz32 alone. This is the only probe the band test would let
        // through, so it is what pins the nz32 clause.
        {0x70B1C200u, 0x6DFBFCEFu},
    }};
    for (const auto& probe : probes) {
        const RunResult r = RunFixture(LeBytes(probe[0], probe[1]));
        ASSERT_TRUE(r.spawned) << "failed to spawn fixture";
        EXPECT_FALSE(r.signaled) << "degenerate sum unexpectedly crashed: a=" << probe[0]
                                 << " b=" << probe[1];
        EXPECT_EQ(r.exit_code, 0);
    }
}

}  // namespace
