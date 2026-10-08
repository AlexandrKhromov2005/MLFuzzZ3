// Unit test для libmlfuzzz3_cov.so:
// 1. Library loadable via dlopen.
// 2. Required symbols present.
// 3. Constructor doesn't crash without env var.
// 4. NULL-safety (ADR 0042 A2+B1): without a coverage fd the
//    constructor backs __mlfuzzz3_cov_map with a full-size
//    writable fallback, and an instrumented binary run without
//    the fd no longer SIGSEGVs on its first edge.

#include <dlfcn.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>

namespace {

// Path to library .so. Set via target_compile_definitions
// в CMakeLists.txt to absolute build path.
#ifndef MLFUZZZ3_COV_LIB_PATH
#error "MLFUZZZ3_COV_LIB_PATH must be defined at compile time"
#endif

// Coverage map size, mirroring COV_MAP_SIZE in the runtime (64 KiB,
// ADR 0017/0021/0024). The inline IR masks indices with
// COV_MAP_SIZE-1, so the fallback map must cover [0, COV_MAP_SIZE).
constexpr unsigned kCovMapSize = 1u << 16;

// Child exit codes, distinct from 0 so the parent can localize failure.
constexpr int kChildDlopenFailed = 10;
constexpr int kChildDlsymFailed = 11;
constexpr int kChildMapNull = 12;

TEST(MlFuzzz3CovTest, LibraryLoadable) {
    // Ensure env var unset — constructor должен быть inert.
    unsetenv("MLFUZZZ3_COV_FD");

    void *handle = dlopen(MLFUZZZ3_COV_LIB_PATH, RTLD_NOW | RTLD_LOCAL);
    ASSERT_NE(handle, nullptr) << "dlopen failed: " << dlerror();

    // Symbols must exist.
    void *init_sym = dlsym(handle, "__sanitizer_cov_trace_pc_guard_init");
    EXPECT_NE(init_sym, nullptr) << "missing __sanitizer_cov_trace_pc_guard_init";

    void *guard_sym = dlsym(handle, "__sanitizer_cov_trace_pc_guard");
    EXPECT_NE(guard_sym, nullptr) << "missing __sanitizer_cov_trace_pc_guard";

    // Constructor должен have run without crash —
    // we got here, so it didn't abort.

    dlclose(handle);
}

// ADR 0042 A2+B1: without MLFUZZZ3_COV_FD the constructor must still
// leave __mlfuzzz3_cov_map pointing at a writable region of the full
// map size (a private fallback), so the Stage 2 inline IR — which does
// not NULL-check — is safe. The library reads the env once at load, so
// the scenario runs in a forked child that dlopens fresh; the child
// writes the first and last map cell (a too-small or NULL fallback
// would SIGSEGV here and the parent would observe a signal).
TEST(MlFuzzz3CovTest, MapBackedByFallbackWithoutFd) {
    const pid_t pid = fork();
    ASSERT_GE(pid, 0) << "fork failed";
    if (pid == 0) {
        unsetenv("MLFUZZZ3_COV_FD");
        void *handle = dlopen(MLFUZZZ3_COV_LIB_PATH, RTLD_NOW | RTLD_LOCAL);
        if (handle == nullptr) {
            _exit(kChildDlopenFailed);
        }
        // dlsym yields the address of the pointer variable.
        auto **map_pp = static_cast<uint8_t **>(dlsym(handle, "__mlfuzzz3_cov_map"));
        if (map_pp == nullptr) {
            _exit(kChildDlsymFailed);
        }
        uint8_t *map = *map_pp;
        if (map == nullptr) {
            _exit(kChildMapNull);  // A2 violated: fallback not mapped
        }
        // Touch both ends of the map; a short or unmapped region faults.
        map[0] = 1;
        map[kCovMapSize - 1] = 1;
        _exit(0);
    }
    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_FALSE(WIFSIGNALED(status))
        << "fallback map write was killed by signal " << WTERMSIG(status);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child failed at stage " << WEXITSTATUS(status) << " (10=dlopen 11=dlsym 12=map NULL)";
}

// ADR 0042 §Testing regression: a real pass-instrumented binary run
// WITHOUT a coverage fd must terminate normally, not by SIGSEGV.
// cov_stdin_target reads stdin and exits 0 with no intentional crash,
// so a signal termination would be the instrumentation faulting on a
// NULL map — the exact bug A2 fixes. Self-skips if the fixture binary
// is absent (clang unavailable at build time).
TEST(MlFuzzz3CovTest, InstrumentedBinaryRunsWithoutFd) {
#ifndef COV_STDIN_BIN
    GTEST_SKIP() << "COV_STDIN_BIN not defined";
#else
    if (access(COV_STDIN_BIN, X_OK) != 0) {
        GTEST_SKIP() << "cov_stdin_target missing: " << COV_STDIN_BIN;
    }
    const pid_t pid = fork();
    ASSERT_GE(pid, 0) << "fork failed";
    if (pid == 0) {
        unsetenv("MLFUZZZ3_COV_FD");
        const int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)dup2(devnull, 0);
            (void)dup2(devnull, 1);
            (void)dup2(devnull, 2);
            if (devnull > 2) {
                (void)close(devnull);
            }
        }
        char arg0[] = COV_STDIN_BIN;
        char *argv[] = {arg0, nullptr};
        execv(arg0, argv);
        _exit(127);
    }
    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_FALSE(WIFSIGNALED(status))
        << "instrumented binary without fd died by signal " << WTERMSIG(status)
        << " (pre-0042 this was SIGSEGV on the first edge)";
    EXPECT_TRUE(WIFEXITED(status));
#endif
}

}  // namespace
