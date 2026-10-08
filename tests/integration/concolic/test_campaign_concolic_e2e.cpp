// End-to-end campaign concolic integration (ADR 0036 §Тестирование). A
// real exec-server runs the cov_xfield fixture; a CampaignLoop with a
// production SessionRunner fuzzes a seed that satisfies C1,C2,C3 but not
// C4 (the wrapping cross-field sum). Byte-flip mutation cannot realistically
// hit (x + y) mod 2^32 == 5 with both fields above the bound, so the seed
// stalls; once its per-seed stagnation counter crosses the (test-lowered)
// threshold the loop itself invokes concolic, which solves the cross-field
// system and drives the input to the crash. The crash is therefore
// attributable to the concolic branch (concolic_crashes > 0), not to a
// lucky mutation.
//
// A FixedScheduler always selects seed 0 so its counter climbs
// deterministically; with a fixed RNG seed the whole campaign is
// reproducible. Self-skips when any artifact is unavailable.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "campaign.h"
#include "corpus.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"

namespace mlfuzzz3::core {
namespace {

struct ExecServerProcess {
    pid_t pid = -1;
    int client_fd = -1;

    ExecServerProcess() = default;
    ExecServerProcess(const ExecServerProcess&) = delete;
    ExecServerProcess& operator=(const ExecServerProcess&) = delete;

    ~ExecServerProcess() {
        if (client_fd >= 0) {
            ::close(client_fd);
        }
        if (pid > 0) {
            ::kill(pid, SIGKILL);
            int status = 0;
            ::waitpid(pid, &status, 0);
        }
    }
};

bool SpawnExecServer(const std::string& bin, const std::string& target, const std::string& cov_lib,
                     ExecServerProcess& out, std::string& out_err) {
    std::array<int, 2> sv{};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv.data()) != 0) {
        out_err = std::string("socketpair: ") + std::strerror(errno);
        return false;
    }
    const int client_fd = sv[0];
    const int server_fd = sv[1];

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        ::close(client_fd);
        ::close(server_fd);
        out_err = std::string("fork: ") + std::strerror(err);
        return false;
    }
    if (pid == 0) {
        ::close(client_fd);
        if (server_fd != 3) {
            if (::dup2(server_fd, 3) < 0) {
                ::_exit(127);
            }
            ::close(server_fd);
        }
        const int flags3 = ::fcntl(3, F_GETFD);
        if (flags3 >= 0) {
            (void)::fcntl(3, F_SETFD, flags3 & ~FD_CLOEXEC);
        }
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)::dup2(devnull, 1);
            (void)::dup2(devnull, 2);
            if (devnull > 2) {
                ::close(devnull);
            }
        }
        const char* argv[] = {
            bin.c_str(), "-target", target.c_str(),    "-cov-library", cov_lib.c_str(),
            "-workers",  "1",       "-run-timeout-ms", "5000",         nullptr,
        };
        ::execv(bin.c_str(), const_cast<char* const*>(argv));
        ::_exit(127);
    }

    ::close(server_fd);
    out.client_fd = client_fd;
    out.pid = pid;
    return true;
}

bool PathReadable(const std::string& path) {
    return ::access(path.c_str(), R_OK) == 0;
}
bool PathExecutable(const std::string& path) {
    return ::access(path.c_str(), R_OK | X_OK) == 0;
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger.
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

TEST(CampaignConcolicE2E, CampaignReachesCrashViaConcolicOnStagnation) {
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string fixture = COV_XFIELD_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(fixture)) {
        GTEST_SKIP() << "cov_xfield_target missing: " << fixture;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    // Workspace: a seed dir holding the stuck seed (passes C1,C2,C3; not C4)
    // and a corpus rooted alongside it.
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_campaign_concolic_e2e";
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    const std::filesystem::path seed_dir = base / "seeds";
    std::filesystem::create_directories(seed_dir);
    // x=0x20000000 @0, y=0x30000000 @4 (LE).
    const std::array<std::uint8_t, 8> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    {
        std::ofstream out(seed_dir / "xfield", std::ios::binary);
        out.write(reinterpret_cast<const char*>(seed.data()),
                  static_cast<std::streamsize>(seed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_GE(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "e2e-run");
    ASSERT_TRUE(metrics.has_value());

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(exec_server, fixture, cov_lib, proc, spawn_err)) << spawn_err;

    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn), ipc::ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    SessionRunner runner(*session);
    FixedScheduler scheduler;
    mutation::ByteFlipMutator mutator;
    // det disabled, small stagnation threshold, generous iteration budget.
    const CampaignConfig cfg{.max_iterations = 200,
                             .metrics_interval = 0,
                             .rng_seed = 7,
                             .max_det_steps = 0,
                             .concolic_stagnation_threshold = 8,
                             .concolic_timeout_ms = 2000};

    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, cfg);
    const CampaignStats stats = loop.Run();

    EXPECT_FALSE(stats.aborted) << "campaign aborted on infrastructure errors";
    EXPECT_GT(stats.concolic_calls, 0U) << "stagnation never triggered concolic";
    EXPECT_GT(stats.concolic_crashes, 0U)
        << "concolic did not reach the cross-field crash (calls=" << stats.concolic_calls
        << ", candidates=" << stats.concolic_candidates << ")";
    // Every crash here is the cross-field wrap crash, unreachable by
    // byte-flip mutation: the crashes are the concolic ones.
    EXPECT_EQ(stats.crashes, stats.concolic_crashes);

    std::filesystem::remove_all(base, ec);
}

}  // namespace
}  // namespace mlfuzzz3::core
