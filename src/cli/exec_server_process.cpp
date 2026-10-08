#include "exec_server_process.h"

#include <fcntl.h>
#include <signal.h>  // NOLINT(modernize-deprecated-headers): POSIX kill()/SIGKILL, no <csignal> equivalent
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace mlfuzzz3::cli {
namespace {

// The inherited IPC socket the exec-server expects at this descriptor
// (cmd/exec-server/main.go). The worker keeps fds >= this for coverage
// channels; the listening socket is fd 3.
constexpr int kIpcFd = 3;
// Child exit code when exec() fails — distinct from any status the
// exec-server itself returns.
constexpr int kExecFailedExitCode = 127;

}  // namespace

// Parameter order mirrors the exec-server CLI flags (-target, -cov-library,
// -target-args); the single call site (RunCampaign) passes them by name.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
tl::expected<ExecServerProcess, std::string> ExecServerProcess::Spawn(
    const std::string& exec_server_bin, const std::string& target, const std::string& cov_lib,
    const std::string& target_args, std::uint64_t run_timeout_ms) {
    // NOLINTEND(bugprone-easily-swappable-parameters)
    // Build the argv before fork so the child path performs no
    // allocation between fork and execv.
    const std::string timeout_ms = std::to_string(run_timeout_ms);
    std::vector<std::string> args = {exec_server_bin, "-target",  target, "-cov-library",
                                     cov_lib,         "-workers", "1",    "-run-timeout-ms",
                                     timeout_ms};
    // Forward target args only when set, so the spawned argv is byte-for-byte
    // identical to the pre-0040 form when the feature is unused (ADR 0040).
    if (!target_args.empty()) {
        args.emplace_back("-target-args");
        args.push_back(target_args);
    }
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    std::array<int, 2> sockets{};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) != 0) {
        return tl::unexpected(std::string("socketpair: ") + std::strerror(errno));
    }
    const int client_fd = std::get<0>(sockets);
    const int server_fd = std::get<1>(sockets);

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        ::close(client_fd);
        ::close(server_fd);
        return tl::unexpected(std::string("fork: ") + std::strerror(err));
    }
    if (pid == 0) {
        // Child: install server_fd at fd 3, silence stdio, exec.
        ::close(client_fd);
        if (server_fd != kIpcFd) {
            if (::dup2(server_fd, kIpcFd) < 0) {
                ::_exit(kExecFailedExitCode);
            }
            ::close(server_fd);
        }
        // fcntl/open are variadic POSIX primitives with no non-vararg
        // alternative; the vararg-call lint is silenced at each site.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        const int flags = ::fcntl(kIpcFd, F_GETFD);
        if (flags >= 0) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
            (void)::fcntl(kIpcFd, F_SETFD, flags & ~FD_CLOEXEC);
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)::dup2(devnull, 1);
            (void)::dup2(devnull, 2);
            if (devnull > 2) {
                ::close(devnull);
            }
        }
        ::execv(exec_server_bin.c_str(), argv.data());
        ::_exit(kExecFailedExitCode);
    }

    ::close(server_fd);
    return ExecServerProcess(pid, client_fd);
}

ExecServerProcess::ExecServerProcess(ExecServerProcess&& other) noexcept
    : pid_(other.pid_), client_fd_(other.client_fd_) {
    other.pid_ = -1;
    other.client_fd_ = -1;
}

ExecServerProcess& ExecServerProcess::operator=(ExecServerProcess&& other) noexcept {
    if (this != &other) {
        if (client_fd_ >= 0) {
            ::close(client_fd_);
        }
        Reap();
        pid_ = other.pid_;
        client_fd_ = other.client_fd_;
        other.pid_ = -1;
        other.client_fd_ = -1;
    }
    return *this;
}

ExecServerProcess::~ExecServerProcess() {
    if (client_fd_ >= 0) {
        ::close(client_fd_);
    }
    Reap();
}

int ExecServerProcess::TakeClientFd() noexcept {
    const int fd = client_fd_;
    client_fd_ = -1;
    return fd;
}

void ExecServerProcess::Reap() noexcept {
    if (pid_ > 0) {
        ::kill(pid_, SIGKILL);
        int status = 0;
        ::waitpid(pid_, &status, 0);
        pid_ = -1;
    }
}

}  // namespace mlfuzzz3::cli
