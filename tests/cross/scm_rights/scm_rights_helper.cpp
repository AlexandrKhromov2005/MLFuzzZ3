// SCM_RIGHTS cross-language E2E helper.
//
// This binary exists solely to validate that the wire
// protocol for ChannelAnnouncement-with-fd is identical
// between the Go server (exec-server) and the C++ client
// (fuzzer-core). It is built only via the project's
// cmake graph and invoked from
// exec-server/internal/ipc/scmrights_crosslang_test.go;
// it is not a product binary.
//
// Contract:
//   - Inherits an AF_UNIX SOCK_STREAM socket at fd 3
//     (mirrors production ipcSocketFd=3 in exec-server
//     main.go).
//   - Reads exactly one envelope via
//     Conn::ReadEnvelopeWithFd().
//   - mmaps the received fd, writes the raw bytes to
//     stdout, exits 0.
//   - On any error: writes diagnostic to stderr, exits
//     non-zero (specific code per failure kind).
//
// The Go test driver compares stdout against the known
// payload it wrote into the source memfd before sending.

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "session.h"
#include "unique_fd.h"

namespace {

constexpr int kSocketFd = 3;

enum ExitCode : int {
    kOk = 0,
    kReadFailed = 10,
    kFstatFailed = 11,
    kMmapFailed = 12,
    kShortWrite = 13,
};

}  // namespace

int main() {
    using namespace mlfuzzz3::ipc;

    Conn conn(kSocketFd);
    auto result = conn.ReadEnvelopeWithFd();
    if (!result.has_value()) {
        std::fprintf(stderr,
                     "scm_rights_helper: ReadEnvelopeWithFd "
                     "error %d\n",
                     static_cast<int>(result.error()));
        return kReadFailed;
    }

    const int recv_fd = result->fd.get();
    struct stat st{};
    if (::fstat(recv_fd, &st) != 0) {
        std::fprintf(stderr, "scm_rights_helper: fstat: %s\n", std::strerror(errno));
        return kFstatFailed;
    }

    const auto size = static_cast<std::size_t>(st.st_size);
    if (size == 0) {
        // Empty payload: nothing to mmap, success.
        return kOk;
    }

    void* mapped = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, recv_fd, 0);
    if (mapped == MAP_FAILED) {
        std::fprintf(stderr, "scm_rights_helper: mmap: %s\n", std::strerror(errno));
        return kMmapFailed;
    }

    std::size_t written_total = 0;
    while (written_total < size) {
        ssize_t n = ::write(STDOUT_FILENO, static_cast<const char*>(mapped) + written_total,
                            size - written_total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::fprintf(stderr, "scm_rights_helper: write: %s\n", std::strerror(errno));
            ::munmap(mapped, size);
            return kShortWrite;
        }
        if (n == 0) {
            std::fprintf(stderr, "scm_rights_helper: write returned 0\n");
            ::munmap(mapped, size);
            return kShortWrite;
        }
        written_total += static_cast<std::size_t>(n);
    }

    ::munmap(mapped, size);
    return kOk;
}
