#include <gtest/gtest.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include "ipc.pb.h"
#include "session.h"
#include "unique_fd.h"

namespace mlfuzzz3::ipc {
namespace {

// MakeSocketPair returns two raw fds connected via
// socketpair(AF_UNIX, SOCK_STREAM, 0). Caller takes ownership
// (typically by wrapping each fd in a Conn).
std::pair<int, int> MakeSocketPair() {
    int fds[2];
    EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0) << "socketpair errno=" << errno;
    return {fds[0], fds[1]};
}

// MemfdCreate wraps memfd_create via raw syscall — per
// project conventions, no new C++ dependency is permitted, and
// glibc < 2.27 may not expose memfd_create() directly. The
// raw syscall is portable across all supported targets
// (Linux >= 3.17 ships __NR_memfd_create).
int MemfdCreate(const char* name) {
#ifdef __NR_memfd_create
    return static_cast<int>(syscall(__NR_memfd_create, name, 0));
#else
    // x86_64 fallback — historical syscall number.
    return static_cast<int>(syscall(319, name, 0));
#endif
}

// EdgeAnnouncementEnv builds a representative envelope
// (ChannelAnnouncement / EdgeChannelInfo) used as the
// "carrier" message across SCM_RIGHTS tests.
v1::Envelope EdgeAnnouncementEnv() {
    v1::Envelope env;
    auto* ann = env.mutable_channel_announcement();
    auto* edge = ann->mutable_edge();
    edge->set_shm_name("edge-test");
    edge->set_offset(0);
    edge->set_length(4096);
    edge->set_schema_version(1);
    return env;
}

TEST(ScmRightsTest, RoundTripSendsFdAndContent) {
    auto [server_fd, client_fd] = MakeSocketPair();
    Conn server(server_fd);
    Conn client(client_fd);

    const char* payload = "scm-rights-cpp-test-payload";
    const std::size_t plen = std::strlen(payload);

    int memfd = MemfdCreate("test-roundtrip");
    ASSERT_GE(memfd, 0) << "memfd_create errno=" << errno;
    ASSERT_EQ(::write(memfd, payload, plen), static_cast<ssize_t>(plen));

    auto env = EdgeAnnouncementEnv();
    auto write_result = server.WriteEnvelopeWithFd(env, memfd);
    ASSERT_TRUE(write_result.has_value())
        << "WriteEnvelopeWithFd error: " << static_cast<int>(write_result.error());

    // Local copy is no longer needed; the kernel already
    // duplicated it for the receiver during sendmsg.
    ::close(memfd);

    auto read_result = client.ReadEnvelopeWithFd();
    ASSERT_TRUE(read_result.has_value())
        << "ReadEnvelopeWithFd error: " << static_cast<int>(read_result.error());

    EXPECT_TRUE(read_result->envelope.has_channel_announcement());
    ASSERT_TRUE(read_result->fd);
    ASSERT_GE(read_result->fd.get(), 0);

    void* mapped = ::mmap(nullptr, plen, PROT_READ, MAP_SHARED, read_result->fd.get(), 0);
    ASSERT_NE(mapped, MAP_FAILED) << "mmap errno=" << errno;
    EXPECT_EQ(std::memcmp(mapped, payload, plen), 0);
    ::munmap(mapped, plen);
}

TEST(ScmRightsTest, ReadWithFdReturnsMissingFdOnPlain) {
    auto [server_fd, client_fd] = MakeSocketPair();
    Conn server(server_fd);
    Conn client(client_fd);

    auto env = EdgeAnnouncementEnv();
    ASSERT_TRUE(server.WriteEnvelope(env).has_value());

    auto read_result = client.ReadEnvelopeWithFd();
    ASSERT_FALSE(read_result.has_value());
    EXPECT_EQ(read_result.error(), IpcError::kMissingFd);
}

TEST(ScmRightsTest, ReadMaybeFdSucceedsWithoutFd) {
    auto [server_fd, client_fd] = MakeSocketPair();
    Conn server(server_fd);
    Conn client(client_fd);

    auto env = EdgeAnnouncementEnv();
    ASSERT_TRUE(server.WriteEnvelope(env).has_value());

    auto read_result = client.ReadEnvelopeMaybeFd();
    ASSERT_TRUE(read_result.has_value());
    EXPECT_FALSE(read_result->fd);
    EXPECT_TRUE(read_result->envelope.has_channel_announcement());
}

TEST(ScmRightsTest, WriteWithFdRejectsOversize) {
    auto [server_fd, client_fd] = MakeSocketPair();
    Conn server(server_fd);
    ::close(client_fd);

    int memfd = MemfdCreate("test-oversize");
    ASSERT_GE(memfd, 0);

    v1::Envelope env;
    auto* req = env.mutable_run_request();
    req->set_input(std::string(2 * 1024 * 1024, 'x'));

    auto result = server.WriteEnvelopeWithFd(env, memfd);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), IpcError::kFraming);

    ::close(memfd);
}

TEST(UniqueFdTest, ClosesOnScopeExit) {
    int memfd = MemfdCreate("test-raii");
    ASSERT_GE(memfd, 0);
    ASSERT_EQ(::write(memfd, "x", 1), 1);

    {
        UniqueFd guard(memfd);
        ASSERT_TRUE(guard);
        ASSERT_EQ(guard.get(), memfd);
    }

    // After UniqueFd's scope exit the fd is closed; any
    // subsequent operation must yield EBADF.
    EXPECT_EQ(::write(memfd, "x", 1), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST(UniqueFdTest, ReleaseTransfersOwnership) {
    int memfd = MemfdCreate("test-release");
    ASSERT_GE(memfd, 0);

    int released = -1;
    {
        UniqueFd guard(memfd);
        released = guard.release();
        EXPECT_EQ(released, memfd);
        EXPECT_FALSE(guard);
        EXPECT_EQ(guard.get(), -1);
    }

    // After release, the fd must remain open (UniqueFd's
    // destructor was a no-op because the wrapper had been
    // emptied to -1).
    EXPECT_EQ(::write(released, "x", 1), 1);
    ::close(released);
}

}  // namespace
}  // namespace mlfuzzz3::ipc
