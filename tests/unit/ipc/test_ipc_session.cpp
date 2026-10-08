#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <span>
#include <thread>
#include <utility>

#include "ipc.pb.h"
#include "session.h"

namespace mlfuzzz3::ipc {
namespace {

// MakeSocketPair creates two connected AF_UNIX SOCK_STREAM fds
// for in-memory client/server testing. Returns (client_fd,
// server_fd). Aborts test on failure.
std::pair<int, int> MakeSocketPair() {
    std::array<int, 2> fds{};
    int rc = ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data());
    EXPECT_EQ(rc, 0) << "socketpair failed: " << std::strerror(errno);
    return {fds[0], fds[1]};
}

// MemfdCreate wraps memfd_create via raw syscall — matches
// the helper in test_scm_rights.cpp so this file does not
// depend on glibc >= 2.27 for memfd_create() availability.
int MemfdCreate(const char* name) {
#ifdef __NR_memfd_create
    return static_cast<int>(syscall(__NR_memfd_create, name, 0));
#else
    return static_cast<int>(syscall(319, name, 0));
#endif
}

// SimulateServer is a hand-rolled server goroutine-equivalent
// running on a second std::thread. It reads the InitRequest,
// replies with a configurable InitResponse, optionally sends
// channel announcements, and then handles a loop of Run
// requests (echoing back OK) until ShutdownRequest arrives.
struct ServerConfig {
    std::uint32_t reply_major = kProtocolVersionMajor;
    std::uint32_t reply_minor = kProtocolVersionMinor;
    int channels = 0;

    // When true, channel announcements are sent via plain
    // WriteEnvelope without an attached fd — used to exercise
    // the Dial fail-fast path that requires SCM_RIGHTS on
    // every announcement per ADR 0028 part A.
    bool announcement_without_fd = false;

    // If true, skips normal handshake and sends a
    // ShutdownResponse immediately (tests unexpected-envelope
    // path).
    bool send_unexpected_at_init = false;
};

void SimulateServer(int server_fd, ServerConfig cfg) {
    Conn server_conn(server_fd);

    // Read InitRequest (we don't validate it here).
    auto init = server_conn.ReadEnvelope();
    if (!init.has_value()) {
        return;
    }

    if (cfg.send_unexpected_at_init) {
        v1::Envelope bad;
        bad.mutable_shutdown_response();
        (void)server_conn.WriteEnvelope(bad);
        return;
    }

    // Send InitResponse.
    v1::Envelope init_resp;
    auto* ir = init_resp.mutable_init_response();
    ir->set_protocol_version_major(cfg.reply_major);
    ir->set_protocol_version_minor(cfg.reply_minor);
    (void)server_conn.WriteEnvelope(init_resp);

    if (cfg.reply_major != kProtocolVersionMajor) {
        return;  // client will abort
    }

    // Send channel announcements, wait for ack each. Each
    // announcement carries the channel memfd via SCM_RIGHTS
    // (mirrors the real exec-server, ADR 0028 part A) unless
    // the test explicitly requests the no-fd path.
    for (int i = 0; i < cfg.channels; ++i) {
        v1::Envelope ann_env;
        auto* ann = ann_env.mutable_channel_announcement();
        auto* edge = ann->mutable_edge();
        edge->set_shm_name("edge-test");
        edge->set_offset(0);
        edge->set_length(65536);
        edge->set_schema_version(1);

        if (cfg.announcement_without_fd) {
            (void)server_conn.WriteEnvelope(ann_env);
        } else {
            int memfd = MemfdCreate("session-test-edge");
            if (memfd < 0) {
                return;
            }
            (void)server_conn.WriteEnvelopeWithFd(ann_env, memfd);
            // Kernel has duplicated the fd into the receiver
            // by this point; close our copy.
            ::close(memfd);
        }

        auto ack = server_conn.ReadEnvelope();
        if (!ack.has_value()) {
            return;
        }
    }

    // Run loop: reply with OK until Shutdown.
    while (true) {
        auto env = server_conn.ReadEnvelope();
        if (!env.has_value()) {
            return;
        }

        if (env->has_shutdown_request()) {
            v1::Envelope resp;
            resp.mutable_shutdown_response();
            (void)server_conn.WriteEnvelope(resp);
            return;
        }

        if (env->has_run_request()) {
            v1::Envelope resp;
            auto* rr = resp.mutable_run_response();
            rr->set_status(v1::EXEC_STATUS_OK);
            (void)server_conn.WriteEnvelope(resp);
            continue;
        }

        return;  // unexpected
    }
}

// ---- Tests ----

TEST(Session, HappyPath) {
    auto [client_fd, server_fd] = MakeSocketPair();

    std::thread server_thread(SimulateServer, server_fd, ServerConfig{.channels = 1});

    Conn client_conn(client_fd);
    auto session = ClientSession::Dial(std::move(client_conn),
                                       ClientConfig{.run_timeout_ms = 500, .expected_channels = 1});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    // ADR 0028 part A: the announcement carried a fd via
    // SCM_RIGHTS and the session must now own it.
    EXPECT_GE(session->coverage_fd(), 0);

    for (int i = 0; i < 3; ++i) {
        std::array<std::uint8_t, 3> input{'r', 'u', 'n'};
        auto result = session->Run(input);
        ASSERT_TRUE(result.has_value()) << "Run failed: " << static_cast<int>(result.error());
        EXPECT_EQ(result->status(), v1::EXEC_STATUS_OK);
    }

    auto shutdown = session->Shutdown();
    ASSERT_TRUE(shutdown.has_value());

    server_thread.join();
}

TEST(Session, CoverageFdReceivedFromAnnouncement) {
    // Focused variant of HappyPath: verifies that the fd
    // attached to the ChannelAnnouncement via SCM_RIGHTS is
    // surfaced through ClientSession::coverage_fd() and is
    // usable (writable through a separate dup'd path on the
    // server side is exercised by the integration test in
    // task-009b; here we only assert the fd reaches the
    // client end and survives Dial).
    auto [client_fd, server_fd] = MakeSocketPair();
    std::thread server_thread(SimulateServer, server_fd, ServerConfig{.channels = 1});

    Conn client_conn(client_fd);
    auto session =
        ClientSession::Dial(std::move(client_conn), ClientConfig{.expected_channels = 1});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    const int cov_fd = session->coverage_fd();
    EXPECT_GE(cov_fd, 0);
    // fstat must succeed on a live fd; EBADF would indicate
    // that the kernel never installed the SCM_RIGHTS fd into
    // the client's table.
    struct stat st{};
    EXPECT_EQ(::fstat(cov_fd, &st), 0) << "fstat errno=" << errno;

    auto shutdown = session->Shutdown();
    ASSERT_TRUE(shutdown.has_value());
    server_thread.join();
}

TEST(Session, AnnouncementWithoutFdFailsFast) {
    auto [client_fd, server_fd] = MakeSocketPair();
    std::thread server_thread(SimulateServer, server_fd,
                              ServerConfig{.channels = 1, .announcement_without_fd = true});

    Conn client_conn(client_fd);
    auto session =
        ClientSession::Dial(std::move(client_conn), ClientConfig{.expected_channels = 1});

    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error(), IpcError::kMissingFd);

    server_thread.join();
}

TEST(Session, VersionMismatch) {
    auto [client_fd, server_fd] = MakeSocketPair();

    std::thread server_thread(SimulateServer, server_fd, ServerConfig{.reply_major = 2});

    Conn client_conn(client_fd);
    auto session = ClientSession::Dial(std::move(client_conn), ClientConfig{});

    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error(), IpcError::kVersionMismatch);

    server_thread.join();
}

TEST(Session, UnexpectedEnvelope) {
    auto [client_fd, server_fd] = MakeSocketPair();

    std::thread server_thread(SimulateServer, server_fd,
                              ServerConfig{.send_unexpected_at_init = true});

    Conn client_conn(client_fd);
    auto session = ClientSession::Dial(std::move(client_conn), ClientConfig{});

    ASSERT_FALSE(session.has_value());
    EXPECT_EQ(session.error(), IpcError::kUnexpectedMessage);

    server_thread.join();
}

TEST(Session, AbruptServerClose) {
    auto [client_fd, server_fd] = MakeSocketPair();

    // Server closes immediately without any handshake.
    std::thread server_thread([server_fd]() { ::close(server_fd); });

    Conn client_conn(client_fd);
    auto session = ClientSession::Dial(std::move(client_conn), ClientConfig{});

    ASSERT_FALSE(session.has_value());
    // Could be kTransportClosed (read EOF) or
    // kTransportError (write EPIPE/broken pipe); both
    // acceptable. Anything else is a state-machine bug.
    EXPECT_TRUE(session.error() == IpcError::kTransportClosed ||
                session.error() == IpcError::kTransportError);

    server_thread.join();
}

}  // namespace
}  // namespace mlfuzzz3::ipc
