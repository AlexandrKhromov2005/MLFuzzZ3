#include "session.h"

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <iterator>
#include <utility>

namespace mlfuzzz3::ipc {

namespace {

// Maps FramingError into the session layer's error space.
IpcError FromFraming(FramingError fe) {
    switch (fe) {
        case FramingError::kShortRead:
            return IpcError::kTransportClosed;
        case FramingError::kLengthTooBig:
        case FramingError::kMarshalFailed:
        case FramingError::kUnmarshalFailed:
            return IpcError::kFraming;
    }
    return IpcError::kFraming;
}

// WriteAll pushes exactly n bytes from buf to fd, retrying on
// partial writes and EINTR. Returns true on success.
bool WriteAll(int fd, const std::uint8_t* buf, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        ssize_t w =
            ::send(fd, std::next(buf, static_cast<std::ptrdiff_t>(off)), n - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (w == 0) {
            return false;
        }
        off += static_cast<std::size_t>(w);
    }
    return true;
}

// ReadExact pulls exactly n bytes from fd into buf, retrying
// on partial reads and EINTR. Returns:
//   std::size_t(0) if the peer closed before any byte arrived,
//   std::size_t(k) where k < n if the peer closed mid-frame,
//   std::size_t(n) on full success,
//   std::size_t(-1) on hard error.
constexpr std::size_t kReadHardError = static_cast<std::size_t>(-1);

std::size_t ReadExact(int fd, std::uint8_t* buf, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        ssize_t r = ::read(fd, std::next(buf, static_cast<std::ptrdiff_t>(off)), n - off);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return kReadHardError;
        }
        if (r == 0) {
            return off;
        }  // EOF (possibly short)
        off += static_cast<std::size_t>(r);
    }
    return off;
}

// SendFrameWithFd sends [length-prefix | body] together with
// fd as SCM_RIGHTS over sockfd in a single sendmsg call.
// Returns kTransportError on sendmsg failure or short write.
tl::expected<void, IpcError> SendFrameWithFd(int sockfd, const std::vector<std::uint8_t>& frame,
                                             int fd) {
    struct iovec iov{};
    // POSIX iovec uses non-const iov_base, but ::sendmsg does
    // not mutate the buffer — frame stays logically const.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    iov.iov_base = const_cast<std::uint8_t*>(frame.data());
    iov.iov_len = frame.size();

    std::array<char, CMSG_SPACE(sizeof(int))> cmsgbuf{};
    cmsgbuf.fill(0);

    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.data();
    msg.msg_controllen = cmsgbuf.size();

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ssize_t n = ::sendmsg(sockfd, &msg, MSG_NOSIGNAL);
    if (n < 0) {
        return tl::unexpected(IpcError::kTransportError);
    }
    if (static_cast<std::size_t>(n) != frame.size()) {
        return tl::unexpected(IpcError::kTransportError);
    }
    return {};
}

// RecvBytesWithCmsg performs a single recvmsg, writing the
// bytes read into `out` (resized to the actual count) and any
// received fd into `out_fd` (-1 if no cmsg). If multiple fds
// arrive in a single cmsg (protocol violation per ADR 0015 §B,
// at most one fd per envelope), all are closed defensively
// and kFraming is returned.
tl::expected<void, IpcError> RecvBytesWithCmsg(int sockfd, std::vector<std::uint8_t>& out,
                                               int& out_fd, std::size_t want) {
    out.assign(want, 0);
    out_fd = -1;

    struct iovec iov{};
    iov.iov_base = out.data();
    iov.iov_len = want;

    std::array<char, CMSG_SPACE(sizeof(int))> cmsgbuf{};
    cmsgbuf.fill(0);

    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.data();
    msg.msg_controllen = cmsgbuf.size();

    ssize_t n = ::recvmsg(sockfd, &msg, 0);
    if (n < 0) {
        return tl::unexpected(IpcError::kTransportError);
    }
    if (n == 0) {
        return tl::unexpected(IpcError::kTransportClosed);
    }
    if (std::cmp_not_equal(n, want)) {
        out.resize(static_cast<std::size_t>(n));
    }

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        std::size_t fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        if (fd_count == 0) {
            continue;
        }
        if (fd_count > 1) {
            // CMSG_DATA returns unsigned char*; reinterpret_cast
            // to int* is the only standard way to read fds out
            // of the cmsg payload. Defensive close of all fds
            // before returning kFraming.
            // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
            const int* fds = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
            for (std::size_t i = 0; i < fd_count; ++i) {
                ::close(fds[i]);
            }
            // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
            if (out_fd != -1) {
                ::close(out_fd);
                out_fd = -1;
            }
            return tl::unexpected(IpcError::kFraming);
        }
        int fd = -1;
        std::memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
        if (out_fd != -1) {
            ::close(fd);
            ::close(out_fd);
            out_fd = -1;
            return tl::unexpected(IpcError::kFraming);
        }
        out_fd = fd;
    }

    return {};
}

}  // namespace

// ---- Conn ----

Conn::Conn(int fd) : fd_(fd) {}

Conn::~Conn() {
    Close();
}

Conn::Conn(Conn&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

Conn& Conn::operator=(Conn&& other) noexcept {
    if (this != &other) {
        Close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

void Conn::Close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

// NOLINTBEGIN(readability-make-member-function-const)
// Side effect via ::write on fd_ is not visible to
// clang-tidy's const analysis; method semantically
// mutates peer state.
tl::expected<void, IpcError> Conn::WriteEnvelope(const v1::Envelope& env) {
    if (fd_ < 0) {
        return tl::unexpected(IpcError::kClosed);
    }
    auto encoded = EncodeFrame(env);
    if (!encoded.has_value()) {
        return tl::unexpected(FromFraming(encoded.error()));
    }
    if (!WriteAll(fd_, encoded->data(), encoded->size())) {
        return tl::unexpected(IpcError::kTransportError);
    }
    return {};
}
// NOLINTEND(readability-make-member-function-const)

// NOLINTBEGIN(readability-make-member-function-const)
// Side effect via ::read on fd_ is not visible to
// clang-tidy's const analysis; method semantically
// mutates peer state.
tl::expected<v1::Envelope, IpcError> Conn::ReadEnvelope() {
    if (fd_ < 0) {
        return tl::unexpected(IpcError::kClosed);
    }

    // Read 4-byte length prefix.
    std::array<std::uint8_t, 4> header{};
    std::size_t got = ReadExact(fd_, header.data(), header.size());
    if (got == kReadHardError) {
        return tl::unexpected(IpcError::kTransportError);
    }
    if (got == 0) {
        return tl::unexpected(IpcError::kTransportClosed);
    }
    if (got < 4) {
        // Peer closed mid-header.
        return tl::unexpected(IpcError::kTransportClosed);
    }

    // Decode length.
    const std::uint32_t length = static_cast<std::uint32_t>(header[0]) |
                                 (static_cast<std::uint32_t>(header[1]) << 8) |
                                 (static_cast<std::uint32_t>(header[2]) << 16) |
                                 (static_cast<std::uint32_t>(header[3]) << 24);

    if (length > kMaxFrameSize) {
        return tl::unexpected(IpcError::kFraming);
    }

    // Read body.
    std::vector<std::uint8_t> frame(4 + length);
    std::memcpy(frame.data(), header.data(), header.size());
    if (length > 0) {
        got = ReadExact(fd_, std::next(frame.data(), 4), length);
        if (got == kReadHardError) {
            return tl::unexpected(IpcError::kTransportError);
        }
        if (got < length) {
            return tl::unexpected(IpcError::kTransportClosed);
        }
    }

    // Delegate parsing to DecodeFrame (includes the 4-byte
    // prefix by contract — we hand it the full frame).
    auto decoded = DecodeFrame(std::span<const std::uint8_t>(frame.data(), frame.size()));
    if (!decoded.has_value()) {
        return tl::unexpected(FromFraming(decoded.error()));
    }
    return std::move(*decoded);
}
// NOLINTEND(readability-make-member-function-const)

// NOLINTBEGIN(readability-make-member-function-const)
// Side effect via ::sendmsg on fd_ is not visible to
// clang-tidy's const analysis; method semantically
// mutates peer state.
tl::expected<void, IpcError> Conn::WriteEnvelopeWithFd(const v1::Envelope& env, int fd) {
    if (fd_ < 0) {
        return tl::unexpected(IpcError::kClosed);
    }
    std::string body;
    if (!env.SerializeToString(&body)) {
        return tl::unexpected(IpcError::kFraming);
    }
    if (body.size() > kMaxFrameSize) {
        return tl::unexpected(IpcError::kFraming);
    }

    std::vector<std::uint8_t> frame(4 + body.size());
    const auto len = static_cast<std::uint32_t>(body.size());
    frame[0] = static_cast<std::uint8_t>(len);
    frame[1] = static_cast<std::uint8_t>(len >> 8);
    frame[2] = static_cast<std::uint8_t>(len >> 16);
    frame[3] = static_cast<std::uint8_t>(len >> 24);
    std::memcpy(std::next(frame.data(), 4), body.data(), body.size());

    return SendFrameWithFd(fd_, frame, fd);
}
// NOLINTEND(readability-make-member-function-const)

// NOLINTBEGIN(readability-make-member-function-const)
// Side effect via ::recvmsg on fd_ is not visible to
// clang-tidy's const analysis; method semantically
// mutates peer state.
tl::expected<Conn::EnvelopeWithFd, IpcError> Conn::ReadEnvelopeWithFd() {
    auto result = ReadEnvelopeMaybeFd();
    if (!result.has_value()) {
        return tl::unexpected(result.error());
    }
    if (!result->fd) {
        return tl::unexpected(IpcError::kMissingFd);
    }
    return std::move(*result);
}
// NOLINTEND(readability-make-member-function-const)

// NOLINTBEGIN(readability-make-member-function-const)
// Side effect via ::recvmsg on fd_ is not visible to
// clang-tidy's const analysis; method semantically
// mutates peer state.
tl::expected<Conn::EnvelopeWithFd, IpcError> Conn::ReadEnvelopeMaybeFd() {
    if (fd_ < 0) {
        return tl::unexpected(IpcError::kClosed);
    }

    // Receive the 4-byte length prefix together with any
    // SCM_RIGHTS cmsg. SCM_RIGHTS, if present, arrives with
    // the very first recvmsg call on a new envelope — the
    // body that follows is read via plain ::read.
    std::vector<std::uint8_t> prefix;
    int received_fd = -1;
    if (auto r = RecvBytesWithCmsg(fd_, prefix, received_fd, 4); !r.has_value()) {
        if (received_fd >= 0) {
            ::close(received_fd);
        }
        return tl::unexpected(r.error());
    }
    if (prefix.size() != 4) {
        // Short read on the prefix — peer closed mid-header
        // (recvmsg returned fewer bytes than requested).
        if (received_fd >= 0) {
            ::close(received_fd);
        }
        return tl::unexpected(IpcError::kTransportClosed);
    }

    const std::uint32_t body_len = static_cast<std::uint32_t>(prefix[0]) |
                                   (static_cast<std::uint32_t>(prefix[1]) << 8) |
                                   (static_cast<std::uint32_t>(prefix[2]) << 16) |
                                   (static_cast<std::uint32_t>(prefix[3]) << 24);

    if (body_len > kMaxFrameSize) {
        if (received_fd >= 0) {
            ::close(received_fd);
        }
        return tl::unexpected(IpcError::kFraming);
    }

    // Read body via plain ::read (no cmsg expected here —
    // SCM_RIGHTS arrives only with the prefix syscall).
    std::vector<std::uint8_t> body(body_len);
    if (body_len > 0) {
        std::size_t got = ReadExact(fd_, body.data(), body_len);
        if (got == kReadHardError) {
            if (received_fd >= 0) {
                ::close(received_fd);
            }
            return tl::unexpected(IpcError::kTransportError);
        }
        if (got < body_len) {
            if (received_fd >= 0) {
                ::close(received_fd);
            }
            return tl::unexpected(IpcError::kTransportClosed);
        }
    }

    EnvelopeWithFd ewf;
    // Wrap received_fd into UniqueFd before parsing so any
    // early return from here closes the fd via RAII.
    ewf.fd = UniqueFd(received_fd);
    if (!ewf.envelope.ParseFromArray(body.data(), static_cast<int>(body.size()))) {
        return tl::unexpected(IpcError::kFraming);
    }
    return ewf;
}
// NOLINTEND(readability-make-member-function-const)

// ---- ClientSession ----

tl::expected<ClientSession, IpcError> ClientSession::Dial(Conn&& conn, const ClientConfig& cfg) {
    ClientSession session{std::move(conn)};

    // Send InitRequest.
    v1::Envelope init_env;
    auto* init_req = init_env.mutable_init_request();
    init_req->set_protocol_version_major(kProtocolVersionMajor);
    init_req->set_protocol_version_minor(kProtocolVersionMinor);
    init_req->set_run_timeout_ms(cfg.run_timeout_ms);

    if (auto w = session.conn_.WriteEnvelope(init_env); !w) {
        return tl::unexpected(w.error());
    }

    // Receive InitResponse.
    auto resp = session.conn_.ReadEnvelope();
    if (!resp.has_value()) {
        return tl::unexpected(resp.error());
    }
    if (!resp->has_init_response()) {
        return tl::unexpected(IpcError::kUnexpectedMessage);
    }
    if (resp->init_response().protocol_version_major() != kProtocolVersionMajor) {
        return tl::unexpected(IpcError::kVersionMismatch);
    }

    // Consume N channel announcements, ack each. Each
    // announcement carries the channel memfd attached via
    // SCM_RIGHTS (ADR 0028 part A); the receive path returns
    // kMissingFd if the peer did not attach one, which we
    // surface unchanged as a fatal handshake error.
    for (int i = 0; i < cfg.expected_channels; ++i) {
        auto ann = session.conn_.ReadEnvelopeWithFd();
        if (!ann.has_value()) {
            return tl::unexpected(ann.error());
        }
        if (!ann->envelope.has_channel_announcement()) {
            return tl::unexpected(IpcError::kUnexpectedMessage);
        }
        // Route the attached fd by descriptor variant: edge → the
        // coverage memfd, branch → the branch-value memfd (ADR 0033).
        // An announcement with neither variant set is a protocol
        // error. The two channels are independent; each fd is held by
        // the session and borrowed read-only by its reader.
        const auto& ca = ann->envelope.channel_announcement();
        if (ca.has_edge()) {
            session.coverage_fd_ = std::move(ann->fd);
        } else if (ca.has_branch()) {
            session.branch_fd_ = std::move(ann->fd);
        } else {
            return tl::unexpected(IpcError::kUnexpectedMessage);
        }

        v1::Envelope ack_env;
        ack_env.mutable_channel_announcement_ack();
        if (auto w = session.conn_.WriteEnvelope(ack_env); !w) {
            return tl::unexpected(w.error());
        }
    }

    session.ready_ = true;
    return session;
}

tl::expected<v1::RunResponse, IpcError> ClientSession::Run(std::span<const std::uint8_t> input) {
    if (!ready_) {
        return tl::unexpected(IpcError::kClosed);
    }

    v1::Envelope env;
    auto* rr = env.mutable_run_request();
    rr->set_input(input.data(), input.size());

    if (auto w = conn_.WriteEnvelope(env); !w) {
        return tl::unexpected(w.error());
    }

    auto resp = conn_.ReadEnvelope();
    if (!resp.has_value()) {
        return tl::unexpected(resp.error());
    }
    if (!resp->has_run_response()) {
        return tl::unexpected(IpcError::kUnexpectedMessage);
    }
    return std::move(*resp->mutable_run_response());
}

tl::expected<void, IpcError> ClientSession::Shutdown() {
    if (!ready_) {
        return tl::unexpected(IpcError::kClosed);
    }

    v1::Envelope env;
    env.mutable_shutdown_request();

    if (auto w = conn_.WriteEnvelope(env); !w) {
        return tl::unexpected(w.error());
    }

    auto resp = conn_.ReadEnvelope();
    if (!resp.has_value()) {
        return tl::unexpected(resp.error());
    }
    if (!resp->has_shutdown_response()) {
        return tl::unexpected(IpcError::kUnexpectedMessage);
    }
    ready_ = false;
    return {};
}

void ClientSession::Close() {
    ready_ = false;
    conn_.Close();
}

}  // namespace mlfuzzz3::ipc
