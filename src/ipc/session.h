#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <tl/expected.hpp>
#include <vector>

#include "framing.h"
#include "ipc.pb.h"
#include "unique_fd.h"

namespace mlfuzzz3::ipc {

// Protocol version this implementation speaks (ADR 0004).
inline constexpr std::uint32_t kProtocolVersionMajor = 1;
inline constexpr std::uint32_t kProtocolVersionMinor = 0;

// Error kinds for the IPC session layer. Framing-level errors
// encountered during session operations are surfaced as
// kFraming; the underlying FramingError value is not preserved
// in the enum because callers typically log the string message
// attached separately (TODO: carry payload once we pick an
// error-with-message idiom).
//
// See ADR 0009 for error-handling policy.
enum class IpcError {
    // Transport-level failure during read or write (EIO,
    // ECONNRESET, write on closed fd, etc).
    kTransportError,

    // Peer closed the connection cleanly before or after an
    // expected message. Distinguished from kTransportError
    // because it is a normal shutdown signal, not a fault.
    kTransportClosed,

    // Framing layer rejected a message (length prefix too big,
    // short read mid-frame, malformed length, etc).
    kFraming,

    // Envelope payload does not match the expected variant
    // for the current session state (e.g. got ShutdownResponse
    // when expecting InitResponse).
    kUnexpectedMessage,

    // Protocol major version mismatch — peer and we cannot
    // interoperate. Both sides abort per ADR 0004.
    kVersionMismatch,

    // Operation called on a Conn/Session that was already
    // closed.
    kClosed,

    // Receive path expected a fd via SCM_RIGHTS but the
    // peer did not attach one. Per ADR 0015 §E, this is a
    // protocol error: the channel kind dictates whether
    // a fd is mandatory, and the receiver enforces it.
    kMissingFd,

    // Receive path got a fd it did not expect (reserved
    // for Phase 1.5 callers that distinguish channel
    // kinds requiring a fd vs. plain envelopes).
    kUnexpectedFd,
};

// Conn wraps an AF_UNIX SOCK_STREAM file descriptor and provides
// envelope-level read and write operations backed by framing
// helpers. Per ADR 0004, IPC transport is always a socket, which
// lets Conn use send() with MSG_NOSIGNAL to get EPIPE as errno
// instead of a process-fatal SIGPIPE on writes to a half-closed
// peer. Conn takes ownership of the fd passed to its constructor
// and closes it on destruction.
//
// Not thread-safe: caller must serialize access. Reading and
// writing from different threads simultaneously is undefined
// behavior for this class.
class Conn {
   public:
    explicit Conn(int fd);
    ~Conn();

    // Non-copyable, movable. Move transfers fd ownership; the
    // moved-from Conn has fd_ = -1 and is unusable.
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
    Conn(Conn&& other) noexcept;
    Conn& operator=(Conn&& other) noexcept;

    // WriteEnvelope serializes env through EncodeFrame and
    // writes the resulting bytes to fd_ in one ::write call.
    // Partial writes are retried until all bytes are sent or
    // an error occurs.
    [[nodiscard]]
    tl::expected<void, IpcError> WriteEnvelope(const v1::Envelope& env);

    // ReadEnvelope reads one length-prefixed frame from fd_
    // and parses it through DecodeFrame. Returns kTransportClosed
    // if the peer closed the connection before any bytes of the
    // next frame were received.
    [[nodiscard]]
    tl::expected<v1::Envelope, IpcError> ReadEnvelope();

    // Close shuts the underlying fd. Subsequent Read/Write
    // calls return kClosed. Idempotent.
    void Close();

    // Access the raw fd for SCM_RIGHTS operations (Task 4c)
    // or diagnostic purposes. Returns -1 after Close.
    [[nodiscard]] int fd() const {
        return fd_;
    }

    // EnvelopeWithFd carries a received envelope and its
    // associated SCM_RIGHTS file descriptor. UniqueFd owns
    // the fd: when EnvelopeWithFd goes out of scope, the
    // fd is closed via RAII unless moved out.
    struct EnvelopeWithFd {
        v1::Envelope envelope;
        UniqueFd fd;
    };

    // WriteEnvelopeWithFd marshals env, prefixes with the
    // 4-byte little-endian length, and sends the resulting
    // frame together with fd via a single sendmsg call
    // carrying SCM_RIGHTS. fd is borrowed: the caller
    // retains ownership and must keep it valid for the
    // duration of this call (per ADR 0015 §D send-side
    // semantics).
    [[nodiscard]]
    tl::expected<void, IpcError> WriteEnvelopeWithFd(const v1::Envelope& env, int fd);

    // ReadEnvelopeWithFd reads exactly one length-prefixed
    // envelope and the fd attached via SCM_RIGHTS. Returns
    // kMissingFd if no fd was attached. The returned
    // UniqueFd owns the received fd.
    //
    // Note: on protocol error after a fd was successfully
    // received (e.g. body unmarshal failure), the fd is
    // closed automatically via UniqueFd RAII. This differs
    // from Go-side semantics (which returns the fd to the
    // caller for explicit cleanup) — C++ RAII makes the
    // explicit transfer unnecessary. Net behavior is
    // identical: no leak in either language.
    [[nodiscard]]
    tl::expected<EnvelopeWithFd, IpcError> ReadEnvelopeWithFd();

    // ReadEnvelopeMaybeFd reads exactly one length-prefixed
    // envelope. If a fd was attached via SCM_RIGHTS it is
    // returned in EnvelopeWithFd::fd; otherwise
    // EnvelopeWithFd::fd is empty (UniqueFd holding -1).
    [[nodiscard]]
    tl::expected<EnvelopeWithFd, IpcError> ReadEnvelopeMaybeFd();

   private:
    int fd_;
};

// ClientConfig for the initial handshake.
struct ClientConfig {
    // Per-run timeout (milliseconds) sent to the server in
    // InitRequest. Applied uniformly to every subsequent Run.
    std::uint64_t run_timeout_ms = 0;

    // Number of ChannelAnnouncement messages to consume from
    // the server after the handshake, acking each. In Phase 1
    // this is 0 or 1 (edge only). Each announcement must
    // carry a fd attached via SCM_RIGHTS (ADR 0028 part A);
    // an announcement without a fd is a fatal protocol error.
    int expected_channels = 0;
};

// ClientSession implements the client-side of the IPC state
// machine per ADR 0004 §Connection lifecycle. Constructed via
// Dial on a pre-established Conn.
//
// Not thread-safe.
class ClientSession {
   public:
    // Dial performs InitRequest/Response and N channel
    // announcement acks on conn. On success returns a session
    // ready for Run; on failure returns IpcError and leaves
    // conn in an indeterminate state (caller should Close).
    //
    // conn is moved into the session; caller's Conn becomes
    // unusable.
    [[nodiscard]]
    static tl::expected<ClientSession, IpcError> Dial(Conn&& conn, const ClientConfig& cfg);

    // Non-copyable, movable.
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;
    ClientSession(ClientSession&&) = default;
    ClientSession& operator=(ClientSession&&) = default;
    ~ClientSession() = default;

    // Run sends one RunRequest and waits for the matching
    // RunResponse. Blocking. Not safe for concurrent calls;
    // serialize externally.
    [[nodiscard]]
    tl::expected<v1::RunResponse, IpcError> Run(std::span<const std::uint8_t> input);

    // Shutdown sends ShutdownRequest and waits for
    // ShutdownResponse. After success, the session is no
    // longer usable.
    [[nodiscard]]
    tl::expected<void, IpcError> Shutdown();

    // Close terminates the underlying connection without
    // graceful shutdown. Use in error paths; prefer Shutdown
    // for normal termination.
    void Close();

    // coverage_fd returns the raw file descriptor of the edge
    // coverage memfd received via SCM_RIGHTS during Dial. The
    // session retains ownership (closes on destruction); the
    // caller borrows the fd for read-only mmap and MUST NOT
    // close it. Returns -1 if no coverage channel was
    // announced (expected_channels == 0).
    [[nodiscard]] int coverage_fd() const noexcept {
        return coverage_fd_.get();
    }

    // branch_fd returns the raw file descriptor of the branch-value
    // memfd received via SCM_RIGHTS during Dial (ADR 0033). Ownership
    // stays with the session; BranchReader borrows the fd for a
    // read-only mmap and MUST NOT close it. Returns -1 if no branch
    // channel was announced.
    [[nodiscard]] int branch_fd() const noexcept {
        return branch_fd_.get();
    }

   private:
    // Private constructor — clients go through Dial.
    explicit ClientSession(Conn&& conn) : conn_(std::move(conn)) {}

    Conn conn_;
    // Edge-coverage memfd received via SCM_RIGHTS attached to
    // the ChannelAnnouncement during Dial. Held by the session
    // for its full lifetime; CoverageReader borrows the raw
    // fd via coverage_fd() per ADR 0028 part A. MVP uses a
    // single channel; the structure can grow to map
    // channel_id → UniqueFd without API breakage when branch /
    // thread / memory channels land.
    UniqueFd coverage_fd_;
    // Branch-value memfd received via SCM_RIGHTS attached to a
    // ChannelAnnouncement during Dial (ADR 0033). Independent of the
    // edge channel; BranchReader borrows the raw fd via branch_fd().
    UniqueFd branch_fd_;
    bool ready_ = false;
};

}  // namespace mlfuzzz3::ipc
