#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <tl/expected.hpp>
#include <vector>

#include "ipc.pb.h"

namespace mlfuzzz3::ipc {

// Hard upper bound on a single framed protobuf message per ADR 0004.
// Frames with a length prefix exceeding this value are treated as
// a corrupted stream.
inline constexpr std::size_t kMaxFrameSize = 1UL << 20;  // 1 MiB

// Error kinds for framing operations. See ADR 0009 for C++ error
// handling policy (tl::expected + module-local enum class).
enum class FramingError {
    // Input buffer shorter than expected (truncated frame or
    // incomplete length prefix).
    kShortRead,

    // Length prefix decodes to a value > kMaxFrameSize.
    kLengthTooBig,

    // protobuf::SerializeToArray failed (should not happen for
    // well-formed Envelope but surfaced for completeness).
    kMarshalFailed,

    // protobuf::ParseFromArray failed on the body bytes.
    kUnmarshalFailed,
};

// Encode env as [4-byte LE length][body]. The returned vector is
// ready to be written to a socket in one call. Bodies exceeding
// kMaxFrameSize return FramingError::kLengthTooBig without
// serialization side-effects.
[[nodiscard]]
tl::expected<std::vector<std::uint8_t>, FramingError> EncodeFrame(const v1::Envelope& env);

// Parse a length-prefixed frame from [frame.begin(), frame.end())
// into an Envelope.
//
// Caller is responsible for providing exactly one complete frame,
// including the 4-byte length prefix. Partial frames return
// FramingError::kShortRead. Corrupted length prefixes (decoded
// value > kMaxFrameSize, or value + 4 != frame.size()) return
// FramingError::kLengthTooBig or kShortRead respectively.
//
// DecodeFrame is a pure function; it does not perform I/O.
// Reading frames from a stream socket is the caller's job (will
// be in a future IPC client module, Phase 1 Task 4+).
[[nodiscard]]
tl::expected<v1::Envelope, FramingError> DecodeFrame(std::span<const std::uint8_t> frame);

}  // namespace mlfuzzz3::ipc
