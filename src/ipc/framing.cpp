#include "framing.h"

#include <array>
#include <cstring>
#include <iterator>
#include <span>

namespace mlfuzzz3::ipc {

namespace {

// Little-endian 32-bit length prefix helpers. We implement them
// explicitly rather than relying on htonl/ntohl to make the
// byte-order invariant (ADR 0004) self-documenting and
// independent of host endianness (we support only little-endian
// hosts in practice, but explicit is safer).

void WriteLengthPrefix(std::span<std::uint8_t, 4> out, std::uint32_t length) {
    out[0] = static_cast<std::uint8_t>(length & 0xFF);
    out[1] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
    out[2] = static_cast<std::uint8_t>((length >> 16) & 0xFF);
    out[3] = static_cast<std::uint8_t>((length >> 24) & 0xFF);
}

std::uint32_t ReadLengthPrefix(std::span<const std::uint8_t, 4> in) {
    return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8) |
           (static_cast<std::uint32_t>(in[2]) << 16) | (static_cast<std::uint32_t>(in[3]) << 24);
}

}  // namespace

tl::expected<std::vector<std::uint8_t>, FramingError> EncodeFrame(const v1::Envelope& env) {
    const std::size_t body_size = env.ByteSizeLong();
    if (body_size > kMaxFrameSize) {
        return tl::unexpected(FramingError::kLengthTooBig);
    }

    std::vector<std::uint8_t> frame(4 + body_size);

    std::array<std::uint8_t, 4> header{};
    WriteLengthPrefix(header, static_cast<std::uint32_t>(body_size));
    std::memcpy(frame.data(), header.data(), header.size());

    if (!env.SerializeToArray(std::next(frame.data(), 4), static_cast<int>(body_size))) {
        return tl::unexpected(FramingError::kMarshalFailed);
    }

    return frame;
}

tl::expected<v1::Envelope, FramingError> DecodeFrame(std::span<const std::uint8_t> frame) {
    if (frame.size() < 4) {
        return tl::unexpected(FramingError::kShortRead);
    }

    const std::uint32_t length = ReadLengthPrefix(frame.first<4>());
    if (length > kMaxFrameSize) {
        return tl::unexpected(FramingError::kLengthTooBig);
    }
    if (frame.size() < 4UL + length) {
        return tl::unexpected(FramingError::kShortRead);
    }

    v1::Envelope env;
    if (!env.ParseFromArray(std::next(frame.data(), 4), static_cast<int>(length))) {
        return tl::unexpected(FramingError::kUnmarshalFailed);
    }

    return env;
}

}  // namespace mlfuzzz3::ipc
