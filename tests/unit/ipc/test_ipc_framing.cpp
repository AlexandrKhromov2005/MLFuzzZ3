#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "framing.h"

namespace mlfuzzz3::ipc {
namespace {

TEST(Framing, EncodeDecodeRoundTrip) {
    v1::Envelope orig;
    auto* init = orig.mutable_init_request();
    init->set_protocol_version_major(1);
    init->set_protocol_version_minor(0);
    init->set_run_timeout_ms(500);

    auto encoded = EncodeFrame(orig);
    ASSERT_TRUE(encoded.has_value()) << "EncodeFrame failed: " << static_cast<int>(encoded.error());

    auto decoded = DecodeFrame(*encoded);
    ASSERT_TRUE(decoded.has_value()) << "DecodeFrame failed: " << static_cast<int>(decoded.error());

    ASSERT_TRUE(decoded->has_init_request());
    EXPECT_EQ(decoded->init_request().protocol_version_major(), 1U);
    EXPECT_EQ(decoded->init_request().protocol_version_minor(), 0U);
    EXPECT_EQ(decoded->init_request().run_timeout_ms(), 500U);
}

TEST(Framing, EncodeDecodeOneofVariant) {
    v1::Envelope orig;
    auto* run = orig.mutable_run_request();
    run->set_input("hello");

    auto encoded = EncodeFrame(orig);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = DecodeFrame(*encoded);
    ASSERT_TRUE(decoded.has_value());

    ASSERT_TRUE(decoded->has_run_request());
    EXPECT_EQ(decoded->run_request().input(), "hello");
}

TEST(Framing, DecodeShortBuffer) {
    // Buffer smaller than 4-byte header.
    std::array<std::uint8_t, 2> bad{0x01, 0x02};
    auto decoded = DecodeFrame(bad);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), FramingError::kShortRead);
}

TEST(Framing, DecodeShortBody) {
    // Header declares 100 bytes, but body only has 5.
    std::vector<std::uint8_t> bad = {
        100,  0,    0,    0,           // length = 100 (LE)
        0xde, 0xad, 0xbe, 0xef, 0x00,  // 5 bytes of body
    };
    auto decoded = DecodeFrame(bad);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), FramingError::kShortRead);
}

TEST(Framing, DecodeLengthTooBig) {
    // Length prefix = 0xFFFFFFFF (~4 GiB), should reject
    // without allocating.
    std::array<std::uint8_t, 4> bad{0xFF, 0xFF, 0xFF, 0xFF};
    auto decoded = DecodeFrame(bad);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), FramingError::kLengthTooBig);
}

TEST(Framing, EncodeOversized) {
    // Synthetic Envelope with a huge input: RunRequest.input is
    // bytes, protobuf serializes it approximately 1:1 + small
    // tag overhead. A 2 MiB input will exceed kMaxFrameSize.
    v1::Envelope orig;
    auto* run = orig.mutable_run_request();
    run->set_input(std::string(2 * kMaxFrameSize, '\0'));

    auto encoded = EncodeFrame(orig);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error(), FramingError::kLengthTooBig);
}

TEST(Framing, LittleEndianLengthPrefix) {
    // Explicit check: encoded length of a tiny message must be
    // written little-endian. Build a minimal Envelope and verify
    // the first 4 bytes of the encoded frame match the body size.
    v1::Envelope orig;
    auto* run = orig.mutable_run_request();
    run->set_input("hi");  // body_size should be small

    auto encoded = EncodeFrame(orig);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GE(encoded->size(), 4U);

    const std::uint32_t declared = static_cast<std::uint32_t>((*encoded)[0]) |
                                   (static_cast<std::uint32_t>((*encoded)[1]) << 8) |
                                   (static_cast<std::uint32_t>((*encoded)[2]) << 16) |
                                   (static_cast<std::uint32_t>((*encoded)[3]) << 24);

    EXPECT_EQ(declared + 4U, encoded->size());
}

}  // namespace
}  // namespace mlfuzzz3::ipc
