#include <gtest/gtest.h>

#include "ipc.pb.h"

namespace {

// Round-trip: serialize and parse an Envelope carrying InitRequest.
// Verifies generated code roundtrips primitive fields.
TEST(ProtoSmoke, InitRequestRoundTrip) {
    mlfuzzz3::ipc::v1::Envelope orig;
    auto* init = orig.mutable_init_request();
    init->set_protocol_version_major(1);
    init->set_protocol_version_minor(0);
    init->set_run_timeout_ms(500);

    std::string bytes;
    ASSERT_TRUE(orig.SerializeToString(&bytes));

    mlfuzzz3::ipc::v1::Envelope got;
    ASSERT_TRUE(got.ParseFromString(bytes));
    ASSERT_TRUE(got.has_init_request());
    EXPECT_EQ(got.init_request().protocol_version_major(), 1u);
    EXPECT_EQ(got.init_request().protocol_version_minor(), 0u);
    EXPECT_EQ(got.init_request().run_timeout_ms(), 500u);
}

// Envelope oneof dispatch: serialize RunRequest variant, ensure
// the right alternative is present after parsing.
TEST(ProtoSmoke, EnvelopeOneofDispatch) {
    mlfuzzz3::ipc::v1::Envelope orig;
    auto* run = orig.mutable_run_request();
    run->set_input("test-input");

    std::string bytes;
    ASSERT_TRUE(orig.SerializeToString(&bytes));

    mlfuzzz3::ipc::v1::Envelope got;
    ASSERT_TRUE(got.ParseFromString(bytes));
    ASSERT_TRUE(got.has_run_request());
    EXPECT_FALSE(got.has_init_request());
    EXPECT_EQ(got.run_request().input(), "test-input");
}

// ExecStatus numeric values lock — wire-level invariant.
// Any renumbering silently breaks compat with deployed readers.
TEST(ProtoSmoke, ExecStatusValues) {
    using mlfuzzz3::ipc::v1::ExecStatus;
    EXPECT_EQ(ExecStatus::EXEC_STATUS_UNSPECIFIED, 0);
    EXPECT_EQ(ExecStatus::EXEC_STATUS_OK, 1);
    EXPECT_EQ(ExecStatus::EXEC_STATUS_CRASH, 2);
    EXPECT_EQ(ExecStatus::EXEC_STATUS_HANG, 3);
    EXPECT_EQ(ExecStatus::EXEC_STATUS_IPC_ERROR, 4);
}

}  // namespace
