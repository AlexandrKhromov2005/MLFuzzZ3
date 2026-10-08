#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "branch_reader.h"
#include "fake_runner.h"
#include "ipc.pb.h"

#ifdef MLFUZZZ3_WITH_CONCOLIC
#include <optional>
#include <span>

#include "concolic.h"
#include "fuzz_input.h"
#endif

// Unit coverage for the ADR 0036 Runner extension (LastBranchRecords) via
// the in-memory FakeRunner — proves the accessor's "OK-run only" semantics
// without a live exec-server, and (under FUZZER_BUILD_Z3) that the canned
// records the fake exposes are canonically what fuzzer::concolic consumes.

namespace mlfuzzz3::core::testing {
namespace {

// fuzzer_rt_cmp_kind values (ADR 0033).
enum : std::uint8_t { kEq = 0, kUlt = 2, kUgt = 4 };

// The real cov_xfield branch log for seed x=0x20000000, y=0x30000000
// (captured in ADR 0035 recon): C1 x>K, C2 y>K, C3 x<y, C4 (x+y)==5.
std::vector<coverage::BranchReader::Record> XfieldRecords() {
    return {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kUlt, 32, 0x20000000ULL, 0x30000000ULL},
        {3, kEq, 32, 0x50000000ULL, 0x00000005ULL},
    };
}

bool SameRecord(const coverage::BranchReader::Record& a, const coverage::BranchReader::Record& b) {
    return a.site_id == b.site_id && a.predicate == b.predicate && a.bit_width == b.bit_width &&
           a.lhs == b.lhs && a.rhs == b.rhs;
}

TEST(RunnerLastBranchRecords, ReturnsCannedRecordsAfterOkRun) {
    FakeRunner runner;
    const std::vector<coverage::BranchReader::Record> records = XfieldRecords();
    runner.set_branch_records(records);
    runner.set_script({FakeRunner::MakeOk(0)});

    const std::vector<std::uint8_t> input = {0x00};
    const auto reply = runner.Run(input);
    ASSERT_TRUE(reply.has_value());

    const auto got = runner.LastBranchRecords();
    ASSERT_EQ(got.size(), records.size());
    for (std::size_t i = 0; i < records.size(); ++i) {
        EXPECT_TRUE(SameRecord(got[i], records[i])) << "record " << i;
    }
}

TEST(RunnerLastBranchRecords, EmptyBeforeAnyRun) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    EXPECT_TRUE(runner.LastBranchRecords().empty());
}

TEST(RunnerLastBranchRecords, EmptyAfterNonOkRun) {
    const std::vector<std::uint8_t> input = {0x00};
    for (const auto status :
         {ipc::v1::EXEC_STATUS_CRASH, ipc::v1::EXEC_STATUS_HANG, ipc::v1::EXEC_STATUS_IPC_ERROR}) {
        FakeRunner runner;
        runner.set_branch_records(XfieldRecords());
        runner.set_script({FakeRunner::MakeStatus(status)});
        (void)runner.Run(input);
        EXPECT_TRUE(runner.LastBranchRecords().empty())
            << "status " << static_cast<int>(status) << " should expose no records";
    }
}

TEST(RunnerLastBranchRecords, EmptyAfterTransportError) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeTransportError()});
    const std::vector<std::uint8_t> input = {0x00};
    const auto reply = runner.Run(input);
    EXPECT_FALSE(reply.has_value());
    EXPECT_TRUE(runner.LastBranchRecords().empty());
}

#ifdef MLFUZZZ3_WITH_CONCOLIC
// The records the fake exposes are canonically what the campaign loop will
// hand to concolic (Session B): feeding LastBranchRecords() of an OK run
// into SolveForCandidate yields a candidate satisfying the cross-field
// crash system.
TEST(RunnerLastBranchRecords, CannedRecordsFeedConcolic) {
    FakeRunner runner;
    runner.set_branch_records(XfieldRecords());
    runner.set_script({FakeRunner::MakeOk(0)});

    // Seed bytes: x=0x20000000 @0, y=0x30000000 @4 (LE).
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    const auto reply = runner.Run(seed);
    ASSERT_TRUE(reply.has_value());

    const auto records = runner.LastBranchRecords();
    const std::optional<mutation::FuzzInput> candidate =
        concolic::SolveForCandidate(std::span<const std::uint8_t>{seed}, records, 5000);
    ASSERT_TRUE(candidate.has_value());
    ASSERT_GE(candidate->size(), 8U);

    const auto read_u32 = [](const std::uint8_t* p) {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    };
    const std::uint32_t x = read_u32(candidate->data());
    const std::uint32_t y = read_u32(candidate->data() + 4);
    EXPECT_GT(x, 0x10000000U);
    EXPECT_GT(y, 0x10000000U);
    EXPECT_LT(x, y);
    EXPECT_EQ(static_cast<std::uint32_t>(x + y), 5U);
}
#endif  // MLFUZZZ3_WITH_CONCOLIC

}  // namespace
}  // namespace mlfuzzz3::core::testing
