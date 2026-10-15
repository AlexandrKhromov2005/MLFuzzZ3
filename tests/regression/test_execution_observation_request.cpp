// SPDX-License-Identifier: MIT
// Mutation must not materialize a comparison log which no component requested.
#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <tl/expected.hpp>
#include <vector>

#include "execution.h"
#include "execution_adapter.h"
#include "ipc.pb.h"
#include "runner.h"
namespace mlfuzzz3::core {
namespace {
class ObservationRunner final : public Runner {
   public:
    tl::expected<ipc::v1::RunResponse, ipc::IpcError> Run(std::span<const std::uint8_t>) override {
        ++runs;
        ipc::v1::RunResponse response;
        response.set_status(ipc::v1::EXEC_STATUS_OK);
        return response;
    }
    std::vector<coverage::BranchReader::Record> LastBranchRecords() const override {
        ++reads;
        return {{0, 0, 8, runs, 42}};
    }
    bool has_comparison_channel() const override {
        return channel;
    }
    unsigned runs = 0;
    mutable unsigned reads = 0;
    bool channel = true;
};
TEST(ObservationRequestRegression, CandidateSkipsTraceWhilePreparationOwnsItsSnapshot) {
    ObservationRunner runner;
    composition::RunnerBackend backend(runner);
    ExecutionService service(backend, {.max_execs = 0, .max_seconds = 0}, {});
    const auto candidate = service.execute({}, RunPurpose::kCandidate, 1);
    ASSERT_TRUE(candidate);
    EXPECT_EQ(runner.reads, 0U);
    EXPECT_FALSE(candidate->comparisons_available);
    EXPECT_FALSE(candidate->comparisons_complete);
    EXPECT_TRUE(candidate->comparisons.empty());
    const auto first = service.execute({}, RunPurpose::kComparisons, 2);
    const auto second = service.execute({}, RunPurpose::kComparisons, 3);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    ASSERT_EQ(first->comparisons.size(), 1U);
    ASSERT_EQ(second->comparisons.size(), 1U);
    EXPECT_EQ(runner.reads, 2U);
    EXPECT_TRUE(first->comparisons_available);
    EXPECT_TRUE(first->comparisons_complete);
    EXPECT_EQ(first->comparisons.front().lhs, 2U);
    EXPECT_EQ(second->comparisons.front().lhs, 3U);
}
TEST(ObservationRequestRegression, MissingChannelIsDistinctFromACompleteEmptyTrace) {
    ObservationRunner runner;
    runner.channel = false;
    composition::RunnerBackend backend(runner);
    ExecutionService service(backend, {.max_execs = 0, .max_seconds = 0}, {});
    const auto result = service.execute({}, RunPurpose::kComparisons, 1);
    ASSERT_TRUE(result);
    EXPECT_EQ(runner.reads, 0U);
    EXPECT_FALSE(result->comparisons_available);
    EXPECT_FALSE(result->comparisons_complete);
}
}  // namespace
}  // namespace mlfuzzz3::core
