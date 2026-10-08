#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "metrics.h"

namespace mlfuzzz3::core {
namespace {

std::vector<std::string> ReadLines(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    return lines;
}

// Structural JSON-object check. A full JSON parser is intentionally not
// pulled in (no new dependency, project conventions); the emitter writes a
// flat object so verifying braces + the presence of every key is a
// sufficient validity gate for the MVP.
bool HasKey(const std::string& line, const std::string& key) {
    return line.find("\"" + key + "\":") != std::string::npos;
}

MetricsSnapshot SampleSnapshot() {
    return MetricsSnapshot{.execs = 1234,
                           .execs_per_sec = 567.5,
                           .corpus_size = 7,
                           .edges = 89,
                           .crashes = 2,
                           .det_execs = 30,
                           .havoc_execs = 1204,
                           .elapsed = 3.25};
}

class MetricsTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        dir_ = std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_metrics_test" /
               (std::string(info->test_suite_name()) + "_" + info->name());
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
        std::filesystem::create_directories(dir_, ec);
        path_ = dir_ / "metrics.jsonl";
    }
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }
    std::filesystem::path dir_;
    std::filesystem::path path_;
};

TEST_F(MetricsTest, EmitWritesValidJsonObjectWithAllFields) {
    auto emitter = MetricsEmitter::Create(path_, "20260603-abcdef0-deadbeef");
    ASSERT_TRUE(emitter.has_value());
    ASSERT_TRUE(emitter->Emit(SampleSnapshot()).has_value());

    const std::vector<std::string> lines = ReadLines(path_);
    ASSERT_EQ(lines.size(), 1U);
    const std::string& line = lines[0];

    ASSERT_FALSE(line.empty());
    EXPECT_EQ(line.front(), '{');
    EXPECT_EQ(line.back(), '}');
    EXPECT_TRUE(HasKey(line, "run_id"));
    EXPECT_TRUE(HasKey(line, "execs"));
    EXPECT_TRUE(HasKey(line, "execs_per_sec"));
    EXPECT_TRUE(HasKey(line, "corpus_size"));
    EXPECT_TRUE(HasKey(line, "edges"));
    EXPECT_TRUE(HasKey(line, "crashes"));
    EXPECT_TRUE(HasKey(line, "det_execs"));
    EXPECT_TRUE(HasKey(line, "havoc_execs"));
    EXPECT_TRUE(HasKey(line, "elapsed"));
    EXPECT_NE(line.find("\"run_id\":\"20260603-abcdef0-deadbeef\""), std::string::npos);
    EXPECT_NE(line.find("\"execs\":1234"), std::string::npos);
    EXPECT_NE(line.find("\"det_execs\":30"), std::string::npos);
    EXPECT_NE(line.find("\"havoc_execs\":1204"), std::string::npos);
}

// ADR 0039: concolic_time_ms_total (solve-only) and concolic_seed_run_ms_total
// (seed-run) are distinct fields — both emitted, each carrying its own value,
// with the new field between concolic_budget_skips and elapsed.
TEST_F(MetricsTest, ConcolicTimeFieldsAreDistinctAndOrdered) {
    auto emitter = MetricsEmitter::Create(path_, "run-0039");
    ASSERT_TRUE(emitter.has_value());
    MetricsSnapshot snapshot = SampleSnapshot();
    snapshot.concolic_time_ms_total = 111;
    snapshot.concolic_seed_run_ms_total = 222;
    ASSERT_TRUE(emitter->Emit(snapshot).has_value());

    const std::vector<std::string> lines = ReadLines(path_);
    ASSERT_EQ(lines.size(), 1U);
    const std::string& line = lines[0];

    EXPECT_NE(line.find("\"concolic_time_ms_total\":111"), std::string::npos);
    EXPECT_NE(line.find("\"concolic_seed_run_ms_total\":222"), std::string::npos);
    const std::size_t budget_pos = line.find("\"concolic_budget_skips\":");
    const std::size_t seed_run_pos = line.find("\"concolic_seed_run_ms_total\":");
    const std::size_t elapsed_pos = line.find("\"elapsed\":");
    ASSERT_NE(budget_pos, std::string::npos);
    ASSERT_NE(seed_run_pos, std::string::npos);
    ASSERT_NE(elapsed_pos, std::string::npos);
    EXPECT_LT(budget_pos, seed_run_pos);
    EXPECT_LT(seed_run_pos, elapsed_pos);
}

// task-021: the fruitless-call reason split is emitted as two new keys while
// the legacy concolic_no_candidate keeps its own key and its old meaning (the
// sum of the two) — a metrics.jsonl reader written before the split keeps
// parsing runs written after it.
TEST_F(MetricsTest, FruitlessReasonSplitIsEmittedAlongsideLegacyField) {
    auto emitter = MetricsEmitter::Create(path_, "run-0021");
    ASSERT_TRUE(emitter.has_value());
    MetricsSnapshot snapshot = SampleSnapshot();
    snapshot.concolic_no_binding = 5;
    snapshot.concolic_error = 3;
    snapshot.concolic_no_candidate = snapshot.concolic_no_binding + snapshot.concolic_error;
    ASSERT_TRUE(emitter->Emit(snapshot).has_value());

    const std::vector<std::string> lines = ReadLines(path_);
    ASSERT_EQ(lines.size(), 1U);
    const std::string& line = lines[0];

    EXPECT_TRUE(HasKey(line, "concolic_no_candidate"));
    EXPECT_TRUE(HasKey(line, "concolic_no_binding"));
    EXPECT_TRUE(HasKey(line, "concolic_error"));
    EXPECT_NE(line.find("\"concolic_no_binding\":5"), std::string::npos);
    EXPECT_NE(line.find("\"concolic_error\":3"), std::string::npos);
    EXPECT_NE(line.find("\"concolic_no_candidate\":8"), std::string::npos);
    // Neighbouring keys are untouched by the insertion.
    EXPECT_TRUE(HasKey(line, "concolic_timeout"));
    EXPECT_TRUE(HasKey(line, "concolic_time_ms_total"));
}

TEST_F(MetricsTest, AppendDoesNotOverwrite) {
    auto emitter = MetricsEmitter::Create(path_, "run-1");
    ASSERT_TRUE(emitter.has_value());

    ASSERT_TRUE(emitter->Emit(SampleSnapshot()).has_value());
    const std::string first = ReadLines(path_).at(0);

    MetricsSnapshot second = SampleSnapshot();
    second.execs = 9999;
    ASSERT_TRUE(emitter->Emit(second).has_value());

    const std::vector<std::string> lines = ReadLines(path_);
    ASSERT_EQ(lines.size(), 2U);
    EXPECT_EQ(lines[0], first);  // first record untouched by the append
    EXPECT_NE(lines[1].find("\"execs\":9999"), std::string::npos);
}

TEST_F(MetricsTest, SecondEmitterAppendsToExistingFile) {
    {
        auto a = MetricsEmitter::Create(path_, "run-a");
        ASSERT_TRUE(a.has_value());
        ASSERT_TRUE(a->Emit(SampleSnapshot()).has_value());
    }
    {
        auto b = MetricsEmitter::Create(path_, "run-b");
        ASSERT_TRUE(b.has_value());
        ASSERT_TRUE(b->Emit(SampleSnapshot()).has_value());
    }
    EXPECT_EQ(ReadLines(path_).size(), 2U);
}

TEST_F(MetricsTest, RunIdQuotesAreEscaped) {
    auto emitter = MetricsEmitter::Create(path_, "weird\"id");
    ASSERT_TRUE(emitter.has_value());
    ASSERT_TRUE(emitter->Emit(SampleSnapshot()).has_value());

    const std::string line = ReadLines(path_).at(0);
    EXPECT_NE(line.find("\"run_id\":\"weird\\\"id\""), std::string::npos);
}

}  // namespace
}  // namespace mlfuzzz3::core
