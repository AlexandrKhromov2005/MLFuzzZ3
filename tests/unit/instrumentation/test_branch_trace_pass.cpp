// IR-level unit test for the branch-tracing pass (ADR 0033 Шаг 3).
//
// Reads the branch-pass-instrumented IR of branch_icmp_target.c
// (emitted by the fixture build with ONLY this pass) and checks the
// inserted instrumentation rather than runtime behaviour — operand
// VALUES are validated by execution in the Шаг 6 e2e.
//
// Asserts:
//   - one fuzzer_rt_log_branch_cmp call per icmp;
//   - the expected (predicate, bit_width) pairs are present, with
//     signed vs unsigned distinguishable at the same width;
//   - site_id constants form the deterministic set {0..N-1}.
//
// Self-skips when the IR artifact is absent (clang not available, so
// the fixture and its IR were not built).

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

#ifndef BRANCH_ICMP_IR_PATH
#error "BRANCH_ICMP_IR_PATH must be defined at compile time"
#endif

// Predicate enum values mirrored from mlfuzzz3_branch.h (the ABI).
constexpr int kEq = 0;
constexpr int kUlt = 2;
constexpr int kUgt = 4;
constexpr int kSlt = 6;
constexpr int kSgt = 8;

std::string ReadFileOrEmpty(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        return {};
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Counts integer-compare instructions in the IR text.
size_t CountIcmps(const std::string& ir) {
    const std::regex re(R"(\bicmp\s+(eq|ne|ult|ule|ugt|uge|slt|sle|sgt|sge)\b)");
    return static_cast<size_t>(
        std::distance(std::sregex_iterator(ir.begin(), ir.end(), re), std::sregex_iterator()));
}

struct CallArgs {
    int site_id;
    int predicate;
    int bit_width;
};

std::vector<CallArgs> ParseCalls(const std::string& ir) {
    // call void @fuzzer_rt_log_branch_cmp(i32 <site>, i64 <lhs>,
    //                                     i64 <rhs>, i8 <pred>, i8 <w>)
    const std::regex re(
        R"(@fuzzer_rt_log_branch_cmp\(i32 (\d+), i64 [^,]+, i64 [^,]+, i8 (\d+), i8 (\d+)\))");
    std::vector<CallArgs> out;
    for (auto it = std::sregex_iterator(ir.begin(), ir.end(), re); it != std::sregex_iterator();
         ++it) {
        const std::smatch& m = *it;
        out.push_back({std::stoi(m[1].str()), std::stoi(m[2].str()), std::stoi(m[3].str())});
    }
    return out;
}

class BranchTracePassIR : public ::testing::Test {
   protected:
    void SetUp() override {
        ir_ = ReadFileOrEmpty(BRANCH_ICMP_IR_PATH);
        if (ir_.empty()) {
            GTEST_SKIP() << "instrumented IR absent (clang unavailable): " << BRANCH_ICMP_IR_PATH;
        }
        calls_ = ParseCalls(ir_);
    }

    std::string ir_;
    std::vector<CallArgs> calls_;
};

// Every icmp gets exactly one hook call; the fixture has five.
TEST_F(BranchTracePassIR, OneCallPerIcmp) {
    const size_t icmps = CountIcmps(ir_);
    EXPECT_GE(icmps, 5u);
    EXPECT_EQ(calls_.size(), icmps);
}

// The expected predicate/width pairs are present, and a signed and an
// unsigned comparison of the same width are both logged (distinct
// predicate values).
TEST_F(BranchTracePassIR, PredicateAndWidthMapping) {
    std::set<std::pair<int, int>> seen;
    for (const CallArgs& c : calls_) {
        seen.insert({c.predicate, c.bit_width});
    }
    EXPECT_TRUE(seen.count({kSlt, 32})) << "signed < at width 32";
    EXPECT_TRUE(seen.count({kUlt, 32})) << "unsigned < at width 32";
    EXPECT_TRUE(seen.count({kEq, 32})) << "eq at width 32";
    EXPECT_TRUE(seen.count({kUgt, 64})) << "unsigned > at width 64";
    EXPECT_TRUE(seen.count({kSgt, 64})) << "signed > at width 64";

    // Signedness is preserved: SLT and ULT differ at the same width.
    EXPECT_NE(kSlt, kUlt);
    EXPECT_TRUE(seen.count({kSlt, 32}) && seen.count({kUlt, 32}));
}

// site_id is a deterministic 0-based module-order set.
TEST_F(BranchTracePassIR, SiteIdsAreDeterministicSet) {
    std::set<int> ids;
    for (const CallArgs& c : calls_) {
        ids.insert(c.site_id);
    }
    EXPECT_EQ(ids.size(), calls_.size()) << "site_ids must be unique";
    std::set<int> expected;
    for (int i = 0; i < static_cast<int>(calls_.size()); ++i) {
        expected.insert(i);
    }
    EXPECT_EQ(ids, expected) << "site_ids must be {0..N-1}";
}

}  // namespace
