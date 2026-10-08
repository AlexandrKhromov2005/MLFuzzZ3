#include <fuzzer/version.h>
#include <gtest/gtest.h>

#include <cstring>

TEST(CoreSmoke, VersionStringIsNotEmpty) {
    ASSERT_NE(fuzzer::kVersion, nullptr);
    EXPECT_GT(std::strlen(fuzzer::kVersion), 0U);
}

TEST(CoreSmoke, VersionMatchesProjectVersion) {
    EXPECT_STREQ(fuzzer::kVersion, "0.0.0");
}
