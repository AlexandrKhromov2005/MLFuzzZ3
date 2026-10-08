#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

#include "corpus.h"
#include "fuzz_input.h"

namespace mlfuzzz3::core {
namespace {

mutation::FuzzInput MakeInput(const std::string& bytes) {
    return mutation::FuzzInput(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

std::vector<std::uint8_t> ReadAll(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
}

std::size_t CountFiles(const std::filesystem::path& dir) {
    std::error_code ec;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (entry.is_regular_file()) {
            ++count;
        }
    }
    return count;
}

class CorpusTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_corpus_test" /
                (std::string(info->test_suite_name()) + "_" + info->name());
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);
    }
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(base_, ec);
    }
    std::filesystem::path base_;
};

TEST_F(CorpusTest, CreateMakesSubdirs) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());
    EXPECT_TRUE(std::filesystem::is_directory(corpus->corpus_dir()));
    EXPECT_TRUE(std::filesystem::is_directory(corpus->crashes_dir()));
    EXPECT_TRUE(std::filesystem::is_directory(corpus->hangs_dir()));
    EXPECT_EQ(corpus->size(), 0U);
    EXPECT_TRUE(corpus->empty());
}

TEST_F(CorpusTest, AddStoresEntryAndWritesFile) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    auto id = corpus->Add(MakeInput("hello"), 5);
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(*id, 0U);
    EXPECT_EQ(corpus->size(), 1U);

    const CorpusEntry& entry = corpus->at(0);
    EXPECT_EQ(entry.id, 0U);
    EXPECT_EQ(entry.new_edges, 5U);

    const std::filesystem::path file = corpus->corpus_dir() / "id_000000.bin";
    ASSERT_TRUE(std::filesystem::exists(file));
    const std::vector<std::uint8_t> on_disk = ReadAll(file);
    const std::vector<std::uint8_t> expected{'h', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(on_disk, expected);
}

TEST_F(CorpusTest, CorpusFileNamesAreDeterministicById) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    ASSERT_TRUE(corpus->Add(MakeInput("first"), 1).has_value());
    ASSERT_TRUE(corpus->Add(MakeInput("second"), 1).has_value());

    EXPECT_TRUE(std::filesystem::exists(corpus->corpus_dir() / "id_000000.bin"));
    EXPECT_TRUE(std::filesystem::exists(corpus->corpus_dir() / "id_000001.bin"));
    EXPECT_EQ(CountFiles(corpus->corpus_dir()), 2U);
}

TEST_F(CorpusTest, BootstrapEmptyStartSeedsOneTrivialInput) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    // Empty seed path → bootstrap injects one trivial input.
    auto count = corpus->Bootstrap(std::filesystem::path{});
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(*count, 1U);
    EXPECT_EQ(corpus->size(), 1U);
    EXPECT_TRUE(std::filesystem::exists(corpus->corpus_dir() / "id_000000.bin"));
}

TEST_F(CorpusTest, BootstrapLoadsSeedDirectory) {
    const std::filesystem::path seed_dir = base_ / "seeds";
    std::filesystem::create_directories(seed_dir);
    {
        std::ofstream(seed_dir / "a.bin", std::ios::binary) << "alpha";
        std::ofstream(seed_dir / "b.bin", std::ios::binary) << "beta";
    }

    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    auto count = corpus->Bootstrap(seed_dir);
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(*count, 2U);
    EXPECT_EQ(corpus->size(), 2U);
    EXPECT_EQ(CountFiles(corpus->corpus_dir()), 2U);
}

TEST_F(CorpusTest, SaveCrashIsContentAddressedAndDeterministic) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    ASSERT_TRUE(corpus->SaveCrash(MakeInput("boom")).has_value());
    // Same bytes → same content-addressed name → still one file.
    ASSERT_TRUE(corpus->SaveCrash(MakeInput("boom")).has_value());
    EXPECT_EQ(CountFiles(corpus->crashes_dir()), 1U);

    // Different bytes → a distinct file.
    ASSERT_TRUE(corpus->SaveCrash(MakeInput("different")).has_value());
    EXPECT_EQ(CountFiles(corpus->crashes_dir()), 2U);

    // SaveCrash does not grow the working set.
    EXPECT_EQ(corpus->size(), 0U);

    for (const auto& entry : std::filesystem::directory_iterator(corpus->crashes_dir())) {
        const std::string name = entry.path().filename().string();
        EXPECT_EQ(name.rfind("crash_", 0), 0U) << "unexpected crash file name: " << name;
        EXPECT_EQ(name.size(), std::string("crash_").size() + 16 + std::string(".bin").size());
    }
}

TEST_F(CorpusTest, SaveHangWritesToHangsDir) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    ASSERT_TRUE(corpus->SaveHang(MakeInput("slow")).has_value());
    EXPECT_EQ(CountFiles(corpus->hangs_dir()), 1U);
    EXPECT_EQ(CountFiles(corpus->crashes_dir()), 0U);
    EXPECT_EQ(corpus->size(), 0U);
}

TEST_F(CorpusTest, NewEntriesStartInDeterministicPhase) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    ASSERT_TRUE(corpus->Add(MakeInput("seed"), 0).has_value());
    const CorpusEntry& entry = corpus->at(0);
    EXPECT_EQ(entry.det.phase, SeedPhase::kDeterministic);
    EXPECT_EQ(entry.det.cursor, 0U);
}

TEST_F(CorpusTest, BootstrapEntryStartsInDeterministicPhase) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());

    ASSERT_TRUE(corpus->Bootstrap(std::filesystem::path{}).has_value());
    ASSERT_EQ(corpus->size(), 1U);
    EXPECT_EQ(corpus->at(0).det.phase, SeedPhase::kDeterministic);
    EXPECT_EQ(corpus->at(0).det.cursor, 0U);
}

TEST_F(CorpusTest, SetDetStateUpdatesOnlyDetState) {
    auto corpus = Corpus::Create(base_);
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Add(MakeInput("hello"), 7).has_value());

    corpus->SetDetState(0, DetState{.phase = SeedPhase::kHavoc, .cursor = 42});

    const CorpusEntry& entry = corpus->at(0);
    EXPECT_EQ(entry.det.phase, SeedPhase::kHavoc);
    EXPECT_EQ(entry.det.cursor, 42U);
    // The id, coverage, and bytes are untouched by SetDetState.
    EXPECT_EQ(entry.id, 0U);
    EXPECT_EQ(entry.new_edges, 7U);
    const std::vector<std::uint8_t> bytes(entry.input.data(),
                                          entry.input.data() + entry.input.size());
    const std::vector<std::uint8_t> expected{'h', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(bytes, expected);
}

}  // namespace
}  // namespace mlfuzzz3::core
