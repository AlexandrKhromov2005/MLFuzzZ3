// Таблица сайтов прохода ветвлений (ADR 0047 §Решение-5).
//
// Читает таблицу, которую фикстура branch_icmp испускает отдельной сборкой
// с -g и заданным MLFUZZZ3_SITEMAP_DIR, и проверяет ровно то, ради чего
// таблица заведена: номер сайта адресуется местом в исходнике.
//
// Само-пропуск, когда артефакта нет (clang недоступен, фикстура не собрана).

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

#ifndef BRANCH_ICMP_SITEMAP_DIR
#error "BRANCH_ICMP_SITEMAP_DIR must be defined at compile time"
#endif

struct Row {
    unsigned site_id = 0;
    std::string module;
    std::string function;
    std::string file;
    unsigned line = 0;
    unsigned col = 0;
    int lhs_const = 0;
    int rhs_const = 0;
};

std::vector<std::filesystem::path> MapFiles() {
    std::vector<std::filesystem::path> out;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(BRANCH_ICMP_SITEMAP_DIR, ec)) {
        if (e.is_regular_file() && e.path().string().ends_with(".sites.tsv")) {
            out.push_back(e.path());
        }
    }
    return out;
}

std::vector<Row> ReadRows(const std::filesystem::path& p) {
    std::vector<Row> rows;
    std::ifstream in(p);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream ss(line);
        Row r;
        std::string tail;
        ss >> r.site_id;
        std::getline(ss, tail, '\t');  // остаток поля номера
        std::getline(ss, r.module, '\t');
        std::getline(ss, r.function, '\t');
        std::getline(ss, r.file, '\t');
        ss >> r.line >> r.col >> r.lhs_const >> r.rhs_const;
        rows.push_back(r);
    }
    return rows;
}

class SiteMapTest : public ::testing::Test {
   protected:
    void SetUp() override {
        files_ = MapFiles();
        if (files_.empty()) {
            GTEST_SKIP() << "таблицы сайтов нет: " << BRANCH_ICMP_SITEMAP_DIR;
        }
        rows_ = ReadRows(files_.front());
    }
    std::vector<std::filesystem::path> files_;
    std::vector<Row> rows_;
};

// Одна единица трансляции — ровно один файл таблицы.
TEST_F(SiteMapTest, OneFilePerTranslationUnit) {
    EXPECT_EQ(files_.size(), 1U);
}

// Номера идут подряд с нуля — то же правило, что у самой инструментации.
TEST_F(SiteMapTest, SiteIdsAreContiguousFromZero) {
    ASSERT_FALSE(rows_.empty());
    std::set<unsigned> ids;
    for (const Row& r : rows_) {
        ids.insert(r.site_id);
    }
    EXPECT_EQ(ids.size(), rows_.size());
    EXPECT_EQ(*ids.begin(), 0U);
    EXPECT_EQ(*ids.rbegin(), rows_.size() - 1);
}

// Ради этого таблица и заведена: у каждой строки есть адрес в исходнике.
TEST_F(SiteMapTest, EveryRowCarriesSourceLocation) {
    ASSERT_FALSE(rows_.empty());
    for (const Row& r : rows_) {
        EXPECT_FALSE(r.file.empty()) << "site_id=" << r.site_id;
        EXPECT_NE(r.file, "-") << "site_id=" << r.site_id;
        EXPECT_GT(r.line, 0U) << "site_id=" << r.site_id;
        EXPECT_FALSE(r.function.empty()) << "site_id=" << r.site_id;
        EXPECT_FALSE(r.module.empty()) << "site_id=" << r.site_id;
    }
}

// Признак «операнд — константа кода» отличает сравнение с литералом от
// сравнения двух вычисленных значений: на этом признаке строится отбор
// derived-гейтов, ради которого таблица нужна.
TEST_F(SiteMapTest, ConstOperandFlagIsSet) {
    ASSERT_FALSE(rows_.empty());
    int with_const = 0;
    for (const Row& r : rows_) {
        EXPECT_GE(r.lhs_const, 0);
        EXPECT_LE(r.rhs_const, 1);
        if (r.lhs_const == 1 || r.rhs_const == 1) {
            ++with_const;
        }
    }
    EXPECT_GT(with_const, 0) << "в фикстуре есть сравнения с литералами";
}

}  // namespace
