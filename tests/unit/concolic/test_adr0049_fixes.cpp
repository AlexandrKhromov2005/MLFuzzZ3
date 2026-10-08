#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Юнит-тесты четырёх починок солверной руки (ADR 0049). Каждая проверяется
// отдельно и против ВЫКЛЮЧЕННОГО состояния: умолчание обязано остаться
// прежним, пока развёртка docs/experiments/solver-fix-ladder/ не назовёт
// числа.

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::Fixes;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::SolveSystemForTarget;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::WriteBackStats;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;

constexpr unsigned kTimeoutMs = 5000;

enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUgt = 4 };

bool SameOperand(const Operand& a, const Operand& b) {
    return a.kind == b.kind && a.var_index == b.var_index && a.var_index2 == b.var_index2 &&
           a.const_value == b.const_value;
}

bool SameSystem(const System& a, const System& b) {
    if (a.num_vars != b.num_vars || a.target_index != b.target_index ||
        a.invertible != b.invertible || a.path.size() != b.path.size() ||
        a.vars.size() != b.vars.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.vars.size(); ++i) {
        if (a.vars[i].offset != b.vars[i].offset || a.vars[i].bit_width != b.vars[i].bit_width ||
            a.vars[i].big_endian != b.vars[i].big_endian) {
            return false;
        }
    }
    for (std::size_t i = 0; i < a.path.size(); ++i) {
        if (a.path[i].predicate != b.path[i].predicate ||
            a.path[i].bit_width != b.path[i].bit_width ||
            !SameOperand(a.path[i].lhs, b.path[i].lhs) ||
            !SameOperand(a.path[i].rhs, b.path[i].rhs)) {
            return false;
        }
    }
    return true;
}

}  // namespace

// F1. Индекс входа обязан отвечать ровно то же, что сканирование. Сравнение
// идёт не по самой FindFirst (она внутренняя), а по её единственному
// наблюдаемому следствию — построенной системе: совпадают привязки, их
// ширины, порядок байт и классификация каждого операнда.
//
// Наборы подобраны против правила выбора: палиндром (LE и BE дают одно
// значение на одном смещении), значение, встречающееся дважды (должно
// выиграть меньшее смещение), значение в самом начале и в самом конце
// входа, нули и все четыре ширины.
TEST(Adr0049F1, IndexReproducesScanningByteForByte) {
    struct Case {
        const char* name;
        std::vector<std::uint8_t> seed;
        std::vector<BranchReader::Record> records;
    };
    const std::vector<Case> cases = {
        {"палиндром",
         {0x12, 0x34, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00},
         {{0, kEq, 16, 0x3412ULL, 0x1234ULL}, {1, kUgt, 32, 0x12343412ULL, 0x00000001ULL}}},
        {"значение дважды",
         {0xAB, 0xCD, 0xAB, 0xCD, 0x01, 0x02, 0x03, 0x04},
         {{0, kUlt, 16, 0xCDABULL, 0xFFFFULL}, {1, kEq, 8, 0xABULL, 0xABULL}}},
        {"нули и края",
         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F},
         {{0, kEq, 64, 0x7F00000000000000ULL, 0x0ULL}, {1, kNe, 8, 0x7FULL, 0x00ULL}}},
        {"суммы полей",
         {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30},
         {{0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
          {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
          {2, kEq, 32, 0x50000000ULL, 0x00000005ULL}}},
    };

    for (const Case& c : cases) {
        Fixes on;
        on.findfirst_index = true;
        const System scanned = BuildSystem(c.seed, c.records);
        const System indexed = BuildSystem(c.seed, c.records, on);
        EXPECT_TRUE(SameSystem(scanned, indexed)) << "расхождение на наборе: " << c.name;
    }
}

// F2. Вырожденная «сумма» перестаёт быть суммой. Вход: 16-битное поле
// 0x1234 в начале и нулевое 32-битное поле следом. Значение 0x00001234 в
// 32 битах прямым поиском не находится (за полем стоит не ноль, а второе
// поле), зато равно «поле + нулевое поле», и до ADR 0049 связывалось как
// kAddVars. Такая привязка не связывает ничего: она вносит в систему
// тождество x + 0 = x.
TEST(Adr0049F2, DegenerateSumsStopBindingAsAddVars) {
    // 0x1234 (LE) на смещении 0; четыре нулевых байта на смещении 4.
    const std::vector<std::uint8_t> seed = {0x34, 0x12, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 16, 0x1234ULL, 0x0001ULL},          // поле 0x1234 -> var
        {1, kEq, 32, 0x00000000ULL, 0x00000000ULL},   // нулевое поле -> var
        {2, kUlt, 32, 0x00001234ULL, 0x00000000ULL},  // 0x1234 == поле + ноль; справа нулевое поле
    };

    const System before = BuildSystem(seed, records);
    ASSERT_GE(before.path.size(), 3U);
    EXPECT_EQ(before.path[2].lhs.kind, Operand::Kind::kAddVars)
        << "до починки вырожденная сумма связывается как kAddVars";

    Fixes on;
    on.strict_addvars = true;
    const System after = BuildSystem(seed, records, on);
    ASSERT_GE(after.path.size(), 3U);
    EXPECT_EQ(after.path[2].lhs.kind, Operand::Kind::kConst)
        << "после починки вырожденная сумма становится константой";
    EXPECT_EQ(after.num_vars, before.num_vars)
        << "переменных столько же: вырожденные пары их не добавляли";
    EXPECT_EQ(after.path.size(), before.path.size())
        << "запись остаётся в пути: её вторая сторона по-прежнему связана";
}

// F2, вторая сторона: НЕвырожденная сумма двух непустых разных полей
// обязана остаться kAddVars — починка не должна отрезать полезное.
TEST(Adr0049F2, HonestSumSurvives) {
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kEq, 32, 0x50000000ULL, 0x00000005ULL},  // сумма двух разных полей
    };
    Fixes on;
    on.strict_addvars = true;
    const System sys = BuildSystem(seed, records, on);
    ASSERT_GE(sys.path.size(), 3U);
    EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kAddVars);
    EXPECT_NE(sys.path[2].lhs.var_index, sys.path[2].lhs.var_index2);
}

// F4, отрицательная сторона. Переменная привязана к ОДНОМУ байту (первая
// нашедшая запись была восьмибитной), а решается шестнадцатибитной: солвер
// вправе вернуть значение шире байта. Соседний байт входа не нулевой,
// значит расширить привязку вход не подтверждает — и кандидат не строится.
// До починки значение молча усекалось, и кандидат переставал удовлетворять
// системе.
TEST(Adr0049F4, ModelWiderThanBindingIsRefusedInsteadOfTruncated) {
    // 0x34 на смещении 0 (байт), 0x1234 на том же смещении (LE, 16 бит).
    const std::vector<std::uint8_t> seed = {0x34, 0x12, 0xFF, 0xAA, 0x5A, 0xA5, 0x0F, 0xF0};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 8, 0x34ULL, 0x10ULL},      // привязка шириной 8 бит
        {1, kEq, 16, 0x1234ULL, 0x1388ULL},  // та же переменная, 16 бит; 5000 != 0x1234
    };

    SolveOutcome before = SolveOutcome::kError;
    const auto candidate_before = SolveForCandidate(seed, records, kTimeoutMs, &before);
    EXPECT_EQ(before, SolveOutcome::kCandidate)
        << "до починки кандидат строится — с молча усечённым значением";
    ASSERT_TRUE(candidate_before.has_value());

    Fixes on;
    on.no_truncation = true;
    SolveOutcome after = SolveOutcome::kError;
    const auto candidate_after = SolveForCandidate(seed, records, kTimeoutMs, &after, on);
    EXPECT_EQ(after, SolveOutcome::kWidthOverflow);
    EXPECT_FALSE(candidate_after.has_value());
}

// F4, положительная сторона. Тот же случай, но соседний байт входа нулевой:
// нулевое расширение подтверждено самим входом, привязка расширяется до
// ширины ограничения, и кандидат строится — с значением, которое влезло
// целиком.
TEST(Adr0049F4, ZeroNeighbourWidensTheBindingAndKeepsTheCandidate) {
    const std::vector<std::uint8_t> seed = {0x34, 0x00, 0xFF, 0xAA, 0x5A, 0xA5, 0x0F, 0xF0};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 8, 0x34ULL, 0x10ULL},      // привязка шириной 8 бит
        {1, kEq, 16, 0x0034ULL, 0x1388ULL},  // та же переменная, 16 бит
    };

    Fixes on;
    on.no_truncation = true;
    SolveOutcome outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &outcome, on);
    ASSERT_EQ(outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(candidate.has_value());
    const std::span<const std::uint8_t> bytes(candidate->data(), candidate->size());
    ASSERT_GE(bytes.size(), 2U);
    const std::uint16_t written =
        static_cast<std::uint16_t>(bytes[0]) | static_cast<std::uint16_t>(bytes[1] << 8);
    EXPECT_EQ(written, 0x1388U) << "значение записано целиком, а не усечено до байта";
}

// F3. В продукте цель — последняя запись, суффикса после неё нет, и
// префиксная форма обязана совпасть с прежней побайтово. Оптимистическая
// форма отдаёт солверу одно ограничение и потому решает другую задачу;
// проверяется, что она доходит до кандидата и что целевое ограничение в нём
// действительно перевёрнуто.
TEST(Adr0049F3, PrefixEqualsOldFormAtTheProductTargetAndOptimisticSolvesOne) {
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kUlt, 32, 0x20000000ULL, 0x30000000ULL},
        {3, kEq, 32, 0x50000000ULL, 0x00000005ULL},
    };

    SolveOutcome old_outcome = SolveOutcome::kError;
    const auto old_candidate = SolveForCandidate(seed, records, kTimeoutMs, &old_outcome);
    ASSERT_EQ(old_outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(old_candidate.has_value());

    Fixes prefix;
    prefix.form = Fixes::Form::kPrefix;
    SolveOutcome prefix_outcome = SolveOutcome::kError;
    const auto prefix_candidate =
        SolveForCandidate(seed, records, kTimeoutMs, &prefix_outcome, prefix);
    ASSERT_EQ(prefix_outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(prefix_candidate.has_value());
    const std::span<const std::uint8_t> old_bytes(old_candidate->data(), old_candidate->size());
    const std::span<const std::uint8_t> prefix_bytes(prefix_candidate->data(),
                                                     prefix_candidate->size());
    ASSERT_EQ(old_bytes.size(), prefix_bytes.size());
    EXPECT_TRUE(std::equal(old_bytes.begin(), old_bytes.end(), prefix_bytes.begin()))
        << "при цели-последней записи префикс равен всему пути";

    Fixes optimistic;
    optimistic.form = Fixes::Form::kOptimistic;
    SolveOutcome opt_outcome = SolveOutcome::kError;
    const auto opt_candidate =
        SolveForCandidate(seed, records, kTimeoutMs, &opt_outcome, optimistic);
    ASSERT_EQ(opt_outcome, SolveOutcome::kCandidate);
    ASSERT_TRUE(opt_candidate.has_value());
    const std::span<const std::uint8_t> opt_bytes(opt_candidate->data(), opt_candidate->size());
    ASSERT_GE(opt_bytes.size(), 8U);
    const auto read_le32 = [](const std::uint8_t* p) {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    };
    const std::uint32_t x = read_le32(opt_bytes.data());
    const std::uint32_t y = read_le32(opt_bytes.data() + 4);
    EXPECT_EQ(static_cast<std::uint32_t>(x + y), 5U)
        << "целевое ограничение перевёрнуто: сумма полей стала равна 5";
}

// Умолчание. Пустой Fixes обязан давать в точности прежнее поведение — это
// условие принятия ADR: пока развёртка не проведена, включать нечего.
TEST(Adr0049Default, EmptyFixesReproduceTheOldBehaviour) {
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kEq, 32, 0x50000000ULL, 0x00000005ULL},
    };
    EXPECT_TRUE(SameSystem(BuildSystem(seed, records), BuildSystem(seed, records, Fixes{})));

    SolveOutcome a = SolveOutcome::kError;
    SolveOutcome b = SolveOutcome::kError;
    const auto ca = SolveForCandidate(seed, records, kTimeoutMs, &a);
    const auto cb = SolveForCandidate(seed, records, kTimeoutMs, &b, Fixes{});
    EXPECT_EQ(a, b);
    ASSERT_EQ(ca.has_value(), cb.has_value());
    if (ca.has_value()) {
        const std::span<const std::uint8_t> xa(ca->data(), ca->size());
        const std::span<const std::uint8_t> xb(cb->data(), cb->size());
        ASSERT_EQ(xa.size(), xb.size());
        EXPECT_TRUE(std::equal(xa.begin(), xa.end(), xb.begin()));
    }
}

// Точка входа для развёрток. Они инвертируют КАЖДУЮ позицию пути, а не
// только последнюю, и обязаны мерить тот же код, которым пользуется
// продукт. Проверяется двумя утверждениями: при цели, равной продуктовой,
// результат совпадает с SolveForCandidate байт в байт; при цели раньше
// последней префиксная форма отдаёт солверу ровно префикс и доходит до
// кандидата, в котором перевёрнуто именно это ограничение.
TEST(Adr0049Entry, SolveSystemForTargetMatchesProductAndSweepsPositions) {
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kUlt, 32, 0x20000000ULL, 0x30000000ULL},
        {3, kEq, 32, 0x50000000ULL, 0x00000005ULL},
    };
    const System sys = BuildSystem(seed, records);
    ASSERT_TRUE(sys.invertible);

    SolveOutcome via_product = SolveOutcome::kError;
    const auto product = SolveForCandidate(seed, records, kTimeoutMs, &via_product);
    SolveOutcome via_entry = SolveOutcome::kError;
    const auto entry =
        SolveSystemForTarget(seed, sys, sys.target_index, kTimeoutMs, &via_entry, Fixes{});
    EXPECT_EQ(via_product, via_entry);
    ASSERT_EQ(product.has_value(), entry.has_value());
    if (product.has_value()) {
        const std::span<const std::uint8_t> a(product->data(), product->size());
        const std::span<const std::uint8_t> b(entry->data(), entry->size());
        ASSERT_EQ(a.size(), b.size());
        EXPECT_TRUE(std::equal(a.begin(), a.end(), b.begin()));
    }

    Fixes prefix;
    prefix.form = Fixes::Form::kPrefix;
    SolveOutcome first = SolveOutcome::kError;
    const auto flipped_first = SolveSystemForTarget(seed, sys, 0, kTimeoutMs, &first, prefix);
    ASSERT_EQ(first, SolveOutcome::kCandidate);
    ASSERT_TRUE(flipped_first.has_value());
    const std::span<const std::uint8_t> bytes(flipped_first->data(), flipped_first->size());
    ASSERT_GE(bytes.size(), 4U);
    const std::uint32_t x =
        static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8) |
        (static_cast<std::uint32_t>(bytes[2]) << 16) | (static_cast<std::uint32_t>(bytes[3]) << 24);
    EXPECT_LE(x, 0x10000000U) << "перевёрнуто первое ограничение: x >u K стало x <=u K";
}

// Счётчики обратной записи считаются ВСЕГДА, и это условие сравнимости
// плеч развёртки: базовое плечо обязано давать долю усечённых тем же
// кодом, что и починенное. На случае затенения ширины без нулевых соседей
// базовое плечо видит усечение и всё равно строит кандидата, а плечо F4 на
// тех же числах отказывается.
TEST(Adr0049Stats, TruncationIsCountedWithAndWithoutTheFix) {
    const std::vector<std::uint8_t> seed = {0x34, 0x12, 0xFF, 0xAA, 0x5A, 0xA5, 0x0F, 0xF0};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 8, 0x34ULL, 0x10ULL},
        {1, kEq, 16, 0x1234ULL, 0x1388ULL},
    };
    const System sys = BuildSystem(seed, records);
    ASSERT_TRUE(sys.invertible);

    WriteBackStats base;
    SolveOutcome base_outcome = SolveOutcome::kError;
    const auto base_cand = SolveSystemForTarget(seed, sys, sys.target_index, kTimeoutMs,
                                                &base_outcome, Fixes{}, &base);
    EXPECT_EQ(base_outcome, SolveOutcome::kCandidate);
    EXPECT_TRUE(base_cand.has_value());
    EXPECT_EQ(base.vars_wider_than_binding, 1);
    EXPECT_EQ(base.vars_truncated, 1);
    EXPECT_EQ(base.vars_widened, 0) << "без флага привязка не расширяется";

    Fixes on;
    on.no_truncation = true;
    WriteBackStats fixed;
    SolveOutcome fixed_outcome = SolveOutcome::kError;
    const auto fixed_cand =
        SolveSystemForTarget(seed, sys, sys.target_index, kTimeoutMs, &fixed_outcome, on, &fixed);
    EXPECT_EQ(fixed_outcome, SolveOutcome::kWidthOverflow);
    EXPECT_FALSE(fixed_cand.has_value());
    EXPECT_EQ(fixed.vars_truncated, base.vars_truncated)
        << "счёт усечённых одинаков: отличается решение, а не измерение";
}
