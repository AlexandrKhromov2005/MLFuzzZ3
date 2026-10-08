#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "binding_provider.h"
#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// Юнит-тесты интерфейса привязки операндов (ADR 0050). Проверяется, что
// провайдер, переданный в Fixes, действительно зовётся на рабочем пути
// BuildSystem и SolveForCandidate, и что явный ValueMatchBinding даёт ту же
// систему, что нулевой указатель. Побайтовая неизменность систем на
// реальных сидах доказывается отдельно
// (docs/experiments/binding-provider-regress/).

namespace {

using mlfuzzz3::concolic::BindingProvider;
using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::Fixes;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::ValueMatchBinding;
using mlfuzzz3::concolic::VarBinding;
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

// Провайдер, который ничего не привязывает и считает обращения к себе.
struct CallCounts {
    int opens = 0;
    int locates = 0;
    int binds = 0;
};

class NothingBinds final : public BindingProvider {
   public:
    explicit NothingBinds(CallCounts* counts) : counts_(counts) {}

    [[nodiscard]] std::unique_ptr<Session> Open(std::span<const std::uint8_t> /*seed*/,
                                                const Fixes& /*fixes*/) const override {
        ++counts_->opens;
        return std::make_unique<NothingSession>(counts_);
    }

   private:
    class NothingSession final : public Session {
       public:
        explicit NothingSession(CallCounts* counts) : counts_(counts) {}

        [[nodiscard]] std::optional<VarBinding> Locate(std::uint64_t /*value*/,
                                                       unsigned /*bit_width*/) const override {
            ++counts_->locates;
            return std::nullopt;
        }

        [[nodiscard]] Operand Bind(
            std::uint64_t value, unsigned /*bit_width*/, const std::vector<VarBinding>& /*vars*/,
            const std::unordered_map<std::size_t, std::size_t>& /*offset_to_index*/)
            const override {
            ++counts_->binds;
            return {.kind = Operand::Kind::kConst,
                    .var_index = 0,
                    .var_index2 = 0,
                    .const_value = value};
        }

       private:
        CallCounts* counts_;
    };

    CallCounts* counts_;
};

// Вход, на котором value-match строит обратимую систему: 16-битное поле
// 0x1234 (LE) на смещении 0 сравнивается с константой.
const std::vector<std::uint8_t> kSeed = {0x34, 0x12, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00};
const std::vector<BranchReader::Record> kRecords = {
    {0, kUgt, 16, 0x1234ULL, 0x0001ULL},
    {1, kNe, 16, 0x1234ULL, 0x4321ULL},
};

}  // namespace

// Явный ValueMatchBinding обязан давать ту же систему, что умолчание, при
// всех сочетаниях флагов, которые читает привязка (F1, F2).
TEST(BindingProvider, ExplicitValueMatchEqualsDefault) {
    const std::vector<std::uint8_t> seed = {0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30};
    const std::vector<BranchReader::Record> records = {
        {0, kUgt, 32, 0x20000000ULL, 0x10000000ULL},
        {1, kUgt, 32, 0x30000000ULL, 0x10000000ULL},
        {2, kEq, 32, 0x50000000ULL, 0x00000005ULL},
        {3, kUlt, 16, 0x0020ULL, 0xFFFFULL},
    };
    const ValueMatchBinding value_match;
    for (const bool f1 : {false, true}) {
        for (const bool f2 : {false, true}) {
            Fixes by_default;
            by_default.findfirst_index = f1;
            by_default.strict_addvars = f2;
            Fixes explicit_vm = by_default;
            explicit_vm.binding = &value_match;
            EXPECT_TRUE(SameSystem(BuildSystem(seed, records, by_default),
                                   BuildSystem(seed, records, explicit_vm)))
                << "F1=" << f1 << " F2=" << f2;
        }
    }
    EXPECT_TRUE(SameSystem(BuildSystem(seed, records), BuildSystem(seed, records, Fixes{})));
}

// Провайдер из Fixes зовётся на рабочем пути BuildSystem: одна сессия на
// разбор, Locate и Bind — по разу на каждый операнд каждой записи. Без
// привязанных операндов все записи отбрасываются (граница «B»).
TEST(BindingProvider, BuildSystemUsesProviderFromFixes) {
    ASSERT_TRUE(BuildSystem(kSeed, kRecords).invertible);

    CallCounts counts;
    const NothingBinds provider(&counts);
    Fixes fixes;
    fixes.binding = &provider;
    const System sys = BuildSystem(kSeed, kRecords, fixes);

    EXPECT_EQ(counts.opens, 1);
    EXPECT_EQ(counts.locates, 4);
    EXPECT_EQ(counts.binds, 4);
    EXPECT_TRUE(sys.vars.empty());
    EXPECT_TRUE(sys.path.empty());
    EXPECT_FALSE(sys.invertible);
}

// Указатель доезжает до BuildSystem и через SolveForCandidate: с
// провайдером, который ничего не привязывает, кандидата нет по причине
// kNoBinding, а с умолчанием на том же входе кандидат есть.
TEST(BindingProvider, SolveForCandidatePassesProviderThrough) {
    SolveOutcome base = SolveOutcome::kError;
    EXPECT_TRUE(SolveForCandidate(kSeed, kRecords, kTimeoutMs, &base, Fixes{}).has_value());
    EXPECT_EQ(base, SolveOutcome::kCandidate);

    CallCounts counts;
    const NothingBinds provider(&counts);
    Fixes fixes;
    fixes.binding = &provider;
    SolveOutcome outcome = SolveOutcome::kCandidate;
    EXPECT_FALSE(SolveForCandidate(kSeed, kRecords, kTimeoutMs, &outcome, fixes).has_value());
    EXPECT_EQ(outcome, SolveOutcome::kNoBinding);
    EXPECT_EQ(counts.opens, 1);
}

// Сессия ValueMatchBinding напрямую, без BuildSystem: что отдают Locate и
// Bind на малом входе. Каждый случай гоняется и прежним сканированием, и
// через индекс F1 — ответы обязаны совпадать.
namespace {

std::unique_ptr<BindingProvider::Session> OpenValueMatch(const ValueMatchBinding& provider,
                                                         const std::vector<std::uint8_t>& seed,
                                                         bool findfirst_index,
                                                         bool strict_addvars) {
    Fixes fixes;
    fixes.findfirst_index = findfirst_index;
    fixes.strict_addvars = strict_addvars;
    return provider.Open(seed, fixes);
}

}  // namespace

// Locate отдаёт смещение, ширину и порядок байт первой находки; значение,
// которого во входе нет, и недопустимая ширина не привязываются.
TEST(ValueMatchBinding, LocateFindsOffsetWidthAndByteOrder) {
    const std::vector<std::uint8_t> seed = {0x00, 0x34, 0x12, 0xAA};
    const ValueMatchBinding provider;
    for (const bool index : {false, true}) {
        SCOPED_TRACE(index ? "F1 index" : "scan");
        const std::unique_ptr<BindingProvider::Session> s =
            OpenValueMatch(provider, seed, index, false);

        const std::optional<VarBinding> le = s->Locate(0x1234, 16);
        ASSERT_TRUE(le.has_value());
        EXPECT_EQ(le->offset, 1U);
        EXPECT_EQ(le->bit_width, 16U);
        EXPECT_FALSE(le->big_endian);

        const std::optional<VarBinding> be = s->Locate(0x3412, 16);
        ASSERT_TRUE(be.has_value());
        EXPECT_EQ(be->offset, 1U);
        EXPECT_TRUE(be->big_endian);

        const std::optional<VarBinding> byte = s->Locate(0xAA, 8);
        ASSERT_TRUE(byte.has_value());
        EXPECT_EQ(byte->offset, 3U);
        EXPECT_EQ(byte->bit_width, 8U);

        // Старшие биты за шириной отбрасываются до поиска.
        const std::optional<VarBinding> truncated = s->Locate(0xFFFF1234ULL, 16);
        ASSERT_TRUE(truncated.has_value());
        EXPECT_EQ(truncated->offset, 1U);

        EXPECT_FALSE(s->Locate(0x7777, 16).has_value());
        EXPECT_FALSE(s->Locate(0x12345678, 32).has_value());
        EXPECT_FALSE(s->Locate(0x1234, 12).has_value());
    }
}

// Bind: прямая находка на заведённом смещении — kVar; иначе сумма двух
// полей — kAddVars; иначе константа, усечённая до ширины.
TEST(ValueMatchBinding, BindPrefersVarThenSumThenConst) {
    const std::vector<std::uint8_t> seed = {0x03, 0x05, 0x00};
    const std::vector<VarBinding> vars = {
        {.offset = 0, .bit_width = 8, .big_endian = false},
        {.offset = 1, .bit_width = 8, .big_endian = false},
    };
    const std::unordered_map<std::size_t, std::size_t> offset_to_index = {{0, 0}, {1, 1}};
    const ValueMatchBinding provider;
    for (const bool index : {false, true}) {
        SCOPED_TRACE(index ? "F1 index" : "scan");
        const std::unique_ptr<BindingProvider::Session> s =
            OpenValueMatch(provider, seed, index, false);

        const Operand var = s->Bind(0x05, 8, vars, offset_to_index);
        EXPECT_EQ(var.kind, Operand::Kind::kVar);
        EXPECT_EQ(var.var_index, 1U);

        const Operand sum = s->Bind(0x08, 8, vars, offset_to_index);
        EXPECT_EQ(sum.kind, Operand::Kind::kAddVars);
        EXPECT_EQ(sum.var_index, 0U);
        EXPECT_EQ(sum.var_index2, 1U);

        const Operand konst = s->Bind(0x1F7, 8, vars, offset_to_index);
        EXPECT_EQ(konst.kind, Operand::Kind::kConst);
        EXPECT_EQ(konst.const_value, 0xF7U);

        // Найденное значение на смещении без переменной (байт 0x00 на
        // смещении 2) переменной не становится.
        const Operand unbound = s->Bind(0x00, 8, vars, offset_to_index);
        EXPECT_EQ(unbound.kind, Operand::Kind::kConst);
    }
}

// F2 (ADR 0049) сессия читает из Fixes: без флага удвоение поля даёт
// kAddVars(i, i), с флагом вырожденная сумма запрещена и остаётся
// константа; невырожденная сумма разных полей разрешена в обоих режимах.
TEST(ValueMatchBinding, BindHonoursStrictAddVars) {
    const std::vector<std::uint8_t> seed = {0x03, 0x05};
    const std::vector<VarBinding> vars = {
        {.offset = 0, .bit_width = 8, .big_endian = false},
        {.offset = 1, .bit_width = 8, .big_endian = false},
    };
    const std::unordered_map<std::size_t, std::size_t> offset_to_index = {{0, 0}, {1, 1}};
    const ValueMatchBinding provider;

    const std::unique_ptr<BindingProvider::Session> loose =
        OpenValueMatch(provider, seed, false, false);
    const Operand doubled = loose->Bind(0x06, 8, vars, offset_to_index);
    EXPECT_EQ(doubled.kind, Operand::Kind::kAddVars);
    EXPECT_EQ(doubled.var_index, 0U);
    EXPECT_EQ(doubled.var_index2, 0U);

    const std::unique_ptr<BindingProvider::Session> strict =
        OpenValueMatch(provider, seed, false, true);
    const Operand refused = strict->Bind(0x06, 8, vars, offset_to_index);
    EXPECT_EQ(refused.kind, Operand::Kind::kConst);
    EXPECT_EQ(refused.const_value, 0x06U);
    EXPECT_EQ(strict->Bind(0x08, 8, vars, offset_to_index).kind, Operand::Kind::kAddVars);
}
