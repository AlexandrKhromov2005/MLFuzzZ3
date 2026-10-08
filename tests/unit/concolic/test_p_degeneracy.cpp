#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "solver_facade.h"

// task-064. Вырожден ли предиктор P в константу `bound` на сетке task-042.
//
// ГИПОТЕЗА, НАЗВАННАЯ ДО ПРОГОНА (записана прежде, чем этот файл был
// собран и запущен хоть один раз):
//   * P — инвертированный целевой предикат, вычисленный на значениях,
//     ПЕРЕЧИТАННЫХ из кандидата после обратной записи (пин:
//     tests/unit/concolic/test_discriminator_residual.cpp:676);
//   * единственный признак, по которому P вообще способен отличаться от
//     «солвер вернул SAT», — потеря при обратной записи, то есть
//     model_mismatch = mismatched_vars > 0U (пин:
//     tests/unit/concolic/test_discriminator_residual.cpp:671);
//   * на сетке, где привязки нигде не перекрываются, обратная запись
//     ничего не теряет, перечитанные значения равны модели, и потому P
//     тождественно истинен ПО ПОСТРОЕНИЮ; его 18 совпадений с меткой
//     task-042 (docs/experiments/solver-discriminator-width-endian/report.md:19)
//     — это ровно те 18 клеток, где task-042 напечатал BOUND, и ничего
//     сверх того.
//
// Гипотеза может не подтвердиться, и тогда это будет НАПЕЧАТАНО, а не
// спрятано: ассертов на p_true_cells==56 и на model_mismatch_cells==0
// здесь нет, оба числа измеряются. Ассерты стоят только на опубликованных
// воспроизводимых числах (p_agrees=18, cells=56) и на контрольных сетках.
//
// Прибор проверяется НЕГАТИВНО дважды: (1) на чужих сетках task-053 (9
// клеток) и task-056 (27 клеток), где привязки перекрываются по
// построению и счётчик mismatched_vars обязан покраснеть; (2) на самой
// сетке task-042 — порчей одного байта кандидата внутри диапазона первой
// привязки.
//
// Знаменатель контроля task-056 здесь 27, а не 18: «18» в тексте очереди —
// это gate_taken=18/27 (docs/experiments/solver-discriminator-residual/report.md:91),
// а не размер сетки. Числа не подгоняются под текст.
//
// Что здесь НЕ делается: ничего под src/ не правится, D не
// переизмеряется (его формула приезжает вместе с дословно скопированным
// телом Measure, но ни одно число D не публикуется), отчёты и харнессы
// task-042/053/056/062 не трогаются, ни одной новой фаззинг-кампании не
// запускается.

namespace {

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:45-53
// (task-062).
using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::concolic::VarBinding;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Operand;
using mlfuzzz3::solver::SolveInverted;
using mlfuzzz3::solver::SolveResult;

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:55-62
// (task-062).
// fuzzer_rt_cmp_kind values (ADR 0033), copied from
// test_discriminator_residual.cpp:77 (a superset of the three codes
// test_domain_form_width_endian.cpp:83 needs, same numbering).
enum : std::uint8_t { kEq = 0, kNe = 1, kUlt = 2, kUle = 3, kUgt = 4, kUge = 5 };

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kBits = 8;
constexpr unsigned kTimeoutMs = 5000;  ///< the constant of all three sources

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:64-79
// (task-062).
// ---------------------------------------------------------------------
// THE DISCRIMINATOR D, copied from test_binding_discriminator.cpp:80-82.
// Not restated, not adapted to the axes measured below.
// ---------------------------------------------------------------------

bool Discriminator(Operand::Kind derived_kind, bool gate_survived) {
    return derived_kind != Operand::Kind::kConst && gate_survived;
}

const char* YesNo(bool value) {
    return value ? "yes" : "no";
}

const char* BoundName(bool bound) {
    return bound ? "bound" : "no_binding";
}

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:81-176
// (task-062).
// ---------------------------------------------------------------------
// P's oracles, copied from test_discriminator_residual.cpp:139-234.
// ---------------------------------------------------------------------

std::uint64_t Truncate(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

std::uint64_t ReadBinding(const std::vector<std::uint8_t>& bytes, const VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[var.offset + k]) << shift;
    }
    return value;
}

// The engine's write-back, replayed from the model returned by a direct
// SolveInverted call (mirrors src/concolic/concolic.cpp:303-317).
std::vector<std::uint8_t> WriteBackModel(const std::vector<std::uint8_t>& seed, const System& sys,
                                         const std::vector<std::uint64_t>& model) {
    std::vector<std::uint8_t> bytes = seed;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const VarBinding& var = sys.vars[k];
        const unsigned n = var.bit_width / kBitsPerByte;
        const std::uint64_t value = Truncate(model[k], var.bit_width);
        for (unsigned b = 0; b < n; ++b) {
            const unsigned shift =
                var.big_endian ? (kBitsPerByte * (n - 1U - b)) : (kBitsPerByte * b);
            bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
        }
    }
    return bytes;
}

std::uint8_t Negate(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return kNe;
        case kNe:
            return kEq;
        case kUlt:
            return kUge;
        case kUle:
            return kUgt;
        case kUgt:
            return kUle;
        case kUge:
            return kUlt;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return predicate;
    }
}

bool Eval(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs, unsigned bit_width) {
    const std::uint64_t l = Truncate(lhs, bit_width);
    const std::uint64_t r = Truncate(rhs, bit_width);
    switch (predicate) {
        case kEq:
            return l == r;
        case kNe:
            return l != r;
        case kUlt:
            return l < r;
        case kUle:
            return l <= r;
        case kUgt:
            return l > r;
        case kUge:
            return l >= r;
        default:
            ADD_FAILURE() << "predicate outside the fixture: " << unsigned{predicate};
            return false;
    }
}

std::uint64_t OperandValue(const Operand& op, const System& sys,
                           const std::vector<std::uint8_t>& bytes, unsigned bit_width) {
    switch (op.kind) {
        case Operand::Kind::kVar:
            return Truncate(ReadBinding(bytes, sys.vars[op.var_index]), bit_width);
        case Operand::Kind::kConst:
            return Truncate(op.const_value, bit_width);
        case Operand::Kind::kAddVars:
            return Truncate(Truncate(ReadBinding(bytes, sys.vars[op.var_index]), bit_width) +
                                Truncate(ReadBinding(bytes, sys.vars[op.var_index2]), bit_width),
                            bit_width);
    }
    ADD_FAILURE() << "unknown operand kind";
    return 0;
}

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:178-346
// (task-062).
// ---------------------------------------------------------------------
// The grid of task-042, copied from test_domain_form_width_endian.cpp:
// encoding helpers (91-145), the seven forms (154-241), the four widths and
// two byte orders (241-272). Copied, not re-derived: if a single constant
// moved, this would be a different grid and the truth column below would not
// apply to it. The grid control test proves it did not move.
// ---------------------------------------------------------------------

std::uint64_t Trunc(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64U) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

void PutField(std::vector<std::uint8_t>& buf, std::size_t offset, std::uint64_t value,
              unsigned bit_width, bool big_endian) {
    const unsigned n = bit_width / kBits;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBits * (n - 1U - k)) : (kBits * k);
        buf[offset + k] = static_cast<std::uint8_t>(value >> shift);
    }
}

std::uint64_t GetField(const std::uint8_t* bytes, std::size_t offset, unsigned bit_width,
                       bool big_endian) {
    const unsigned n = bit_width / kBits;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBits * (n - 1U - k)) : (kBits * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

// Independent restatement of the substring search FindFirst performs
// (src/concolic/concolic.cpp:136).
bool Occurs(const std::vector<std::uint8_t>& seed, std::uint64_t value, unsigned bit_width) {
    const unsigned n = bit_width / kBits;
    if (n == 0U || seed.size() < n) {
        return false;
    }
    const std::uint64_t v = Trunc(value, bit_width);
    for (std::size_t off = 0; off + n <= seed.size(); ++off) {
        bool le = true;
        bool be = true;
        for (unsigned k = 0; k < n; ++k) {
            const std::uint8_t byte = seed[off + k];
            if (byte != static_cast<std::uint8_t>(v >> (kBits * k))) {
                le = false;
            }
            if (byte != static_cast<std::uint8_t>(v >> (kBits * (n - 1U - k)))) {
                be = false;
            }
        }
        if (le || be) {
            return true;
        }
    }
    return false;
}

// The compile-time addend of FORM 6, pinned from test_domain_map.cpp:245.
constexpr std::uint64_t kConstAddend = 0x00000010ULL;

std::uint64_t SumOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) + Trunc(b, w), w);
}
std::uint64_t DiffOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) - Trunc(b, w), w);
}
std::uint64_t XorOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) ^ Trunc(b, w), w);
}
std::uint64_t AndOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) & Trunc(b, w), w);
}
std::uint64_t MulOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(Trunc(a, w) * Trunc(b, w), w);
}
std::uint64_t AddConstOf(std::uint64_t a, unsigned w) {
    return Trunc(Trunc(a, w) + Trunc(kConstAddend, w), w);
}
bool LessThanOf(std::uint64_t a, std::uint64_t b, unsigned w) {
    return Trunc(a, w) < Trunc(b, w);
}

enum class FormKind { kAdd, kSub, kXor, kAnd, kMul, kAddConst, kLt };

struct FormSpec {
    FormKind kind;
    const char* name;
    bool lhs_is_verbatim;  ///< true only for `lt`, whose LHS IS a field
};

constexpr std::array<FormSpec, 7> kForms{{
    {FormKind::kAdd, "add", false},
    {FormKind::kSub, "sub", false},
    {FormKind::kXor, "xor", false},
    {FormKind::kAnd, "and", false},
    {FormKind::kMul, "mul", false},
    {FormKind::kAddConst, "add-const", false},
    {FormKind::kLt, "lt", true},
}};

std::uint64_t DerivedOf(FormKind form, std::uint64_t a, std::uint64_t b, unsigned w) {
    switch (form) {
        case FormKind::kAdd:
            return SumOf(a, b, w);
        case FormKind::kSub:
            return DiffOf(a, b, w);
        case FormKind::kXor:
            return XorOf(a, b, w);
        case FormKind::kAnd:
            return AndOf(a, b, w);
        case FormKind::kMul:
            return MulOf(a, b, w);
        case FormKind::kAddConst:
            return AddConstOf(a, w);
        case FormKind::kLt:
            break;
    }
    return Trunc(a, w);
}

bool GateHolds(FormKind form, std::uint64_t a, std::uint64_t b, unsigned w, std::uint64_t magic) {
    if (form == FormKind::kLt) {
        return LessThanOf(a, b, w);
    }
    return DerivedOf(form, a, b, w) == Trunc(magic, w);
}

std::uint8_t PredicateOf(FormKind form) {
    return form == FormKind::kLt ? kUlt : kEq;
}

struct WidthConst {
    unsigned bit_width;
    std::uint64_t field_a;
    std::uint64_t field_b;
    std::uint64_t low;    ///< guard bound, below both fields and absent from the seed
    std::uint64_t magic;  ///< the gate's constant, absent from the seed
};

constexpr WidthConst kW8{
    .bit_width = 8, .field_a = 0x11U, .field_b = 0x22U, .low = 0x05U, .magic = 0x2AU};
constexpr WidthConst kW16{
    .bit_width = 16, .field_a = 0x1122U, .field_b = 0x3344U, .low = 0x0101U, .magic = 0x002AU};
constexpr WidthConst kW32{.bit_width = 32,
                          .field_a = 0x11223344U,
                          .field_b = 0x55667788U,
                          .low = 0x01010101U,
                          .magic = 0x0000002AU};
constexpr WidthConst kW64{.bit_width = 64,
                          .field_a = 0x1122334455667788ULL,
                          .field_b = 0x99AABBCCDDEEFF11ULL,
                          .low = 0x0101010101010101ULL,
                          .magic = 0x000000000000002AULL};

constexpr std::array<WidthConst, 4> kWidths{{kW8, kW16, kW32, kW64}};
constexpr std::array<bool, 2> kByteOrders{{false, true}};

std::vector<std::uint8_t> SeedOf(const WidthConst& w, bool big_endian) {
    const unsigned n = w.bit_width / kBits;
    std::vector<std::uint8_t> seed(static_cast<std::size_t>(2U * n));
    PutField(seed, 0, w.field_a, w.bit_width, big_endian);
    PutField(seed, n, w.field_b, w.bit_width, big_endian);
    return seed;
}

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:348-434
// (task-062).
// ---------------------------------------------------------------------
// THE TRUTH COLUMN. The class published by task-042 for each of the 56
// cells, in the iteration order form-major, then width, then byte order —
// the same order the table of
// docs/experiments/solver-domain-form-width-endian/report.md:170-225 is
// printed in, so index k here is report.md line 170+k. These strings are
// the only thing taken from task-042 by hand; every other number below is
// produced by running the engine.
// ---------------------------------------------------------------------

constexpr std::size_t kCells = 56;
constexpr std::size_t kTruthFirstLine = 170;  ///< report.md line of index 0

constexpr std::array<const char*, kCells> kTruth{{
    // add — report.md:170-177
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    // sub — report.md:178-185
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // xor — report.md:186-193; the u8 pair is the crossroads cell of
    // report.md:111, BOUND and lost at the same time.
    "BOUND+NO-FLIP",
    "BOUND+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // and — report.md:194-201
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // mul — report.md:202-209
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // add-const — report.md:210-217
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    "NO-BINDING+NO-FLIP",
    // lt — report.md:218-225
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
    "BOUND+FLIP",
}};

// The published label reduced to the one bit D and P predict: did the gate's
// derived operand reach the solver as something other than a constant.
// task-042 counts bound=18 = 16 BOUND+FLIP + 2 BOUND+NO-FLIP (report.md:95).
bool TruthBound(std::size_t index) {
    const std::string cls = kTruth[index];
    return cls.rfind("BOUND", 0) == 0;
}

// Copied verbatim from tests/unit/concolic/test_discriminator_residual.cpp:444-567
// (task-057). The two CONTROL grids: bindings that DO overlap by
// construction. Names untouched, bodies untouched.
// ---------------------------------------------------------------------
// CLASSES task053 / task056 — copied from test_binding_overlap.cpp:86-482
// and test_binding_overlap_order.cpp:81-579.
// ---------------------------------------------------------------------

namespace overlap {

constexpr std::size_t kSeedSize = 16;

constexpr std::array<std::uint8_t, kSeedSize> kSeed = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

constexpr std::uint64_t kTarget32 = 0x11223344ULL;
constexpr std::uint64_t kTarget64 = 0x1122334455667788ULL;

std::vector<std::uint8_t> Seed() {
    return {kSeed.begin(), kSeed.end()};
}

// Little-endian read straight from the seed (test_binding_overlap.cpp:119).
std::uint64_t ReadLe(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (kBitsPerByte * k);
    }
    return value;
}

// The order-aware read of task-056 (test_binding_overlap_order.cpp:115).
std::uint64_t ReadSeedField(const std::vector<std::uint8_t>& bytes, std::size_t offset, unsigned n,
                            bool big_endian) {
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << shift;
    }
    return value;
}

struct Row {
    const char* name;
    unsigned wide_bits;
    unsigned narrow_bits;
};

constexpr std::array<Row, 3> kRows = {{
    {"u32+u16", 32U, 16U},
    {"u32+u8", 32U, 8U},
    {"u64+u32", 64U, 32U},
}};

constexpr std::array<std::size_t, 3> kShifts = {1U, 2U, 3U};

// A layout is one point on the two coordinates task-053 left open.
struct Layout {
    const char* name;
    bool reverse;     // narrow field at the LOWER offset
    bool big_endian;  // fields requested through their big-endian encoding
};

constexpr Layout kReverseLe = {"rev-le", true, false};
constexpr Layout kForwardBe = {"fwd-be", false, true};
constexpr Layout kReverseBe = {"rev-be", true, true};

constexpr std::array<Layout, 3> kLayouts = {{kReverseLe, kForwardBe, kReverseBe}};

// test_binding_overlap.cpp:334-357 — the task-053 records.
std::vector<BranchReader::Record> MakeRecords053(std::size_t shift, unsigned wide_bits,
                                                 unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const std::uint64_t a = ReadLe(seed, 0, wide_bits / kBitsPerByte);
    const std::uint64_t b = ReadLe(seed, shift, narrow_bits / kBitsPerByte);
    const std::uint64_t target = wide_bits == 64U ? kTarget64 : kTarget32;
    return {
        {.site_id = 1,
         .predicate = kUgt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b - 1U},
        {.site_id = 2,
         .predicate = kUlt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b + 1U},
        {.site_id = 3,
         .predicate = kEq,
         .bit_width = static_cast<std::uint8_t>(wide_bits),
         .lhs = a,
         .rhs = target},
    };
}

// test_binding_overlap_order.cpp:375-404 — the task-056 records.
std::vector<BranchReader::Record> MakeRecords056(const Layout& layout, std::size_t shift,
                                                 unsigned wide_bits, unsigned narrow_bits) {
    const std::vector<std::uint8_t> seed = Seed();
    const unsigned wide_len = wide_bits / kBitsPerByte;
    const unsigned narrow_len = narrow_bits / kBitsPerByte;
    const std::size_t wide_offset = layout.reverse ? shift : 0U;
    const std::size_t narrow_offset = layout.reverse ? 0U : shift;
    const std::uint64_t a =
        ReadSeedField(seed, wide_offset, wide_len, layout.big_endian && wide_len > 1U);
    const std::uint64_t b =
        ReadSeedField(seed, narrow_offset, narrow_len, layout.big_endian && narrow_len > 1U);
    const std::uint64_t target = wide_bits == 64U ? kTarget64 : kTarget32;
    return {
        {.site_id = 1,
         .predicate = kUgt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b - 1U},
        {.site_id = 2,
         .predicate = kUlt,
         .bit_width = static_cast<std::uint8_t>(narrow_bits),
         .lhs = b,
         .rhs = b + 1U},
        {.site_id = 3,
         .predicate = kEq,
         .bit_width = static_cast<std::uint8_t>(wide_bits),
         .lhs = a,
         .rhs = target},
    };
}

}  // namespace overlap

// Copied verbatim from tests/unit/concolic/test_discriminator_residual.cpp:573-580
// (task-057).
struct VarFact {
    std::size_t offset = 0;
    std::uint8_t bit_width = 0;
    bool big_endian = false;
    std::uint64_t model_value = 0;
    std::uint64_t reread_value = 0;
    bool matches = false;
};

// NEW in task-064. A MEASUREMENT, not a claim about how the grid was built:
// a binding covers the byte range [offset, offset + bit_width/8), and two
// bindings overlap when max(start_i, start_j) < min(end_i, end_j). Counted
// over all unordered pairs.
unsigned OverlappingPairs(const std::vector<VarBinding>& vars) {
    unsigned pairs = 0;
    for (std::size_t i = 0; i < vars.size(); ++i) {
        for (std::size_t j = i + 1U; j < vars.size(); ++j) {
            const std::size_t start_i = vars[i].offset;
            const std::size_t end_i = start_i + (vars[i].bit_width / kBitsPerByte);
            const std::size_t start_j = vars[j].offset;
            const std::size_t end_j = start_j + (vars[j].bit_width / kBitsPerByte);
            if (std::max(start_i, start_j) < std::min(end_i, end_j)) {
                ++pairs;
            }
        }
    }
    return pairs;
}

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:436-466
// (task-062), with the task-064 fields appended at the end and marked.
// ---------------------------------------------------------------------
// One measured cell.
// ---------------------------------------------------------------------

struct Cell {
    std::size_t index = 0;
    FormKind form = FormKind::kAdd;
    unsigned bit_width = 0;
    bool big_endian = false;

    // Read out of the run, never assumed.
    Operand::Kind derived_kind = Operand::Kind::kConst;  ///< from the PROBE system
    std::size_t num_vars = 0;
    std::size_t path_size = 0;
    std::size_t target_index = 0;
    bool invertible = false;
    bool gate_survived = false;
    SolveOutcome outcome = SolveOutcome::kError;
    SolveResult::Status status = SolveResult::Status::kError;
    bool has_candidate = false;
    bool guards_hold_end_to_end = false;
    bool gate_flipped_end_to_end = false;
    bool gate_taken_on_seed = false;
    bool derived_findable = false;

    // The two predictions and the truth they are scored against.
    bool d = false;
    bool p = false;
    bool truth_bound = false;
    std::string built_class;  ///< the class recomputed here, for the grid control

    // NEW in task-064: the write-back audit and the overlap measurement.
    std::vector<VarFact> vars;     ///< model vs re-read, per binding
    unsigned mismatched_vars = 0;  ///< bindings whose re-read value != model
    bool model_mismatch = false;   ///< mismatched_vars > 0U
    bool overlapping = false;      ///< overlapping_pairs > 0
    unsigned overlapping_pairs = 0;
    // Kept so the negative self-check can re-read the same bytes with the
    // same ReadBinding after corrupting one of them.
    std::vector<std::uint8_t> candidate_bytes;  ///< the replayed write-back, empty when no model
    std::vector<VarBinding> bindings;           ///< sys.vars of this cell
};

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:510-528
// (task-062).
const char* NameOf(FormKind form) {
    for (const FormSpec& spec : kForms) {
        if (spec.kind == form) {
            return spec.name;
        }
    }
    return "?";
}

// The cell's class, recomputed exactly as task-042 computes it
// (test_domain_form_width_endian.cpp:426-431). This is the grid control:
// if this string differs from kTruth[index], the grid built here is not
// task-042's grid and no agreement number below means anything.
std::string ClassOf(const Cell& cell) {
    const bool bound = cell.derived_kind != Operand::Kind::kConst;
    std::string cls = bound ? "BOUND" : "NO-BINDING";
    cls += cell.gate_flipped_end_to_end ? "+FLIP" : "+NO-FLIP";
    return cls;
}

// Copied verbatim from tests/unit/concolic/test_discriminator_width_endian.cpp:530-626
// (task-062), with the task-064 write-back audit and overlap measurement
// inserted in the SAME branch that already computes P, and marked as such.
Cell Measure(std::size_t index, FormKind form, const WidthConst& w, bool big_endian) {
    const unsigned bw = w.bit_width;
    const unsigned n = bw / kBits;
    const std::vector<std::uint8_t> seed = SeedOf(w, big_endian);
    const auto width_byte = static_cast<std::uint8_t>(bw);

    const std::uint64_t derived = DerivedOf(form, w.field_a, w.field_b, bw);
    const std::uint64_t rhs = form == FormKind::kLt ? Trunc(w.field_b, bw) : Trunc(w.magic, bw);

    const std::vector<BranchReader::Record> guards = {
        {0, kUgt, width_byte, w.field_a, w.low},
        {1, kUgt, width_byte, w.field_b, w.low},
    };

    std::vector<BranchReader::Record> records = guards;
    records.push_back({2, PredicateOf(form), width_byte, derived, rhs});

    std::vector<BranchReader::Record> probe = guards;
    probe.push_back({2, kEq, width_byte, derived, w.field_b});

    Cell cell{};
    cell.index = index;
    cell.form = form;
    cell.bit_width = bw;
    cell.big_endian = big_endian;

    // derived_kind comes from the PROBE system, the same way task-042 reads
    // it (test_domain_form_width_endian.cpp:336-340).
    const System probe_sys = BuildSystem(seed, probe);
    if (probe_sys.path.empty()) {
        ADD_FAILURE() << "probe system kept no constraint — the probe fixture itself is broken";
    } else {
        cell.derived_kind = probe_sys.path.back().lhs.kind;
    }

    const System sys = BuildSystem(seed, records);
    cell.num_vars = sys.num_vars;
    cell.path_size = sys.path.size();
    cell.target_index = sys.target_index;
    cell.invertible = sys.invertible;
    cell.gate_survived = sys.path.size() == records.size();
    cell.gate_taken_on_seed = GateHolds(form, w.field_a, w.field_b, bw, w.magic);
    cell.derived_findable = Occurs(seed, derived, bw);

    // NEW in task-064: the overlap of the bindings this cell actually built.
    cell.bindings = sys.vars;
    cell.overlapping_pairs = OverlappingPairs(sys.vars);
    cell.overlapping = cell.overlapping_pairs > 0U;

    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();
    if (candidate.has_value() && candidate->size() >= seed.size()) {
        const std::uint64_t a = GetField(candidate->data(), 0, bw, big_endian);
        const std::uint64_t b = GetField(candidate->data(), n, bw, big_endian);
        const std::uint64_t low = Trunc(w.low, bw);
        cell.guards_hold_end_to_end = a > low && b > low;
        cell.gate_flipped_end_to_end =
            GateHolds(form, a, b, bw, w.magic) != cell.gate_taken_on_seed;
    }

    // D — applied to what the run produced, not to what the table says.
    cell.d = Discriminator(cell.derived_kind, cell.gate_survived);

    // P, copied from test_discriminator_residual.cpp:646-679 together with
    // its two guards: without them P is false by construction.
    if (sys.invertible && !sys.path.empty()) {
        const SolveResult result =
            SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMs);
        cell.status = result.status;
        if (result.status == SolveResult::Status::kSat &&
            result.model_values.size() == sys.num_vars) {
            const std::vector<std::uint8_t> reread = WriteBackModel(seed, sys, result.model_values);
            // NEW in task-064, after the same write-back and before P, by the
            // pattern of test_discriminator_residual.cpp:658-671: does the
            // write-back lose anything on THIS grid?
            cell.candidate_bytes = reread;
            for (std::size_t k = 0; k < sys.vars.size(); ++k) {
                const std::uint64_t model = Truncate(result.model_values[k], sys.vars[k].bit_width);
                const std::uint64_t reread_value = ReadBinding(cell.candidate_bytes, sys.vars[k]);
                cell.vars.push_back({.offset = sys.vars[k].offset,
                                     .bit_width = sys.vars[k].bit_width,
                                     .big_endian = sys.vars[k].big_endian,
                                     .model_value = model,
                                     .reread_value = reread_value,
                                     .matches = model == reread_value});
                if (model != reread_value) {
                    ++cell.mismatched_vars;
                }
            }
            cell.model_mismatch = cell.mismatched_vars > 0U;
            // THE POST-CHECK P: the inverted target predicate on the values
            // RE-READ from the candidate, i.e. after the write-back rather
            // than before it.
            const unsigned target_width = sys.path[sys.target_index].bit_width;
            cell.p = Eval(Negate(sys.path[sys.target_index].predicate),
                          OperandValue(sys.path[sys.target_index].lhs, sys, reread, target_width),
                          OperandValue(sys.path[sys.target_index].rhs, sys, reread, target_width),
                          target_width);
        }
    }

    cell.truth_bound = TruthBound(index);
    cell.built_class = ClassOf(cell);
    return cell;
}

std::vector<Cell> BuildGrid() {
    std::vector<Cell> cells;
    cells.reserve(kCells);
    std::size_t index = 0;
    for (const FormSpec& spec : kForms) {
        for (const WidthConst& w : kWidths) {
            for (const bool big_endian : kByteOrders) {
                cells.push_back(Measure(index, spec.kind, w, big_endian));
                ++index;
            }
        }
    }
    return cells;
}

// ---------------------------------------------------------------------
// NEW in task-064: the control grids, the printing and the tallies.
// ---------------------------------------------------------------------

// One cell of a CONTROL grid (task-053 / task-056). Only what this
// question needs: how many bindings, how many of their byte ranges
// overlap, and what the write-back lost.
struct ControlCell {
    std::string cls;
    std::string id;
    std::size_t num_vars = 0;
    unsigned overlapping_pairs = 0;
    unsigned mismatched_vars = 0;
    bool model_mismatch = false;
    bool p = false;
    bool gate_taken = false;
};

ControlCell MeasureControl(const char* cls, const std::string& id,
                           const std::vector<std::uint8_t>& seed,
                           const std::vector<BranchReader::Record>& recs) {
    ControlCell cell;
    cell.cls = cls;
    cell.id = id;

    const System sys = BuildSystem(seed, recs);
    cell.num_vars = sys.num_vars;
    cell.overlapping_pairs = OverlappingPairs(sys.vars);

    if (!sys.invertible || sys.path.empty()) {
        return cell;  // P stays false, nothing was written back
    }
    const SolveResult result = SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMs);
    if (result.status != SolveResult::Status::kSat || result.model_values.size() != sys.num_vars) {
        return cell;  // P stays false
    }

    const std::vector<std::uint8_t> candidate = WriteBackModel(seed, sys, result.model_values);
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const std::uint64_t model = Truncate(result.model_values[k], sys.vars[k].bit_width);
        const std::uint64_t reread = ReadBinding(candidate, sys.vars[k]);
        if (model != reread) {
            ++cell.mismatched_vars;
        }
    }
    cell.model_mismatch = cell.mismatched_vars > 0U;

    const unsigned target_width = sys.path[sys.target_index].bit_width;
    cell.p = Eval(Negate(sys.path[sys.target_index].predicate),
                  OperandValue(sys.path[sys.target_index].lhs, sys, candidate, target_width),
                  OperandValue(sys.path[sys.target_index].rhs, sys, candidate, target_width),
                  target_width);
    // The truth column of task-053/task-056 is GateOnCandidate
    // (test_discriminator_residual.cpp:690-700) — literally the SAME
    // expression as P above, on the same bytes. It is printed as a corpus
    // identity cross-check against
    // docs/experiments/solver-discriminator-residual/report.md:91
    // (gate_taken=18/27 on task-056), NOT as an independent oracle.
    cell.gate_taken = cell.p;
    return cell;
}

std::vector<ControlCell> CollectTask053() {
    std::vector<ControlCell> cells;
    const std::vector<std::uint8_t> seed = overlap::Seed();
    for (const overlap::Row& row : overlap::kRows) {
        for (const std::size_t shift : overlap::kShifts) {
            const std::string id = std::string(row.name) + "-d" + std::to_string(shift);
            cells.push_back(
                MeasureControl("task053", id, seed,
                               overlap::MakeRecords053(shift, row.wide_bits, row.narrow_bits)));
        }
    }
    return cells;
}

std::vector<ControlCell> CollectTask056() {
    std::vector<ControlCell> cells;
    const std::vector<std::uint8_t> seed = overlap::Seed();
    for (const overlap::Layout& layout : overlap::kLayouts) {
        for (const overlap::Row& row : overlap::kRows) {
            for (const std::size_t shift : overlap::kShifts) {
                const std::string id =
                    std::string(layout.name) + "-" + row.name + "-d" + std::to_string(shift);
                cells.push_back(MeasureControl(
                    "task056", id, seed,
                    overlap::MakeRecords056(layout, shift, row.wide_bits, row.narrow_bits)));
            }
        }
    }
    return cells;
}

struct ControlTotals {
    unsigned cells = 0;
    unsigned model_mismatch_cells = 0;
    unsigned overlapping_cells = 0;
    unsigned gate_taken = 0;
};

ControlTotals TallyControl(const std::vector<ControlCell>& cells) {
    ControlTotals totals;
    for (const ControlCell& cell : cells) {
        ++totals.cells;
        totals.model_mismatch_cells += cell.model_mismatch ? 1U : 0U;
        totals.overlapping_cells += cell.overlapping_pairs > 0U ? 1U : 0U;
        totals.gate_taken += cell.gate_taken ? 1U : 0U;
    }
    return totals;
}

void PrintControl(const ControlCell& cell) {
    std::cout << "PDEG-CONTROL class=" << cell.cls << " id=" << cell.id
              << " num_vars=" << cell.num_vars << " overlapping_pairs=" << cell.overlapping_pairs
              << " mismatched_vars=" << cell.mismatched_vars
              << " model_mismatch=" << YesNo(cell.model_mismatch) << " P=" << BoundName(cell.p)
              << "\n";
}

void PrintControlTotals(const char* cls, const ControlTotals& totals) {
    std::cout << "PDEG-CONTROL-TOTALS class=" << cls << " cells=" << totals.cells
              << " model_mismatch_cells=" << totals.model_mismatch_cells
              << " overlapping_cells=" << totals.overlapping_cells
              << " gate_taken=" << totals.gate_taken << "\n";
}

void PrintVars(const Cell& cell) {
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        const VarFact& var = cell.vars[k];
        std::cout << "PDEG-VAR idx=" << cell.index << " form=" << NameOf(cell.form) << " width=u"
                  << cell.bit_width << " endian=" << (cell.big_endian ? "BE" : "LE") << " k=" << k
                  << " offset=" << var.offset << " bit_width=" << unsigned{var.bit_width}
                  << " big_endian=" << YesNo(var.big_endian) << " byte_lo=" << var.offset
                  << " byte_hi=" << (var.offset + (var.bit_width / kBitsPerByte))
                  << " model_value=" << var.model_value << " reread_value=" << var.reread_value
                  << " matches=" << YesNo(var.matches) << "\n";
    }
}

void PrintCell(const Cell& cell) {
    std::cout << "PDEG-CELL idx=" << cell.index << " form=" << NameOf(cell.form) << " width=u"
              << cell.bit_width << " endian=" << (cell.big_endian ? "BE" : "LE")
              << " num_vars=" << cell.num_vars << " overlapping_pairs=" << cell.overlapping_pairs
              << " overlapping=" << YesNo(cell.overlapping)
              << " mismatched_vars=" << cell.mismatched_vars
              << " model_mismatch=" << YesNo(cell.model_mismatch) << " P=" << BoundName(cell.p)
              << " truth=" << BoundName(cell.truth_bound)
              << " P_agrees=" << YesNo(cell.p == cell.truth_bound)
              << " built_class=" << cell.built_class << " truth_class=" << kTruth[cell.index]
              << " grid_matches=" << YesNo(cell.built_class == kTruth[cell.index])
              << " truth_pin=report.md:" << (kTruthFirstLine + cell.index) << "\n";
}

struct GridTotals {
    unsigned p_true_cells = 0;
    unsigned p_false_cells = 0;
    unsigned p_agrees = 0;
    unsigned overlapping_cells = 0;
    unsigned model_mismatch_cells = 0;
    unsigned mismatched_vars_total = 0;
    unsigned grid_matches = 0;
};

GridTotals TallyGrid(const std::vector<Cell>& cells) {
    GridTotals totals;
    for (const Cell& cell : cells) {
        totals.p_true_cells += cell.p ? 1U : 0U;
        totals.p_false_cells += cell.p ? 0U : 1U;
        totals.p_agrees += cell.p == cell.truth_bound ? 1U : 0U;
        totals.overlapping_cells += cell.overlapping ? 1U : 0U;
        totals.model_mismatch_cells += cell.model_mismatch ? 1U : 0U;
        totals.mismatched_vars_total += cell.mismatched_vars;
        totals.grid_matches += cell.built_class == kTruth[cell.index] ? 1U : 0U;
    }
    return totals;
}

// The write-back audit re-run on arbitrary bytes: the model values of the
// cell are fixed, the bytes they are re-read from are the argument. This is
// what lets the negative self-check corrupt a candidate and see the counter
// move.
unsigned MismatchesOn(const Cell& cell, const std::vector<std::uint8_t>& bytes) {
    if (cell.vars.size() != cell.bindings.size()) {
        ADD_FAILURE() << "cell " << cell.index << ": vars/bindings size mismatch";
        return 0;
    }
    unsigned bad = 0;
    for (std::size_t k = 0; k < cell.vars.size(); ++k) {
        if (cell.vars[k].model_value != ReadBinding(bytes, cell.bindings[k])) {
            ++bad;
        }
    }
    return bad;
}

}  // namespace

// THE GRID CONTROL, replayed from task-062
// (test_discriminator_width_endian.cpp:746-767). A precondition, not a
// finding: if one cell's recomputed class differs from the class task-042
// published, this harness measures a DIFFERENT grid and every number below
// is void.
TEST(PDegeneracy, BuiltGridIsTheSameGridAsTask042) {
    const std::vector<Cell> cells = BuildGrid();
    ASSERT_EQ(cells.size(), kCells);
    const GridTotals totals = TallyGrid(cells);
    for (const Cell& cell : cells) {
        EXPECT_EQ(cell.built_class, std::string(kTruth[cell.index]))
            << "cell " << NameOf(cell.form) << "/u" << cell.bit_width << "/"
            << (cell.big_endian ? "BE" : "LE")
            << " does not match report.md:" << (kTruthFirstLine + cell.index);
    }
    EXPECT_EQ(totals.grid_matches, 56U);
}

// THE INSTRUMENT CONTROL. mismatched_vars is the only channel through which
// P can differ from "the solver said SAT"; a green zero on the task-042 grid
// is worthless unless the same counter is shown to redden where the
// write-back really does lose bytes. The two grids where it does are not
// invented here: they are task-053 (9 cells) and task-056 (27 cells),
// replayed verbatim, with the numbers their own harness asserts.
TEST(PDegeneracy, OverlappingControlGridsRedenTheMismatchCounter) {
    const std::vector<ControlCell> cells053 = CollectTask053();
    const std::vector<ControlCell> cells056 = CollectTask056();
    for (const ControlCell& cell : cells053) {
        PrintControl(cell);
    }
    for (const ControlCell& cell : cells056) {
        PrintControl(cell);
    }
    const ControlTotals t053 = TallyControl(cells053);
    const ControlTotals t056 = TallyControl(cells056);
    PrintControlTotals("task053", t053);
    PrintControlTotals("task056", t056);
    std::cout << "PDEG-CONTROL-NOTE t056_cells=27 t056_gate_taken=" << t056.gate_taken
              << " queue_denominator_said=18 reason=gate_taken_not_grid_size\n";

    ASSERT_EQ(cells053.size(), 9U);
    ASSERT_EQ(cells056.size(), 27U);
    // test_discriminator_residual.cpp:921 — task-053: all 9 cells mismatch.
    EXPECT_EQ(t053.model_mismatch_cells, 9U);
    // test_discriminator_residual.cpp:923 — task-056: 17 of 27 mismatch.
    EXPECT_EQ(t056.model_mismatch_cells, 17U);
}

// THE NEGATIVE SELF-CHECK, on the task-042 grid itself rather than on a
// foreign one: corrupt a single byte of a candidate INSIDE the byte range of
// its first binding and the same counter that reads zero on the untouched
// candidate must move off zero. Without this, "model_mismatch_cells=0" would
// be indistinguishable from a counter that cannot count.
TEST(PDegeneracy, FlippedCandidateByteTurnsMatchIntoMismatch) {
    const std::vector<Cell> cells = BuildGrid();
    ASSERT_EQ(cells.size(), kCells);

    const Cell* chosen = nullptr;
    for (const Cell& cell : cells) {
        if (!cell.candidate_bytes.empty() && !cell.bindings.empty() && !cell.vars.empty()) {
            chosen = &cell;
            break;
        }
    }
    ASSERT_NE(chosen, nullptr) << "no cell on the task-042 grid produced a written-back candidate";

    const std::size_t flipped_offset = chosen->bindings[0].offset;
    ASSERT_LT(flipped_offset, chosen->candidate_bytes.size());
    std::vector<std::uint8_t> flipped = chosen->candidate_bytes;
    flipped[flipped_offset] = static_cast<std::uint8_t>(flipped[flipped_offset] ^ 0xFFU);

    const unsigned clean = MismatchesOn(*chosen, chosen->candidate_bytes);
    const unsigned broken = MismatchesOn(*chosen, flipped);
    std::cout << "PDEG-NEGATIVE idx=" << chosen->index << " mismatched_vars_clean=" << clean
              << " mismatched_vars_flipped=" << broken << " flipped_offset=" << flipped_offset
              << "\n";

    EXPECT_EQ(clean, 0U);
    EXPECT_GT(broken, 0U);
}

// The table itself. The assertions are only on published, reproducible
// numbers; p_true_cells and model_mismatch_cells are the MEASURED outcome of
// the question and are printed, not asserted.
TEST(PDegeneracy, PredictorDegeneracyTableIsEmitted) {
    const std::vector<Cell> cells = BuildGrid();
    ASSERT_EQ(cells.size(), kCells);

    for (const Cell& cell : cells) {
        PrintVars(cell);
    }
    for (const Cell& cell : cells) {
        PrintCell(cell);
    }

    const GridTotals totals = TallyGrid(cells);
    std::cout << "PDEG-TOTALS cells=" << cells.size() << " p_true_cells=" << totals.p_true_cells
              << " p_false_cells=" << totals.p_false_cells << " p_agrees=" << totals.p_agrees
              << " overlapping_cells=" << totals.overlapping_cells
              << " model_mismatch_cells=" << totals.model_mismatch_cells
              << " mismatched_vars_total=" << totals.mismatched_vars_total
              << " grid_matches=" << totals.grid_matches << "/" << kCells << "\n";

    // The controls are recomputed here (silently — they print in their own
    // test) so the VERDICT line cannot claim a working instrument while the
    // instrument control is red.
    const ControlTotals t053 = TallyControl(CollectTask053());
    const ControlTotals t056 = TallyControl(CollectTask056());
    const bool reddens = t053.model_mismatch_cells > 0U && t056.model_mismatch_cells > 0U;
    const bool p_constant = totals.p_true_cells == kCells;
    const bool explained = p_constant && totals.model_mismatch_cells == 0U &&
                           totals.overlapping_cells == 0U && reddens;

    std::cout << "VERDICT: P-DEGENERACY: cells=" << cells.size()
              << ", grid=7x4x2, truth_source=task-042, truth_table_matches_task042="
              << YesNo(totals.grid_matches == kCells) << ", p_true_cells=" << totals.p_true_cells
              << "/56, p_constant=" << YesNo(p_constant)
              << ", p_agrees_matches_task062=" << YesNo(totals.p_agrees == 18U)
              << ", overlapping_cells=" << totals.overlapping_cells
              << ", model_mismatch_cells=" << totals.model_mismatch_cells
              << ", mismatched_vars_total=" << totals.mismatched_vars_total
              << ", control_t053_model_mismatch=" << t053.model_mismatch_cells
              << "/9, control_t056_model_mismatch=" << t056.model_mismatch_cells
              << "/27, control_instrument_reddens=" << YesNo(reddens)
              << ", explanation_confirmed=" << YesNo(explained)
              << ", src_modified=0, new_fuzzing_runs=0, reports_modified=0\n";

    // docs/experiments/solver-discriminator-width-endian/report.md:19 — P
    // agreed with the task-042 label on 18 of the 56 cells.
    EXPECT_EQ(totals.p_agrees, 18U);
    EXPECT_EQ(cells.size(), kCells);
}
