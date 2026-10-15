// SPDX-License-Identifier: MIT
#include "binding_provider.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>
namespace mlfuzzz3::concolic {
namespace {
// fuzzer_rt_cmp_kind values (ADR 0033, fixed ABI).
enum CmpKind : std::uint8_t {
    kEq = 0,
    kNe = 1,
    kUlt = 2,
    kUle = 3,
    kUgt = 4,
    kUge = 5,
    kSlt = 6,
    kSle = 7,
    kSgt = 8,
    kSge = 9,
};

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kMaxBvWidth = 64;

std::uint64_t TruncateToWidth(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= kMaxBvWidth) {
        return value;
    }
    return value & ((std::uint64_t{1} << bit_width) - 1U);
}

bool ByteWidthValid(unsigned bit_width) {
    return bit_width != 0 && bit_width <= kMaxBvWidth && (bit_width % kBitsPerByte) == 0;
}

// Read a bit_width-bit field from `seed` at `offset` in the given
// endianness.
std::uint64_t ReadField(std::span<const std::uint8_t> seed, const VarBinding& field) {
    const unsigned n = field.bit_width / kBitsPerByte;
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift =
            field.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(seed[field.offset + k]) << shift;
    }
    return value;
}

struct Match {
    std::size_t offset;
    bool big_endian;
};

// Find the first byte offset (ascending; little-endian before big-endian)
// where `value`'s bit_width/8-byte encoding occurs as a substring of
// `seed`. Returns nullopt if not present or the width is not byte-aligned.
std::optional<Match> FindFirst(std::span<const std::uint8_t> seed, std::uint64_t value,
                               unsigned bit_width, const std::function<bool()>& cancelled) {
    if (!ByteWidthValid(bit_width)) {
        return std::nullopt;
    }
    const unsigned n = bit_width / kBitsPerByte;
    if (seed.size() < n) {
        return std::nullopt;
    }
    const std::uint64_t v = TruncateToWidth(value, bit_width);
    for (std::size_t off = 0; off + n <= seed.size(); ++off) {
        constexpr std::size_t kCancellationStride = 4096;
        if (off % kCancellationStride == 0 && cancelled && cancelled()) {
            return std::nullopt;
        }
        bool le = true;
        bool be = true;
        for (unsigned k = 0; k < n; ++k) {
            const auto byte = static_cast<std::uint8_t>(seed[off + k]);
            if (byte != static_cast<std::uint8_t>(v >> (kBitsPerByte * k))) {
                le = false;
            }
            if (byte != static_cast<std::uint8_t>(v >> (kBitsPerByte * (n - 1U - k)))) {
                be = false;
            }
        }
        if (le) {
            return Match{.offset = off, .big_endian = false};
        }
        if (be) {
            return Match{.offset = off, .big_endian = true};
        }
    }
    return std::nullopt;
}

// Индекс значений сида (ADR 0049, F1). `FindFirst` сканирует весь вход на
// КАЖДЫЙ операнд КАЖДОЙ записи, и развёртка E3 показала, что именно это, а
// не перебор пар, несёт цену построения системы (медиана 9745 мс,
// docs/experiments/solver-build-cost/report.md). Индекс строится один раз
// за проход по сиду и отвечает на тот же вопрос поиском в таблице.
//
// Правило выбора совпадения сохраняется побайтно: наименьшее смещение, при
// равном смещении little-endian прежде big-endian. Оно получается само,
// если заполнять таблицу по возрастанию смещения и на каждом смещении
// класть сначала LE, потом BE, а повторные ключи игнорировать.
//
// Цена — память: для входа длиной S таблицы держат до 8S записей (четыре
// ширины на два порядка байт). На сидах libtiff это единицы мегабайт.
class SeedIndex {
   public:
    explicit SeedIndex(std::span<const std::uint8_t> seed, const std::function<bool()>& cancelled) {
        for (const unsigned n : {1U, 2U, 4U, 8U}) {
            if (seed.size() < n) {
                continue;
            }
            std::unordered_map<std::uint64_t, Match>& table = tables_.at(Slot(n));
            table.reserve(2 * (seed.size() - n + 1));
            for (std::size_t off = 0; off + n <= seed.size(); ++off) {
                constexpr std::size_t kCancellationStride = 4096;
                if (off % kCancellationStride == 0 && cancelled && cancelled()) {
                    return;
                }
                std::uint64_t le = 0;
                std::uint64_t be = 0;
                for (unsigned k = 0; k < n; ++k) {
                    const auto byte = static_cast<std::uint64_t>(seed[off + k]);
                    le |= byte << (kBitsPerByte * k);
                    be |= byte << (kBitsPerByte * (n - 1U - k));
                }
                table.try_emplace(le, Match{.offset = off, .big_endian = false});
                table.try_emplace(be, Match{.offset = off, .big_endian = true});
            }
        }
    }

    [[nodiscard]] std::optional<Match> Find(std::uint64_t value, unsigned bit_width) const {
        if (!ByteWidthValid(bit_width)) {
            return std::nullopt;
        }
        const std::unordered_map<std::uint64_t, Match>& table =
            tables_.at(Slot(bit_width / kBitsPerByte));
        const auto it = table.find(TruncateToWidth(value, bit_width));
        if (it == table.end()) {
            return std::nullopt;
        }
        return it->second;
    }

   private:
    static std::size_t Slot(unsigned byte_width) {
        switch (byte_width) {
            case 1:
                return 0;
            case 2:
                return 1;
            case 4:
                return 2;
            default:
                return 3;
        }
    }

    std::array<std::unordered_map<std::uint64_t, Match>, 4> tables_;
};

// Единственная точка поиска значения во входе: через индекс, когда он есть
// (F1), иначе прежним сканированием.
std::optional<Match> FindValue(std::span<const std::uint8_t> seed, const SeedIndex* index,
                               std::uint64_t value, unsigned bit_width,
                               const std::function<bool()>& cancelled) {
    if (cancelled && cancelled()) {
        return std::nullopt;
    }
    if (index != nullptr) {
        return index->Find(value, bit_width);
    }
    return FindFirst(seed, value, bit_width, cancelled);
}

solver::Operand MakeVar(std::size_t index) {
    return {
        .kind = solver::Operand::Kind::kVar, .var_index = index, .var_index2 = 0, .const_value = 0};
}
solver::Operand MakeConst(std::uint64_t value) {
    return {.kind = solver::Operand::Kind::kConst,
            .var_index = 0,
            .var_index2 = 0,
            .const_value = value};
}
solver::Operand MakeAdd(std::size_t i, std::size_t j) {
    return {
        .kind = solver::Operand::Kind::kAddVars, .var_index = i, .var_index2 = j, .const_value = 0};
}

// Bind one operand value to a field (ADR 0035 §2): DIRECT findable ->
// kVar; else SUM of two findable fields -> kAddVars; else kConst.
solver::Operand BindOperand(std::span<const std::uint8_t> seed, std::uint64_t value,
                            unsigned bit_width, const std::vector<VarBinding>& vars,
                            const std::unordered_map<std::size_t, std::size_t>& offset_to_index,
                            const Fixes& fixes, const SeedIndex* index) {
    if (const std::optional<Match> direct =
            FindValue(seed, index, value, bit_width, fixes.cancelled)) {
        const auto it = offset_to_index.find(direct->offset);
        if (it != offset_to_index.end()) {
            return MakeVar(it->second);
        }
    }
    const std::uint64_t target = TruncateToWidth(value, bit_width);
    for (std::size_t i = 0; i < vars.size(); ++i) {
        if (fixes.cancelled && fixes.cancelled()) {
            return MakeConst(0);
        }
        for (std::size_t j = i; j < vars.size(); ++j) {
            constexpr std::size_t kCancellationStride = 4096;
            if ((j - i) % kCancellationStride == 0 && fixes.cancelled && fixes.cancelled()) {
                return MakeConst(0);
            }
            if (fixes.strict_addvars) {
                // F2 (ADR 0049). Вырожденная «сумма» ничего не связывает:
                // i == j это удвоение одного поля, а нулевое слагаемое даёт
                // тождество x + 0 = x. Перепись E2 нашла такими 67.94 %
                // всех kAddVars (docs/experiments/solver-binding-census/).
                if (i == j || ReadField(seed, vars[i]) == 0 || ReadField(seed, vars[j]) == 0) {
                    continue;
                }
            }
            const std::uint64_t sum =
                TruncateToWidth(TruncateToWidth(ReadField(seed, vars[i]), bit_width) +
                                    TruncateToWidth(ReadField(seed, vars[j]), bit_width),
                                bit_width);
            if (sum == target) {
                return MakeAdd(i, j);
            }
        }
    }
    return MakeConst(target);
}

}  // namespace
// ValueMatchBinding (ADR 0050): сессии нужны закрытые функции поиска
// и привязки выше. Реализация не зависит от библиотеки решателя.
namespace {

class ValueMatchSession final : public BindingProvider::Session {
   public:
    ValueMatchSession(std::span<const std::uint8_t> seed, Fixes fixes)
        : seed_(seed), fixes_(std::move(fixes)) {
        // F1 (ADR 0049): индекс строится один раз на весь разбор и заменяет
        // сканирование входа в обоих проходах. Без флага указатель нулевой,
        // и поиск идёт прежним путём.
        if (fixes_.findfirst_index) {
            index_.emplace(seed_, fixes_.cancelled);
        }
    }

    [[nodiscard]] std::optional<VarBinding> Locate(std::uint64_t value,
                                                   unsigned bit_width) const override {
        const std::optional<Match> m =
            FindValue(seed_, IndexPtr(), value, bit_width, fixes_.cancelled);
        if (!m.has_value()) {
            return std::nullopt;
        }
        return VarBinding{.offset = m->offset,
                          .bit_width = static_cast<std::uint8_t>(bit_width),
                          .big_endian = m->big_endian};
    }

    [[nodiscard]] solver::Operand Bind(
        std::uint64_t value, unsigned bit_width, const std::vector<VarBinding>& vars,
        const std::unordered_map<std::size_t, std::size_t>& offset_to_index) const override {
        return BindOperand(seed_, value, bit_width, vars, offset_to_index, fixes_, IndexPtr());
    }

   private:
    [[nodiscard]] const SeedIndex* IndexPtr() const {
        return index_.has_value() ? &index_.value() : nullptr;
    }

    std::span<const std::uint8_t> seed_;
    Fixes fixes_;
    std::optional<SeedIndex> index_;
};

}  // namespace

// Sign-extend the low bit_width bits of v to signed 64-bit (C++20:
// arithmetic right shift on signed integers). value-then-width order.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::int64_t SignExtend(std::uint64_t v, unsigned bit_width) {
    if (bit_width == 0 || bit_width >= kMaxBvWidth) {
        return static_cast<std::int64_t>(v);
    }
    const unsigned shift = kMaxBvWidth - bit_width;
    return static_cast<std::int64_t>(v << shift) >> shift;
}

// Evaluate a logged comparison on its operand values (the observed,
// "as-taken" outcome on the seed path). Mirrors SolverFacade's predicate
// semantics.
bool evaluate_comparison(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs,
                         unsigned bit_width) {
    const std::uint64_t l = TruncateToWidth(lhs, bit_width);
    const std::uint64_t r = TruncateToWidth(rhs, bit_width);
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
        case kSlt:
            return SignExtend(l, bit_width) < SignExtend(r, bit_width);
        case kSle:
            return SignExtend(l, bit_width) <= SignExtend(r, bit_width);
        case kSgt:
            return SignExtend(l, bit_width) > SignExtend(r, bit_width);
        case kSge:
            return SignExtend(l, bit_width) >= SignExtend(r, bit_width);
        default:
            return false;
    }
}

std::unique_ptr<BindingProvider::Session> ValueMatchBinding::Open(
    std::span<const std::uint8_t> seed, const Fixes& fixes) const {
    return std::make_unique<ValueMatchSession>(seed, fixes);
}

}  // namespace mlfuzzz3::concolic
