// Привязка операндов сравнения к полям входа за интерфейсом (ADR 0050,
// «Решение»). BuildSystem спрашивает провайдера, от каких байтов входа
// зависит значение операнда (проход 1) и каким операндом солвера его
// представить (проход 2). Единственная реализация — ValueMatchBinding:
// прежнее сопоставление значения с байтами сида (ADR 0035 §2), с индексом
// F1 и запретом вырожденных сумм F2 из ADR 0049. Провайдер едет в
// BuildSystem полем `Fixes::binding`; нулевой указатель — ValueMatchBinding.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "concolic.h"
#include "solver_facade.h"

namespace mlfuzzz3::concolic {

/// Способ привязать операнды записей сравнения к полям входа.
class BindingProvider {
   public:
    /// Привязка на одном сиде. Открывается на весь разбор BuildSystem, так
    /// что подготовку под сид (например, индекс входа) провайдер делает один
    /// раз.
    class Session {
       public:
        Session() = default;
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;
        Session(Session&&) = delete;
        Session& operator=(Session&&) = delete;
        virtual ~Session() = default;

        /// Зависимость значения от входа — смещение, ширина и порядок байт
        /// поля, из которого значение взято; `std::nullopt`, если значение
        /// не привязывается к входу напрямую. Проход 1 заводит переменные
        /// по этим зависимостям, упорядочивая их по смещению.
        [[nodiscard]] virtual std::optional<VarBinding> Locate(std::uint64_t value,
                                                               unsigned bit_width) const = 0;

        /// Операнд солвера для значения над уже заведёнными переменными:
        /// `vars` — переменные системы, `offset_to_index` — их индексы по
        /// смещению.
        [[nodiscard]] virtual solver::Operand Bind(
            std::uint64_t value, unsigned bit_width, const std::vector<VarBinding>& vars,
            const std::unordered_map<std::size_t, std::size_t>& offset_to_index) const = 0;
    };

    BindingProvider() = default;
    BindingProvider(const BindingProvider&) = delete;
    BindingProvider& operator=(const BindingProvider&) = delete;
    BindingProvider(BindingProvider&&) = delete;
    BindingProvider& operator=(BindingProvider&&) = delete;
    virtual ~BindingProvider() = default;

    /// Открыть привязку на `seed`. `seed` обязан пережить сессию.
    [[nodiscard]] virtual std::unique_ptr<Session> Open(std::span<const std::uint8_t> seed,
                                                        const Fixes& fixes) const = 0;
};

/// Сопоставление по значению (ADR 0035 §2): операнд — прямая находка его
/// кодировки во входе (`kVar`), иначе сумма двух найденных полей
/// (`kAddVars`), иначе константа. Из `fixes` читает `findfirst_index` (F1)
/// и `strict_addvars` (F2).
class ValueMatchBinding final : public BindingProvider {
   public:
    [[nodiscard]] std::unique_ptr<Session> Open(std::span<const std::uint8_t> seed,
                                                const Fixes& fixes) const override;
};

}  // namespace mlfuzzz3::concolic
