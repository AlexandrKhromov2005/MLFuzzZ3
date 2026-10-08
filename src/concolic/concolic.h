// Cross-field concolic orchestrator (ADR 0035 "Решение §2"). Reconstructs
// a constraint system from a branch-value log (ADR 0033) over the
// findable input fields, inverts the last branch, solves via SolverFacade,
// and places the solved field values back into the input — producing a
// candidate that flips the target branch.
//
// This header exposes no Z3 types: SolverFacade hides z3++ behind
// fuzzer::solver. The orchestrator is a pure candidate producer; it does
// not touch corpus, scheduler, or the mutation loop (campaign integration
// is ADR 0036).

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "branch_reader.h"
#include "fuzz_input.h"
#include "solver_facade.h"

namespace mlfuzzz3::concolic {

/// A symbolic variable's binding to an input field. The variable index is
/// the position of this binding in `System::vars`; it corresponds to the
/// byte OFFSET (not the value), so two fields that happen to share a value
/// at different offsets stay distinct (ADR 0035 §2 variable-binding rules).
struct VarBinding {
    std::size_t offset;      ///< byte offset of the field in the input.
    std::uint8_t bit_width;  ///< field width in bits.
    bool big_endian;         ///< encoding under which the value was found.
};

/// The constraint system reconstructed from a branch log.
struct System {
    std::size_t num_vars = 0;
    std::vector<solver::Constraint> path;
    std::size_t target_index = 0;
    std::vector<VarBinding> vars;  ///< index == var_index referenced by the constraints.
    bool invertible = false;       ///< false when no usable target (empty path after binding).
};

/// Reconstruct the cross-field system from `seed` and its branch
/// `records` (ADR 0035 §2):
///   - input-to-state binds each operand to a field — DIRECT (the value's
///     `bit_width/8`-byte encoding is a substring of `seed`, either
///     endianness) or SUM (the value equals `field_i + field_j` mod
///     2^bit_width for two already-findable fields → `kAddVars`); an
///     operand bound to neither becomes a constant;
///   - operand order and findability never reorder a comparison; only the
///     Var/Const/AddVars classification depends on findability;
///   - each constraint is encoded as its AS-TAKEN path conjunct: the
///     logged comparison is evaluated on the logged operands and, when it
///     was FALSE on the seed, the predicate is negated — so inverting the
///     target flips the branch toward its unobserved side;
///   - a record whose BOTH sides are constants is dropped (boundary "B");
///   - the target is the last surviving constraint.
[[nodiscard]] System BuildSystem(std::span<const std::uint8_t> seed,
                                 const std::vector<coverage::BranchReader::Record>& records);

/// Why a SolveForCandidate call did or did not yield a candidate — lets the
/// caller attribute fruitless calls for metrics (ADR 0036 §4).
enum class SolveOutcome {
    kCandidate,      ///< a candidate input was produced
    kNoBinding,      ///< no constraint bound to the input (empty path / derived operands)
    kUnsat,          ///< the inverted system is unsatisfiable
    kTimeout,        ///< the solver returned unknown / timed out
    kError,          ///< solver error or model inconsistent with the bindings
    kWidthOverflow,  ///< model value does not fit the binding's field (ADR 0049, F4)
};

/// Починки солверной руки (ADR 0049). Каждая включается отдельно, и
/// значения по умолчанию воспроизводят поведение ДО ADR 0049: ADR принят не
/// будет, пока развёртка `docs/experiments/solver-fix-ladder/` не назовёт
/// числа, поэтому умолчание обязано оставаться прежним.
struct Fixes {
    /// F3: форма системы, которую получает солвер.
    enum class Form : std::uint8_t {
        kAllButTarget,  ///< `{ path[i] : i != target } ∧ ¬path[target]` — как было
        kPrefix,        ///< `path[0..target) ∧ ¬path[target]` — DART/SAGE, ADR 0034 §Решение
        kOptimistic,    ///< только `¬path[target]` — оптимистическая форма QSYM/Sydr
    };

    /// F1: значение ищется по индексу входа, а не сканированием всего сида
    /// на каждый операнд каждой записи. Семантика `FindFirst` сохраняется
    /// побайтно: первое вхождение по возрастанию смещения, при равном
    /// смещении little-endian прежде big-endian.
    bool findfirst_index = false;
    /// F2: `kAddVars` только для невырожденных пар — запрещены `i == j` и
    /// пары, где значение одного из полей на сиде равно нулю. Такая «сумма»
    /// ничего не связывает, а лишь вносит в систему тождество.
    bool strict_addvars = false;
    /// F4: обратная запись не усекает. Значение модели, не помещающееся в
    /// ширину привязки, даёт `kWidthOverflow` вместо тихого усечения;
    /// привязка расширяется до ширины ограничения, если соседние байты
    /// входа нулевые (нулевое расширение подтверждается самим входом).
    bool no_truncation = false;
    Form form = Form::kAllButTarget;
    /// Привязка операндов (ADR 0050, `binding_provider.h`); нулевой
    /// указатель — ValueMatchBinding, то есть прежнее поведение. Не
    /// владеет: провайдер обязан пережить вызов. `class` в объявлении
    /// вводит имя в пространство имён, не сдвигая строк выше.
    const class BindingProvider* binding = nullptr;
};

/// `BuildSystem` с включёнными починками ADR 0049 (F1 — индекс входа,
/// F2 — запрет вырожденных сумм). При `Fixes{}` результат совпадает с
/// перегрузкой выше побайтно.
[[nodiscard]] System BuildSystem(std::span<const std::uint8_t> seed,
                                 const std::vector<coverage::BranchReader::Record>& records,
                                 const Fixes& fixes);

/// Build the system, solve `{ non-target } ∧ ¬target` via SolverFacade,
/// and write each solved variable back to its bound offset in a copy of
/// `seed`. Returns the candidate on kSat; nullopt when the system is not
/// invertible, the solver returns kUnsat/kTimeout/kError, or the model is
/// inconsistent with the bindings. When `outcome` is non-null it receives
/// the reason (one of SolveOutcome); the return is `std::nullopt` for every
/// outcome except kCandidate.
[[nodiscard]] std::optional<mutation::FuzzInput> SolveForCandidate(
    std::span<const std::uint8_t> seed, const std::vector<coverage::BranchReader::Record>& records,
    unsigned timeout_ms, SolveOutcome* outcome = nullptr);

/// То же с включёнными починками ADR 0049. Дополнительно к перегрузке выше
/// возможен исход `kWidthOverflow` (F4), а форма системы задаётся
/// `fixes.form` (F3). При `Fixes{}` поведение совпадает с прежним.
[[nodiscard]] std::optional<mutation::FuzzInput> SolveForCandidate(
    std::span<const std::uint8_t> seed, const std::vector<coverage::BranchReader::Record>& records,
    unsigned timeout_ms, SolveOutcome* outcome, const Fixes& fixes);

/// Что случилось при обратной записи модели. Считается ВСЕГДА, независимо
/// от флагов: развёртка ADR 0049 сравнивает плечи по доле усечённых, и
/// базовое плечо обязано давать это число тем же кодом, что и починенное.
struct WriteBackStats {
    int vars_written = 0;             ///< переменных, упомянутых в отданной системе
    int vars_wider_than_binding = 0;  ///< солвер вёл переменную шире её поля
    int vars_truncated = 0;           ///< значение модели не поместилось в поле
    int vars_widened = 0;             ///< привязка расширена по нулевым соседям (F4)
};

/// Решить УЖЕ ПОСТРОЕННУЮ систему, инвертируя ограничение `target_index`,
/// и записать модель обратно в копию `seed`.
///
/// Существует ради развёрток: они инвертируют каждую позицию пути, а не
/// только последнюю, и должны мерить ТОТ ЖЕ код, которым пользуется
/// продукт, а не его копию в харнессе. `SolveForCandidate` — это и есть
/// вызов этой функции с `sys.target_index`.
///
/// Форма системы (`fixes.form`), отказ от усечения и расширение привязки
/// (`fixes.no_truncation`) работают здесь так же, как в продукте.
/// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): порядок повторяет
/// SolveForCandidate и SolveInverted (ADR 0035 §1).
[[nodiscard]] std::optional<mutation::FuzzInput> SolveSystemForTarget(
    std::span<const std::uint8_t> seed, const System& sys, std::size_t target_index,
    unsigned timeout_ms, SolveOutcome* outcome, const Fixes& fixes,
    WriteBackStats* stats = nullptr);

/// Куда прибавлять цену одного вызова `SolveForCandidate`, разложенную на
/// построение системы и её решение (ADR 0049: лестница мерила этот разрез
/// офлайн, на записанных трассах; кампании нужен тот же разрез на её рабочем
/// пути). Накопители — в МИКРОсекундах и только ПРИБАВЛЯЮТСЯ, null — не мерить.
/// Таймер ADR 0039 (`concolic_time_ms_total`) этим не заменяется: он усекает
/// каждый вызов до целых миллисекунд и охватывает оба участка сразу.
struct CallTiming {
    std::uint64_t* build_us = nullptr;  ///< `BuildSystem`
    std::uint64_t* solve_us = nullptr;  ///< форма системы, солвер, обратная запись
};

/// `SolveForCandidate` с починками и разметкой времени. Время решения
/// прибавляется только когда система обратима — иначе солвер не зовётся и
/// решению не достаётся ни микросекунды. Кандидат и `outcome` совпадают с
/// перегрузкой без `timing`.
[[nodiscard]] std::optional<mutation::FuzzInput> SolveForCandidate(
    std::span<const std::uint8_t> seed, const std::vector<coverage::BranchReader::Record>& records,
    unsigned timeout_ms, SolveOutcome* outcome, const Fixes& fixes, const CallTiming& timing);

}  // namespace mlfuzzz3::concolic
