// Cross-field concolic orchestrator implementation (ADR 0035 §2).
#include "concolic.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <unordered_map>

#include "binding_provider.h"

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
bool EvalPredicate(std::uint8_t predicate, std::uint64_t lhs, std::uint64_t rhs,
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

// Logical negation of a comparison predicate (eq<->ne, ult<->uge, ...).
// Used to encode an as-taken-false conjunct: a comparison that evaluated
// FALSE on the seed contributes its negation to the path condition.
std::uint8_t NegatePredicate(std::uint8_t predicate) {
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
        case kSlt:
            return kSge;
        case kSle:
            return kSgt;
        case kSgt:
            return kSle;
        case kSge:
            return kSlt;
        default:
            return predicate;
    }
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
                               unsigned bit_width) {
    if (!ByteWidthValid(bit_width)) {
        return std::nullopt;
    }
    const unsigned n = bit_width / kBitsPerByte;
    if (seed.size() < n) {
        return std::nullopt;
    }
    const std::uint64_t v = TruncateToWidth(value, bit_width);
    for (std::size_t off = 0; off + n <= seed.size(); ++off) {
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
    explicit SeedIndex(std::span<const std::uint8_t> seed) {
        for (const unsigned n : {1U, 2U, 4U, 8U}) {
            if (seed.size() < n) {
                continue;
            }
            std::unordered_map<std::uint64_t, Match>& table = tables_.at(Slot(n));
            table.reserve(2 * (seed.size() - n + 1));
            for (std::size_t off = 0; off + n <= seed.size(); ++off) {
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
                               std::uint64_t value, unsigned bit_width) {
    if (index != nullptr) {
        return index->Find(value, bit_width);
    }
    return FindFirst(seed, value, bit_width);
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
    if (const std::optional<Match> direct = FindValue(seed, index, value, bit_width)) {
        const auto it = offset_to_index.find(direct->offset);
        if (it != offset_to_index.end()) {
            return MakeVar(it->second);
        }
    }
    const std::uint64_t target = TruncateToWidth(value, bit_width);
    for (std::size_t i = 0; i < vars.size(); ++i) {
        for (std::size_t j = i; j < vars.size(); ++j) {
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

System BuildSystem(std::span<const std::uint8_t> seed,
                   const std::vector<coverage::BranchReader::Record>& records) {
    return BuildSystem(seed, records, Fixes{});
}

System BuildSystem(std::span<const std::uint8_t> seed,
                   const std::vector<coverage::BranchReader::Record>& records, const Fixes& fixes) {
    System sys;

    // Привязка операндов — за интерфейсом (ADR 0050). Сессия открывается
    // один раз на весь разбор и обслуживает оба прохода; без провайдера в
    // Fixes действует ValueMatchBinding — прежний поиск значения во входе,
    // с индексом F1 (ADR 0049), который строит сама сессия.
    const ValueMatchBinding value_match;
    const BindingProvider& provider = fixes.binding != nullptr ? *fixes.binding : value_match;
    const std::unique_ptr<BindingProvider::Session> session = provider.Open(seed, fixes);
    // Кодировка поля и ширина задаются зависимостью, отданной провайдером.

    // Pass 1: discover findable fields (ordered by offset -> var_index).
    std::map<std::size_t, VarBinding> fields;
    const auto collect = [&](std::uint64_t value, unsigned bit_width) {
        if (const std::optional<VarBinding> dep = session->Locate(value, bit_width)) {
            // Первая находка на смещении задаёт ширину и порядок байт поля;
            // повторные находки на том же смещении его не меняют
            // (try_emplace), как и до вынесения привязки за интерфейс.
            fields.try_emplace(dep->offset, *dep);
        }
    };
    for (const coverage::BranchReader::Record& rec : records) {
        collect(rec.lhs, rec.bit_width);
        collect(rec.rhs, rec.bit_width);
    }

    std::unordered_map<std::size_t, std::size_t> offset_to_index;
    for (const auto& [offset, binding] : fields) {
        offset_to_index.emplace(offset, sys.vars.size());
        sys.vars.push_back(binding);
    }
    sys.num_vars = sys.vars.size();

    // Pass 2: bind operands, encode each constraint as its as-taken
    // conjunct, drop records with no findable side (boundary "B").
    for (const coverage::BranchReader::Record& rec : records) {
        const solver::Operand lhs =
            session->Bind(rec.lhs, rec.bit_width, sys.vars, offset_to_index);
        const solver::Operand rhs =
            session->Bind(rec.rhs, rec.bit_width, sys.vars, offset_to_index);
        if (lhs.kind == solver::Operand::Kind::kConst &&
            rhs.kind == solver::Operand::Kind::kConst) {
            continue;
        }
        const bool taken = EvalPredicate(rec.predicate, rec.lhs, rec.rhs, rec.bit_width);
        const std::uint8_t predicate = taken ? rec.predicate : NegatePredicate(rec.predicate);
        sys.path.push_back(
            {.predicate = predicate, .bit_width = rec.bit_width, .lhs = lhs, .rhs = rhs});
    }

    sys.invertible = !sys.path.empty();
    sys.target_index = sys.invertible ? sys.path.size() - 1 : 0;
    return sys;
}

namespace {

// F4 (ADR 0049): расширить привязку до ширины ограничения, если вход
// ПОДТВЕРЖДАЕТ нулевое расширение. Солвер ведёт переменную шириной в
// максимум ширин упоминающих её ограничений (src/solver/solver_facade.h:67),
// а пишется она в поле той ширины, какую зафиксировала первая нашедшая
// запись. Если старшие байты поля во входе нулевые, поле и есть более
// широкое число, и запись можно вести в его настоящей ширине: для
// little-endian старшие байты идут ЗА полем, для big-endian — ПЕРЕД ним, и
// тогда смещение сдвигается влево. Возвращает false, если подтверждения
// нет: тогда кандидат не строится (kWidthOverflow), а не усекается молча.
bool TryWidenBinding(std::span<const std::uint8_t> seed, VarBinding* var, unsigned wanted_bits) {
    if (var == nullptr || !ByteWidthValid(wanted_bits) || wanted_bits <= var->bit_width) {
        return false;
    }
    const unsigned old_n = var->bit_width / kBitsPerByte;
    const unsigned new_n = wanted_bits / kBitsPerByte;
    const unsigned delta = new_n - old_n;
    if (!var->big_endian) {
        if (var->offset + new_n > seed.size()) {
            return false;
        }
        for (unsigned k = old_n; k < new_n; ++k) {
            if (seed[var->offset + k] != 0) {
                return false;
            }
        }
        var->bit_width = static_cast<std::uint8_t>(wanted_bits);
        return true;
    }
    if (var->offset < delta) {
        return false;
    }
    for (unsigned k = 1; k <= delta; ++k) {
        if (seed[var->offset - k] != 0) {
            return false;
        }
    }
    var->offset -= delta;
    var->bit_width = static_cast<std::uint8_t>(wanted_bits);
    return true;
}

// Переменные, упомянутые в отданной солверу системе, и наибольшая ширина
// ограничения на каждую. Первое нужно для F3: в префиксной и
// оптимистической форме неупомянутые переменные система не ограничивает,
// солвер возвращает для них произвольные значения, и запись их в кандидата
// портила бы поля, которых система не касалась. Второе нужно для F4.
void ScanReferences(const std::vector<solver::Constraint>& system, std::vector<bool>* referenced,
                    std::vector<unsigned>* max_width) {
    const auto visit = [&](const solver::Operand& op, unsigned bit_width) {
        const auto mark = [&](std::size_t idx) {
            if (idx < referenced->size()) {
                (*referenced)[idx] = true;
                (*max_width)[idx] = std::max((*max_width)[idx], bit_width);
            }
        };
        if (op.kind == solver::Operand::Kind::kVar) {
            mark(op.var_index);
        } else if (op.kind == solver::Operand::Kind::kAddVars) {
            mark(op.var_index);
            mark(op.var_index2);
        }
    };
    for (const solver::Constraint& c : system) {
        visit(c.lhs, c.bit_width);
        visit(c.rhs, c.bit_width);
    }
}

// Map a non-SAT solver status to the corresponding fruitless outcome.
SolveOutcome NonSatOutcome(solver::SolveResult::Status status) {
    switch (status) {
        case solver::SolveResult::Status::kUnsat:
            return SolveOutcome::kUnsat;
        case solver::SolveResult::Status::kTimeout:
            return SolveOutcome::kTimeout;
        case solver::SolveResult::Status::kSat:
        case solver::SolveResult::Status::kError:
        default:
            return SolveOutcome::kError;
    }
}

// Прибавить к накопителю (если он задан) время от `start` до сейчас, в
// микросекундах.
void AddElapsedUs(std::uint64_t* total_us, std::chrono::steady_clock::time_point start) {
    if (total_us != nullptr) {
        *total_us +=
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                           std::chrono::steady_clock::now() - start)
                                           .count());
    }
}

}  // namespace

std::optional<mutation::FuzzInput> SolveForCandidate(
    std::span<const std::uint8_t> seed, const std::vector<coverage::BranchReader::Record>& records,
    unsigned timeout_ms, SolveOutcome* outcome) {
    return SolveForCandidate(seed, records, timeout_ms, outcome, Fixes{});
}

std::optional<mutation::FuzzInput> SolveForCandidate(
    std::span<const std::uint8_t> seed, const std::vector<coverage::BranchReader::Record>& records,
    unsigned timeout_ms, SolveOutcome* outcome, const Fixes& fixes) {
    return SolveForCandidate(seed, records, timeout_ms, outcome, fixes, CallTiming{});
}

std::optional<mutation::FuzzInput> SolveForCandidate(
    std::span<const std::uint8_t> seed, const std::vector<coverage::BranchReader::Record>& records,
    unsigned timeout_ms, SolveOutcome* outcome, const Fixes& fixes, const CallTiming& timing) {
    const auto report = [outcome](SolveOutcome value) {
        if (outcome != nullptr) {
            *outcome = value;
        }
    };

    const auto build_start = std::chrono::steady_clock::now();
    const System sys = BuildSystem(seed, records, fixes);
    AddElapsedUs(timing.build_us, build_start);
    if (!sys.invertible) {
        report(SolveOutcome::kNoBinding);
        return std::nullopt;
    }
    const auto solve_start = std::chrono::steady_clock::now();
    std::optional<mutation::FuzzInput> candidate =
        SolveSystemForTarget(seed, sys, sys.target_index, timeout_ms, outcome, fixes);
    AddElapsedUs(timing.solve_us, solve_start);
    return candidate;
}

// Подготовка одной переменной к записи: расширение привязки по нулевым
// соседям (F4) и решение, помещается ли значение модели. Отдельной функцией
// — чтобы WriteBackModel не набирала когнитивную сложность выше порога
// readability-function-cognitive-complexity.
VarBinding PrepareBinding(std::span<const std::uint8_t> seed, const VarBinding& original,
                          unsigned solver_width, const Fixes& fixes, std::uint64_t model_value,
                          WriteBackStats* stats, bool* truncated) {
    VarBinding var = original;
    const bool wider = solver_width > var.bit_width;
    bool widened = false;
    if (fixes.no_truncation && wider) {
        widened = TryWidenBinding(seed, &var, solver_width);
    }
    *truncated = TruncateToWidth(model_value, var.bit_width) != model_value;
    if (stats != nullptr) {
        ++stats->vars_written;
        stats->vars_wider_than_binding += wider ? 1 : 0;
        stats->vars_truncated += *truncated ? 1 : 0;
        stats->vars_widened += widened ? 1 : 0;
    }
    return var;
}

// Запись значения в поле входа в порядке байт этого поля.
void WriteField(std::vector<std::uint8_t>& bytes, const VarBinding& var, std::uint64_t value) {
    const unsigned n = var.bit_width / kBitsPerByte;
    for (unsigned b = 0; b < n; ++b) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - b)) : (kBitsPerByte * b);
        bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
    }
}

// Обратная запись модели в копию входа. Возвращает nullopt, когда кандидата
// строить нельзя; причину кладёт в *outcome. Счёт усечённых идёт до конца
// пути, а не обрывается на первом переполнении: решение от этого не
// меняется, а статистика перестаёт быть усечённой на самой себе.
std::optional<std::vector<std::uint8_t>> WriteBackModel(
    std::span<const std::uint8_t> seed, const System& sys, const std::vector<std::uint64_t>& model,
    const std::vector<bool>& referenced, const std::vector<unsigned>& max_width, const Fixes& fixes,
    WriteBackStats* stats, SolveOutcome* outcome) {
    std::vector<std::uint8_t> bytes(seed.begin(), seed.end());
    bool overflow = false;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        // Неупомянутые переменные пропускаются только тогда, когда форму
        // системы меняли: при прежней форме поведение обязано остаться
        // байт в байт прежним.
        if (fixes.form != Fixes::Form::kAllButTarget && !referenced[k]) {
            continue;
        }
        bool truncated = false;
        const VarBinding var =
            PrepareBinding(seed, sys.vars[k], max_width[k], fixes, model[k], stats, &truncated);
        if (fixes.no_truncation && truncated) {
            overflow = true;
            continue;
        }
        const unsigned n = var.bit_width / kBitsPerByte;
        if (var.offset + n > bytes.size()) {
            if (outcome != nullptr) {
                *outcome = SolveOutcome::kError;  // binding inconsistent with the input
            }
            return std::nullopt;
        }
        WriteField(bytes, var, TruncateToWidth(model[k], var.bit_width));
    }
    if (overflow) {
        if (outcome != nullptr) {
            *outcome = SolveOutcome::kWidthOverflow;
        }
        return std::nullopt;
    }
    return bytes;
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters): порядок повторяет
// SolveForCandidate и SolveInverted (ADR 0035 §1); менять его здесь значило
// бы завести две разные конвенции на один и тот же вызов.
std::optional<mutation::FuzzInput> SolveSystemForTarget(std::span<const std::uint8_t> seed,
                                                        const System& sys, std::size_t target_index,
                                                        unsigned timeout_ms, SolveOutcome* outcome,
                                                        const Fixes& fixes, WriteBackStats* stats) {
    const auto report = [outcome](SolveOutcome value) {
        if (outcome != nullptr) {
            *outcome = value;
        }
    };
    if (!sys.invertible || target_index >= sys.path.size()) {
        report(SolveOutcome::kNoBinding);
        return std::nullopt;
    }

    // F3 (ADR 0049): какая система уходит солверу. Умолчание — прежняя
    // форма всё-кроме-цели; префикс отрезает суффикс пути после цели,
    // оптимистическая форма оставляет одно отрицаемое ограничение.
    std::vector<solver::Constraint> system;
    std::size_t target = target_index;
    switch (fixes.form) {
        case Fixes::Form::kPrefix:
            system.assign(sys.path.begin(),
                          sys.path.begin() + static_cast<std::ptrdiff_t>(target_index) + 1);
            target = target_index;
            break;
        case Fixes::Form::kOptimistic:
            system.assign(1, sys.path[target_index]);
            target = 0;
            break;
        case Fixes::Form::kAllButTarget:
        default:
            system = sys.path;
            target = target_index;
            break;
    }

    const solver::SolveResult result =
        solver::SolveInverted(sys.num_vars, system, target, timeout_ms);
    if (result.status != solver::SolveResult::Status::kSat ||
        result.model_values.size() != sys.num_vars) {
        // A SAT result whose model count disagrees with num_vars is a
        // (defensive) error; everything else maps from the solver status.
        report(result.status == solver::SolveResult::Status::kSat ? SolveOutcome::kError
                                                                  : NonSatOutcome(result.status));
        return std::nullopt;
    }

    std::vector<bool> referenced(sys.vars.size(), false);
    std::vector<unsigned> max_width(sys.vars.size(), 0);
    ScanReferences(system, &referenced, &max_width);

    const std::optional<std::vector<std::uint8_t>> bytes = WriteBackModel(
        seed, sys, result.model_values, referenced, max_width, fixes, stats, outcome);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    report(SolveOutcome::kCandidate);
    return mutation::FuzzInput(std::vector<std::uint8_t>(*bytes));
}
// NOLINTEND(bugprone-easily-swappable-parameters)

// ValueMatchBinding (ADR 0050) определён в конце файла, чтобы вынесение
// привязки за интерфейс не сдвинуло строки, на которые ссылаются отчёты:
// сессии нужны закрытые FindValue, SeedIndex и BindOperand выше.
namespace {

class ValueMatchSession final : public BindingProvider::Session {
   public:
    ValueMatchSession(std::span<const std::uint8_t> seed, const Fixes& fixes)
        : seed_(seed), fixes_(fixes) {
        // F1 (ADR 0049): индекс строится один раз на весь разбор и заменяет
        // сканирование входа в обоих проходах. Без флага указатель нулевой,
        // и поиск идёт прежним путём.
        if (fixes_.findfirst_index) {
            index_.emplace(seed_);
        }
    }

    [[nodiscard]] std::optional<VarBinding> Locate(std::uint64_t value,
                                                   unsigned bit_width) const override {
        const std::optional<Match> m = FindValue(seed_, IndexPtr(), value, bit_width);
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

std::unique_ptr<BindingProvider::Session> ValueMatchBinding::Open(
    std::span<const std::uint8_t> seed, const Fixes& fixes) const {
    return std::make_unique<ValueMatchSession>(seed, fixes);
}

}  // namespace mlfuzzz3::concolic
