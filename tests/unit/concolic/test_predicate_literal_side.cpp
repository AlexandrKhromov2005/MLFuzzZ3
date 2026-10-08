// task-055 — предикат × сторона с литералом и предикат × kAddVars.
//
// ЧТО ЭТО ЗАМЕРЯЕТ И ЧЕМ ОТЛИЧАЕТСЯ ОТ СОСЕДЕЙ.
// task-052 (`tests/unit/concolic/test_predicate_axis.cpp`) сняла ось
// предиката при ОДНОМ значении координаты стороны: обе стороны гейта —
// дословные поля сида, то есть обе `kVar`. Её собственный раздел границ
// говорит, что клетки «предикат × сторона с литералом» и «предикат ×
// kAddVars» не снимались. Этот харнесс снимает ровно их: те же десять
// сравнений ABI, тот же сид и те же два гейта-якоря, но сторона гейта
// принимает ещё два значения —
//   LIT — левая сторона дословное поле (`kVar`), правая литерал, которого
//         в сиде нет и который не выражается суммой полей (`kConst`);
//   ADD — обе стороны суммы двух findable-полей (`kAddVars`), ни одна не
//         findable напрямую.
// DOMAIN-3AXIS (`docs/experiments/solver-domain-form-width-endian/`)
// перебирает форму × ширину × порядок при ОДНОМ предикате равенства; здесь
// наоборот — предикат переменный, а форма стороны фиксирована двумя новыми
// значениями. Пересечение этих двух осей до сих пор пустое.
//
// Три контрольные клетки повторяют снятую координату task-052 (обе стороны
// `kVar`) и обязаны воспроизвести её числа клетка в клетку.
//
// `src/` этим харнессом не изменяется; кампаний не запускается.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "concolic.h"
#include "fuzz_input.h"
#include "solver_facade.h"

namespace {

using mlfuzzz3::concolic::BuildSystem;
using mlfuzzz3::concolic::SolveForCandidate;
using mlfuzzz3::concolic::SolveOutcome;
using mlfuzzz3::concolic::System;
using mlfuzzz3::coverage::BranchReader;
using mlfuzzz3::solver::Constraint;
using mlfuzzz3::solver::Operand;
using mlfuzzz3::solver::SolveInverted;
using mlfuzzz3::solver::SolveResult;

// Байты ABI сравнений (ADR 0033), в том же порядке, что и в task-052.
enum : std::uint8_t {
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

constexpr std::uint8_t kWidth = 32;
constexpr unsigned kTimeoutMs = 5000;
constexpr std::size_t kFieldBytes = 4;

// Сид и якоря — те же, что в task-052, иначе контрольные клетки не с чем
// сверять.
constexpr std::uint32_t kFieldA = 0x80000001U;
constexpr std::uint32_t kFieldB = 0x11223344U;
constexpr std::uint32_t kLow = 0x01010101U;

// Литерал координаты LIT. Три требования, и все три проверяются тестом
// FixtureShapesAreAsIntended: (1) его четырёхбайтовой кодировки нет в сиде
// ни в LE, ни в BE, поэтому он не станет `kVar`; (2) он не равен ни одной
// из трёх сумм findable-полей, поэтому не станет `kAddVars`; (3) он НЕ
// равен `kLow`, иначе инверсия цели столкнулась бы с гейтом-якорем и
// клетки давали бы kUnsat по вине якоря, а не по вине координаты.
constexpr std::uint32_t kLiteral = 0x40000000U;

// Стороны координаты ADD: суммы, которые биндер обязан отдать как
// kAddVars(0,1) и kAddVars(1,1).
constexpr std::uint32_t kSumAB = kFieldA + kFieldB;  // 0x91223345
constexpr std::uint32_t kSumBB = kFieldB + kFieldB;  // 0x22446688

std::vector<std::uint8_t> Seed() {
    std::vector<std::uint8_t> seed(2 * kFieldBytes);
    for (unsigned k = 0; k < kFieldBytes; ++k) {
        seed[k] = static_cast<std::uint8_t>(kFieldA >> (8U * k));
        seed[kFieldBytes + k] = static_cast<std::uint8_t>(kFieldB >> (8U * k));
    }
    return seed;
}

std::vector<BranchReader::Record> Guards() {
    return {
        {0, kUgt, kWidth, kFieldA, kLow},
        {1, kUgt, kWidth, kFieldB, kLow},
    };
}

std::uint32_t GetU32Le(const std::uint8_t* p) {
    std::uint32_t v = 0;
    for (unsigned k = 0; k < kFieldBytes; ++k) {
        v |= static_cast<std::uint32_t>(p[k]) << (8U * k);
    }
    return v;
}

// ORACLE 1 — истинность сравнения, выписанная из ABI. Знаковые случаи
// читают операнды как int32_t; неизвестный предикат объявляется
// «неразрешимым», а не «ложным».
struct Truth {
    bool value;
    bool decidable;
};

Truth EvalOracle(std::uint8_t predicate, std::uint32_t l, std::uint32_t r) {
    const auto sl = static_cast<std::int32_t>(l);
    const auto sr = static_cast<std::int32_t>(r);
    switch (predicate) {
        case kEq:
            return {l == r, true};
        case kNe:
            return {l != r, true};
        case kUlt:
            return {l < r, true};
        case kUle:
            return {l <= r, true};
        case kUgt:
            return {l > r, true};
        case kUge:
            return {l >= r, true};
        case kSlt:
            return {sl < sr, true};
        case kSle:
            return {sl <= sr, true};
        case kSgt:
            return {sl > sr, true};
        case kSge:
            return {sl >= sr, true};
        default:
            return {false, false};
    }
}

// ORACLE 2 — таблица отрицаний, выписанная из ABI.
struct Negation {
    std::uint8_t value;
    bool defined;
};

Negation ExpectedNegation(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return {kNe, true};
        case kNe:
            return {kEq, true};
        case kUlt:
            return {kUge, true};
        case kUle:
            return {kUgt, true};
        case kUgt:
            return {kUle, true};
        case kUge:
            return {kUlt, true};
        case kSlt:
            return {kSge, true};
        case kSle:
            return {kSgt, true};
        case kSgt:
            return {kSle, true};
        case kSge:
            return {kSlt, true};
        default:
            return {predicate, false};
    }
}

std::string PredicateName(std::uint8_t predicate) {
    switch (predicate) {
        case kEq:
            return "kEq";
        case kNe:
            return "kNe";
        case kUlt:
            return "kUlt";
        case kUle:
            return "kUle";
        case kUgt:
            return "kUgt";
        case kUge:
            return "kUge";
        case kSlt:
            return "kSlt";
        case kSle:
            return "kSle";
        case kSgt:
            return "kSgt";
        case kSge:
            return "kSge";
        default:
            return "OUT-OF-ABI";
    }
}

std::string PredicateLabel(std::uint8_t predicate) {
    return PredicateName(predicate) + "(" + std::to_string(static_cast<unsigned>(predicate)) + ")";
}

std::string KindName(Operand::Kind kind) {
    switch (kind) {
        case Operand::Kind::kVar:
            return "kVar";
        case Operand::Kind::kConst:
            return "kConst";
        case Operand::Kind::kAddVars:
            return "kAddVars";
    }
    return "?";
}

std::string OutcomeName(SolveOutcome outcome) {
    switch (outcome) {
        case SolveOutcome::kCandidate:
            return "kCandidate";
        case SolveOutcome::kNoBinding:
            return "kNoBinding";
        case SolveOutcome::kUnsat:
            return "kUnsat";
        case SolveOutcome::kTimeout:
            return "kTimeout";
        default:  // kError и kWidthOverflow (ADR 0049): здесь недостижим
            return "kError";
    }
    return "?";
}

std::string StatusName(SolveResult::Status status) {
    switch (status) {
        case SolveResult::Status::kSat:
            return "kSat";
        case SolveResult::Status::kUnsat:
            return "kUnsat";
        case SolveResult::Status::kTimeout:
            return "kTimeout";
        case SolveResult::Status::kError:
            return "kError";
    }
    return "?";
}

std::string YesNo(bool value) {
    return value ? "yes" : "no";
}

// Координата стороны. `slot` имеет смысл только для CTRL: 0 — поле по
// смещению 0, 1 — поле по смещению 4.
enum class Side : std::uint8_t {
    kCtrl,  ///< обе стороны kVar — снятая координата task-052
    kLit,   ///< kVar слева, литерал справа
    kAdd,   ///< kAddVars по обе стороны
};

struct Config {
    const char* name;   ///< метка клетки в сыром выводе
    Side side;          ///< координата стороны
    unsigned lhs_slot;  ///< CTRL: какое поле слева
    unsigned rhs_slot;  ///< CTRL: какое поле справа
};

constexpr Config kLit{"LIT", Side::kLit, 0, 0};
constexpr Config kAdd{"ADD", Side::kAdd, 0, 0};
constexpr Config kCtrlAA{"CTRL-AA", Side::kCtrl, 0, 0};
constexpr Config kCtrlAB{"CTRL-AB", Side::kCtrl, 0, 1};

std::uint32_t SlotValue(unsigned slot) {
    return slot == 0 ? kFieldA : kFieldB;
}

// Значения сторон гейта, как они попали бы в лог ветвлений на СИДЕ.
struct Sides {
    std::uint32_t lhs;
    std::uint32_t rhs;
};

Sides LoggedSides(const Config& cfg) {
    switch (cfg.side) {
        case Side::kCtrl:
            return {SlotValue(cfg.lhs_slot), SlotValue(cfg.rhs_slot)};
        case Side::kLit:
            return {kFieldA, kLiteral};
        case Side::kAdd:
            return {kSumAB, kSumBB};
    }
    return {0, 0};
}

// Те же стороны, но пересчитанные по ПРОИЗВОЛЬНОЙ паре значений полей —
// нужно, чтобы перечитать гейт на кандидате и на модели решателя. Для ADD
// это и есть композиция, которую координата проверяет.
Sides SidesFromFields(const Config& cfg, std::uint32_t f0, std::uint32_t f1) {
    switch (cfg.side) {
        case Side::kCtrl:
            return {cfg.lhs_slot == 0 ? f0 : f1, cfg.rhs_slot == 0 ? f0 : f1};
        case Side::kLit:
            return {f0, kLiteral};
        case Side::kAdd:
            return {static_cast<std::uint32_t>(f0 + f1), static_cast<std::uint32_t>(f1 + f1)};
    }
    return {0, 0};
}

// Одна измеренная клетка. Поля — ровно те, что требует постановка
// task-055, плюс два столбца прямого вызова SolveInverted.
struct Cell {
    std::uint8_t predicate_in;
    const char* config;
    Side side;
    std::string lhs_kind;        ///< вид операнда в sys.path[target_index]
    std::string rhs_kind;        ///< вид операнда в sys.path[target_index]
    std::size_t num_vars;        ///< sys.num_vars
    std::size_t records_in;      ///< сколько записей подано в BuildSystem
    std::size_t path_size;       ///< сколько дошло до sys.path
    std::size_t dropped;         ///< records_in - path_size (граница B)
    bool gate_survived;          ///< дошла ли запись гейта до пути
    bool in_domain;              ///< см. определение в отчёте: gate_survived
    std::size_t target_index;    ///< какое ограничение движок инвертирует
    std::uint8_t predicate_out;  ///< что легло в sys.path[target_index]
    std::uint8_t expected_out;   ///< что говорит оракул отрицания
    bool expectation_defined;
    bool as_taken_correct;  ///< predicate_out == expected_out
    bool taken_on_seed;
    SolveOutcome outcome;        ///< исход SolveForCandidate
    SolveResult::Status status;  ///< статус прямого SolveInverted
    bool has_candidate;
    bool gate_on_seed;
    bool gate_on_candidate;
    bool gate_on_candidate_known;
    bool flipped;      ///< гейт на кандидате разошёлся с гейтом на сиде
    bool model_flips;  ///< as-taken конъюнкт ЛОЖЕН на модели SolveInverted
    bool model_known;
};

// Значение стороны на модели решателя: kVar — модель переменной, kConst —
// сама константа, kAddVars — сумма двух моделей по модулю 2^32.
std::uint32_t OperandOnModel(const Operand& op, const std::vector<std::uint64_t>& model, bool* ok) {
    switch (op.kind) {
        case Operand::Kind::kConst:
            return static_cast<std::uint32_t>(op.const_value);
        case Operand::Kind::kVar:
            if (op.var_index >= model.size()) {
                *ok = false;
                return 0;
            }
            return static_cast<std::uint32_t>(model[op.var_index]);
        case Operand::Kind::kAddVars:
            if (op.var_index >= model.size() || op.var_index2 >= model.size()) {
                *ok = false;
                return 0;
            }
            return static_cast<std::uint32_t>(model[op.var_index]) +
                   static_cast<std::uint32_t>(model[op.var_index2]);
    }
    *ok = false;
    return 0;
}

Cell Measure(std::uint8_t predicate, const Config& cfg) {
    const std::vector<std::uint8_t> seed = Seed();
    const Sides logged = LoggedSides(cfg);

    std::vector<BranchReader::Record> records = Guards();
    records.push_back({2, predicate, kWidth, logged.lhs, logged.rhs});

    const System sys = BuildSystem(seed, records);

    Cell cell{};
    cell.predicate_in = predicate;
    cell.config = cfg.name;
    cell.side = cfg.side;
    cell.num_vars = sys.num_vars;
    cell.records_in = records.size();
    cell.path_size = sys.path.size();
    cell.dropped = records.size() - sys.path.size();
    cell.gate_survived = sys.path.size() == records.size();
    cell.in_domain = cell.gate_survived;
    cell.target_index = sys.target_index;

    if (sys.path.empty()) {
        cell.lhs_kind = "none";
        cell.rhs_kind = "none";
        cell.predicate_out = 0xFEU;
    } else {
        const Constraint& target = sys.path[sys.target_index];
        cell.lhs_kind = KindName(target.lhs.kind);
        cell.rhs_kind = KindName(target.rhs.kind);
        cell.predicate_out = target.predicate;
    }

    const Truth truth = EvalOracle(predicate, logged.lhs, logged.rhs);
    cell.taken_on_seed = truth.value;
    cell.gate_on_seed = truth.value;

    const Negation negation = ExpectedNegation(predicate);
    cell.expectation_defined = negation.defined;
    cell.expected_out = truth.value ? predicate : negation.value;
    cell.as_taken_correct =
        negation.defined && truth.decidable && cell.predicate_out == cell.expected_out;

    // Прямой вызов SolveInverted — тот же путь, которым идёт движок, но без
    // обратной записи в байты: он даёт модель, на которой видно, ложен ли
    // as-taken конъюнкт цели.
    if (sys.invertible) {
        const SolveResult result =
            SolveInverted(sys.num_vars, sys.path, sys.target_index, kTimeoutMs);
        cell.status = result.status;
        if (result.status == SolveResult::Status::kSat && !sys.path.empty()) {
            const Constraint& target = sys.path[sys.target_index];
            bool ok = true;
            const std::uint32_t lhs_m = OperandOnModel(target.lhs, result.model_values, &ok);
            const std::uint32_t rhs_m = OperandOnModel(target.rhs, result.model_values, &ok);
            const Truth on_model = EvalOracle(target.predicate, lhs_m, rhs_m);
            cell.model_known = ok && on_model.decidable;
            cell.model_flips = cell.model_known && !on_model.value;
        }
    } else {
        cell.status = SolveResult::Status::kError;
    }

    cell.outcome = SolveOutcome::kError;
    const auto candidate = SolveForCandidate(seed, records, kTimeoutMs, &cell.outcome);
    cell.has_candidate = candidate.has_value();

    if (candidate.has_value() && candidate->size() >= seed.size()) {
        const std::uint32_t f0 = GetU32Le(candidate->data());
        const std::uint32_t f1 = GetU32Le(candidate->data() + kFieldBytes);
        const Sides after_sides = SidesFromFields(cfg, f0, f1);
        const Truth after = EvalOracle(predicate, after_sides.lhs, after_sides.rhs);
        cell.gate_on_candidate_known = after.decidable;
        cell.gate_on_candidate = after.value;
        cell.flipped = after.decidable && after.value != truth.value;
    }
    return cell;
}

void PrintHeader() {
    std::cout << "\n"
              << "GRID predicate-literal-side: seed=a@0=0x80000001,b@4=0x11223344 (u32 LE), "
                 "guards=[a >u 0x01010101, b >u 0x01010101]\n"
              << "LIT: gate is a <op> 0x40000000 (literal absent from the seed and not a sum "
                 "of fields)\n"
              << "ADD: gate is (a+b) <op> (b+b) = 0x91223345 <op> 0x22446688, neither side "
                 "findable directly\n"
              << "CTRL-AA: gate is a <op> a | CTRL-AB: gate is a <op> b — the side coordinate "
                 "task-052 already measured\n";
}

void PrintCell(const Cell& cell) {
    std::cout << "CELL"
              << " pred_in=" << std::setw(11) << std::left << PredicateLabel(cell.predicate_in)
              << " side=" << std::setw(8) << std::left << cell.config
              << " lhs_kind=" << std::setw(9) << std::left << cell.lhs_kind
              << " rhs_kind=" << std::setw(9) << std::left << cell.rhs_kind
              << " num_vars=" << cell.num_vars << " path_size=" << cell.path_size
              << " dropped=" << cell.dropped << " in_domain=" << std::setw(3) << std::left
              << YesNo(cell.in_domain) << " target_index=" << cell.target_index
              << " taken_on_seed=" << std::setw(3) << std::left << YesNo(cell.taken_on_seed)
              << " pred_out=" << std::setw(11) << std::left << PredicateLabel(cell.predicate_out)
              << " expected=" << std::setw(11) << std::left
              << (cell.expectation_defined ? PredicateLabel(cell.expected_out)
                                           : std::string("none"))
              << " as_taken_correct=" << std::setw(3) << std::left << YesNo(cell.as_taken_correct)
              << " outcome=" << std::setw(10) << std::left << OutcomeName(cell.outcome)
              << " solve_inverted=" << std::setw(8) << std::left << StatusName(cell.status)
              << " model_flips=" << std::setw(3) << std::left
              << (cell.model_known ? YesNo(cell.model_flips) : std::string("n/a"))
              << " gate_on_seed=" << std::setw(3) << std::left << YesNo(cell.gate_on_seed)
              << " gate_on_candidate=" << std::setw(3) << std::left
              << (cell.gate_on_candidate_known ? YesNo(cell.gate_on_candidate) : std::string("n/a"))
              << " flipped=" << YesNo(cell.flipped) << "\n";
}

constexpr std::array<std::uint8_t, 10> kPredicates = {kEq,  kNe,  kUlt, kUle, kUgt,
                                                      kUge, kSlt, kSle, kSgt, kSge};

}  // namespace

// Фикстура: координаты стороны обязаны быть теми, за которые их выдают.
// Без этого теста вся сетка могла бы молча мерить не ту форму операнда.
TEST(SolverPredicateLiteralSide, FixtureShapesAreAsIntended) {
    const std::vector<std::uint8_t> seed = Seed();
    ASSERT_EQ(seed.size(), 2U * kFieldBytes);

    // LIT: слева переменная, справа константа.
    {
        std::vector<BranchReader::Record> records = Guards();
        records.push_back({2, kUgt, kWidth, kFieldA, kLiteral});
        const System sys = BuildSystem(seed, records);
        ASSERT_EQ(sys.num_vars, 2U);
        ASSERT_EQ(sys.path.size(), 3U);
        EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kVar);
        EXPECT_EQ(sys.path[2].rhs.kind, Operand::Kind::kConst);
        EXPECT_EQ(sys.path[2].rhs.const_value, kLiteral);
        // Литерал не совпал с границей якоря — иначе kUnsat пришёл бы от
        // гейта-якоря, а не от координаты.
        EXPECT_NE(kLiteral, kLow);
    }

    // ADD: обе стороны — суммы, и именно те пары, что заявлены.
    {
        std::vector<BranchReader::Record> records = Guards();
        records.push_back({2, kUgt, kWidth, kSumAB, kSumBB});
        const System sys = BuildSystem(seed, records);
        ASSERT_EQ(sys.num_vars, 2U);
        ASSERT_EQ(sys.path.size(), 3U);
        EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kAddVars);
        EXPECT_EQ(sys.path[2].rhs.kind, Operand::Kind::kAddVars);
        EXPECT_EQ(sys.path[2].lhs.var_index, 0U);
        EXPECT_EQ(sys.path[2].lhs.var_index2, 1U);
        EXPECT_EQ(sys.path[2].rhs.var_index, 1U);
        EXPECT_EQ(sys.path[2].rhs.var_index2, 1U);
    }

    // CTRL: обе стороны — переменные, как в task-052.
    {
        std::vector<BranchReader::Record> records = Guards();
        records.push_back({2, kUgt, kWidth, kFieldA, kFieldB});
        const System sys = BuildSystem(seed, records);
        ASSERT_EQ(sys.path.size(), 3U);
        EXPECT_EQ(sys.path[2].lhs.kind, Operand::Kind::kVar);
        EXPECT_EQ(sys.path[2].rhs.kind, Operand::Kind::kVar);
    }
}

// Сетка: десять сравнений ABI × две неснятые координаты стороны = 20 клеток.
TEST(SolverPredicateLiteralSide, TenPredicatesTwoSideCoordinates) {
    PrintHeader();

    const std::array<Config, 2> coords = {kLit, kAdd};

    unsigned cells = 0;
    unsigned as_taken_correct = 0;
    unsigned flipped = 0;
    unsigned in_domain = 0;
    unsigned dropped_total = 0;
    unsigned model_flips = 0;

    // Разделяет ли предикат домен: считаем на КАЖДОЙ координате отдельно,
    // сколько клеток в домене. Координата разделена, если её десять клеток
    // дали не один и тот же ответ.
    std::array<unsigned, 2> in_domain_per_coord = {0, 0};

    for (unsigned c = 0; c < coords.size(); ++c) {
        for (const std::uint8_t predicate : kPredicates) {
            const Cell cell = Measure(predicate, coords[c]);
            PrintCell(cell);
            ++cells;

            EXPECT_EQ(cell.num_vars, 2U) << PredicateName(predicate) << "/" << coords[c].name;
            EXPECT_EQ(cell.target_index, 2U) << PredicateName(predicate) << "/" << coords[c].name;
            EXPECT_TRUE(cell.as_taken_correct)
                << PredicateName(predicate) << "/" << coords[c].name
                << ": pred_out=" << PredicateLabel(cell.predicate_out)
                << " expected=" << PredicateLabel(cell.expected_out);

            if (cell.as_taken_correct) {
                ++as_taken_correct;
            }
            if (cell.flipped) {
                ++flipped;
            }
            if (cell.in_domain) {
                ++in_domain;
                ++in_domain_per_coord[c];
            }
            if (cell.model_flips) {
                ++model_flips;
            }
            dropped_total += static_cast<unsigned>(cell.dropped);
        }
    }

    const bool lit_separates = in_domain_per_coord[0] != 0 && in_domain_per_coord[0] != 10;
    const bool add_separates = in_domain_per_coord[1] != 0 && in_domain_per_coord[1] != 10;
    const bool separates = lit_separates || add_separates;

    std::cout << "SUMMARY-SIDE predicates=10 side_coords=2 cells=" << cells
              << " as_taken_correct=" << as_taken_correct << "/" << cells << " flipped=" << flipped
              << "/" << cells << " model_flips=" << model_flips << "/" << cells
              << " dropped=" << dropped_total << " in_domain=" << in_domain << "/" << cells
              << " in_domain_LIT=" << in_domain_per_coord[0] << "/10"
              << " in_domain_ADD=" << in_domain_per_coord[1] << "/10"
              << " predicate_separates_domain=" << YesNo(separates) << "\n";

    EXPECT_EQ(cells, 20U);
    EXPECT_EQ(as_taken_correct, 20U);
    EXPECT_EQ(in_domain, 20U);
    EXPECT_EQ(dropped_total, 0U);
    EXPECT_FALSE(separates);
    // Измерено, а не предсказано: обе новые координаты переворачиваются на
    // всех десяти предикатах. Две неперевернувшиеся клетки task-052 —
    // вырожденная конфигурация `a <op> a`, а не свойство предиката; здесь
    // такой конфигурации нет, поэтому 20/20, а не 18/20.
    EXPECT_EQ(flipped, 20U);
    EXPECT_EQ(model_flips, 20U);
}

// Контроль: три клетки на снятой координате task-052 (обе стороны kVar).
// Они обязаны воспроизвести числа её закрывающей записи — иначе сравнивать
// новые координаты не с чем.
TEST(SolverPredicateLiteralSide, ControlCellsReproduceTask052) {
    struct Expect {
        std::uint8_t predicate;
        Config cfg;
        const char* task052_pin;
        bool taken_on_seed;
        std::uint8_t predicate_out;
        SolveOutcome outcome;
        bool flipped;
    };

    const std::array<Expect, 3> kControls = {{
        {kEq, kCtrlAA, "raw-grid.txt:12", true, kEq, SolveOutcome::kUnsat, false},
        {kNe, kCtrlAA, "raw-grid.txt:15", false, kEq, SolveOutcome::kUnsat, false},
        {kUgt, kCtrlAB, "raw-grid.txt:20", true, kUgt, SolveOutcome::kCandidate, true},
    }};

    unsigned matched = 0;
    for (const Expect& e : kControls) {
        const Cell cell = Measure(e.predicate, e.cfg);
        PrintCell(cell);

        const bool match = cell.taken_on_seed == e.taken_on_seed &&
                           cell.predicate_out == e.predicate_out && cell.as_taken_correct &&
                           cell.outcome == e.outcome && cell.flipped == e.flipped &&
                           cell.gate_survived && cell.path_size == 3U && cell.target_index == 2U &&
                           cell.dropped == 0U;
        std::cout << "CONTROL pred=" << PredicateLabel(e.predicate) << " cfg=" << e.cfg.name
                  << " task052_pin=" << e.task052_pin << " matches_task052=" << YesNo(match)
                  << "\n";
        EXPECT_TRUE(match) << PredicateName(e.predicate) << "/" << e.cfg.name
                           << ": taken_on_seed=" << YesNo(cell.taken_on_seed)
                           << " pred_out=" << PredicateLabel(cell.predicate_out)
                           << " outcome=" << OutcomeName(cell.outcome)
                           << " flipped=" << YesNo(cell.flipped);
        if (match) {
            ++matched;
        }
    }

    std::cout << "SUMMARY-CONTROL control_cells=3 matched=" << matched << "/3"
              << " control_matches_task052=" << YesNo(matched == 3) << "\n";
    EXPECT_EQ(matched, 3U);
}
