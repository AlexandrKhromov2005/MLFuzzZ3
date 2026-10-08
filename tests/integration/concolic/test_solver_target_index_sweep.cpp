// E0 (recon, ADR-0047) — какое ограничение инвертирует солвер на реальной
// цели и сколько из 99.5 % unsat объясняется ВЫБОРОМ ЦЕЛИ, а не алиасингом.
//
// Что измеряется. Продукт инвертирует ровно одну запись пути — последнюю:
// `sys.target_index = sys.invertible ? sys.path.size() - 1 : 0;`
// (src/concolic/concolic.cpp:255). Другого выбора цели в коде нет, и он
// никогда не измерялся: ADR-0047 объясняет 99.5 % unsat диагностики libtiff
// (2196 из 2207, docs/experiments/comparative-magma-libtiff/ANALYSIS.md
// :57-60) алиасингом и as-taken пиннингом, то есть свойством ПУТИ. Этот
// харнесс отделяет свойство пути от свойства ВЫБОРА: на одном и том же пути
// он инвертирует по очереди КАЖДУЮ запись.
//
// Почему это делается без единой правки src/. Перебор возможен потому, что
// solver::SolveInverted (src/solver/solver_facade.h) принимает target_index
// параметром — ограничение «всегда последняя» живёт не в солвере, а в одной
// строке оркестратора. Харнесс зовёт публичный BuildSystem, берёт из System
// готовый путь и крутит по нему тот же самый SolveInverted, каким пользуется
// продукт. Поэтому измеряется именно продуктовый солвер на продуктовом пути,
// а не его пересказ.
//
// Связка снятия пути — дословно кампанийная: Run(seed) и сразу следом
// LastBranchRecords(), без единого прогона между ними
// (src/core/campaign.cpp:180-181, ADR-0036 §3). BuildSystem зовётся ОДИН раз
// на сид: путь у всех клеток сида общий, различается только target_index.
//
// Обратная запись модели во вход. Продуктовая обратная запись сидит внутри
// SolveForCandidate (concolic.cpp:307-325) и снаружи недоступна отдельно от
// выбора цели, а SolveForCandidate умеет только last. Поэтому ApplyModel
// ниже повторяет её правила один в один — усечение значения до ширины поля
// и раскладка байтов по var.big_endian — и ровно этим повторением
// проверяется на отрицательном контроле: add_gate обязан упасть от
// кандидата, собранного ЭТОЙ функцией. Если бы ApplyModel расходилась с
// продуктовой записью, контроль бы не прошёл.
//
// Три гипотезы и правило чтения зарегистрированы ДО прогона в шапке
// docs/experiments/solver-target-index-sweep/run.sh и реализованы в
// analyze.py, закоммиченном тем же коммитом. Харнесс НЕ решает, какая
// гипотеза выжила: он печатает клетки и счётчики, решение считается из
// сырья отдельно.
//
// Расписание клеток (предрегистрировано там же). Фаза A — отрицательный
// контроль на add_gate. Фаза B — по каждому сиду метаданные пути и ровно
// одна клетка i=last, то есть контроль воспроизведения диагностики; он идёт
// до развёртки, чтобы остаться снятым при любом исчерпании бюджета. Фаза C —
// круговой обход: раунд r берёт у каждого сида r-ю точку его сетки. Индекс
// last в сетку фазы C не входит — он измерен в фазе B, и каждая клетка
// попадает в сырьё ровно один раз.
//
// Границы. src/ не изменяется, правка выбора цели не предлагается, кампании
// не запускаются. Жёсткий лимит стены 5400 с внутри харнесса; когда он
// потрачен, стенд останавливается там, где стоит, и печатает
// stop_reason=walltime. Каждый печатаемый путь — относительный от корня
// репозитория, поэтому сырьё не несёт абсолютных путей.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "concolic.h"
#include "runner.h"
#include "session.h"
#include "solver_facade.h"

namespace mlfuzzz3::core {
namespace {

// Протокол E0: ни одна из этих величин не меняется по итогу прогона.
constexpr unsigned kSolveTimeoutMs = 2000;
constexpr std::size_t kGridMax = 2000;
constexpr double kWalltimeBudgetS = 5400.0;
constexpr unsigned kRunTimeoutMs = 5000;
constexpr unsigned kBitsPerByte = 8;

// Сид add_gate отрицательного контроля — дословно сид task-070
// (tests/integration/concolic/test_add_gate_crash_budget.cpp:194).
constexpr std::array<std::uint8_t, 8> kAddGateSeed = {0x11, 0x22, 0x33, 0x44,
                                                      0x2D, 0x2C, 0x2B, 0x2A};

struct ExecServerProcess {
    pid_t pid = -1;
    int client_fd = -1;

    ExecServerProcess() = default;
    ExecServerProcess(const ExecServerProcess&) = delete;
    ExecServerProcess& operator=(const ExecServerProcess&) = delete;
    ExecServerProcess(ExecServerProcess&&) = delete;
    ExecServerProcess& operator=(ExecServerProcess&&) = delete;

    ~ExecServerProcess() {
        if (client_fd >= 0) {
            ::close(client_fd);
        }
        if (pid > 0) {
            ::kill(pid, SIGKILL);
            int status = 0;
            ::waitpid(pid, &status, 0);
        }
    }
};

bool SpawnExecServer(const std::string& bin, const std::string& target, const std::string& cov_lib,
                     ExecServerProcess& out, std::string& out_err) {
    std::array<int, 2> sv{};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv.data()) != 0) {
        out_err = std::string("socketpair: ") + std::strerror(errno);
        return false;
    }
    const int client_fd = sv[0];
    const int server_fd = sv[1];

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        ::close(client_fd);
        ::close(server_fd);
        out_err = std::string("fork: ") + std::strerror(err);
        return false;
    }
    if (pid == 0) {
        ::close(client_fd);
        if (server_fd != 3) {
            if (::dup2(server_fd, 3) < 0) {
                ::_exit(127);
            }
            ::close(server_fd);
        }
        const int flags3 = ::fcntl(3, F_GETFD);
        if (flags3 >= 0) {
            (void)::fcntl(3, F_SETFD, flags3 & ~FD_CLOEXEC);
        }
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)::dup2(devnull, 1);
            (void)::dup2(devnull, 2);
            if (devnull > 2) {
                ::close(devnull);
            }
        }
        const char* argv[] = {
            bin.c_str(), "-target", target.c_str(),    "-cov-library", cov_lib.c_str(),
            "-workers",  "1",       "-run-timeout-ms", "5000",         nullptr,
        };
        ::execv(bin.c_str(), const_cast<char* const*>(argv));
        ::_exit(127);
    }

    ::close(server_fd);
    out.client_fd = client_fd;
    out.pid = pid;
    return true;
}

bool PathReadable(const std::string& path) {
    return ::access(path.c_str(), R_OK) == 0;
}
bool PathExecutable(const std::string& path) {
    return ::access(path.c_str(), R_OK | X_OK) == 0;
}

// Пусто, когда все артефакты на месте; иначе причина пропуска. Каждый
// артефакт называется ОТНОСИТЕЛЬНЫМ путём, чтобы даже пропущенный прогон не
// оставил в сырье абсолютного пути.
std::string MissingArtifact() {
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_REL;
    }
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing: ") + ADD_GATE_REL;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_REL;
    }
    if (!PathExecutable(TIFF_TARGET_BIN)) {
        return std::string("libtiff target missing: ") + TIFF_TARGET_REL;
    }
    if (!PathReadable(TIFF_CORPUS_DIR)) {
        return std::string("libtiff corpus missing: ") + TIFF_CORPUS_REL;
    }
    return {};
}

const char* KindName(solver::Operand::Kind kind) {
    switch (kind) {
        case solver::Operand::Kind::kVar:
            return "var";
        case solver::Operand::Kind::kConst:
            return "const";
        case solver::Operand::Kind::kAddVars:
            return "addvars";
    }
    return "?";
}

const char* StatusName(solver::SolveResult::Status status) {
    switch (status) {
        case solver::SolveResult::Status::kSat:
            return "sat";
        case solver::SolveResult::Status::kUnsat:
            return "unsat";
        case solver::SolveResult::Status::kTimeout:
            return "timeout";
        case solver::SolveResult::Status::kError:
            return "error";
    }
    return "error";
}

std::uint64_t TruncateToWidth(std::uint64_t value, std::uint8_t bit_width) {
    if (bit_width >= 64) {
        return value;
    }
    return value & ((1ULL << bit_width) - 1ULL);
}

// Повторяет обратную запись SolveForCandidate (concolic.cpp:307-325) один в
// один; отдельно наружу она не выведена, а продуктовый вход умеет только
// target_index=last. Корректность этого повторения проверяется
// отрицательным контролем: кандидат, собранный этой функцией, обязан
// уронить add_gate.
std::optional<std::vector<std::uint8_t>> ApplyModel(std::span<const std::uint8_t> seed,
                                                    const concolic::System& sys,
                                                    const std::vector<std::uint64_t>& model) {
    if (model.size() != sys.num_vars) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(seed.begin(), seed.end());
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        const concolic::VarBinding& var = sys.vars[k];
        const unsigned n = var.bit_width / kBitsPerByte;
        if (var.offset + n > bytes.size()) {
            return std::nullopt;
        }
        const std::uint64_t value = TruncateToWidth(model[k], var.bit_width);
        for (unsigned b = 0; b < n; ++b) {
            const unsigned shift =
                var.big_endian ? (kBitsPerByte * (n - 1U - b)) : (kBitsPerByte * b);
            bytes[var.offset + b] = static_cast<std::uint8_t>(value >> shift);
        }
    }
    return bytes;
}

// Сетка развёртки одного сида: все i при path.size() <= kGridMax, иначе
// kGridMax точек равномерным шагом по [0, n-1]. Дубликаты не попадают.
std::vector<std::size_t> GridFor(std::size_t n) {
    std::vector<std::size_t> grid;
    if (n == 0) {
        return grid;
    }
    if (n <= kGridMax) {
        grid.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            grid.push_back(i);
        }
        return grid;
    }
    grid.reserve(kGridMax);
    for (std::size_t k = 0; k < kGridMax; ++k) {
        const std::size_t i = static_cast<std::size_t>(
            (static_cast<unsigned long long>(k) * static_cast<unsigned long long>(n - 1)) /
            static_cast<unsigned long long>(kGridMax - 1));
        if (grid.empty() || grid.back() != i) {
            grid.push_back(i);
        }
    }
    return grid;
}

// Порядок обхода сетки одного сида — перестановка Ван дер Корпута
// (обращение битов индекса). Зачем она нужна: бюджет стены конечен, и
// развёртка почти наверняка усекается на середине. При обходе сетки ПОДРЯД
// любой такой обрыв оставляет измеренным только НАЧАЛО пути — первый прогон
// этого стенда снял 1415 клеток, и 1394 из них легли в первый дециль
// позиции, то есть ось «где по пути стоит цель» осталась неизмеренной вовсе.
// При обращении битов любой ПРЕФИКС обхода примерно равномерен по всей
// длине сетки, поэтому усечение по бюджету даёт равномерную выборку позиций,
// а не её начало. Сама сетка не меняется — меняется только порядок, в
// котором её точки берутся.
std::vector<std::size_t> SweepOrder(std::size_t m) {
    std::vector<std::size_t> order;
    if (m == 0) {
        return order;
    }
    unsigned bits = 1;
    while ((1ULL << bits) < static_cast<unsigned long long>(m)) {
        ++bits;
    }
    const unsigned long long span = 1ULL << bits;
    order.reserve(m);
    for (unsigned long long k = 0; k < span; ++k) {
        unsigned long long rev = 0;
        for (unsigned b = 0; b < bits; ++b) {
            if ((k >> b) & 1ULL) {
                rev |= 1ULL << (bits - 1U - b);
            }
        }
        if (rev < static_cast<unsigned long long>(m)) {
            order.push_back(static_cast<std::size_t>(rev));
        }
    }
    return order;
}

struct SeedState {
    std::string name;
    std::size_t len = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<coverage::BranchReader::Record> records;
    concolic::System sys;
    std::vector<std::size_t> grid;   // фаза C: сетка без last
    std::vector<std::size_t> order;  // порядок обхода grid (Ван дер Корпут)
    std::size_t cells_done = 0;
    bool usable = false;
};

// Одна клетка развёртки: решает SolveInverted на заданном target_index и,
// когда sat, собирает кандидата и прогоняет его.
void MeasureCell(SeedState& st, std::size_t i, bool is_last, Runner* runner) {
    const solver::Constraint& target = st.sys.path[i];
    const auto t0 = std::chrono::steady_clock::now();
    const solver::SolveResult result =
        solver::SolveInverted(st.sys.num_vars, st.sys.path, i, kSolveTimeoutMs);
    const auto t1 = std::chrono::steady_clock::now();
    const long long solver_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::cout << "SWEEP-CELL seed=" << st.name << " i=" << i
              << " is_last=" << (is_last ? "yes" : "no") << " outcome=" << StatusName(result.status)
              << " path_size=" << st.sys.path.size() << " num_vars=" << st.sys.num_vars
              << " predicate=" << static_cast<unsigned>(target.predicate)
              << " bit_width=" << static_cast<unsigned>(target.bit_width)
              << " lhs_kind=" << KindName(target.lhs.kind)
              << " rhs_kind=" << KindName(target.rhs.kind) << " solver_ms=" << solver_ms;

    if (result.status == solver::SolveResult::Status::kSat) {
        const std::span<const std::uint8_t> seed(st.bytes.data(), st.bytes.size());
        const std::optional<std::vector<std::uint8_t>> cand =
            ApplyModel(seed, st.sys, result.model_values);
        if (!cand.has_value()) {
            std::cout << " cand=inconsistent cand_status=-2 cand_new_edges=-1";
        } else if (runner == nullptr) {
            std::cout << " cand=built cand_status=-3 cand_new_edges=-1";
        } else {
            const std::span<const std::uint8_t> cand_span(cand->data(), cand->size());
            const auto response = runner->Run(cand_span);
            if (!response.has_value()) {
                std::cout << " cand=built cand_status=-1 cand_new_edges=-1";
            } else {
                const int new_edges = response->has_edge_result()
                                          ? static_cast<int>(response->edge_result().new_edges())
                                          : 0;
                std::cout << " cand=built cand_status=" << static_cast<int>(response->status())
                          << " cand_new_edges=" << new_edges;
            }
        }
    }
    std::cout << '\n' << std::flush;
    ++st.cells_done;
}

TEST(SolverTargetIndexSweep, WhichConstraintIsInvertibleOnARealTarget) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    std::cout << "SWEEP-META solve_timeout_ms=" << kSolveTimeoutMs << " grid_max=" << kGridMax
              << " walltime_budget_s=" << kWalltimeBudgetS << " run_timeout_ms=" << kRunTimeoutMs
              << " target=" << TIFF_TARGET_REL << " corpus=" << TIFF_CORPUS_REL
              << " records_via=LastBranchRecords src_modified=0\n"
              << std::flush;

    // --- фаза A: отрицательный контроль стенда на add_gate ---
    {
        ExecServerProcess proc;
        std::string spawn_err;
        ASSERT_TRUE(
            SpawnExecServer(EXEC_SERVER_BIN, ADD_GATE_BIN, COV_LIBRARY_PATH, proc, spawn_err))
            << spawn_err;
        ipc::Conn client_conn(proc.client_fd);
        proc.client_fd = -1;
        auto session = ipc::ClientSession::Dial(
            std::move(client_conn),
            ipc::ClientConfig{.run_timeout_ms = kRunTimeoutMs, .expected_channels = 2});
        ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

        SessionRunner runner(*session);
        const std::span<const std::uint8_t> seed(kAddGateSeed.data(), kAddGateSeed.size());
        const auto response = runner.Run(seed);
        ASSERT_TRUE(response.has_value())
            << "transport error " << static_cast<int>(response.error());
        const std::vector<coverage::BranchReader::Record> records = runner.LastBranchRecords();
        const concolic::System sys = concolic::BuildSystem(seed, records);

        std::string outcome = "no-binding";
        int cand_status = -1;
        bool crashed = false;
        if (sys.invertible) {
            const solver::SolveResult result =
                solver::SolveInverted(sys.num_vars, sys.path, sys.path.size() - 1, kSolveTimeoutMs);
            outcome = StatusName(result.status);
            if (result.status == solver::SolveResult::Status::kSat) {
                const std::optional<std::vector<std::uint8_t>> cand =
                    ApplyModel(seed, sys, result.model_values);
                if (cand.has_value()) {
                    const std::span<const std::uint8_t> cand_span(cand->data(), cand->size());
                    const auto cand_response = runner.Run(cand_span);
                    if (cand_response.has_value()) {
                        cand_status = static_cast<int>(cand_response->status());
                        crashed = cand_response->status() == ipc::v1::EXEC_STATUS_CRASH;
                    }
                }
            }
        }
        std::cout << "SWEEP-CONTROL-ADDGATE records=" << records.size()
                  << " path_size=" << sys.path.size() << " num_vars=" << sys.num_vars
                  << " outcome=" << outcome << " cand_status=" << cand_status
                  << " crash=" << (crashed ? "yes" : "no") << '\n'
                  << std::flush;
        ASSERT_EQ(outcome, "sat") << "стенд сломан: add_gate не решается на i=last";
        ASSERT_TRUE(crashed) << "стенд сломан: кандидат add_gate не уронил цель";
    }

    // --- сиды: читаются с диска в лексикографическом порядке имени ---
    std::vector<SeedState> seeds;
    {
        std::vector<std::filesystem::path> files;
        for (const auto& entry : std::filesystem::directory_iterator(TIFF_CORPUS_DIR)) {
            if (entry.is_regular_file()) {
                files.push_back(entry.path());
            }
        }
        std::sort(files.begin(), files.end());
        for (const std::filesystem::path& file : files) {
            SeedState st;
            st.name = file.filename().string();
            std::ifstream in(file, std::ios::binary);
            st.bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            st.len = st.bytes.size();
            seeds.push_back(std::move(st));
        }
    }
    ASSERT_FALSE(seeds.empty()) << "корпус пуст";

    // --- фазы B и C идут в одной сессии над целью libtiff ---
    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(
        SpawnExecServer(EXEC_SERVER_BIN, TIFF_TARGET_BIN, COV_LIBRARY_PATH, proc, spawn_err))
        << spawn_err;
    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn),
        ipc::ClientConfig{.run_timeout_ms = kRunTimeoutMs, .expected_channels = 2});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());
    SessionRunner runner(*session);

    std::string stop_reason = "complete";

    // Фаза B: путь каждого сида и ровно одна клетка i=last.
    for (SeedState& st : seeds) {
        const std::span<const std::uint8_t> seed(st.bytes.data(), st.bytes.size());
        const auto response = runner.Run(seed);
        const int status = response.has_value() ? static_cast<int>(response->status()) : -1;
        if (response.has_value()) {
            st.records = runner.LastBranchRecords();
            st.sys = concolic::BuildSystem(seed, st.records);
            st.usable = st.sys.invertible;
        }
        std::vector<std::size_t> full_grid;
        if (st.usable) {
            full_grid = GridFor(st.sys.path.size());
            for (const std::size_t i : full_grid) {
                if (i != st.sys.path.size() - 1) {
                    st.grid.push_back(i);
                }
            }
            st.order = SweepOrder(st.grid.size());
        }
        std::cout << "SWEEP-SEED name=" << st.name << " len=" << st.len << " status=" << status
                  << " records=" << st.records.size() << " path_size=" << st.sys.path.size()
                  << " num_vars=" << st.sys.num_vars << " invertible=" << (st.usable ? "yes" : "no")
                  << " grid=" << full_grid.size()
                  << " grid_full=" << ((st.sys.path.size() <= kGridMax) ? "yes" : "no")
                  << " sweep_cells=" << st.grid.size() << '\n'
                  << std::flush;
        if (st.usable) {
            MeasureCell(st, st.sys.path.size() - 1, true, &runner);
        }
        if (elapsed_s() > kWalltimeBudgetS) {
            stop_reason = "walltime";
            break;
        }
    }

    // Фаза C: круговой обход сетки — раунд r берёт у каждого сида r-ю точку.
    if (stop_reason == "complete") {
        std::size_t max_grid = 0;
        for (const SeedState& st : seeds) {
            max_grid = std::max(max_grid, st.order.size());
        }
        for (std::size_t r = 0; r < max_grid && stop_reason == "complete"; ++r) {
            for (SeedState& st : seeds) {
                if (!st.usable || r >= st.order.size()) {
                    continue;
                }
                MeasureCell(st, st.grid[st.order[r]], false, &runner);
                if (elapsed_s() > kWalltimeBudgetS) {
                    stop_reason = "walltime";
                    break;
                }
            }
        }
    }

    std::size_t total_cells = 0;
    for (const SeedState& st : seeds) {
        std::cout << "SWEEP-SEED-DONE name=" << st.name << " cells=" << st.cells_done
                  << " sweep_cells=" << st.grid.size() << '\n';
        total_cells += st.cells_done;
    }
    std::cout << "SWEEP-DONE seeds=" << seeds.size() << " cells=" << total_cells
              << " stop_reason=" << stop_reason
              << " elapsed_s=" << static_cast<long long>(elapsed_s()) << " src_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
