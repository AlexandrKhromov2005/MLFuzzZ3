// Лестница починок солверной руки (ADR 0049): что каждая из четырёх правок
// делает с рукой на реальной цели.
//
// Зачем. Цепочка E0-E3 нашла четыре дефекта: построение системы в 59 раз
// дороже решения и цену несёт поиск операндов по входу (D1); две трети сумм
// полей вырождены (D2); форма системы включает суффикс пути после цели, чего
// нет ни в литературе, ни в тексте ADR-0034 (D3); обратная запись молча
// усекает модель у 98 % выполнимых кандидатов (D4). ADR 0049 предлагает по
// правке на дефект, каждую за своим флагом и по умолчанию выключенную.
// Принимать ADR или нет — решают числа этой развёртки.
//
// СТЕНД — тот же, что у E1 (tests/integration/concolic/test_solver_prefix_sweep.cpp),
// и от него не отличается ничем, кроме набора плеч: та же цель libtiff
// (md5 проверяет run.sh), те же 21 сид, та же сетка позиций, тот же порядок
// обхода (Ван дер Корпут), тот же таймаут решения 2000 мс. Вспомогательный
// код — дословно из харнесса E1.
//
// ПЛЕЧИ (восемь, порядок фиксирован здесь):
//   base            — всё выключено, воспроизведение E1 в форме продукта;
//   F4              — обратная запись не усекает;
//   F4+F2           — плюс запрет вырожденных сумм;
//   F4+F2+F1        — плюс индекс входа;
//   F4+F2+F1+F3pre  — плюс префиксная форма;
//   F4+F2+F1+F3opt  — плюс оптимистическая форма;
//   F2              — изоляция F2 (для P2);
//   F1              — изоляция F1 (для P3).
//
// ЧТО МЕРИТСЯ на клетку: исход, число записанных переменных, из них
// ведомых солвером шире их поля, усечённых и расширенных; новые рёбра
// кандидата и статус его прогона; время решения. На сид и плечо — время
// построения системы, размер пути и число переменных.
//
// ПОЧЕМУ ЧЕРЕЗ SolveSystemForTarget. Развёртка инвертирует каждую позицию
// пути, а продуктовый SolveForCandidate всегда берёт последнюю запись.
// Прежние развёртки решали это копией обратной записи внутри харнесса;
// здесь харнесс зовёт тот же код, которым пользуется продукт, и потому
// мерит его, а не свою копию.
//
// Предсказания P1-P5 и пороги записаны в ADR-0049 ДО этого прогона и после
// него не двигаются. Правило чтения — в run.sh каталога развёртки.

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

constexpr unsigned kSolveTimeoutMs = 2000;
constexpr std::size_t kGridMax = 2000;
// Бюджет стены НА ПЛЕЧО. У E1 он равен 5400 с, но там плечо было одно, а
// здесь их восемь: при 5400 с прогон занял бы около двенадцати часов.
// Сокращение бюджета не смещает выборку: обход идёт порядком Ван дер
// Корпута, и любой его префикс равномерен по позициям пути, поэтому
// урезанное плечо — равномерная подвыборка той же сетки, а не её начало.
constexpr double kWalltimeBudgetS = 2700.0;
constexpr unsigned kRunTimeoutMs = 5000;

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
// --- плечи лестницы -------------------------------------------------------

struct Arm {
    const char* name;
    concolic::Fixes fixes;
};

concolic::Fixes MakeFixes(bool f1, bool f2, bool f4, concolic::Fixes::Form form) {
    concolic::Fixes fx;
    fx.findfirst_index = f1;
    fx.strict_addvars = f2;
    fx.no_truncation = f4;
    fx.form = form;
    return fx;
}

std::vector<Arm> Arms() {
    using Form = concolic::Fixes::Form;
    return {
        {"base", MakeFixes(false, false, false, Form::kAllButTarget)},
        {"F4", MakeFixes(false, false, true, Form::kAllButTarget)},
        {"F4+F2", MakeFixes(false, true, true, Form::kAllButTarget)},
        {"F4+F2+F1", MakeFixes(true, true, true, Form::kAllButTarget)},
        {"F4+F2+F1+F3pre", MakeFixes(true, true, true, Form::kPrefix)},
        {"F4+F2+F1+F3opt", MakeFixes(true, true, true, Form::kOptimistic)},
        {"F2", MakeFixes(false, true, false, Form::kAllButTarget)},
        {"F1", MakeFixes(true, false, false, Form::kAllButTarget)},
    };
}

const char* OutcomeName(concolic::SolveOutcome outcome) {
    switch (outcome) {
        case concolic::SolveOutcome::kCandidate:
            return "candidate";
        case concolic::SolveOutcome::kNoBinding:
            return "no_binding";
        case concolic::SolveOutcome::kUnsat:
            return "unsat";
        case concolic::SolveOutcome::kTimeout:
            return "timeout";
        case concolic::SolveOutcome::kWidthOverflow:
            return "width_overflow";
        default:
            return "error";
    }
}

// Одна клетка: инверсия позиции i в системе этого плеча. Решение и обратная
// запись идут продуктовым кодом; харнесс печатает только то, что тот вернул.
void MeasureLadderCell(const Arm& arm, SeedState& st, std::size_t i, bool is_last, Runner* runner) {
    const solver::Constraint& target = st.sys.path[i];
    const std::span<const std::uint8_t> seed(st.bytes.data(), st.bytes.size());
    concolic::WriteBackStats stats;
    concolic::SolveOutcome outcome = concolic::SolveOutcome::kError;
    const auto t0 = std::chrono::steady_clock::now();
    const std::optional<mutation::FuzzInput> cand = concolic::SolveSystemForTarget(
        seed, st.sys, i, kSolveTimeoutMs, &outcome, arm.fixes, &stats);
    const auto t1 = std::chrono::steady_clock::now();
    const long long solve_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::cout << "LADDER-CELL arm=" << arm.name << " seed=" << st.name << " i=" << i
              << " is_last=" << (is_last ? "yes" : "no") << " outcome=" << OutcomeName(outcome)
              << " path_size=" << st.sys.path.size() << " num_vars=" << st.sys.num_vars
              << " predicate=" << static_cast<unsigned>(target.predicate)
              << " bit_width=" << static_cast<unsigned>(target.bit_width)
              << " lhs_kind=" << KindName(target.lhs.kind)
              << " rhs_kind=" << KindName(target.rhs.kind) << " solve_ms=" << solve_ms
              << " vars_written=" << stats.vars_written
              << " vars_wider=" << stats.vars_wider_than_binding
              << " vars_truncated=" << stats.vars_truncated
              << " vars_widened=" << stats.vars_widened;

    if (cand.has_value()) {
        if (runner == nullptr) {
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
    } else {
        std::cout << " cand=none cand_status=-4 cand_new_edges=-1";
    }
    std::cout << '\n' << std::flush;
    ++st.cells_done;
}

// Контроль на синтетическом гейте: сид известен, ответ известен. Печатает
// одну строку на плечо и на гейт; проверка порога — в analyze.py, харнесс
// только сообщает.
void RunGateControl(const Arm& arm, const char* label, const std::string& binary,
                    std::span<const std::uint8_t> seed) {
    ExecServerProcess proc;
    std::string spawn_err;
    if (!SpawnExecServer(EXEC_SERVER_BIN, binary, COV_LIBRARY_PATH, proc, spawn_err)) {
        std::cout << "LADDER-CONTROL arm=" << arm.name << " gate=" << label
                  << " outcome=spawn_failed cand_status=-1 crash=no new_edges=-1\n"
                  << std::flush;
        return;
    }
    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn),
        ipc::ClientConfig{.run_timeout_ms = kRunTimeoutMs, .expected_channels = 2});
    if (!session.has_value()) {
        std::cout << "LADDER-CONTROL arm=" << arm.name << " gate=" << label
                  << " outcome=dial_failed cand_status=-1 crash=no new_edges=-1\n"
                  << std::flush;
        return;
    }
    SessionRunner runner(*session);
    const auto response = runner.Run(seed);
    if (!response.has_value()) {
        std::cout << "LADDER-CONTROL arm=" << arm.name << " gate=" << label
                  << " outcome=run_failed cand_status=-1 crash=no new_edges=-1\n"
                  << std::flush;
        return;
    }
    const std::vector<coverage::BranchReader::Record> records = runner.LastBranchRecords();
    const concolic::System sys = concolic::BuildSystem(seed, records, arm.fixes);

    concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
    int cand_status = -1;
    int new_edges = -1;
    bool crashed = false;
    if (sys.invertible) {
        concolic::WriteBackStats stats;
        const std::optional<mutation::FuzzInput> cand = concolic::SolveSystemForTarget(
            seed, sys, sys.target_index, kSolveTimeoutMs, &outcome, arm.fixes, &stats);
        if (cand.has_value()) {
            const std::span<const std::uint8_t> cand_span(cand->data(), cand->size());
            const auto cand_response = runner.Run(cand_span);
            if (cand_response.has_value()) {
                cand_status = static_cast<int>(cand_response->status());
                crashed = cand_response->status() == ipc::v1::EXEC_STATUS_CRASH;
                new_edges = cand_response->has_edge_result()
                                ? static_cast<int>(cand_response->edge_result().new_edges())
                                : 0;
            }
        }
    }
    std::cout << "LADDER-CONTROL arm=" << arm.name << " gate=" << label
              << " records=" << records.size() << " path_size=" << sys.path.size()
              << " num_vars=" << sys.num_vars << " outcome=" << OutcomeName(outcome)
              << " cand_status=" << cand_status << " crash=" << (crashed ? "yes" : "no")
              << " new_edges=" << new_edges << '\n'
              << std::flush;
}

}  // namespace

TEST(SolverFixLadder, WhatFourFixesDoToTheSolverArm) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << "нет артефакта стенда: " << missing;
    }

    const std::vector<Arm> arms = Arms();
    std::cout << "LADDER-META arms=" << arms.size() << " solve_timeout_ms=" << kSolveTimeoutMs
              << " grid_max=" << kGridMax << " wall_budget_s_per_arm=" << kWalltimeBudgetS
              << " target=" << TIFF_TARGET_REL << " corpus=" << TIFF_CORPUS_REL
              << " records_via=LastBranchRecords solve_via=SolveSystemForTarget\n"
              << std::flush;
    for (const Arm& arm : arms) {
        std::cout << "LADDER-ARM name=" << arm.name << " f1=" << (arm.fixes.findfirst_index ? 1 : 0)
                  << " f2=" << (arm.fixes.strict_addvars ? 1 : 0)
                  << " f4=" << (arm.fixes.no_truncation ? 1 : 0) << " form="
                  << (arm.fixes.form == concolic::Fixes::Form::kPrefix
                          ? "prefix"
                          : (arm.fixes.form == concolic::Fixes::Form::kOptimistic
                                 ? "optimistic"
                                 : "all-but-target"))
                  << '\n'
                  << std::flush;
    }

    // Сиды читаются один раз: байты от плеча не зависят.
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(TIFF_CORPUS_DIR)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    ASSERT_FALSE(files.empty()) << "корпус пуст: " << TIFF_CORPUS_DIR;

    for (const Arm& arm : arms) {
        // К1 и К2 — до развёртки плеча: сломанный стенд не должен дать
        // ни одной клетки.
        const std::span<const std::uint8_t> gate_seed(kAddGateSeed.data(), kAddGateSeed.size());
        RunGateControl(arm, "add_gate", ADD_GATE_BIN, gate_seed);
        RunGateControl(arm, "add_gate_w16", ADD_GATE_W16_BIN, gate_seed);

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

        std::vector<SeedState> seeds;
        for (const std::filesystem::path& f : files) {
            SeedState st;
            st.name = f.filename().string();
            std::ifstream in(f, std::ios::binary);
            st.bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            st.len = st.bytes.size();
            const std::span<const std::uint8_t> seed(st.bytes.data(), st.bytes.size());
            const auto response = runner.Run(seed);
            if (!response.has_value()) {
                std::cout << "LADDER-SEED arm=" << arm.name << " seed=" << st.name
                          << " status=run_failed\n"
                          << std::flush;
                continue;
            }
            st.records = runner.LastBranchRecords();
            const auto b0 = std::chrono::steady_clock::now();
            st.sys = concolic::BuildSystem(seed, st.records, arm.fixes);
            const auto b1 = std::chrono::steady_clock::now();
            const long long build_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(b1 - b0).count();
            st.usable = st.sys.invertible;
            st.grid = st.usable ? GridFor(st.sys.path.size()) : std::vector<std::size_t>{};
            st.order = SweepOrder(st.grid.size());
            std::cout << "LADDER-BUILD arm=" << arm.name << " seed=" << st.name << " len=" << st.len
                      << " records=" << st.records.size() << " path_size=" << st.sys.path.size()
                      << " num_vars=" << st.sys.num_vars << " build_ms=" << build_ms
                      << " grid=" << st.grid.size() << " usable=" << (st.usable ? "yes" : "no")
                      << '\n'
                      << std::flush;
            if (st.usable) {
                seeds.push_back(std::move(st));
            }
        }

        // Фаза 1: клетка i = last у каждого сида — она сравнима с E0 и E1
        // напрямую и снимается раньше, чем кончится бюджет стены.
        const auto arm_start = std::chrono::steady_clock::now();
        for (SeedState& st : seeds) {
            MeasureLadderCell(arm, st, st.sys.path.size() - 1, true, &runner);
        }

        // Фаза 2: круговой обход сидов, внутри сида — порядок Ван дер
        // Корпута, чтобы любой префикс прогона был равномерен по позициям.
        bool progress = true;
        std::size_t round = 0;
        while (progress) {
            progress = false;
            for (SeedState& st : seeds) {
                if (round >= st.order.size()) {
                    continue;
                }
                const std::size_t gi = st.order[round];
                if (gi >= st.grid.size()) {
                    continue;
                }
                const std::size_t i = st.grid[gi];
                if (i + 1 == st.sys.path.size()) {
                    continue;  // уже снято в фазе 1
                }
                MeasureLadderCell(arm, st, i, false, &runner);
                progress = true;
                const double elapsed =
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - arm_start)
                        .count();
                if (elapsed > kWalltimeBudgetS) {
                    std::cout << "LADDER-BUDGET arm=" << arm.name << " stopped_after_s=" << elapsed
                              << '\n'
                              << std::flush;
                    progress = false;
                    break;
                }
            }
            ++round;
        }

        std::size_t cells = 0;
        for (const SeedState& st : seeds) {
            cells += st.cells_done;
        }
        const double arm_s =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - arm_start).count();
        std::cout << "LADDER-ARM-DONE arm=" << arm.name << " seeds=" << seeds.size()
                  << " cells=" << cells << " wall_s=" << arm_s << '\n'
                  << std::flush;
    }

    std::cout << "LADDER-DONE\n" << std::flush;
}

}  // namespace mlfuzzz3::core
