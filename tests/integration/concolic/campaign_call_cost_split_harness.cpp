// Харнесс task-191 (ADR-0049): на что уходит цена вызова концолики В КАМПАНИИ —
// на построение системы или на её решение, с починкой F1 и без неё.
//
// Зачем. Лестница ADR-0049 мерила построение и решение офлайн, на записанных
// трассах, и потому оценка критерия К2 кампании опубликована двумя границами
// (docs/experiments/solver-fix-ladder/report.md:179-183). Здесь то же
// расщепление снимается внутри живой кампании — накопителями
// CampaignStats::concolic_build_us_total / concolic_solve_us_total
// (src/core/campaign.h:156-157), в микросекундах.
//
// Как снимается ПО-ВЫЗОВНОЕ сырьё без правки src/. Колбэка на вызов солвера у
// кампании нет; единственная публичная точка — CampaignLoop::Run, и её
// CampaignStats заводится заново на каждый вызов (src/core/campaign.cpp:360),
// а ГПСЧ, стагнация и корпус живут в членах объекта. Поэтому плечо идёт
// ЧАНКАМИ: max_iterations = 1 и Run() в цикле на одном экземпляре. Бюджет
// проверяется только в начале итерации (campaign.cpp:364), так что шаг
// концолики не разрывается между чанками, и чанк с concolic_calls == 1 несёт
// цену ровно одного вызова — без вычитаний.
//
// Контроль чанкования. Повторный Run обнуляет stats.execs, а якорь
// ограничителя частоты (ADR 0038) живёт в объекте: пока ограничитель молчит,
// это ни на что не влияет, а если бы он сработал, траектория чанков разошлась
// бы с цельной кампанией. Поэтому каждая пара (сид, плечо) прогоняется ещё и
// ЦЕЛИКОМ, одним Run, и счётчики траектории сверяются поле в поле:
// trajectory_match=yes|no.
//
// Плечи и сиды. Два плеча — F1 выключен (по умолчанию) и включён
// (CampaignConfig::concolic_fix_findfirst_index); бюджет, сид ГПСЧ, порог
// стагнации, таймаут солвера и max_det_steps — одни и те же константы. Сидов
// 21, они заданы формулой MakeSeed до прогона: префикс — восемь байт донора
// (kArmSeed, два verbatim-поля гейта), хвост — из mt19937_64 до длины от 8 до
// 64 байт (add_gate.c читает не больше 64). Хвост цель не читает, но
// построение системы сканирует весь сид на каждый операнд каждой записи, и
// именно эту работу F1 заменяет индексом (src/concolic/concolic.h:86-90).
//
// Детерминированная стадия выключена (max_det_steps = 0): иначе она способна
// съесть бюджет, и тогда concolic_calls = 0 при взведённой руке. Строка
// CALL-COST-CAMPAIGN печатает havoc_execs и calls, сводка —
// zero_call_campaigns.
//
// В ctest НЕ регистрируется: 42 кампании чанками и 42 контрольные — это
// минуты стены, а длинные развёртки в ctest стоят гейту часов. Запуск — своим
// run.sh. Бюджет стены kWalltimeBudgetS проверяется перед каждой кампанией;
// когда он потрачен, стенд печатает stop_reason=walltime.
//
// В сырьё попадают только относительные пути (*_REL); рабочие каталоги — под
// ::testing::TempDir(), то есть под TEST_TMPDIR, если она задана.

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
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <system_error>
#include <vector>

#include "campaign.h"
#include "corpus.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"

namespace mlfuzzz3::core {
namespace {

struct ExecServerProcess {
    pid_t pid = -1;
    int client_fd = -1;

    ExecServerProcess() = default;
    ExecServerProcess(const ExecServerProcess&) = delete;
    ExecServerProcess& operator=(const ExecServerProcess&) = delete;

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

// Донор: test_solver_time_by_outcome.cpp:111-161, без изменений.
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

// Пусто, если все артефакты на месте; иначе — причина пропуска, с путями от
// корня репозитория.
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
    return {};
}

// Всегда сид 0 корпуса: концолика каждый раз получает ровно сид этой
// кампании (донор: test_solver_time_by_outcome.cpp:193-201).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// Префикс каждого сида — байт в байт сид task-102/task-104
// (test_solver_time_by_outcome.cpp:206): под add_gate.c это a = 0x11223344,
// b = 0x2D2C2B2A.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Заданы до прогона и одинаковы в обоих плечах. Сид ГПСЧ, порог стагнации,
// бюджет и таймаут — донорские (test_solver_time_by_outcome.cpp:211-214).
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;
constexpr std::uint64_t kBudget = 200;
constexpr unsigned kConcolicTimeoutMs = 2000;

// Сиды: kSeedCount штук, длина растёт от kMinSeedLen до kMaxSeedLen
// равномерно, хвост — из mt19937_64 с затравкой kTailGenBase + k.
constexpr std::size_t kSeedCount = 21;
constexpr std::size_t kMinSeedLen = 8;   // add_gate.c:20, короче цель не читает
constexpr std::size_t kMaxSeedLen = 64;  // add_gate.c:18, длиннее цель не читает
constexpr std::uint64_t kTailGenBase = 191000;

// Бюджет стены на весь прогон; проверяется перед каждой кампанией.
constexpr double kWalltimeBudgetS = 1200.0;

std::size_t SeedLength(std::size_t k) {
    return kMinSeedLen + (k * (kMaxSeedLen - kMinSeedLen)) / (kSeedCount - 1);
}

std::vector<std::uint8_t> MakeSeed(std::size_t k) {
    std::vector<std::uint8_t> bytes(SeedLength(k));
    std::mt19937_64 gen(kTailGenBase + k);
    for (std::uint8_t& b : bytes) {
        b = static_cast<std::uint8_t>(gen() & 0xFFU);
    }
    std::copy(kArmSeed.begin(), kArmSeed.end(), bytes.begin());
    return bytes;
}

std::string Hex(const std::vector<std::uint8_t>& bytes) {
    static constexpr std::array<char, 16> kDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::uint8_t b : bytes) {
        out.push_back(kDigits[static_cast<std::size_t>(b >> 4U)]);
        out.push_back(kDigits[static_cast<std::size_t>(b & 0x0FU)]);
    }
    return out;
}

const char* ArmName(bool f1) {
    return f1 ? "f1_on" : "f1_off";
}

// Исход одного вызова по счётчикам чанка, в котором он был единственным.
const char* CallOutcome(const CampaignStats& chunk) {
    if (chunk.concolic_candidates != 0) {
        return "candidate";
    }
    if (chunk.concolic_no_binding != 0) {
        return "no_binding";
    }
    if (chunk.concolic_unsat != 0) {
        return "unsat";
    }
    if (chunk.concolic_timeout != 0) {
        return "timeout";
    }
    if (chunk.concolic_error != 0) {
        return "error";
    }
    return "unknown";
}

// Сумма чанков. Счётчик включений ограничителя — не приращение, а снимок
// накопителя объекта (campaign.cpp:220), поэтому берётся максимум.
void Accumulate(CampaignStats& into, const CampaignStats& chunk) {
    into.execs += chunk.execs;
    into.accepted += chunk.accepted;
    into.edges += chunk.edges;
    into.crashes += chunk.crashes;
    into.hangs += chunk.hangs;
    into.ipc_errors += chunk.ipc_errors;
    into.det_execs += chunk.det_execs;
    into.havoc_execs += chunk.havoc_execs;
    into.concolic_calls += chunk.concolic_calls;
    into.concolic_candidates += chunk.concolic_candidates;
    into.concolic_edges += chunk.concolic_edges;
    into.concolic_crashes += chunk.concolic_crashes;
    into.concolic_unsat += chunk.concolic_unsat;
    into.concolic_timeout += chunk.concolic_timeout;
    into.concolic_no_candidate += chunk.concolic_no_candidate;
    into.concolic_no_binding += chunk.concolic_no_binding;
    into.concolic_error += chunk.concolic_error;
    into.concolic_time_ms_total += chunk.concolic_time_ms_total;
    into.concolic_budget_skips += chunk.concolic_budget_skips;
    into.concolic_throttle_skips += chunk.concolic_throttle_skips;
    into.concolic_throttle_engagements =
        std::max(into.concolic_throttle_engagements, chunk.concolic_throttle_engagements);
    into.concolic_seed_run_ms_total += chunk.concolic_seed_run_ms_total;
    into.concolic_build_us_total += chunk.concolic_build_us_total;
    into.concolic_solve_us_total += chunk.concolic_solve_us_total;
    into.aborted = into.aborted || chunk.aborted;
}

// Траектория — всё, что не время. Совпадение поле в поле с цельной кампанией
// доказывает, что чанкование не изменило ни одного решения цикла.
bool SameTrajectory(const CampaignStats& a, const CampaignStats& b) {
    return a.execs == b.execs && a.accepted == b.accepted && a.edges == b.edges &&
           a.crashes == b.crashes && a.hangs == b.hangs && a.ipc_errors == b.ipc_errors &&
           a.det_execs == b.det_execs && a.havoc_execs == b.havoc_execs &&
           a.concolic_calls == b.concolic_calls && a.concolic_candidates == b.concolic_candidates &&
           a.concolic_edges == b.concolic_edges && a.concolic_crashes == b.concolic_crashes &&
           a.concolic_unsat == b.concolic_unsat && a.concolic_timeout == b.concolic_timeout &&
           a.concolic_no_binding == b.concolic_no_binding && a.concolic_error == b.concolic_error &&
           a.concolic_budget_skips == b.concolic_budget_skips &&
           a.concolic_throttle_skips == b.concolic_throttle_skips &&
           a.concolic_throttle_engagements == b.concolic_throttle_engagements &&
           a.aborted == b.aborted;
}

// Доля построения в цене вызова: build / (build + solve). -1, если вызовов с
// ненулевым временем не было.
double BuildShare(const CampaignStats& s) {
    const std::uint64_t sum = s.concolic_build_us_total + s.concolic_solve_us_total;
    return sum == 0 ? -1.0
                    : static_cast<double>(s.concolic_build_us_total) / static_cast<double>(sum);
}

// Одна кампания плеча. chunked = true — чанками по одной итерации с печатью
// строки на каждый вызов концолики; false — одним Run (контроль).
void RunArm(const std::vector<std::uint8_t>& seed, std::size_t seed_index, bool f1, bool chunked,
            CampaignStats& out_stats, std::uint64_t& out_chunks, std::uint64_t& out_wall_ms) {
    const std::string workspace = std::string("call_cost_split_") + ArmName(f1) +
                                  (chunked ? "_chunked_" : "_whole_") + std::to_string(seed_index);
    const std::filesystem::path base = std::filesystem::path(::testing::TempDir()) / workspace;
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    const std::filesystem::path seed_dir = base / "seeds";
    std::filesystem::create_directories(seed_dir);
    {
        std::ofstream out(seed_dir / "seed", std::ios::binary);
        out.write(reinterpret_cast<const char*>(seed.data()),
                  static_cast<std::streamsize>(seed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_EQ(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "call-cost-split");
    ASSERT_TRUE(metrics.has_value());

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(EXEC_SERVER_BIN, ADD_GATE_BIN, COV_LIBRARY_PATH, proc, spawn_err))
        << spawn_err;

    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn), ipc::ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    SessionRunner runner(*session);
    FixedScheduler scheduler;
    mutation::ByteFlipMutator mutator;
    const CampaignConfig cfg{.max_iterations = chunked ? std::uint64_t{1} : kBudget,
                             .metrics_interval = 0,
                             .rng_seed = kRngSeed,
                             .max_det_steps = 0,
                             .concolic_stagnation_threshold = kStagnationThreshold,
                             .concolic_timeout_ms = kConcolicTimeoutMs,
                             .concolic_fix_findfirst_index = f1};

    out_stats = CampaignStats{};
    out_chunks = 0;
    const auto t0 = std::chrono::steady_clock::now();
    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, cfg);
    if (!chunked) {
        out_stats = loop.Run();
        out_chunks = 1;
    } else {
        std::uint64_t call_index = 0;
        while (out_stats.execs < kBudget && !out_stats.aborted) {
            const std::uint64_t exec_at = out_stats.execs;
            const CampaignStats chunk = loop.Run();
            ++out_chunks;
            Accumulate(out_stats, chunk);
            if (chunk.concolic_calls > 1) {
                ADD_FAILURE() << "chunk carried " << chunk.concolic_calls << " concolic calls";
            }
            if (chunk.concolic_calls != 0) {
                std::cout << "CALL-COST-CALL arm=" << ArmName(f1) << " seed=" << seed_index
                          << " len=" << seed.size() << " call=" << call_index
                          << " exec_at=" << exec_at << " outcome=" << CallOutcome(chunk)
                          << " build_us=" << chunk.concolic_build_us_total
                          << " solve_us=" << chunk.concolic_solve_us_total
                          << " call_ms_trunc=" << chunk.concolic_time_ms_total
                          << " seed_run_ms=" << chunk.concolic_seed_run_ms_total
                          << " candidate_crashed=" << chunk.concolic_crashes << '\n';
                ++call_index;
            }
            if (chunk.execs == 0) {
                ADD_FAILURE() << "chunk made no progress";
                break;
            }
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    out_wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    std::filesystem::remove_all(base, ec);
}

void PrintCampaign(const char* tag, bool f1, std::size_t seed_index, std::size_t len,
                   const CampaignStats& s, std::uint64_t chunks, std::uint64_t wall_ms) {
    std::cout << tag << " arm=" << ArmName(f1) << " seed=" << seed_index << " len=" << len
              << " chunks=" << chunks << " execs=" << s.execs << " havoc_execs=" << s.havoc_execs
              << " det_execs=" << s.det_execs << " calls=" << s.concolic_calls
              << " candidates=" << s.concolic_candidates << " no_binding=" << s.concolic_no_binding
              << " unsat=" << s.concolic_unsat << " timeout=" << s.concolic_timeout
              << " error=" << s.concolic_error << " concolic_crashes=" << s.concolic_crashes
              << " crashes=" << s.crashes << " budget_skips=" << s.concolic_budget_skips
              << " throttle_engagements=" << s.concolic_throttle_engagements
              << " build_us_total=" << s.concolic_build_us_total
              << " solve_us_total=" << s.concolic_solve_us_total
              << " concolic_time_ms_total=" << s.concolic_time_ms_total << std::fixed
              << std::setprecision(4) << " build_share=" << BuildShare(s) << std::defaultfloat
              << " wall_ms=" << wall_ms << " aborted=" << (s.aborted ? "yes" : "no") << '\n'
              << std::flush;
}

// Минимум, медиана и максимум долей по сидам. Сидов нечётное число, и медиана
// берётся только при нечётном n — средний элемент, без полусумм; при чётном
// (стенд остановлен по стене) печатается median=na.
void PrintSummary(bool f1, const std::vector<double>& shares, std::uint64_t calls,
                  std::uint64_t build_us, std::uint64_t solve_us, std::size_t zero_call,
                  std::size_t mismatches) {
    std::vector<double> sorted = shares;
    std::sort(sorted.begin(), sorted.end());
    std::cout << "CALL-COST-SUMMARY arm=" << ArmName(f1) << " seeds_with_calls=" << sorted.size()
              << " calls=" << calls << " build_us_total=" << build_us
              << " solve_us_total=" << solve_us << " zero_call_campaigns=" << zero_call
              << " trajectory_mismatches=" << mismatches << std::fixed << std::setprecision(4);
    if (sorted.empty()) {
        std::cout << " build_share_min=na build_share_median=na build_share_max=na";
    } else {
        std::cout << " build_share_min=" << sorted.front();
        if (sorted.size() % 2 == 1) {
            std::cout << " build_share_median=" << sorted[sorted.size() / 2];
        } else {
            std::cout << " build_share_median=na";
        }
        std::cout << " build_share_max=" << sorted.back();
    }
    std::cout << std::defaultfloat << '\n' << std::flush;
}

}  // namespace

TEST(CampaignCallCostSplit, BuildVersusSolvePerCallWithAndWithoutF1) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }

    std::cout << "CALL-COST-META target=" << ADD_GATE_REL << " exec_server=" << EXEC_SERVER_REL
              << " cov_library=" << COV_LIBRARY_REL << " seeds=" << kSeedCount
              << " rng_seed=" << kRngSeed << " stagnation_threshold=" << kStagnationThreshold
              << " budget=" << kBudget << " concolic_timeout_ms=" << kConcolicTimeoutMs
              << " max_det_steps=0 walltime_budget_s=" << kWalltimeBudgetS
              << " time_unit=us arms=f1_off,f1_on\n"
              << std::flush;

    const auto start = std::chrono::steady_clock::now();
    std::array<std::vector<double>, 2> shares;
    std::array<std::uint64_t, 2> calls{};
    std::array<std::uint64_t, 2> build_us{};
    std::array<std::uint64_t, 2> solve_us{};
    std::array<std::size_t, 2> zero_call{};
    std::array<std::size_t, 2> mismatches{};
    const char* stop_reason = "done";
    std::size_t seeds_done = 0;

    for (std::size_t k = 0; k < kSeedCount; ++k) {
        const double spent =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (spent >= kWalltimeBudgetS) {
            stop_reason = "walltime";
            break;
        }
        const std::vector<std::uint8_t> seed = MakeSeed(k);
        std::cout << "CALL-COST-SEED seed=" << k << " len=" << seed.size() << " hex=" << Hex(seed)
                  << '\n'
                  << std::flush;
        for (const bool f1 : {false, true}) {
            const std::size_t arm = f1 ? 1 : 0;
            CampaignStats split;
            std::uint64_t split_chunks = 0;
            std::uint64_t split_wall_ms = 0;
            RunArm(seed, k, f1, /*chunked=*/true, split, split_chunks, split_wall_ms);
            if (HasFatalFailure()) {
                return;
            }
            PrintCampaign("CALL-COST-CAMPAIGN", f1, k, seed.size(), split, split_chunks,
                          split_wall_ms);

            CampaignStats whole;
            std::uint64_t whole_chunks = 0;
            std::uint64_t whole_wall_ms = 0;
            RunArm(seed, k, f1, /*chunked=*/false, whole, whole_chunks, whole_wall_ms);
            if (HasFatalFailure()) {
                return;
            }
            PrintCampaign("CALL-COST-CONTROL", f1, k, seed.size(), whole, whole_chunks,
                          whole_wall_ms);
            const bool match = SameTrajectory(split, whole);
            std::cout << "CALL-COST-TRAJECTORY arm=" << ArmName(f1) << " seed=" << k
                      << " trajectory_match=" << (match ? "yes" : "no") << '\n'
                      << std::flush;
            EXPECT_TRUE(match) << "seed " << k << " arm " << ArmName(f1);
            EXPECT_GT(split.concolic_calls, 0U) << "seed " << k << " arm " << ArmName(f1);

            calls[arm] += split.concolic_calls;
            build_us[arm] += split.concolic_build_us_total;
            solve_us[arm] += split.concolic_solve_us_total;
            if (split.concolic_calls == 0) {
                ++zero_call[arm];
            }
            if (!match) {
                ++mismatches[arm];
            }
            const double share = BuildShare(split);
            if (share >= 0.0) {
                shares[arm].push_back(share);
            }
        }
        ++seeds_done;
    }

    for (const bool f1 : {false, true}) {
        const std::size_t arm = f1 ? 1 : 0;
        PrintSummary(f1, shares[arm], calls[arm], build_us[arm], solve_us[arm], zero_call[arm],
                     mismatches[arm]);
    }
    const double used =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::cout << "CALL-COST-END seeds_done=" << seeds_done << " stop_reason=" << stop_reason
              << std::fixed << std::setprecision(0) << " walltime_used_s=" << used
              << std::defaultfloat << '\n'
              << std::flush;
}

}  // namespace mlfuzzz3::core
