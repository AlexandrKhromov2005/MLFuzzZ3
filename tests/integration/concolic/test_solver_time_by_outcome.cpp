// task-107 (ADR-0039) — чистое время Z3 по классам исхода: там, где task-105
// мерил стенные часы, снимается таймер concolic_time_ms_total.
//
// Разрыв, который стенд закрывает. task-105 разделил обращения к солверу по
// исходу и получил медиану 320.00 мс у вызова, дошедшего до решения, против
// 4.93 мс у вызова, умершего на привязке, — отношение 64.9
// (docs/experiments/solver-call-cost-by-outcome/report.md, строка
// `VERDICT: SOLVER-CALL-COST-BY-OUTCOME`). Но делил он `wall_ms` всей пробы
// на число вызовов, то есть мерил стенные часы: прогон цели, инструментацию
// и накладные расходы кампании вместе с солвером. Чистое время Z3 отдельно
// от них не снималось ни разу.
//
// Откуда берётся чистое время. Поле `CampaignStats::concolic_time_ms_total`
// объявлено в src/core/campaign.h:123, а таймер вокруг него стоит в
// src/core/campaign.cpp:188-196: `solve_start` берётся на campaign.cpp:192,
// прибавление — на campaign.cpp:195, и под таймером ровно один вызов
// `concolic::SolveForCandidate` (campaign.cpp:194). Прогон сида под этот
// таймер НЕ попадает: он размечен отдельным счётчиком
// `concolic_seed_run_ms_total` на campaign.cpp:182-184, ДО начала
// `solve_start`. Поэтому вычитать время сида из `concolic_time_ms_total`
// нечего — его там нет.
//
// Что делает этот харнесс. В ОДНОМ процессе поднимает два плеча с уже
// известными чистыми классами исхода, на одном и том же RNG-сиде 7, одном и
// том же входном сиде, пороге стагнации 8 и бюджете 200:
//
//   * плечо b — tests/fixtures/add_gate/add_gate.c (u32). По task-102 даёт
//     `concolic_candidates=19, concolic_no_binding=0` — практически чистый
//     класс «дошёл до Z3»;
//   * плечо c — tests/fixtures/add_gate_w16/add_gate_w16.c (w16). По
//     task-102 даёт `concolic_calls=21, concolic_candidates=0,
//     concolic_no_binding=21` — чистый класс «умер на привязке».
//
// По каждому плечу печатается строка TIME-BY-OUTCOME с чистым временем и
// средним на вызов, строка TIME-BY-OUTCOME-PURITY с фактической чистотой
// класса в ЭТОМ прогоне (а не по памяти о task-102), и в конце строка
// TIME-BY-OUTCOME-SUMMARY с отношением b/c по чистому времени и ответом
// ratio_agrees против 64.9 из task-105. Допуск ±20% зарегистрирован ДО
// прогона в шапке docs/experiments/solver-time-by-outcome/run.sh, и
// kRatioTolerancePct ниже — ровно он.
//
// Чего стенд НЕ утверждает. Что число переносимо на реальные таргеты:
// измерение синтетическое, обе фикстуры — гейты из tests/fixtures. Что
// среднее по смешанному плечу есть цена класса: если плечо дало
// одновременно candidates>0 И no_binding>0, строка PURITY печатает
// mixed=yes, и среднее по нему читается как смесь, а не как цена класса.
//
// Границы. Бюджет фиксирован на 200, минимальный бюджет НЕ ищется: задача
// про цену вызова, а не про цену гейта. src/ не изменяется — таймер уже
// есть, его надо только прочитать. Жёсткий лимит времени 900 с
// (kWalltimeBudgetS, донорский рецепт test_w16_binding_gap.cpp:212): когда
// он потрачен, стенд останавливается там, где стоит, и публикует
// stop_reason=walltime.
//
// Гранулярность. Таймер копит целые миллисекунды и усекает КАЖДЫЙ вызов
// по отдельности (campaign.cpp:195-196, duration_cast в milliseconds), так
// что вызов короче миллисекунды вносит 0. Для дешёвого плеча это
// систематическое занижение вниз, и оно названо в meta-строке.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <system_error>

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

// Empty when every artifact this stand needs is present; otherwise the
// reason to skip. The message names artifacts by their REPO-RELATIVE path so
// that even a skipped run leaves no absolute path in the raw log.
std::string MissingArtifact() {
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_REL;
    }
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing (arm b, u32): ") + ADD_GATE_REL;
    }
    if (!PathExecutable(ADD_GATE_W16_BIN)) {
        return std::string("add_gate_w16 fixture missing (arm c, w16): ") + ADD_GATE_W16_REL;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_REL;
    }
    return {};
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger, and so the seed the concolic step
// sees is byte for byte the kArmSeed below
// (donor: test_w16_binding_gap.cpp:177-189).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// Byte for byte the seed of task-102/task-104 (test_w16_binding_gap.cpp:194).
// Under add_gate.c it decodes to a = 0x11223344, b = 0x2D2C2B2A; under
// add_gate_w16.c to a = 0x2211, b = 0x4433.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Fixed before the run, all four taken from task-104
// (test_w16_binding_gap.cpp:199-202). The budget is the control probe's 200;
// the minimal budget is NOT searched here.
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;
constexpr std::uint64_t kBudget = 200;
constexpr unsigned kConcolicTimeoutMs = 2000;

// The wall-clock ratio task-105 published (320.00 ms / 4.93 ms) and the
// tolerance registered before this run in the header of
// docs/experiments/solver-time-by-outcome/run.sh. ratio_agrees=yes iff the
// clean-time ratio lands inside 64.9 +- 20%, i.e. [51.92, 77.88].
constexpr double kTask105WallRatio = 64.9;
constexpr double kRatioTolerancePct = 20.0;

// Hard wall-time budget for the whole unit, named before the run
// (donor: test_w16_binding_gap.cpp:212). Checked before every campaign
// probe; when it is spent the stand stops where it stands and publishes
// stop_reason=walltime instead of a number it did not finish earning.
constexpr double kWalltimeBudgetS = 900.0;

// One bounded campaign, its counters and its wall time — the donor's
// RunCampaign (test_w16_binding_gap.cpp:436-486) unchanged, with the budget
// fixed at kBudget and no search around it. out_stats carries
// concolic_time_ms_total straight out of CampaignLoop::Run (campaign.h:157),
// which is the only way this stand learns the clean time.
void RunCampaign(const char* fixture_bin, const char* seed_name, const char* metrics_tag,
                 const char* workspace, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    const std::filesystem::path base = std::filesystem::path(::testing::TempDir()) / workspace;
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    const std::filesystem::path seed_dir = base / "seeds";
    std::filesystem::create_directories(seed_dir);
    {
        std::ofstream out(seed_dir / seed_name, std::ios::binary);
        out.write(reinterpret_cast<const char*>(kArmSeed.data()),
                  static_cast<std::streamsize>(kArmSeed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_GE(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", metrics_tag);
    ASSERT_TRUE(metrics.has_value());

    ExecServerProcess proc;
    std::string spawn_err;
    ASSERT_TRUE(SpawnExecServer(EXEC_SERVER_BIN, fixture_bin, COV_LIBRARY_PATH, proc, spawn_err))
        << spawn_err;

    ipc::Conn client_conn(proc.client_fd);
    proc.client_fd = -1;
    auto session = ipc::ClientSession::Dial(
        std::move(client_conn), ipc::ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
    ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

    SessionRunner runner(*session);
    FixedScheduler scheduler;
    mutation::ByteFlipMutator mutator;
    const CampaignConfig cfg{.max_iterations = kBudget,
                             .metrics_interval = 0,
                             .rng_seed = kRngSeed,
                             .max_det_steps = 0,
                             .concolic_stagnation_threshold = kStagnationThreshold,
                             .concolic_timeout_ms = kConcolicTimeoutMs};

    const auto t0 = std::chrono::steady_clock::now();
    CampaignLoop loop(runner, mutator, scheduler, *corpus, *metrics, cfg);
    out_stats = loop.Run();
    const auto t1 = std::chrono::steady_clock::now();
    out_wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    std::filesystem::remove_all(base, ec);
}

double MeanSolverMsPerCall(const CampaignStats& s) {
    return s.concolic_calls == 0 ? 0.0
                                 : static_cast<double>(s.concolic_time_ms_total) /
                                       static_cast<double>(s.concolic_calls);
}

double SolverShareOfWall(const CampaignStats& s, std::uint64_t wall_ms) {
    return wall_ms == 0
               ? 0.0
               : static_cast<double>(s.concolic_time_ms_total) / static_cast<double>(wall_ms);
}

// The required line, printed identically for both arms and read from one and
// the same field: stats.concolic_time_ms_total (campaign.h:123).
void PrintArm(const char* arm, const CampaignStats& s, std::uint64_t wall_ms) {
    std::cout << "TIME-BY-OUTCOME arm=" << arm << " calls=" << s.concolic_calls
              << " candidates=" << s.concolic_candidates << " no_binding=" << s.concolic_no_binding
              << " concolic_time_ms_total=" << s.concolic_time_ms_total << std::fixed
              << std::setprecision(2) << " mean_solver_ms_per_call=" << MeanSolverMsPerCall(s)
              << std::defaultfloat << " wall_ms=" << wall_ms << std::fixed << std::setprecision(2)
              << " solver_share_of_wall=" << SolverShareOfWall(s, wall_ms) << std::defaultfloat
              << '\n'
              << std::flush;
}

// Purity of the outcome class measured in THIS run, not recalled from
// task-102. expected_hits is candidates for the "reached Z3" arm and
// no_binding for the "died on binding" arm; mixed=yes as soon as both
// counters are non-zero, and then the mean above is a mixture, not the price
// of a class.
void PrintPurity(const char* arm, const char* expected_class, const CampaignStats& s) {
    const std::uint64_t expected_hits = std::strcmp(expected_class, "reached_z3") == 0
                                            ? s.concolic_candidates
                                            : s.concolic_no_binding;
    const bool mixed = s.concolic_candidates > 0 && s.concolic_no_binding > 0;
    const double frac = s.concolic_calls == 0 ? 0.0
                                              : static_cast<double>(expected_hits) /
                                                    static_cast<double>(s.concolic_calls);
    std::cout << "TIME-BY-OUTCOME-PURITY arm=" << arm << " expected_class=" << expected_class
              << " purity=" << expected_hits << "/" << s.concolic_calls << std::fixed
              << std::setprecision(2) << " purity_frac=" << frac << std::defaultfloat
              << " mixed=" << (mixed ? "yes" : "no") << " unsat=" << s.concolic_unsat
              << " timeout=" << s.concolic_timeout << " error=" << s.concolic_error
              << " execs=" << s.execs << " crashes=" << s.crashes
              << " aborted=" << (s.aborted ? "yes" : "no") << '\n'
              << std::flush;
}

}  // namespace

TEST(SolverTimeByOutcome, CleanZ3TimeSplitByOutcomeClass) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    const double lo = kTask105WallRatio * (1.0 - kRatioTolerancePct / 100.0);
    const double hi = kTask105WallRatio * (1.0 + kRatioTolerancePct / 100.0);

    std::cout << "TIME-BY-OUTCOME-META rng_seed=" << kRngSeed
              << " stagnation_threshold=" << kStagnationThreshold << " budget=" << kBudget
              << " concolic_timeout_ms=" << kConcolicTimeoutMs << " seed_len=" << kArmSeed.size()
              << " walltime_budget_s=" << kWalltimeBudgetS << " arm_b=" << ADD_GATE_REL
              << " arm_c=" << ADD_GATE_W16_REL
              << " time_source=CampaignStats::concolic_time_ms_total"
              << " timer_at=src/core/campaign.cpp:192-196"
              << " timer_covers=SolveForCandidate_only"
              << " seed_run_excluded=concolic_seed_run_ms_total"
              << " timer_granularity_ms=1 timer_truncates_per_call=yes"
              << " task105_wall_ratio=" << kTask105WallRatio << std::fixed << std::setprecision(2)
              << " tolerance_pct=" << kRatioTolerancePct << " agree_band=[" << lo << "," << hi
              << "]" << std::defaultfloat << " src_modified=0\n"
              << std::flush;

    const char* stop_reason = "complete";

    CampaignStats b_stats;
    std::uint64_t b_wall_ms = 0;
    bool b_ran = false;
    if (elapsed_s() <= kWalltimeBudgetS) {
        RunCampaign(ADD_GATE_BIN, "arm_b_u32.bin", "time-by-outcome-b", "time-by-outcome-b",
                    b_stats, b_wall_ms);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
        b_ran = true;
        PrintArm("u32", b_stats, b_wall_ms);
        PrintPurity("u32", "reached_z3", b_stats);
    } else {
        stop_reason = "walltime";
    }

    CampaignStats c_stats;
    std::uint64_t c_wall_ms = 0;
    bool c_ran = false;
    if (elapsed_s() <= kWalltimeBudgetS) {
        RunCampaign(ADD_GATE_W16_BIN, "arm_c_w16.bin", "time-by-outcome-c", "time-by-outcome-c",
                    c_stats, c_wall_ms);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
        c_ran = true;
        PrintArm("w16", c_stats, c_wall_ms);
        PrintPurity("w16", "died_on_binding", c_stats);
    } else {
        stop_reason = "walltime";
    }

    // The ratio is only defined when both arms ran AND the cheap arm's clean
    // time is non-zero; a zero there is the 1 ms granularity swallowing the
    // arm, not an infinitely fast solver, so it is published as
    // ratio=undefined rather than as a number.
    const double b_mean = MeanSolverMsPerCall(b_stats);
    const double c_mean = MeanSolverMsPerCall(c_stats);
    const bool ratio_defined = b_ran && c_ran && c_mean > 0.0;
    const double ratio = ratio_defined ? b_mean / c_mean : 0.0;
    const bool agrees = ratio_defined && ratio >= lo && ratio <= hi;

    std::cout << std::fixed << std::setprecision(2)
              << "TIME-BY-OUTCOME-SUMMARY arm_b=u32 arm_b_calls=" << b_stats.concolic_calls
              << " arm_b_purity=" << b_stats.concolic_candidates << "/" << b_stats.concolic_calls
              << " arm_b_mean_solver_ms=" << b_mean << " arm_c=w16"
              << " arm_c_calls=" << c_stats.concolic_calls
              << " arm_c_purity=" << c_stats.concolic_no_binding << "/" << c_stats.concolic_calls
              << " arm_c_mean_solver_ms=" << c_mean << " ratio_b_over_c_solver=";
    if (ratio_defined) {
        std::cout << std::setprecision(1) << ratio << std::setprecision(2);
    } else {
        std::cout << "undefined";
    }
    std::cout << " ratio_b_over_c_wall_task105=" << kTask105WallRatio
              << " ratio_agrees=" << (agrees ? "yes" : "no")
              << " solver_share_of_wall_b=" << SolverShareOfWall(b_stats, b_wall_ms)
              << " solver_share_of_wall_c=" << SolverShareOfWall(c_stats, c_wall_ms)
              << std::defaultfloat << " rng_seed=" << kRngSeed
              << " stagnation_threshold=" << kStagnationThreshold << " budget=" << kBudget
              << " stop_reason=" << stop_reason << " src_modified=0\n"
              << std::flush;

    // The stand must have measured something to be worth reading: both arms
    // ran and both actually reached the solver. Nothing is asserted about
    // WHICH way the ratio came out — both outcomes are a result.
    EXPECT_TRUE(b_ran) << "arm b (u32) did not run: stop_reason=" << stop_reason;
    EXPECT_TRUE(c_ran) << "arm c (w16) did not run: stop_reason=" << stop_reason;
    EXPECT_GT(b_stats.concolic_calls, 0U) << "arm b never called the solver";
    EXPECT_GT(c_stats.concolic_calls, 0U) << "arm c never called the solver";
}

}  // namespace mlfuzzz3::core
