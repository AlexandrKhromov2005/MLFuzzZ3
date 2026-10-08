// task-106 (ADR-0047) — что именно рвёт привязку на 16 битах: маркировка
// ширины в записи ветвления или поиск смещений во входе.
//
// Разрыв, который стенд обязан разделить. task-104
// (docs/experiments/solver-w16-binding-gap/report.md) снял живые записи
// плеча add_gate_w16 и получил `h1=SURVIVED, h2=SURVIVED, h3=EXCLUDED,
// cause_named=no`: записи сравнений над uint16_t-полями приходят с
// `bit_width=32` (строки W16-RECORD в raw-w16-binding-gap.txt), поэтому
// поле шириной 16 никто во входе не ищет. Этого хватило, чтобы исключить
// H3, но не хватило, чтобы разделить
//   H1 — до солвера не доходят записи нужной формы (виновата маркировка
//        ширины в записи), и
//   H2 — записи те, но байты полей не находятся во входе дословно
//        (виноват поиск смещений, concolic.cpp:136 FindFirst).
// Обе гипотезы предсказывают одно и то же наблюдаемое
// (`concolic_candidates=0` при `concolic_calls=21`, task-102), но означают
// разное.
//
// Что делает этот харнесс. В ОДНОМ процессе снимает живые записи плеча w16
// тем же вызовом, каким их берёт кампания (Run(seed), сразу
// LastBranchRecords(); ADR-0036, src/core/campaign.cpp:180-181), и делает
// над ОДНИМИ И ТЕМИ ЖЕ записями и ОДНИМ И ТЕМ ЖЕ входом три прямые пробы:
//
//   A — concolic::BuildSystem над записями КАК ЕСТЬ. Контроль
//       воспроизведения task-104; ожидание bound=no.
//   B — concolic::BuildSystem над КОПИЕЙ тех же записей, у которой
//       bit_width усечён до 16 (значения операндов не меняются). Копия
//       строится из того же вектора — см. NarrowToW16 ниже.
//   C — поиск двухбайтового представления КАЖДОГО операнда тех же записей
//       по тому же входу: находится ли паттерн вообще.
//
// Почему проба C зовёт продакшен-поиск не по имени. FindFirst
// (src/concolic/concolic.cpp:136) объявлен в анонимном пространстве имён
// concolic.cpp, у него внутренняя компоновка, а src/ этот юнит не трогает.
// Поэтому C доходит до ТОГО ЖЕ FindFirst через единственный публичный вход,
// который его вызывает: BuildSystem, проход 1 «discover findable fields»
// (concolic.cpp:216-228) зовёт FindFirst на обоих операндах каждой записи и
// кладёт найденное поле в System::vars. C подсовывает синтетическую запись
// из одного сравнения eq(V, V) шириной 16 бит и читает System::vars —
// то есть печатает ровно то, что вернул FindFirst (смещение и порядок
// байтов), а не пересказ его правил.
//
// Почему классификация операндов в A и B читается из ПОЛНОЙ системы.
// Привязка операнда зависит от набора полей, найденных по ВСЕМ записям
// (concolic.cpp:229-236 offset_to_index, concolic.cpp:196-207 сумма двух
// полей → kAddVars), поэтому одна запись в отдельности классифицируется
// иначе, чем та же запись внутри своего набора: у add_gate_w16 сумма
// a+b находится только тогда, когда оба поля уже открыты другими записями.
// ClassifyRecord ниже дублирует разбираемую запись в ХВОСТ того же вектора:
// набор найденных полей от этого не меняется (try_emplace по смещению), а
// разбираемая запись становится последней, поэтому её конъюнкт — это
// path.back(), и видно, пережила ли она границу «B» (concolic.cpp:244-247).
//
// Правило чтения гипотез зарегистрировано ДО прогона в шапке
// docs/experiments/solver-w16-hypothesis-split/run.sh; функция Decide ниже
// реализует ровно те правила и ничего сверх них.
//
// Границы. Бюджет кампании фиксирован на 200 (значение контрольной пробы
// task-102), минимальный бюджет НЕ ищется, кампания нужна только чтобы
// счётчики этого прогона можно было сверить с task-102/task-104. src/ не
// изменяется. Жёсткий лимит времени 900 с по донорскому рецепту
// (test_add_gate_be_crash_budget.cpp:214-218): когда он потрачен, стенд
// останавливается там, где стоит, и публикует stop_reason=walltime.

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
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include "campaign.h"
#include "concolic.h"
#include "corpus.h"
#include "metrics.h"
#include "mutators/byte_flip.h"
#include "runner.h"
#include "seed_scheduler.h"
#include "session.h"
#include "solver_facade.h"

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
    if (!PathExecutable(ADD_GATE_W16_BIN)) {
        return std::string("add_gate_w16 fixture missing: ") + ADD_GATE_W16_REL;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_REL;
    }
    return {};
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger (donor:
// test_w16_binding_gap.cpp, FixedScheduler).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// Byte for byte the seed of task-102/task-104
// (test_w16_binding_gap.cpp, kArmSeed). Under add_gate_w16.c it decodes to
// a = 0x2211 (offset 0) and b = 0x4433 (offset 2).
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Fixed before the run, all taken from task-102 via task-104. The budget is
// the control probe's 200; the minimal budget is NOT searched here.
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;
constexpr std::uint64_t kBudget = 200;
constexpr unsigned kConcolicTimeoutMs = 2000;

// The width of the fields add_gate_w16.c reads (add_gate_w16.c:60-62) —
// the width probes B and C use, and the only width this stand narrows to.
constexpr unsigned kW16FieldBits = 16;
constexpr unsigned kBitsPerByte = 8;

// Hard wall-time budget for the whole unit, named before the run
// (test_add_gate_be_crash_budget.cpp:214-218).
constexpr double kWalltimeBudgetS = 900.0;

// fuzzer_rt_cmp_kind names, ADR-0033 fixed ABI (mirror of concolic.cpp:13-25).
const char* PredicateName(std::uint8_t predicate) {
    switch (predicate) {
        case 0:
            return "eq";
        case 1:
            return "ne";
        case 2:
            return "ult";
        case 3:
            return "ule";
        case 4:
            return "ugt";
        case 5:
            return "uge";
        case 6:
            return "slt";
        case 7:
            return "sle";
        case 8:
            return "sgt";
        case 9:
            return "sge";
        default:
            return "unknown";
    }
}

const char* KindName(solver::Operand::Kind kind) {
    switch (kind) {
        case solver::Operand::Kind::kVar:
            return "var";
        case solver::Operand::Kind::kAddVars:
            return "addvars";
        case solver::Operand::Kind::kConst:
        default:
            return "const";
    }
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
        case concolic::SolveOutcome::kError:
        default:
            return "error";
    }
}

std::string Hex(std::uint64_t value) {
    std::ostringstream os;
    os << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return os.str();
}

// The little-endian byte pattern FindFirst looks for at this width: the low
// bit_width/8 bytes of the value, low byte first. This is FORMATTING of the
// operand value, not a search — the search itself is always the production
// one (see the header note on probe C).
std::string PatternHex(std::uint64_t value, unsigned bit_width) {
    const unsigned n = bit_width / kBitsPerByte;
    if (n == 0 || n > sizeof(std::uint64_t)) {
        return "-";
    }
    std::ostringstream os;
    for (unsigned k = 0; k < n; ++k) {
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned>(static_cast<std::uint8_t>(value >> (kBitsPerByte * k)));
    }
    return os.str();
}

// A copy of the same records with bit_width truncated to 16; operand values
// are NOT touched. This is the ONLY difference between probe A and probe B,
// and the copy is made from the very vector probe A ran on.
std::vector<coverage::BranchReader::Record> NarrowToW16(
    const std::vector<coverage::BranchReader::Record>& records) {
    std::vector<coverage::BranchReader::Record> narrowed = records;
    for (coverage::BranchReader::Record& rec : narrowed) {
        rec.bit_width = static_cast<std::uint8_t>(std::min<unsigned>(rec.bit_width, kW16FieldBits));
    }
    return narrowed;
}

// What the production binding did with ONE side of ONE record, read off the
// system the production code built.
struct SideBinding {
    solver::Operand::Kind kind = solver::Operand::Kind::kConst;
    bool record_kept = false;  // the record survived boundary "B"
    std::string offset = "none";
    std::string endian = "-";
    std::string sum_offsets = "-";
};

// Classify record `index` inside its OWN record set: duplicate it at the
// tail of the same vector (field discovery is by offset and idempotent, so
// the found-field set does not change), build the system, and read the last
// conjunct — that is this record's, if it survived boundary "B".
void ClassifyRecord(std::span<const std::uint8_t> seed,
                    const std::vector<coverage::BranchReader::Record>& records, std::size_t index,
                    std::size_t base_path_len, SideBinding& lhs_out, SideBinding& rhs_out) {
    std::vector<coverage::BranchReader::Record> probe = records;
    probe.push_back(records[index]);
    const concolic::System sys = concolic::BuildSystem(seed, probe);
    if (sys.path.size() != base_path_len + 1) {
        return;  // dropped by boundary "B": both sides are constants
    }
    const solver::Constraint& c = sys.path.back();
    const auto fill = [&sys](const solver::Operand& operand, SideBinding& out) {
        out.kind = operand.kind;
        out.record_kept = true;
        if (operand.kind == solver::Operand::Kind::kVar && operand.var_index < sys.vars.size()) {
            out.offset = std::to_string(sys.vars[operand.var_index].offset);
            out.endian = sys.vars[operand.var_index].big_endian ? "be" : "le";
        } else if (operand.kind == solver::Operand::Kind::kAddVars &&
                   operand.var_index < sys.vars.size() && operand.var_index2 < sys.vars.size()) {
            out.sum_offsets = std::to_string(sys.vars[operand.var_index].offset) + "+" +
                              std::to_string(sys.vars[operand.var_index2].offset);
        }
    };
    fill(c.lhs, lhs_out);
    fill(c.rhs, rhs_out);
}

// Everything one system-level probe (A or B) contributes to the verdict.
struct SystemProbe {
    std::string label;
    std::size_t records = 0;
    std::size_t num_vars = 0;
    std::size_t path_len = 0;
    std::size_t records_kept = 0;
    std::size_t direct_binds = 0;   // operands bound as kVar
    std::size_t addvars_binds = 0;  // operands bound as kAddVars
    bool invertible = false;
    concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
    bool candidate = false;
    std::string vars_desc = "-";
};

// Run one system-level probe over `recs` (the records as they go into
// BuildSystem) while reporting each record's ORIGINAL width from `original`,
// so an A/B line pair shows exactly what changed between the probes.
void RunSystemProbe(const char* label, std::span<const std::uint8_t> seed,
                    const std::vector<coverage::BranchReader::Record>& recs,
                    const std::vector<coverage::BranchReader::Record>& original, SystemProbe& out) {
    out.label = label;
    out.records = recs.size();

    const concolic::System sys = concolic::BuildSystem(seed, recs);
    out.num_vars = sys.num_vars;
    out.path_len = sys.path.size();
    out.invertible = sys.invertible;

    for (std::size_t i = 0; i < recs.size(); ++i) {
        SideBinding lhs;
        SideBinding rhs;
        ClassifyRecord(seed, recs, i, sys.path.size(), lhs, rhs);
        if (lhs.record_kept) {
            ++out.records_kept;
        }
        for (int side = 0; side < 2; ++side) {
            const SideBinding& b = (side == 0) ? lhs : rhs;
            const std::uint64_t value = (side == 0) ? recs[i].lhs : recs[i].rhs;
            const bool bound = b.record_kept && b.kind != solver::Operand::Kind::kConst;
            if (bound && b.kind == solver::Operand::Kind::kVar) {
                ++out.direct_binds;
            }
            if (bound && b.kind == solver::Operand::Kind::kAddVars) {
                ++out.addvars_binds;
            }
            std::cout << "SPLIT-PROBE probe=" << label << " seq=" << i
                      << " side=" << (side == 0 ? "lhs" : "rhs")
                      << " op=" << PredicateName(recs[i].predicate) << "("
                      << static_cast<unsigned>(recs[i].predicate) << ")"
                      << " bit_width_in=" << static_cast<unsigned>(original[i].bit_width)
                      << " bit_width_used=" << static_cast<unsigned>(recs[i].bit_width)
                      << " operand=" << Hex(value)
                      << " pattern_bytes=" << PatternHex(value, recs[i].bit_width)
                      << " found_offset=" << b.offset << " endian=" << b.endian
                      << " bound=" << (bound ? "yes" : "no") << " kind=" << KindName(b.kind)
                      << " sum_offsets=" << b.sum_offsets
                      << " record_kept=" << (b.record_kept ? "yes" : "no")
                      << " site_id=" << recs[i].site_id << '\n';
        }
    }

    std::ostringstream vars;
    for (std::size_t i = 0; i < sys.vars.size(); ++i) {
        vars << (i == 0 ? "" : ",") << sys.vars[i].offset << (sys.vars[i].big_endian ? "be" : "le")
             << "/" << static_cast<unsigned>(sys.vars[i].bit_width);
    }
    out.vars_desc = sys.vars.empty() ? std::string("-") : vars.str();

    concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
    const auto candidate = concolic::SolveForCandidate(seed, recs, kConcolicTimeoutMs, &outcome);
    out.outcome = outcome;
    out.candidate = candidate.has_value();

    std::cout << "SPLIT-SYSTEM probe=" << label << " records=" << out.records
              << " num_vars=" << out.num_vars << " path_len=" << out.path_len
              << " target_index=" << sys.target_index
              << " invertible=" << (out.invertible ? "yes" : "no") << " vars=" << out.vars_desc
              << " direct_binds=" << out.direct_binds << " addvars_binds=" << out.addvars_binds
              << " records_kept=" << out.records_kept << " outcome=" << OutcomeName(out.outcome)
              << " candidate=" << (out.candidate ? "yes" : "no") << '\n'
              << std::flush;
}

// Probe C for one operand value: does its 16-bit little/big-endian pattern
// occur in the input at all? Reaches the production FindFirst
// (concolic.cpp:136) through BuildSystem's discovery pass by handing it a
// single synthetic comparison eq(V, V) at 16 bits and reading System::vars.
struct FoundField {
    std::size_t offset = 0;
    bool big_endian = false;
};

std::optional<FoundField> ProbeFindFirstW16(std::span<const std::uint8_t> seed,
                                            std::uint64_t value) {
    const coverage::BranchReader::Record synthetic{
        .site_id = 0,
        .predicate = 0,  // eq
        .bit_width = static_cast<std::uint8_t>(kW16FieldBits),
        .lhs = value,
        .rhs = value,
    };
    const concolic::System sys =
        concolic::BuildSystem(seed, std::vector<coverage::BranchReader::Record>{synthetic});
    if (sys.vars.empty()) {
        return std::nullopt;
    }
    return FoundField{.offset = sys.vars.front().offset, .big_endian = sys.vars.front().big_endian};
}

// One bounded campaign on the w16 arm — counters only, budget fixed at
// kBudget, no search around it (donor: test_w16_binding_gap.cpp,
// RunCampaign).
void RunCampaign(const char* fixture_bin, CampaignStats& out_stats, std::uint64_t& out_wall_ms) {
    const std::filesystem::path base =
        std::filesystem::path(::testing::TempDir()) / "w16-hypothesis-split";
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    const std::filesystem::path seed_dir = base / "seeds";
    std::filesystem::create_directories(seed_dir);
    {
        std::ofstream out(seed_dir / "arm_w16.bin", std::ios::binary);
        out.write(reinterpret_cast<const char*>(kArmSeed.data()),
                  static_cast<std::streamsize>(kArmSeed.size()));
    }

    auto corpus = Corpus::Create(base / "corpus");
    ASSERT_TRUE(corpus.has_value());
    ASSERT_TRUE(corpus->Bootstrap(seed_dir).has_value());
    ASSERT_GE(corpus->size(), 1U);

    auto metrics = MetricsEmitter::Create(base / "metrics.jsonl", "w16split-w16");
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

// The pre-registered reading rule, transcribed from the header of
// docs/experiments/solver-w16-hypothesis-split/run.sh. Nothing here reads
// anything but the three probes.
struct Split {
    const char* h1 = "SURVIVED";
    const char* h2 = "SURVIVED";
    bool reformulate = false;
    bool cause_named = false;
    const char* rule = "none";
};

Split Decide(bool probe_a_bound, bool probe_b_bound, std::size_t probe_c_found) {
    Split out;
    if (probe_a_bound) {
        // Probe A did not reproduce task-104: the split says nothing.
        out.rule = "R0-no-repro";
        return out;
    }
    if (probe_b_bound) {
        out.h1 = "SURVIVED";
        out.h2 = "EXCLUDED";
        out.cause_named = true;
        out.rule = "R1-width-marking";
        return out;
    }
    if (probe_c_found > 0) {
        out.h1 = "EXCLUDED";
        out.h2 = "SURVIVED";
        out.cause_named = true;
        out.rule = "R2-after-offset-search";
        return out;
    }
    out.reformulate = true;
    out.rule = "R3-reformulate";
    return out;
}

TEST(W16HypothesisSplit, WhatBreaksBindingAtWidth16MarkingOrOffsetSearch) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    std::cout << "SPLIT-META rng_seed=" << kRngSeed
              << " stagnation_threshold=" << kStagnationThreshold << " budget=" << kBudget
              << " concolic_timeout_ms=" << kConcolicTimeoutMs << " width_bits=" << kW16FieldBits
              << " endian=le seed_len=" << kArmSeed.size()
              << " walltime_budget_s=" << kWalltimeBudgetS << " w16=" << ADD_GATE_W16_REL
              << " records_via=LastBranchRecords src_modified=0\n"
              << std::flush;

    // --- live records of the w16 arm, taken the campaign's own way ---
    std::vector<coverage::BranchReader::Record> records;
    {
        ExecServerProcess proc;
        std::string spawn_err;
        ASSERT_TRUE(
            SpawnExecServer(EXEC_SERVER_BIN, ADD_GATE_W16_BIN, COV_LIBRARY_PATH, proc, spawn_err))
            << spawn_err;

        ipc::Conn client_conn(proc.client_fd);
        proc.client_fd = -1;
        auto session = ipc::ClientSession::Dial(
            std::move(client_conn),
            ipc::ClientConfig{.run_timeout_ms = 5000, .expected_channels = 2});
        ASSERT_TRUE(session.has_value()) << "Dial failed: " << static_cast<int>(session.error());

        SessionRunner runner(*session);
        const std::span<const std::uint8_t> arm_seed(kArmSeed.data(), kArmSeed.size());
        // The campaign's own two lines, in the campaign's own order
        // (src/core/campaign.cpp:180-181, ADR-0036 §3).
        const auto response = runner.Run(arm_seed);
        ASSERT_TRUE(response.has_value())
            << "transport error " << static_cast<int>(response.error());
        records = runner.LastBranchRecords();

        std::ostringstream seed_hex;
        for (const std::uint8_t byte : kArmSeed) {
            seed_hex << std::hex << std::setw(2) << std::setfill('0')
                     << static_cast<unsigned>(byte);
        }
        std::cout << "SPLIT-SEED arm=w16 bytes=" << seed_hex.str() << " len=" << kArmSeed.size()
                  << " status=" << static_cast<int>(response->status())
                  << " records=" << records.size() << '\n'
                  << std::flush;
    }
    ASSERT_FALSE(records.empty()) << "no live branch records: nothing to split hypotheses on";

    const std::span<const std::uint8_t> seed(kArmSeed.data(), kArmSeed.size());

    std::size_t records_bw16 = 0;
    std::size_t records_bw32 = 0;
    for (const coverage::BranchReader::Record& rec : records) {
        if (rec.bit_width == kW16FieldBits) {
            ++records_bw16;
        }
        if (rec.bit_width == 32) {
            ++records_bw32;
        }
    }

    // --- probe A: the records as they are ---
    SystemProbe probe_a;
    RunSystemProbe("A", seed, records, records, probe_a);

    // --- probe B: the SAME records, bit_width truncated to 16 ---
    const std::vector<coverage::BranchReader::Record> narrowed = NarrowToW16(records);
    SystemProbe probe_b;
    RunSystemProbe("B", seed, narrowed, records, probe_b);

    // --- probe C: is each operand's two-byte pattern in the input at all ---
    std::size_t probe_c_values = 0;
    std::size_t probe_c_found = 0;
    for (std::size_t i = 0; i < records.size(); ++i) {
        for (int side = 0; side < 2; ++side) {
            const std::uint64_t value = (side == 0) ? records[i].lhs : records[i].rhs;
            const std::optional<FoundField> found = ProbeFindFirstW16(seed, value);
            ++probe_c_values;
            if (found.has_value()) {
                ++probe_c_found;
            }
            std::cout << "SPLIT-PROBE probe=C seq=" << i << " side=" << (side == 0 ? "lhs" : "rhs")
                      << " op=" << PredicateName(records[i].predicate) << "("
                      << static_cast<unsigned>(records[i].predicate) << ")"
                      << " bit_width_in=" << static_cast<unsigned>(records[i].bit_width)
                      << " bit_width_used=" << kW16FieldBits << " operand=" << Hex(value)
                      << " pattern_bytes=" << PatternHex(value, kW16FieldBits) << " found_offset="
                      << (found.has_value() ? std::to_string(found->offset) : std::string("none"))
                      << " endian=" << (found.has_value() ? (found->big_endian ? "be" : "le") : "-")
                      << " bound=" << (found.has_value() ? "yes" : "no")
                      << " kind=" << (found.has_value() ? "var" : "const") << " sum_offsets=-"
                      << " record_kept=" << (found.has_value() ? "yes" : "no")
                      << " site_id=" << records[i].site_id << '\n';
        }
    }
    std::cout << "SPLIT-C values=" << probe_c_values << " found=" << probe_c_found << '\n'
              << std::flush;

    // --- the campaign at the fixed budget, for continuity with task-102/104 ---
    const char* stop_reason = "complete";
    std::uint64_t campaign_calls = 0;
    std::uint64_t campaign_candidates = 0;
    std::uint64_t campaign_no_binding = 0;
    if (elapsed_s() <= kWalltimeBudgetS) {
        CampaignStats stats;
        std::uint64_t wall_ms = 0;
        RunCampaign(ADD_GATE_W16_BIN, stats, wall_ms);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
        campaign_calls = stats.concolic_calls;
        campaign_candidates = stats.concolic_candidates;
        campaign_no_binding = stats.concolic_no_binding;
        std::cout << "SPLIT-CAMPAIGN arm=w16 gate=add_gate_w16 budget=" << kBudget
                  << " concolic=on execs=" << stats.execs << " crashes=" << stats.crashes
                  << " concolic_calls=" << stats.concolic_calls
                  << " concolic_candidates=" << stats.concolic_candidates
                  << " concolic_unsat=" << stats.concolic_unsat
                  << " concolic_no_binding=" << stats.concolic_no_binding
                  << " concolic_timeout=" << stats.concolic_timeout
                  << " aborted=" << (stats.aborted ? "yes" : "no") << " wall_ms=" << wall_ms << '\n'
                  << std::flush;
    } else {
        stop_reason = "walltime";
    }

    // "Bound" means the binding stage produced a usable system: the path is
    // non-empty after boundary "B" (System::invertible, concolic.cpp:252).
    const bool a_bound = probe_a.invertible;
    const bool b_bound = probe_b.invertible;
    const Split split = Decide(a_bound, b_bound, probe_c_found);

    std::cout << "SPLIT-VERDICT probeA_bound=" << (a_bound ? "yes" : "no")
              << " probeB_bound=" << (b_bound ? "yes" : "no") << " probeC_found=" << probe_c_found
              << "/" << probe_c_values << " probeA_outcome=" << OutcomeName(probe_a.outcome)
              << " probeB_outcome=" << OutcomeName(probe_b.outcome)
              << " probeA_direct_binds=" << probe_a.direct_binds
              << " probeB_direct_binds=" << probe_b.direct_binds
              << " probeA_addvars_binds=" << probe_a.addvars_binds
              << " probeB_addvars_binds=" << probe_b.addvars_binds
              << " probeA_num_vars=" << probe_a.num_vars << " probeB_num_vars=" << probe_b.num_vars
              << " probeA_path_len=" << probe_a.path_len << " probeB_path_len=" << probe_b.path_len
              << " probeB_vars=" << probe_b.vars_desc << " h1=" << split.h1 << " h2=" << split.h2
              << " reformulate=" << (split.reformulate ? "yes" : "no")
              << " cause_named=" << (split.cause_named ? "yes" : "no") << " rule=" << split.rule
              << " records_w16=" << records.size() << " records_bw16=" << records_bw16
              << " records_bw32=" << records_bw32 << " campaign_calls=" << campaign_calls
              << " campaign_candidates=" << campaign_candidates
              << " campaign_no_binding=" << campaign_no_binding << " rng_seed=" << kRngSeed
              << " stagnation_threshold=" << kStagnationThreshold << " budget=" << kBudget
              << " width_bits=" << kW16FieldBits << " endian=le stop_reason=" << stop_reason
              << " src_modified=0\n"
              << std::flush;

    // The stand must have measured something at all; the split itself is
    // published by the verdict line, not asserted here.
    EXPECT_FALSE(records.empty());
    EXPECT_EQ(probe_a.records, probe_b.records)
        << "probes A and B must run over the same number of records";
}

}  // namespace
}  // namespace mlfuzzz3::core
