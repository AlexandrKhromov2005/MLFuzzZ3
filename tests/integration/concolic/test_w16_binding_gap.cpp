// task-104 (ADR-0047) — почему при 16 битах привязка не состоялась: карта
// домена говорит одно, кампания показала другое.
//
// Разрыв, который стенд обязан объяснить. task-102 прогнал ось ширины на
// живой кампании и получил на вооружённом плече add_gate_w16
// `concolic_calls=21 concolic_candidates=0 concolic_no_binding=21`
// (docs/experiments/solver-add-gate-width16-crash-budget/
// raw-w16-crash-budget.txt), тогда как контроль на u32 в том же процессе дал
// `concolic_candidates=19 concolic_no_binding=0`. Карта домена
// (docs/experiments/solver-domain-form-width-endian/report.md) утверждает
// обратное: ширины 8/16/32/64 сняты, зависимость от ширины найдена только у
// формы xor. Разница между измерениями в том, что карта домена строит
// записи BranchReader::Record СИНТЕТИЧЕСКИ, а кампания получает их с живого
// прогона — и вопрос ровно в том, где рвётся цепочка.
//
// Что делает этот харнесс. В ОДНОМ процессе поднимает обе фикстуры —
// tests/fixtures/add_gate/add_gate.c (32-битный контроль) и
// tests/fixtures/add_gate_w16/add_gate_w16.c — на одном и том же RNG-сиде 7,
// одном и том же входном сиде и одном и том же пороге стагнации 8, и для
// каждой:
//
//   * снимает РЕАЛЬНЫЕ записи ветвлений тем же путём, каким их берёт
//     кампания: Run(seed) и сразу LastBranchRecords() (ADR-0036; кампания
//     делает это на campaign.cpp:179-181), и печатает их поштучно строками
//     W16-RECORD;
//   * прогоняет каждую запись через ПРОДАКШЕН-код привязки
//     concolic::BuildSystem (concolic.h), а не через пересказ его правил, и
//     печатает по каждой записи связанность и вид операндов;
//   * вызывает concolic::SolveForCandidate на снимке и печатает исход;
//   * прогоняет кампанию с бюджетом 200 (значение контрольной пробы
//     task-102), чтобы счётчики concolic_calls/candidates/no_binding в этом
//     же прогоне можно было сверить с task-102.
//
// Три гипотезы H1/H2/H3 и правила их исключения зарегистрированы ДО прогона
// в шапке docs/experiments/solver-w16-binding-gap/run.sh; функция Decide
// ниже реализует ровно те правила и ничего сверх них.
//
// Границы. Бюджет фиксирован на 200, минимальный бюджет НЕ ищется. src/ не
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
    if (!PathExecutable(ADD_GATE_BIN)) {
        return std::string("add_gate fixture missing (32-bit control): ") + ADD_GATE_REL;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_REL;
    }
    return {};
}

// Always selects corpus seed 0 so its stagnation counter climbs
// deterministically toward the trigger, and so the seed the concolic step
// sees is byte for byte the kArmSeed below (donor:
// test_add_gate_w16_crash_budget.cpp:196-204).
class FixedScheduler final : public SeedScheduler {
   public:
    std::size_t Choose(std::size_t /*corpus_size*/) override {
        return 0;
    }
    [[nodiscard]] const char* name() const noexcept override {
        return "fixed0";
    }
};

// Byte for byte the seed of task-102 (test_add_gate_w16_crash_budget.cpp:213).
// Under add_gate.c it decodes to a = 0x11223344, b = 0x2D2C2B2A; under
// add_gate_w16.c to a = 0x2211, b = 0x4433.
constexpr std::array<std::uint8_t, 8> kArmSeed = {0x11, 0x22, 0x33, 0x44, 0x2D, 0x2C, 0x2B, 0x2A};

// Fixed before the run, all three taken from task-102
// (test_add_gate_w16_crash_budget.cpp:217-224). The budget is the control
// probe's 200; the minimal budget is NOT searched here.
constexpr std::uint64_t kRngSeed = 7;
constexpr std::uint32_t kStagnationThreshold = 8;
constexpr std::uint64_t kBudget = 200;
constexpr unsigned kConcolicTimeoutMs = 2000;

// The width of the fields add_gate_w16.c reads (add_gate_w16.c:66-68). H1 is
// stated against this number and against nothing else.
constexpr unsigned kW16FieldBits = 16;

// Hard wall-time budget for the whole unit, named before the run
// (test_add_gate_be_crash_budget.cpp:214-218). Checked before every campaign
// probe; when it is spent the stand stops where it stands and publishes
// stop_reason=walltime instead of a number it did not finish earning.
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

// Where an operand landed in the input, read off the SYSTEM the production
// code built (concolic::System::vars) rather than off a re-implementation of
// the search: "-" for a constant, "<offset><le|be>" for a direct field,
// "<offset><le|be>+<offset><le|be>" for a SUM of two fields.
std::string OperandOffsets(const concolic::System& sys, const solver::Operand& operand) {
    const auto one = [&sys](std::size_t index) {
        std::ostringstream os;
        if (index >= sys.vars.size()) {
            os << "?";
            return os.str();
        }
        os << sys.vars[index].offset << (sys.vars[index].big_endian ? "be" : "le");
        return os.str();
    };
    switch (operand.kind) {
        case solver::Operand::Kind::kVar:
            return one(operand.var_index);
        case solver::Operand::Kind::kAddVars:
            return one(operand.var_index) + "+" + one(operand.var_index2);
        case solver::Operand::Kind::kConst:
        default:
            return "-";
    }
}

// Everything one arm contributes to the verdict.
struct ArmSnapshot {
    std::string arm;
    std::size_t records = 0;
    std::size_t records_bw16 = 0;   // records logged at the fixture's field width
    std::size_t records_bw32 = 0;   // records logged at 32 bits
    std::size_t direct_binds = 0;   // operands bound DIRECTLY (kVar) across all records
    std::size_t records_bound = 0;  // records with at least one non-const operand
    std::size_t num_vars = 0;       // fields the full system found in the seed
    std::size_t path_len = 0;       // constraints that survived boundary "B"
    bool invertible = false;
    concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
    bool snapshot_ok = false;  // the arm seed ran cleanly and records were read
    // Campaign counters at budget 200, concolic armed.
    std::uint64_t concolic_calls = 0;
    std::uint64_t concolic_candidates = 0;
    std::uint64_t concolic_no_binding = 0;
    std::uint64_t execs = 0;
    std::uint64_t crashes = 0;
    bool campaign_ran = false;
};

// Snapshot one arm: run the arm seed once through a live SessionRunner, take
// the branch records the way the campaign takes them (campaign.cpp:179-181),
// print each record with the production binding verdict, and solve on it.
//
// The per-record `bound`/`kind`/`*_offsets` come from calling the PUBLIC
// concolic::BuildSystem on a one-record vector: pass 1 of BuildSystem
// discovers the fields of exactly that record's two operands, pass 2 binds
// them, so the printed classification is the production one, not a paraphrase.
// The aggregate over all records is printed separately on the W16-SYSTEM
// line, where cross-record field sharing is in play.
void SnapshotArm(const char* arm, const char* fixture_bin, ArmSnapshot& out) {
    out.arm = arm;

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
    const std::span<const std::uint8_t> seed(kArmSeed.data(), kArmSeed.size());

    // The campaign's own two lines, in the campaign's own order: Run, then
    // LastBranchRecords with no other Run in between (ADR-0036 §3).
    const auto response = runner.Run(seed);
    ASSERT_TRUE(response.has_value())
        << "arm " << arm << ": transport error " << static_cast<int>(response.error());
    const std::vector<coverage::BranchReader::Record> records = runner.LastBranchRecords();
    out.snapshot_ok = true;
    out.records = records.size();

    std::ostringstream seed_hex;
    for (const std::uint8_t byte : kArmSeed) {
        seed_hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    }
    std::cout << "W16-SEED arm=" << arm << " bytes=" << seed_hex.str() << " len=" << kArmSeed.size()
              << " status=" << static_cast<int>(response->status()) << " records=" << records.size()
              << '\n';

    for (std::size_t i = 0; i < records.size(); ++i) {
        const coverage::BranchReader::Record& rec = records[i];
        if (rec.bit_width == kW16FieldBits) {
            ++out.records_bw16;
        }
        if (rec.bit_width == 32) {
            ++out.records_bw32;
        }

        const std::vector<coverage::BranchReader::Record> one{rec};
        const concolic::System sys = concolic::BuildSystem(seed, one);
        const bool bound = !sys.path.empty();
        std::string lhs_off = "-";
        std::string rhs_off = "-";
        std::string kind = "const:const";
        if (bound) {
            const solver::Constraint& c = sys.path.front();
            lhs_off = OperandOffsets(sys, c.lhs);
            rhs_off = OperandOffsets(sys, c.rhs);
            kind = std::string(KindName(c.lhs.kind)) + ":" + KindName(c.rhs.kind);
            if (c.lhs.kind == solver::Operand::Kind::kVar) {
                ++out.direct_binds;
            }
            if (c.rhs.kind == solver::Operand::Kind::kVar) {
                ++out.direct_binds;
            }
            ++out.records_bound;
        }

        std::cout << "W16-RECORD arm=" << arm << " seq=" << i
                  << " op=" << PredicateName(rec.predicate) << "("
                  << static_cast<unsigned>(rec.predicate) << ")"
                  << " bit_width=" << static_cast<unsigned>(rec.bit_width)
                  << " lhs=" << Hex(rec.lhs) << " rhs=" << Hex(rec.rhs)
                  << " lhs_offsets=" << lhs_off << " rhs_offsets=" << rhs_off
                  << " bound=" << (bound ? "yes" : "no") << " kind=" << kind
                  << " site_id=" << rec.site_id << '\n';
    }

    const concolic::System full = concolic::BuildSystem(seed, records);
    out.num_vars = full.num_vars;
    out.path_len = full.path.size();
    out.invertible = full.invertible;
    std::ostringstream vars;
    for (std::size_t i = 0; i < full.vars.size(); ++i) {
        vars << (i == 0 ? "" : ",") << full.vars[i].offset
             << (full.vars[i].big_endian ? "be" : "le") << "/"
             << static_cast<unsigned>(full.vars[i].bit_width);
    }
    std::cout << "W16-SYSTEM arm=" << arm << " records=" << out.records
              << " num_vars=" << out.num_vars << " path_len=" << out.path_len
              << " target_index=" << full.target_index
              << " invertible=" << (out.invertible ? "yes" : "no")
              << " vars=" << (full.vars.empty() ? std::string("-") : vars.str())
              << " direct_binds=" << out.direct_binds << " records_bound=" << out.records_bound
              << " records_bw16=" << out.records_bw16 << " records_bw32=" << out.records_bw32
              << '\n';

    concolic::SolveOutcome outcome = concolic::SolveOutcome::kNoBinding;
    const auto candidate = concolic::SolveForCandidate(seed, records, kConcolicTimeoutMs, &outcome);
    out.outcome = outcome;
    std::cout << "W16-SOLVE arm=" << arm << " outcome=" << OutcomeName(outcome)
              << " candidate=" << (candidate.has_value() ? "yes" : "no") << '\n'
              << std::flush;
}

// One bounded campaign, its counters and its wall time — the donor's
// RunCampaign (test_add_gate_w16_crash_budget.cpp:261-311) with the budget
// fixed at kBudget and no search around it.
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

// The pre-registered decision rules, transcribed from the header of
// docs/experiments/solver-w16-binding-gap/run.sh and applied to the w16 arm
// only. Nothing here reads the u32 arm: the control decides whether the
// stand measured anything, not which hypothesis survived.
const char* Decide(const ArmSnapshot& w16, int which) {
    switch (which) {
        case 1:  // H1: records of the needed form never reach the solver.
            return (w16.records > 0 && w16.records_bw16 > 0) ? "EXCLUDED" : "SURVIVED";
        case 2:  // H2: binding dies in the offset search.
            return (w16.direct_binds > 0) ? "EXCLUDED" : "SURVIVED";
        case 3:  // H3: binding dies later, inside system building.
        default:
            return (w16.direct_binds > 0 && !w16.invertible) ? "SURVIVED" : "EXCLUDED";
    }
}

TEST(W16BindingGap, WhyTheWidth16ArmNeverBindsWhileTheU32ControlDoes) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }

    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };

    std::cout << "W16-META rng_seed=" << kRngSeed
              << " stagnation_threshold=" << kStagnationThreshold << " budget=" << kBudget
              << " concolic_timeout_ms=" << kConcolicTimeoutMs << " width_bits=" << kW16FieldBits
              << " endian=le seed_len=" << kArmSeed.size()
              << " walltime_budget_s=" << kWalltimeBudgetS << " control=" << ADD_GATE_REL
              << " w16=" << ADD_GATE_W16_REL << " records_via=LastBranchRecords"
              << " src_modified=0\n"
              << std::flush;

    ArmSnapshot u32;
    SnapshotArm("u32", ADD_GATE_BIN, u32);
    if (::testing::Test::HasFatalFailure()) {
        return;
    }
    ArmSnapshot w16;
    SnapshotArm("w16", ADD_GATE_W16_BIN, w16);
    if (::testing::Test::HasFatalFailure()) {
        return;
    }

    const char* stop_reason = "complete";
    if (elapsed_s() <= kWalltimeBudgetS) {
        CampaignStats stats;
        std::uint64_t wall_ms = 0;
        RunCampaign(ADD_GATE_BIN, "arm_u32.bin", "w16gap-u32", "w16-gap-u32", stats, wall_ms);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
        u32.campaign_ran = true;
        u32.concolic_calls = stats.concolic_calls;
        u32.concolic_candidates = stats.concolic_candidates;
        u32.concolic_no_binding = stats.concolic_no_binding;
        u32.execs = stats.execs;
        u32.crashes = stats.crashes;
        std::cout << "W16-PROBE arm=u32 gate=add_gate budget=" << kBudget
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

    if (elapsed_s() <= kWalltimeBudgetS) {
        CampaignStats stats;
        std::uint64_t wall_ms = 0;
        RunCampaign(ADD_GATE_W16_BIN, "arm_w16.bin", "w16gap-w16", "w16-gap-w16", stats, wall_ms);
        if (::testing::Test::HasFatalFailure()) {
            return;
        }
        w16.campaign_ran = true;
        w16.concolic_calls = stats.concolic_calls;
        w16.concolic_candidates = stats.concolic_candidates;
        w16.concolic_no_binding = stats.concolic_no_binding;
        w16.execs = stats.execs;
        w16.crashes = stats.crashes;
        std::cout << "W16-PROBE arm=w16 gate=add_gate_w16 budget=" << kBudget
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

    // The control decides whether the stand measured what it claims: the
    // u32 arm must bind in THIS process, on THIS seed, or the w16 result is
    // a stand failure and not a property of 16 bits.
    const bool control_bound = u32.invertible && u32.outcome == concolic::SolveOutcome::kCandidate;
    const bool w16_bound = w16.invertible && w16.outcome == concolic::SolveOutcome::kCandidate;

    const char* h1 = Decide(w16, 1);
    const char* h2 = Decide(w16, 2);
    const char* h3 = Decide(w16, 3);
    const int survived = (std::strcmp(h1, "SURVIVED") == 0 ? 1 : 0) +
                         (std::strcmp(h2, "SURVIVED") == 0 ? 1 : 0) +
                         (std::strcmp(h3, "SURVIVED") == 0 ? 1 : 0);

    std::cout << "W16-VERDICT control_u32_bound=" << (control_bound ? "yes" : "no")
              << " w16_bound=" << (w16_bound ? "yes" : "no") << " records_u32=" << u32.records
              << " records_w16=" << w16.records << " records_w16_bw16=" << w16.records_bw16
              << " records_w16_bw32=" << w16.records_bw32
              << " direct_binds_u32=" << u32.direct_binds
              << " direct_binds_w16=" << w16.direct_binds << " num_vars_u32=" << u32.num_vars
              << " num_vars_w16=" << w16.num_vars << " path_len_u32=" << u32.path_len
              << " path_len_w16=" << w16.path_len
              << " invertible_u32=" << (u32.invertible ? "yes" : "no")
              << " invertible_w16=" << (w16.invertible ? "yes" : "no")
              << " outcome_u32=" << OutcomeName(u32.outcome)
              << " outcome_w16=" << OutcomeName(w16.outcome)
              << " campaign_calls_u32=" << u32.concolic_calls
              << " campaign_candidates_u32=" << u32.concolic_candidates
              << " campaign_no_binding_u32=" << u32.concolic_no_binding
              << " campaign_calls_w16=" << w16.concolic_calls
              << " campaign_candidates_w16=" << w16.concolic_candidates
              << " campaign_no_binding_w16=" << w16.concolic_no_binding << " h1=" << h1
              << " h2=" << h2 << " h3=" << h3 << " survived=" << survived
              << " cause_named=" << (survived == 1 ? "yes" : "no") << " rng_seed=" << kRngSeed
              << " stagnation_threshold=" << kStagnationThreshold << " budget=" << kBudget
              << " width_bits=" << kW16FieldBits << " endian=le stop_reason=" << stop_reason
              << " src_modified=0\n"
              << std::flush;

    // The stand must have measured something at all: both arms produced
    // records through the campaign's own call.
    EXPECT_TRUE(u32.snapshot_ok);
    EXPECT_TRUE(w16.snapshot_ok);
    // The control is an assertion about the STAND, not about 16 bits: if it
    // fails, the w16 numbers below say nothing about width.
    EXPECT_TRUE(control_bound) << "control arm did not bind in this process; the w16 result is a "
                                  "stand failure, not a property of 16 bits";
}

}  // namespace
}  // namespace mlfuzzz3::core
