// Побайтовый дамп систем concolic на стенде E1 — эталон для рефакторинга
// привязки операндов (ADR 0050, интерфейс BindingProvider).
//
// Зачем. Рефакторинг выносит привязку операнда из BuildSystem за интерфейс
// и обязан не менять ни одной системы. Совпадение счётчиков (размер пути,
// число переменных) этого не доказывает: две разные системы могут иметь
// одинаковые размеры. Харнесс сериализует систему целиком — переменные с
// привязками, каждое ограничение, целевой индекс, флаг invertible — в
// канонический текст, по файлу на (плечо, сид). Сверка до и после правки —
// sha256 этих файлов (docs/experiments/binding-provider-regress/run.sh).
//
// СТЕНД — тот же, что у E1 и лестницы починок
// (tests/integration/concolic/test_solver_fix_ladder.cpp): цель libtiff,
// те же 21 сид. Каждый сид исполняется ОДИН раз, и все плечи строятся из
// одних и тех же записей; записи тоже сериализуются, чтобы сверка «после»
// могла доказать, что на вход BuildSystem пришло то же самое.
//
// ПЛЕЧИ. BuildSystem читает из Fixes только findfirst_index (F1) и
// strict_addvars (F2); форма и F4 на построение не влияют. Поэтому плеч
// пять: перегрузка без Fixes и четыре сочетания F1×F2.
//
// Каталог вывода задаёт SYSDUMP_OUT_DIR; без него харнесс пропускается.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
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

constexpr unsigned kRunTimeoutMs = 5000;

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

std::string MissingArtifact() {
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_REL;
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

void WriteOperand(std::ostream& os, const solver::Operand& op) {
    switch (op.kind) {
        case solver::Operand::Kind::kVar:
            os << "var:" << op.var_index;
            return;
        case solver::Operand::Kind::kConst:
            os << "const:" << op.const_value;
            return;
        case solver::Operand::Kind::kAddVars:
            os << "addvars:" << op.var_index << '+' << op.var_index2;
            return;
    }
    os << "?";
}

// Канонический текст системы: все поля System в фиксированном порядке,
// числа в десятичной записи. Поля Operand, не относящиеся к его виду, не
// пишутся: их значение не определено контрактом и в систему не входит.
void WriteSystem(std::ostream& os, const concolic::System& sys) {
    os << "num_vars " << sys.num_vars << '\n';
    os << "target_index " << sys.target_index << '\n';
    os << "invertible " << (sys.invertible ? 1 : 0) << '\n';
    os << "vars " << sys.vars.size() << '\n';
    for (std::size_t i = 0; i < sys.vars.size(); ++i) {
        const concolic::VarBinding& v = sys.vars[i];
        os << "v " << i << " off=" << v.offset << " w=" << static_cast<unsigned>(v.bit_width)
           << " be=" << (v.big_endian ? 1 : 0) << '\n';
    }
    os << "path " << sys.path.size() << '\n';
    for (std::size_t i = 0; i < sys.path.size(); ++i) {
        const solver::Constraint& c = sys.path[i];
        os << "c " << i << " p=" << static_cast<unsigned>(c.predicate)
           << " w=" << static_cast<unsigned>(c.bit_width) << ' ';
        WriteOperand(os, c.lhs);
        os << ' ';
        WriteOperand(os, c.rhs);
        os << '\n';
    }
}

void WriteRecords(std::ostream& os, const std::vector<coverage::BranchReader::Record>& records) {
    os << "records " << records.size() << '\n';
    for (const auto& r : records) {
        os << r.site_id << ' ' << static_cast<unsigned>(r.predicate) << ' '
           << static_cast<unsigned>(r.bit_width) << ' ' << r.lhs << ' ' << r.rhs << '\n';
    }
}

struct DumpArm {
    const char* name;
    std::optional<concolic::Fixes> fixes;  // пусто — перегрузка без Fixes
};

std::vector<DumpArm> DumpArms() {
    auto make = [](bool f1, bool f2) {
        concolic::Fixes fx;
        fx.findfirst_index = f1;
        fx.strict_addvars = f2;
        return fx;
    };
    return {
        {"nofix", std::nullopt},   {"base", make(false, false)}, {"F1", make(true, false)},
        {"F2", make(false, true)}, {"F1F2", make(true, true)},
    };
}

TEST(SystemDump, SerializesEverySystemOfTheE1Bench) {
    const char* out_env = std::getenv("SYSDUMP_OUT_DIR");
    if (out_env == nullptr || *out_env == '\0') {
        GTEST_SKIP() << "SYSDUMP_OUT_DIR не задан";
    }
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << "нет артефакта стенда: " << missing;
    }
    const std::filesystem::path out_dir(out_env);
    std::filesystem::create_directories(out_dir);

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(TIFF_CORPUS_DIR)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    ASSERT_FALSE(files.empty()) << "корпус пуст: " << TIFF_CORPUS_REL;

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

    const std::vector<DumpArm> arms = DumpArms();
    std::cout << "SYSDUMP-META seeds=" << files.size() << " arms=" << arms.size()
              << " target=" << TIFF_TARGET_REL << " corpus=" << TIFF_CORPUS_REL << '\n'
              << std::flush;
    for (const std::filesystem::path& f : files) {
        const std::string name = f.filename().string();
        std::ifstream in(f, std::ios::binary);
        const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                              std::istreambuf_iterator<char>());
        const std::span<const std::uint8_t> seed(bytes.data(), bytes.size());
        const auto response = runner.Run(seed);
        ASSERT_TRUE(response.has_value()) << "прогон сида не удался: " << name;
        const std::vector<coverage::BranchReader::Record> records = runner.LastBranchRecords();
        {
            std::ofstream rec_out(out_dir / ("records." + name + ".txt"), std::ios::binary);
            WriteRecords(rec_out, records);
            ASSERT_TRUE(rec_out.good()) << "запись не удалась: records." << name;
        }
        for (const DumpArm& arm : arms) {
            const concolic::System sys = arm.fixes.has_value()
                                             ? concolic::BuildSystem(seed, records, *arm.fixes)
                                             : concolic::BuildSystem(seed, records);
            std::ofstream sys_out(
                out_dir / ("system." + std::string(arm.name) + "." + name + ".txt"),
                std::ios::binary);
            WriteSystem(sys_out, sys);
            ASSERT_TRUE(sys_out.good()) << "запись не удалась: " << arm.name << ' ' << name;
            std::cout << "SYSDUMP arm=" << arm.name << " seed=" << name
                      << " records=" << records.size() << " path_size=" << sys.path.size()
                      << " num_vars=" << sys.num_vars << " target_index=" << sys.target_index
                      << " invertible=" << (sys.invertible ? 1 : 0) << '\n'
                      << std::flush;
        }
    }
}

}  // namespace
}  // namespace mlfuzzz3::core
