// Выравнивание трасс записей сравнения по позиции против выравнивания по
// (site_id, номер повтора) при возмущении одного байта входа (task-270).
//
// Зачем. У записи сравнения есть стабильный site_id, но нет номера повтора:
// повторы одного сайта различаются только позицией в append-only массиве.
// Номер повтора считается на чтении (coverage::NumberSiteOccurrences); этот
// харнесс снимает трассы, по которым сравниваются два способа сопоставить
// записи двух прогонов.
//
// СТЕНД — тот же, что у E1 и дампа систем (test_system_dump.cpp): цель
// libtiff, те же 21 сид. На каждый сид три прогона: сид (A), тот же сид
// повторно (A2, контроль детерминизма) и сид с одним возмущённым байтом (B).
// Правило возмущения фиксировано (PerturbOffset): младший байт тега первой
// записи первого IFD, XOR 0x01 — смена тега уводит разбор на другую ветку,
// не обрывая его. Если заголовок не TIFF или IFD за концом входа — байт
// size/2 (rule=fallback в выводе).
//
// Вывод. Строка OCC-RUN на прогон: исход, overflow_flag из ответа
// сервера, число записей, признак reliable из NumberSiteOccurrences. Файл
// trace.<плечо>.<сид>.txt в OCCALIGN_OUT_DIR — по строке на запись:
// позиция, site_id, номер повтора. Сопоставление и доли считает разбор
// (docs/experiments/branch-occurrence-alignment/analyze.py).
//
// Каталог вывода задаёт OCCALIGN_OUT_DIR; без него харнесс пропускается.

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
#include <span>
#include <string>
#include <vector>

#include "branch_reader.h"
#include "runner.h"
#include "session.h"

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

// Arm — один прогон на сид: имя плеча и признак возмущения.
struct Arm {
    const char* name;
    bool perturb;
};

constexpr std::array<Arm, 3> kArms = {{{"A", false}, {"A2", false}, {"B", true}}};
constexpr std::uint8_t kPerturbXor = 0x01;

// Perturbation — выбранный байт и правило, по которому он выбран.
struct Perturbation {
    std::size_t offset;
    const char* rule;
};

// PerturbOffset: заголовок TIFF — порядок байт (II/MM) и смещение первого
// IFD (u32 по смещению 4); запись IFD начинается через 2 байта счётчика,
// тег — её первые 2 байта, младший байт тега лежит по +2 (II) или +3 (MM).
Perturbation PerturbOffset(const std::vector<std::uint8_t>& seed) {
    const Perturbation fallback{seed.size() / 2, "fallback"};
    if (seed.size() < 8) {
        return fallback;
    }
    const bool le = seed[0] == 'I' && seed[1] == 'I';
    const bool be = seed[0] == 'M' && seed[1] == 'M';
    if (!le && !be) {
        return fallback;
    }
    std::uint64_t ifd = 0;
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t b = seed[static_cast<std::size_t>(4 + i)];
        ifd |= le ? (b << (8 * i)) : (b << (8 * (3 - i)));
    }
    const std::uint64_t offset = ifd + (le ? 2U : 3U);
    if (offset >= seed.size()) {
        return fallback;
    }
    return {static_cast<std::size_t>(offset), "ifd0_tag"};
}

void WriteTrace(std::ostream& os, const std::vector<coverage::BranchReader::Record>& records,
                const coverage::SiteOccurrences& occ) {
    os << "records " << records.size() << " reliable " << (occ.reliable ? 1 : 0) << '\n';
    for (std::size_t i = 0; i < records.size(); ++i) {
        os << i << ' ' << records[i].site_id << ' ' << occ.occurrence[i] << '\n';
    }
}

TEST(OccurrenceAlignment, TracesOriginalAndPerturbedSeedsOfTheE1Bench) {
    const char* out_env = std::getenv("OCCALIGN_OUT_DIR");
    if (out_env == nullptr || *out_env == '\0') {
        GTEST_SKIP() << "OCCALIGN_OUT_DIR не задан";
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

    std::cout << "OCC-META seeds=" << files.size() << " arms=" << kArms.size()
              << " perturb=ifd0_tag^0x01 target=" << TIFF_TARGET_REL
              << " corpus=" << TIFF_CORPUS_REL << '\n'
              << std::flush;
    for (const std::filesystem::path& f : files) {
        const std::string name = f.filename().string();
        std::ifstream in(f, std::ios::binary);
        const std::vector<std::uint8_t> seed((std::istreambuf_iterator<char>(in)),
                                             std::istreambuf_iterator<char>());
        ASSERT_FALSE(seed.empty()) << "пустой сид: " << name;
        const Perturbation pert = PerturbOffset(seed);
        for (const Arm& arm : kArms) {
            std::vector<std::uint8_t> input = seed;
            if (arm.perturb) {
                input[pert.offset] ^= kPerturbXor;
            }
            const auto response = runner.Run(input);
            ASSERT_TRUE(response.has_value()) << "прогон не удался: " << arm.name << ' ' << name;
            const bool overflow =
                response->has_branch_result() && response->branch_result().overflow();
            const std::vector<coverage::BranchReader::Record> records = runner.LastBranchRecords();
            const coverage::SiteOccurrences occ =
                coverage::NumberSiteOccurrences(records, overflow);
            {
                std::ofstream out(
                    out_dir / ("trace." + std::string(arm.name) + "." + name + ".txt"),
                    std::ios::binary);
                WriteTrace(out, records, occ);
                ASSERT_TRUE(out.good()) << "запись не удалась: " << arm.name << ' ' << name;
            }
            std::cout << "OCC-RUN arm=" << arm.name << " seed=" << name << " size=" << seed.size()
                      << " offset=" << (arm.perturb ? static_cast<long long>(pert.offset) : -1LL)
                      << " rule=" << (arm.perturb ? pert.rule : "none")
                      << " status=" << static_cast<int>(response->status())
                      << " overflow=" << (overflow ? 1 : 0) << " records=" << records.size()
                      << " reliable=" << (occ.reliable ? 1 : 0) << '\n'
                      << std::flush;
        }
    }
}

}  // namespace
}  // namespace mlfuzzz3::core
