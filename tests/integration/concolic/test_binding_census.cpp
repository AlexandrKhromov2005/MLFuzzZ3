// E2 и E3 (recon, ADR-0047) — из чего на реальной цели состоит система,
// которую строит concolic::BuildSystem, и сколько стоит её построение.
//
// Зачем. Развёртка E0 (docs/experiments/solver-target-index-sweep/) показала,
// что на 21 пути libtiff не выполнима ни одна из 9850 инверсий, и что при
// этом `kAddVars` стоит хотя бы на одной стороне у 86 % целей (0.993 на
// 64 битах) при всего 29–48 переменных на путь в 3859–35594 записи. Там же
// осталось неизвестным, ЧТО это за привязки: значения операндов и пары полей
// не печатались. А отчёт по smoke кампании v2 отнёс 8283 мс на вызов к
// построению системы, не имея прямого замера построения.
//
// Два теста, один харнесс, ни одного вызова солвера:
//   BindingCensus.* (E2) — перепись привязок: у каждой записи пути какая
//     сторона чем связана, какие поля входа участвуют, вырождены ли суммы,
//     сколько переменных несут все привязки и сколько в пути повторов;
//   BuildCost.* (E3) — время BuildSystem отдельно, с повторами и лестницей
//     по доле записей, рядом с records, seed_len, num_vars, path_size.
// Гипотезы, пороги и правило чтения — в шапках
// docs/experiments/solver-binding-census/run.sh и
// docs/experiments/solver-build-cost/run.sh, закоммиченных до сырья. Харнесс
// ничего не решает: он печатает факты, решение считает analyze.py из сырья.
//
// Как харнесс сверяет перепись с продуктом (СЕРИЯ 2). BuildSystem публичен и
// отдаёт System: путь (Constraint с видом стороны и индексами переменных) и
// привязки переменных (смещение, ширина, порядок байт). Чтобы приписать
// элементу пути его запись ветвления (site_id, наблюдённые операнды), путь
// выравнивается по живым записям. Серия 1 выравнивала по ЗНАЧЕНИЯМ сторон и
// не сошлась ни на одном сиде (docs/experiments/solver-binding-census/
// raw-series1-blocked-align.txt): значение kVar по привязке продукта не
// обязано совпадать с операндом, потому что переменная заводится с шириной
// первой записи, нашедшей её смещение, а потом служит записям другой ширины.
// Серия 2 выравнивает по ПРИВЯЗКАМ: для каждой записи харнесс сам
// предсказывает, как продукт свяжет её стороны (FindFirstAsProduct и
// PredictBinding повторяют правила src/concolic/concolic.cpp:136-166 и
// :185-207), и требует, чтобы выжившие записи дали РОВНО путь продукта —
// та же ширина, тот же вид каждой стороны, те же индексы переменных, та же
// константа, элемент за элементом, и число выживших равно path_size. Повтор
// правил продукта этим не принимается на веру: любое расхождение — align_ok=no
// и номер первой несошедшейся записи. Расхождение значения kVar с операндом
// теперь не ломает сверку, а считается отдельно (kvar_value_mismatch).
//
// Связка снятия записей — дословно кампанийная: Run(seed) и сразу
// LastBranchRecords() (src/core/campaign.cpp:180-181, ADR-0036).
//
// Границы. src/ не изменяется, солвер не вызывается, кампании не
// запускаются. У каждого теста свой лимит стены; исчерпав его, тест
// останавливается и печатает stop_reason=walltime. Все печатаемые пути
// относительны от корня репозитория.

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
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "concolic.h"
#include "runner.h"
#include "session.h"
#include "solver_facade.h"

namespace mlfuzzz3::core {
namespace {

// Протокол E2/E3: ни одна из этих величин не меняется по итогу прогона.
constexpr unsigned kRunTimeoutMs = 5000;
constexpr std::size_t kSamplePerSeed = 400;
constexpr std::size_t kTopPool = 5;
constexpr int kBuildRepeats = 3;
constexpr double kCensusWalltimeS = 1500.0;
constexpr double kBuildWalltimeS = 2700.0;
constexpr unsigned kBitsPerByte = 8;

// Сид add_gate положительного контроля переписи — дословно сид task-070
// (tests/integration/concolic/test_add_gate_crash_budget.cpp:194).
constexpr std::array<std::uint8_t, 8> kAddGateSeed = {0x11, 0x22, 0x33, 0x44,
                                                      0x2D, 0x2C, 0x2B, 0x2A};

using Record = coverage::BranchReader::Record;
using Kind = solver::Operand::Kind;

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

// Сессия exec-server над одной целью; держит процесс и раннер вместе.
struct TargetSession {
    ExecServerProcess proc;
    std::optional<ipc::ClientSession> session;
    std::optional<SessionRunner> runner;
};

bool OpenSession(const std::string& target, TargetSession& ts, std::string& err) {
    if (!SpawnExecServer(EXEC_SERVER_BIN, target, COV_LIBRARY_PATH, ts.proc, err)) {
        return false;
    }
    ipc::Conn client_conn(ts.proc.client_fd);
    ts.proc.client_fd = -1;
    auto dialed = ipc::ClientSession::Dial(
        std::move(client_conn),
        ipc::ClientConfig{.run_timeout_ms = kRunTimeoutMs, .expected_channels = 2});
    if (!dialed.has_value()) {
        err = "Dial failed: " + std::to_string(static_cast<int>(dialed.error()));
        return false;
    }
    ts.session.emplace(std::move(*dialed));
    ts.runner.emplace(*ts.session);
    return true;
}

struct Seed {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

// Сиды — с диска, в лексикографическом порядке имени (как в E0).
std::vector<Seed> LoadSeeds() {
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(TIFF_CORPUS_DIR)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    std::vector<Seed> seeds;
    for (const std::filesystem::path& file : files) {
        Seed s;
        s.name = file.filename().string();
        std::ifstream in(file, std::ios::binary);
        s.bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        seeds.push_back(std::move(s));
    }
    return seeds;
}

std::uint64_t Truncate(std::uint64_t value, unsigned bit_width) {
    if (bit_width >= 64) {
        return value;
    }
    return value & ((1ULL << bit_width) - 1ULL);
}

std::string Hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

// Значение поля входа, к которому привязана переменная, в её собственной
// ширине и порядке байт. Проверяется выравниванием пути по записям.
std::uint64_t ReadVar(std::span<const std::uint8_t> seed, const concolic::VarBinding& var) {
    const unsigned n = var.bit_width / kBitsPerByte;
    if (var.offset + n > seed.size()) {
        return 0;
    }
    std::uint64_t value = 0;
    for (unsigned k = 0; k < n; ++k) {
        const unsigned shift = var.big_endian ? (kBitsPerByte * (n - 1U - k)) : (kBitsPerByte * k);
        value |= static_cast<std::uint64_t>(seed[var.offset + k]) << shift;
    }
    return value;
}

// Значение стороны под её привязкой, при ширине сравнения.
std::uint64_t SideValue(std::span<const std::uint8_t> seed, const concolic::System& sys,
                        const solver::Operand& op, unsigned bit_width) {
    switch (op.kind) {
        case Kind::kVar:
            return Truncate(ReadVar(seed, sys.vars[op.var_index]), bit_width);
        case Kind::kAddVars:
            return Truncate(Truncate(ReadVar(seed, sys.vars[op.var_index]), bit_width) +
                                Truncate(ReadVar(seed, sys.vars[op.var_index2]), bit_width),
                            bit_width);
        case Kind::kConst:
            return Truncate(op.const_value, bit_width);
    }
    return 0;
}

const char* KindName(Kind kind) {
    switch (kind) {
        case Kind::kVar:
            return "var";
        case Kind::kConst:
            return "const";
        case Kind::kAddVars:
            return "addvars";
    }
    return "?";
}

// Описание стороны одной лексемой без пробелов.
std::string Describe(std::span<const std::uint8_t> seed, const concolic::System& sys,
                     const solver::Operand& op, unsigned bit_width) {
    std::ostringstream out;
    switch (op.kind) {
        case Kind::kVar: {
            const concolic::VarBinding& v = sys.vars[op.var_index];
            out << "var:" << op.var_index << "@" << v.offset << "/"
                << static_cast<unsigned>(v.bit_width) << (v.big_endian ? "be" : "le");
            break;
        }
        case Kind::kAddVars: {
            const concolic::VarBinding& a = sys.vars[op.var_index];
            const concolic::VarBinding& b = sys.vars[op.var_index2];
            out << "add:" << op.var_index << "+" << op.var_index2 << "@" << a.offset << "+"
                << b.offset << "=" << Hex(Truncate(ReadVar(seed, a), bit_width)) << "+"
                << Hex(Truncate(ReadVar(seed, b), bit_width));
            break;
        }
        case Kind::kConst:
            out << "const:" << Hex(Truncate(op.const_value, bit_width));
            break;
    }
    return out.str();
}

// Порядок выборки — перестановка Ван дер Корпута, как в E0: любой префикс
// равномерен по длине пути.
std::vector<std::size_t> BitReversalOrder(std::size_t m) {
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

using OpKey = std::tuple<int, std::size_t, std::size_t, std::uint64_t>;

OpKey KeyOf(const solver::Operand& op) {
    switch (op.kind) {
        case Kind::kVar:
            return {0, op.var_index, 0, 0};
        case Kind::kAddVars:
            return {1, op.var_index, op.var_index2, 0};
        case Kind::kConst:
            return {2, 0, 0, op.const_value};
    }
    return {3, 0, 0, 0};
}

// Первое вхождение значения во вход по правилам FindFirst продукта
// (src/concolic/concolic.cpp:136-166): ширина ненулевая, не больше 64 и кратна
// 8; смещения по возрастанию; на одном смещении little-endian раньше big-endian.
struct Found {
    std::size_t offset;
    bool big_endian;
};

std::optional<Found> FindFirstAsProduct(std::span<const std::uint8_t> seed, std::uint64_t value,
                                        unsigned bit_width) {
    if (bit_width == 0 || bit_width > 64 || (bit_width % kBitsPerByte) != 0) {
        return std::nullopt;
    }
    const unsigned n = bit_width / kBitsPerByte;
    if (seed.size() < n) {
        return std::nullopt;
    }
    const std::uint64_t v = Truncate(value, bit_width);
    for (std::size_t off = 0; off + n <= seed.size(); ++off) {
        bool le = true;
        bool be = true;
        for (unsigned k = 0; k < n; ++k) {
            const std::uint8_t byte = seed[off + k];
            if (byte != static_cast<std::uint8_t>(v >> (kBitsPerByte * k))) {
                le = false;
            }
            if (byte != static_cast<std::uint8_t>(v >> (kBitsPerByte * (n - 1U - k)))) {
                be = false;
            }
        }
        if (le) {
            return Found{.offset = off, .big_endian = false};
        }
        if (be) {
            return Found{.offset = off, .big_endian = true};
        }
    }
    return std::nullopt;
}

// Как продукт свяжет одну сторону (src/concolic/concolic.cpp:185-207):
// дословная находка -> kVar; иначе первая пара i <= j, чья сумма по модулю
// ширины равна значению -> kAddVars; иначе kConst.
solver::Operand PredictBinding(std::span<const std::uint8_t> seed, std::uint64_t value,
                               unsigned bit_width, const concolic::System& sys,
                               const std::map<std::size_t, std::size_t>& offset_index) {
    if (const std::optional<Found> f = FindFirstAsProduct(seed, value, bit_width)) {
        const auto it = offset_index.find(f->offset);
        if (it != offset_index.end()) {
            return {.kind = Kind::kVar, .var_index = it->second, .var_index2 = 0, .const_value = 0};
        }
    }
    const std::uint64_t target = Truncate(value, bit_width);
    for (std::size_t i = 0; i < sys.vars.size(); ++i) {
        for (std::size_t j = i; j < sys.vars.size(); ++j) {
            const std::uint64_t sum = Truncate(Truncate(ReadVar(seed, sys.vars[i]), bit_width) +
                                                   Truncate(ReadVar(seed, sys.vars[j]), bit_width),
                                               bit_width);
            if (sum == target) {
                return {.kind = Kind::kAddVars, .var_index = i, .var_index2 = j, .const_value = 0};
            }
        }
    }
    return {.kind = Kind::kConst, .var_index = 0, .var_index2 = 0, .const_value = target};
}

// Индекс записи для каждого элемента пути. ok только если выжившие по
// предсказанию записи дали ровно путь продукта, элемент за элементом.
struct Alignment {
    std::vector<std::size_t> record_of_path;
    std::size_t dropped = 0;
    long long first_mismatch_record = -1;
    bool ok = false;
};

Alignment AlignPath(std::span<const std::uint8_t> seed, const concolic::System& sys,
                    const std::vector<Record>& records) {
    Alignment al;
    std::map<std::size_t, std::size_t> offset_index;
    for (std::size_t k = 0; k < sys.vars.size(); ++k) {
        offset_index.emplace(sys.vars[k].offset, k);
    }
    al.record_of_path.reserve(sys.path.size());
    std::size_t p = 0;
    for (std::size_t r = 0; r < records.size(); ++r) {
        const Record& rec = records[r];
        const solver::Operand lhs = PredictBinding(seed, rec.lhs, rec.bit_width, sys, offset_index);
        const solver::Operand rhs = PredictBinding(seed, rec.rhs, rec.bit_width, sys, offset_index);
        if (lhs.kind == Kind::kConst && rhs.kind == Kind::kConst) {
            ++al.dropped;
            continue;
        }
        if (p >= sys.path.size() || sys.path[p].bit_width != rec.bit_width ||
            KeyOf(sys.path[p].lhs) != KeyOf(lhs) || KeyOf(sys.path[p].rhs) != KeyOf(rhs)) {
            al.first_mismatch_record = static_cast<long long>(r);
            return al;
        }
        al.record_of_path.push_back(r);
        ++p;
    }
    al.ok = (p == sys.path.size());
    return al;
}

// Перепись одного сида: печатает строки CENSUS-* и возвращает align_ok.
bool CensusOfSeed(const std::string& name, std::span<const std::uint8_t> seed, int status,
                  const std::vector<Record>& records, bool print_sample) {
    const concolic::System sys = concolic::BuildSystem(seed, records);
    const Alignment al = AlignPath(seed, sys, records);
    const std::size_t n_vars = sys.vars.size();

    std::uint64_t kvar = 0;
    std::uint64_t kconst = 0;
    std::uint64_t kadd = 0;
    std::uint64_t add_same = 0;
    std::uint64_t add_zero = 0;
    std::uint64_t add_both = 0;
    std::uint64_t pred_as_logged = 0;
    std::uint64_t kvar_width_mismatch = 0;
    std::uint64_t kvar_value_mismatch = 0;
    std::uint64_t kaddvars_value_mismatch = 0;
    std::map<unsigned, std::pair<std::uint64_t, std::uint64_t>> add_by_width;
    std::vector<std::uint64_t> kvar_uses(n_vars, 0);
    std::vector<std::uint64_t> add_uses(n_vars, 0);
    std::map<std::tuple<unsigned, std::size_t, std::size_t>, std::uint64_t> pairs;

    using SiteKey = std::tuple<std::uint32_t, std::uint8_t, std::uint8_t, OpKey, OpKey>;
    std::map<SiteKey, std::uint64_t> with_site;
    std::set<std::tuple<std::uint8_t, std::uint8_t, OpKey, OpKey>> solver_only;
    std::set<std::tuple<std::uint32_t, std::uint8_t, std::uint8_t, std::uint64_t, std::uint64_t>>
        observed;
    std::set<std::uint32_t> sites;

    for (std::size_t p = 0; p < sys.path.size(); ++p) {
        const solver::Constraint& c = sys.path[p];
        for (const solver::Operand* op : {&c.lhs, &c.rhs}) {
            switch (op->kind) {
                case Kind::kVar:
                    ++kvar;
                    ++kvar_uses[op->var_index];
                    break;
                case Kind::kConst:
                    ++kconst;
                    break;
                case Kind::kAddVars: {
                    ++kadd;
                    const bool same = op->var_index == op->var_index2;
                    const bool zero =
                        Truncate(ReadVar(seed, sys.vars[op->var_index]), c.bit_width) == 0 ||
                        Truncate(ReadVar(seed, sys.vars[op->var_index2]), c.bit_width) == 0;
                    add_same += same ? 1 : 0;
                    add_zero += zero ? 1 : 0;
                    add_both += (same && zero) ? 1 : 0;
                    auto& w = add_by_width[c.bit_width];
                    ++w.first;
                    w.second += (same || zero) ? 1 : 0;
                    ++add_uses[op->var_index];
                    if (!same) {
                        ++add_uses[op->var_index2];
                    }
                    ++pairs[{c.bit_width, op->var_index, op->var_index2}];
                    break;
                }
            }
        }
        for (const solver::Operand* op : {&c.lhs, &c.rhs}) {
            if (op->kind == Kind::kVar && sys.vars[op->var_index].bit_width != c.bit_width) {
                ++kvar_width_mismatch;
            }
        }
        if (al.ok) {
            const Record& rec = records[al.record_of_path[p]];
            pred_as_logged += (c.predicate == rec.predicate) ? 1 : 0;
            const std::array<std::pair<const solver::Operand*, std::uint64_t>, 2> sides = {
                std::pair{&c.lhs, rec.lhs}, std::pair{&c.rhs, rec.rhs}};
            for (const auto& [op, observed_value] : sides) {
                if (op->kind == Kind::kConst || SideValue(seed, sys, *op, c.bit_width) ==
                                                    Truncate(observed_value, c.bit_width)) {
                    continue;
                }
                if (op->kind == Kind::kVar) {
                    ++kvar_value_mismatch;
                } else {
                    ++kaddvars_value_mismatch;
                }
            }
            ++with_site[{rec.site_id, c.predicate, c.bit_width, KeyOf(c.lhs), KeyOf(c.rhs)}];
            observed.insert({rec.site_id, rec.predicate, rec.bit_width,
                             Truncate(rec.lhs, rec.bit_width), Truncate(rec.rhs, rec.bit_width)});
            sites.insert(rec.site_id);
        }
        solver_only.insert({c.predicate, c.bit_width, KeyOf(c.lhs), KeyOf(c.rhs)});
    }

    // Пул: переменные по числу привязок, в которых они участвуют; верхние
    // kTopPool (при равенстве — меньший индекс) и доля привязок, задевающих их.
    std::vector<std::size_t> by_part(n_vars);
    for (std::size_t v = 0; v < n_vars; ++v) {
        by_part[v] = v;
    }
    std::stable_sort(by_part.begin(), by_part.end(), [&](std::size_t a, std::size_t b) {
        return kvar_uses[a] + add_uses[a] > kvar_uses[b] + add_uses[b];
    });
    std::vector<bool> in_top(n_vars, false);
    for (std::size_t k = 0; k < std::min(kTopPool, n_vars); ++k) {
        in_top[by_part[k]] = true;
    }
    std::uint64_t covered = 0;
    for (const solver::Constraint& c : sys.path) {
        for (const solver::Operand* op : {&c.lhs, &c.rhs}) {
            if (op->kind == Kind::kVar) {
                covered += in_top[op->var_index] ? 1 : 0;
            } else if (op->kind == Kind::kAddVars) {
                covered += (in_top[op->var_index] || in_top[op->var_index2]) ? 1 : 0;
            }
        }
    }

    for (std::size_t v = 0; v < n_vars; ++v) {
        const concolic::VarBinding& b = sys.vars[v];
        std::cout << "CENSUS-VAR seed=" << name << " var=" << v << " offset=" << b.offset
                  << " width=" << static_cast<unsigned>(b.bit_width)
                  << " endian=" << (b.big_endian ? "be" : "le")
                  << " value=" << Hex(ReadVar(seed, b)) << " kvar_uses=" << kvar_uses[v]
                  << " addvars_uses=" << add_uses[v] << " top=" << (in_top[v] ? "yes" : "no")
                  << '\n';
    }
    for (const auto& [key, uses] : pairs) {
        const auto& [bw, i, j] = key;
        const concolic::VarBinding& a = sys.vars[i];
        const concolic::VarBinding& b = sys.vars[j];
        const std::uint64_t vi = Truncate(ReadVar(seed, a), bw);
        const std::uint64_t vj = Truncate(ReadVar(seed, b), bw);
        std::cout << "CENSUS-PAIR seed=" << name << " bit_width=" << bw << " i=" << i << " j=" << j
                  << " off_i=" << a.offset << " off_j=" << b.offset
                  << " w_i=" << static_cast<unsigned>(a.bit_width)
                  << " w_j=" << static_cast<unsigned>(b.bit_width) << " val_i=" << Hex(vi)
                  << " val_j=" << Hex(vj) << " uses=" << uses
                  << " same_ij=" << (i == j ? "yes" : "no")
                  << " zero_field=" << ((vi == 0 || vj == 0) ? "yes" : "no") << '\n';
    }
    for (const auto& [bw, counts] : add_by_width) {
        std::cout << "CENSUS-WIDTH seed=" << name << " bit_width=" << bw
                  << " addvars=" << counts.first << " degenerate=" << counts.second << '\n';
    }
    if (!with_site.empty()) {
        const auto top =
            std::max_element(with_site.begin(), with_site.end(),
                             [](const auto& a, const auto& b) { return a.second < b.second; });
        const auto& [site, pred, bw, lk, rk] = top->first;
        std::cout << "CENSUS-TOPREPEAT seed=" << name << " count=" << top->second
                  << " site=" << site << " pred=" << static_cast<unsigned>(pred)
                  << " bit_width=" << static_cast<unsigned>(bw) << " lhs_kind=" << std::get<0>(lk)
                  << " rhs_kind=" << std::get<0>(rk) << '\n';
    }
    if (print_sample) {
        const std::vector<std::size_t> order = BitReversalOrder(sys.path.size());
        const std::size_t take = std::min(kSamplePerSeed, order.size());
        for (std::size_t k = 0; k < take; ++k) {
            const std::size_t p = order[k];
            const solver::Constraint& c = sys.path[p];
            std::cout << "CENSUS-SAMPLE seed=" << name << " idx=" << p;
            if (al.ok) {
                const Record& rec = records[al.record_of_path[p]];
                std::cout << " rec=" << al.record_of_path[p] << " site=" << rec.site_id
                          << " pred_logged=" << static_cast<unsigned>(rec.predicate)
                          << " lhs_obs=" << Hex(Truncate(rec.lhs, rec.bit_width))
                          << " rhs_obs=" << Hex(Truncate(rec.rhs, rec.bit_width));
            }
            std::cout << " pred_path=" << static_cast<unsigned>(c.predicate)
                      << " bit_width=" << static_cast<unsigned>(c.bit_width)
                      << " lhs_kind=" << KindName(c.lhs.kind)
                      << " rhs_kind=" << KindName(c.rhs.kind)
                      << " lhs=" << Describe(seed, sys, c.lhs, c.bit_width)
                      << " rhs=" << Describe(seed, sys, c.rhs, c.bit_width) << '\n';
        }
    }

    std::cout << "CENSUS-SEED name=" << name << " len=" << seed.size() << " status=" << status
              << " records=" << records.size() << " path_size=" << sys.path.size()
              << " num_vars=" << sys.num_vars << " align_ok=" << (al.ok ? "yes" : "no")
              << " dropped=" << al.dropped << " pred_as_logged=" << pred_as_logged
              << " sides=" << 2 * sys.path.size() << " kvar=" << kvar << " kconst=" << kconst
              << " kaddvars=" << kadd << " addvars_same_ij=" << add_same
              << " addvars_zero_field=" << add_zero << " addvars_same_and_zero=" << add_both
              << " bindings=" << kvar + kadd << " top5_covered=" << covered
              << " distinct_sites=" << sites.size()
              << " distinct_site_pred_ops=" << (al.ok ? with_site.size() : 0)
              << " distinct_solver_constraints=" << solver_only.size()
              << " distinct_observed=" << (al.ok ? observed.size() : 0)
              << " kvar_width_mismatch=" << kvar_width_mismatch << " kvar_value_mismatch="
              << (al.ok ? static_cast<long long>(kvar_value_mismatch) : -1)
              << " kaddvars_value_mismatch="
              << (al.ok ? static_cast<long long>(kaddvars_value_mismatch) : -1)
              << " first_mismatch_record=" << al.first_mismatch_record << '\n'
              << std::flush;
    return al.ok;
}

TEST(BindingCensus, OperandBindingsOnARealTarget) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }
    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };
    std::cout << "CENSUS-META sample_per_seed=" << kSamplePerSeed << " top_pool=" << kTopPool
              << " walltime_budget_s=" << kCensusWalltimeS << " target=" << TIFF_TARGET_REL
              << " corpus=" << TIFF_CORPUS_REL
              << " records_via=LastBranchRecords solver_calls=0 src_modified=0\n"
              << std::flush;

    // Положительный контроль: на add_gate гейт a+b==MAGIC обязан переписаться
    // одной невырожденной суммой полей на смещениях 0 и 4.
    {
        TargetSession ts;
        std::string err;
        ASSERT_TRUE(OpenSession(ADD_GATE_BIN, ts, err)) << err;
        const std::span<const std::uint8_t> seed(kAddGateSeed.data(), kAddGateSeed.size());
        const auto response = ts.runner->Run(seed);
        ASSERT_TRUE(response.has_value());
        const std::vector<Record> records = ts.runner->LastBranchRecords();
        std::cout << "CENSUS-CONTROL-ADDGATE-BEGIN\n";
        const bool ok =
            CensusOfSeed("add_gate", seed, static_cast<int>(response->status()), records, true);
        std::cout << "CENSUS-CONTROL-ADDGATE-END align_ok=" << (ok ? "yes" : "no") << '\n'
                  << std::flush;
        ASSERT_TRUE(ok) << "стенд сломан: путь add_gate не выровнялся по записям";
    }

    const std::vector<Seed> seeds = LoadSeeds();
    ASSERT_FALSE(seeds.empty()) << "корпус пуст";
    TargetSession ts;
    std::string err;
    ASSERT_TRUE(OpenSession(TIFF_TARGET_BIN, ts, err)) << err;

    std::string stop_reason = "complete";
    std::size_t done = 0;
    std::size_t aligned = 0;
    for (const Seed& s : seeds) {
        const std::span<const std::uint8_t> seed(s.bytes.data(), s.bytes.size());
        const auto response = ts.runner->Run(seed);
        const int status = response.has_value() ? static_cast<int>(response->status()) : -1;
        const std::vector<Record> records =
            response.has_value() ? ts.runner->LastBranchRecords() : std::vector<Record>{};
        aligned += CensusOfSeed(s.name, seed, status, records, true) ? 1 : 0;
        ++done;
        if (elapsed_s() > kCensusWalltimeS) {
            stop_reason = "walltime";
            break;
        }
    }
    std::cout << "CENSUS-DONE seeds=" << done << " of=" << seeds.size()
              << " align_ok_seeds=" << aligned << " stop_reason=" << stop_reason
              << " elapsed_s=" << static_cast<long long>(elapsed_s())
              << " solver_calls=0 src_modified=0\n"
              << std::flush;
}

long long TimeBuildUs(std::span<const std::uint8_t> seed, const std::vector<Record>& records,
                      concolic::System& out) {
    const auto t0 = std::chrono::steady_clock::now();
    out = concolic::BuildSystem(seed, records);
    const auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
}

TEST(BuildCost, SystemConstructionCostOnARealTarget) {
    const std::string missing = MissingArtifact();
    if (!missing.empty()) {
        GTEST_SKIP() << missing;
    }
    const auto t_start = std::chrono::steady_clock::now();
    const auto elapsed_s = [t_start]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    };
    std::cout << "BUILD-META reps=" << kBuildRepeats << " fracs=1/8,1/4,1/2"
              << " walltime_budget_s=" << kBuildWalltimeS << " target=" << TIFF_TARGET_REL
              << " corpus=" << TIFF_CORPUS_REL << " clock=steady_clock unit=us"
              << " solver_calls=0 src_modified=0\n"
              << std::flush;

    const std::vector<Seed> seeds = LoadSeeds();
    ASSERT_FALSE(seeds.empty()) << "корпус пуст";
    TargetSession ts;
    std::string err;
    ASSERT_TRUE(OpenSession(TIFF_TARGET_BIN, ts, err)) << err;

    std::string stop_reason = "complete";
    std::size_t done = 0;
    for (const Seed& s : seeds) {
        const std::span<const std::uint8_t> seed(s.bytes.data(), s.bytes.size());
        const auto response = ts.runner->Run(seed);
        if (!response.has_value()) {
            std::cout << "BUILD-SEED-SKIPPED seed=" << s.name << " reason=transport\n";
            continue;
        }
        const std::vector<Record> records = ts.runner->LastBranchRecords();

        // Порядок внутри сида перемешан намеренно: полный прогон, лестница,
        // ещё два полных — дрейф частоты процессора не ляжет на одну ступень.
        const auto full = [&](int rep) {
            concolic::System sys;
            const long long us = TimeBuildUs(seed, records, sys);
            std::uint64_t kv = 0;
            std::uint64_t kc = 0;
            std::uint64_t ka = 0;
            for (const solver::Constraint& c : sys.path) {
                for (const solver::Operand* op : {&c.lhs, &c.rhs}) {
                    kv += op->kind == Kind::kVar ? 1 : 0;
                    kc += op->kind == Kind::kConst ? 1 : 0;
                    ka += op->kind == Kind::kAddVars ? 1 : 0;
                }
            }
            std::cout << "BUILD-REP seed=" << s.name << " rep=" << rep
                      << " seed_len=" << s.bytes.size() << " records=" << records.size()
                      << " path_size=" << sys.path.size() << " num_vars=" << sys.num_vars
                      << " path_kvar_sides=" << kv << " path_kconst_sides=" << kc
                      << " path_kaddvars_sides=" << ka
                      << " dropped_records=" << records.size() - sys.path.size()
                      << " build_us=" << us << '\n'
                      << std::flush;
        };
        full(0);
        for (const unsigned denom : {8U, 4U, 2U}) {
            const std::vector<Record> prefix(
                records.begin(),
                records.begin() + static_cast<std::ptrdiff_t>(records.size() / denom));
            concolic::System sys;
            const long long us = TimeBuildUs(seed, prefix, sys);
            std::cout << "BUILD-SCALE seed=" << s.name << " frac=1/" << denom
                      << " seed_len=" << s.bytes.size() << " records=" << prefix.size()
                      << " path_size=" << sys.path.size() << " num_vars=" << sys.num_vars
                      << " build_us=" << us << '\n'
                      << std::flush;
        }
        for (int rep = 1; rep < kBuildRepeats; ++rep) {
            full(rep);
        }
        ++done;
        if (elapsed_s() > kBuildWalltimeS) {
            stop_reason = "walltime";
            break;
        }
    }
    std::cout << "BUILD-DONE seeds=" << done << " of=" << seeds.size()
              << " stop_reason=" << stop_reason
              << " elapsed_s=" << static_cast<long long>(elapsed_s())
              << " solver_calls=0 src_modified=0\n"
              << std::flush;
}

}  // namespace
}  // namespace mlfuzzz3::core
