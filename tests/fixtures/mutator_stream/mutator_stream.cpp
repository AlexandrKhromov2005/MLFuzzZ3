// Регистратор потока входов для сравнения мутаторов (пункт добора Д4
// карты docs/EVALUATION.md).
//
// Одна фикстура закрывает обе стороны сравнения, потому что сравнивать
// надо не результат фаззера, а поток входов, который мутатор порождает:
//
//   * режим record — цель, под которой работает ЧУЖОЙ движок (afl-fuzz).
//     Вход читается со stdin и дописывается в общий журнал; сам вход
//     никак не обрабатывается, поэтому журнал есть в точности поток
//     чужого мутатора и ничего больше.
//   * режимы emit-havoc и emit-det — НАШ движок. Мутанты порождаются
//     прямым вызовом mutation::HavocMutator::mutate и
//     mutation::DeterministicStage::apply (боевые файлы src/mutation/,
//     не копии) и пишутся в журнал ТОГО ЖЕ формата.
//
// Формат журнала: подряд идущие записи «длина uint32 LE + байты». Он
// одинаков для обоих плеч — иначе разница плеч могла бы прийти из
// разного способа снятия потока, а не из мутатора.
//
// Фикстура ничего не измеряет: покрытие обоих потоков снимается ОДНОЙ
// инструментированной сборкой цели уже после съёма (capture.py).

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "mutation/deterministic_stage.h"
#include "mutation/fuzz_input.h"
#include "mutation/mutators/havoc.h"
#include "mutation/rng.h"

namespace {

using mlfuzzz3::mutation::DeterministicStage;
using mlfuzzz3::mutation::FuzzInput;
using mlfuzzz3::mutation::HavocMutator;

constexpr std::size_t kReadChunk = 65536;

// Одна запись журнала: длина (uint32 LE) и байты, единственным write().
// Единственным — потому что в режиме record писать могут наследники
// afl-fuzz, и запись, разорванная на два вызова, перемешалась бы.
bool AppendRecord(int fd, const std::vector<std::uint8_t>& bytes) {
    std::vector<std::uint8_t> frame;
    frame.reserve(bytes.size() + 4);
    const auto len = static_cast<std::uint32_t>(bytes.size());
    for (int i = 0; i < 4; ++i) {
        frame.push_back(static_cast<std::uint8_t>((len >> (8 * i)) & 0xFFU));
    }
    frame.insert(frame.end(), bytes.begin(), bytes.end());
    const ssize_t written = ::write(fd, frame.data(), frame.size());
    return written == static_cast<ssize_t>(frame.size());
}

int OpenLog(const char* path) {
    return ::open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

std::vector<std::uint8_t> ReadAll(std::FILE* stream) {
    std::vector<std::uint8_t> out;
    std::vector<std::uint8_t> chunk(kReadChunk);
    while (true) {
        const std::size_t got = std::fread(chunk.data(), 1, chunk.size(), stream);
        out.insert(out.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(got));
        if (got < chunk.size()) {
            break;
        }
    }
    return out;
}

bool ReadSeed(const char* path, std::vector<std::uint8_t>* out) {
    std::FILE* fh = std::fopen(path, "rb");
    if (fh == nullptr) {
        return false;
    }
    *out = ReadAll(fh);
    std::fclose(fh);
    return true;
}

int Usage() {
    std::fprintf(stderr,
                 "usage:\n"
                 "  mutator_stream record <log>\n"
                 "  mutator_stream emit-havoc <log> <count> <rng_seed> <seed>...\n"
                 "  mutator_stream emit-det <log> <count> <cursor_offset> <seed>...\n");
    return 2;
}

// Чужое плечо: вход приходит по stdin от afl-fuzz, дописывается в журнал
// и НЕ обрабатывается. Код возврата всегда 0 — цель не должна выглядеть
// падающей, иначе чужой планировщик сменит поведение.
int RunRecord(const char* log_path) {
    const std::vector<std::uint8_t> input = ReadAll(stdin);
    const int fd = OpenLog(log_path);
    if (fd < 0) {
        std::fprintf(stderr, "mutator_stream: open %s: %s\n", log_path, std::strerror(errno));
        return 1;
    }
    const bool ok = AppendRecord(fd, input);
    ::close(fd);
    return ok ? 0 : 1;
}

// Наше плечо. `stage` выбирает оператор: havoc берёт ГПСЧ с явным зерном,
// детерминированная стадия ГПСЧ не имеет вовсе и ходит по курсору.
int RunEmit(bool havoc, const char* log_path, std::uint64_t count, std::uint64_t knob,
            const std::vector<std::string>& seed_paths) {
    std::vector<FuzzInput> seeds;
    seeds.reserve(seed_paths.size());
    for (const std::string& path : seed_paths) {
        std::vector<std::uint8_t> bytes;
        if (!ReadSeed(path.c_str(), &bytes)) {
            std::fprintf(stderr, "mutator_stream: seed %s unreadable\n", path.c_str());
            return 1;
        }
        seeds.emplace_back(std::move(bytes));
    }
    if (seeds.empty()) {
        return Usage();
    }

    const int fd = OpenLog(log_path);
    if (fd < 0) {
        std::fprintf(stderr, "mutator_stream: open %s: %s\n", log_path, std::strerror(errno));
        return 1;
    }

    const HavocMutator mutator;
    std::mt19937_64 rng = mlfuzzz3::mutation::make_rng(knob);

    // Длины детерминированного обхода печатаются в stderr, чтобы сырьё
    // называло, исчерпывается ли стадия на выданном бюджете.
    std::uint64_t det_total = 0;
    for (const FuzzInput& seed : seeds) {
        const std::uint64_t len = DeterministicStage::length(seed);
        det_total += len;
        std::fprintf(stderr, "STAGE det_length seed_bytes=%zu steps=%llu\n", seed.size(),
                     static_cast<unsigned long long>(len));
    }
    std::fprintf(stderr, "STAGE det_total steps=%llu\n",
                 static_cast<unsigned long long>(det_total));

    std::uint64_t emitted = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        const FuzzInput& seed = seeds[i % seeds.size()];
        FuzzInput out;
        if (havoc) {
            out = mutator.mutate(seed, rng);
        } else {
            const std::uint64_t len = DeterministicStage::length(seed);
            if (len == 0) {
                continue;
            }
            out = DeterministicStage::apply(seed, (knob + i / seeds.size()) % len);
        }
        std::vector<std::uint8_t> bytes(out.data(), out.data() + out.size());
        if (!AppendRecord(fd, bytes)) {
            ::close(fd);
            return 1;
        }
        ++emitted;
    }
    ::close(fd);
    std::fprintf(stderr, "STAGE emitted count=%llu\n", static_cast<unsigned long long>(emitted));
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        return Usage();
    }
    const std::string mode = argv[1];
    if (mode == "record") {
        return RunRecord(argv[2]);
    }
    if (mode == "emit-havoc" || mode == "emit-det") {
        if (argc < 6) {
            return Usage();
        }
        const auto count = std::strtoull(argv[3], nullptr, 10);
        const auto knob = std::strtoull(argv[4], nullptr, 10);
        std::vector<std::string> seeds;
        for (int i = 5; i < argc; ++i) {
            seeds.emplace_back(argv[i]);
        }
        return RunEmit(mode == "emit-havoc", argv[2], count, knob, seeds);
    }
    return Usage();
}
