#include "corpus.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iterator>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "fnv.h"
#include "log.h"

namespace mlfuzzz3::core {
namespace {

// Finding file names (crashes/, hangs/) are content-addressed via
// FnvHash (src/core/fnv.h): identical findings collapse to one file and
// names are deterministic (ADR 0029 replay).
constexpr int kHashHexWidth = 16;  // 64-bit hash → 16 hex digits
constexpr int kCorpusIdWidth = 6;  // zero-padded entry id in corpus/ names
constexpr std::uint8_t kTrivialSeedByte = 0;

std::span<const std::uint8_t> AsSpan(const mutation::FuzzInput& input) {
    return {input.data(), input.size()};
}

// WriteBytes truncates path and writes bytes verbatim. Per-byte put with
// an explicit char cast avoids a reinterpret_cast of the uint8_t buffer.
bool WriteBytes(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    for (const std::uint8_t byte : bytes) {
        out.put(static_cast<char>(byte));
    }
    out.flush();
    return out.good();
}

tl::expected<std::vector<std::uint8_t>, CorpusError> ReadFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return tl::unexpected(CorpusError::kSeedReadFailed);
    }
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
    if (in.bad()) {
        return tl::unexpected(CorpusError::kSeedReadFailed);
    }
    return bytes;
}

std::string FindingName(std::string_view prefix, std::uint64_t hash) {
    std::ostringstream name;
    name << prefix << std::hex << std::setw(kHashHexWidth) << std::setfill('0') << hash << ".bin";
    return name.str();
}

// Bootstrap visibility helpers (ADR 0032 follow-up). Logging only — the
// seed-loading behaviour in Corpus::Bootstrap is unchanged; these only
// describe what was loaded and flag suspicious-looking seeds.

// LoadedSeed records one seed's display name and byte size for the log.
struct LoadedSeed {
    std::string name;
    std::size_t size;
};

// A seed whose size exceeds this multiple of the corpus median is
// flagged. A tunable default, not a contract.
constexpr std::size_t kSizeOutlierFactor = 8;
// Below this many seeds the median is not a meaningful baseline, so the
// size-outlier screen is skipped (the doc-name screen still runs).
constexpr std::size_t kMinSeedsForOutlierScreen = 3;

// IsDocLikeName flags inputs that look like documentation accidentally
// dropped into a seed directory (the README-as-seed footgun): a .md/.txt
// extension or "readme" anywhere in the name (case-insensitive).
bool IsDocLikeName(const std::string& name) {
    std::string lower = name;
    std::ranges::transform(lower, lower.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return lower.ends_with(".md") || lower.ends_with(".txt") ||
           lower.find("readme") != std::string::npos;
}

// MedianSize returns the upper-median of the sizes (0 for an empty set).
std::size_t MedianSize(std::vector<std::size_t> sizes) {
    if (sizes.empty()) {
        return 0;
    }
    std::ranges::sort(sizes);
    return sizes[sizes.size() / 2];
}

// LogBootstrapSeeds reports the loaded seed set (count, names, sizes) and
// warns on anomalies. No-op when no seed directory was given.
void LogBootstrapSeeds(const std::filesystem::path& seed_dir,
                       const std::vector<LoadedSeed>& loaded) {
    if (seed_dir.empty()) {
        return;
    }
    LOG_INFO("corpus bootstrap: loaded {} seed(s) from {}", loaded.size(), seed_dir.string());

    std::vector<std::size_t> sizes;
    sizes.reserve(loaded.size());
    for (const LoadedSeed& seed : loaded) {
        LOG_INFO("  seed: {} ({} bytes)", seed.name, seed.size);
        sizes.push_back(seed.size);
    }

    const std::size_t median = MedianSize(sizes);
    const bool screen_outliers = loaded.size() >= kMinSeedsForOutlierScreen && median > 0;
    for (const LoadedSeed& seed : loaded) {
        if (IsDocLikeName(seed.name)) {
            LOG_WARN(
                "corpus bootstrap: seed {} looks like documentation "
                "(.md/.txt/README), not a test input",
                seed.name);
        }
        if (screen_outliers && seed.size > kSizeOutlierFactor * median) {
            LOG_WARN(
                "corpus bootstrap: seed {} is {} bytes, far above the corpus "
                "median of {} bytes",
                seed.name, seed.size, median);
        }
    }
}

}  // namespace

tl::expected<Corpus, CorpusError> Corpus::Create(const std::filesystem::path& base_dir) {
    std::filesystem::path corpus_dir = base_dir / "corpus";
    std::filesystem::path crashes_dir = base_dir / "crashes";
    std::filesystem::path hangs_dir = base_dir / "hangs";

    std::error_code ec;
    std::filesystem::create_directories(corpus_dir, ec);
    if (ec) {
        return tl::unexpected(CorpusError::kDirectoryCreateFailed);
    }
    std::filesystem::create_directories(crashes_dir, ec);
    if (ec) {
        return tl::unexpected(CorpusError::kDirectoryCreateFailed);
    }
    std::filesystem::create_directories(hangs_dir, ec);
    if (ec) {
        return tl::unexpected(CorpusError::kDirectoryCreateFailed);
    }

    return Corpus(std::move(corpus_dir), std::move(crashes_dir), std::move(hangs_dir));
}

tl::expected<std::size_t, CorpusError> Corpus::Bootstrap(const std::filesystem::path& seed_dir) {
    // Metadata for the bootstrap visibility log (ADR 0032 follow-up),
    // collected as seeds load; the load itself is unchanged.
    std::vector<LoadedSeed> loaded;

    if (!seed_dir.empty()) {
        std::error_code ec;
        if (std::filesystem::is_directory(seed_dir, ec)) {
            for (const auto& entry : std::filesystem::directory_iterator(seed_dir, ec)) {
                std::error_code fec;
                if (!entry.is_regular_file(fec) || fec) {
                    continue;
                }
                auto bytes = ReadFile(entry.path());
                if (!bytes) {
                    return tl::unexpected(bytes.error());
                }
                const std::size_t size = bytes->size();
                auto id = Add(mutation::FuzzInput(std::move(*bytes)), 0);
                if (!id) {
                    return tl::unexpected(id.error());
                }
                loaded.push_back(
                    LoadedSeed{.name = entry.path().filename().string(), .size = size});
            }
            if (ec) {
                return tl::unexpected(CorpusError::kSeedReadFailed);
            }
        }
    }

    LogBootstrapSeeds(seed_dir, loaded);

    if (entries_.empty()) {
        auto id = Add(mutation::FuzzInput(std::vector<std::uint8_t>{kTrivialSeedByte}), 0);
        if (!id) {
            return tl::unexpected(id.error());
        }
        LOG_INFO("corpus bootstrap: no usable seeds; injected one trivial 1-byte input");
    }
    return entries_.size();
}

tl::expected<std::uint64_t, CorpusError> Corpus::Add(mutation::FuzzInput input,
                                                     std::uint32_t new_edges) {
    const std::uint64_t id = next_id_;
    std::ostringstream name;
    name << "id_" << std::setw(kCorpusIdWidth) << std::setfill('0') << id << ".bin";
    const std::filesystem::path path = corpus_dir_ / name.str();

    if (!WriteBytes(path, AsSpan(input))) {
        return tl::unexpected(CorpusError::kWriteFailed);
    }

    entries_.push_back(CorpusEntry{.id = id, .input = std::move(input), .new_edges = new_edges});
    ++next_id_;
    return id;
}

void Corpus::SetDetState(std::size_t index, DetState state) {
    entries_.at(index).det = state;
}

tl::expected<void, CorpusError> Corpus::SaveCrash(const mutation::FuzzInput& input) {
    const std::filesystem::path path = crashes_dir_ / FindingName("crash_", FnvHash(AsSpan(input)));
    if (!WriteBytes(path, AsSpan(input))) {
        return tl::unexpected(CorpusError::kWriteFailed);
    }
    return {};
}

tl::expected<void, CorpusError> Corpus::SaveHang(const mutation::FuzzInput& input) {
    const std::filesystem::path path = hangs_dir_ / FindingName("hang_", FnvHash(AsSpan(input)));
    if (!WriteBytes(path, AsSpan(input))) {
        return tl::unexpected(CorpusError::kWriteFailed);
    }
    return {};
}

}  // namespace mlfuzzz3::core
