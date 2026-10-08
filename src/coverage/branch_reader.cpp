#include "branch_reader.h"

#include <sys/mman.h>

#include <algorithm>
#include <cstring>
#include <span>
#include <unordered_map>

namespace mlfuzzz3::coverage {

namespace {

using ByteSpan = std::span<const std::uint8_t>;

std::uint8_t LoadU8(ByteSpan b) {
    std::uint8_t v = 0;
    std::memcpy(&v, b.data(), sizeof(v));
    return v;
}

std::uint32_t LoadU32(ByteSpan b) {
    std::uint32_t v = 0;
    std::memcpy(&v, b.data(), sizeof(v));
    return v;
}

std::uint64_t LoadU64(ByteSpan b) {
    std::uint64_t v = 0;
    std::memcpy(&v, b.data(), sizeof(v));
    return v;
}

}  // namespace

tl::expected<BranchReader, BranchReaderError> BranchReader::Create(int borrowed_fd,
                                                                   std::size_t size) {
    if (size != kBranchSegmentSize) {
        return tl::unexpected(BranchReaderError::kSizeMismatch);
    }
    void* map = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, borrowed_fd, 0);
    if (map == MAP_FAILED) {
        return tl::unexpected(BranchReaderError::kMmapFailed);
    }
    return BranchReader{map, size};
}

BranchReader::BranchReader(BranchReader&& other) noexcept : map_(other.map_), size_(other.size_) {
    other.map_ = nullptr;
    other.size_ = 0;
}

BranchReader& BranchReader::operator=(BranchReader&& other) noexcept {
    if (this != &other) {
        Munmap();
        map_ = other.map_;
        size_ = other.size_;
        other.map_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

BranchReader::~BranchReader() {
    Munmap();
}

void BranchReader::Munmap() noexcept {
    if (map_ != nullptr) {
        ::munmap(map_, size_);
        map_ = nullptr;
        size_ = 0;
    }
}

std::uint32_t BranchReader::RecordCount() const noexcept {
    if (map_ == nullptr || size_ < kBranchHeaderSize) {
        return 0;
    }
    const ByteSpan seg{static_cast<const std::uint8_t*>(map_), size_};
    return LoadU32(seg.subspan(kBranchOffCount));
}

bool BranchReader::Overflow() const noexcept {
    if (map_ == nullptr || size_ < kBranchHeaderSize) {
        return false;
    }
    const ByteSpan seg{static_cast<const std::uint8_t*>(map_), size_};
    return LoadU32(seg.subspan(kBranchOffOverflow)) != 0;
}

std::vector<BranchReader::Record> BranchReader::Records() const {
    std::vector<Record> out;
    if (map_ == nullptr || size_ < kBranchHeaderSize) {
        return out;
    }
    const ByteSpan seg{static_cast<const std::uint8_t*>(map_), size_};

    std::uint32_t count = LoadU32(seg.subspan(kBranchOffCount));
    const std::uint32_t capacity = LoadU32(seg.subspan(kBranchOffCapacity));
    count = std::min(count, capacity);
    const auto max_by_buf =
        static_cast<std::uint32_t>((size_ - kBranchHeaderSize) / kBranchRecordSize);
    count = std::min(count, max_by_buf);

    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t off =
            kBranchHeaderSize + (static_cast<std::size_t>(i) * kBranchRecordSize);
        const ByteSpan rec = seg.subspan(off, kBranchRecordSize);
        out.push_back(Record{
            .site_id = LoadU32(rec.subspan(kRecOffSiteId)),
            .predicate = LoadU8(rec.subspan(kRecOffPredicate)),
            .bit_width = LoadU8(rec.subspan(kRecOffBitWidth)),
            .lhs = LoadU64(rec.subspan(kRecOffLhs)),
            .rhs = LoadU64(rec.subspan(kRecOffRhs)),
        });
    }
    return out;
}

SiteOccurrences BranchReader::Occurrences() const {
    return NumberSiteOccurrences(Records(), Overflow());
}

SiteOccurrences NumberSiteOccurrences(std::span<const BranchReader::Record> records,
                                      bool overflow) {
    SiteOccurrences out;
    out.reliable = !overflow;
    out.occurrence.reserve(records.size());
    std::unordered_map<std::uint32_t, std::uint32_t> seen;
    for (const BranchReader::Record& rec : records) {
        out.occurrence.push_back(seen[rec.site_id]++);
    }
    return out;
}

}  // namespace mlfuzzz3::coverage
