#include "coverage_reader.h"

#include <sys/mman.h>

#include <cstring>
#include <utility>

namespace mlfuzzz3::coverage {

tl::expected<CoverageReader, CoverageReaderError> CoverageReader::Create(int borrowed_fd,
                                                                         std::size_t size) {
    if (size != kMapSize) {
        return tl::unexpected(CoverageReaderError::kSizeMismatch);
    }
    void* map = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, borrowed_fd, 0);
    if (map == MAP_FAILED) {
        return tl::unexpected(CoverageReaderError::kMmapFailed);
    }
    return CoverageReader{map, size};
}

CoverageReader::CoverageReader(CoverageReader&& other) noexcept
    : map_(other.map_), size_(other.size_) {
    other.map_ = nullptr;
    other.size_ = 0;
}

CoverageReader& CoverageReader::operator=(CoverageReader&& other) noexcept {
    if (this != &other) {
        Munmap();
        map_ = other.map_;
        size_ = other.size_;
        other.map_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

CoverageReader::~CoverageReader() {
    Munmap();
}

void CoverageReader::Munmap() noexcept {
    if (map_ != nullptr) {
        ::munmap(map_, size_);
        map_ = nullptr;
        size_ = 0;
    }
}

std::vector<std::uint8_t> CoverageReader::Read() const {
    std::vector<std::uint8_t> out(size_);
    if (size_ > 0) {
        std::memcpy(out.data(), map_, size_);
    }
    return out;
}

}  // namespace mlfuzzz3::coverage
