#pragma once

#include <unistd.h>

#include <utility>

namespace mlfuzzz3::ipc {

// UniqueFd is a move-only RAII wrapper for a Unix file
// descriptor. Closes the fd on destruction. Used by the
// SCM_RIGHTS receive path (Conn::ReadEnvelopeWithFd /
// ReadEnvelopeMaybeFd) per ADR 0015 §D recv-side
// transfer semantics.
//
// Invariant: a fd_ value of -1 represents "no fd"; the
// destructor is a no-op in that case.
class UniqueFd {
   public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    ~UniqueFd() {
        reset();
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.release();
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

    [[nodiscard]] int release() noexcept {
        int t = fd_;
        fd_ = -1;
        return t;
    }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return fd_ >= 0;
    }

   private:
    int fd_ = -1;
};

}  // namespace mlfuzzz3::ipc
