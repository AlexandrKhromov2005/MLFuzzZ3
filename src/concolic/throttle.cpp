#include "throttle.h"

#include <cstddef>

namespace mlfuzzz3::concolic {

void ConcolicThrottle::Observe(SolveOutcome outcome) {
    if (cfg_.window == 0) {
        return;
    }
    if (window_.size() < cfg_.window) {
        window_.push_back(outcome);
    } else {
        // Evict the oldest entry before it is overwritten.
        if (window_[head_] == SolveOutcome::kUnsat) {
            --unsat_count_;
        }
        window_[head_] = outcome;
        head_ = (head_ + 1) % cfg_.window;
    }
    if (outcome == SolveOutcome::kUnsat) {
        ++unsat_count_;
    }

    // A candidate proves the target is still solvable: release at once and
    // drop the accumulated backoff (§ asymmetry, see the header).
    if (outcome == SolveOutcome::kCandidate) {
        engaged_ = false;
        shift_ = 0;
        return;
    }
    Reevaluate();
}

void ConcolicThrottle::Reevaluate() {
    const std::size_t samples = window_.size();
    if (samples < cfg_.min_samples) {
        return;  // not enough evidence to call the target unsat-dominated
    }
    const double ratio = static_cast<double>(unsat_count_) / static_cast<double>(samples);
    if (ratio < cfg_.unsat_ratio) {
        engaged_ = false;
        shift_ = 0;
        return;
    }
    if (!engaged_) {
        engaged_ = true;
        shift_ = 0;
        ++engagements_;
        return;
    }
    if (shift_ < cfg_.max_shift) {
        ++shift_;  // multiplicative backoff while the evidence keeps holding
    }
}

std::uint64_t ConcolicThrottle::CurrentInterval() const {
    if (!cfg_.enabled || !engaged_) {
        return 0;
    }
    return cfg_.base_interval << shift_;
}

}  // namespace mlfuzzz3::concolic
