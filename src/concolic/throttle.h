#ifndef MLFUZZZ3_CONCOLIC_THROTTLE_H_
#define MLFUZZZ3_CONCOLIC_THROTTLE_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "concolic.h"

namespace mlfuzzz3::concolic {

/// Defaults for ThrottleConfig, named so the tuning is readable at the point
/// it is argued about (ADR 0038, adaptive extension) rather than inline.
///
/// The window is long enough that a burst of unsat cannot trip it and short
/// enough to notice a target that starts converting again; min_samples is half
/// the window, so no verdict is reached on partial evidence. The ratio is
/// deliberately near-total: "unsat-dominated" must mean dominated, not merely
/// frequent. base_interval is one call per 1000 execs at the first step —
/// already a large cut against an every-stagnation rate — and the shift cap
/// bounds the backoff at 32x that, so a throttled stage still gets a periodic
/// chance to discover the target became solvable.
inline constexpr std::size_t kDefaultThrottleWindow = 32;
inline constexpr std::size_t kDefaultThrottleMinSamples = 16;
inline constexpr double kDefaultThrottleUnsatRatio = 0.9;
inline constexpr std::uint64_t kDefaultThrottleBaseInterval = 1000;
inline constexpr unsigned kDefaultThrottleMaxShift = 5;

/// Tuning for ConcolicThrottle. The defaults are deliberately conservative:
/// the throttle stays silent unless a long run of calls is overwhelmingly
/// unsat, so a target that still yields candidates is never slowed down.
struct ThrottleConfig {
    /// Master switch. false -> CurrentInterval() is always 0 (pre-throttle
    /// behavior: only the static ADR 0038 budget applies).
    bool enabled = true;
    /// Sliding window of the most recent solve outcomes.
    std::size_t window = kDefaultThrottleWindow;
    /// No judgement before this many outcomes are in the window — a handful
    /// of early unsat calls must not be read as "the target is unsat-bound".
    std::size_t min_samples = kDefaultThrottleMinSamples;
    /// Engage at or above this unsat share of the window.
    double unsat_ratio = kDefaultThrottleUnsatRatio;
    /// Interval (in execs) demanded at the first backoff step.
    std::uint64_t base_interval = kDefaultThrottleBaseInterval;
    /// Cap on the doubling: the demanded interval never exceeds
    /// base_interval << max_shift.
    unsigned max_shift = kDefaultThrottleMaxShift;
};

/// Adaptive rate-limit for the concolic stage on an unsat-dominated target
/// (ADR 0038, adaptive extension of the static concolic_min_exec_interval).
///
/// The static budget of 0038 is a fixed toll paid on every target. It cannot
/// tell a target where solving pays for itself from one where the inverted
/// system is essentially always unsatisfiable and every call is pure cost.
/// This throttle reads that difference off the outcome stream:
///
///   - each finished solve is reported through Observe();
///   - once the sliding window holds at least `min_samples` outcomes and the
///     unsat share reaches `unsat_ratio`, the throttle ENGAGES and demands a
///     minimum exec interval between calls, doubling it on each further unsat
///     up to base_interval << max_shift (multiplicative backoff);
///   - a single kCandidate — proof the target is still solvable — disengages
///     it immediately and resets the backoff to zero. That asymmetry is the
///     point: cost is reclaimed slowly, productivity is honoured at once.
///
/// CurrentInterval() returns 0 while disengaged, so a caller that takes the
/// max of it and the static budget is bit-for-bit unchanged on any target the
/// throttle does not fire on. Not thread-safe (the MVP loop is single-threaded).
class ConcolicThrottle {
   public:
    ConcolicThrottle() = default;
    explicit ConcolicThrottle(ThrottleConfig cfg) : cfg_(cfg) {}

    /// Report the outcome of one finished solve.
    void Observe(SolveOutcome outcome);

    /// Minimum execs the throttle demands between concolic calls right now.
    /// 0 means "no demand" — disengaged, or disabled by config.
    [[nodiscard]] std::uint64_t CurrentInterval() const;

    /// Whether the throttle is currently holding the stage back.
    [[nodiscard]] bool engaged() const {
        return engaged_;
    }

    /// Number of times the throttle went from disengaged to engaged — the
    /// metric that says "the adaptive path actually fired", distinct from how
    /// many calls it blocked.
    [[nodiscard]] std::uint64_t engagements() const {
        return engagements_;
    }

    /// Outcomes currently in the window and how many of them were unsat —
    /// exposed so a test can pin the decision instead of only its effect.
    [[nodiscard]] std::size_t samples() const {
        return window_.size();
    }
    [[nodiscard]] std::size_t unsat_samples() const {
        return unsat_count_;
    }

   private:
    void Reevaluate();

    ThrottleConfig cfg_{};
    std::vector<SolveOutcome> window_;  // ring buffer, at most cfg_.window entries
    std::size_t head_ = 0;              // next slot to overwrite once full
    std::size_t unsat_count_ = 0;
    bool engaged_ = false;
    unsigned shift_ = 0;
    std::uint64_t engagements_ = 0;
};

}  // namespace mlfuzzz3::concolic

#endif  // MLFUZZZ3_CONCOLIC_THROTTLE_H_
