"""Two-sample survival statistics for the ADR-0046 time-to-reach primary axis.

Hand-implemented in the standard library — no numpy, no scipy — so the
benchmark harness carries no heavy stats dependency (same rationale as
``mannwhitney.py``; ADR-0044 D1). The log-rank statistic and p-value are the
textbook Mantel-Cox test with the hypergeometric (ties-aware) variance, the
same definition ``lifelines.statistics.logrank_test`` and
``scipy.stats.logrank`` compute; values are cross-checked against both offline
(see ``test_survival.py``) within a tight tolerance.

Event coding (ADR-0046): for one (arm, trial, codec-gated bug), the observation
is the time-to-first-reach. ``event=1`` means the bug was reached at that time;
``event=0`` means it was never reached within the budget (right-censored at the
budget). Times come from the log-spaced snapshot grid, so MANY observations tie
at the same grid time — the hypergeometric variance handles ties exactly.

Edge cases return a status marker instead of raising / NaN-propagating:
  - 'no_events'      : no bug reached in either group (all censored).
  - 'no_separation'  : total variance is 0 (e.g. every subject tied at one time).
  - 'ok'             : a defined (chi2, p).
"""
from __future__ import annotations

import math


def _as_pairs(times, events):
    if len(times) != len(events):
        raise ValueError("times and events must be the same length")
    return list(zip([float(t) for t in times], [int(e) for e in events]))


def logrank_test(times_a, events_a, times_b, events_b):
    """Two-sample log-rank (Mantel-Cox) test.

    Returns ``(chi2, p, status)``. ``chi2`` is the 1-df statistic computed
    against group A (the first sample); ``p`` is the two-sided p-value from the
    chi-square(1) survival function. On an undefined comparison ``chi2`` is NaN,
    ``p`` is 1.0, and ``status`` names the reason ('no_events'/'no_separation').
    """
    a = _as_pairs(times_a, events_a)
    b = _as_pairs(times_b, events_b)
    combined = [(t, e, 0) for t, e in a] + [(t, e, 1) for t, e in b]

    # Distinct times at which at least one event (reach) occurs.
    event_times = sorted({t for t, e, _ in combined if e == 1})
    if not event_times:
        return float("nan"), 1.0, "no_events"

    obs_a = 0.0   # observed events in group A
    exp_a = 0.0   # expected events in group A under H0
    var = 0.0     # summed hypergeometric variance
    for t in event_times:
        # Risk set just before t: everyone whose time is >= t.
        n = sum(1 for tt, _, _ in combined if tt >= t)
        n_a = sum(1 for tt, _, g in combined if tt >= t and g == 0)
        # Events at exactly t (ties), and how many fall in group A.
        d = sum(1 for tt, e, _ in combined if tt == t and e == 1)
        d_a = sum(1 for tt, e, g in combined if tt == t and e == 1 and g == 0)
        if n <= 1:
            # variance factor (n - d) / (n - 1) is undefined / zero at n == 1.
            continue
        frac_a = n_a / n
        obs_a += d_a
        exp_a += d * frac_a
        var += d * frac_a * (1.0 - frac_a) * (n - d) / (n - 1)

    if var <= 0.0:
        return float("nan"), 1.0, "no_separation"

    chi2 = (obs_a - exp_a) ** 2 / var
    # chi-square(1) survival: P(X >= chi2) = erfc(sqrt(chi2 / 2)).
    p = math.erfc(math.sqrt(chi2 / 2.0))
    return chi2, p, "ok"


def kaplan_meier(times, events):
    """Kaplan-Meier survival estimate S(t) = P(time-to-reach > t).

    Returns a list of ``(t, S)`` step points starting at ``(0.0, 1.0)``; S drops
    at each distinct event time by the factor ``(1 - d/n)``. Censored
    observations stay in the risk set until their censoring time, then leave.
    Suitable for drawing a right-continuous step survival curve.
    """
    data = sorted(_as_pairs(times, events))
    event_times = sorted({t for t, e in data if e == 1})
    steps = [(0.0, 1.0)]
    surv = 1.0
    for t in event_times:
        n = sum(1 for tt, _ in data if tt >= t)        # at risk just before t
        d = sum(1 for tt, e in data if tt == t and e == 1)  # events at t
        if n > 0:
            surv *= 1.0 - d / n
        steps.append((t, surv))
    return steps
