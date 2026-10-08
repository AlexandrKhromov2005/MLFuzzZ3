"""Dependency-free Mann-Whitney U test and Holm-Bonferroni adjustment.

ADR 0032: the reproducible dev image (ADR 0006) ships only the python3
standard library — no numpy, no scipy — so the benchmark harness carries
its own statistics.

Two ways to get ``p`` live here, and ``method`` picks between them.

* ``asymptotic`` — normal approximation, the module's original and (until
  2026-09-16) only behaviour. It mirrors
  ``scipy.stats.mannwhitneyu(..., method='asymptotic', use_continuity=True)``:
  average ranks for ties, a tie-corrected variance, and a continuity
  correction of 0.5 toward the mean. Reference values in the test module
  were generated offline from scipy 1.17.1 and are matched within a tight
  tolerance.
* ``exact`` — the exact conditional (permutation) null distribution of U.
  The approximation is justified for large samples; our benchmarks almost
  always run N = 10 against 10, where the approximation is visibly wrong
  in the tail: at U = 0, n = m = 10 it reports 1.83e-04 where the exact
  two-sided p is 2 / C(20, 10) = 1.08e-05, a factor of 17.

``method="auto"`` (the default since 2026-09-16) takes the exact branch
when both samples are smaller than ``EXACT_MAX_N`` and falls back to the
approximation otherwise. Callers that need the pre-2026-09-16 numbers ask
for ``method="asymptotic"`` explicitly.

Pure standard library: only ``math`` and ``itertools``.
"""

from __future__ import annotations

import math
from itertools import combinations

#: Exact branch applies when both samples are smaller than this.
EXACT_MAX_N = 20

#: Cap on the tie-aware enumeration: C(n1 + n2, n1) splits are walked, so
#: the cost is linear in this number. 2e6 covers every n1, n2 <= 11 and
#: the common 10-vs-10 case (C(20, 10) = 184 756) with room to spare.
EXACT_MAX_SPLITS = 2000000


def _average_ranks(values):
    """Return 1-based ranks aligned with ``values``, averaging ties."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    n = len(values)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        # Positions i..j (inclusive) are tied; share the average rank.
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def _tie_correction(values):
    """Sum of ``t**3 - t`` over tie groups of size ``t``."""
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return sum(t * t * t - t for t in counts.values() if t > 1)


def _has_ties(values):
    return len(set(values)) != len(values)


def _u_counts_no_ties(n1, n2):
    """``counts[u]`` — number of splits with statistic ``u``, no ties.

    Without ties the pooled ranks are exactly ``1..n1+n2``, so the null
    distribution of U depends on the sizes alone: the number of ways to
    choose ``n1`` distinct ranks with a given rank sum, shifted by the
    constant ``n1 (n1 + 1) / 2``. Counted by dynamic programming over the
    rank values, which is exact in integer arithmetic.
    """
    n = n1 + n2
    smax = sum(range(n - n1 + 1, n + 1))
    table = [[0] * (smax + 1) for _ in range(n1 + 1)]
    table[0][0] = 1
    for v in range(1, n + 1):
        for k in range(min(n1, v), 0, -1):
            row_k = table[k]
            row_prev = table[k - 1]
            for s in range(smax, v - 1, -1):
                if row_prev[s - v]:
                    row_k[s] += row_prev[s - v]
    offset = n1 * (n1 + 1) // 2
    return [table[n1][s] for s in range(offset, smax + 1)]


def _exact_p_no_ties(n1, n2, u):
    counts = _u_counts_no_ties(n1, n2)
    total = sum(counts)
    idx = int(round(u))
    lo = sum(counts[: idx + 1])
    hi = sum(counts[idx:])
    return min(1.0, 2.0 * min(lo, hi) / total)


def _exact_p_with_ties(ranks, n1, u_obs):
    """Exact two-sided p by walking every split of the pooled ranks.

    With ties the null distribution depends on the data, not only on the
    sizes: the pooled mid-ranks are fixed, and each split just chooses
    which ``n1`` of them fall in the first sample. Walking all
    ``C(n1+n2, n1)`` splits is therefore exact.
    """
    n = len(ranks)
    offset = n1 * (n1 + 1) / 2.0
    le = 0
    ge = 0
    total = 0
    eps = 1e-9
    for pick in combinations(range(n), n1):
        u = math.fsum(ranks[i] for i in pick) - offset
        total += 1
        if u <= u_obs + eps:
            le += 1
        if u >= u_obs - eps:
            ge += 1
    return min(1.0, 2.0 * min(le, ge) / total)


def _asymptotic_p(combined, n1, n2, u1):
    n = n1 + n2
    mu = n1 * n2 / 2.0
    tie = _tie_correction(combined)
    var = (n1 * n2 / 12.0) * ((n + 1) - tie / (n * (n - 1)))
    sigma = math.sqrt(var) if var > 0.0 else 0.0
    if sigma == 0.0:
        # Zero variance (e.g. every observation tied): no evidence either way.
        return 1.0
    numerator = u1 - mu
    # Continuity correction: shrink |numerator| by 0.5 toward the mean.
    if numerator > 0.0:
        numerator -= 0.5
    elif numerator < 0.0:
        numerator += 0.5
    z = numerator / sigma
    # Two-sided p = 2 * sf(|z|) = erfc(|z| / sqrt(2)); clip to [0, 1].
    p = math.erfc(abs(z) / math.sqrt(2.0))
    return min(1.0, max(0.0, p))


def exact_applies(a, b):
    """Whether ``method="auto"`` will take the exact branch for these samples."""
    n1 = len(a)
    n2 = len(b)
    if n1 == 0 or n2 == 0 or n1 >= EXACT_MAX_N or n2 >= EXACT_MAX_N:
        return False
    if not _has_ties(list(a) + list(b)):
        return True
    return math.comb(n1 + n2, n1) <= EXACT_MAX_SPLITS


def mannwhitneyu(a, b, method="auto"):
    """Two-sided Mann-Whitney U test.

    Returns ``(u, p)`` where ``u`` is the statistic for the first sample
    ``a`` (scipy's convention) and ``p`` is the two-sided p-value.

    ``method``:
      * ``"auto"`` (default) — exact when both samples are smaller than
        ``EXACT_MAX_N`` and the tie-aware enumeration is within
        ``EXACT_MAX_SPLITS``; the normal approximation otherwise;
      * ``"exact"`` — force the exact distribution, ``ValueError`` when it
        is out of reach;
      * ``"asymptotic"`` — the normal approximation with tie and
        continuity corrections (the module's behaviour before 2026-09-16).

    Raises ``ValueError`` on an empty sample or an unknown ``method``.
    """
    if method not in ("auto", "exact", "asymptotic"):
        raise ValueError(f"unknown method: {method!r}")
    n1 = len(a)
    n2 = len(b)
    if n1 == 0 or n2 == 0:
        raise ValueError("mannwhitneyu requires non-empty samples")

    combined = list(a) + list(b)
    ranks = _average_ranks(combined)
    # Plain sum, not math.fsum: the published asymptotic p-values were
    # produced by this expression, and a different summation order would
    # move the last bits of u1 and with them the reproduced numbers.
    r1 = sum(ranks[:n1])
    u1 = r1 - n1 * (n1 + 1) / 2.0

    if method == "asymptotic":
        return (u1, _asymptotic_p(combined, n1, n2, u1))

    ties = _has_ties(combined)
    if method == "exact" or exact_applies(a, b):
        if not ties:
            return (u1, _exact_p_no_ties(n1, n2, u1))
        if math.comb(n1 + n2, n1) <= EXACT_MAX_SPLITS:
            return (u1, _exact_p_with_ties(ranks, n1, u1))
        if method == "exact":
            raise ValueError(
                "exact test with ties needs "
                f"{math.comb(n1 + n2, n1)} splits, over the "
                f"EXACT_MAX_SPLITS={EXACT_MAX_SPLITS} cap"
            )
    return (u1, _asymptotic_p(combined, n1, n2, u1))


def holm_bonferroni(pvalues):
    """Holm-Bonferroni step-down adjusted p-values, in input order.

    Adjusted p-values are monotone non-decreasing in rank and clipped to
    ``[0, 1]``. A family member is significant at level ``alpha`` iff its
    adjusted p-value ``<= alpha``. Empty input returns an empty list.
    """
    m = len(pvalues)
    if m == 0:
        return []
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, idx in enumerate(order):
        raw = (m - rank) * pvalues[idx]
        running = max(running, raw)
        adjusted[idx] = min(1.0, running)
    return adjusted
