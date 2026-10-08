"""Unit tests for the dependency-free Mann-Whitney U / Holm-Bonferroni module.

Run (not a CI gate; research tooling, ADR 0032):

    python3 scripts/stats/test_mannwhitney.py

The Mann-Whitney reference values below were generated offline from
scipy 1.17.1 via
``scipy.stats.mannwhitneyu(a, b, alternative='two-sided',
method='asymptotic', use_continuity=True)`` and are matched within a tight
tolerance (1e-9 on U, 1e-6 on p). This validates the in-repo asymptotic
approximation against a trusted implementation without taking a runtime
dependency on scipy.

Since 2026-09-16 the module's default is the exact null distribution of U
(``ExactDistributionTest`` below), so the scipy references are checked
with ``method="asymptotic"`` — they describe the approximation, which is
unchanged. scipy is not available here at all (ADR 0032), so the exact
branch is validated differently: against the closed-form known answer
2 / C(20, 10) at U = 0, and by computing the same distribution two ways —
dynamic programming over ranks against brute-force enumeration of all
C(n1+n2, n1) splits.
"""

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mannwhitney as mw  # noqa: E402


# (a, b, scipy_U, scipy_p) — scipy 1.17.1 asymptotic, two-sided, continuity.
REFERENCE = [
    ([1, 2, 3, 4], [5, 6, 7, 8], 0.0, 0.0303828219766),
    ([1, 2, 3, 4, 5], [3, 4, 5, 6, 7], 4.5, 0.113846298007),
    ([10, 20, 30], [15, 25, 35], 3.0, 0.66252058354),
    ([1, 1, 1, 2], [1, 2, 2, 2], 4.0, 0.247061525092),
    ([5, 6, 7, 8, 9, 10], [1, 2, 3, 4], 24.0, 0.0142140388691),
    ([2.5, 3.1, 4.0, 1.2, 5.5], [2.5, 3.1, 4.0, 1.2, 5.5], 12.5, 1.0),
    ([12, 15, 9, 11, 14, 13, 8], [22, 18, 25, 30, 16, 19], 0.0, 0.00340523582129),
]


class MannWhitneyTest(unittest.TestCase):
    def test_matches_scipy_asymptotic(self):
        # Explicit method="asymptotic": since 2026-09-16 the default is the
        # exact test for these sizes, and these references are scipy's
        # asymptotic numbers. The approximation itself is unchanged.
        for a, b, u_ref, p_ref in REFERENCE:
            u, p = mw.mannwhitneyu(a, b, method="asymptotic")
            self.assertAlmostEqual(u, u_ref, delta=1e-9, msg=f"U for {a} vs {b}")
            self.assertAlmostEqual(p, p_ref, delta=1e-6, msg=f"p for {a} vs {b}")

    def test_statistic_is_for_first_sample(self):
        # Swapping arguments complements U to n1*n2 but keeps the two-sided p.
        a, b = [1, 2, 3, 4], [5, 6, 7, 8]
        u_ab, p_ab = mw.mannwhitneyu(a, b)
        u_ba, p_ba = mw.mannwhitneyu(b, a)
        self.assertAlmostEqual(u_ab + u_ba, len(a) * len(b), delta=1e-9)
        self.assertAlmostEqual(p_ab, p_ba, delta=1e-12)

    def test_empty_sample_raises(self):
        with self.assertRaises(ValueError):
            mw.mannwhitneyu([], [1, 2, 3])

    def test_unknown_method_raises(self):
        with self.assertRaises(ValueError):
            mw.mannwhitneyu([1, 2], [3, 4], method="permutation")


class ExactDistributionTest(unittest.TestCase):
    """The exact branch (наряд «гигиена + ADR-0049» §0.4)."""

    def test_known_answer_u_zero_ten_by_ten(self):
        # Полное разделение при n = m = 10: единственная расстановка рангов,
        # дающая U = 0, и единственная зеркальная, дающая U = 100. Поэтому
        # двусторонний p в точности 2 / C(20, 10) = 1.0825e-05 — против
        # 1.8267e-04 у приближения, в 16.9 раза больше.
        a = list(range(10))
        b = list(range(100, 110))
        u, p = mw.mannwhitneyu(a, b)
        self.assertEqual(u, 0.0)
        self.assertEqual(p, 2.0 / math.comb(20, 10))
        _, p_asym = mw.mannwhitneyu(a, b, method="asymptotic")
        self.assertAlmostEqual(p_asym, 0.000182672, delta=1e-9)

    def test_small_example_is_two_over_seventy(self):
        u, p = mw.mannwhitneyu([1, 2, 3, 4], [5, 6, 7, 8])
        self.assertEqual(u, 0.0)
        self.assertEqual(p, 2.0 / math.comb(8, 4))

    def test_no_ties_dp_matches_enumeration(self):
        # Динамика по рангам против полного перебора C(n1+n2, n1) разбиений —
        # два независимых способа посчитать одно и то же распределение.
        for n1 in range(1, 6):
            for n2 in range(1, 6):
                ranks = [float(i + 1) for i in range(n1 + n2)]
                for u in range(0, n1 * n2 + 1):
                    dp = mw._exact_p_no_ties(n1, n2, u)
                    brute = mw._exact_p_with_ties(ranks, n1, u)
                    self.assertAlmostEqual(dp, brute, delta=1e-12, msg=f"{n1}x{n2} u={u}")

    def test_counts_sum_to_binomial(self):
        for n1 in range(1, 8):
            for n2 in range(1, 8):
                self.assertEqual(sum(mw._u_counts_no_ties(n1, n2)), math.comb(n1 + n2, n1))

    def test_ties_use_the_data_not_the_sizes(self):
        # Со связями распределение зависит от самих данных: две выборки с
        # одинаковыми n и одинаковым U дают разные p, если связки разные.
        a1, b1 = [1, 2, 3, 4], [4, 5, 6, 7]
        a2, b2 = [1, 2, 3, 4], [5, 6, 7, 8]
        u1, p1 = mw.mannwhitneyu(a1, b1)
        u2, p2 = mw.mannwhitneyu(a2, b2)
        self.assertNotEqual(p1, p2)
        self.assertLess(u2, u1)

    def test_identical_samples_give_p_one(self):
        a = [2.5, 3.1, 4.0, 1.2, 5.5]
        _, p = mw.mannwhitneyu(a, list(a))
        self.assertEqual(p, 1.0)

    def test_auto_falls_back_above_the_size_cap(self):
        a = list(range(mw.EXACT_MAX_N))
        b = list(range(100, 100 + mw.EXACT_MAX_N))
        self.assertFalse(mw.exact_applies(a, b))
        _, p_auto = mw.mannwhitneyu(a, b)
        _, p_asym = mw.mannwhitneyu(a, b, method="asymptotic")
        self.assertEqual(p_auto, p_asym)

    def test_exact_with_ties_over_the_split_cap_raises(self):
        # Со связями точная ветвь перебирает C(n1+n2, n1) разбиений; при
        # 15 на 15 это 155 117 520 — выше потолка, и method="exact" обязан
        # сказать об этом, а не молча посчитать приближением.
        a = [1] * 15
        b = [1] * 14 + [2]
        self.assertFalse(mw.exact_applies(a, b))
        with self.assertRaises(ValueError):
            mw.mannwhitneyu(a, b, method="exact")
        _, p_auto = mw.mannwhitneyu(a, b)
        _, p_asym = mw.mannwhitneyu(a, b, method="asymptotic")
        self.assertEqual(p_auto, p_asym)

    def test_exact_never_exceeds_one_and_is_symmetric(self):
        a = [3, 1, 4, 1, 5, 9, 2, 6]
        b = [2, 7, 1, 8, 2, 8, 1, 8]
        u_ab, p_ab = mw.mannwhitneyu(a, b)
        u_ba, p_ba = mw.mannwhitneyu(b, a)
        self.assertLessEqual(p_ab, 1.0)
        self.assertAlmostEqual(p_ab, p_ba, delta=1e-12)
        self.assertAlmostEqual(u_ab + u_ba, len(a) * len(b), delta=1e-9)


class HolmBonferroniTest(unittest.TestCase):
    def test_basic_stepdown_with_monotonicity(self):
        # sorted: 0.01, 0.03, 0.04 -> raw 0.03, 0.06, 0.04 -> monotone 0.03, 0.06, 0.06
        adj = mw.holm_bonferroni([0.01, 0.04, 0.03])
        self.assertAlmostEqual(adj[0], 0.03, delta=1e-12)
        self.assertAlmostEqual(adj[1], 0.06, delta=1e-12)
        self.assertAlmostEqual(adj[2], 0.06, delta=1e-12)

    def test_preserves_input_order(self):
        adj = mw.holm_bonferroni([0.04, 0.01, 0.03])
        self.assertAlmostEqual(adj[0], 0.06, delta=1e-12)
        self.assertAlmostEqual(adj[1], 0.03, delta=1e-12)
        self.assertAlmostEqual(adj[2], 0.06, delta=1e-12)

    def test_clips_to_one(self):
        for v in mw.holm_bonferroni([0.5, 0.5, 0.5]):
            self.assertEqual(v, 1.0)

    def test_single_and_empty(self):
        self.assertEqual(mw.holm_bonferroni([]), [])
        adj = mw.holm_bonferroni([0.02])
        self.assertAlmostEqual(adj[0], 0.02, delta=1e-12)


if __name__ == "__main__":
    unittest.main()
