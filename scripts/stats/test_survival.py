"""Unit tests for the dependency-free log-rank / Kaplan-Meier module.

Run (not a CI gate; research tooling, ADR 0032 — like test_mannwhitney.py):

    python3 scripts/stats/test_survival.py

The reference p-values below were generated offline and cross-checked against
BOTH ``scipy.stats.logrank`` (scipy 1.18.0) and
``lifelines.statistics.logrank_test`` (lifelines 0.30.3) on the same inputs;
our hand-rolled value matched both to < 1e-6 (worst observed |Δ| ~ 3.6e-15).
Hardcoding them validates the in-repo implementation without a runtime scipy /
lifelines dependency. The cases deliberately cover the adversarial-review
checklist: ties-heavy (log-spaced grid), censoring-heavy, mixed, one-arm-all-
censored, an n==1 long tail (where the risk set collapses to a single subject),
strong separation, and the two undefined-comparison markers.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import survival  # noqa: E402


# Log-spaced snapshot grid (the real run's time axis) and the budget / censoring
# time, so the test data ties exactly the way live time-to-reach data does.
G = [1, 2.8, 7.9, 22, 62, 175, 493, 1385, 3892, 10939, 30743, 86400]
B = 86400

# (name, times_a, events_a, times_b, events_b, reference_p)
# reference_p: scipy 1.18.0 == lifelines 0.30.3 (agree to ~1e-15).
REFERENCE = [
    # ties-heavy: every time snapped to a grid point (many ties).
    ("ties_grid",
     [G[1], G[1], G[2], G[2], G[3], G[3], G[1], G[4], G[2], G[3]], [1] * 10,
     [G[3], G[4], G[4], G[5], G[5], G[3], G[6], G[4], G[5], G[6]], [1] * 10,
     0.000335367551784),
    # censoring-heavy: half never reach (censored at budget).
    ("cens_heavy",
     [G[2], G[3], G[4], B, B, B, G[3], B, G[5], B], [1, 1, 1, 0, 0, 0, 1, 0, 1, 0],
     [G[5], G[6], B, B, B, B, G[6], B, B, B], [1, 1, 0, 0, 0, 0, 1, 0, 0, 0],
     0.214519198499),
    # mixed ties + censoring.
    ("mixed",
     [G[2], G[2], G[4], G[4], B, G[3], B, G[2], G[5], B], [1, 1, 1, 1, 0, 1, 0, 1, 1, 0],
     [G[4], G[5], G[5], B, B, G[6], G[6], B, B, B], [1, 1, 1, 0, 0, 1, 1, 0, 0, 0],
     0.117386248499),
    # (г) one arm all censored, the other a mix of events + censoring.
    ("one_arm_all_censored",
     [B, B, B, B, B], [0, 0, 0, 0, 0],
     [G[2], G[3], G[4], B, G[5]], [1, 1, 1, 0, 1],
     0.013279076708),
    # (д) n==1 long tail: distinct single late events collapse the risk set to
    # one subject — exercises the `if n <= 1: continue` branch against reference.
    ("n1_tail",
     [G[1], G[2], G[3], G[8], G[9], G[10], G[11]], [1, 1, 1, 1, 1, 1, 1],
     [G[1], G[2], G[4], G[5], G[6], G[7], B], [1, 1, 1, 1, 1, 1, 0],
     0.816201541862),
    # (е) strong separation: A all reach immediately, B all censored. p -> ~0.
    ("strong_separation",
     [G[1]] * 10, [1] * 10,
     [B] * 10, [0] * 10,
     1.30718453668e-05),
]


class LogRankReferenceTest(unittest.TestCase):
    def test_matches_scipy_lifelines_reference(self):
        for name, ta, ea, tb, eb, ref_p in REFERENCE:
            with self.subTest(case=name):
                chi2, p, status = survival.logrank_test(ta, ea, tb, eb)
                self.assertEqual(status, "ok", name)
                self.assertFalse(chi2 != chi2, f"{name}: chi2 is NaN")  # not NaN
                self.assertAlmostEqual(p, ref_p, delta=1e-6,
                                       msg=f"{name}: p={p} ref={ref_p}")

    def test_strong_separation_p_near_zero_not_nan(self):
        # (е) huge chi2 must yield a tiny finite p, never NaN / exception.
        chi2, p, status = survival.logrank_test([G[1]] * 10, [1] * 10, [B] * 10, [0] * 10)
        self.assertEqual(status, "ok")
        self.assertTrue(0.0 <= p < 1e-4)
        self.assertFalse(p != p)

    def test_symmetry_two_sided(self):
        # Swapping the groups must not change the two-sided p.
        ta, ea = [G[1], G[2], G[2]], [1, 1, 1]
        tb, eb = [G[5], G[6], B], [1, 1, 0]
        _, p1, _ = survival.logrank_test(ta, ea, tb, eb)
        _, p2, _ = survival.logrank_test(tb, eb, ta, ea)
        self.assertAlmostEqual(p1, p2, delta=1e-12)


class EdgeMarkerTest(unittest.TestCase):
    def test_all_censored_is_no_events(self):
        # (ж) no bug reached in either group -> 'no_events', p=1.0, no crash.
        chi2, p, status = survival.logrank_test([B] * 5, [0] * 5, [B] * 5, [0] * 5)
        self.assertEqual(status, "no_events")
        self.assertEqual(p, 1.0)
        self.assertTrue(chi2 != chi2)  # NaN

    def test_all_tied_one_time_both_groups_is_no_separation(self):
        # (б) every subject events at one identical time (d == n) -> var 0.
        chi2, p, status = survival.logrank_test([G[3]] * 5, [1] * 5, [G[3]] * 5, [1] * 5)
        self.assertEqual(status, "no_separation")
        self.assertEqual(p, 1.0)

    def test_empty_group_is_no_separation(self):
        # (в) one arm has no observations -> no group-A risk -> var 0, no crash.
        chi2, p, status = survival.logrank_test([], [], [G[2], G[3], G[4]], [1, 1, 1])
        self.assertEqual(status, "no_separation")
        self.assertEqual(p, 1.0)

    def test_mismatched_lengths_raise(self):
        with self.assertRaises(ValueError):
            survival.logrank_test([1, 2], [1], [3], [1])


class KaplanMeierTest(unittest.TestCase):
    def test_step_function_drops_at_events(self):
        # 2 events @ G[1], 1 @ G[3], 2 censored: S = 1 -> 3/5 -> 0.6*(2/3)=0.4.
        steps = survival.kaplan_meier([G[1], G[1], G[3], B, B], [1, 1, 1, 0, 0])
        self.assertEqual(steps[0], (0.0, 1.0))
        ts = [round(t, 4) for t, _ in steps]
        ss = [round(s, 6) for _, s in steps]
        self.assertEqual(ts, [0.0, G[1], G[3]])
        self.assertEqual(ss, [1.0, 0.6, 0.4])

    def test_all_censored_stays_at_one(self):
        steps = survival.kaplan_meier([B, B, B], [0, 0, 0])
        self.assertEqual(steps, [(0.0, 1.0)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
