"""Self-tests for the comparative benchmark pure logic (ADR 0044 Step 4).

Run (not a CI gate; host-only research tooling):

    python3 scripts/test_comparative_benchmark.py

Exercises step-resampling, cross-run aggregation, and SVG rendering on
fabricated coverage(time) curves — no fuzzing, no binaries. The orchestration
(run_with_snapshots / main) is exercised by the live comparative smoke, not
here.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comparative_benchmark as cb  # noqa: E402


class ResampleCurveTest(unittest.TestCase):
    def test_step_holds_last_value(self):
        snaps = [(5.0, 10), (10.0, 25), (15.0, 30)]
        grid = [5, 10, 15]
        self.assertEqual(cb.resample_curve(snaps, grid), [10, 25, 30])

    def test_zero_before_first_snapshot(self):
        snaps = [(7.0, 12)]
        self.assertEqual(cb.resample_curve(snaps, [5, 10]), [0, 12])

    def test_grid_between_snapshots_holds_earlier(self):
        snaps = [(5.0, 10), (12.0, 20)]
        # at t=10 the latest snap <=10 is the t=5 one → 10; at t=15 → 20.
        self.assertEqual(cb.resample_curve(snaps, [10, 15]), [10, 20])

    def test_unsorted_snaps_handled(self):
        snaps = [(15.0, 30), (5.0, 10), (10.0, 25)]
        self.assertEqual(cb.resample_curve(snaps, [5, 10, 15]), [10, 25, 30])


class AggregateTest(unittest.TestCase):
    def test_median_and_minmax_band(self):
        curves = [[10, 20, 30], [12, 18, 36], [11, 22, 33]]
        median, lo, hi = cb.aggregate(curves)
        self.assertEqual(median, [11, 20, 33])
        self.assertEqual(lo, [10, 18, 30])
        self.assertEqual(hi, [12, 22, 36])

    def test_single_run_band_is_the_run(self):
        median, lo, hi = cb.aggregate([[5, 9, 9]])
        self.assertEqual(median, [5, 9, 9])
        self.assertEqual(lo, [5, 9, 9])
        self.assertEqual(hi, [5, 9, 9])


class RenderSvgTest(unittest.TestCase):
    def setUp(self):
        self.grid = [5, 10, 15]
        self.series = {
            "mlfuzzz3": {"median": [10, 20, 30], "lo": [9, 18, 28], "hi": [11, 22, 32]},
            "AFL++": {"median": [12, 19, 29], "lo": [11, 17, 27], "hi": [13, 21, 31]},
        }

    def test_is_wellformed_svg(self):
        svg = cb.render_svg(self.grid, self.series, title="t")
        self.assertTrue(svg.lstrip().startswith("<svg"))
        self.assertIn("</svg>", svg)

    def test_one_median_line_and_band_per_fuzzer(self):
        svg = cb.render_svg(self.grid, self.series, title="t")
        self.assertEqual(svg.count("<polyline"), 2)  # one median line each
        self.assertEqual(svg.count("<polygon"), 2)   # one min/max band each

    def test_legend_lists_both_fuzzers(self):
        svg = cb.render_svg(self.grid, self.series, title="t")
        self.assertIn("mlfuzzz3", svg)
        self.assertIn("AFL++", svg)

    def test_title_is_escaped(self):
        svg = cb.render_svg(self.grid, self.series, title="a < b & c")
        self.assertIn("a &lt; b &amp; c", svg)


class RenderSvgAxisTest(unittest.TestCase):
    """Log-X and integer-Y-tick opt-ins (ADR-0045 comparative figures)."""

    def setUp(self):
        self.grid = [1, 10, 100, 1000, 10000]
        self.series = {
            "a": {"median": [0, 1, 2, 2, 3], "lo": [0, 0, 1, 2, 2],
                  "hi": [0, 1, 2, 3, 3]},
        }

    def test_default_axes_unchanged(self):
        # No opt-in -> original linear-X, 0/mid/max scheme preserved for the
        # other callers (ADR-0044 figure, unit tests).
        svg = cb.render_svg(self.grid, self.series, title="t")
        self.assertIn(">0s</text>", svg)        # linear x tick at 0
        self.assertIn(">10000s</text>", svg)    # linear x tick at max

    def test_log_x_spreads_points_across_axis(self):
        svg = cb.render_svg(self.grid, self.series, title="t", log_x=True)
        m = re.search(r'<polyline points="([^"]+)"', svg)
        self.assertIsNotNone(m)
        xs = [float(p.split(",")[0]) for p in m.group(1).split()]
        # grid min (1s) at the left plot edge; grid max (10000s) near the right.
        # Linear would bunch every point but the last into the first few px.
        self.assertAlmostEqual(xs[0], 60, delta=1)      # margin_l
        self.assertGreater(xs[-1], 500)                 # near margin_l+plot_w
        gaps = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
        self.assertGreater(min(gaps), 0.5 * max(gaps))  # evenly log-spaced

    def test_log_x_ticks_on_powers_of_ten(self):
        svg = cb.render_svg(self.grid, self.series, title="t", log_x=True)
        for lbl in ("1s", "10s", "100s", "1000s", "10000s"):
            self.assertIn(f">{lbl}</text>", svg)
        self.assertNotIn(">0s</text>", svg)  # no t=0 on a log axis

    def test_integer_y_ticks_label_equals_position(self):
        svg = cb.render_svg(self.grid, self.series, title="t", y_integer_ticks=True)
        ticks = re.findall(
            r'<text x="\d+" y="([\d.]+)" text-anchor="end">(\d+)</text>', svg)
        labels = sorted(int(v) for _, v in ticks)
        self.assertEqual(labels, [0, 1, 2, 3])  # hi max is 3 -> integer 0..3
        # Each label sits at its own value's pixel: larger value -> smaller y.
        by_value = sorted(((int(v), float(y)) for y, v in ticks))
        ys = [y for _, y in by_value]
        self.assertEqual(ys, sorted(ys, reverse=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
