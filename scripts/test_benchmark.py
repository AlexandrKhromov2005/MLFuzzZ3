"""Self-tests for the benchmark harness pure logic (ADR 0032).

Run (not a CI gate; research tooling):

    python3 scripts/test_benchmark.py

Exercises metrics parsing, censored time-to-crash derivation, crash-rate,
and the Mann-Whitney + Holm analysis table on fabricated metrics — no real
fuzzing.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import benchmark as bench  # noqa: E402


def snap(execs, crashes, edges, det=0, hav=0, run_id="ts-sha-cfg"):
    return {
        "run_id": run_id, "execs": execs, "execs_per_sec": 1.0, "corpus_size": 1,
        "edges": edges, "crashes": crashes, "det_execs": det, "havoc_execs": hav,
        "elapsed": 0.1,
    }


class SummarizeRunTest(unittest.TestCase):
    def test_first_crash_snapshot_sets_uncensored_ttc(self):
        snaps = [snap(100, 0, 5), snap(200, 3, 7), snap(300, 5, 9)]
        out = bench.summarize_run(snaps, budget=300)
        self.assertEqual(out["edges"], 9)  # edges-at-budget = last snapshot
        self.assertEqual(out["ttc"], 200)  # first snapshot with a crash
        self.assertFalse(out["censored"])
        self.assertTrue(out["crashed"])

    def test_no_crash_is_right_censored_at_budget(self):
        snaps = [snap(100, 0, 4), snap(200, 0, 6), snap(300, 0, 6)]
        out = bench.summarize_run(snaps, budget=300)
        self.assertEqual(out["edges"], 6)
        self.assertEqual(out["ttc"], 300)  # censored at the budget
        self.assertTrue(out["censored"])
        self.assertFalse(out["crashed"])

    def test_empty_metrics(self):
        out = bench.summarize_run([], budget=500)
        self.assertEqual(out["edges"], 0)
        self.assertEqual(out["ttc"], 500)
        self.assertTrue(out["censored"])

    def test_ttc_clamped_to_budget(self):
        # A snapshot can report execs slightly past the cap; clamp it.
        out = bench.summarize_run([snap(520, 1, 3)], budget=500)
        self.assertEqual(out["ttc"], 500)


class ParseTest(unittest.TestCase):
    def test_parse_metrics_lines_skips_blanks(self):
        lines = ['{"execs":1,"crashes":0,"edges":2}', "", "  ",
                 '{"execs":2,"crashes":1,"edges":3}']
        snaps = bench.parse_metrics_lines(lines)
        self.assertEqual(len(snaps), 2)
        self.assertEqual(snaps[1]["crashes"], 1)


class AnalyzeTest(unittest.TestCase):
    def _results(self):
        # reference clearly worse on edges than "strong", tied with "same".
        return {
            "byteflip-only": [{"edges": 5, "ttc": 300, "crashed": True} for _ in range(6)],
            "strong": [{"edges": 9, "ttc": 100, "crashed": True} for _ in range(6)],
            "same": [{"edges": 5, "ttc": 300, "crashed": True} for _ in range(6)],
        }

    def test_edges_direction_and_pvalues(self):
        rows = bench.analyze_metric(self._results(), "byteflip-only", "edges",
                                    higher_is_better=True)
        by = {r["config"]: r for r in rows}
        # "strong" has higher edges than the reference -> strong better.
        self.assertEqual(by["strong"]["direction"], "strong better")
        self.assertEqual(by["same"]["direction"], "tie")
        for r in rows:
            self.assertGreaterEqual(r["p"], 0.0)
            self.assertLessEqual(r["p_adj"], 1.0)
            self.assertGreaterEqual(r["p_adj"], r["p"] - 1e-12)  # adjusted >= raw

    def test_ttc_direction_lower_is_better(self):
        rows = bench.analyze_metric(self._results(), "byteflip-only", "ttc",
                                    higher_is_better=False)
        by = {r["config"]: r for r in rows}
        # "strong" crashes faster (lower ttc) -> strong better.
        self.assertEqual(by["strong"]["direction"], "strong better")

    def test_crash_rate(self):
        runs = [{"crashed": True}, {"crashed": False}, {"crashed": True}, {"crashed": True}]
        self.assertAlmostEqual(bench.crash_rate(runs), 0.75, delta=1e-12)
        self.assertEqual(bench.crash_rate([]), 0.0)


class CoverageCurveTest(unittest.TestCase):
    """The smoke preset's curve (ADR 0040/0041): every snapshot becomes one
    edges-vs-(execs, elapsed) point, in order."""

    def test_curve_from_fabricated_metrics(self):
        lines = [
            '{"execs":50,"crashes":0,"edges":185,"elapsed":0.09}',
            "",
            '{"execs":100,"crashes":0,"edges":202,"elapsed":0.17}',
            '{"execs":150,"crashes":0,"edges":221,"elapsed":0.25}',
        ]
        curve = bench.coverage_curve(bench.parse_metrics_lines(lines))
        self.assertEqual([p["execs"] for p in curve], [50, 100, 150])
        self.assertEqual([p["edges"] for p in curve], [185, 202, 221])
        self.assertAlmostEqual(curve[0]["elapsed"], 0.09, delta=1e-12)

    def test_empty(self):
        self.assertEqual(bench.coverage_curve([]), [])


if __name__ == "__main__":
    unittest.main()
