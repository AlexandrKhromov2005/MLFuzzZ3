"""Self-tests for the smoke benchmark report logic (ADR 0040/0041).

Run (research tooling, not a CI gate):

    python3 scripts/test_smoke_benchmark.py

Exercises the coverage-curve report rendering on a fabricated metrics.jsonl —
no real fuzzing. The curve construction itself is shared with the full preset
and tested in test_benchmark.py (CoverageCurveTest).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import benchmark as bench  # noqa: E402
import smoke_benchmark as smoke  # noqa: E402


FAKE_METRICS = [
    '{"run_id":"ts-sha-cfg","execs":50,"crashes":0,"edges":185,"corpus_size":4,'
    '"execs_per_sec":600.0,"concolic_calls":0,"elapsed":0.09}',
    '{"run_id":"ts-sha-cfg","execs":100,"crashes":0,"edges":202,"corpus_size":7,'
    '"execs_per_sec":610.0,"concolic_calls":0,"elapsed":0.17}',
    '{"run_id":"ts-sha-cfg","execs":150,"crashes":0,"edges":221,"corpus_size":9,'
    '"execs_per_sec":605.0,"concolic_calls":7,"concolic_unsat":2,'
    '"concolic_no_candidate":5,"concolic_time_ms_total":40,"elapsed":0.25}',
]


class RenderTest(unittest.TestCase):
    def _render(self):
        snaps = bench.parse_metrics_lines(FAKE_METRICS)
        curve = bench.coverage_curve(snaps)
        meta = {
            "target": "/tmp/base64", "target_args": "-d", "mutator": "havoc",
            "max_det_steps": 65536, "max_seconds": 30.0, "interval": 50, "seed": 1234,
            "rc": 0, "provenance": "GNU coreutils 8.24",
            "provenance_date": "2026-06-10", "provenance_note": "GNU hash verified",
        }
        return smoke.render_report(meta, snaps, curve)

    def test_report_has_provenance_block(self):
        report = self._render()
        self.assertIn("## Provenance", report)
        self.assertIn("GNU coreutils 8.24", report)
        self.assertIn("GNU hash verified", report)
        self.assertIn("2026-06-10", report)

    def test_report_has_curve_rows_in_order(self):
        report = self._render()
        self.assertIn("## Coverage curve", report)
        # Every snapshot becomes a table row; check the edge values appear.
        for edges in (185, 202, 221):
            self.assertIn(f"| {edges} |", report)
        # Final block reflects the last snapshot.
        self.assertIn("edges (cumulative frontier): 221", report)

    def test_target_args_recorded(self):
        self.assertIn("`-d`", self._render())

    def test_concolic_section(self):
        report = self._render()
        self.assertIn("## Concolic", report)
        self.assertIn("calls (stagnation-triggered solves): 7", report)
        self.assertIn("inverted systems UNSAT: 2", report)


if __name__ == "__main__":
    unittest.main()
