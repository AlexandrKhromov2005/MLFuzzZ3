"""Self-tests for the neutral coverage-replay module (ADR 0044 Step 2).

Run (not a CI gate; host-only research tooling):

    python3 scripts/test_coverage_replay.py

The pure parsing tests always run. The replay tests need the host coverage
binary (benchmarks/lava-m/build_cov.sh → vendor/base64-cov) and the LLVM 20
coverage tools; they self-skip when either is absent (mirroring how the cov
fixtures self-skip without clang).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coverage_replay as cr  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COV_BIN = os.path.join(_REPO, "benchmarks", "lava-m", "vendor", "base64-cov")
_SEEDS = os.path.join(_REPO, "benchmarks", "lava-m", "seeds")

_TOOLS = cr.resolve_llvm_tool("llvm-profdata") and cr.resolve_llvm_tool("llvm-cov")
_REPLAY_READY = os.path.isfile(_COV_BIN) and bool(_TOOLS)
_SKIP_REASON = "needs vendor/base64-cov (build_cov.sh) + llvm-cov-20 (host-only)"


class ParseRegionSummaryTest(unittest.TestCase):
    """Pure JSON parsing — no binary, always runs."""

    def _doc(self, covered, count):
        return {
            "version": "2.0.1",
            "type": "llvm.coverage.json.export",
            "data": [{"totals": {"regions": {
                "count": count, "covered": covered,
                "notcovered": count - covered,
                "percent": 100.0 * covered / count if count else 0.0,
            }}}],
        }

    def test_parses_covered_and_total(self):
        covered, total = cr.parse_region_summary(self._doc(187, 1801))
        self.assertEqual((covered, total), (187, 1801))

    def test_accepts_json_string(self):
        import json
        covered, total = cr.parse_region_summary(json.dumps(self._doc(5, 10)))
        self.assertEqual((covered, total), (5, 10))

    def test_zero_covered(self):
        self.assertEqual(cr.parse_region_summary(self._doc(0, 1801)), (0, 1801))


@unittest.skipUnless(_REPLAY_READY, _SKIP_REASON)
class ReplayRegionsTest(unittest.TestCase):
    """Integration — replays real seeds through the coverage binary."""

    def _seed(self, name):
        return os.path.join(_SEEDS, name)

    def test_single_seed_covers_nonzero_regions(self):
        covered, total = cr.replay_regions(_COV_BIN, [self._seed("hello.b64")])
        self.assertGreater(total, 0)
        self.assertGreater(covered, 0)
        self.assertLessEqual(covered, total)

    def test_deterministic_across_runs(self):
        inputs = [self._seed("hello.b64"), self._seed("abc.b64")]
        first = cr.replay_regions(_COV_BIN, inputs)
        second = cr.replay_regions(_COV_BIN, inputs)
        self.assertEqual(first, second)

    def test_more_inputs_never_reduce_coverage(self):
        one = cr.replay_regions(_COV_BIN, [self._seed("hello.b64")])
        three = cr.replay_regions(
            _COV_BIN,
            [self._seed("hello.b64"), self._seed("abc.b64"), self._seed("nums.b64")],
        )
        # Same total region count (same binary); covered is monotone in corpus.
        self.assertEqual(one[1], three[1])
        self.assertGreaterEqual(three[0], one[0])

    def test_empty_input_set_is_zero(self):
        self.assertEqual(cr.replay_regions(_COV_BIN, []), (0, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
