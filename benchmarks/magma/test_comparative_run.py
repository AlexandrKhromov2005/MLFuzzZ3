"""Self-tests for the Magma comparative orchestrator pure logic
(ADR 0045 Развилка G).

Run (not a CI gate; host-only research tooling):

    python3 benchmarks/magma/test_comparative_run.py

Exercises the orchestrator's pure helpers — oracle-dump parsing, resume
work-list, core assignment, axis aggregation, pairwise stats, the hardlink
snapshot pool, and checkpoint discovery — on fabricated data, no fuzzing and no
target binaries. The live orchestration (run_trial / replay) is exercised by
the pre-flight (smoke_comparative_run.sh).
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comparative_run as crun  # noqa: E402


class ParseOracleDumpTest(unittest.TestCase):
    def test_reached_and_triggered_sets(self):
        text = "PNG001 4 0\nPNG006 14 2\nPNG003 0 0\n"
        reached, triggered = crun.parse_oracle_dump(text)
        self.assertEqual(reached, {"PNG001", "PNG006"})
        self.assertEqual(triggered, {"PNG006"})

    def test_ignores_malformed_lines(self):
        text = "PNG001 4 0\ngarbage line\n\nPNG002 x y\nPNG003 1 1\n"
        reached, triggered = crun.parse_oracle_dump(text)
        self.assertEqual(reached, {"PNG001", "PNG003"})
        self.assertEqual(triggered, {"PNG003"})

    def test_empty(self):
        self.assertEqual(crun.parse_oracle_dump(""), (set(), set()))


class PendingTrialsTest(unittest.TestCase):
    def test_skips_done(self):
        self.assertEqual(crun.pending_trials(5, {0, 2}), [1, 3, 4])

    def test_all_done(self):
        self.assertEqual(crun.pending_trials(3, {0, 1, 2}), [])

    def test_none_done(self):
        self.assertEqual(crun.pending_trials(3, set()), [0, 1, 2])


class CoreAssignmentTest(unittest.TestCase):
    def test_distinct_blocks_no_overlap(self):
        cores = [0, 1, 2, 3, 4, 5]
        a = crun.assign_cores(0, 3, cores)
        b = crun.assign_cores(1, 3, cores)
        self.assertEqual(a, [0, 1, 2])
        self.assertEqual(b, [3, 4, 5])
        self.assertEqual(set(a) & set(b), set())  # no shared core

    def test_pool_too_small_raises(self):
        with self.assertRaises(ValueError):
            crun.assign_cores(1, 3, [0, 1, 2])

    def test_campaign_cores_reserves_os(self):
        # 8 cpus, jobs=1, 3 fuzzers, reserve 2 -> first 3 cpus.
        self.assertEqual(crun.campaign_cores(8, 1, 3, 2), [0, 1, 2])
        # jobs=2 -> 6 cpus, still fits under 8-2=6.
        self.assertEqual(crun.campaign_cores(8, 2, 3, 2), [0, 1, 2, 3, 4, 5])

    def test_campaign_cores_overcommit_raises(self):
        with self.assertRaises(ValueError):
            crun.campaign_cores(8, 3, 3, 2)  # needs 9 > 6 usable


class BuildAxisSeriesTest(unittest.TestCase):
    def test_median_and_band_on_grid(self):
        grid = [5, 10, 15]
        curves = [
            [(5.0, 10), (10.0, 20), (15.0, 30)],
            [(5.0, 12), (10.0, 18), (15.0, 36)],
            [(5.0, 11), (10.0, 22), (15.0, 33)],
        ]
        series = crun.build_axis_series(curves, grid)
        self.assertEqual(series["median"], [11, 20, 33])
        self.assertEqual(series["lo"], [10, 18, 30])
        self.assertEqual(series["hi"], [12, 22, 36])

    def test_step_resample_before_first_snapshot_is_zero(self):
        grid = [1, 10]
        series = crun.build_axis_series([[(5.0, 7)]], grid)
        self.assertEqual(series["median"], [0, 7])


class PairwiseStatsTest(unittest.TestCase):
    def test_returns_three_pairs_in_order(self):
        finals = {"mlfuzzz3": [30, 31, 29, 32, 30],
                  "afl": [20, 21, 19, 22, 20],
                  "libfuzzer": [25, 24, 26, 25, 25]}
        rows = crun.pairwise_stats(finals)
        self.assertEqual(len(rows), 3)
        self.assertEqual([(a, b) for a, b, *_ in rows],
                         [("mlfuzzz3", "afl"), ("mlfuzzz3", "libfuzzer"),
                          ("afl", "libfuzzer")])
        # Holm-adjusted p-values are clipped to [0, 1].
        for *_, adj in rows:
            self.assertGreaterEqual(adj, 0.0)
            self.assertLessEqual(adj, 1.0)

    def test_identical_groups_do_not_crash(self):
        finals = {"mlfuzzz3": [0, 0], "afl": [0, 0], "libfuzzer": [0, 0]}
        rows = crun.pairwise_stats(finals)
        self.assertEqual(len(rows), 3)
        for _a, _b, _u, p, _adj in rows:
            self.assertEqual(p, 1.0)  # zero variance -> no evidence


class HardlinkPoolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mlf_pool_")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk(self, name, content=b"data"):
        path = os.path.join(self.src, name)
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_grows_and_dedups_by_source(self):
        pool = crun.HardlinkPool(os.path.join(self.tmp, "pool"))
        a, b = self._mk("a"), self._mk("b")
        self.assertEqual(pool.add_harvest([a, b]), 2)
        # Re-harvesting the same sources adds nothing (same realpath).
        self.assertEqual(pool.add_harvest([a, b]), 2)
        c = self._mk("c")
        self.assertEqual(pool.add_harvest([a, b, c]), 3)

    def test_prefix_is_cumulative_snapshot(self):
        pool = crun.HardlinkPool(os.path.join(self.tmp, "pool"))
        a, b, c = self._mk("a"), self._mk("b"), self._mk("c")
        pool.add_harvest([a])
        cut1 = pool.size
        pool.add_harvest([a, b, c])
        cut2 = pool.size
        self.assertEqual(len(pool.prefix(cut1)), 1)
        self.assertEqual(len(pool.prefix(cut2)), 3)
        # Pool entries are hardlinks: same content as the source.
        with open(pool.prefix(cut2)[0], "rb") as fh:
            self.assertEqual(fh.read(), b"data")

    def test_hardlink_survives_source_deletion(self):
        pool = crun.HardlinkPool(os.path.join(self.tmp, "pool"))
        a = self._mk("a", b"persist")
        pool.add_harvest([a])
        os.unlink(a)  # fuzzer rotated/removed the original
        with open(pool.prefix(1)[0], "rb") as fh:
            self.assertEqual(fh.read(), b"persist")


class CheckpointTest(unittest.TestCase):
    def test_load_only_in_range_indices(self):
        tmp = tempfile.mkdtemp(prefix="mlf_ckpt_")
        try:
            ckpt = os.path.join(tmp, "checkpoints")
            os.makedirs(ckpt)
            for idx in (0, 2, 7):  # 7 is out of a 5-trial range
                with open(os.path.join(ckpt, f"trial_{idx:03d}.json"), "w") as fh:
                    json.dump({"trial": idx, "fuzzers": {}}, fh)
            done = crun.load_checkpoints(tmp, 5)
            self.assertEqual(set(done), {0, 2})
            self.assertEqual(crun.pending_trials(5, done.keys()), [1, 3, 4])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_missing_checkpoint_dir(self):
        tmp = tempfile.mkdtemp(prefix="mlf_ckpt2_")
        try:
            self.assertEqual(crun.load_checkpoints(tmp, 5), {})
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
