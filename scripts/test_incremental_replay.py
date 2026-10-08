"""Self-tests for incremental coverage replay (ADR 0045 Step 5).

Run (not a CI gate; host-only research tooling):

    python3 scripts/test_incremental_replay.py

The pure tests (log_spaced_grid, file_hash) always run. The equivalence
micro-confirm — the Step 5 STOP gate — replays through the libpng measurement
binary (benchmarks/magma/build_cov.sh → vendor/out-cov/libpng_read_fuzzer) and
asserts incremental cumulative-merge replay yields a byte-identical llvm-cov
export to a full re-replay. It self-skips when the binary or LLVM 20 tools are
absent.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coverage_replay as cr  # noqa: E402
import incremental_replay as ir  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COV_BIN = os.path.join(_REPO, "benchmarks", "magma", "vendor", "out-cov",
                        "libpng_read_fuzzer")
_SEEDS = os.path.join(_REPO, "benchmarks", "magma", "vendor", "magma-src",
                      "targets", "libpng", "corpus", "libpng_read_fuzzer")

_TOOLS = cr.resolve_llvm_tool("llvm-profdata") and cr.resolve_llvm_tool("llvm-cov")
_READY = os.path.isfile(_COV_BIN) and os.path.isdir(_SEEDS) and bool(_TOOLS)
_SKIP = "needs vendor/out-cov/libpng_read_fuzzer (build_cov.sh) + llvm-cov-20 (host-only)"


class LogSpacedGridTest(unittest.TestCase):
    """Pure — no binary, always runs."""

    def test_endpoints_and_monotonic(self):
        grid = ir.log_spaced_grid(120, 8, first=1.0)
        self.assertEqual(grid[0], 1.0)
        self.assertEqual(grid[-1], 120.0)
        self.assertTrue(all(b > a for a, b in zip(grid, grid[1:])))
        self.assertLessEqual(len(grid), 8)

    def test_dense_early_sparse_late(self):
        grid = ir.log_spaced_grid(1000, 10, first=1.0)
        gaps = [b - a for a, b in zip(grid, grid[1:])]
        # Log spacing → gaps grow monotonically.
        self.assertTrue(all(b >= a for a, b in zip(gaps, gaps[1:])))
        self.assertLess(gaps[0], gaps[-1])

    def test_degenerate(self):
        self.assertEqual(ir.log_spaced_grid(30, 1), [30.0])
        self.assertEqual(ir.log_spaced_grid(5, 8, first=10.0), [5.0])


@unittest.skipUnless(_READY, _SKIP)
class FileHashTest(unittest.TestCase):
    def test_same_content_same_hash(self):
        seeds = cr.list_corpus_inputs(_SEEDS)
        self.assertEqual(ir.file_hash(seeds[0]), ir.file_hash(seeds[0]))
        self.assertNotEqual(ir.file_hash(seeds[0]), ir.file_hash(seeds[1]))


@unittest.skipUnless(_READY, _SKIP)
class IncrementalEquivalenceTest(unittest.TestCase):
    """Step 5 STOP gate: incremental == full re-replay (libpng frame)."""

    def setUp(self):
        self.inputs = cr.list_corpus_inputs(_SEEDS)
        self.assertGreaterEqual(len(self.inputs), 3, "need a few seeds")

    def _export_json(self, cov_bin, profdata):
        out = subprocess.run(
            [cr.resolve_llvm_tool("llvm-cov"), "export", cov_bin,
             f"-instr-profile={profdata}"],
            check=True, capture_output=True, text=True,
        )
        return out.stdout

    def test_summary_matches_full_replay(self):
        full = cr.replay_regions(_COV_BIN, self.inputs, target_args=())
        # Cumulative snapshots: first half, then all.
        half = max(1, len(self.inputs) // 2)
        snaps = [self.inputs[:half], self.inputs]
        incr = ir.replay_incremental(_COV_BIN, snaps, target_args=())
        self.assertEqual(incr[-1], full)
        # Coverage is monotone across snapshots.
        self.assertLessEqual(incr[0][0], incr[-1][0])
        self.assertEqual(incr[0][1], incr[-1][1])

    def test_full_export_json_identical(self):
        # all-at-once (single chunk) == full re-replay merge.
        with tempfile.TemporaryDirectory() as tmp:
            p_full = os.path.join(tmp, "full.profdata")
            p_incr = os.path.join(tmp, "incr.profdata")
            ir.replay_incremental(_COV_BIN, [self.inputs], target_args=(),
                                  profdata_out=p_full)
            third = max(1, len(self.inputs) // 3)
            snaps = [self.inputs[:third], self.inputs[:2 * third], self.inputs]
            ir.replay_incremental(_COV_BIN, snaps, target_args=(),
                                  profdata_out=p_incr)
            j_full = json.loads(self._export_json(_COV_BIN, p_full))
            j_incr = json.loads(self._export_json(_COV_BIN, p_incr))
            self.assertEqual(j_full, j_incr,
                             "incremental cumulative merge diverged from full re-replay")


class MemoryCapTest(unittest.TestCase):
    """The replay RLIMIT_AS cap (ADR 0046) — the main fix for the N=10 OOM,
    where a crafted libtiff input ballooned to 21.8 GB during replay."""

    def test_preexec_none_is_disabled(self):
        self.assertIsNone(ir.rlimit_as_preexec(None))

    def test_cap_kills_oversized_alloc_but_not_a_small_one(self):
        # A 2 GB allocation: succeeds with no cap, is killed under a 1 GB cap —
        # exactly how a crafted balloon input dies inside one replay exec.
        alloc = "b = bytearray(2 * 1024 * 1024 * 1024); print('alloc-ok')"
        ok = subprocess.run([sys.executable, "-c", alloc], capture_output=True,
                            text=True, preexec_fn=ir.rlimit_as_preexec(None))
        self.assertEqual(ok.returncode, 0)
        self.assertIn("alloc-ok", ok.stdout)
        capped = subprocess.run([sys.executable, "-c", alloc], capture_output=True,
                                text=True,
                                preexec_fn=ir.rlimit_as_preexec(1 * 1024 * 1024 * 1024))
        self.assertNotEqual(capped.returncode, 0)
        self.assertNotIn("alloc-ok", capped.stdout)

    @unittest.skipUnless(_READY, _SKIP)
    def test_cap_does_not_change_legit_replay(self):
        # Backward-compat: on legitimate inputs (no balloon), a 4 GB cap yields
        # byte-identical region coverage to the uncapped replay — the cap only
        # kills OOM inputs, never changes results.
        seeds = [os.path.join(_SEEDS, f) for f in sorted(os.listdir(_SEEDS))
                 if os.path.isfile(os.path.join(_SEEDS, f))]
        no_cap = ir.replay_incremental(_COV_BIN, [seeds], target_args=(),
                                       mem_limit_bytes=None)
        capped = ir.replay_incremental(_COV_BIN, [seeds], target_args=(),
                                       mem_limit_bytes=4 * 1024 * 1024 * 1024)
        self.assertEqual(no_cap, capped)


if __name__ == "__main__":
    unittest.main(verbosity=2)
