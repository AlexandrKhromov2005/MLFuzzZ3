"""Self-tests for the comparative-benchmark drivers (ADR 0044 Step 3).

Run (not a CI gate; host-only research tooling):

    python3 scripts/test_fuzzer_drivers.py

Harvest tests fabricate fuzzer output directories — no fuzzing — and assert
that only replayable inputs are picked up, never AFL metadata. Command-builder
tests check argv shape (stdin mode, wall-clock budget). The end-to-end AFL run
+ replay lives in Step 4's smoke, not here.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fuzzer_drivers as fd  # noqa: E402


def _touch(path, content=b"x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)


class HarvestAflTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mlf_afl_out_")
        inst = os.path.join(self.tmp, "default")
        # Real inputs.
        _touch(os.path.join(inst, "queue", "id:000000,orig:hello"))
        _touch(os.path.join(inst, "queue", "id:000001,src:000000,op:flip1"))
        _touch(os.path.join(inst, "crashes", "id:000000,sig:06"))
        # Metadata that MUST be excluded.
        _touch(os.path.join(inst, "fuzzer_stats"))
        _touch(os.path.join(inst, "fuzzer_setup"))
        _touch(os.path.join(inst, "plot_data"))
        _touch(os.path.join(inst, "cmdline"))
        _touch(os.path.join(inst, "crashes", "README.txt"))
        _touch(os.path.join(inst, "queue", ".state", "auto_extras", "x"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_harvest_picks_only_queue_and_crash_inputs(self):
        got = sorted(os.path.relpath(p, self.tmp) for p in fd.harvest_afl(self.tmp))
        self.assertEqual(got, [
            "default/crashes/id:000000,sig:06",
            "default/queue/id:000000,orig:hello",
            "default/queue/id:000001,src:000000,op:flip1",
        ])

    def test_harvest_excludes_metadata_and_readme_and_state(self):
        names = {os.path.basename(p) for p in fd.harvest_afl(self.tmp)}
        for bad in ("fuzzer_stats", "fuzzer_setup", "plot_data", "cmdline", "README.txt"):
            self.assertNotIn(bad, names)
        # .state is a dir; nothing under it should leak in (no recursion).
        self.assertFalse(any(".state" in p for p in fd.harvest_afl(self.tmp)))

    def test_empty_out_dir(self):
        empty = tempfile.mkdtemp(prefix="mlf_afl_empty_")
        try:
            self.assertEqual(fd.harvest_afl(empty), [])
        finally:
            os.rmdir(empty)


class HarvestOursTest(unittest.TestCase):
    def test_harvest_corpus_and_crashes(self):
        tmp = tempfile.mkdtemp(prefix="mlf_our_out_")
        try:
            _touch(os.path.join(tmp, "corpus", "0001"))
            _touch(os.path.join(tmp, "corpus", "0002"))
            _touch(os.path.join(tmp, "crashes", "crash_abc"))
            _touch(os.path.join(tmp, "metrics.jsonl"))  # not under corpus/crashes
            got = sorted(os.path.basename(p) for p in fd.harvest_ours(tmp))
            self.assertEqual(got, ["0001", "0002", "crash_abc"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class HarvestLibfuzzerTest(unittest.TestCase):
    def test_harvest_corpus_and_artefacts_not_seeds(self):
        tmp = tempfile.mkdtemp(prefix="mlf_lf_out_")
        try:
            corpus = os.path.join(tmp, "corpus")
            artifacts = os.path.join(tmp, "artifacts")
            _touch(os.path.join(corpus, "aaaa"))
            _touch(os.path.join(corpus, "bbbb"))
            _touch(os.path.join(artifacts, "crash-deadbeef"))
            _touch(os.path.join(artifacts, "oom-cafebabe"))
            _touch(os.path.join(artifacts, "fuzz-0.log"))  # not an input artefact
            got = sorted(os.path.basename(p)
                         for p in fd.harvest_libfuzzer(corpus, artifacts))
            self.assertEqual(got, ["aaaa", "bbbb", "crash-deadbeef", "oom-cafebabe"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_harvest_without_artifact_dir(self):
        tmp = tempfile.mkdtemp(prefix="mlf_lf_out2_")
        try:
            _touch(os.path.join(tmp, "corpus", "x"))
            got = [os.path.basename(p) for p in fd.harvest_libfuzzer(os.path.join(tmp, "corpus"))]
            self.assertEqual(got, ["x"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class CommandBuilderTest(unittest.TestCase):
    def test_afl_command_is_stdin_mode_with_wallclock(self):
        cmd = fd.afl_command("/b/base64-afl", seed_dir="/s", out_dir="/o",
                             max_seconds=30)
        self.assertEqual(cmd[:7], ["afl-fuzz", "-i", "/s", "-o", "/o", "-V", "30"])
        self.assertNotIn("@@", cmd)  # stdin mode
        self.assertEqual(cmd[-2:], ["/b/base64-afl", "-d"])

    def test_our_command_carries_target_args_and_budget(self):
        paths = {"fuzzer": "f", "exec_server": "es", "target": "t", "cov_library": "c"}
        cmd = fd.our_command(paths, seed_dir="/s", out_dir="/o", max_seconds=30,
                            target_args="-d")
        self.assertIn("--max-seconds", cmd)
        self.assertEqual(cmd[cmd.index("--max-seconds") + 1], "30")
        self.assertIn("--target-args", cmd)
        self.assertEqual(cmd[cmd.index("--target-args") + 1], "-d")

    def test_afl_env_has_noninteractive_guards(self):
        env = fd.afl_env()
        self.assertEqual(env["AFL_SKIP_CPUFREQ"], "1")
        self.assertEqual(env["AFL_NO_UI"], "1")

    def test_afl_env_merges_extra(self):
        env = fd.afl_env({"AFL_NO_AFFINITY": "1"})
        self.assertEqual(env["AFL_NO_AFFINITY"], "1")
        self.assertEqual(env["AFL_SKIP_CPUFREQ"], "1")

    def test_lf_command_budget_corpus_and_seeds(self):
        cmd = fd.lf_command("/b/lf", seed_dir="/s", out_corpus="/o/corpus",
                            max_seconds=30, artifact_dir="/o/art")
        self.assertEqual(cmd[0], "/b/lf")
        self.assertIn("-max_total_time=30", cmd)
        self.assertIn("-close_fd_mask=3", cmd)
        self.assertIn("-artifact_prefix=/o/art/", cmd)
        # corpus dir (grown) precedes the read-only seed dir.
        self.assertEqual(cmd[-2:], ["/o/corpus", "/s"])

    def test_lf_command_without_artifact_dir(self):
        cmd = fd.lf_command("/b/lf", seed_dir="/s", out_corpus="/o/c", max_seconds=5)
        self.assertFalse(any(a.startswith("-artifact_prefix") for a in cmd))
        self.assertEqual(cmd[-2:], ["/o/c", "/s"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
