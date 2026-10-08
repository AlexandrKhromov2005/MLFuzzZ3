"""Unit tests for the libtiff orchestrator's pure logic (ADR 0046 Step 3).

Run (not a CI gate; research tooling):  python3 benchmarks/magma/test_comparative_run_tiff.py

Covers the NEW pieces — time-to-reach extraction, the survival/predreg
aggregation, checkpoint/resume across a batch boundary, and an
aggregate_and_render smoke — on SYNTHETIC checkpoints (no real campaign).
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import comparative_run as base  # noqa: E402
import comparative_run_tiff as t  # noqa: E402

GRID = [1.0, 7.9, 62.0, 493.0, 3892.0, 30743.0, 86400.0]
BUDGET = 86400


def _codec_reach(reach_idx, bug_id):
    """Build a codec_reach list: bug_id appears from grid index reach_idx on
    (None = never reached)."""
    out = []
    for gi, gt in enumerate(GRID):
        ids = [bug_id] if (reach_idx is not None and gi >= reach_idx) else []
        out.append((gt, ids))
    return out


def _fuzzers_block(reach_map):
    """reach_map: {arm: {bug_id: reach_idx or None}} -> a checkpoint 'fuzzers' dict."""
    block = {}
    for arm in t.FUZZERS:
        # merge per-bug codec_reach into one list aligned to GRID
        merged = []
        for gi, gt in enumerate(GRID):
            ids = sorted(b for b, idx in reach_map[arm].items()
                         if idx is not None and gi >= idx)
            merged.append((gt, ids))
        block[arm] = {
            "regions": [(gt, 1000 + gi * 100) for gi, gt in enumerate(GRID)],
            "reached": [(gt, len(ids)) for gt, ids in merged],
            "triggered": [(gt, 0) for gt in GRID],
            "codec_reach": merged,
            "final_regions": 1000 + (len(GRID) - 1) * 100,
            "final_reached": len(merged[-1][1]),
            "final_triggered": 0,
            "reached_set": merged[-1][1],
            "triggered_set": [],
            "corpus_size": 100,
        }
    return block


def _demo_checkpoint(trial):
    # ours + cmplog reach all 3 codec gates ~grid 2; afl-plain/libfuzzer never.
    rm = {}
    for arm in t.FUZZERS:
        if arm in ("mlfuzzz3", "afl-cmplog"):
            rm[arm] = {"TIF002": 2, "TIF006": 2, "TIF010": 2, "TIF005": 3}
        else:
            rm[arm] = {"TIF002": None, "TIF006": None, "TIF010": None, "TIF005": None}
    return {"trial": trial, "budget": BUDGET, "fuzzers": _fuzzers_block(rm)}


class TimeToReachTest(unittest.TestCase):
    def test_first_reach_and_censor(self):
        cr = _codec_reach(3, "TIF010")
        self.assertEqual(t.time_to_reach(cr, ("TIF010",), BUDGET), (GRID[3], 1))
        self.assertEqual(t.time_to_reach(_codec_reach(None, "TIF010"),
                                         ("TIF010",), BUDGET), (float(BUDGET), 0))

    def test_gate_is_any_of_ids(self):
        # PixarLog gate = TIF002 OR TIF006; reaching either counts.
        cr = []
        for gi, gt in enumerate(GRID):
            cr.append((gt, ["TIF006"] if gi >= 4 else []))
        self.assertEqual(t.time_to_reach(cr, ("TIF002", "TIF006"), BUDGET), (GRID[4], 1))


class SurvivalAxisTest(unittest.TestCase):
    def test_predreg_met_when_ours_reaches_baselines_dont(self):
        by_trial = [_demo_checkpoint(i) for i in range(10)]
        surv = t.survival_axis(by_trial)
        self.assertEqual(set(surv), {"PixarLog", "LZW", "LUV"})
        for gate, d in surv.items():
            self.assertTrue(d["won"], f"{gate} should be a predreg win")
            holm = {r[0]: r[4] for r in d["rows"]}
            self.assertLess(holm["afl-plain"], 0.05)
            self.assertLess(holm["libfuzzer"], 0.05)
            # CmpLog is the ceiling: ours ~ cmplog -> NOT significant (no_events
            # both reach identically) -> p == 1.0 / no_events status.
            cmplog_row = [r for r in d["rows"] if r[0] == "afl-cmplog"][0]
            self.assertGreaterEqual(cmplog_row[4], 0.05)

    def test_no_one_reaches_is_not_a_win(self):
        rm_none = {a: {b: None for b in ("TIF002", "TIF006", "TIF010", "TIF005")}
                   for a in t.FUZZERS}
        ck = {"trial": 0, "budget": BUDGET, "fuzzers": _fuzzers_block(rm_none)}
        surv = t.survival_axis([ck] * 6)
        for gate, d in surv.items():
            self.assertFalse(d["won"])
            self.assertFalse(d["ours_reaches"])


class ResumeAcrossBatchTest(unittest.TestCase):
    def test_resume_no_loss_no_duplicate(self):
        # N=10, jobs=5: simulate batch 1 (trials 0..4) checkpointed, then a kill.
        with tempfile.TemporaryDirectory() as wd:
            ckdir = os.path.join(wd, "checkpoints")
            os.makedirs(ckdir)
            for i in range(5):  # batch 1 done
                with open(os.path.join(ckdir, f"trial_{i:03d}.json"), "w") as fh:
                    json.dump(_demo_checkpoint(i), fh)
            done = base.load_checkpoints(wd, 10)
            todo = base.pending_trials(10, done.keys())
            self.assertEqual(sorted(done), [0, 1, 2, 3, 4])      # no loss
            self.assertEqual(todo, [5, 6, 7, 8, 9])              # exactly the rest
            self.assertEqual(set(done) & set(todo), set())       # no duplicate


class AggregateSmokeTest(unittest.TestCase):
    def test_renders_survival_secondary_and_report(self):
        by_trial = {i: _demo_checkpoint(i) for i in range(10)}
        with tempfile.TemporaryDirectory() as out:
            class A:
                pass
            args = A()
            args.out = out
            args.budget = BUDGET
            args.jobs = 5
            cfg = type("C", (), {"grid": GRID, "budget": BUDGET, "jobs": 5})()
            degen = t.aggregate_and_render(by_trial, cfg, args, logfh=None)
            for f in ("coverage_curve.svg", "bugs_curve.svg", "report.md",
                      "survival_PixarLog.svg", "survival_LZW.svg", "survival_LUV.svg"):
                self.assertTrue(os.path.exists(os.path.join(out, f)), f)
            with open(os.path.join(out, "report.md")) as fh:
                rep = fh.read()
            self.assertIn("3/3 gates won", rep)
            self.assertIn("MET", rep)
            self.assertIn("CmpLog arm is the classical", rep)
            # degeneracy report present for all 4 arms
            self.assertEqual(set(degen), set(t.FUZZERS))


# ==========================================================================
# ADR 0048 — пятое плечо, счётчики исполнений, сохранение артефактов.
#
# Всё ниже проверяется на СИНТЕТИЧЕСКИХ входах с известным ответом: ни одна
# кампания не запускается, ни один бинарь не нужен.
# ==========================================================================

import fuzzer_drivers as fd  # noqa: E402  (scripts/ на пути после импорта t)


class _Cfg:
    """Минимальный конфиг для _campaign_plan — только те поля, которые он
    читает. Заводить настоящий Config ради четырёх строк не нужно, а лишние
    поля прятали бы, что именно план использует."""

    def __init__(self, **kw):
        self.fuzzer = "F"
        self.exec_server = "E"
        self.cov_library = "C"
        self.ours_bin = "OURS"
        self.afl_bin = "AFL"
        self.afl_cmplog_bin = "CMPLOG"
        self.lf_bin = "LF"
        self.cov_bin = "COV"
        self.canary_bin = "CANARY"
        self.oracle_read = "ORACLE"
        self.seeds = "SEEDS"
        self.work_dir = "WORK"
        self.budget = 600
        self.target_args = ()
        self.afl_no_autodict = False
        self.keep_artifacts = True
        self.__dict__.update(kw)


class NoConcolicArmTest(unittest.TestCase):
    def tearDown(self):
        t.select_arms("v1")

    def test_v2_adds_the_arm_and_v1_does_not(self):
        self.assertNotIn("mlfuzzz3-noconcolic", t.select_arms("v1"))
        arms = t.select_arms("v2")
        self.assertIn("mlfuzzz3-noconcolic", arms)
        self.assertEqual(len(arms), 5)
        # Порядок фиксирован: плечо без солвера идёт сразу за нашим основным,
        # потому что именно эта ПАРА и есть измерение цены солвера.
        self.assertEqual(arms[:2], ("mlfuzzz3", "mlfuzzz3-noconcolic"))
        self.assertIn("mlfuzzz3-noconcolic", t.DISPLAY)

    def test_flag_and_out_dir_differ_between_the_two_our_arms(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _Cfg()
            plain = t._campaign_plan("mlfuzzz3", cfg, 0, tmp, 3)
            nocon = t._campaign_plan("mlfuzzz3-noconcolic", cfg, 1, tmp, 3)
            self.assertNotIn("--no-concolic", plain.plan.cmd)
            self.assertIn("--no-concolic", nocon.plan.cmd)
            # Разные выходные каталоги — иначе плечи затирали бы друг друга.
            plain_out = plain.plan.cmd[plain.plan.cmd.index("--out-dir") + 1]
            nocon_out = nocon.plan.cmd[nocon.plan.cmd.index("--out-dir") + 1]
            self.assertNotEqual(plain_out, nocon_out)
            # Сид ГСЧ у обоих плеч одинаковый: это один и тот же трайл.
            self.assertEqual(plain.plan.cmd[plain.plan.cmd.index("--seed") + 1],
                             nocon.plan.cmd[nocon.plan.cmd.index("--seed") + 1])


class AflAutodictTest(unittest.TestCase):
    def test_no_autodict_only_on_plain_and_only_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            on = _Cfg(afl_no_autodict=True)
            off = _Cfg(afl_no_autodict=False)
            plain_on = t._campaign_plan("afl-plain", on, 0, tmp, 0).plan.env
            cmplog_on = t._campaign_plan("afl-cmplog", on, 1, tmp, 0).plan.env
            plain_off = t._campaign_plan("afl-plain", off, 2, tmp, 0).plan.env
            self.assertEqual(plain_on.get("AFL_NO_AUTODICT"), "1")
            # cmplog — потолок классического I2S; глушить ему словарь незачем.
            self.assertIsNone(cmplog_on.get("AFL_NO_AUTODICT"))
            self.assertIsNone(plain_off.get("AFL_NO_AUTODICT"))


class ExecsParsingTest(unittest.TestCase):
    """Знаменатель для нормировки на исполнение — три формата, три ответа."""

    def test_ours_takes_last_COMPLETE_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "metrics.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"execs": 100, "elapsed": 1}) + "\n")
                fh.write(json.dumps({"execs": 250, "elapsed": 2}) + "\n")
                fh.write('{"execs": 999, "elap')      # оборванная запись
            # Последняя строка недописана — её нельзя ни разобрать, ни счесть
            # нулём; берётся последняя целая.
            self.assertEqual(fd.read_ours_execs(tmp), 250)

    def test_ours_missing_file_is_none_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(fd.read_ours_execs(tmp))

    def test_afl_sums_execs_done_over_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, execs in (("default", 4242), ("secondary", 58)):
                inst = os.path.join(tmp, name)
                os.makedirs(inst)
                with open(os.path.join(inst, "fuzzer_stats"), "w", encoding="utf-8") as fh:
                    fh.write("start_time : 1750000000\n")
                    fh.write(f"execs_done : {execs}\n")
                    fh.write("execs_per_sec : 123.45\n")
            self.assertEqual(fd.read_afl_execs(tmp), 4300)

    def test_afl_without_stats_is_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "default"))
            self.assertIsNone(fd.read_afl_execs(tmp))

    def test_libfuzzer_progress_then_final_stat(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "libfuzzer.campaign.log")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("#2\tINITED cov: 10 ft: 20 corp: 1/1b exec/s: 0 rss: 30Mb\n")
                fh.write("#4096\tNEW    cov: 44 ft: 91 corp: 7/9b exec/s: 900 rss: 33Mb\n")
                fh.write("#1024\tpulse  cov: 44 ft: 91 corp: 7/9b exec/s: 900 rss: 33Mb\n")
            # Пока прогон идёт, итоговой строки нет — берётся наибольший #N,
            # а не последний: строки pulse и NEW перемежаются.
            self.assertEqual(fd.read_libfuzzer_execs(log), 4096)
            with open(log, "a", encoding="utf-8") as fh:
                fh.write("stat::number_of_executed_units: 5120\n")
                fh.write("stat::average_exec_per_sec:     850\n")
            # Итоговая строка точнее прогресса и вытесняет его.
            self.assertEqual(fd.read_libfuzzer_execs(log), 5120)

    def test_libfuzzer_missing_log_is_none(self):
        self.assertIsNone(fd.read_libfuzzer_execs("/nonexistent/libfuzzer.log"))

    def test_libfuzzer_final_stats_flag_is_in_the_v2_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = t._campaign_plan("libfuzzer", _Cfg(), 0, tmp, 0)
            # Без флага строки stat:: в логе не будет вовсе, и знаменателя нет.
            self.assertIn("-print_final_stats=1", plan.plan.cmd)


class KeepArtifactsTest(unittest.TestCase):
    """Ровно тот материал, который кампания N=10 потеряла вместе с каталогом
    трайла: fuzzer_stats, plot_data, финальные корпуса, наш metrics.jsonl."""

    def test_ours_keeps_metrics_and_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "mlfuzzz3_out")
            os.makedirs(os.path.join(out, "corpus"))
            open(os.path.join(out, "metrics.jsonl"), "w").write('{"execs": 7}\n')
            open(os.path.join(out, "corpus", "id0"), "wb").write(b"AAA")
            dest = os.path.join(tmp, "kept")
            t._keep_ours(out, dest)
            self.assertTrue(os.path.exists(os.path.join(dest, "metrics.jsonl")))
            self.assertTrue(os.path.exists(os.path.join(dest, "corpus", "id0")))

    def test_afl_keeps_stats_plotdata_and_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            inst = os.path.join(tmp, "afl_out", "default")
            os.makedirs(os.path.join(inst, "queue"))
            open(os.path.join(inst, "fuzzer_stats"), "w").write("execs_done : 5\n")
            open(os.path.join(inst, "plot_data"), "w").write("# rel_time\n1,2\n")
            open(os.path.join(inst, "queue", "id:000000"), "wb").write(b"Q")
            dest = os.path.join(tmp, "kept")
            t._keep_afl(os.path.join(tmp, "afl_out"), dest)
            for rel in ("default/fuzzer_stats", "default/plot_data",
                        "default/queue/id:000000"):
                self.assertTrue(os.path.exists(os.path.join(dest, rel)), rel)

    def test_libfuzzer_keeps_corpus_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = os.path.join(tmp, "corp")
            arts = os.path.join(tmp, "arts")
            os.makedirs(corpus)
            os.makedirs(arts)
            open(os.path.join(corpus, "aa"), "wb").write(b"x")
            open(os.path.join(arts, "crash-1"), "wb").write(b"y")
            dest = os.path.join(tmp, "kept")
            t._keep_libfuzzer(corpus, arts, dest)
            self.assertTrue(os.path.exists(os.path.join(dest, "corpus", "aa")))
            self.assertTrue(os.path.exists(os.path.join(dest, "artifacts", "crash-1")))


class ArmsMarkerTest(unittest.TestCase):
    """Смешать наборы плеч в одном рабочем каталоге нельзя: отпечаток движка
    про плечи не знает, и без маркера пятиплечий прогон молча продолжился бы
    четырьмя."""

    def test_created_then_resumed_with_same_arms(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(t.check_arms_marker(tmp, t.FUZZERS_V2), "created")
            self.assertEqual(t.check_arms_marker(tmp, t.FUZZERS_V2), "resumed")

    def test_different_arms_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            t.check_arms_marker(tmp, t.FUZZERS_V2)
            with self.assertRaises(SystemExit):
                t.check_arms_marker(tmp, t.FUZZERS_V1)

    def test_out_equal_to_work_dir_does_not_clobber_engine_fingerprint(self):
        t.select_arms("v2")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                # Отпечаток движка лежит под тем же именем в --work-dir.
                with open(os.path.join(tmp, "config.json"), "w", encoding="utf-8") as fh:
                    json.dump({"trials": 10, "budget": 86400}, fh)
                cfg = _Cfg(trials=1, jobs=1, arms=t.FUZZERS_V2, work_dir=tmp)
                args = type("A", (), {"arms": "v2"})()
                path, _ = t.write_config_json(args, cfg, list(range(5)), [1.0], tmp)
                self.assertTrue(path.endswith("campaign-config.json"))
                saved = json.load(open(os.path.join(tmp, "config.json"), encoding="utf-8"))
                self.assertEqual(saved["trials"], 10)   # отпечаток цел
        finally:
            t.select_arms("v1")


class ConfigJsonTest(unittest.TestCase):
    def tearDown(self):
        t.select_arms("v1")

    def test_affinity_is_recorded_and_conflict_free(self):
        t.select_arms("v2")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _Cfg(trials=2, jobs=2, arms=t.FUZZERS_V2)
            cores = list(range(10))          # 2 слота x 5 плеч — ровно хватает
            args = type("A", (), {"arms": "v2"})()
            path, conflicts = t.write_config_json(args, cfg, cores, [1.0, 2.0], tmp)
            self.assertEqual(conflicts, [])
            cfgj = json.load(open(path, encoding="utf-8"))
            self.assertEqual(cfgj["adr"], "0048")
            self.assertEqual(len(cfgj["arms"]), 5)
            # Каждое плечо каждого слота получило СВОЁ ядро.
            used = [c for slot in cfgj["affinity"].values() for c in slot.values()]
            self.assertEqual(len(used), len(set(used)))
            # Значения throttle прочитаны из заголовка, а не вписаны руками.
            self.assertIn("base_interval", cfgj["throttle"])
            self.assertIsNone(cfgj["throttle"]["cli_switch"])

    def test_too_small_core_pool_is_recorded_not_silently_shared(self):
        t.select_arms("v2")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _Cfg(trials=1, jobs=2, arms=t.FUZZERS_V2)
            cores = list(range(5))           # хватает на один слот из двух
            args = type("A", (), {"arms": "v2"})()
            path, _ = t.write_config_json(args, cfg, cores, [1.0], tmp)
            cfgj = json.load(open(path, encoding="utf-8"))
            self.assertIn("error", cfgj["affinity"]["slot1"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
