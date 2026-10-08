"""Comparative fuzzer benchmark orchestrator — Magma libtiff slice (ADR 0046).

The libtiff *demonstrator* run. Fork of comparative_run.py (libpng, ADR 0045):
the campaign/snapshot/replay engine, checkpoint/resume, and the secondary
Mann-Whitney+Holm machinery are imported from that module unchanged (``base``);
this file adds only what ADR 0046 needs:

  * FOUR arms instead of three — ours / AFL++ plain forkserver / AFL++ CmpLog /
    libFuzzer. The CmpLog arm drives the plain forkserver binary WITH a
    ``-c <cmplog-companion>`` (AFL's input-to-state), serving as the upper bound
    of classical input-to-state on the literal codec gates (ADR 0046 F1).

  * PRIMARY metric — time-to-reach each codec-gated bug. For one (arm, trial,
    gate) the observation is the first log-spaced snapshot time at which any of
    the gate's bug ids enters the reached set; never reached within budget ->
    right-censored at the budget. Compared pairwise (ours vs each arm) with the
    hand-rolled log-rank test (scripts/stats/survival.py) + Holm. Mann-Whitney
    is statistically invalid for right-censored time-to-event data, so it is NOT
    used here for the primary axis (ADR 0046 Решение).

  * SECONDARY metrics — neutral region coverage and bug-oracle reach/trigger,
    aggregated and tested with Mann-Whitney+Holm exactly as the libpng run
    (methodology consistency, ADR 0045).

The codec gates (zlib-available, ADR 0046 Q1): PixarLog (TIF002/TIF006),
LZW (TIF010), LUV (TIF005). Background bugs reachable by any TIFF (e.g. TIF003,
TIF012) are not codec-gated and are not part of the primary metric.

Host-only research tooling; not a CI gate. Build the arms first
(benchmarks/magma/build_tiff*.sh). NEVER points a fuzzer at the canonical seed
dir as a writable corpus (per-trial scratch corpora only) — the canonical
corpus stays clean.
"""
from __future__ import annotations

import glob
import hashlib
import itertools
import json
import os
import re
import queue
import shutil
import subprocess
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
_SCRIPTS = os.path.join(_REPO, "scripts")
sys.path.insert(0, _SCRIPTS)
sys.path.insert(0, os.path.join(_SCRIPTS, "stats"))

import argparse  # noqa: E402

import comparative_run as base  # noqa: E402  (engine: pools, replay, resume, MW)
import comparative_benchmark as cb  # noqa: E402  (render_svg)
import fuzzer_drivers as fd  # noqa: E402
import incremental_replay as ir  # noqa: E402
import mannwhitney as mw  # noqa: E402  (holm_bonferroni)
import survival  # noqa: E402  (log-rank + Kaplan-Meier, ADR 0046)

# Наборы плеч (внутренний ключ -> отображаемое имя + фиксированный порядок).
#
# v1 — четвёрка ADR-0046, ровно та, которой снята кампания N=10. Она остаётся
# умолчанием, чтобы прежний прогон воспроизводился командой без новых флагов.
# v2 — пятёрка ADR-0048: к ней добавлено плечо «мы без солвера». Оно и есть
# смысл кампании v2: без него разность «мы против AFL++» неразложима — в ней
# сложены цена солвера, цена субстрата и качество стратегии.
FUZZERS_V1 = ("mlfuzzz3", "afl-plain", "afl-cmplog", "libfuzzer")
FUZZERS_V2 = ("mlfuzzz3", "mlfuzzz3-noconcolic", "afl-plain", "afl-cmplog", "libfuzzer")
FUZZERS = FUZZERS_V1
DISPLAY = {
    "mlfuzzz3": "mlfuzzz3",
    "mlfuzzz3-noconcolic": "mlfuzzz3 (--no-concolic)",
    "afl-plain": "AFL++ (plain)",
    "afl-cmplog": "AFL++ (CmpLog)",
    "libfuzzer": "libFuzzer",
}
# Наши плечи — те, для которых знаменатель берётся из metrics.jsonl.
OURS_ARMS = ("mlfuzzz3", "mlfuzzz3-noconcolic")


def select_arms(campaign):
    """Выбирает набор плеч на весь прогон и возвращает его.

    Модульная глобаль FUZZERS переопределяется ОДИН раз, из main(), до того
    как стартует хоть один трайл, и дальше только читается — трайлы идут в
    потоках, и менять её после старта было бы гонкой. Тот же вызов делает
    smoke и тесты, когда им нужна пятёрка.
    """
    global FUZZERS  # noqa: PLW0603 — ровно один раз, до запуска трайлов
    FUZZERS = FUZZERS_V2 if campaign == "v2" else FUZZERS_V1
    return FUZZERS
# Baselines WITHOUT input-to-state — the predregistered comparison group.
BASELINES_NO_I2S = ("afl-plain", "libfuzzer")

# Codec-gated bugs (ADR 0046 Q1): a gate is reached if ANY of its ids is reached.
CODEC_GATES = {
    "PixarLog": ("TIF002", "TIF006"),
    "LZW": ("TIF010",),
    "LUV": ("TIF005",),
}
CODEC_IDS = frozenset(itertools.chain.from_iterable(CODEC_GATES.values()))

# Per-process memory caps (ADR 0046): a crafted libtiff input ballooned to
# ~21.8 GB and OOM-killed the N=10 run during replay. legit raster is bounded to
# ~2 GB by the harness MAX_SIZE guard, so 4 GB sits safely between legit decode
# and the 21.8 GB pathology. The cap is UNIFORM across all four arms (4096 MB) so
# the substrate is identical — an asymmetric cap would confound the comparison.
# Our arm's `ulimit -v` covers its whole tree (fuzzer+Z3+target); a concolic
# branch-flip query is small, so 4 GB is ample, and a >4 GB run is anomalous
# (crash-class), not legitimate codec reachability (gates are by Compression
# tag, not memory).
_MEM_CAP_MB = 4096                              # AFL -m / libFuzzer rss+malloc / replay / ours
_REPLAY_AS_BYTES = _MEM_CAP_MB * 1024 * 1024    # RLIMIT_AS on replay execs (4 GB)
_OURS_VIRT_KB = _MEM_CAP_MB * 1024              # ulimit -v for our campaign (4 GB, uniform)


class Config:
    """Resolved run configuration (CLI args + derived grid/cores). Carries the
    extra CmpLog companion binary the 4th arm needs."""

    def __init__(self, args, grid, cores):
        self.trials = args.trials
        self.budget = args.budget
        self.jobs = args.jobs
        self.grid = grid
        self.cores = cores
        self.seeds = args.seeds
        self.fuzzer = args.fuzzer
        self.exec_server = args.exec_server
        self.cov_library = args.cov_library
        self.ours_bin = args.ours_bin
        self.afl_bin = args.afl_bin
        self.afl_cmplog_bin = args.afl_cmplog_bin
        self.lf_bin = args.lf_bin
        self.cov_bin = args.cov_bin
        self.canary_bin = args.canary_bin
        self.oracle_read = args.oracle_read
        self.target_args = tuple(args.target_args.split()) if args.target_args else ()
        # ADR 0048
        self.arms = tuple(FUZZERS)
        self.work_dir = args.work_dir
        self.afl_no_autodict = args.afl_no_autodict
        self.keep_artifacts = args.keep_artifacts


# --------------------------------------------------------------------------
# Campaign plans (which command / harvest / env per arm)
# --------------------------------------------------------------------------

def _keep_ours(out, dest):
    """Артефакты нашего плеча: metrics.jsonl ЦЕЛИКОМ и финальный корпус."""
    os.makedirs(dest, exist_ok=True)
    metrics = os.path.join(out, "metrics.jsonl")
    if os.path.exists(metrics):
        shutil.copy2(metrics, os.path.join(dest, "metrics.jsonl"))
    for sub in ("corpus", "crashes"):
        src = os.path.join(out, sub)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(dest, sub), dirs_exist_ok=True)


def _keep_afl(out, dest):
    """Артефакты плеча AFL++: fuzzer_stats и plot_data КАЖДОГО инстанса плюс
    его финальная очередь и падения. Имя каталога инстанса не фиксировано,
    поэтому берутся все подкаталоги."""
    os.makedirs(dest, exist_ok=True)
    for inst in sorted(glob.glob(os.path.join(out, "*"))):
        if not os.path.isdir(inst):
            continue
        dst = os.path.join(dest, os.path.basename(inst))
        os.makedirs(dst, exist_ok=True)
        for fname in ("fuzzer_stats", "plot_data", "cmdline", "fuzzer_setup"):
            src = os.path.join(inst, fname)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dst, fname))
        for sub in ("queue", "crashes"):
            src = os.path.join(inst, sub)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(dst, sub), dirs_exist_ok=True)


def _keep_libfuzzer(corpus, artifacts, dest):
    """Артефакты плеча libFuzzer: выращенный корпус и аварийные артефакты.
    Счётчик исполнений у него живёт не в файле, а в собственном логе трайла,
    и лог остаётся на месте отдельно."""
    os.makedirs(dest, exist_ok=True)
    if os.path.isdir(corpus):
        shutil.copytree(corpus, os.path.join(dest, "corpus"), dirs_exist_ok=True)
    if artifacts and os.path.isdir(artifacts):
        shutil.copytree(artifacts, os.path.join(dest, "artifacts"), dirs_exist_ok=True)


class _ArmPlan:
    """План одного плеча плюс две вещи, которых у ADR-0046 не было:
    чтение счётчика исполнений на любой момент прогона и сохранение
    артефактов трайла. Оба нужны кампании v2 по построению — см. ADR-0048."""

    __slots__ = ("plan", "execs", "keep")

    def __init__(self, plan, execs, keep):
        self.plan = plan
        self.execs = execs    # () -> int | None
        self.keep = keep      # (dest) -> None


def _campaign_plan(key, cfg, core, trial_dir, trial_idx):
    """Run plan for one arm in one trial: argv (taskset-pinned), env, cwd, and a
    zero-arg harvest closure over the live output dirs. Every fuzzer writes into
    ``trial_dir`` scratch; ``cfg.seeds`` is a read-only seed source (the
    canonical corpus is never grown).

    Возвращает _ArmPlan: сам план, читатель счётчика исполнений и сохранятель
    артефактов (ADR 0048)."""
    taskset = ["taskset", "-c", str(core)]
    target_args = cfg.target_args

    if key in OURS_ARMS:
        no_concolic = key == "mlfuzzz3-noconcolic"
        out = os.path.join(trial_dir, "mlfuzzz3_noconcolic_out" if no_concolic
                           else "mlfuzzz3_out")
        cmd = fd.our_command(
            {"fuzzer": cfg.fuzzer, "exec_server": cfg.exec_server,
             "target": cfg.ours_bin, "cov_library": cfg.cov_library},
            seed_dir=cfg.seeds, out_dir=out, max_seconds=cfg.budget,
            target_args=" ".join(target_args), rng_seed=1000 + trial_idx,
            no_concolic=no_concolic,
        )
        # exec-server has no per-target RLIMIT_AS (and the pins forbid changing
        # it), so cap the whole campaign tree with `ulimit -v` at the SAME 4 GB
        # as the other arms (uniform substrate): each child (fuzzer+Z3,
        # exec-server, the libtiff target) gets a 4 GB address-space ceiling —
        # ample for a branch-flip query, and it kills a 21.8 GB target balloon.
        wrapped = ["bash", "-c", f"ulimit -v {_OURS_VIRT_KB}; exec \"$@\"", "bash"] + taskset + cmd
        return _ArmPlan(
            base._Plan(wrapped, dict(os.environ), None, lambda: fd.harvest_ours(out)),
            lambda: fd.read_ours_execs(out),
            lambda dest: _keep_ours(out, dest))

    if key in ("afl-plain", "afl-cmplog"):
        out = os.path.join(trial_dir, f"{key}_out")
        os.makedirs(out, exist_ok=True)
        # Both AFL arms fuzz the SAME plain forkserver binary (cfg.afl_bin); the
        # CmpLog arm additionally loads the CmpLog companion via -c. -m caps each
        # target run (AFL kills it on exceed and keeps fuzzing).
        cmplog_bin = cfg.afl_cmplog_bin if key == "afl-cmplog" else None
        cmd = fd.afl_command(cfg.afl_bin, seed_dir=cfg.seeds, out_dir=out,
                             max_seconds=cfg.budget, target_args=tuple(target_args),
                             cmplog_bin=cmplog_bin, mem_mb=_MEM_CAP_MB)
        extra = {"AFL_NO_AFFINITY": "1"}
        # ADR 0048 плечо 3: autodict вытаскивает литералы (включая codec-magic)
        # прямо из инструментированного бинаря, поэтому «AFL++ plain» в N=10
        # НЕ был базовой линией без input-to-state, каковой был объявлен
        # (ANALYSIS.md:30, вывод 1). Гасится только у plain — cmplog остаётся
        # потолком классического I2S и autodict ему не мешает.
        if cfg.afl_no_autodict and key == "afl-plain":
            extra["AFL_NO_AUTODICT"] = "1"
        env = {**os.environ, **fd.afl_env(extra)}
        return _ArmPlan(
            base._Plan(taskset + cmd, env, None, lambda: fd.harvest_afl(out)),
            lambda: fd.read_afl_execs(out),
            lambda dest: _keep_afl(out, dest))

    if key == "libfuzzer":
        corpus = os.path.join(trial_dir, "libfuzzer_corpus")
        artifacts = os.path.join(trial_dir, "libfuzzer_artifacts")
        os.makedirs(corpus, exist_ok=True)
        os.makedirs(artifacts, exist_ok=True)
        cmd = fd.lf_command(cfg.lf_bin, seed_dir=cfg.seeds, out_corpus=corpus,
                            max_seconds=cfg.budget, artifact_dir=artifacts,
                            target_args=tuple(target_args),
                            rss_limit_mb=_MEM_CAP_MB, malloc_limit_mb=_MEM_CAP_MB,
                            print_final_stats=True)
        # Счётчик исполнений libFuzzer живёт только в его собственном логе —
        # том самом, куда run_trial направляет stdout кампании.
        log_path = os.path.join(trial_dir, f"{key}.campaign.log")
        return _ArmPlan(
            base._Plan(taskset + cmd, dict(os.environ), artifacts,
                       lambda: fd.harvest_libfuzzer(corpus, artifacts)),
            lambda: fd.read_libfuzzer_execs(log_path),
            lambda dest: _keep_libfuzzer(corpus, artifacts, dest))

    raise ValueError(f"unknown fuzzer key: {key}")


def run_trial(trial_idx, slot, cfg, work_dir, logfh, replay_lock):
    """Run one trial (four campaigns) and write its checkpoint. Mirrors
    base.run_trial (proven by the libpng N=5 run) but iterates the four libtiff
    arms and records, per snapshot, the SET of codec-gated bug ids reached
    (``codec_reach``) — the raw material for the time-to-reach survival axis."""
    cores = base.assign_cores(slot, len(FUZZERS), cfg.cores)
    trial_dir = os.path.join(work_dir, "trials", f"trial_{trial_idx:03d}")
    if os.path.isdir(trial_dir):
        shutil.rmtree(trial_dir, ignore_errors=True)
    os.makedirs(trial_dir, exist_ok=True)

    arms, procs, pools, snaps, execs = {}, {}, {}, {}, {}
    for f_idx, key in enumerate(FUZZERS):
        arms[key] = _campaign_plan(key, cfg, cores[f_idx], trial_dir, trial_idx)
        pools[key] = base.HardlinkPool(os.path.join(trial_dir, key, "pool"))
        snaps[key] = []
        execs[key] = []
    # Тело ниже читает plans[key].cmd/env/cwd/harvest ровно как в ADR-0046;
    # счётчик исполнений и сохранение артефактов висят отдельно на arms[key].
    plans = {key: arm.plan for key, arm in arms.items()}

    base._log(logfh, f"trial {trial_idx}: launching {len(FUZZERS)} campaigns on "
                     f"cores {cores} (budget {cfg.budget}s)")
    for key in FUZZERS:
        logpath = os.path.join(trial_dir, f"{key}.campaign.log")
        with open(logpath, "wb") as clog:
            procs[key] = subprocess.Popen(
                plans[key].cmd, env=plans[key].env, cwd=plans[key].cwd,
                stdout=clog, stderr=subprocess.STDOUT,
            )

    start = time.monotonic()
    grid = cfg.grid
    gi = 0
    hard_limit = cfg.budget + base._HARD_LIMIT_SLACK
    last_beat = 0.0
    while any(p.poll() is None for p in procs.values()):
        time.sleep(0.5)
        elapsed = time.monotonic() - start
        while gi < len(grid) and elapsed >= grid[gi]:
            for key in FUZZERS:
                size = pools[key].add_harvest(plans[key].harvest())
                snaps[key].append((elapsed, size))
                # Знаменатель для нормировки на исполнение. None означает
                # «счётчика ещё нет», и это НЕ ноль — их нельзя смешивать.
                execs[key].append((elapsed, arms[key].execs()))
            base._log(logfh, f"trial {trial_idx}: snapshot @ {elapsed:.1f}s "
                             f"pool sizes " + ", ".join(
                                 f"{key}={pools[key].size}" for key in FUZZERS))
            gi += 1
        if elapsed - last_beat >= 300.0:
            last_beat = elapsed
            base._log(logfh, f"trial {trial_idx}: alive @ {elapsed:.0f}s "
                             f"(of {cfg.budget}s)")
        if elapsed > hard_limit:
            base._log(logfh, f"trial {trial_idx}: HARD LIMIT {hard_limit:.0f}s — "
                             f"terminating stragglers")
            for p in procs.values():
                if p.poll() is None:
                    p.terminate()
            break

    for key, p in procs.items():
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()

    final_elapsed = time.monotonic() - start
    for key in FUZZERS:
        size = pools[key].add_harvest(plans[key].harvest())
        snaps[key].append((final_elapsed, size))
        execs[key].append((final_elapsed, arms[key].execs()))
    base._log(logfh, f"trial {trial_idx}: campaigns done @ {final_elapsed:.1f}s; "
                     f"final corpora " + ", ".join(
                         f"{key}={pools[key].size}" for key in FUZZERS))

    result = {"trial": trial_idx, "budget": cfg.budget, "fuzzers": {}}
    with replay_lock:
        for key in FUZZERS:
            cuts = snaps[key]
            snap_inputs = [pools[key].prefix(cut) for _elapsed, cut in cuts]
            times = [elapsed for elapsed, _cut in cuts]

            base._log(logfh, f"trial {trial_idx}: [{key}] region replay "
                             f"({pools[key].size} inputs, {len(snap_inputs)} snaps)")
            region_pts = ir.replay_incremental(cfg.cov_bin, snap_inputs,
                                               target_args=cfg.target_args,
                                               mem_limit_bytes=_REPLAY_AS_BYTES)
            regions = [(t, covered) for t, (covered, _total) in zip(times, region_pts)]

            base._log(logfh, f"trial {trial_idx}: [{key}] oracle replay")
            oracle_pts = base.replay_oracle_incremental(
                cfg.canary_bin, cfg.oracle_read, snap_inputs,
                target_args=cfg.target_args, mem_limit_bytes=_REPLAY_AS_BYTES)
            reached = [(t, len(r)) for t, (r, _tg) in zip(times, oracle_pts)]
            triggered = [(t, len(tg)) for t, (_r, tg) in zip(times, oracle_pts)]
            # Per-snapshot codec-gated reached ids — the survival raw material.
            codec_reach = [(t, sorted(set(r) & CODEC_IDS))
                           for t, (r, _tg) in zip(times, oracle_pts)]
            final_reached = sorted(oracle_pts[-1][0]) if oracle_pts else []
            final_triggered = sorted(oracle_pts[-1][1]) if oracle_pts else []

            result["fuzzers"][key] = {
                "regions": regions,
                "reached": reached,
                "triggered": triggered,
                "codec_reach": codec_reach,
                "final_regions": regions[-1][1] if regions else 0,
                "final_reached": len(final_reached),
                "final_triggered": len(final_triggered),
                "reached_set": final_reached,
                "triggered_set": final_triggered,
                "corpus_size": pools[key].size,
                # ADR 0048: (время, исполнений) на каждый снапшот. У кампании
                # N=10 этого ряда не было вовсе, поэтому её числа нормировать
                # на исполнение оказалось нечем.
                "execs": execs[key],
            }
            base._log(logfh, f"trial {trial_idx}: [{key}] regions="
                             f"{result['fuzzers'][key]['final_regions']} reached="
                             f"{len(final_reached)} triggered={len(final_triggered)}")

    ckpt_dir = os.path.join(work_dir, "checkpoints")
    os.makedirs(ckpt_dir, exist_ok=True)
    ckpt_path = os.path.join(ckpt_dir, f"trial_{trial_idx:03d}.json")
    tmp_path = ckpt_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    os.replace(tmp_path, ckpt_path)  # atomic; survives a batch-boundary kill
    base._log(logfh, f"trial {trial_idx}: checkpoint written -> {ckpt_path}")

    if cfg.keep_artifacts:
        # ADR 0048. Раньше здесь стоял безусловный rmtree всего каталога
        # трайла, и вместе с ним исчезали fuzzer_stats, plot_data, финальные
        # корпуса и наш metrics.jsonl — то есть ровно тот материал, без
        # которого кампанию нельзя ни нормировать, ни перепроверить. Теперь
        # перечисленное сначала складывается в trials/trial_NNN/artifacts/, и
        # только потом вычищается всё остальное (пулы жёстких ссылок и живые
        # выходные каталоги плеч), иначе диск не выдержит десяти трайлов.
        keep_root = os.path.join(trial_dir, "artifacts")
        for key in FUZZERS:
            try:
                arms[key].keep(os.path.join(keep_root, key))
            except OSError as exc:
                base._log(logfh, f"trial {trial_idx}: [{key}] артефакты не сохранены: {exc}")
        keep_names = {"artifacts"} | {f"{key}.campaign.log" for key in FUZZERS}
        for entry in os.listdir(trial_dir):
            if entry in keep_names:
                continue
            victim = os.path.join(trial_dir, entry)
            if os.path.isdir(victim):
                shutil.rmtree(victim, ignore_errors=True)
            else:
                try:
                    os.remove(victim)
                except OSError:
                    pass
        base._log(logfh, f"trial {trial_idx}: артефакты сохранены -> {keep_root}")
    else:
        shutil.rmtree(trial_dir, ignore_errors=True)
    return result


# --------------------------------------------------------------------------
# PRIMARY axis: time-to-reach survival
# --------------------------------------------------------------------------

def time_to_reach(codec_reach, ids, budget):
    """First snapshot time at which any of ``ids`` is reached, with event=1;
    else (budget, 0) — right-censored. ``codec_reach`` = [(t, [reached ids]), ...]."""
    want = set(ids)
    for t, reached in codec_reach:
        if want & set(reached):
            return float(t), 1
    return float(budget), 0


def survival_axis(by_trial):
    """For each codec gate: per-arm (times, events) over the N trials, the
    pairwise log-rank of ours vs every other arm (Holm-corrected across that
    gate's family), and the predregistered win flag (ours significantly ahead of
    BOTH no-I2S baselines). Returns {gate: {...}}."""
    out = {}
    for gate, ids in CODEC_GATES.items():
        tte = {k: ([], []) for k in FUZZERS}
        for tr in by_trial:
            budget = tr["budget"]
            for key in FUZZERS:
                cr = tr["fuzzers"][key].get("codec_reach", [])
                t, e = time_to_reach(cr, ids, budget)
                tte[key][0].append(t)
                tte[key][1].append(e)

        rows = []
        for other in [k for k in FUZZERS if k != "mlfuzzz3"]:
            ta, ea = tte["mlfuzzz3"]
            tb, eb = tte[other]
            chi2, p, status = survival.logrank_test(ta, ea, tb, eb)
            rows.append([other, chi2, p, status])
        adj = mw.holm_bonferroni([r[2] for r in rows])
        rows = [r + [a] for r, a in zip(rows, adj)]  # [other, chi2, p, status, holm]

        # Predreg: ours reaches AND beats both no-I2S baselines (Holm p < 0.05).
        # "ours reaches" guards against a degenerate gate where nobody reaches.
        ours_reaches = any(e for e in tte["mlfuzzz3"][1])
        no_i2s = {r[0]: r[4] for r in rows if r[0] in BASELINES_NO_I2S}
        won = ours_reaches and all(p < 0.05 for p in no_i2s.values())
        out[gate] = {"tte": tte, "rows": rows, "won": won,
                     "ours_reaches": ours_reaches}
    return out


def _km_series_on_grid(tte, grid):
    """Kaplan-Meier S(t) per arm, sampled onto ``grid`` as a flat (no-band)
    series for cb.render_svg. S = fraction NOT yet reached."""
    series = {}
    for key in FUZZERS:
        times, events = tte[key]
        steps = survival.kaplan_meier(times, events)  # [(t, S)], right-continuous
        vals = []
        for g in grid:
            s = 1.0
            for st, sv in steps:
                if st <= g:
                    s = sv
                else:
                    break
            vals.append(s)
        series[DISPLAY[key]] = {"median": vals, "lo": vals, "hi": vals}
    return series


# --------------------------------------------------------------------------
# Aggregation: primary survival + secondary MW, figures, report
# --------------------------------------------------------------------------

def aggregate_and_render(checkpoints, cfg, args, logfh):
    grid = cfg.grid
    by_trial = [checkpoints[i] for i in sorted(checkpoints)]
    n = len(by_trial)
    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    # --- SECONDARY axes (region coverage + oracle reach/trigger), MW+Holm ---
    region_curves = {k: [] for k in FUZZERS}
    trig_curves = {k: [] for k in FUZZERS}
    reach_curves = {k: [] for k in FUZZERS}
    finals = {"regions": {k: [] for k in FUZZERS},
              "reached": {k: [] for k in FUZZERS},
              "triggered": {k: [] for k in FUZZERS}}
    for tr in by_trial:
        for key in FUZZERS:
            fz = tr["fuzzers"][key]
            region_curves[key].append([tuple(p) for p in fz["regions"]])
            trig_curves[key].append([tuple(p) for p in fz["triggered"]])
            reach_curves[key].append([tuple(p) for p in fz["reached"]])
            finals["regions"][key].append(fz["final_regions"])
            finals["reached"][key].append(fz["final_reached"])
            finals["triggered"][key].append(fz["final_triggered"])

    region_series, trig_series, reach_series = {}, {}, {}
    for key in FUZZERS:
        region_series[DISPLAY[key]] = base.build_axis_series(region_curves[key], grid)
        trig_series[DISPLAY[key]] = base.build_axis_series(trig_curves[key], grid)
        reach_series[DISPLAY[key]] = base.build_axis_series(reach_curves[key], grid)

    with open(os.path.join(out_dir, "coverage_curve.svg"), "w", encoding="utf-8") as fh:
        fh.write(cb.render_svg(grid, region_series,
                               title=f"libtiff region coverage vs wall-clock (N={n})",
                               ylabel="region coverage", log_x=True))
    with open(os.path.join(out_dir, "bugs_curve.svg"), "w", encoding="utf-8") as fh:
        fh.write(cb.render_svg(grid, trig_series,
                               title=f"libtiff bug-oracle triggered bugs vs wall-clock (N={n})",
                               ylabel="triggered bugs", log_x=True, y_integer_ticks=True))

    sec_stats = {axis: _pairwise_vs_ours(finals[axis])
                 for axis in ("regions", "reached", "triggered")}

    # --- PRIMARY axis (time-to-reach survival, log-rank) ---
    surv = survival_axis(by_trial)
    for gate, data in surv.items():
        km = _km_series_on_grid(data["tte"], grid)
        with open(os.path.join(out_dir, f"survival_{gate}.svg"), "w", encoding="utf-8") as fh:
            fh.write(cb.render_svg(
                grid, km,
                title=f"libtiff {gate}-gate: P(not yet reached) vs wall-clock (N={n})",
                ylabel="survival S(t)", log_x=True))
    won = sum(1 for d in surv.values() if d["won"])

    report = _render_report(args, cfg, grid, n, finals, sec_stats, surv, won, by_trial)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    base._log(logfh, f"wrote {out_dir}/coverage_curve.svg, bugs_curve.svg, "
                     f"survival_*.svg, report.md")

    degen = {}
    for key in FUZZERS:
        degen[key] = {
            "regions": region_series[DISPLAY[key]]["median"][-1] if grid else 0,
            "reached": reach_series[DISPLAY[key]]["median"][-1] if grid else 0,
            "triggered": trig_series[DISPLAY[key]]["median"][-1] if grid else 0,
        }
    base._log(logfh, f"primary delta: {won}/{len(CODEC_GATES)} codec-gates won "
                     f"(ours > both no-I2S baselines, Holm p<0.05); "
                     f"threshold >=2 -> {'MET' if won >= 2 else 'NOT MET'}")
    return degen


def _pairwise_vs_ours(per_arm_finals):
    """Mann-Whitney U + Holm over (ours vs each other arm) for a secondary axis.
    Returns [(other, u, p, holm)]. Holm family = the three ours-vs-baseline pairs."""
    raw = []
    for other in [k for k in FUZZERS if k != "mlfuzzz3"]:
        try:
            u, p = mw.mannwhitneyu(per_arm_finals["mlfuzzz3"], per_arm_finals[other])
        except ValueError:
            u, p = float("nan"), 1.0
        raw.append((other, u, p))
    adj = mw.holm_bonferroni([r[2] for r in raw])
    return [(o, u, p, a) for (o, u, p), a in zip(raw, adj)]


def _render_report(args, cfg, grid, n, finals, sec_stats, surv, won, by_trial):
    L = []
    L.append("# Comparative benchmark — Magma libtiff (ADR 0046 demonstrator)\n")
    L.append(f"N={n} trials, per-trial budget {cfg.budget}s, jobs {cfg.jobs}. Four "
             "arms: mlfuzzz3 (ours), AFL++ plain, AFL++ CmpLog, libFuzzer. PRIMARY "
             "axis is time-to-reach each codec-gated bug (log-rank on right-censored "
             "data); region coverage and bug-oracle counts are secondary "
             "(Mann-Whitney+Holm, as ADR 0045).\n")

    L.append("## PRIMARY — time-to-reach codec gates (log-rank + Holm)\n")
    L.append("Pairwise ours vs each arm, per gate. Predregistered delta: ours "
             "reaches AND beats BOTH no-I2S baselines (AFL++ plain, libFuzzer), "
             "Holm-p < 0.05, on >= 2 of 3 gates. The CmpLog arm is the classical "
             "input-to-state CEILING — ours is expected to MATCH it (not beat it) "
             "on these literal codec gates.\n")
    for gate, data in surv.items():
        L.append(f"### Gate {gate} {CODEC_GATES[gate]}")
        reach_counts = {k: sum(e for e in data["tte"][k][1]) for k in FUZZERS}
        L.append("- reached in (of %d trials): %s" % (
            n, ", ".join(f"{DISPLAY[k]}={reach_counts[k]}" for k in FUZZERS)))
        for other, chi2, p, status, holm in data["rows"]:
            chi_s = "nan" if chi2 != chi2 else f"{chi2:.2f}"
            L.append(f"  - mlfuzzz3 vs {DISPLAY[other]}: chi2={chi_s}, p={p:.4f}, "
                     f"Holm-adj={holm:.4f} [{status}]")
        L.append(f"  -> predreg win (ours > both no-I2S, Holm p<0.05): {data['won']}\n")
    L.append(f"**Predregistered result: {won}/{len(CODEC_GATES)} gates won — "
             f"{'MET' if won >= 2 else 'NOT MET'} (threshold >= 2/3). Reported "
             f"regardless of outcome (anti-p-hacking, ADR 0046 F4).**\n")

    L.append("## SECONDARY — region coverage & bug oracle (Mann-Whitney + Holm)\n")
    for axis, label in (("regions", "Final region coverage"),
                        ("reached", "Final reached bugs"),
                        ("triggered", "Final triggered bugs")):
        L.append(f"### {label} (per trial)")
        for key in FUZZERS:
            L.append(f"- {DISPLAY[key]}: {finals[axis][key]}")
        L.append("Mann-Whitney U + Holm (ours vs each arm):")
        for other, u, p, holm in sec_stats[axis]:
            u_s = "nan" if u != u else f"{u:.1f}"
            L.append(f"  - mlfuzzz3 vs {DISPLAY[other]}: U={u_s}, p={p:.4f}, "
                     f"Holm-adj={holm:.4f}")
        L.append("")

    L.append("## Figures\n")
    L.append("- `survival_<gate>.svg` — Kaplan-Meier P(not yet reached) per arm "
             "(ours drops as it solves the codec gate; no-I2S baselines stay high).")
    L.append("- `coverage_curve.svg`, `bugs_curve.svg` — secondary axes (as ADR 0045).\n")
    return "\n".join(L)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _default(*parts):
    return os.path.join(_HERE, "vendor", *parts)


def build_parser():
    p = argparse.ArgumentParser(
        description="Comparative fuzzer benchmark orchestrator — Magma libtiff "
                    "demonstrator (ADR 0046).")
    p.add_argument("--trials", type=int, default=10,
                   help="number of trials N (ADR 0046 Q2: N=10)")
    p.add_argument("--budget", type=int, default=86400,
                   help="per-trial wall-clock budget in seconds (default 24h)")
    p.add_argument("--jobs", type=int, default=5,
                   help="concurrent trials (nominal 5: per_trial=4 arms = 20 "
                        "dedicated cores on a 24-core host). The post-OOM N=10 "
                        "run uses --jobs 3 (12 cores, extra memory headroom).")
    p.add_argument("--snapshots", type=int, default=12,
                   help="number of log-spaced snapshot points (default 12)")
    p.add_argument("--reserve-cores", type=int, default=4,
                   help="CPUs left for OS / replay (default 4)")
    p.add_argument("--out", default=os.path.join(_REPO, "docs", "experiments",
                                                  "comparative-magma-libtiff"),
                   help="aggregated artefacts dir (committed separately)")
    p.add_argument("--work-dir", default=_default("comparative-tiff-work"),
                   help="gitignored intermediate state: pools, checkpoints, log")
    p.add_argument("--seeds", default=_default("magma-src", "targets", "libtiff",
                                               "corpus", "tiff_read_rgba_fuzzer"))
    p.add_argument("--fuzzer", default=os.path.join(_REPO, "build", "src", "cli", "fuzzer"))
    p.add_argument("--exec-server", default=os.path.join(_REPO, "build", "exec-server-bin"))
    p.add_argument("--cov-library", default=os.path.join(
        _REPO, "build", "src", "runtime", "coverage", "libmlfuzzz3_cov.so"))
    p.add_argument("--ours-bin", default=_default("out-tiff", "tiff_read_rgba_fuzzer"))
    p.add_argument("--afl-bin", default=_default("out-afl-tiff", "tiff_read_rgba_fuzzer"),
                   help="plain forkserver binary (both AFL arms fuzz this)")
    p.add_argument("--afl-cmplog-bin",
                   default=_default("out-afl-cmplog-tiff", "tiff_read_rgba_fuzzer"),
                   help="CmpLog companion binary (afl-fuzz -c) for the cmplog arm")
    p.add_argument("--lf-bin", default=_default("out-libfuzzer-tiff", "tiff_read_rgba_fuzzer"))
    p.add_argument("--cov-bin", default=_default("out-cov-tiff", "tiff_read_rgba_fuzzer"))
    p.add_argument("--canary-bin", default=_default("out-tiff", "tiff_read_rgba_fuzzer"),
                   help="canary build (canaries ON) for the oracle axis")
    p.add_argument("--oracle-read", default=_default("oracle", "oracle_read"))
    p.add_argument("--target-args", default="",
                   help="args passed to the target (libtiff harness takes none)")
    p.add_argument("--require-nondegenerate", action="store_true",
                   help="exit non-zero if any arm's final region OR reached median "
                        "is 0 (pre-flight STOP gate)")
    p.add_argument("--arms", choices=("v1", "v2"), default="v1",
                   help="v1 — четвёрка ADR-0046 (умолчание, прежний прогон "
                        "воспроизводится без новых флагов); v2 — пятёрка "
                        "ADR-0048 с плечом mlfuzzz3 --no-concolic")
    p.add_argument("--afl-no-autodict", action="store_true",
                   help="AFL_NO_AUTODICT=1 плечу afl-plain (ADR 0048): без него "
                        "плечо не является базовой линией БЕЗ input-to-state. "
                        "Включается само при --arms v2")
    p.add_argument("--keep-artifacts", action="store_true",
                   help="оставить fuzzer_stats, plot_data, финальные корпуса и "
                        "metrics.jsonl в trials/trial_NNN/artifacts/ (ADR 0048). "
                        "Включается само при --arms v2")
    return p


def _file_facts(path):
    """Путь (относительно корня репозитория, если он под ним), md5 и размер."""
    rel = os.path.relpath(path, _REPO) if path.startswith(_REPO + os.sep) else path
    out = {"path": rel}
    try:
        with open(path, "rb") as fh:
            digest = hashlib.md5()
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        out["md5"] = digest.hexdigest()
        out["size"] = os.path.getsize(path)
    except OSError as exc:
        out["error"] = str(exc)
    return out


def _throttle_defaults():
    """Умолчания ADR-0038 ЧИТАЮТСЯ из заголовка, а не переписываются сюда:
    пересказ протухает молча, чтение — нет."""
    out = {}
    header = os.path.join(_REPO, "src", "concolic", "throttle.h")
    try:
        text = open(header, encoding="utf-8").read()
    except OSError as exc:
        return {"error": str(exc)}
    for name, key in (("kDefaultThrottleWindow", "window"),
                      ("kDefaultThrottleMinSamples", "min_samples"),
                      ("kDefaultThrottleUnsatRatio", "unsat_ratio"),
                      ("kDefaultThrottleBaseInterval", "base_interval"),
                      ("kDefaultThrottleMaxShift", "max_shift")):
        m = re.search(rf"{name}\s*=\s*([0-9.]+)", text)
        if m:
            out[key] = float(m.group(1)) if "." in m.group(1) else int(m.group(1))
    campaign_h = os.path.join(_REPO, "src", "core", "campaign.h")
    try:
        m = re.search(r"bool concolic_adaptive_throttle\s*=\s*(true|false)",
                      open(campaign_h, encoding="utf-8").read())
        if m:
            out["adaptive_throttle_default"] = (m.group(1) == "true")
    except OSError:
        pass
    # У адаптивного throttle НЕТ флага CLI (grep по src/cli/args.cpp): плечо
    # «throttle-on» — это просто сегодняшняя сборка по умолчанию, и отличие
    # от N=10 состоит в БИНАРЕ, а не в конфигурации прогона.
    out["cli_switch"] = None
    return out


def _fuzzer_build_z3():
    cache = os.path.join(_REPO, "build", "CMakeCache.txt")
    try:
        for line in open(cache, encoding="utf-8"):
            if line.startswith("FUZZER_BUILD_Z3:"):
                return line.strip().split("=", 1)[1]
    except OSError:
        pass
    return None


def _git_head():
    try:
        return subprocess.run(["git", "-C", _REPO, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def check_arms_marker(work_dir, arms):
    """Запретить смешивать наборы плеч в одном рабочем каталоге.

    Отпечаток движка (`comparative_run._config_fingerprint`) сравнивает только
    trials/budget/snapshots/target_args и про плечи ничего не знает — значит
    прогон, начатый на пяти плечах, можно молча продолжить на четырёх, и в
    одном каталоге окажутся чекпойнты разной формы. Чинить сам отпечаток
    нельзя: добавление ключа обнулило бы возобновление ВСЕХ уже начатых
    прогонов, включая libpng. Поэтому набор плеч держится отдельным маркером
    рядом с ним.
    """
    path = os.path.join(work_dir, "arms.json")
    current = list(arms)
    if os.path.exists(path):
        try:
            saved = json.load(open(path, encoding="utf-8"))
        except ValueError:
            saved = None
        if saved != current:
            raise SystemExit(
                f"comparative_run_tiff: --work-dir {work_dir} держит прогон на "
                f"плечах {saved}, а этот запуск — на {current}. Возьмите свежий "
                f"--work-dir или тот же набор плеч."
            )
        return "resumed"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(current, fh)
    return "created"


def write_config_json(args, cfg, cores, grid, out_dir):
    """Полная конфигурация прогона рядом с отчётом (ADR 0048).

    Кампания N=10 не оставила ни раскладки по ядрам, ни md5 бинарей, ни
    значений throttle — поэтому её условия сегодня восстанавливаются по
    косвенным признакам. Здесь они записываются прямо, до первого трайла.
    Раскладка по ядрам проверяется на конфликт: два плеча на одном ядре —
    ошибка конфигурации, а не мелочь.
    """
    affinity, seen = {}, {}
    conflicts = []
    for slot in range(cfg.jobs):
        try:
            slot_cores = base.assign_cores(slot, len(cfg.arms), cores)
        except ValueError as exc:
            affinity[f"slot{slot}"] = {"error": str(exc)}
            continue
        affinity[f"slot{slot}"] = dict(zip(cfg.arms, slot_cores))
        for arm, core in zip(cfg.arms, slot_cores):
            if core in seen:
                conflicts.append(f"core {core}: {seen[core]} и slot{slot}/{arm}")
            seen[core] = f"slot{slot}/{arm}"

    config = {
        "adr": "0048" if args.arms == "v2" else "0046",
        "arms": list(cfg.arms),
        "arm_display": {k: DISPLAY[k] for k in cfg.arms},
        "trials": cfg.trials,
        "budget_s": cfg.budget,
        "jobs": cfg.jobs,
        "snapshots": len(grid),
        "rng_seeds": [1000 + i for i in range(cfg.trials)],
        "afl_no_autodict": cfg.afl_no_autodict,
        "keep_artifacts": cfg.keep_artifacts,
        "core_pool": list(cores),
        "affinity": affinity,
        "affinity_conflicts": conflicts,
        "git_head": _git_head(),
        "fuzzer_build_z3": _fuzzer_build_z3(),
        "throttle": _throttle_defaults(),
        "binaries": {
            "fuzzer": _file_facts(cfg.fuzzer),
            "exec_server": _file_facts(cfg.exec_server),
            "cov_library": _file_facts(cfg.cov_library),
            "ours_bin": _file_facts(cfg.ours_bin),
            "afl_bin": _file_facts(cfg.afl_bin),
            "afl_cmplog_bin": _file_facts(cfg.afl_cmplog_bin),
            "lf_bin": _file_facts(cfg.lf_bin),
            "cov_bin": _file_facts(cfg.cov_bin),
            "canary_bin": _file_facts(cfg.canary_bin),
            "oracle_read": _file_facts(cfg.oracle_read),
        },
    }
    os.makedirs(out_dir, exist_ok=True)
    # Движок держит СВОЙ config.json (отпечаток возобновления) в --work-dir.
    # Обычно это разные каталоги, но если оператор направил --out туда же,
    # одноимённый файл затёр бы отпечаток и сломал возобновление.
    name = "config.json"
    if os.path.abspath(out_dir) == os.path.abspath(getattr(cfg, "work_dir", "")):
        name = "campaign-config.json"
    path = os.path.join(out_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    return path, conflicts


def _validate_binaries(args):
    missing = []
    for label, path in (("fuzzer", args.fuzzer), ("exec-server", args.exec_server),
                        ("cov-library", args.cov_library), ("ours-bin", args.ours_bin),
                        ("afl-bin", args.afl_bin), ("afl-cmplog-bin", args.afl_cmplog_bin),
                        ("lf-bin", args.lf_bin), ("cov-bin", args.cov_bin),
                        ("canary-bin", args.canary_bin), ("oracle-read", args.oracle_read)):
        if not os.path.exists(path):
            missing.append(f"{label}={path}")
    if not os.path.isdir(args.seeds):
        missing.append(f"seeds={args.seeds}")
    return missing


def main(argv=None):
    args = build_parser().parse_args(argv)

    # Набор плеч выбирается ОДИН раз и до всего остального: от него зависят и
    # раскладка по ядрам, и состав чекпойнта.
    select_arms(args.arms)
    if args.arms == "v2":
        # ADR 0048: и то и другое — часть определения кампании v2, а не
        # настройка вкуса. Явные флаги их и так включают; здесь они просто
        # не дают забыть.
        args.afl_no_autodict = True
        args.keep_artifacts = True

    missing = _validate_binaries(args)
    if missing:
        print("comparative_run_tiff: missing prerequisites (build the arms first):",
              file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 2

    nproc = os.cpu_count() or 4
    try:
        cores = base.campaign_cores(nproc, args.jobs, len(FUZZERS), args.reserve_cores)
    except ValueError as exc:
        print(f"comparative_run_tiff: {exc}", file=sys.stderr)
        return 2
    grid = ir.log_spaced_grid(args.budget, args.snapshots, first=1.0)

    os.makedirs(args.work_dir, exist_ok=True)
    logfh = open(os.path.join(args.work_dir, "run.log"), "a", encoding="utf-8")
    try:
        base._check_resume_config(args.work_dir, args, logfh)
        cfg = Config(args, grid, cores)

        arms_state = check_arms_marker(args.work_dir, cfg.arms)
        base._log(logfh, f"набор плеч: {list(cfg.arms)} ({arms_state})")
        cfg_path, conflicts = write_config_json(args, cfg, cores, grid, args.out)
        base._log(logfh, f"config -> {cfg_path}; arms={list(cfg.arms)}; "
                         f"afl_no_autodict={cfg.afl_no_autodict}; "
                         f"keep_artifacts={cfg.keep_artifacts}")
        if conflicts:
            # Два плеча на одном ядре обесценивают ЛЮБОЕ сравнение по времени,
            # поэтому это отказ запуска, а не предупреждение.
            for line in conflicts:
                print(f"comparative_run_tiff: конфликт ядер — {line}", file=sys.stderr)
            return 2

        done = base.load_checkpoints(args.work_dir, args.trials)
        todo = base.pending_trials(args.trials, done.keys())
        base._log(logfh, f"run start: {args.trials} trials, budget {args.budget}s, "
                         f"jobs {args.jobs}, cores {cores}, grid {len(grid)} pts; "
                         f"{len(done)} done, {len(todo)} to run: {todo}")

        if todo:
            replay_lock = threading.Lock()
            slot_q = queue.Queue()
            for s in range(args.jobs):
                slot_q.put(s)
            errors = []
            lock = threading.Lock()

            def worker(trial_idx):
                slot = slot_q.get()
                try:
                    res = run_trial(trial_idx, slot, cfg, args.work_dir, logfh,
                                    replay_lock)
                    with lock:
                        done[trial_idx] = res
                except Exception as exc:  # noqa: BLE001 - record + continue others
                    with lock:
                        errors.append((trial_idx, repr(exc)))
                    base._log(logfh, f"trial {trial_idx}: FAILED — {exc!r}")
                finally:
                    slot_q.put(slot)

            threads, running = [], []
            for trial_idx in todo:
                t = threading.Thread(target=worker, args=(trial_idx,))
                t.start()
                threads.append(t)
                running.append(t)
                while sum(1 for x in running if x.is_alive()) >= args.jobs:
                    time.sleep(0.5)
            for t in threads:
                t.join()

            if errors:
                base._log(logfh, f"run: {len(errors)} trial(s) failed: {errors}")
                print(f"comparative_run_tiff: {len(errors)} trial(s) failed: {errors}",
                      file=sys.stderr)
                return 3

        done = base.load_checkpoints(args.work_dir, args.trials)
        if len(done) < args.trials:
            base._log(logfh, f"run: only {len(done)}/{args.trials} trials complete — "
                             f"no aggregation (resume to finish)")
            return 4

        degen = aggregate_and_render(done, cfg, args, logfh)
        base._log(logfh, f"degeneracy check (final medians): {degen}")
        if args.require_nondegenerate:
            bad = [k for k, v in degen.items() if v["regions"] <= 0 or v["reached"] <= 0]
            if bad:
                base._log(logfh, f"STOP: degenerate arm(s): {bad}")
                print(f"comparative_run_tiff: STOP — degenerate arm(s): {bad}",
                      file=sys.stderr)
                return 5
            base._log(logfh, "pre-flight gate: OK — all arms non-degenerate")
        base._log(logfh, "run complete")
        return 0
    finally:
        logfh.close()


if __name__ == "__main__":
    raise SystemExit(main())
