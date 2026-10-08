"""Comparative fuzzer benchmark orchestrator — Magma libpng slice.

ADR 0045 Развилка G: EXECUTION of the accepted methodology (ADR 0032 form:
N>=5 trials, long wall-clock per trial, Mann-Whitney+Holm; host-only manual
entry). This is glue over the proven Steps 0-7 primitives — it introduces no
new measurement algorithm:

  * per-fuzzer run/harvest commands ........ scripts/fuzzer_drivers.py (Step 6)
  * neutral region coverage (incremental) .. scripts/incremental_replay.py (5)
  * bug-oracle fork-exec replay model ...... benchmarks/magma/oracle_axis_gate
                                             .sh + vendor/oracle/oracle_read (4)
  * Mann-Whitney U + Holm-Bonferroni ....... scripts/stats/mannwhitney.py (0032)
  * curve resample / aggregate / SVG ....... scripts/comparative_benchmark.py (44)

It runs three fuzzers (ours, AFL++, libFuzzer — racing builds) for ``--trials``
trials of ``--budget`` wall-clock seconds each, on two axes measured POST-HOC:

  Axis 1 — region coverage(t): each fuzzer's corpus snapshot is replayed
           through the single ``-fcoverage-mapping`` measurement build
           (vendor/out-cov), incrementally (O(total inputs), Step 5), giving a
           neutral regions(t) curve.
  Axis 2 — bug-oracle(t): each snapshot's inputs are fork-exec replayed
           single-threaded through the canary build (vendor/out, canaries ON),
           accumulating reach/trigger counters in a per-(trial,fuzzer)
           MAGMA_STORAGE file; oracle_read yields the SET of reached/triggered
           bug ids at each snapshot. The fork-exec-per-input harvest model is
           the one the Step-4 gate proved equivalent to Magma's own
           ``monitor --fetch watch`` ground truth.

Campaign isolation (protects the time axis): every campaign is pinned to its
own dedicated CPU with ``taskset -c``; two campaigns never share a core. The
default ``--jobs 1`` runs one trial's three fuzzers in parallel (3 cores) with
trials sequential, leaving the rest of the host for the OS and post-hoc replay.

Snapshots use a log-spaced time grid (dense early, sparse late — Развилка E /
ADR 0044 Step 8) and are taken DURING the campaign as a hardlink pool (no full
corpus copy — the 24h disk budget rules that out; hardlinks share the inode so
they also survive a fuzzer rewriting/rotating its dir). Replay is POST-HOC so
its CPU never perturbs a running campaign.

Per-trial checkpoints make the run resumable: each completed trial's raw curves
(both axes, all three fuzzers) are written to ``<work>/checkpoints/`` and a
restart continues with the unfinished trials, losing no finished work.

Aggregation: numpy median + min/max band across trials, both axes -> two
dependency-free SVGs (regions(t), triggered-bugs(t)); Mann-Whitney+Holm on the
final value of each axis, pairwise across the three fuzzers.

Host-only research tooling; NOT a CI gate. Final aggregated artefacts land in
``--out`` (docs/experiments/comparative-magma-libpng/, committed separately on
run completion); all intermediate state (snapshot pools, per-trial checkpoints,
the run log) lives under the gitignored ``--work-dir``.

The pure helpers (parse_oracle_dump, pending_trials, assign_cores,
build_axis_series, pairwise_stats) are unit-tested without fuzzing
(test_comparative_run.py); the orchestration needs the host binaries and is
exercised end-to-end by the pre-flight (smoke_comparative_run.sh).
"""

from __future__ import annotations

import argparse
import json
import os
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

import comparative_benchmark as cb  # noqa: E402  (resample_curve, aggregate, render_svg)
import coverage_replay as cr  # noqa: E402
import fuzzer_drivers as fd  # noqa: E402
import incremental_replay as ir  # noqa: E402
import mannwhitney as mw  # noqa: E402

try:
    import numpy as np
except ImportError:  # pragma: no cover - numpy is a host dependency
    np = None


# Display names + order; "key" is the internal id used in checkpoints.
FUZZERS = ("mlfuzzz3", "afl", "libfuzzer")
DISPLAY = {"mlfuzzz3": "mlfuzzz3", "afl": "AFL++", "libfuzzer": "libFuzzer"}

# Magma canary storage is a fixed-size mmap'd file; mirror the Step-4 model
# exactly (oracle_axis_gate.sh / smoke_three_fuzzers.sh zero-init 2048 bytes).
_CANARY_STORAGE_BYTES = 2048

# Seconds of slack past the budget before a stuck campaign is force-terminated.
_HARD_LIMIT_SLACK = 120.0


# --------------------------------------------------------------------------
# Pure helpers (unit-tested without binaries)
# --------------------------------------------------------------------------

def parse_oracle_dump(text):
    """Parse ``oracle_read`` output ("NAME REACHED TRIGGERED" per line) into
    ``(reached_set, triggered_set)`` of bug ids — the oracle-axis metric is the
    SET (binary per bug); counters are secondary. Pure."""
    reached, triggered = set(), set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        try:
            r = int(parts[1])
            t = int(parts[2])
        except ValueError:
            continue
        if r > 0:
            reached.add(name)
        if t > 0:
            triggered.add(name)
    return reached, triggered


def pending_trials(total, done):
    """Trial indices in ``[0, total)`` not present in the ``done`` set (the
    resume work-list)."""
    return [i for i in range(total) if i not in set(done)]


def assign_cores(slot, per_trial, cores):
    """Dedicated CPU ids for one concurrently-running trial ``slot``.

    ``cores`` is the ordered pool of usable campaign CPUs; slot ``s`` claims the
    contiguous block ``[s*per_trial, s*per_trial+per_trial)``. No two slots
    overlap, so no two campaigns share a core. Raises if the pool is too small.
    """
    base = slot * per_trial
    if base + per_trial > len(cores):
        raise ValueError(
            f"core pool too small: slot {slot} needs {per_trial} cores from "
            f"{cores} (raise the pool or lower --jobs)"
        )
    return [cores[base + f] for f in range(per_trial)]


def campaign_cores(nproc, jobs, per_trial=3, reserve=2):
    """The CPU pool for campaigns: the first ``nproc-reserve`` CPUs, enough for
    ``jobs`` concurrent trials of ``per_trial`` fuzzers each. Leaves ``reserve``
    CPUs for the OS / snapshotting / post-hoc replay (ADR 0045 isolation rule).
    Raises if ``jobs`` does not fit."""
    usable = max(0, nproc - reserve)
    need = jobs * per_trial
    if need > usable:
        raise ValueError(
            f"--jobs {jobs} needs {need} dedicated cores but only {usable} are "
            f"usable ({nproc} cpus minus {reserve} reserved). Lower --jobs."
        )
    return list(range(need))


def build_axis_series(per_trial_curves, grid):
    """Aggregate per-trial ``[(elapsed, value), ...]`` curves onto ``grid`` ->
    ``{"median": [...], "lo": [...], "hi": [...]}`` (numpy median + min/max
    band). Reuses the ADR-0044 step-resample + aggregate 1:1."""
    resampled = [cb.resample_curve(curve, grid) for curve in per_trial_curves]
    median, lo, hi = cb.aggregate(resampled)
    return {"median": median, "lo": lo, "hi": hi}


def pairwise_stats(finals):
    """Mann-Whitney U + Holm-Bonferroni over the three pairwise comparisons of
    one axis. ``finals`` = {key: [final value per trial]}. Returns a list of
    ``(a, b, u, p, p_holm)`` in a fixed pair order; the Holm family is the three
    pairs of THIS axis (ADR 0045: per-axis pairwise across the three fuzzers)."""
    pairs = [("mlfuzzz3", "afl"), ("mlfuzzz3", "libfuzzer"), ("afl", "libfuzzer")]
    raw = []
    for a, b in pairs:
        try:
            u, p = mw.mannwhitneyu(finals[a], finals[b])
        except ValueError:
            u, p = float("nan"), 1.0
        raw.append((a, b, u, p))
    adjusted = mw.holm_bonferroni([r[3] for r in raw])
    return [(a, b, u, p, adj) for (a, b, u, p), adj in zip(raw, adjusted)]


# --------------------------------------------------------------------------
# Snapshot hardlink pool
# --------------------------------------------------------------------------

class HardlinkPool:
    """A growing hardlink farm for one (trial, fuzzer) campaign.

    A snapshot is NOT a copy of the corpus (the 24h disk budget forbids it): at
    each log-spaced time we hardlink every not-yet-seen harvested input into a
    flat pool under a sequential name. A hardlink shares the source inode, so it
    costs only a dir entry and survives the fuzzer later deleting/rotating the
    original — and it always reads the input's final bytes (no torn mid-write
    copy). A "snapshot" is then just the pool prefix length at that time; the
    full cumulative input list for snapshot ``i`` is the first ``cut[i]`` pool
    files. Content dedup is left to the replay layer (incremental_replay /
    oracle), so a path appearing in two harvests is linked once here and a
    byte-identical input is replayed once there.
    """

    def __init__(self, pool_dir):
        self.pool_dir = pool_dir
        os.makedirs(pool_dir, exist_ok=True)
        self._seen_src = set()
        self._files = []  # pool paths in insertion order

    def add_harvest(self, paths):
        """Hardlink any new source ``paths`` into the pool; return current size."""
        for src in paths:
            real = os.path.realpath(src)
            if real in self._seen_src:
                continue
            self._seen_src.add(real)
            dest = os.path.join(self.pool_dir, f"{len(self._files):08d}")
            try:
                os.link(src, dest)
            except OSError:
                # Cross-device or vanished mid-link: fall back to a copy so the
                # snapshot is never silently short an input.
                try:
                    shutil.copy2(src, dest)
                except OSError:
                    continue
            self._files.append(dest)
        return len(self._files)

    @property
    def size(self):
        return len(self._files)

    def prefix(self, cut):
        """The first ``cut`` pool files (a cumulative snapshot's input list)."""
        return self._files[:cut]


# --------------------------------------------------------------------------
# Oracle-axis replay (fork-exec, single-threaded, content-dedup, incremental)
# --------------------------------------------------------------------------

def replay_oracle_incremental(canary_bin, oracle_read, snapshots, target_args=(),
                              mem_limit_bytes=None):
    """Replay cumulative corpus ``snapshots`` through the canary build and
    return ``[(reached_set, triggered_set), ...]``, one per snapshot.

    The accepted Step-4 harvest model: one fresh fork-exec per input (a fresh
    per-process latch, ADR 0011), input on stdin, counters accumulating in one
    shared MAGMA_STORAGE file. Counter accumulation across processes is
    commutative and the bug SET is monotone, so feeding each unique input once
    into a persistent storage is identical to a full re-replay of every
    cumulative snapshot (same equivalence as the coverage axis, Step 5) — at
    O(total inputs) instead of O(snapshots x corpus). Single-threaded by
    construction. ``oracle_read`` is run on the storage after each snapshot's
    new inputs to read the cumulative sets.
    """
    storage = None
    seen = set()
    results = []
    try:
        storage = _new_canary_storage()
        for snapshot in snapshots:
            for input_path in snapshot:
                digest = ir.file_hash(input_path)
                if digest in seen:
                    continue
                seen.add(digest)
                with open(input_path, "rb") as handle:
                    subprocess.run(
                        [canary_bin, *target_args],
                        stdin=handle,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env={**os.environ, "MAGMA_STORAGE": storage},
                        check=False,
                        preexec_fn=ir.rlimit_as_preexec(mem_limit_bytes),
                    )
            dumped = subprocess.run(
                [oracle_read, storage],
                check=False,
                capture_output=True,
                text=True,
            )
            results.append(parse_oracle_dump(dumped.stdout))
        return results
    finally:
        if storage and os.path.exists(storage):
            os.unlink(storage)


def _new_canary_storage():
    """A fresh zero-initialised MAGMA_STORAGE file (mirrors the Step-4 model's
    ``head -c 2048 /dev/zero``)."""
    import tempfile
    fd_, path = tempfile.mkstemp(prefix="mlf_canary_", suffix=".raw")
    with os.fdopen(fd_, "wb") as handle:
        handle.write(b"\x00" * _CANARY_STORAGE_BYTES)
    return path


# --------------------------------------------------------------------------
# Campaign plans (which command / harvest / env per fuzzer)
# --------------------------------------------------------------------------

def _campaign_plan(key, cfg, core, trial_dir, trial_idx):
    """Build the run plan for one fuzzer in one trial: argv (taskset-pinned),
    env, cwd, output dirs and a zero-arg harvest closure over the live dirs."""
    taskset = ["taskset", "-c", str(core)]
    target_args = cfg.target_args

    if key == "mlfuzzz3":
        out = os.path.join(trial_dir, "mlfuzzz3_out")
        cmd = fd.our_command(
            {"fuzzer": cfg.fuzzer, "exec_server": cfg.exec_server,
             "target": cfg.ours_bin, "cov_library": cfg.cov_library},
            seed_dir=cfg.seeds, out_dir=out, max_seconds=cfg.budget,
            target_args=" ".join(target_args), rng_seed=1000 + trial_idx,
        )
        return _Plan(taskset + cmd, dict(os.environ), None,
                     lambda: fd.harvest_ours(out))

    if key == "afl":
        out = os.path.join(trial_dir, "afl_out")
        os.makedirs(out, exist_ok=True)
        cmd = fd.afl_command(cfg.afl_bin, seed_dir=cfg.seeds, out_dir=out,
                             max_seconds=cfg.budget, target_args=tuple(target_args))
        # taskset owns affinity; tell AFL not to fight it for a free core.
        env = {**os.environ, **fd.afl_env({"AFL_NO_AFFINITY": "1"})}
        return _Plan(taskset + cmd, env, None, lambda: fd.harvest_afl(out))

    if key == "libfuzzer":
        corpus = os.path.join(trial_dir, "libfuzzer_corpus")
        artifacts = os.path.join(trial_dir, "libfuzzer_artifacts")
        os.makedirs(corpus, exist_ok=True)
        os.makedirs(artifacts, exist_ok=True)
        cmd = fd.lf_command(cfg.lf_bin, seed_dir=cfg.seeds, out_corpus=corpus,
                            max_seconds=cfg.budget, artifact_dir=artifacts,
                            target_args=tuple(target_args))
        return _Plan(taskset + cmd, dict(os.environ), artifacts,
                     lambda: fd.harvest_libfuzzer(corpus, artifacts))

    raise ValueError(f"unknown fuzzer key: {key}")


class _Plan:
    __slots__ = ("cmd", "env", "cwd", "harvest")

    def __init__(self, cmd, env, cwd, harvest):
        self.cmd = cmd
        self.env = env
        self.cwd = cwd
        self.harvest = harvest


# --------------------------------------------------------------------------
# Per-trial orchestration
# --------------------------------------------------------------------------

class Config:
    """Resolved run configuration (CLI args + derived grid/cores)."""

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
        self.lf_bin = args.lf_bin
        self.cov_bin = args.cov_bin
        self.canary_bin = args.canary_bin
        self.oracle_read = args.oracle_read
        self.target_args = tuple(args.target_args.split()) if args.target_args else ()


def _log(logfh, message):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    line = f"[{stamp}] {message}"
    print(line, flush=True)
    if logfh is not None:
        logfh.write(line + "\n")
        logfh.flush()


def run_trial(trial_idx, slot, base_cfg, work_dir, logfh, replay_lock):
    """Run one trial (three campaigns) and write its checkpoint. Returns the
    checkpoint dict. Campaigns race in parallel pinned to dedicated cores;
    snapshots are hardlinked on the log-spaced grid; replay is post-hoc."""
    cfg = base_cfg
    cores = assign_cores(slot, len(FUZZERS), cfg.cores)
    trial_dir = os.path.join(work_dir, "trials", f"trial_{trial_idx:03d}")
    if os.path.isdir(trial_dir):
        shutil.rmtree(trial_dir, ignore_errors=True)  # stale partial trial
    os.makedirs(trial_dir, exist_ok=True)

    plans, procs, pools, snaps = {}, {}, {}, {}
    for f_idx, key in enumerate(FUZZERS):
        plan = _campaign_plan(key, cfg, cores[f_idx], trial_dir, trial_idx)
        plans[key] = plan
        pools[key] = HardlinkPool(os.path.join(trial_dir, key, "pool"))
        snaps[key] = []  # (elapsed, cut)

    _log(logfh, f"trial {trial_idx}: launching 3 campaigns on cores {cores} "
                f"(budget {cfg.budget}s)")
    for key in FUZZERS:
        plan = plans[key]
        logpath = os.path.join(trial_dir, f"{key}.campaign.log")
        with open(logpath, "wb") as clog:
            procs[key] = subprocess.Popen(
                plan.cmd, env=plan.env, cwd=plan.cwd,
                stdout=clog, stderr=subprocess.STDOUT,
            )

    # Snapshot loop: wake at each log-spaced grid time, hardlink fresh inputs.
    start = time.monotonic()
    grid = cfg.grid
    gi = 0
    hard_limit = cfg.budget + _HARD_LIMIT_SLACK
    last_beat = 0.0
    while any(p.poll() is None for p in procs.values()):
        time.sleep(0.5)
        elapsed = time.monotonic() - start
        while gi < len(grid) and elapsed >= grid[gi]:
            for key in FUZZERS:
                size = pools[key].add_harvest(plans[key].harvest())
                snaps[key].append((elapsed, size))
            _log(logfh, f"trial {trial_idx}: snapshot @ {elapsed:.1f}s "
                        f"pool sizes " + ", ".join(
                            f"{key}={pools[key].size}" for key in FUZZERS))
            gi += 1
        if elapsed - last_beat >= 300.0:
            last_beat = elapsed
            _log(logfh, f"trial {trial_idx}: alive @ {elapsed:.0f}s "
                        f"(of {cfg.budget}s)")
        if elapsed > hard_limit:
            _log(logfh, f"trial {trial_idx}: HARD LIMIT {hard_limit:.0f}s — "
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

    # Final snapshot after all campaigns exit (captures the last inputs).
    final_elapsed = time.monotonic() - start
    for key in FUZZERS:
        size = pools[key].add_harvest(plans[key].harvest())
        snaps[key].append((final_elapsed, size))
    _log(logfh, f"trial {trial_idx}: campaigns done @ {final_elapsed:.1f}s; "
                f"final corpora " + ", ".join(
                    f"{key}={pools[key].size}" for key in FUZZERS))

    # POST-HOC replay (serialised across concurrent trials to keep replay off
    # the campaign cores and single-threaded for the oracle).
    result = {"trial": trial_idx, "budget": cfg.budget, "fuzzers": {}}
    with replay_lock:
        for key in FUZZERS:
            cuts = snaps[key]
            snap_inputs = [pools[key].prefix(cut) for _elapsed, cut in cuts]
            times = [elapsed for elapsed, _cut in cuts]

            _log(logfh, f"trial {trial_idx}: [{key}] region replay "
                        f"({pools[key].size} inputs, {len(snap_inputs)} snaps)")
            region_pts = ir.replay_incremental(cfg.cov_bin, snap_inputs,
                                               target_args=cfg.target_args)
            regions = [(t, covered) for t, (covered, _total) in zip(times, region_pts)]

            _log(logfh, f"trial {trial_idx}: [{key}] oracle replay")
            oracle_pts = replay_oracle_incremental(cfg.canary_bin, cfg.oracle_read,
                                                    snap_inputs, target_args=cfg.target_args)
            reached = [(t, len(r)) for t, (r, _tg) in zip(times, oracle_pts)]
            triggered = [(t, len(tg)) for t, (_r, tg) in zip(times, oracle_pts)]
            final_reached = sorted(oracle_pts[-1][0]) if oracle_pts else []
            final_triggered = sorted(oracle_pts[-1][1]) if oracle_pts else []

            result["fuzzers"][key] = {
                "regions": regions,
                "reached": reached,
                "triggered": triggered,
                "final_regions": regions[-1][1] if regions else 0,
                "final_reached": len(final_reached),
                "final_triggered": len(final_triggered),
                "reached_set": final_reached,
                "triggered_set": final_triggered,
                "corpus_size": pools[key].size,
            }
            _log(logfh, f"trial {trial_idx}: [{key}] regions="
                        f"{result['fuzzers'][key]['final_regions']} reached="
                        f"{len(final_reached)} triggered={len(final_triggered)}")

    ckpt_dir = os.path.join(work_dir, "checkpoints")
    os.makedirs(ckpt_dir, exist_ok=True)
    ckpt_path = os.path.join(ckpt_dir, f"trial_{trial_idx:03d}.json")
    tmp_path = ckpt_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    os.replace(tmp_path, ckpt_path)  # atomic: a half-written checkpoint never resumes
    _log(logfh, f"trial {trial_idx}: checkpoint written -> {ckpt_path}")

    # Free disk: the hardlink pools/corpora are no longer needed once the raw
    # curves are checkpointed (a resume re-runs an unfinished trial from zero).
    shutil.rmtree(trial_dir, ignore_errors=True)
    return result


# --------------------------------------------------------------------------
# Checkpoint / resume bookkeeping
# --------------------------------------------------------------------------

def load_checkpoints(work_dir, total):
    """Load completed-trial checkpoints from ``<work>/checkpoints/`` -> dict
    keyed by trial index (only indices in ``[0, total)``)."""
    ckpt_dir = os.path.join(work_dir, "checkpoints")
    done = {}
    if not os.path.isdir(ckpt_dir):
        return done
    for name in sorted(os.listdir(ckpt_dir)):
        if not (name.startswith("trial_") and name.endswith(".json")):
            continue
        with open(os.path.join(ckpt_dir, name), encoding="utf-8") as fh:
            data = json.load(fh)
        idx = data.get("trial")
        if isinstance(idx, int) and 0 <= idx < total:
            done[idx] = data
    return done


def _config_fingerprint(args):
    return {"trials": args.trials, "budget": args.budget,
            "snapshots": args.snapshots, "target_args": args.target_args}


def _check_resume_config(work_dir, args, logfh):
    """Persist (first run) or validate (resume) the run fingerprint; refuse to
    mix incompatible trials/budget/snapshots into one work-dir."""
    path = os.path.join(work_dir, "config.json")
    current = _config_fingerprint(args)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            saved = json.load(fh)
        if saved != current:
            raise SystemExit(
                f"comparative_run: --work-dir {work_dir} holds a run with config "
                f"{saved} but this invocation is {current}. Use a fresh "
                f"--work-dir or matching parameters."
            )
        _log(logfh, f"resuming run in {work_dir} (config matches)")
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(current, fh)


# --------------------------------------------------------------------------
# Aggregation + artefacts
# --------------------------------------------------------------------------

def aggregate_and_render(checkpoints, cfg, args, logfh):
    """Build both axes' series, render two SVGs + report.md into ``--out``, run
    Mann-Whitney+Holm on each axis. Returns a degeneracy report (per fuzzer:
    final region / reached / triggered medians) for the pre-flight gate."""
    grid = cfg.grid
    by_trial = [checkpoints[i] for i in sorted(checkpoints)]

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
        region_series[DISPLAY[key]] = build_axis_series(region_curves[key], grid)
        trig_series[DISPLAY[key]] = build_axis_series(trig_curves[key], grid)
        reach_series[DISPLAY[key]] = build_axis_series(reach_curves[key], grid)

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    n = len(by_trial)
    region_svg = cb.render_svg(
        grid, region_series,
        title=f"libpng region coverage vs wall-clock (N={n})",
        ylabel="region coverage", log_x=True)
    bugs_svg = cb.render_svg(
        grid, trig_series,
        title=f"libpng bug-oracle triggered bugs vs wall-clock (N={n})",
        ylabel="triggered bugs", log_x=True, y_integer_ticks=True)
    with open(os.path.join(out_dir, "coverage_curve.svg"), "w", encoding="utf-8") as fh:
        fh.write(region_svg)
    with open(os.path.join(out_dir, "bugs_curve.svg"), "w", encoding="utf-8") as fh:
        fh.write(bugs_svg)

    stats = {axis: pairwise_stats(finals[axis])
             for axis in ("regions", "reached", "triggered")}

    report = _render_report(args, cfg, grid, n, finals, stats,
                            region_series, trig_series, reach_series, by_trial)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    _log(logfh, f"wrote {out_dir}/coverage_curve.svg, bugs_curve.svg, report.md")

    # Degeneracy report (pre-flight gate): per fuzzer final medians.
    degen = {}
    for key in FUZZERS:
        degen[key] = {
            "regions": region_series[DISPLAY[key]]["median"][-1] if grid else 0,
            "reached": reach_series[DISPLAY[key]]["median"][-1] if grid else 0,
            "triggered": trig_series[DISPLAY[key]]["median"][-1] if grid else 0,
        }
    return degen


def _fmt_pair_stats(rows):
    out = []
    for a, b, u, p, adj in rows:
        out.append(f"  - {DISPLAY[a]} vs {DISPLAY[b]}: U={u:.1f}, p={p:.4f}, "
                   f"Holm-adj={adj:.4f}")
    return "\n".join(out)


def _render_report(args, cfg, grid, n, finals, stats, region_series, trig_series,
                   reach_series, by_trial):
    lines = ["# Comparative benchmark — Magma libpng (ADR 0045, Развилка G)\n"]
    lines.append(
        "Methodology: ADR 0032 form (N>=5 trials, long wall-clock per trial, "
        "Mann-Whitney+Holm), executed on the unsaturated libpng target with a "
        "ground-truth bug oracle over the ADR-0044 neutral coverage frame "
        "(ADR 0045). Three fuzzers race their own instrumented builds under a "
        "shared per-trial wall-clock budget, each pinned to a dedicated core; "
        "corpora are scored POST-HOC on two axes — neutral llvm-cov region "
        "coverage (vendor/out-cov, incremental replay) and the Magma bug oracle "
        "(reached/triggered sets via single-threaded fork-exec canary replay, "
        "the Step-4 accepted model). Snapshots are taken on a log-spaced time "
        "grid as a hardlink pool (no full corpus copy).\n")
    lines.append("## Run\n")
    lines.append(f"- trials (N): {n} (requested {args.trials})")
    lines.append(f"- per-trial wall-clock budget: {cfg.budget} s")
    lines.append(f"- concurrent trials (--jobs): {args.jobs}; campaign cores: {cfg.cores}")
    lines.append(f"- log-spaced snapshot grid (s): "
                 f"{[round(t, 2) for t in grid]}")
    lines.append(f"- target args: `{args.target_args}`")
    lines.append("")
    lines.append("## Final region coverage (per trial)\n")
    for key in FUZZERS:
        lines.append(f"- {DISPLAY[key]}: {finals['regions'][key]}")
    lines.append("")
    lines.append("## Final bug oracle (per trial)\n")
    lines.append("Reached bugs (distinct ids with reach>0):")
    for key in FUZZERS:
        lines.append(f"- {DISPLAY[key]}: {finals['reached'][key]}")
    lines.append("\nTriggered bugs (distinct ids with trigger>0):")
    for key in FUZZERS:
        lines.append(f"- {DISPLAY[key]}: {finals['triggered'][key]}")
    lines.append("")
    lines.append("Final bug-id sets (last trial):")
    for key in FUZZERS:
        fz = by_trial[-1]["fuzzers"][key]
        lines.append(f"- {DISPLAY[key]}: reached={fz['reached_set']} "
                     f"triggered={fz['triggered_set']}")
    lines.append("")
    lines.append("## Statistics (Mann-Whitney U + Holm, pairwise, per axis)\n")
    lines.append("Region coverage (final):")
    lines.append(_fmt_pair_stats(stats["regions"]))
    lines.append("\nReached bugs (final):")
    lines.append(_fmt_pair_stats(stats["reached"]))
    lines.append("\nTriggered bugs (final):")
    lines.append(_fmt_pair_stats(stats["triggered"]))
    lines.append("")
    lines.append("## Curves\n")
    lines.append("- `coverage_curve.svg` — median region coverage + min/max band per fuzzer.")
    lines.append("- `bugs_curve.svg` — median triggered-bug count + min/max band per fuzzer.")
    lines.append("")
    lines.append("Median region coverage at each grid point:\n")
    lines.append("| t (s) | " + " | ".join(DISPLAY[k] for k in FUZZERS) + " |")
    lines.append("| --- | " + " | ".join("---" for _ in FUZZERS) + " |")
    for idx, t in enumerate(grid):
        cells = " | ".join(f"{region_series[DISPLAY[k]]['median'][idx]:.0f}"
                           for k in FUZZERS)
        lines.append(f"| {t:.1f} | {cells} |")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def _default(*parts):
    return os.path.join(_HERE, "vendor", *parts)


def build_parser():
    p = argparse.ArgumentParser(
        description="Comparative fuzzer benchmark orchestrator — Magma libpng "
                    "(ADR 0045 Развилка G).")
    # Run shape — no N/budget hardcode; both are required choices (ADR 0045 G1).
    p.add_argument("--trials", type=int, required=True,
                   help="number of trials N (>=5 for the full run; ADR 0032)")
    p.add_argument("--budget", type=int, required=True,
                   help="per-trial wall-clock budget in seconds (e.g. 86400 = 24h)")
    p.add_argument("--jobs", type=int, default=1,
                   help="concurrent trials (default 1: one trial's 3 fuzzers in "
                        "parallel on dedicated cores, trials sequential)")
    p.add_argument("--snapshots", type=int, default=12,
                   help="number of log-spaced snapshot points (default 12)")
    p.add_argument("--reserve-cores", type=int, default=2,
                   help="CPUs left for OS / replay (default 2)")
    # Outputs.
    p.add_argument("--out", default=os.path.join(_REPO, "docs", "experiments",
                                                  "comparative-magma-libpng"),
                   help="aggregated artefacts dir (committed separately)")
    p.add_argument("--work-dir", default=_default("comparative-work"),
                   help="gitignored intermediate state: snapshot pools, "
                        "checkpoints, run log")
    # Binaries / inputs (default to the vendored libpng racing/measurement builds).
    p.add_argument("--seeds", default=_default("magma-src", "targets", "libpng",
                                               "corpus", "libpng_read_fuzzer"))
    p.add_argument("--fuzzer", default=os.path.join(_REPO, "build", "src", "cli", "fuzzer"))
    p.add_argument("--exec-server", default=os.path.join(_REPO, "build", "exec-server-bin"))
    p.add_argument("--cov-library", default=os.path.join(
        _REPO, "build", "src", "runtime", "coverage", "libmlfuzzz3_cov.so"))
    p.add_argument("--ours-bin", default=_default("out", "libpng_read_fuzzer"))
    p.add_argument("--afl-bin", default=_default("out-afl", "libpng_read_fuzzer"))
    p.add_argument("--lf-bin", default=_default("out-libfuzzer", "libpng_read_fuzzer"))
    p.add_argument("--cov-bin", default=_default("out-cov", "libpng_read_fuzzer"))
    p.add_argument("--canary-bin", default=_default("out", "libpng_read_fuzzer"),
                   help="canary build (canaries ON) for the oracle axis")
    p.add_argument("--oracle-read", default=_default("oracle", "oracle_read"))
    p.add_argument("--target-args", default="",
                   help="args passed to the target (libpng harness takes none)")
    # Pre-flight gate.
    p.add_argument("--require-nondegenerate", action="store_true",
                   help="exit non-zero if any fuzzer's final region OR reached "
                        "median is 0 (pre-flight STOP gate)")
    return p


def _validate_binaries(args):
    missing = []
    for label, path in (("fuzzer", args.fuzzer), ("exec-server", args.exec_server),
                        ("cov-library", args.cov_library), ("ours-bin", args.ours_bin),
                        ("afl-bin", args.afl_bin), ("lf-bin", args.lf_bin),
                        ("cov-bin", args.cov_bin), ("canary-bin", args.canary_bin),
                        ("oracle-read", args.oracle_read)):
        if not os.path.exists(path):
            missing.append(f"{label}={path}")
    if not os.path.isdir(args.seeds):
        missing.append(f"seeds={args.seeds}")
    return missing


def main(argv=None):
    args = build_parser().parse_args(argv)

    missing = _validate_binaries(args)
    if missing:
        print("comparative_run: missing prerequisites (build the arms first):",
              file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 2

    nproc = os.cpu_count() or 4
    try:
        cores = campaign_cores(nproc, args.jobs, len(FUZZERS), args.reserve_cores)
    except ValueError as exc:
        print(f"comparative_run: {exc}", file=sys.stderr)
        return 2
    grid = ir.log_spaced_grid(args.budget, args.snapshots, first=1.0)

    os.makedirs(args.work_dir, exist_ok=True)
    logfh = open(os.path.join(args.work_dir, "run.log"), "a", encoding="utf-8")
    try:
        _check_resume_config(args.work_dir, args, logfh)
        cfg = Config(args, grid, cores)

        done = load_checkpoints(args.work_dir, args.trials)
        todo = pending_trials(args.trials, done.keys())
        _log(logfh, f"run start: {args.trials} trials, budget {args.budget}s, "
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
                    _log(logfh, f"trial {trial_idx}: FAILED — {exc!r}")
                finally:
                    slot_q.put(slot)

            threads = []
            running = []
            for trial_idx in todo:
                t = threading.Thread(target=worker, args=(trial_idx,))
                t.start()
                threads.append(t)
                running.append(t)
                # Cap live threads at --jobs (each blocks on a slot anyway, but
                # avoid spawning all trials' threads up front for a long run).
                while sum(1 for x in running if x.is_alive()) >= args.jobs:
                    time.sleep(0.5)
            for t in threads:
                t.join()

            if errors:
                _log(logfh, f"run: {len(errors)} trial(s) failed: {errors}")
                print(f"comparative_run: {len(errors)} trial(s) failed: {errors}",
                      file=sys.stderr)
                return 3

        # All trials present -> aggregate.
        done = load_checkpoints(args.work_dir, args.trials)
        if len(done) < args.trials:
            _log(logfh, f"run: only {len(done)}/{args.trials} trials complete — "
                        f"no aggregation (resume to finish)")
            return 4

        degen = aggregate_and_render(done, cfg, args, logfh)
        _log(logfh, f"degeneracy check (final medians): {degen}")

        if args.require_nondegenerate:
            bad = [k for k, v in degen.items()
                   if v["regions"] <= 0 or v["reached"] <= 0]
            if bad:
                _log(logfh, f"STOP: degenerate arm(s): {bad} (need regions>0 ∧ reached>0)")
                print(f"comparative_run: STOP — degenerate arm(s): {bad}",
                      file=sys.stderr)
                return 5
            _log(logfh, "pre-flight gate: OK — all arms non-degenerate "
                        "(regions>0 ∧ reached>0), both axes present, stats + 2 SVGs rendered")
        _log(logfh, "run complete")
        return 0
    finally:
        logfh.close()


if __name__ == "__main__":
    raise SystemExit(main())
