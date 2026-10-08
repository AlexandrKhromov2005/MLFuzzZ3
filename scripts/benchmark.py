#!/usr/bin/env python3
"""Campaign benchmark harness for the Phase 2 checkpoint (ADR 0032).

Pure python3 standard library (plus the in-repo Mann-Whitney module). Runs
the four-config matrix against the cov_parser discriminating fixture, N runs
per config with distinct RNG seeds and a round-robin input seed from the
neutral set S, then analyses two metrics separately:

  * edges-at-budget  — coverage growth at a fixed exec budget (higher better)
  * time-to-crash    — t = min(execs_to_first_crash, budget), right-censored
                       (lower better); censored runs (no crash) contribute
                       t = budget and so the largest ranks.

The primary comparison family is the reference config (byteflip-only) vs
each other config, per metric, corrected with Holm-Bonferroni. Crash-rate is
reported descriptively only. Not a CI gate: runs are long and havoc is
stochastic.

This harness drives the real `fuzzer` CLI, which spawns a real exec-server;
all binary/seed paths are resolved to absolute paths because the fuzzer
resolves the exec-server relative to its own working directory.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "stats"))
import mannwhitney as mw  # noqa: E402

# Matrix (ADR 0032 Развилка 3). The "-only" configs disable the
# deterministic stage (--max-det-steps 0) so the named mutator is the sole
# strategy; det+havoc keeps the full deterministic sweep.
DEFAULT_DET_CAP = 1 << 16
CONFIGS = [
    {"name": "bitflip-only", "mutator": "bitflip", "max_det_steps": 0},
    {"name": "byteflip-only", "mutator": "byteflip", "max_det_steps": 0},
    {"name": "havoc-only", "mutator": "havoc", "max_det_steps": 0},
    {"name": "det+havoc", "mutator": "havoc", "max_det_steps": DEFAULT_DET_CAP},
]
REFERENCE = "byteflip-only"

# Metric definitions: (key, label, higher_is_better).
METRICS = [
    ("edges", "edges-at-budget", True),
    ("ttc", "time-to-crash", False),
]


# --- Pure logic (unit-tested without any fuzzing) -------------------------


def parse_metrics_lines(lines):
    """Parse metrics.jsonl text lines into a list of snapshot dicts."""
    snaps = []
    for line in lines:
        line = line.strip()
        if line:
            snaps.append(json.loads(line))
    return snaps


def summarize_run(snaps, budget):
    """Reduce a run's snapshots to the benchmark metrics.

    edges-at-budget is the last snapshot's edge count. time-to-crash is the
    exec count of the first snapshot reporting a crash (right-censored at the
    budget when no snapshot crashed).
    """
    if not snaps:
        return {
            "edges": 0,
            "ttc": budget,
            "censored": True,
            "crashed": False,
            "det_execs": 0,
            "havoc_execs": 0,
            "final_crashes": 0,
            "run_id": "",
        }
    last = snaps[-1]
    ttc, censored = budget, True
    for snap in snaps:
        if int(snap.get("crashes", 0)) > 0:
            ttc = min(int(snap["execs"]), budget)
            censored = False
            break
    return {
        "edges": int(last.get("edges", 0)),
        "ttc": ttc,
        "censored": censored,
        "crashed": not censored,
        "det_execs": int(last.get("det_execs", 0)),
        "havoc_execs": int(last.get("havoc_execs", 0)),
        "final_crashes": int(last.get("crashes", 0)),
        "run_id": str(last.get("run_id", "")),
    }


def coverage_curve(snaps):
    """Edges-vs-(execs, elapsed) curve from metrics snapshots (ADR 0040/0041).

    Returns one point per snapshot, in order, carrying the cumulative edge
    frontier sampled every --metrics-interval execs. This is the slice's
    primary research artifact (coverage growth over a budget); the matrix
    path (summarize_run) keeps only the final snapshot, whereas the smoke
    preset consumes the whole series via this function.
    """
    return [
        {
            "execs": int(s.get("execs", 0)),
            "edges": int(s.get("edges", 0)),
            "elapsed": float(s.get("elapsed", 0.0)),
        }
        for s in snaps
    ]


def analyze_metric(results, reference, key, higher_is_better):
    """Mann-Whitney (reference vs each other config) + Holm-Bonferroni.

    Returns a list of row dicts (one per non-reference config) carrying U,
    raw and adjusted p, the two medians, and the effect direction relative
    to the reference under the metric's better-is direction.
    """
    ref_vals = [r[key] for r in results[reference]]
    others = [name for name in results if name != reference]
    raw = []
    for name in others:
        other_vals = [r[key] for r in results[name]]
        u_stat, p_value = mw.mannwhitneyu(ref_vals, other_vals)
        raw.append((name, u_stat, p_value, other_vals))
    adjusted = mw.holm_bonferroni([p for (_, _, p, _) in raw])

    ref_median = statistics.median(ref_vals)
    rows = []
    for (name, u_stat, p_value, other_vals), p_adj in zip(raw, adjusted):
        other_median = statistics.median(other_vals)
        if other_median == ref_median:
            direction = "tie"
        else:
            ref_better = (other_median < ref_median) if higher_is_better else (
                other_median > ref_median
            )
            direction = "reference better" if ref_better else f"{name} better"
        rows.append(
            {
                "config": name,
                "u": u_stat,
                "p": p_value,
                "p_adj": p_adj,
                "ref_median": ref_median,
                "median": other_median,
                "direction": direction,
            }
        )
    return rows


def crash_rate(runs):
    """Fraction of runs that reached any crash."""
    if not runs:
        return 0.0
    return sum(1 for r in runs if r["crashed"]) / len(runs)


# --- Orchestration (real fuzzing) -----------------------------------------


def run_one(paths, cfg, rng_seed, seed_dir, budget, interval):
    """Drive one fuzzer campaign and summarize its metrics.jsonl."""
    out = tempfile.mkdtemp(prefix="mlf_bench_")
    try:
        cmd = [
            paths["fuzzer"], "--exec-server", paths["exec_server"],
            "--target", paths["target"], "--cov-library", paths["cov_library"],
            "--seed-dir", seed_dir, "--out-dir", out,
            "--mutator", cfg["mutator"], "--max-det-steps", str(cfg["max_det_steps"]),
            "--max-iterations", str(budget), "--metrics-interval", str(interval),
            "--seed", str(rng_seed),
        ]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False)
        metrics_path = os.path.join(out, "metrics.jsonl")
        snaps = []
        if os.path.exists(metrics_path):
            with open(metrics_path, encoding="utf-8") as handle:
                snaps = parse_metrics_lines(handle.readlines())
        summary = summarize_run(snaps, budget)
        summary["rc"] = proc.returncode
        summary["rng_seed"] = rng_seed
        summary["input_seed"] = os.path.basename(seed_dir)
        return summary
    finally:
        shutil.rmtree(out, ignore_errors=True)


def build_seed_dirs(seeds_dir, scratch):
    """One temp dir per seed file, so each run is bootstrapped from a single
    input seed (round-robin across S). Returns the list of dir paths."""
    seed_files = sorted(glob.glob(os.path.join(seeds_dir, "*.bin")))
    if not seed_files:
        raise SystemExit(f"no .bin seeds under {seeds_dir}")
    dirs = []
    for path in seed_files:
        one = os.path.join(scratch, os.path.splitext(os.path.basename(path))[0])
        os.makedirs(one, exist_ok=True)
        shutil.copy(path, one)
        dirs.append((one, os.path.basename(path)))
    return seed_files, dirs


def render_report(meta, results):
    """Build the markdown report string."""
    lines = []
    lines.append("# Phase 2 benchmark checkpoint — mutator comparison\n")
    lines.append("Methodology: ADR 0032. Synthetic discriminating fixture "
                 "(`cov_parser`); relative ordering of strategies, not "
                 "absolute strength on real targets.\n")
    lines.append("## Run group\n")
    lines.append(f"- fuzzer run_id sample: `{meta['run_id']}`")
    lines.append(f"- runs per config (N): {meta['n']}")
    lines.append(f"- exec budget per run: {meta['budget']}")
    lines.append(f"- metrics interval: {meta['interval']}")
    lines.append(f"- base RNG seed: {meta['base_seed']} (run i uses base+i)")
    lines.append(f"- reference config: `{REFERENCE}`")
    lines.append("- input seeds (round-robin): "
                 + ", ".join(f"`{os.path.basename(s)}`" for s in meta["seed_files"]))
    lines.append("")

    lines.append("## Descriptive summary\n")
    lines.append("| config | mutator | det cap | crash-rate | median edges "
                 "| median time-to-crash | median det_execs | median havoc_execs |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for cfg in CONFIGS:
        runs = results[cfg["name"]]
        med_edges = statistics.median([r["edges"] for r in runs])
        med_ttc = statistics.median([r["ttc"] for r in runs])
        med_det = statistics.median([r["det_execs"] for r in runs])
        med_hav = statistics.median([r["havoc_execs"] for r in runs])
        lines.append(
            f"| `{cfg['name']}` | {cfg['mutator']} | {cfg['max_det_steps']} "
            f"| {crash_rate(runs):.0%} | {med_edges:g} | {med_ttc:g} "
            f"| {med_det:g} | {med_hav:g} |"
        )
    lines.append("")

    for key, label, higher in METRICS:
        better = "higher is better" if higher else "lower is better (right-censored)"
        lines.append(f"## Mann-Whitney U — {label} ({better})\n")
        lines.append("Primary family: reference vs each config, two-sided "
                     "asymptotic, Holm-Bonferroni adjusted.\n")
        lines.append("| reference vs | U | p (raw) | p (Holm) | ref median "
                     "| config median | direction |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for row in analyze_metric(results, REFERENCE, key, higher):
            lines.append(
                f"| `{REFERENCE}` vs `{row['config']}` | {row['u']:g} "
                f"| {row['p']:.4g} | {row['p_adj']:.4g} | {row['ref_median']:g} "
                f"| {row['median']:g} | {row['direction']} |"
            )
        lines.append("")

    lines.append("## Notes\n")
    lines.append("- Coverage and crash are analysed separately (ADR 0032).")
    lines.append("- time-to-crash is right-censored at the budget; censored "
                 "(non-crashing) runs take t = budget and the largest ranks.")
    lines.append("- crash-rate is descriptive and not part of the test.")
    lines.append("- Mann-Whitney U is the in-repo asymptotic approximation "
                 "(scripts/stats/mannwhitney.py), validated against scipy.")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phase 2 benchmark checkpoint (ADR 0032)")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build = os.path.join(root, "build")
    parser.add_argument("--fuzzer", default=os.path.join(build, "src/cli/fuzzer"))
    parser.add_argument("--exec-server", default=os.path.join(build, "exec-server-bin"))
    parser.add_argument(
        "--target",
        default=os.path.join(build, "tests/fixtures/cov_parser/cov_parser_target"),
    )
    parser.add_argument(
        "--cov-library",
        default=os.path.join(build, "src/runtime/coverage/libmlfuzzz3_cov.so"),
    )
    parser.add_argument(
        "--seeds", default=os.path.join(root, "tests/fixtures/cov_parser/seeds")
    )
    parser.add_argument("-n", "--runs", type=int, default=10,
                        help="runs per config (target 10; 5 is the low-power floor)")
    parser.add_argument("--budget", type=int, default=3000, help="execs per run")
    parser.add_argument("--base-seed", type=int, default=1000)
    parser.add_argument("--out-dir", default=os.path.join(root, "docs/experiments"))
    parser.add_argument("--group", default=None,
                        help="report subdir name (default: derived from a run_id)")
    args = parser.parse_args(argv)

    paths = {
        "fuzzer": os.path.abspath(args.fuzzer),
        "exec_server": os.path.abspath(args.exec_server),
        "target": os.path.abspath(args.target),
        "cov_library": os.path.abspath(args.cov_library),
    }
    for label, path in paths.items():
        if not os.path.exists(path):
            raise SystemExit(f"missing {label}: {path}")

    interval = max(1, args.budget // 60)
    scratch = tempfile.mkdtemp(prefix="mlf_bench_seeds_")
    try:
        seed_files, seed_dirs = build_seed_dirs(os.path.abspath(args.seeds), scratch)
        results = {cfg["name"]: [] for cfg in CONFIGS}
        for i in range(args.runs):
            seed_dir, _seed_name = seed_dirs[i % len(seed_dirs)]
            rng_seed = args.base_seed + i
            for cfg in CONFIGS:
                summary = run_one(paths, cfg, rng_seed, seed_dir, args.budget, interval)
                results[cfg["name"]].append(summary)
            done = (i + 1) * len(CONFIGS)
            print(f"  {done}/{args.runs * len(CONFIGS)} runs", file=sys.stderr)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    run_id = ""
    for runs in results.values():
        for run in runs:
            if run["run_id"]:
                run_id = run["run_id"]
                break
        if run_id:
            break

    group = args.group or (run_id.replace("|", "_") if run_id else "run")
    out_group = os.path.join(args.out_dir, group)
    os.makedirs(out_group, exist_ok=True)

    meta = {
        "n": args.runs,
        "budget": args.budget,
        "interval": interval,
        "base_seed": args.base_seed,
        "seed_files": seed_files,
        "run_id": run_id,
    }
    with open(os.path.join(out_group, "raw.json"), "w", encoding="utf-8") as handle:
        json.dump({"meta": {k: v for k, v in meta.items() if k != "seed_files"},
                   "seed_files": [os.path.basename(s) for s in seed_files],
                   "results": results}, handle, indent=2, sort_keys=True)
    report = render_report(meta, results)
    with open(os.path.join(out_group, "report.md"), "w", encoding="utf-8") as handle:
        handle.write(report)

    print(report)
    print(f"\nreport written to {out_group}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
