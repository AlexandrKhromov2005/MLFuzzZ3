#!/usr/bin/env python3
"""Smoke-preset benchmark: one external target, one config, a coverage curve.

The smoke preset (ADR 0040 Развилка 5, refined by ADR 0041) is the cheap
"are we moving in the right direction" check: a single fuzzer campaign on one
real target under a small wall-clock budget (``--max-seconds``), producing an
edges-vs-time/execs coverage curve. No statistics — that is the full preset's
job (``benchmark.py`` matrix + Mann-Whitney).

It shares the full preset's pure logic by import — ``parse_metrics_lines`` and
``coverage_curve`` from ``benchmark`` — so the parsing and curve construction
never drift between presets (the duplication ADR 0040 Развилка 5 rejected).
Only the orchestration differs: one config, wall-clock budget, target args,
and a report that records source provenance.

This drives the real ``fuzzer`` CLI, which spawns a real exec-server; all paths
are resolved to absolute because the fuzzer resolves the exec-server relative
to its own working directory.

Run (research tool, not a CI gate):

    scripts/smoke_benchmark.py --target <bin> --target-args "-d" \\
        --max-seconds 30 --provenance "GNU coreutils 8.24" \\
        --provenance-date 2026-06-10 --provenance-note "GNU hash verified"
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark as bench  # noqa: E402  (shared pure logic: parse + curve)


def run_campaign(paths, cfg, max_seconds, interval, rng_seed, seed_dir, target_args):
    """Drive one wall-clock-bounded campaign; return its metrics snapshots.

    Unlike the matrix runner (benchmark.run_one, exec-budget, summary only),
    this keeps the full snapshot series so the coverage curve can be built.
    """
    out = tempfile.mkdtemp(prefix="mlf_smoke_")
    try:
        cmd = [
            paths["fuzzer"], "--exec-server", paths["exec_server"],
            "--target", paths["target"], "--cov-library", paths["cov_library"],
            "--seed-dir", seed_dir, "--out-dir", out,
            "--mutator", cfg["mutator"], "--max-det-steps", str(cfg["max_det_steps"]),
            "--max-seconds", str(max_seconds), "--metrics-interval", str(interval),
            "--seed", str(rng_seed),
        ]
        if target_args:
            cmd += ["--target-args", target_args]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False)
        metrics_path = os.path.join(out, "metrics.jsonl")
        snaps = []
        if os.path.exists(metrics_path):
            with open(metrics_path, encoding="utf-8") as handle:
                snaps = bench.parse_metrics_lines(handle.readlines())
        return snaps, proc.returncode
    finally:
        shutil.rmtree(out, ignore_errors=True)


def compact_curve(curve):
    """Collapse the curve to edge-frontier transitions plus the final point.

    The per-interval series (kept in full in raw.json) plateaus once mutation
    stops finding edges, so the report table would be mostly identical rows.
    Keeping only the points where the edge count changes — plus the last
    point, to show where the budget ended — yields a compact, still-faithful
    curve. Edges-at-execs is deterministic for a fixed seed, so these
    transition points are reproducible even though wall-clock elapsed is not.
    """
    if not curve:
        return []
    compact = [curve[0]]
    for pt in curve[1:]:
        if pt["edges"] != compact[-1]["edges"]:
            compact.append(pt)
    if curve[-1] is not compact[-1]:
        compact.append(curve[-1])
    return compact


def render_report(meta, snaps, curve):
    """Build the markdown smoke report: provenance, run group, coverage curve."""
    last = snaps[-1] if snaps else {}
    lines = []
    lines.append("# Smoke benchmark — coverage curve\n")
    lines.append("Methodology: ADR 0040 / 0041 smoke preset. One target, one "
                 "config, wall-clock budget; coverage growth only, no "
                 "statistics (that is the full preset, ADR 0032).\n")

    lines.append("## Provenance\n")
    lines.append(f"- source: {meta['provenance']}")
    lines.append(f"- obtained: {meta['provenance_date']}")
    lines.append(f"- note: {meta['provenance_note']}")
    lines.append("")

    lines.append("## Run\n")
    lines.append(f"- target: `{meta['target']}`")
    lines.append(f"- target args: `{meta['target_args'] or '(none)'}`")
    lines.append(f"- config: mutator=`{meta['mutator']}` max_det_steps={meta['max_det_steps']}")
    lines.append(f"- wall-clock budget: {meta['max_seconds']} s")
    lines.append(f"- metrics interval: {meta['interval']} execs")
    lines.append(f"- RNG seed: {meta['seed']}")
    lines.append(f"- run_id: `{last.get('run_id', '')}`")
    lines.append(f"- fuzzer exit code: {meta['rc']}")
    lines.append("")

    lines.append("## Final\n")
    lines.append(f"- execs: {int(last.get('execs', 0))}")
    lines.append(f"- edges (cumulative frontier): {int(last.get('edges', 0))}")
    lines.append(f"- corpus size: {int(last.get('corpus_size', 0))}")
    lines.append(f"- crashes: {int(last.get('crashes', 0))}")
    lines.append(f"- execs/sec: {float(last.get('execs_per_sec', 0.0)):.1f}")
    lines.append("")

    lines.append("## Concolic (ADR 0036/0040 Step 4)\n")
    lines.append("Non-zero `calls` proves the branch-value channel reaches the "
                 "solver on the real target; `unsat` means a path condition was "
                 "built and solved. Clean base64 has no magic-byte bugs, so few "
                 "candidates are expected — that payoff is LAVA-M (Step 2b).\n")
    for key, label in (
        ("concolic_calls", "calls (stagnation-triggered solves)"),
        ("concolic_candidates", "candidates produced"),
        ("concolic_edges", "candidates accepted (new edges)"),
        ("concolic_crashes", "candidates that crashed the target"),
        ("concolic_unsat", "inverted systems UNSAT"),
        ("concolic_timeout", "solves timed out"),
        ("concolic_no_candidate", "calls with no candidate"),
        ("concolic_time_ms_total", "solver time (ms)"),
    ):
        lines.append(f"- {label}: {int(last.get(key, 0))}")
    lines.append("")

    compact = compact_curve(curve)
    lines.append("## Coverage curve (edges vs elapsed/execs)\n")
    lines.append(f"Edge-frontier transitions plus the final point ({len(curve)} "
                 "raw snapshots collapsed; full series in raw.json). edges-at-execs "
                 "is deterministic for the fixed seed; elapsed is wall-clock and "
                 "machine-dependent.\n")
    lines.append("| elapsed (s) | execs | edges |")
    lines.append("| --- | --- | --- |")
    for pt in compact:
        lines.append(f"| {pt['elapsed']:.2f} | {pt['execs']} | {pt['edges']} |")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Smoke benchmark (ADR 0040/0041)")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build = os.path.join(root, "build")
    parser.add_argument("--fuzzer", default=os.path.join(build, "src/cli/fuzzer"))
    parser.add_argument("--exec-server", default=os.path.join(build, "exec-server-bin"))
    parser.add_argument("--target", required=True, help="instrumented target binary")
    parser.add_argument(
        "--cov-library",
        default=os.path.join(build, "src/runtime/coverage/libmlfuzzz3_cov.so"),
    )
    parser.add_argument("--seeds", required=True, help="seed corpus directory")
    parser.add_argument("--target-args", default="",
                        help="args forwarded to the target (e.g. -d); input stays on stdin")
    parser.add_argument("--max-seconds", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--mutator", default="havoc")
    parser.add_argument("--max-det-steps", type=int, default=1 << 16)
    parser.add_argument("--metrics-interval", type=int, default=50)
    parser.add_argument("--out-dir", default=os.path.join(root, "docs/experiments"))
    parser.add_argument("--group", default=None, help="report subdir (default: from run_id)")
    parser.add_argument("--provenance", default="(unspecified)",
                        help="source of the target (URL or path)")
    parser.add_argument("--provenance-date", default="(unspecified)",
                        help="date the source was obtained")
    parser.add_argument("--provenance-note", default="",
                        help="authenticity note, e.g. 'GNU hash verified' or "
                             "'TOFU — authenticity unverifiable'")
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
    seed_dir = os.path.abspath(args.seeds)
    if not os.path.isdir(seed_dir):
        raise SystemExit(f"missing seed dir: {seed_dir}")

    cfg = {"mutator": args.mutator, "max_det_steps": args.max_det_steps}
    snaps, rc = run_campaign(paths, cfg, args.max_seconds, args.metrics_interval,
                             args.seed, seed_dir, args.target_args)
    curve = bench.coverage_curve(snaps)

    # Record the target repo-relative when possible so the committed report
    # carries no machine-specific absolute path.
    try:
        display_target = os.path.relpath(paths["target"], root)
        if display_target.startswith(".."):
            display_target = paths["target"]
    except ValueError:
        display_target = paths["target"]

    run_id = snaps[-1]["run_id"] if snaps else ""
    group = args.group or (run_id.replace("|", "_") if run_id else "smoke")
    out_group = os.path.join(args.out_dir, group)
    os.makedirs(out_group, exist_ok=True)

    meta = {
        "target": display_target,
        "target_args": args.target_args,
        "mutator": args.mutator,
        "max_det_steps": args.max_det_steps,
        "max_seconds": args.max_seconds,
        "interval": args.metrics_interval,
        "seed": args.seed,
        "rc": rc,
        "provenance": args.provenance,
        "provenance_date": args.provenance_date,
        "provenance_note": args.provenance_note or "(none)",
    }
    with open(os.path.join(out_group, "raw.json"), "w", encoding="utf-8") as handle:
        json.dump({"meta": meta, "curve": curve, "snapshots": snaps},
                  handle, indent=2, sort_keys=True)
    report = render_report(meta, snaps, curve)
    with open(os.path.join(out_group, "report.md"), "w", encoding="utf-8") as handle:
        handle.write(report)

    print(report)
    print(f"\nreport written to {out_group}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
