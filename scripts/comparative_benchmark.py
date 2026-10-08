"""Comparative fuzzer benchmark in a neutral coverage frame (ADR 0044 Step 4).

Runs each fuzzer (ours, AFL++) on its own instrumented build of the target
under a shared wall-clock budget, snapshotting each fuzzer's output directory
on a wall-clock timer (ADR 0044 Развилка F1 — NOT mtime reconstruction, which
AFL's queue resync would distort). Every snapshot's corpus is replayed through
the single neutral measurement build (coverage_replay → region coverage), so a
coverage-over-time curve is built in one common frame. Curves are aggregated
across N runs (numpy median + min/max band) and drawn as a dependency-free SVG
(stdlib string building, ADR 0044 Развилка D1). Final region counts are
compared with Mann-Whitney + Holm (reused 1:1 from scripts/stats).

Host-only research tooling (AFL++, llvm-cov, the racing/measurement binaries
all live on the host). Not a CI gate. base64 is saturated, so the dynamics are
expected to be flat — this slice proves the measurement PIPELINE end-to-end;
discrimination is a later milestone on Magma (ADR 0044 Развилка E / Ограничение).

The pure helpers (resample_curve, aggregate, render_svg) are unit-tested
without fuzzing; the orchestration (run_with_snapshots, measure_run, main)
needs the host binaries.
"""

from __future__ import annotations

import argparse
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "stats"))

import coverage_replay as cr  # noqa: E402
import fuzzer_drivers as fd  # noqa: E402
import mannwhitney as mw  # noqa: E402

try:
    import numpy as np
except ImportError:  # pragma: no cover - numpy is a host dependency
    np = None


# --- pure curve helpers ----------------------------------------------------

def resample_curve(snaps, grid):
    """Step-resample ``snaps`` = [(elapsed, regions), ...] onto ``grid`` times.

    At grid time ``t`` the value is the regions of the latest snapshot whose
    elapsed time is ``<= t`` (a fuzzer's cumulative coverage only grows), or 0
    before the first snapshot. ``snaps`` need not be sorted.
    """
    ordered = sorted(snaps, key=lambda pt: pt[0])
    out = []
    for t in grid:
        value = 0
        for elapsed, regions in ordered:
            if elapsed <= t:
                value = regions
            else:
                break
        out.append(value)
    return out


def aggregate(run_curves):
    """Aggregate ``run_curves`` (list of equal-length region series, one per
    run) into ``(median, lo, hi)`` triples per grid point. ``lo``/``hi`` are
    the min/max across runs — honest spread for the small N typical here (a
    percentile band is degenerate at N=2). Requires numpy."""
    if np is None:
        raise RuntimeError("numpy required for aggregation")
    matrix = np.array(run_curves, dtype=float)
    median = np.median(matrix, axis=0)
    lo = np.min(matrix, axis=0)
    hi = np.max(matrix, axis=0)
    return median.tolist(), lo.tolist(), hi.tolist()


# --- SVG (dependency-free) -------------------------------------------------

_SVG_COLORS = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd"]


def render_svg(grid, series, *, title, ylabel="region coverage", width=720, height=420,
               log_x=False, y_integer_ticks=False):
    """Render a multi-fuzzer metric(time) chart as an SVG string.

    ``series`` = {name: {"median": [...], "lo": [...], "hi": [...]}} all on the
    common ``grid`` (wall-clock seconds). Each fuzzer gets a min/max band
    (``<polygon>``) and a median line (``<polyline>``); one shared y-axis
    labelled ``ylabel`` (default neutral region coverage; the Magma orchestrator
    passes a bug-oracle label for its second axis). Pure string building — no
    matplotlib.

    ``log_x`` (opt-in): place the time axis on a log10 scale so a log-spaced
    snapshot grid spreads evenly instead of bunching the early points against
    the left edge. The grid minimum must be > 0 (our grids start at t=1s).
    Tick marks land on powers of ten plus the grid maximum.

    ``y_integer_ticks`` (opt-in): label the y-axis with integers 0..ceil(max)
    at their true pixel positions — correct for a count axis (triggered bugs),
    where a 0/mid/max scheme would mislabel the geometric midpoint (e.g. 1.5
    shown as "2"). Default keeps the 0/mid/max scheme for continuous metrics.
    """
    margin_l, margin_r, margin_t, margin_b = 60, 160, 40, 50
    plot_w = width - margin_l - margin_r
    plot_h = height - margin_t - margin_b

    x_max = max(grid) if grid else 1.0
    x_min = min(grid) if grid else 1.0
    if log_x and x_min <= 0:
        x_min = 1.0
    y_data_max = 1.0
    for s in series.values():
        y_data_max = max(y_data_max, max(s["hi"]) if s["hi"] else 1.0)
    # Round y_max up to a tidy number (headroom keeps lines off the top edge).
    y_max = float(y_data_max) * 1.05

    def px(t):
        if log_x:
            lmin, lmax = math.log10(x_min), math.log10(x_max)
            if lmax <= lmin:
                return margin_l
            tv = t if t > 0 else x_min
            return margin_l + (math.log10(tv) - lmin) / (lmax - lmin) * plot_w
        return margin_l + (t / x_max) * plot_w if x_max else margin_l

    def py(v):
        return margin_t + plot_h - (v / y_max) * plot_h if y_max else margin_t + plot_h

    parts = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="sans-serif" font-size="12">'
    )
    parts.append(f'<rect width="{width}" height="{height}" fill="white"/>')
    parts.append(
        f'<text x="{width / 2:.0f}" y="22" text-anchor="middle" '
        f'font-size="15" font-weight="bold">{_esc(title)}</text>'
    )

    # Axes.
    parts.append(
        f'<line x1="{margin_l}" y1="{margin_t + plot_h}" x2="{margin_l + plot_w}" '
        f'y2="{margin_t + plot_h}" stroke="#333" stroke-width="1"/>'
    )
    parts.append(
        f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" '
        f'y2="{margin_t + plot_h}" stroke="#333" stroke-width="1"/>'
    )
    # Y ticks. Each tick's label is the value at its own pixel position.
    if y_integer_ticks:
        y_top = max(1, int(math.ceil(y_data_max)))
        yticks = [float(k) for k in range(0, y_top + 1)]
    else:
        yticks = [y_max * frac for frac in (0.0, 0.5, 1.0)]
    for yv in yticks:
        yy = py(yv)
        parts.append(
            f'<line x1="{margin_l - 4:.0f}" y1="{yy:.1f}" x2="{margin_l}" '
            f'y2="{yy:.1f}" stroke="#333"/>'
        )
        parts.append(
            f'<text x="{margin_l - 8:.0f}" y="{yy + 4:.1f}" text-anchor="end">{yv:.0f}</text>'
        )
    # X ticks. Log axis: powers of ten within the grid span plus the maximum;
    # linear axis: the original 0/mid/max scheme.
    if log_x:
        xticks = []
        k = int(math.floor(math.log10(x_min)))
        while 10 ** k <= x_max:
            if 10 ** k >= x_min:
                xticks.append(float(10 ** k))
            k += 1
        if not xticks or xticks[-1] != float(x_max):
            xticks.append(float(x_max))
    else:
        xticks = [x_max * frac for frac in (0.0, 0.5, 1.0)]
    for xv in xticks:
        xx = px(xv)
        parts.append(
            f'<line x1="{xx:.1f}" y1="{margin_t + plot_h}" x2="{xx:.1f}" '
            f'y2="{margin_t + plot_h + 4}" stroke="#333"/>'
        )
        parts.append(
            f'<text x="{xx:.1f}" y="{margin_t + plot_h + 18:.0f}" '
            f'text-anchor="middle">{xv:.0f}s</text>'
        )
    parts.append(
        f'<text x="{margin_l + plot_w / 2:.0f}" y="{height - 8}" '
        f'text-anchor="middle">wall-clock (s)</text>'
    )
    parts.append(
        f'<text x="16" y="{margin_t + plot_h / 2:.0f}" text-anchor="middle" '
        f'transform="rotate(-90 16 {margin_t + plot_h / 2:.0f})">{_esc(ylabel)}</text>'
    )

    legend_y = margin_t + 6
    for index, (name, s) in enumerate(sorted(series.items())):
        color = _SVG_COLORS[index % len(_SVG_COLORS)]
        # Band: lo forward, hi backward.
        band = []
        for t, v in zip(grid, s["lo"]):
            band.append(f"{px(t):.1f},{py(v):.1f}")
        for t, v in zip(reversed(grid), reversed(s["hi"])):
            band.append(f"{px(t):.1f},{py(v):.1f}")
        parts.append(
            f'<polygon points="{" ".join(band)}" fill="{color}" fill-opacity="0.15" '
            f'stroke="none"/>'
        )
        # Median line.
        line = " ".join(f"{px(t):.1f},{py(v):.1f}" for t, v in zip(grid, s["median"]))
        parts.append(
            f'<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2"/>'
        )
        # Legend entry.
        ly = legend_y + index * 18
        parts.append(
            f'<rect x="{margin_l + plot_w + 16}" y="{ly - 9}" width="12" height="12" '
            f'fill="{color}"/>'
        )
        parts.append(
            f'<text x="{margin_l + plot_w + 32}" y="{ly + 1}">{_esc(name)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _esc(text):
    return (
        str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


# --- orchestration (host binaries) -----------------------------------------

def _safe_snapshot(out_dir, dest):
    """Copy ``out_dir`` into ``dest`` tolerating files that a running fuzzer
    deletes mid-copy (AFL's .cur_input, locks). Preserves structure so the
    per-fuzzer harvest works on the snapshot."""
    for root, _dirs, files in os.walk(out_dir):
        rel = os.path.relpath(root, out_dir)
        target = os.path.join(dest, rel) if rel != "." else dest
        os.makedirs(target, exist_ok=True)
        for name in files:
            try:
                shutil.copy2(os.path.join(root, name), os.path.join(target, name))
            except OSError:
                pass


def run_with_snapshots(cmd, env, out_dir, *, interval, max_seconds, snap_root):
    """Run ``cmd`` (a fuzzer campaign that self-stops at its wall-clock budget)
    and snapshot ``out_dir`` every ``interval`` seconds. Returns a list of
    ``(elapsed_seconds, snapshot_dir)``, including a final snapshot at exit."""
    os.makedirs(out_dir, exist_ok=True)
    proc = subprocess.Popen(
        cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    snaps = []
    start = time.monotonic()
    next_at = float(interval)
    hard_limit = max_seconds + 60  # safety net if a fuzzer ignores its budget
    try:
        while proc.poll() is None:
            time.sleep(0.2)
            elapsed = time.monotonic() - start
            if elapsed >= next_at:
                snap = os.path.join(snap_root, f"t{int(round(elapsed))}")
                _safe_snapshot(out_dir, snap)
                snaps.append((elapsed, snap))
                next_at += interval
            if elapsed > hard_limit:
                proc.terminate()
                break
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    elapsed = time.monotonic() - start
    final = os.path.join(snap_root, f"t{int(round(elapsed))}_final")
    _safe_snapshot(out_dir, final)
    snaps.append((elapsed, final))
    return snaps


def measure_run(snaps, harvest_fn, cov_bin, target_args):
    """Replay each snapshot's harvested corpus through the neutral build →
    ``[(elapsed, regions), ...]``."""
    curve = []
    for elapsed, snap_dir in snaps:
        inputs = harvest_fn(snap_dir)
        covered, _total = cr.replay_regions(cov_bin, inputs, target_args)
        curve.append((elapsed, covered))
    return curve


def main(argv=None):
    parser = argparse.ArgumentParser(description="Comparative fuzzer benchmark (ADR 0044)")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bench = os.path.join(root, "benchmarks", "lava-m")
    parser.add_argument("--seeds", default=os.path.join(bench, "seeds"))
    parser.add_argument("--our-target", default=os.path.join(bench, "vendor", "coreutils-8.24", "src", "base64"))
    parser.add_argument("--afl-target", default=os.path.join(bench, "vendor", "base64-afl"))
    parser.add_argument("--cov-target", default=os.path.join(bench, "vendor", "base64-cov"))
    parser.add_argument("--fuzzer", default=os.path.join(root, "build", "src", "cli", "fuzzer"))
    parser.add_argument("--exec-server", default=os.path.join(root, "build", "exec-server-bin"))
    parser.add_argument("--cov-library", default=os.path.join(root, "build", "src", "runtime", "coverage", "libmlfuzzz3_cov.so"))
    parser.add_argument("--target-args", default="-d")
    parser.add_argument("--max-seconds", type=int, default=30)
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--out-dir", default=os.path.join(root, "docs", "experiments"))
    parser.add_argument("--group", default="comparative-base64")
    args = parser.parse_args(argv)

    target_args = tuple(args.target_args.split()) if args.target_args else ()
    grid = list(range(args.interval, args.max_seconds + 1, args.interval))
    if not grid or grid[-1] < args.max_seconds:
        grid.append(args.max_seconds)

    scratch = tempfile.mkdtemp(prefix="mlf_cmp_")
    results = {"ours": [], "afl": []}  # final regions per run
    resampled = {"ours": [], "afl": []}  # per-run resampled curves
    try:
        for run in range(args.runs):
            # ours
            out = os.path.join(scratch, f"ours_run{run}_out")
            our_cmd = fd.our_command(
                {"fuzzer": args.fuzzer, "exec_server": args.exec_server,
                 "target": args.our_target, "cov_library": args.cov_library},
                seed_dir=args.seeds, out_dir=out, max_seconds=args.max_seconds,
                target_args=args.target_args, rng_seed=1000 + run,
            )
            snaps = run_with_snapshots(
                our_cmd, {**os.environ}, out, interval=args.interval,
                max_seconds=args.max_seconds, snap_root=os.path.join(scratch, f"ours_run{run}_snaps"),
            )
            curve = measure_run(snaps, fd.harvest_ours, args.cov_target, target_args)
            resampled["ours"].append(resample_curve(curve, grid))
            results["ours"].append(curve[-1][1] if curve else 0)
            print(f"ours run {run}: final {results['ours'][-1]} regions over {len(snaps)} snaps", flush=True)

            # AFL
            out = os.path.join(scratch, f"afl_run{run}_out")
            afl_cmd = fd.afl_command(args.afl_target, seed_dir=args.seeds, out_dir=out,
                                     max_seconds=args.max_seconds, target_args=target_args)
            snaps = run_with_snapshots(
                afl_cmd, {**os.environ, **fd.afl_env()}, out, interval=args.interval,
                max_seconds=args.max_seconds, snap_root=os.path.join(scratch, f"afl_run{run}_snaps"),
            )
            curve = measure_run(snaps, fd.harvest_afl, args.cov_target, target_args)
            resampled["afl"].append(resample_curve(curve, grid))
            results["afl"].append(curve[-1][1] if curve else 0)
            print(f"afl  run {run}: final {results['afl'][-1]} regions over {len(snaps)} snaps", flush=True)

        series = {}
        for name in ("ours", "afl"):
            median, lo, hi = aggregate(resampled[name])
            series["mlfuzzz3" if name == "ours" else "AFL++"] = {
                "median": median, "lo": lo, "hi": hi,
            }

        out_group = os.path.join(args.out_dir, args.group)
        os.makedirs(out_group, exist_ok=True)
        svg = render_svg(grid, series,
                         title=f"base64 region coverage vs wall-clock (N={args.runs})")
        with open(os.path.join(out_group, "coverage_curve.svg"), "w", encoding="utf-8") as fh:
            fh.write(svg)

        # Mann-Whitney on final regions (needs >1 run per fuzzer).
        stat_line = "N too small for Mann-Whitney (need >=1 per group, ideally more)."
        if len(results["ours"]) >= 1 and len(results["afl"]) >= 1:
            try:
                u, p = mw.mannwhitneyu(results["ours"], results["afl"])
                adj = mw.holm_bonferroni([p])[0]
                stat_line = (f"Mann-Whitney U={u:.1f}, p={p:.4f}, Holm-adj={adj:.4f} "
                             f"(ours final {results['ours']} vs AFL {results['afl']})")
            except ValueError as exc:
                stat_line = f"Mann-Whitney skipped: {exc}"

        report = _render_report(args, grid, series, results, stat_line)
        with open(os.path.join(out_group, "report.md"), "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"wrote {out_group}/coverage_curve.svg and report.md", flush=True)
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _render_report(args, grid, series, results, stat_line):
    lines = ["# Comparative benchmark — base64, neutral coverage frame (ADR 0044)\n"]
    lines.append("Methodology: ADR 0044. Each fuzzer races its own instrumented "
                 "base64 under a shared wall-clock budget; output corpora are "
                 "replayed through one `-fcoverage-mapping` build (vendor/base64-cov) "
                 "and scored in llvm-cov region coverage — a neutral unit. "
                 "Coverage-over-time from wall-clock timer snapshots (Развилка F1).\n")
    lines.append("base64 is saturated: flat dynamics are expected. This slice "
                 "proves the measurement PIPELINE end-to-end (ours vs AFL++ in a "
                 "neutral frame), not fuzzer discrimination — that is a later "
                 "Magma milestone (ADR 0044 Развилка E / Ограничение).\n")
    lines.append("## Run\n")
    lines.append(f"- wall-clock budget: {args.max_seconds} s; snapshot interval: {args.interval} s; runs (N): {args.runs}")
    lines.append(f"- target args: `{args.target_args}`")
    lines.append(f"- grid (s): {grid}")
    lines.append("")
    lines.append("## Final region coverage (per run)\n")
    lines.append(f"- mlfuzzz3: {results['ours']}")
    lines.append(f"- AFL++: {results['afl']}")
    lines.append("")
    lines.append("## Statistics\n")
    lines.append(f"- {stat_line}")
    lines.append("")
    lines.append("## Curve (median region coverage at each grid point)\n")
    lines.append("| t (s) | " + " | ".join(sorted(series.keys())) + " |")
    lines.append("| --- | " + " | ".join("---" for _ in series) + " |")
    for index, t in enumerate(grid):
        cells = " | ".join(f"{series[name]['median'][index]:.0f}" for name in sorted(series.keys()))
        lines.append(f"| {t} | {cells} |")
    lines.append("")
    lines.append("Plot: `coverage_curve.svg` (median line + min/max band per fuzzer).")
    lines.append("")
    lines.append("Reading the curve: a grid point reads 0 only when it precedes the "
                 "first wall-clock snapshot of the run (the timer's first copy lands "
                 "at ~`interval` s, so `t=interval` may fall just before it) — it is "
                 "not zero coverage. base64's decode FSM saturates within well under "
                 "a second (both fuzzers reach the region ceiling almost immediately), "
                 "so a wall-clock curve at this granularity is uninformative *by "
                 "construction* — exactly why this slice is a pipeline proof and "
                 "discrimination waits for an unsaturated target (Magma).")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
