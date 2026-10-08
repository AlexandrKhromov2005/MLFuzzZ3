"""Recompute a published Mann-Whitney p with the exact null distribution.

Naryad «гигиена + ADR-0049» §0.4: every p published in
``docs/experiments/*/report.md`` and ``docs/EVALUATION.md`` with n < 20 in
both groups has to be recomputed exactly instead of by the normal
approximation. This tool does one comparison at a time and, crucially,
prints BOTH numbers — the asymptotic one is the reproduction check: if it
does not match the literal in the report, the samples fed here are not the
samples the report used, and the exact number must not be published.

Usage:

    python3 scripts/stats/recheck_exact.py --a 1,2,3 --b 4,5,6
    python3 scripts/stats/recheck_exact.py --json pairs.json
    python3 scripts/stats/recheck_exact.py --holm 0.01,0.02 --holm-method exact ...

``--json`` takes ``{"label": ..., "a": [...], "b": [...]}`` objects, one per
line or as a list, and prints one result line per object.

Output fields, one line per comparison:

    label=<label> n1=<n1> n2=<n2> u=<u> ties=<0|1> p_asym=<p> p_exact=<p> \
        method=<exact|asymptotic> ratio=<p_asym/p_exact>

``method=asymptotic`` means the exact branch does not apply (a sample of
20 or more, or a tie-aware enumeration over the cap) — there the two
numbers are equal by construction and nothing in the report changes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mannwhitney as mw  # noqa: E402


def _fmt(x):
    return repr(float(x))


def compare(a, b, label=""):
    u_asym, p_asym = mw.mannwhitneyu(a, b, method="asymptotic")
    u_auto, p_auto = mw.mannwhitneyu(a, b, method="auto")
    assert u_asym == u_auto, (u_asym, u_auto)
    exact = mw.exact_applies(a, b)
    combined = list(a) + list(b)
    ties = 0 if len(set(combined)) == len(combined) else 1
    ratio = (p_asym / p_auto) if p_auto > 0.0 else float("inf")
    return (
        f"label={label} n1={len(a)} n2={len(b)} u={_fmt(u_asym)} ties={ties} "
        f"p_asym={_fmt(p_asym)} p_exact={_fmt(p_auto)} "
        f"method={'exact' if exact else 'asymptotic'} ratio={ratio:.4g}"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", help="первая выборка, через запятую")
    ap.add_argument("--b", help="вторая выборка, через запятую")
    ap.add_argument("--label", default="")
    ap.add_argument("--json", help="файл с объектами {label,a,b}")
    ap.add_argument("--holm", help="семья p, через запятую: печатает поправку Холма")
    args = ap.parse_args()

    if args.holm:
        raw = [float(x) for x in args.holm.split(",")]
        adj = mw.holm_bonferroni(raw)
        print("holm_in=" + ",".join(_fmt(x) for x in raw))
        print("holm_out=" + ",".join(_fmt(x) for x in adj))
        return

    if args.json:
        with open(args.json, encoding="utf-8") as fh:
            text = fh.read().strip()
        objs = json.loads(text) if text.startswith("[") else [
            json.loads(line) for line in text.splitlines() if line.strip()
        ]
        for obj in objs:
            print(compare(obj["a"], obj["b"], obj.get("label", "")))
        return

    if not args.a or not args.b:
        ap.error("нужны --a и --b, либо --json, либо --holm")
    a = [float(x) for x in args.a.split(",")]
    b = [float(x) for x in args.b.split(",")]
    print(compare(a, b, args.label))


if __name__ == "__main__":
    main()
