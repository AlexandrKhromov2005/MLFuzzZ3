"""Per-input replay-cost sizing for the Magma libpng comparative run
(ADR 0045 Step 7).

Measures the dominant cost of the neutral measurement pipeline — replaying one
input through the ``-fcoverage-mapping`` build — and contrasts the ADR-0044 full
re-replay (O(snapshots x corpus)) with the ADR-0045 incremental replay
(O(total inputs)) on a fixed corpus split into log-spaced snapshots. Prints the
measured per-input constant and an extrapolation in terms of (final corpus N,
snapshots S, runs R, fuzzers F); it deliberately fixes NO N/budget — the full
statistical run is a separate manual host-only entry (ADR 0045 Step 7 / Развилка
G).

Host-only research tooling; not a CI gate. Requires build_cov.sh
(vendor/out-cov/libpng_read_fuzzer) + LLVM 20 tools, and a corpus (defaults to a
fuzzer corpus under vendor/oracle/fuzzcorpus/corpus, else the libpng stock seeds).

Run:  python3 benchmarks/magma/sizing_replay_cost.py [corpus_dir]
"""

import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.join(_REPO, "scripts"))

import coverage_replay as cr  # noqa: E402
import incremental_replay as ir  # noqa: E402

_VENDOR = os.path.join(_HERE, "vendor")
_COV_BIN = os.path.join(_VENDOR, "out-cov", "libpng_read_fuzzer")
_DEFAULT_CORPUS = os.path.join(_VENDOR, "oracle", "fuzzcorpus", "corpus")
_STOCK = os.path.join(_VENDOR, "magma-src", "targets", "libpng", "corpus",
                      "libpng_read_fuzzer")


def _cumulative_snapshots(inputs, num_snaps):
    """Split inputs into `num_snaps` log-spaced cumulative prefixes (mimics a
    growing corpus sampled on a log-spaced snapshot grid)."""
    n = len(inputs)
    grid = ir.log_spaced_grid(n, num_snaps, first=max(1, n // (num_snaps * 4)))
    cuts = sorted({min(n, max(1, int(round(t)))) for t in grid})
    if cuts[-1] != n:
        cuts.append(n)
    return [inputs[:k] for k in cuts]


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    corpus = argv[0] if argv else _DEFAULT_CORPUS
    if not os.path.isdir(corpus):
        corpus = _STOCK
    if not os.path.isfile(_COV_BIN):
        print(f"sizing: measurement binary missing: {_COV_BIN} "
              f"(run benchmarks/magma/build_cov.sh)", file=sys.stderr)
        return 2

    inputs = cr.list_corpus_inputs(corpus)
    if not inputs:
        print(f"sizing: no inputs under {corpus}", file=sys.stderr)
        return 2
    n = len(inputs)
    print(f"sizing: corpus={corpus} inputs={n}")

    # Per-input replay cost: one full re-replay of the whole corpus.
    t0 = time.monotonic()
    covered, total = cr.replay_regions(_COV_BIN, inputs, target_args=())
    full_once = time.monotonic() - t0
    per_input = full_once / n
    print(f"sizing: full replay of {n} inputs: {full_once:.2f}s "
          f"=> {per_input * 1000:.2f} ms/input  ({covered}/{total} regions)")

    # Full re-replay vs incremental on S log-spaced snapshots of this corpus.
    snaps = _cumulative_snapshots(inputs, 8)
    sizes = [len(s) for s in snaps]

    t0 = time.monotonic()
    for snap in snaps:
        cr.replay_regions(_COV_BIN, snap, target_args=())
    full_rereplay = time.monotonic() - t0

    t0 = time.monotonic()
    ir.replay_incremental(_COV_BIN, snaps, target_args=())
    incremental = time.monotonic() - t0

    print(f"sizing: {len(snaps)} snapshots (sizes {sizes})")
    print(f"sizing:   full re-replay (ADR 0044): {full_rereplay:.2f}s "
          f"(replays sum(|snap|)={sum(sizes)} inputs)")
    print(f"sizing:   incremental   (ADR 0045): {incremental:.2f}s "
          f"(replays {n} inputs once)")
    if incremental > 0:
        print(f"sizing:   speedup x{full_rereplay / incremental:.2f} on this corpus")

    print("sizing: extrapolation (no N/budget fixed here — separate manual run):")
    print(f"sizing:   per fuzzer-run, incremental replay cost ~= N * {per_input * 1000:.2f} ms")
    print("sizing:   total ~= per_input * N * R * F  (R runs, F=3 fuzzers); "
          "full re-replay multiplies that by ~mean(|snap|)/N * S.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
