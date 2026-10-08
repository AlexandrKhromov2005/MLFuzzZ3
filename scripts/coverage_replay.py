"""Neutral coverage measurement for the comparative benchmark (ADR 0044 Step 2).

Replays a corpus — the output inputs of ANY fuzzer (ours, AFL++, libFuzzer) —
through the single ``-fcoverage-mapping`` build of the target (built by
``benchmarks/lava-m/build_cov.sh`` → ``vendor/base64-cov``) and reports
llvm-cov *region coverage*. That region count, measured in one shared frame, is
the neutral unit that makes a cross-fuzzer comparison valid (ADR 0044 Развилка
A1): no fuzzer's own instrumentation is used as the yardstick, so there is no
self-report bias.

This replaces ``coverage_curve`` / ``summarize_run`` *for the comparative
preset only* — those read our fuzzer's self-reported ``edges`` (ADR 0021
server frontier) and stay as-is for our own single-fuzzer reports.

Host-only research tooling: the coverage binary and ``llvm-cov-20`` /
``llvm-profdata-20`` live on the host, not in the dev image (ADR 0044 / 0006).
Not a CI gate.

Scale (ADR 0044 Ограничение): replay is linear in the number of inputs — each
input is one short process producing one ``.profraw`` — but there is exactly
ONE ``llvm-profdata merge`` + export per call (i.e. per snapshot), never per
input. base64 is one-shot per input, so this is the standard llvm-cov
corpus-replay; for larger corpora (Magma) a batched/sampled variant will be
needed.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile


def resolve_llvm_tool(name):
    """Resolve an LLVM tool, preferring the ``-20`` suffix (bare names are
    absent on the host; ADR 0043/0044). Returns the path or ``None``."""
    for candidate in (f"{name}-20", name):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def parse_region_summary(export_json):
    """Extract ``(covered, total)`` regions from ``llvm-cov export
    --summary-only`` output. Pure — unit-testable without a binary.

    Accepts either the JSON string or an already-parsed dict.
    """
    doc = json.loads(export_json) if isinstance(export_json, str) else export_json
    regions = doc["data"][0]["totals"]["regions"]
    return int(regions["covered"]), int(regions["count"])


def list_corpus_inputs(corpus_dir):
    """Every regular file directly under ``corpus_dir`` (sorted), treated as a
    raw input. Fuzzers write plain input files; the caller is responsible for
    pointing this at the right directory (e.g. AFL ``queue/`` only, never the
    ``out/`` root with its ``fuzzer_stats``/``.state`` metadata — ADR 0044 C2).
    """
    return sorted(
        path
        for path in glob.glob(os.path.join(corpus_dir, "*"))
        if os.path.isfile(path)
    )


def replay_regions(
    cov_bin,
    inputs,
    target_args=("-d",),
    *,
    scratch=None,
    llvm_profdata=None,
    llvm_cov=None,
):
    """Replay ``inputs`` through ``cov_bin`` and return ``(covered, total)``
    region coverage in the neutral frame.

    Each input is fed on stdin to one ``cov_bin <target_args>`` process with a
    unique ``LLVM_PROFILE_FILE``; all resulting ``.profraw`` are merged once
    and exported once (per call = per snapshot, ADR 0044 scale note). Inputs
    that produce no ``.profraw`` (e.g. the binary rejected them before any
    instrumented code ran) are skipped. Returns ``(0, 0)`` for an empty/failed
    input set.

    ``cov_bin`` must be the ``-fcoverage-mapping`` build (build_cov.sh).
    """
    profdata_tool = llvm_profdata or resolve_llvm_tool("llvm-profdata")
    cov_tool = llvm_cov or resolve_llvm_tool("llvm-cov")
    if not profdata_tool or not cov_tool:
        raise RuntimeError(
            "llvm-profdata-20 / llvm-cov-20 not found — host coverage tools required"
        )

    owns_scratch = scratch is None
    scratch = scratch or tempfile.mkdtemp(prefix="mlf_cov_replay_")
    try:
        profraws = []
        for index, input_path in enumerate(inputs):
            profraw = os.path.join(scratch, f"r{index}.profraw")
            with open(input_path, "rb") as handle:
                subprocess.run(
                    [cov_bin, *target_args],
                    stdin=handle,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={**os.environ, "LLVM_PROFILE_FILE": profraw},
                    check=False,
                )
            if os.path.exists(profraw):
                profraws.append(profraw)

        if not profraws:
            return 0, 0

        merged = os.path.join(scratch, "merged.profdata")
        subprocess.run(
            [profdata_tool, "merge", "-o", merged, *profraws],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        exported = subprocess.run(
            [cov_tool, "export", cov_bin, f"-instr-profile={merged}", "--summary-only"],
            check=True,
            capture_output=True,
            text=True,
        )
        return parse_region_summary(exported.stdout)
    finally:
        if owns_scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def replay_corpus_dir(cov_bin, corpus_dir, target_args=("-d",), **kwargs):
    """Convenience: ``replay_regions`` over every plain file in ``corpus_dir``."""
    return replay_regions(cov_bin, list_corpus_inputs(corpus_dir), target_args, **kwargs)
