"""Incremental coverage replay + log-spaced snapshot grid (ADR 0045 Step 5).

Extends the ADR-0044 neutral coverage frame (``coverage_replay.py``) for long
Magma campaigns. Re-replaying the full corpus at every snapshot is
O(snapshots × corpus); incremental replay feeds each NEW input through the
measurement binary exactly once and accumulates a running ``llvm-profdata
merge``, giving the same region coverage at each snapshot in O(total inputs).

Equivalence to a full re-replay rests on two facts: ``llvm-profdata merge`` is a
commutative/associative sum of execution counters, and ``llvm-cov`` region
coverage is the predicate counter>0. Merging the same set of ``.profraw`` in any
grouping (all-at-once vs cumulative-by-chunk) yields identical counters and thus
an identical ``llvm-cov export``. ``test_incremental_replay`` is the micro-confirm
(ADR 0045 Step 5 STOP gate): it asserts the export is identical to a full
re-replay; a divergence means the equivalence is broken.

Inputs are deduplicated by CONTENT HASH, not path or name: snapshots are copies
of a fuzzer's output dir at successive times, so the same logical input has a
different path in each snapshot. Replaying identical bytes twice cannot change
coverage, so content-hash dedup is both correct and robust to AFL/our naming.

Host-only research tooling; not a CI gate. The pure helpers (log_spaced_grid,
file hashing) are unit-tested without a binary.
"""

from __future__ import annotations

import hashlib
import math
import os
import resource
import shutil
import subprocess
import tempfile

import coverage_replay as cr


def rlimit_as_preexec(limit_bytes):
    """Return a ``preexec_fn`` that caps the child's address space (RLIMIT_AS) at
    ``limit_bytes``, or ``None`` to disable (back-compat default).

    Replaying an untrusted corpus runs the coverage/canary binary on
    fuzzer-crafted inputs; a single libtiff input ballooned to ~21.8 GB and
    OOM-killed the whole N=10 run during replay (ADR 0046). Capping RLIMIT_AS
    makes such an allocation fail inside that ONE exec (it exits, contributing no
    profraw) instead of taking down the host. ``setrlimit`` is async-signal-safe,
    so it is safe to call between fork and exec in the threaded orchestrator.
    """
    if limit_bytes is None:
        return None

    def _set_limit():  # runs in the child, post-fork / pre-exec
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))

    return _set_limit


def log_spaced_grid(max_seconds, num_points, *, first=1.0):
    """A snapshot/resample grid that is dense early and sparse late.

    ``--interval`` (ADR 0044) only gives a uniform grid; lowering it to catch
    early coverage growth multiplies snapshots across the whole run. A
    log-spaced grid from ``first`` to ``max_seconds`` captures the early rise
    cheaply. Returns a sorted list of strictly increasing times whose first
    element is ``first`` and last is ``max_seconds`` (deduped after rounding to
    the millisecond); length is at most ``num_points``.
    """
    hi = float(max_seconds)
    lo = float(first)
    if num_points < 2 or hi <= lo:
        return [hi]
    raw = [lo * (hi / lo) ** (i / (num_points - 1)) for i in range(num_points)]
    grid = sorted({round(t, 3) for t in raw})
    grid[0] = lo
    grid[-1] = hi
    return [t for t in grid if t > 0]


def file_hash(path):
    """SHA-1 of a file's bytes (content identity for dedup). Pure I/O helper."""
    h = hashlib.sha1()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.digest()


def replay_incremental(
    cov_bin,
    snapshots,
    target_args=("-d",),
    *,
    scratch=None,
    llvm_profdata=None,
    llvm_cov=None,
    profdata_out=None,
    mem_limit_bytes=None,
):
    """Replay a sequence of cumulative corpus ``snapshots`` incrementally.

    ``snapshots`` is a list of input-path lists, each a superset (by content) of
    the previous. Each not-yet-seen input is replayed once into its own
    ``.profraw``; per snapshot, the new ``.profraw`` are merged into the running
    cumulative ``.profdata`` and region coverage is exported. Returns
    ``[(covered, total), ...]``, one per snapshot. ``(0, 0)`` for a snapshot with
    no coverage yet. If ``profdata_out`` is given, the final cumulative
    ``.profdata`` is copied there (used by the micro-confirm to diff exports).
    """
    profdata_tool = llvm_profdata or cr.resolve_llvm_tool("llvm-profdata")
    cov_tool = llvm_cov or cr.resolve_llvm_tool("llvm-cov")
    if not profdata_tool or not cov_tool:
        raise RuntimeError(
            "llvm-profdata-20 / llvm-cov-20 not found — host coverage tools required"
        )

    owns_scratch = scratch is None
    scratch = scratch or tempfile.mkdtemp(prefix="mlf_incr_replay_")
    try:
        seen = set()
        cumulative = None  # path to the running merged .profdata
        raw_index = 0
        results = []
        for snap_index, snapshot in enumerate(snapshots):
            new_raws = []
            for input_path in snapshot:
                digest = file_hash(input_path)
                if digest in seen:
                    continue
                seen.add(digest)
                profraw = os.path.join(scratch, f"r{raw_index}.profraw")
                raw_index += 1
                with open(input_path, "rb") as handle:
                    subprocess.run(
                        [cov_bin, *target_args],
                        stdin=handle,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env={**os.environ, "LLVM_PROFILE_FILE": profraw},
                        check=False,
                        preexec_fn=rlimit_as_preexec(mem_limit_bytes),
                    )
                if os.path.exists(profraw):
                    new_raws.append(profraw)

            if new_raws:
                merged = os.path.join(scratch, f"cum{snap_index}.profdata")
                merge_inputs = ([cumulative] if cumulative else []) + new_raws
                subprocess.run(
                    [profdata_tool, "merge", "-o", merged, *merge_inputs],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                cumulative = merged

            if cumulative:
                exported = subprocess.run(
                    [cov_tool, "export", cov_bin, f"-instr-profile={cumulative}",
                     "--summary-only"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                results.append(cr.parse_region_summary(exported.stdout))
            else:
                results.append((0, 0))

        if profdata_out and cumulative:
            shutil.copy(cumulative, profdata_out)
        return results
    finally:
        if owns_scratch:
            shutil.rmtree(scratch, ignore_errors=True)
