"""Per-fuzzer drivers for the comparative benchmark (ADR 0044 Step 3).

Each fuzzer races its own instrumented build of the target under a shared
wall-clock budget and writes a corpus of plain input files. This module knows,
per fuzzer, (a) how to build the run command and (b) how to *harvest* the
replayable inputs from its output directory — the inputs that the neutral
measurement frame (coverage_replay) then scores.

Harvesting is where the fuzzers differ (ADR 0044 C2):

* ours    — accepted inputs in ``<out>/corpus/`` (+ ``crashes/``); plain
            content-addressed files.
* AFL++   — inputs in ``<out>/<name>/queue/`` (+ ``crashes/``); the rest of the
            ``out/`` tree is metadata (``fuzzer_stats``, ``plot_data``,
            ``cmdline``, ``.state/``, ``README.txt`` in ``crashes/``) and must
            NOT be replayed.

Host-only research tooling (AFL++ + the racing binaries live on the host); not
a CI gate. Running the fuzzers and snapshotting belongs to Step 4; this module
is the pure command/harvest layer so it is unit-testable without fuzzing.
"""

from __future__ import annotations

import glob
import json
import os
import re


# --- harvest ---------------------------------------------------------------

def _plain_files(directory, *, exclude_names=()):
    """Regular files directly under ``directory`` (no recursion into subdirs
    such as AFL's ``.state/``), excluding dotfiles and ``exclude_names``."""
    if not os.path.isdir(directory):
        return []
    out = []
    for entry in sorted(os.listdir(directory)):
        if entry.startswith(".") or entry in exclude_names:
            continue
        path = os.path.join(directory, entry)
        if os.path.isfile(path):
            out.append(path)
    return out


def harvest_ours(out_dir):
    """Replayable inputs from our fuzzer's output: ``corpus/`` + ``crashes/``."""
    inputs = _plain_files(os.path.join(out_dir, "corpus"))
    inputs += _plain_files(os.path.join(out_dir, "crashes"))
    return inputs


def harvest_afl(out_dir):
    """Replayable inputs from an AFL++ output dir: every ``*/queue/`` and
    ``*/crashes/`` across fuzzer instances, skipping AFL metadata.

    AFL writes ``fuzzer_stats``/``fuzzer_setup``/``plot_data``/``cmdline`` in
    the instance root (excluded by only descending into ``queue``/``crashes``),
    a ``.state/`` subdir (excluded — not a regular file), and a ``README.txt``
    in ``crashes/`` (excluded by name).
    """
    inputs = []
    for queue in sorted(glob.glob(os.path.join(out_dir, "*", "queue"))):
        inputs += _plain_files(queue)
    for crashes in sorted(glob.glob(os.path.join(out_dir, "*", "crashes"))):
        inputs += _plain_files(crashes, exclude_names=("README.txt",))
    return inputs


# libFuzzer artefact prefixes written to the campaign CWD / -artifact_prefix
# dir on a finding (a crash/oom/leak/timeout input is exactly a bug-triggering
# input — it must be replayed for the oracle axis, not just the grown corpus).
_LF_ARTEFACT_PREFIXES = ("crash-", "oom-", "leak-", "timeout-", "slow-unit-")


def harvest_libfuzzer(corpus_dir, artifact_dir=None):
    """Replayable inputs from a libFuzzer campaign.

    The first positional argument to libFuzzer is the corpus directory it grows
    (every file there is a kept input); read-only seed dirs come after it and
    are NOT harvested (they are not the campaign's product). Crash/oom/leak/
    timeout artefacts land in ``artifact_dir`` (the campaign CWD or
    ``-artifact_prefix`` target) and are harvested too — a crashing input is a
    triggered bug on the oracle axis. Mirrors harvest_ours/harvest_afl: only
    plain files, no recursion, dotfiles skipped.
    """
    inputs = _plain_files(corpus_dir)
    if artifact_dir and os.path.isdir(artifact_dir):
        for entry in sorted(os.listdir(artifact_dir)):
            if not entry.startswith(_LF_ARTEFACT_PREFIXES):
                continue
            path = os.path.join(artifact_dir, entry)
            if os.path.isfile(path):
                inputs.append(path)
    return inputs


# --- run commands ----------------------------------------------------------

def our_command(paths, *, seed_dir, out_dir, max_seconds, target_args,
                mutator="havoc", max_det_steps=0, metrics_interval=1000, rng_seed=0,
                no_concolic=False):
    """Argv for one of our fuzzer's campaigns (wall-clock budget). Mirrors
    smoke_benchmark.run_campaign; the racing target is the pass-instrumented
    base64 (build.sh).

    ``no_concolic`` (ADR 0048 плечо 2): добавляет ``--no-concolic``
    (src/cli/args.cpp:51), который разоружает солверную руку на весь прогон.
    Контракт ADR-0036 обязывает такой прогон дать ``concolic_calls = 0``, и
    smoke кампании v2 это ПРОВЕРЯЕТ, а не предполагает. По умолчанию False —
    команда существующих вызывающих байт в байт прежняя."""
    cmd = [
        paths["fuzzer"], "--exec-server", paths["exec_server"],
        "--target", paths["target"], "--cov-library", paths["cov_library"],
        "--seed-dir", seed_dir, "--out-dir", out_dir,
        "--mutator", mutator, "--max-det-steps", str(max_det_steps),
        "--max-seconds", str(max_seconds), "--metrics-interval", str(metrics_interval),
        "--seed", str(rng_seed),
    ]
    if no_concolic:
        cmd.append("--no-concolic")
    if target_args:
        cmd += ["--target-args", target_args]
    return cmd


def afl_command(afl_bin, *, seed_dir, out_dir, max_seconds, target_args=("-d",),
                afl_fuzz="afl-fuzz", cmplog_bin=None, mem_mb=None):
    """Argv for an afl-fuzz campaign on the AFL-instrumented target.

    base64/libpng are stdin-driven, so no ``@@`` placeholder is used — AFL feeds
    the input on stdin by default. ``-V <sec>`` is AFL's wall-clock stop (the
    shared budget, ADR 0044 invariant). Plain forkserver; the target is
    unmodified (persistent mode deferred).

    ``cmplog_bin`` (ADR 0046): if given, afl-fuzz drives CmpLog input-to-state
    via ``-c <cmplog_bin>`` — the separately ``AFL_LLVM_CMPLOG=1``-built
    companion binary. Default ``None`` leaves the plain forkserver command
    unchanged, so existing callers (the libpng arms) are unaffected.

    ``mem_mb`` (ADR 0046): if given, ``-m <mem_mb>`` caps each target execution's
    memory (MB). On exceeding, AFL kills that target run (counts as a crash) and
    the forkserver keeps fuzzing — so a crafted input that balloons memory no
    longer OOM-kills the whole host (a libtiff input ballooned to 21.8 GB during
    the N=10 run). Default ``None`` = no ``-m`` (libpng command byte-identical).
    """
    cmd = [afl_fuzz, "-i", seed_dir, "-o", out_dir, "-V", str(int(max_seconds))]
    if mem_mb is not None:
        cmd += ["-m", str(int(mem_mb))]
    if cmplog_bin is not None:
        cmd += ["-c", cmplog_bin]
    return cmd + ["--", afl_bin, *target_args]


def afl_env(extra=None):
    """Environment for non-interactive afl-fuzz on a CI-style host: skip the
    cpufreq governor nag and tolerate a piped core_pattern (we are not chasing
    crashes on saturated base64). Callers merge this over os.environ."""
    env = {
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_UI": "1",
        "AFL_BENCH_UNTIL_CRASH": "0",
    }
    if extra:
        env.update(extra)
    return env


def lf_command(lf_bin, *, seed_dir, out_corpus, max_seconds, artifact_dir=None,
               target_args=(), rss_limit_mb=None, malloc_limit_mb=None,
               print_final_stats=False):
    """Argv for a libFuzzer campaign on the libFuzzer-instrumented target.

    ``out_corpus`` is the (writable) corpus directory libFuzzer grows;
    ``seed_dir`` is appended as a read-only seed source. ``-max_total_time`` is
    libFuzzer's wall-clock stop (the shared budget, ADR 0045 invariant).
    ``-close_fd_mask=3`` mutes the target's stdout+stderr (matches the smoke;
    keeps a long run's logs sane). ``-artifact_prefix`` (if given) directs
    crash/oom artefacts to a known dir so harvest_libfuzzer can pick them up;
    the OSS-Fuzz harness drives ``LLVMFuzzerTestOneInput`` in-process, so no
    ``@@``/stdin placeholder applies on the fuzzing side (the neutral replay
    still feeds harvested files on stdin to OUR shim build).

    ``rss_limit_mb`` / ``malloc_limit_mb`` (ADR 0046): cap libFuzzer's resident
    set and single-allocation size (MB). On exceeding, libFuzzer reports an
    out-of-memory and exits — so a crafted input that balloons memory ends only
    this campaign (partial corpus harvested) instead of OOM-killing the host.
    Default ``None`` = no flag (libpng command byte-identical).
    """
    cmd = [lf_bin, f"-max_total_time={int(max_seconds)}", "-close_fd_mask=3"]
    if print_final_stats:
        # ADR 0048: без этого флага libFuzzer не печатает
        # ``stat::number_of_executed_units`` вовсе, и знаменателя для
        # нормировки на исполнение у плеча просто нет. Default False
        # оставляет команду прежних вызывающих байт в байт.
        cmd.append("-print_final_stats=1")
    if rss_limit_mb is not None:
        cmd.append(f"-rss_limit_mb={int(rss_limit_mb)}")
    if malloc_limit_mb is not None:
        cmd.append(f"-malloc_limit_mb={int(malloc_limit_mb)}")
    if artifact_dir is not None:
        prefix = artifact_dir if artifact_dir.endswith("/") else artifact_dir + "/"
        cmd.append(f"-artifact_prefix={prefix}")
    cmd += [*target_args, out_corpus, seed_dir]
    return cmd


# --------------------------------------------------------------------------
# Счётчики исполнений по плечам (ADR 0048)
#
# Кампания N=10 не сохранила ни одного знаменателя: пер-трайловые метрики
# удалялись вместе с каталогом трайла, поэтому нормировка на исполнение
# оказалась невозможна задним числом. Эти три читателя снимают счётчик у
# каждого плеча ПО ХОДУ прогона, из того файла, который плечо пишет само.
# Каждый возвращает None, когда счётчика ещё нет (плечо только стартовало)
# или файл повреждён — None и 0 означают разное, и смешивать их нельзя.
# --------------------------------------------------------------------------

def read_ours_execs(out_dir):
    """Счётчик исполнений нашего фаззера: поле ``execs`` последней ЦЕЛОЙ
    строки ``metrics.jsonl``. Последняя строка файла бывает недописана (её
    пишут во время чтения), поэтому разбор идёт с конца до первой строки,
    которая разобралась."""
    path = os.path.join(out_dir, "metrics.jsonl")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            return int(json.loads(line)["execs"])
        except (ValueError, KeyError, TypeError):
            continue
    return None


def read_afl_execs(out_dir):
    """Счётчик исполнений AFL++: ``execs_done`` из ``fuzzer_stats``. Каталог
    инстанса под out_dir не фиксирован по имени, поэтому берутся все
    ``*/fuzzer_stats`` и суммируются — при одном инстансе это он и есть."""
    total = None
    for stats in sorted(glob.glob(os.path.join(out_dir, "*", "fuzzer_stats"))):
        try:
            with open(stats, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    key, _, value = line.partition(":")
                    if key.strip() == "execs_done":
                        total = (total or 0) + int(value.strip())
                        break
        except (OSError, ValueError):
            continue
    return total


_LF_FINAL = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
_LF_PROGRESS = re.compile(r"^#(\d+)\s", re.M)


def read_libfuzzer_execs(log_path):
    """Счётчик исполнений libFuzzer из его собственного лога.

    По окончании прогона libFuzzer печатает
    ``stat::number_of_executed_units: N`` (только при ``-print_final_stats=1``)
    — это точное итоговое число, и оно предпочитается. Пока прогон идёт,
    такой строки ещё нет, поэтому берётся наибольший счётчик ``#N`` из строк
    прогресса: это то же самое число исполнений на момент печати строки.
    """
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    final = _LF_FINAL.findall(text)
    if final:
        return int(final[-1])
    progress = _LF_PROGRESS.findall(text)
    if progress:
        return max(int(v) for v in progress)
    return None
