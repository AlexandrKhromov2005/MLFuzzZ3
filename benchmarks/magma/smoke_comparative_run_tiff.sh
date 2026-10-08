#!/usr/bin/env bash
#
# Pre-flight smoke for the libtiff comparative orchestrator (ADR 0046 F5).
#
# Runs benchmarks/magma/comparative_run_tiff.py end-to-end on a TINY budget to
# prove the whole chain works before the real N=10 run is launched: FOUR arms
# (ours; AFL++ plain forkserver; AFL++ CmpLog `-c`; libFuzzer without
# value-profile) x N trials x three axes (log-rank survival on the codec gates
# = PRIMARY, region coverage + bug oracle = secondary) x log-spaced snapshots x
# post-hoc replay x log-rank/Mann-Whitney+Holm x five SVGs, plus
# checkpoint+resume. Asserts no arm is degenerate (regions>0 AND reach>0) via
# the orchestrator's --require-nondegenerate STOP gate.
#
# Three phases: [1/3] a clean full run; [2/3] resume after a finished
# checkpoint is dropped; [3/3] resume after the orchestrator is SIGKILLed in
# mid-trial, with the fingerprint guard checked from the refusing side too.
# Phase 3 is the one that matches how a two-day N=10 campaign actually dies.
#
# This is the STOP gate of ADR 0046 F5: if it is not green, the real run is NOT
# launched — the exact failure is surfaced and root-caused.
#
# The pre-flight is throwaway (toy budget): its artefacts go to a gitignored
# scratch under vendor/, NEVER to docs/experiments/ (that is the real run's).
#
# SEED-CORPUS POLICY (ADR 0046 gotcha — a real incident, not a hypothetical).
# The orchestrator hands --seeds straight to every arm without copying it
# (comparative_run_tiff.py:135/154/165). libFuzzer takes it as a second
# positional (read-only by contract) but has already polluted the canonical
# Magma corpus once, 21 clean seeds -> 402. So this pre-flight NEVER points the
# arms at the canonical seed dir: it copies the seeds into a scratch dir under
# vendor/ and passes THAT. Two canaries below turn the policy into a
# measurement instead of a hope:
#   canary A — sha256 manifest of the canonical corpus before/after must be
#              byte-identical (the corpus is intact);
#   canary B — the scratch copy's file count before/after, reported either way
#              (if it grew, the copy was load-bearing and the canonical dir
#              would have been polluted without it).
#
# Host-only; not a CI gate. Requires all five libtiff binaries built
# (build_tiff.sh, build_tiff_cov.sh, build_tiff_afl.sh, build_tiff_afl.sh
# --cmplog, build_tiff_libfuzzer.sh) plus our host fuzzer/exec-server (cmake
# build). `afl-fuzz` must be on PATH (ADR 0045 run-env).
#
# Usage:  benchmarks/magma/smoke_comparative_run_tiff.sh [trials] [budget_seconds]
#         (defaults: 2 trials, 45 s/trial)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="${SCRIPT_DIR}/vendor"

die() { echo "smoke_comparative_run_tiff.sh: $*" >&2; exit 1; }

# sha256 manifest of a corpus dir: one "<hash>  <relpath>" per file, sorted.
manifest() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum); }

# Пути, общие обоим режимам (v2 ниже читает их до объявления остальных).
SEEDS_CANON="${VENDOR}/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
ORACLE="${VENDOR}/oracle"
MSRC="${VENDOR}/magma-src/magma/src"

# --------------------------------------------------------------------------
# РЕЖИМ v2 (ADR 0048): пять плеч x один трайл x 600 с.
#
# Это ДРУГОЙ smoke, чем трёхфазный гейт ADR-0046 ниже, и он проверяет другое:
# не то, что цепочка переживает падение и возобновление, а то, что кампания v2
# вообще может быть снята — что пятое плечо существует, что знаменатель для
# нормировки на исполнение пишется, и что артефакты трайла переживают его
# конец. Запуск:  smoke_comparative_run_tiff.sh --v2 [budget_seconds]
#
# КРИТЕРИИ, ЗАРЕГИСТРИРОВАННЫЕ ЗДЕСЬ ДО ПРОГОНА. Любой невыполненный —
# smoke=FAIL; отчёт публикуется как FAIL, и кампания N=10 v2 НЕ
# рекомендуется. Пороги под результат не двигаются: если критерий не взят,
# это и есть результат.
#
#   К1. Все пять плеч дожили до конца бюджета. Проверяется по ряду
#       (время, исполнений) из чекпойнта: у каждого плеча последняя отметка
#       не раньше 90 % бюджета.
#   К2. Плечо 1 (mlfuzzz3, throttle-on): concolic_budget_skips > 0 И доля
#       времени солвера <= 30 % стены. Первое доказывает, что rate-limit
#       ADR-0038 ЖИВ (в N=10 он был мёртв: skips = 0), второе — что он
#       действительно ограничивает (в диагностике доля была 93.8 %).
#   К3. Плечо 2 (mlfuzzz3 --no-concolic): concolic_calls == 0. Контракт
#       ADR-0036 — проверяется, а не предполагается.
#   К4. Счётчик исполнений записан у ВСЕХ плеч в КАЖДОМ снапшоте (ни одного
#       None). Без этого нормировка на исполнение снова окажется невозможной.
#   К5. Артефакты трайла лежат на диске после его конца: у каждого плеча
#       непустой trials/trial_000/artifacts/<плечо>/.
#
# Что этот smoke НЕ проверяет: ни одного утверждения P1–P4 (для них нужен
# N=10), ни возобновления, ни невырожденности плеч — за 600 с плечо вправе
# не найти ничего, и это не дефект оснастки.
# --------------------------------------------------------------------------
if [ "${1:-}" = "--v2" ]; then
    V2_BUDGET="${2:-600}"
    V2_WORK="${VENDOR}/smoke-v2-tiff-work"
    V2_OUT="${VENDOR}/smoke-v2-tiff-out"
    V2_SEEDS="${VENDOR}/smoke-v2-tiff-seeds"

    command -v afl-fuzz >/dev/null 2>&1 \
        || die "afl-fuzz not on PATH — source the ADR 0045 run-env first"
    [ -d "${SEEDS_CANON}" ] || die "canonical seed corpus missing: ${SEEDS_CANON}"
    if [ ! -x "${ORACLE}/oracle_read" ]; then
        mkdir -p "${ORACLE}"
        clang-20 -I "${MSRC}" -O1 "${SCRIPT_DIR}/fuzzers/mlfuzzz3/src/oracle_read.c" \
            -o "${ORACLE}/oracle_read" || die "failed to build oracle_read"
    fi

    rm -rf "${V2_WORK}" "${V2_OUT}" "${V2_SEEDS}"
    mkdir -p "${V2_SEEDS}"
    cp -a "${SEEDS_CANON}/." "${V2_SEEDS}/"
    V2_CANON_BEFORE="$(manifest "${SEEDS_CANON}")"

    echo "smoke v2: пять плеч, один трайл, бюджет ${V2_BUDGET} с"
    python3 "${SCRIPT_DIR}/comparative_run_tiff.py" \
        --arms v2 --trials 1 --budget "${V2_BUDGET}" --jobs 1 --snapshots 8 \
        --work-dir "${V2_WORK}" --out "${V2_OUT}" --seeds "${V2_SEEDS}" \
        || echo "smoke v2: оркестратор вернул ненулевой код (см. ${V2_WORK}/run.log)"

    V2_CANON_AFTER="$(manifest "${SEEDS_CANON}")"
    if [ "${V2_CANON_BEFORE}" = "${V2_CANON_AFTER}" ]; then
        echo "smoke v2: КАНАРЕЙКА корпуса — эталонный корпус цел"
    else
        echo "smoke v2: КАНАРЕЙКА корпуса — ЭТАЛОННЫЙ КОРПУС ИЗМЕНЁН"
    fi

    V2_BUDGET="${V2_BUDGET}" V2_WORK="${V2_WORK}" V2_OUT="${V2_OUT}" \
        python3 "${SCRIPT_DIR}/smoke_v2_criteria.py"
    exit $?
fi

TRIALS="${1:-2}"
BUDGET="${2:-45}"

# Phase 3 kills the last trial and then proves the EARLIER one survived intact;
# with a single trial there is nothing to protect and the check would be vacuous.
[ "${TRIALS}" -ge 2 ] || { echo "smoke_comparative_run_tiff.sh: need trials>=2 (resume checks)" >&2; exit 2; }

WORK="${VENDOR}/preflight-tiff-work"    # gitignored (under vendor/)
OUT="${VENDOR}/preflight-tiff-out"      # gitignored (under vendor/) — throwaway
SEEDS_SCRATCH="${VENDOR}/preflight-tiff-seeds"   # the arms only ever see THIS


command -v afl-fuzz >/dev/null 2>&1 \
    || die "afl-fuzz not on PATH — source the ADR 0045 run-env first"
[ -d "${SEEDS_CANON}" ] || die "canonical seed corpus missing: ${SEEDS_CANON}"

# The oracle reader is a throwaway host tool, not a build artefact — make it on
# demand (same one-liner as smoke_three_fuzzers.sh).
if [ ! -x "${ORACLE}/oracle_read" ]; then
    mkdir -p "${ORACLE}"
    clang-20 -I "${MSRC}" -O1 "${SCRIPT_DIR}/fuzzers/mlfuzzz3/src/oracle_read.c" \
        -o "${ORACLE}/oracle_read" || die "failed to build oracle_read"
fi

# Fresh scratch each run (the pre-flight is not resumed from a stale state; the
# orchestrator would reject a work-dir whose config fingerprint disagrees).
rm -rf "${WORK}" "${OUT}" "${SEEDS_SCRATCH}"

# --- seed policy: arms fuzz a COPY, never the canonical corpus --------------
mkdir -p "${SEEDS_SCRATCH}"
cp -a "${SEEDS_CANON}/." "${SEEDS_SCRATCH}/"
CANON_BEFORE="$(manifest "${SEEDS_CANON}")"
SCRATCH_BEFORE="$(find "${SEEDS_SCRATCH}" -type f | wc -l)"

echo "smoke_comparative_run_tiff.sh: pre-flight — trials=${TRIALS} budget=${BUDGET}s"
echo "smoke_comparative_run_tiff.sh: work=${WORK} out=${OUT}"
echo "smoke_comparative_run_tiff.sh: seeds=${SEEDS_SCRATCH} (scratch copy of ${SCRATCH_BEFORE} canonical seeds)"

# One argv shared by every phase. The resume hinges on the config fingerprint,
# so a re-run has to be spelled exactly like the run it resumes.
RUN_ARGS=(--trials "${TRIALS}" --budget "${BUDGET}" --jobs 1 --snapshots 8
          --work-dir "${WORK}" --out "${OUT}" --seeds "${SEEDS_SCRATCH}"
          --require-nondegenerate)

run() { python3 "${SCRIPT_DIR}/comparative_run_tiff.py" "${RUN_ARGS[@]}"; }

# Artefacts: two axis curves + one KM survival curve per codec gate + report.
SVGS=(coverage_curve.svg bugs_curve.svg
      survival_PixarLog.svg survival_LZW.svg survival_LUV.svg)

check_artefacts() {
    local phase="$1"
    for svg in "${SVGS[@]}"; do
        [ -s "${OUT}/${svg}" ] || die "STOP — ${phase}: missing/empty artefact: ${OUT}/${svg}"
        grep -q "<svg" "${OUT}/${svg}" || die "STOP — ${phase}: malformed SVG: ${svg}"
    done
    [ -s "${OUT}/report.md" ] || die "STOP — ${phase}: missing/empty ${OUT}/report.md"
    # PRIMARY axis (log-rank survival on codec gates) present, with a verdict.
    grep -q "PRIMARY — time-to-reach codec gates" "${OUT}/report.md" \
        || die "STOP — ${phase}: report missing PRIMARY survival axis"
    grep -q "Predregistered result:" "${OUT}/report.md" \
        || die "STOP — ${phase}: report missing predregistered verdict"
    for gate in PixarLog LZW LUV; do
        grep -q "### Gate ${gate}" "${OUT}/report.md" \
            || die "STOP — ${phase}: report missing gate ${gate}"
    done
    # SECONDARY axes (region coverage + bug oracle, Mann-Whitney + Holm).
    grep -q "Mann-Whitney" "${OUT}/report.md" \
        || die "STOP — ${phase}: report missing statistics"
    grep -q "Final region coverage" "${OUT}/report.md" \
        || die "STOP — ${phase}: region axis missing"
    grep -q "Final triggered bugs" "${OUT}/report.md" \
        || die "STOP — ${phase}: oracle axis missing"
    # All four arms reported (a silently-dropped arm must not read as green).
    for arm in "mlfuzzz3" "AFL++ (plain)" "AFL++ (CmpLog)" "libFuzzer"; do
        grep -qF "${arm}" "${OUT}/report.md" \
            || die "STOP — ${phase}: arm absent from report: ${arm}"
    done
}

count_ckpts() { find "${WORK}/checkpoints" -name 'trial_*.json' | wc -l; }

# --- run 1: full chain ------------------------------------------------------
echo "smoke_comparative_run_tiff.sh: [1/3] full run"
run || die "STOP — orchestrator returned non-zero (see ${WORK}/run.log)"

check_artefacts "full run"
CKPTS="$(count_ckpts)"
[ "${CKPTS}" -eq "${TRIALS}" ] || die "STOP — expected ${TRIALS} checkpoints, found ${CKPTS}"
echo "smoke_comparative_run_tiff.sh: [1/3] OK — ${#SVGS[@]} SVGs + report + ${CKPTS} checkpoints, 4 arms non-degenerate"

# --- run 2: checkpoint + resume --------------------------------------------
# Drop the last trial's checkpoint to simulate an interrupted run; a resume
# must re-run ONLY that trial and re-aggregate, keeping the finished trials.
echo "smoke_comparative_run_tiff.sh: [2/3] resume — dropping one checkpoint"
LAST="$(printf 'trial_%03d.json' "$((TRIALS - 1))")"
[ -f "${WORK}/checkpoints/${LAST}" ] || die "STOP — no ${LAST} to drop (checkpoint naming changed?)"
KEPT_FIRST="$(cat "${WORK}/checkpoints/trial_000.json")"
rm -f "${WORK}/checkpoints/${LAST}"
rm -f "${OUT}"/*.svg "${OUT}/report.md"
run || die "STOP — resume returned non-zero (checkpoint/resume broken)"

check_artefacts "resume"
CKPTS="$(count_ckpts)"
[ "${CKPTS}" -eq "${TRIALS}" ] || die "STOP — after resume expected ${TRIALS} checkpoints, found ${CKPTS}"
# The kept trial must be reused verbatim, not silently re-run.
[ "${KEPT_FIRST}" = "$(cat "${WORK}/checkpoints/trial_000.json")" ] \
    || die "STOP — resume re-ran a checkpointed trial (trial_000 changed)"
echo "smoke_comparative_run_tiff.sh: [2/3] OK — resume rebuilt only the missing trial + artefacts"

# --- run 3: hard kill in mid-trial + resume ---------------------------------
# Run 2's interruption was synthetic: a *finished* checkpoint removed from an
# otherwise clean work-dir. No real crash leaves that state. Here the
# orchestrator is SIGKILLed while the third of the four arms is being replayed
# — two arms measured and held only in memory, one in flight, one untouched,
# and no checkpoint for the trial. A resume must throw that debris away, redo
# exactly that one trial, and leave the finished trial byte-identical.
KILL_TRIAL="$((TRIALS - 1))"
KILL_CKPT="${WORK}/checkpoints/$(printf 'trial_%03d.json' "${KILL_TRIAL}")"
# Third arm of four, mid-replay: late enough that the trial is half-measured,
# early enough that the fourth arm has not been touched.
KILL_MARK="trial ${KILL_TRIAL}: \[afl-cmplog\] region replay"
echo "smoke_comparative_run_tiff.sh: [3/3] hard kill — SIGKILL inside trial ${KILL_TRIAL}, at arm 3 of 4"

KEPT_FIRST="$(cat "${WORK}/checkpoints/trial_000.json")"
KEPT_MTIME="$(stat -c %.9Y "${WORK}/checkpoints/trial_000.json")"
rm -f "${KILL_CKPT}"
rm -f "${OUT}"/*.svg "${OUT}/report.md"
# run.log is append-only across phases and already contains this marker from
# runs 1-2; only the tail written by THIS run may be matched.
LOG_MARK="$(wc -l < "${WORK}/run.log")"
log_tail() { sed -n "$((LOG_MARK + 1)),\$p" "${WORK}/run.log"; }

# setsid: the victim gets its own process group, so any survivor of the kill is
# attributable to it and cannot be confused with this script's own children.
setsid python3 "${SCRIPT_DIR}/comparative_run_tiff.py" "${RUN_ARGS[@]}" >/dev/null 2>&1 &
VICTIM=$!
VICTIM_PGID="$(ps -o pgid= -p "${VICTIM}" | tr -d ' ')"

DEADLINE=$(( SECONDS + 3 * BUDGET + 300 ))
REACHED=0
while [ "${SECONDS}" -lt "${DEADLINE}" ]; do
    if log_tail | grep -qE "${KILL_MARK}"; then REACHED=1; break; fi
    kill -0 "${VICTIM}" 2>/dev/null \
        || die "STOP — the run ended before the kill point; '${KILL_MARK}' was never logged (arm names changed?)"
    sleep 0.5
done
if [ "${REACHED}" -ne 1 ]; then
    kill -s KILL "${VICTIM}" 2>/dev/null || true
    die "STOP — kill point not reached within $(( 3 * BUDGET + 300 ))s"
fi
kill -s KILL "${VICTIM}" || die "STOP — could not SIGKILL the orchestrator (pid ${VICTIM})"
wait "${VICTIM}" 2>/dev/null || true

# Replay children are short-lived, but a survivor would quietly eat cores and
# taint the trial that is about to be redone — so insist the group drains.
STRAY=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    STRAY="$(pgrep -g "${VICTIM_PGID}" 2>/dev/null | tr '\n' ' ' || true)"
    [ -z "${STRAY}" ] && break
    sleep 1
done
[ -z "${STRAY}" ] \
    || die "STOP — process group ${VICTIM_PGID} outlived the kill: ${STRAY} — kill it before re-running"

DEBRIS="$(ls "${WORK}/trials" 2>/dev/null | tr '\n' ' ' || true)"
if [ -e "${KILL_CKPT}" ]; then
    die "STOP — a checkpoint exists for the killed trial: a half-measured trial must never count as finished"
fi
CKPTS="$(count_ckpts)"
[ "${CKPTS}" -eq "$((TRIALS - 1))" ] \
    || die "STOP — after the kill expected $((TRIALS - 1)) checkpoints, found ${CKPTS}"
echo "smoke_comparative_run_tiff.sh: [3/3] killed — no group survivors, ${CKPTS} checkpoint(s) kept, debris left: [${DEBRIS:-none}]"

run || die "STOP — resume after a hard kill returned non-zero (see ${WORK}/run.log)"

log_tail | grep -qF "(config matches)" \
    || die "STOP — resume did not recognise the work-dir by its config fingerprint"
log_tail | grep -qF "$((TRIALS - 1)) done, 1 to run: [${KILL_TRIAL}]" \
    || die "STOP — resume did not pick up exactly the killed trial; it restarted from scratch or skipped work"
check_artefacts "hard-kill resume"
CKPTS="$(count_ckpts)"
[ "${CKPTS}" -eq "${TRIALS}" ] \
    || die "STOP — after the hard-kill resume expected ${TRIALS} checkpoints, found ${CKPTS}"
[ "${KEPT_FIRST}" = "$(cat "${WORK}/checkpoints/trial_000.json")" ] \
    || die "STOP — resume re-ran a checkpointed trial (trial_000 content changed)"
[ "${KEPT_MTIME}" = "$(stat -c %.9Y "${WORK}/checkpoints/trial_000.json")" ] \
    || die "STOP — resume rewrote a checkpointed trial (trial_000 mtime moved)"
# No duplicates: exactly one checkpoint per trial index, indices 0..TRIALS-1.
python3 - "${WORK}/checkpoints" "${TRIALS}" <<'DUPCHECK' \
    || die "STOP — the checkpoint set is not one entry per trial (duplicate or missing index)"
import json, os, sys
ckpt_dir, total = sys.argv[1], int(sys.argv[2])
idx = sorted(json.load(open(os.path.join(ckpt_dir, f), encoding="utf-8"))["trial"]
             for f in os.listdir(ckpt_dir)
             if f.startswith("trial_") and f.endswith(".json"))
sys.exit(0 if idx == list(range(total)) else 1)
DUPCHECK
[ -z "$(ls -A "${WORK}/trials" 2>/dev/null)" ] \
    || die "STOP — resume left the killed trial's debris behind: $(ls "${WORK}/trials" | tr '\n' ' ' || true)"
echo "smoke_comparative_run_tiff.sh: [3/3] OK — resume redid only trial ${KILL_TRIAL}; finished trial byte-identical, no duplicates"

# The resume above is only trustworthy if the fingerprint actually guards the
# work-dir: a differently-parameterised invocation must be refused, not blended
# into the existing checkpoints.
if python3 "${SCRIPT_DIR}/comparative_run_tiff.py" --trials "${TRIALS}" \
        --budget "$((BUDGET + 1))" --jobs 1 --snapshots 8 --work-dir "${WORK}" \
        --out "${OUT}" --seeds "${SEEDS_SCRATCH}" --require-nondegenerate \
        > "${WORK}/fingerprint-mismatch.log" 2>&1; then
    die "STOP — the work-dir accepted a run with a different --budget; the fingerprint guard is not holding"
fi
grep -qF "holds a run with config" "${WORK}/fingerprint-mismatch.log" \
    || die "STOP — the mismatched run failed, but not on the fingerprint guard: $(tail -1 "${WORK}/fingerprint-mismatch.log")"
CKPTS="$(count_ckpts)"
[ "${CKPTS}" -eq "${TRIALS}" ] \
    || die "STOP — the refused run disturbed the checkpoints (${CKPTS} left of ${TRIALS})"
echo "smoke_comparative_run_tiff.sh: [3/3] OK — a mismatched --budget is refused by fingerprint, checkpoints untouched"

# --- seed-corpus canaries ---------------------------------------------------
CANON_AFTER="$(manifest "${SEEDS_CANON}")"
if [ "${CANON_BEFORE}" != "${CANON_AFTER}" ]; then
    diff <(echo "${CANON_BEFORE}") <(echo "${CANON_AFTER}") >&2 || true
    die "STOP — canonical seed corpus was MODIFIED (restore: git -C ${VENDOR}/magma-src clean -f targets/libtiff/corpus/...)"
fi
SCRATCH_AFTER="$(find "${SEEDS_SCRATCH}" -type f | wc -l)"
echo "smoke_comparative_run_tiff.sh: canary A — canonical corpus byte-identical (${SCRATCH_BEFORE} seeds, sha256 manifest matches)"
if [ "${SCRATCH_AFTER}" -ne "${SCRATCH_BEFORE}" ]; then
    echo "smoke_comparative_run_tiff.sh: canary B — scratch seed copy grew ${SCRATCH_BEFORE} -> ${SCRATCH_AFTER}:"
    echo "smoke_comparative_run_tiff.sh:   an arm DOES write to --seeds; the copy is load-bearing, keep it."
else
    echo "smoke_comparative_run_tiff.sh: canary B — scratch seed copy unchanged (${SCRATCH_AFTER} files); no arm wrote to --seeds this run"
fi

echo "smoke_comparative_run_tiff.sh: PRE-FLIGHT GREEN — full 4-arm chain proven on a toy budget,"
echo "smoke_comparative_run_tiff.sh:   including resume across a real mid-trial SIGKILL."
echo "smoke_comparative_run_tiff.sh: (pre-flight artefacts in ${OUT} are throwaway; NOT committed)"
