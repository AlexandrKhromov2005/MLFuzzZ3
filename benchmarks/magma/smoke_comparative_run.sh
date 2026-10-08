#!/usr/bin/env bash
#
# Pre-flight smoke for the comparative orchestrator (ADR 0045 Развилка G).
#
# Runs benchmarks/magma/comparative_run.py end-to-end on a TINY budget to prove
# the whole chain works before the real 24h run is launched: three fuzzers x N
# trials x both axes (region coverage + bug oracle) x log-spaced snapshots x
# incremental/fork-exec post-hoc replay x Mann-Whitney+Holm x two SVGs, plus
# checkpoint+resume. Asserts no arm is degenerate (regions>0 AND reach>0) via
# the orchestrator's --require-nondegenerate STOP gate.
#
# This is the STOP gate of ADR 0045 Развилка G: if it is not green, the real
# run is NOT launched — the exact failure is surfaced and root-caused.
#
# The pre-flight is throwaway (toy budget): its artefacts go to a gitignored
# scratch under vendor/, NEVER to docs/experiments/ (that is the real run's).
#
# Host-only; not a CI gate. Requires all four arms built (build.sh, build_cov.sh,
# build_afl.sh, build_libfuzzer.sh) plus our host fuzzer/exec-server (cmake build).
#
# Usage:  benchmarks/magma/smoke_comparative_run.sh [trials] [budget_seconds]
#         (defaults: 2 trials, 45 s/trial)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VENDOR="${SCRIPT_DIR}/vendor"

TRIALS="${1:-2}"
BUDGET="${2:-45}"

WORK="${VENDOR}/preflight-work"   # gitignored (under vendor/)
OUT="${VENDOR}/preflight-out"     # gitignored (under vendor/) — throwaway

die() { echo "smoke_comparative_run.sh: $*" >&2; exit 1; }

# Fresh scratch each run (the pre-flight is not resumed from a stale state).
rm -rf "${WORK}" "${OUT}"

echo "smoke_comparative_run.sh: pre-flight — trials=${TRIALS} budget=${BUDGET}s"
echo "smoke_comparative_run.sh: work=${WORK} out=${OUT}"

run() {
    python3 "${SCRIPT_DIR}/comparative_run.py" \
        --trials "${TRIALS}" --budget "${BUDGET}" --jobs 1 --snapshots 8 \
        --work-dir "${WORK}" --out "${OUT}" \
        --require-nondegenerate
}

# --- run 1: full chain ------------------------------------------------------
echo "smoke_comparative_run.sh: [1/2] full run"
run || die "STOP — orchestrator returned non-zero (see ${WORK}/run.log)"

for art in coverage_curve.svg bugs_curve.svg report.md; do
    [ -s "${OUT}/${art}" ] || die "STOP — missing/empty artefact: ${OUT}/${art}"
done
grep -q "<svg" "${OUT}/coverage_curve.svg" || die "STOP — coverage SVG malformed"
grep -q "<svg" "${OUT}/bugs_curve.svg"     || die "STOP — bugs SVG malformed"
grep -q "Mann-Whitney" "${OUT}/report.md"  || die "STOP — report missing statistics"
# Both axes present in the report (region coverage + bug oracle).
grep -q "Final region coverage" "${OUT}/report.md" || die "STOP — region axis missing"
grep -q "Final bug oracle"      "${OUT}/report.md" || die "STOP — oracle axis missing"
CKPTS="$(find "${WORK}/checkpoints" -name 'trial_*.json' | wc -l)"
[ "${CKPTS}" -eq "${TRIALS}" ] || die "STOP — expected ${TRIALS} checkpoints, found ${CKPTS}"
echo "smoke_comparative_run.sh: [1/2] OK — 2 SVGs + report + ${CKPTS} checkpoints, non-degenerate"

# --- run 2: checkpoint + resume --------------------------------------------
# Drop the last trial's checkpoint to simulate an interrupted run; a resume
# must re-run ONLY that trial and re-aggregate, keeping the finished trials.
echo "smoke_comparative_run.sh: [2/2] resume — dropping one checkpoint"
LAST="$(printf 'trial_%03d.json' "$((TRIALS - 1))")"
rm -f "${WORK}/checkpoints/${LAST}"
rm -f "${OUT}/coverage_curve.svg" "${OUT}/bugs_curve.svg" "${OUT}/report.md"
run || die "STOP — resume returned non-zero (checkpoint/resume broken)"
for art in coverage_curve.svg bugs_curve.svg report.md; do
    [ -s "${OUT}/${art}" ] || die "STOP — resume did not regenerate ${art}"
done
CKPTS="$(find "${WORK}/checkpoints" -name 'trial_*.json' | wc -l)"
[ "${CKPTS}" -eq "${TRIALS}" ] || die "STOP — after resume expected ${TRIALS} checkpoints, found ${CKPTS}"
echo "smoke_comparative_run.sh: [2/2] OK — resume rebuilt the missing trial + artefacts"

echo "smoke_comparative_run.sh: PRE-FLIGHT GREEN — full chain proven on a toy budget."
echo "smoke_comparative_run.sh: (pre-flight artefacts in ${OUT} are throwaway; NOT committed)"
