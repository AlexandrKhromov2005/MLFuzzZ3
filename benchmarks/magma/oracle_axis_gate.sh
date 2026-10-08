#!/usr/bin/env bash
#
# Oracle-axis gate for the Magma libpng slice (ADR 0045 Step 4).
#
# The bug oracle (magma/src/canary.c) accumulates reach/trigger counters into a
# shared MAGMA_STORAGE file, gated by a static `magma_faulty` latch: once any
# trigger fires WITHIN a process, all further counting (every bug) is zeroed for
# the rest of that process. The latch is designed for a crash-restart fuzzer
# (the process dies on a real bug and restarts fresh), so the correct ground
# truth is one execution per input.
#
# Our harvest model (ADR 0045 Развилка D, refined): a SINGLE-THREADED SEQUENTIAL
# offline replay of a corpus snapshot — each input fed to a fresh fork+exec of
# the target on stdin (ADR 0011), counters accumulating in one shared file.
# Sequential replay also sidesteps any race on the shared file that a live
# multi-worker read would incur.
#
# GATE (primary reference = Magma's OWN per-input ground truth, NOT a persistent
# single process): our fork-exec offline replay must reproduce what Magma's
# `monitor --fetch watch` produces — fetch_watch execve's the target once per
# input (fresh latch) and reads producer_buffer directly. We sum its per-input
# counts over the corpus and compare to our accumulated replay. The oracle-axis
# metric is the SET of reached/triggered bugs (binary per bug); raw counters are
# a secondary check (both models are per-input-fresh, so they must also match).
#
# A persistent single-process replay is ALSO run, purely as a NON-asserting
# diagnostic: it undercounts (the latch assumes crash-restart, absent offline),
# so it is documented here as an invalid reference, not the gate.
#
# fetch_watch feeds the input via the monitor's inherited stdin (its forked
# child leaves fd 0 untouched), matching our stdin shim. If a future target fed
# inputs differently (argv file, etc.) this equivalence would break — the gate
# would diverge and must be re-examined, not auto-resolved.
#
# Host-only; not a CI gate. Requires benchmarks/magma/build.sh (racing build).
#
# Usage:  benchmarks/magma/oracle_axis_gate.sh [corpus_dir]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"

VENDOR="${SCRIPT_DIR}/vendor"
RACE_OUT="${VENDOR}/out"
REPO="${VENDOR}/ours/libpng/repo"   # build.sh builds in its private copy (task-011)
MSRC="${VENDOR}/magma-src/magma/src"
STANDALONE_SRC="${VENDOR}/magma-src/fuzzers/llvm_cov/src/StandaloneFuzzTargetMain.c"
FUZZER="${SCRIPT_DIR}/fuzzers/mlfuzzz3"
ORACLE="${VENDOR}/oracle"
MONITOR="${RACE_OUT}/monitor"

CORPUS="${1:-${VENDOR}/magma-src/targets/libpng/corpus/libpng_read_fuzzer}"

die() { echo "oracle_axis_gate.sh: $*" >&2; exit 1; }

FORKEXEC_BIN="${RACE_OUT}/libpng_read_fuzzer"
[ -x "${FORKEXEC_BIN}" ]          || die "racing binary missing — run benchmarks/magma/build.sh first"
[ -x "${MONITOR}" ]               || die "monitor missing — run benchmarks/magma/build.sh first"
[ -f "${REPO}/.libs/libpng16.a" ] || die "racing libpng16.a missing — run benchmarks/magma/build.sh first"
[ -f "${RACE_OUT}/magma.o" ]      || die "magma.o missing — run benchmarks/magma/build.sh first"
[ -f "${STANDALONE_SRC}" ]        || die "StandaloneFuzzTargetMain.c missing in fetched Magma"
[ -d "${CORPUS}" ]                || die "corpus dir missing: ${CORPUS}"
CORPUS="$(cd "${CORPUS}" && pwd)"  # absolute: fetch_watch loop cd's into a scratch CWD

export MLFUZZZ3_EDGE_PASS="${BUILD_DIR}/src/instrumentation/edge_coverage_pass/libEdgeCoveragePass.so"
export MLFUZZZ3_BRANCH_PASS="${BUILD_DIR}/src/instrumentation/branch_trace_pass/libBranchTracePass.so"
export MLFUZZZ3_COV_LIB="${BUILD_DIR}/src/runtime/coverage/libmlfuzzz3_cov.so"
export MLFUZZZ3_CLANG=clang-20
export MLFUZZZ3_CLANGXX=clang++-20

mkdir -p "${ORACLE}"

echo "oracle_axis_gate.sh: build reader + persistent canary binary (diagnostic)"
clang-20 -I "${MSRC}" -O1 "${FUZZER}/src/oracle_read.c" -o "${ORACLE}/oracle_read"
clang-20 -O1 -g -fPIC -c "${STANDALONE_SRC}" -o "${ORACLE}/standalone_main.o"
PERSISTENT_BIN="${ORACLE}/libpng_read_fuzzer_persistent"
( cd "${REPO}" && "${FUZZER}/bin/mlfuzzz3-clang-fast++" \
    -include "${MSRC}/canary.h" -DMAGMA_ENABLE_CANARIES -g -O0 -std=c++11 -I. \
    contrib/oss-fuzz/libpng_read_fuzzer.cc \
    -o "${PERSISTENT_BIN}" \
    -g .libs/libpng16.a "${RACE_OUT}/magma.o" "${ORACLE}/standalone_main.o" \
    -lstdc++ -lrt -lz )
[ -x "${PERSISTENT_BIN}" ] || die "persistent binary link failed"

mapfile -t INPUTS < <(find "${CORPUS}" -maxdepth 1 -type f | sort)
[ "${#INPUTS[@]}" -gt 0 ] || die "no inputs in ${CORPUS}"
echo "oracle_axis_gate.sh: replaying ${#INPUTS[@]} inputs from $(basename "${CORPUS}")"

A_FILE="${ORACLE}/canaries_forkexec.raw"
B_FILE="${ORACLE}/canaries_persistent.raw"
REF_RAW="${ORACLE}/fetchwatch_perinput.txt"
head -c 2048 /dev/zero > "${A_FILE}"
head -c 2048 /dev/zero > "${B_FILE}"
: > "${REF_RAW}"

# (a) fork-exec-per-input, accumulating in one shared file (our harvest model).
for f in "${INPUTS[@]}"; do
    MAGMA_STORAGE="${A_FILE}" "${FORKEXEC_BIN}" <"${f}" >/dev/null 2>&1 || true
done
A_OUT="$("${ORACLE}/oracle_read" "${A_FILE}" | sort)"

# (ref) Magma's own per-input ground truth: monitor --fetch watch execve's the
# target once per input (fresh latch, fresh temp storage), reads producer_buffer
# directly. Sum its per-input "human" dumps over the corpus. Run from a writable
# scratch CWD (fetch_watch mkstemp's its temp storage in CWD).
WATCH_WD="${ORACLE}/watch_wd"
rm -rf "${WATCH_WD}"; mkdir -p "${WATCH_WD}"
for f in "${INPUTS[@]}"; do
    ( cd "${WATCH_WD}" && "${MONITOR}" --fetch watch --dump human "${FORKEXEC_BIN}" <"${f}" ) >>"${REF_RAW}" 2>/dev/null || true
done
REF_OUT="$(awk '{r[$1]+=$3; t[$1]+=$5} END{for(n in r) print n, r[n], t[n]}' "${REF_RAW}" | sort)"

# (b) persistent single process — NON-asserting diagnostic (undercounts: latch).
MAGMA_STORAGE="${B_FILE}" "${PERSISTENT_BIN}" "${INPUTS[@]}" >/dev/null 2>&1 || true
B_OUT="$("${ORACLE}/oracle_read" "${B_FILE}" | sort)"

echo "=== (a) fork-exec offline replay (our harvest)   [name reached triggered] ==="
echo "${A_OUT:-<none>}"
echo "=== (ref) Magma monitor --fetch watch, summed per-input [name reached triggered] ==="
echo "${REF_OUT:-<none>}"
echo "=== (diag) persistent single process (undercounts; latch, NOT a reference) ==="
echo "${B_OUT:-<none>}"

# Oracle-axis metric: SET of reached / triggered bugs (binary per bug).
set_of() { echo "$1" | awk -v col="$2" '$col+0>0 {print $1}' | sort | tr '\n' ' '; }
A_REACH="$(set_of "${A_OUT}" 2)"; REF_REACH="$(set_of "${REF_OUT}" 2)"
A_TRIG="$(set_of "${A_OUT}" 3)";  REF_TRIG="$(set_of "${REF_OUT}" 3)"
echo "reached set — replay: [${A_REACH}] vs fetch_watch: [${REF_REACH}]"
echo "triggered set — replay: [${A_TRIG}] vs fetch_watch: [${REF_TRIG}]"

ok=1
[ "${A_REACH}" = "${REF_REACH}" ] || { echo "MISMATCH: reached SET differs (axis metric)" >&2; ok=0; }
[ "${A_TRIG}" = "${REF_TRIG}" ]   || { echo "MISMATCH: triggered SET differs (axis metric)" >&2; ok=0; }
[ "${A_OUT}" = "${REF_OUT}" ]     || { echo "MISMATCH: raw counters differ (secondary check)" >&2; ok=0; }

if [ "${ok}" -eq 1 ]; then
    echo "oracle_axis_gate.sh: OK — fork-exec offline replay reproduces Magma fetch_watch ground truth"
    echo "oracle_axis_gate.sh:    (reached/triggered sets AND counters match; oracle axis accepted)"
    exit 0
else
    echo "oracle_axis_gate.sh: STOP — fork-exec replay does NOT match Magma fetch_watch ground truth" >&2
    diff <(echo "${A_OUT}") <(echo "${REF_OUT}") >&2 || true
    exit 1
fi
