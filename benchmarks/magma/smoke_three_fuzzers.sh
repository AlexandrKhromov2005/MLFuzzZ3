#!/usr/bin/env bash
#
# Three-fuzzer smoke on the Magma libpng slice (ADR 0045 Step 6).
#
# Runs all three fuzzers (ours, AFL++, libFuzzer) on libpng under a small shared
# wall-clock budget, then scores each fuzzer's harvested corpus in the two
# neutral frames the milestone defines:
#   - region coverage via the measurement binary (build_cov.sh)
#   - bug-oracle reach via the canary binary, single-threaded fork-exec replay
#     (the accepted harvest model, ADR 0045 Step 4)
# Asserts every fuzzer reaches BOTH non-zero regions AND non-zero oracle reach —
# proving the three-fuzzer pipeline end-to-end. A degenerate result (0 regions)
# is a real failure to root-cause, not an artifact to keep (ADR 0044 lesson:
# a muted-stderr harness once hid a dead build).
#
# Host-only; not a CI gate. Requires fetch_magma.sh + build.sh + build_cov.sh +
# build_afl.sh + build_libfuzzer.sh.
#
# Usage:  benchmarks/magma/smoke_three_fuzzers.sh [seconds]   (default 30)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"
VENDOR="${SCRIPT_DIR}/vendor"

SECS="${1:-30}"

FUZZER="${BUILD_DIR}/src/cli/fuzzer"
EXEC_SERVER="${BUILD_DIR}/exec-server-bin"
COV_LIB="${BUILD_DIR}/src/runtime/coverage/libmlfuzzz3_cov.so"
SEEDS="${VENDOR}/magma-src/targets/libpng/corpus/libpng_read_fuzzer"

OURS_BIN="${VENDOR}/out/libpng_read_fuzzer"        # our pass build (also the canary binary)
COV_BIN="${VENDOR}/out-cov/libpng_read_fuzzer"     # neutral measurement frame
AFL_BIN="${VENDOR}/out-afl/libpng_read_fuzzer"
LF_BIN="${VENDOR}/out-libfuzzer/libpng_read_fuzzer"
CANARY_BIN="${OURS_BIN}"                            # canaries ON (build.sh)
ORACLE_READ="${VENDOR}/oracle/oracle_read"

die() { echo "smoke_three_fuzzers.sh: $*" >&2; exit 1; }
for b in "${FUZZER}" "${EXEC_SERVER}" "${OURS_BIN}" "${COV_BIN}" "${AFL_BIN}" "${LF_BIN}" "${CANARY_BIN}"; do
    [ -x "${b}" ] || die "missing binary: ${b} (build all arms first)"
done
[ -f "${COV_LIB}" ] || die "missing libmlfuzzz3_cov: ${COV_LIB}"
[ -d "${SEEDS}" ]   || die "missing libpng corpus: ${SEEDS}"
MSRC="${VENDOR}/magma-src/magma/src"
[ -x "${ORACLE_READ}" ] || clang-20 -I "${MSRC}" -O1 "${SCRIPT_DIR}/fuzzers/mlfuzzz3/src/oracle_read.c" -o "${ORACLE_READ}"

WORK="$(mktemp -d /tmp/mlf_3fuzz_XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# Score a staging dir of inputs: prints "<regions> <reach>".
measure() {
    local dir="$1"
    local regions reach raw
    regions="$(python3 -c "
import sys; sys.path.insert(0, '${REPO_ROOT}/scripts')
import coverage_replay as cr
print(cr.replay_corpus_dir('${COV_BIN}', '${dir}', target_args=())[0])
")"
    raw="$(mktemp)"; head -c 2048 /dev/zero > "${raw}"
    local f
    for f in "${dir}"/*; do
        [ -f "${f}" ] && MAGMA_STORAGE="${raw}" "${CANARY_BIN}" <"${f}" >/dev/null 2>&1 || true
    done
    reach="$("${ORACLE_READ}" "${raw}" | awk '$2+0>0' | wc -l)"
    rm -f "${raw}"
    echo "${regions} ${reach}"
}

stage() { mkdir -p "$1"; }   # flat staging dir per fuzzer

echo "smoke_three_fuzzers.sh: budget ${SECS}s/fuzzer on libpng"

# --- ours ------------------------------------------------------------------
echo "  [ours] running"
"${FUZZER}" --exec-server "${EXEC_SERVER}" --target "${OURS_BIN}" --cov-library "${COV_LIB}" \
    --seed-dir "${SEEDS}" --out-dir "${WORK}/ours" --mutator havoc --max-det-steps 0 \
    --max-seconds "${SECS}" --metrics-interval 1000 --seed 0 >/dev/null 2>&1 || die "ours campaign failed"
S_OURS="${WORK}/stage_ours"; stage "${S_OURS}"
find "${WORK}/ours/corpus" "${WORK}/ours/crashes" -maxdepth 1 -type f -exec cp -t "${S_OURS}" {} + 2>/dev/null || true

# --- AFL++ -----------------------------------------------------------------
echo "  [afl] running"
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
    afl-fuzz -i "${SEEDS}" -o "${WORK}/afl" -V "${SECS}" -- "${AFL_BIN}" >/dev/null 2>&1 || die "afl campaign failed"
S_AFL="${WORK}/stage_afl"; stage "${S_AFL}"
find "${WORK}/afl"/*/queue "${WORK}/afl"/*/crashes -maxdepth 1 -type f ! -name 'README.txt' -exec cp -t "${S_AFL}" {} + 2>/dev/null || true

# --- libFuzzer -------------------------------------------------------------
echo "  [libfuzzer] running"
mkdir -p "${WORK}/lf_corpus"
"${LF_BIN}" -max_total_time="${SECS}" -close_fd_mask=3 "${WORK}/lf_corpus" "${SEEDS}" >/dev/null 2>&1 || true
S_LF="${WORK}/stage_lf"; stage "${S_LF}"
find "${WORK}/lf_corpus" -maxdepth 1 -type f -exec cp -t "${S_LF}" {} + 2>/dev/null || true

# --- score + assert --------------------------------------------------------
ok=1
printf '%-10s %8s %6s\n' fuzzer regions reach
for name in ours afl lf; do
    eval "s=\${S_${name^^}}"
    n="$(find "${s}" -maxdepth 1 -type f | wc -l)"
    read -r regions reach < <(measure "${s}")
    printf '%-10s %8s %6s  (corpus %s)\n' "${name}" "${regions}" "${reach}" "${n}"
    [ "${regions:-0}" -gt 0 ] || { echo "  FAIL: ${name} produced 0 regions" >&2; ok=0; }
    [ "${reach:-0}" -gt 0 ]   || { echo "  FAIL: ${name} produced 0 oracle reach" >&2; ok=0; }
done

if [ "${ok}" -eq 1 ]; then
    echo "smoke_three_fuzzers.sh: OK — all three fuzzers: non-zero regions AND non-zero oracle reach"
    exit 0
else
    echo "smoke_three_fuzzers.sh: FAIL — a fuzzer was degenerate (do not commit; root-cause)" >&2
    exit 1
fi
