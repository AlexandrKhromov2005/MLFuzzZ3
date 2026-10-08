#!/usr/bin/env bash
#
# Exec-server end-to-end smoke for the Magma libpng slice (ADR 0045 Step 2).
#
# Confirms our stdin driver shim drives the in-process Magma harness through the
# exec-server's process model (fork+exec, input on stdin, LD_PRELOAD coverage
# runtime, fd 3 edge / fd 4 branch — ADR 0011/0033). Magma harnesses export the
# libFuzzer callback LLVMFuzzerTestOneInput with no main(); the shim supplies
# main() and feeds one stdin input per process. This proves the shim/harness
# contract (signature + optional LLVMFuzzerInitialize) holds under exec-server,
# not just standalone — the Step 2 STOP gate.
#
# Runs a brief coverage-only campaign of our fuzzer over the libpng corpus and
# asserts: edges recorded > 0, zero IPC errors, executions happened. base64-
# style host-only smoke; not a CI gate. Requires benchmarks/magma/build.sh to
# have produced vendor/out/libpng_read_fuzzer.
#
# Usage:  benchmarks/magma/smoke_execserver.sh [seconds]   (default 6)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"

SECONDS_BUDGET="${1:-6}"

FUZZER="${BUILD_DIR}/src/cli/fuzzer"
EXEC_SERVER="${BUILD_DIR}/exec-server-bin"
COV="${BUILD_DIR}/src/runtime/coverage/libmlfuzzz3_cov.so"
TARGET="${SCRIPT_DIR}/vendor/out/libpng_read_fuzzer"
SEEDS="${SCRIPT_DIR}/vendor/magma-src/targets/libpng/corpus/libpng_read_fuzzer"

die() { echo "smoke_execserver.sh: $*" >&2; exit 1; }

[ -x "${FUZZER}" ]      || die "fuzzer CLI missing: ${FUZZER} (build the project)"
[ -x "${EXEC_SERVER}" ] || die "exec-server missing: ${EXEC_SERVER} (build the project)"
[ -f "${COV}" ]         || die "libmlfuzzz3_cov missing: ${COV} (build the project)"
[ -x "${TARGET}" ]      || die "target missing: ${TARGET} (run benchmarks/magma/build.sh)"
[ -d "${SEEDS}" ]       || die "libpng corpus missing: ${SEEDS}"

OUT="$(mktemp -d /tmp/mlf_magma_smoke_XXXXXX)"
LOG="${OUT}/campaign.log"
trap 'rm -rf "${OUT}"' EXIT

echo "smoke_execserver.sh: running ${SECONDS_BUDGET}s coverage campaign on libpng_read_fuzzer"
"${FUZZER}" \
    --exec-server "${EXEC_SERVER}" \
    --target "${TARGET}" --cov-library "${COV}" \
    --seed-dir "${SEEDS}" --out-dir "${OUT}" \
    --mutator havoc --max-det-steps 0 \
    --max-seconds "${SECONDS_BUDGET}" --metrics-interval 200 --seed 0 \
    >"${LOG}" 2>&1 || die "fuzzer campaign exited non-zero (see ${LOG})"

# The authoritative summary is the "campaign done:" log line, which carries
# ipc_errors and aborted (the metrics.jsonl record does not).
DONE="$(grep -o 'campaign done:.*' "${LOG}" | tail -1 || true)"
[ -n "${DONE}" ] || die "no 'campaign done' line — campaign did not complete"
echo "smoke_execserver.sh: ${DONE}"

field() { echo "${DONE}" | grep -oE "$1=[^ ]+" | head -1 | cut -d= -f2; }
EXECS="$(field execs)"; EDGES="$(field edges)"
IPC="$(field ipc_errors)"; ABORTED="$(field aborted)"

[ "${EXECS:-0}" -gt 0 ]    || die "no executions — exec-server did not drive the harness"
[ "${EDGES:-0}" -gt 0 ]    || die "zero edges — instrumentation/shim dead through exec-server"
[ "${IPC:-1}" -eq 0 ]      || die "IPC errors (${IPC}) — shim/harness mismatch under exec-server"
[ "${ABORTED}" = "false" ] || die "campaign aborted — shim/harness or exec-server failure"

echo "smoke_execserver.sh: OK — shim drives the libpng harness through exec-server (${EDGES} edges, 0 IPC errors)"
