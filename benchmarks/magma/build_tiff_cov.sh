#!/usr/bin/env bash
#
# Neutral measurement build of the Magma libtiff harness (ADR 0046 Step 2).
#
# Measurement frame, NOT a racing arm: every fuzzer (ours, AFL++ plain, AFL++
# cmplog, libFuzzer) races libtiff on its OWN instrumentation; their corpora are
# replayed through THIS single clang source-coverage binary and scored in
# llvm-cov region coverage (ADR 0044 neutral-frame invariant; ADR 0046).
#
# Mirrors build_cov.sh (libpng) with TARGET=libtiff and program
# tiff_read_rgba_fuzzer. The codec set (PixarLog/LZW/LUV — ADR 0046 Q1) comes
# ONLY from patches/libtiff-narrow-codecs.patch applied by prep_target, so the
# measurement frame carries the SAME codecs as the racing arms (a correct
# comparison requires it). Canaries OFF, no pass plugin, no libmlfuzzz3_cov; the
# stdin shim supplies main() so the binary reads one input per process on stdin,
# matching coverage_replay.py.
#
# Own tree (vendor/cov-tiff, vendor/out-cov-tiff). Host-only; not a CI gate.
# Run benchmarks/magma/fetch_magma.sh first.
#
# Usage:  benchmarks/magma/build_tiff_cov.sh [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
# shellcheck source=lib/prep_target.sh
source "${SCRIPT_DIR}/lib/prep_target.sh"

MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libtiff"
TARGET="${VENDOR_DIR}/cov-tiff/libtiff"      # private copy so its repo/.libs are isolated
FUZZER="${SCRIPT_DIR}/fuzzers/mlfuzzz3"        # reuse the stdin shim source
OUT="${VENDOR_DIR}/out-cov-tiff"
COV_BIN="${OUT}/tiff_read_rgba_fuzzer"
PATCH="${SCRIPT_DIR}/patches/libtiff-narrow-codecs.patch"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
die() { echo "build_tiff_cov.sh: $*" >&2; exit 1; }

[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run benchmarks/magma/fetch_magma.sh first"
command -v clang-20 >/dev/null || die "clang-20 not found on host"

# --- Coverage toolchain (bare names absent on host; prefer -20) -----------
LLVM_PROFDATA="$(command -v llvm-profdata-20 || command -v llvm-profdata || true)"
LLVM_COV="$(command -v llvm-cov-20 || command -v llvm-cov || true)"
[ -n "${LLVM_PROFDATA}" ] || die "llvm-profdata-20 not found (need LLVM 20 coverage tools)"
[ -n "${LLVM_COV}" ]      || die "llvm-cov-20 not found (need LLVM 20 coverage tools)"

if [ -x "${COV_BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_tiff_cov.sh: ${COV_BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}"
    # Private copy + narrowing patch + fetch + apply_patches (same codec source).
    prep_target "${TARGET_SRC}" "${TARGET}" "${MAGMA}" "${PATCH}" \
        || die "prep_target failed (patch drift / fetch?)"

    echo "build_tiff_cov.sh: build stdin shim (plain clang)"
    "${MLFUZZZ3_CLANG:-clang-20}" -O1 -g -fPIC -c \
        "${FUZZER}/src/mlfuzzz3_shim.c" -o "${OUT}/mlfuzzz3_shim.o"

    # Neutral measurement instrumentation: clang source-based coverage, no pass
    # plugin, no libmlfuzzz3_cov, no canaries. Codec set fixed by the patch.
    COVFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wno-implicit-function-declaration"
    export CC="clang-20 ${COVFLAGS}"
    export CXX="clang++-20 ${COVFLAGS}"
    export CFLAGS="-g -O0"
    export CXXFLAGS="-g -O0"
    export LIBS="-l:mlfuzzz3_shim.o -lstdc++"
    export LDFLAGS="-L${OUT} -g"
    export OUT TARGET

    echo "build_tiff_cov.sh: build measurement target"
    "${TARGET}/build.sh"

    [ -x "${COV_BIN}" ] || die "build reported success but ${COV_BIN} is missing"
fi

# --- Smoke: coverage mapping yields nonzero regions on a real TIFF seed ----
echo "build_tiff_cov.sh: smoke — neutral region replay of one input"
SEED_DIR="${TARGET_SRC}/corpus/tiff_read_rgba_fuzzer"
# -print -quit (not `| head -1`): the libtiff corpus has hundreds of seeds, and
# `find | head -1` makes find take SIGPIPE — fatal under `set -o pipefail`.
SEED="$(find "${SEED_DIR}" -maxdepth 1 -type f -print -quit)"
[ -n "${SEED}" ] || die "no seed under ${SEED_DIR}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

LLVM_PROFILE_FILE="${TMP}/run.profraw" "${COV_BIN}" <"${SEED}" >/dev/null 2>&1 || true
[ -f "${TMP}/run.profraw" ] || die "no .profraw written (coverage instrumentation dead)"
"${LLVM_PROFDATA}" merge "${TMP}/run.profraw" -o "${TMP}/cov.profdata" \
    || die "llvm-profdata merge failed"
"${LLVM_COV}" export "${COV_BIN}" -instr-profile="${TMP}/cov.profdata" --summary-only \
    >"${TMP}/summary.json" || die "llvm-cov export failed"

read -r COVERED TOTAL < <(python3 -c "
import json
d = json.load(open('${TMP}/summary.json'))
r = d['data'][0]['totals']['regions']
print(r['covered'], r['count'])
") || die "could not parse llvm-cov export JSON"

[ "${COVERED}" -gt 0 ] || die "smoke failed: ${COVERED}/${TOTAL} regions (coverage frame dead)"

echo "build_tiff_cov.sh: OK — ${COV_BIN}"
echo "build_tiff_cov.sh:    region replay smoke: ${COVERED}/${TOTAL} regions covered on $(basename "${SEED}")"
