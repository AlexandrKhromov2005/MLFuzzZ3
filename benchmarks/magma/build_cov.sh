#!/usr/bin/env bash
#
# Neutral measurement build of the Magma libpng harness (ADR 0045 Step 3).
#
# This is the measurement frame, NOT a racing target. Every fuzzer (ours,
# AFL++, libFuzzer) races libpng on its OWN instrumentation; their output
# corpora are then replayed through THIS single binary, built with clang
# source-based coverage (-fprofile-instr-generate -fcoverage-mapping), and
# scored in llvm-cov region coverage. That neutral unit is what makes the
# cross-fuzzer comparison valid (ADR 0044 invariant; ADR 0045 Развилка F1: the
# measurement build is standardised on clang-20.1.2 — Magma's own fuzzers/
# llvm_cov is clang-9 and would desync the unit from the racing toolchain).
#
# Same env-driven recipe as build.sh, but the compiler flag is swapped from our
# pass plugins to clang coverage, no libmlfuzzz3_cov is linked, and canaries are
# OFF — this is a clean libpng region frame, a separate artifact from the racing
# builds (ADR 0044). The stdin driver shim still supplies main() so the binary
# reads one input per process on stdin, matching coverage_replay.py.
#
# Built in its own tree (vendor/cov/) and own OUT (vendor/out-cov/) so it never
# clobbers build.sh's racing tree. Host-only research tooling; not a CI gate.
# Run benchmarks/magma/fetch_magma.sh first.
#
# Usage:  benchmarks/magma/build_cov.sh [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libpng"
TARGET="${VENDOR_DIR}/cov/libpng"          # private copy so its repo/.libs are isolated
FUZZER="${SCRIPT_DIR}/fuzzers/mlfuzzz3"     # reuse the stdin shim source
OUT="${VENDOR_DIR}/out-cov"
COV_BIN="${OUT}/libpng_read_fuzzer"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "build_cov.sh: $*" >&2; exit 1; }

[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run benchmarks/magma/fetch_magma.sh first"
command -v clang-20 >/dev/null || die "clang-20 not found on host"

# --- Coverage toolchain (bare names absent on host; prefer -20) -----------
LLVM_PROFDATA="$(command -v llvm-profdata-20 || command -v llvm-profdata || true)"
LLVM_COV="$(command -v llvm-cov-20 || command -v llvm-cov || true)"
[ -n "${LLVM_PROFDATA}" ] || die "llvm-profdata-20 not found (need LLVM 20 coverage tools)"
[ -n "${LLVM_COV}" ]      || die "llvm-cov-20 not found (need LLVM 20 coverage tools)"

if [ -x "${COV_BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_cov.sh: ${COV_BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}"
    # Private target copy (carries build.sh/fetch.sh/configrc/patches) so its
    # in-tree repo/.libs never collide with the racing build's tree. TARGET_SRC
    # is the canonical vendor target and stays stock — since task-011 the racing
    # canary build.sh also builds in its own copy, so no arm ever fetches or
    # patches in place and the copy starts as a clean, unpatched recipe.
    rm -rf "${TARGET}"
    mkdir -p "$(dirname "${TARGET}")"
    cp -a "${TARGET_SRC}" "${TARGET}"

    echo "build_cov.sh: fetch libpng (pinned a37d4836)"
    TARGET="${TARGET}" "${TARGET}/fetch.sh"
    echo "build_cov.sh: apply patches (setup + bugs; canary calls compile out)"
    TARGET="${TARGET}" "${MAGMA}/apply_patches.sh"

    echo "build_cov.sh: build stdin shim (plain clang)"
    "${MLFUZZZ3_CLANG:-clang-20}" -O1 -g -fPIC -c \
        "${FUZZER}/src/mlfuzzz3_shim.c" -o "${OUT}/mlfuzzz3_shim.o"

    # Neutral measurement instrumentation: clang source-based coverage, no pass
    # plugin, no libmlfuzzz3_cov, no canaries (no -include canary.h, no magma.o).
    # The profile runtime is pulled by clang at link because CC links too.
    COVFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wno-implicit-function-declaration"
    export CC="clang-20 ${COVFLAGS}"
    export CXX="clang++-20 ${COVFLAGS}"
    export CFLAGS="-g -O0"
    export CXXFLAGS="-g -O0"
    export LIBS="-l:mlfuzzz3_shim.o -lstdc++"
    export LDFLAGS="-L${OUT} -g"
    export OUT TARGET

    echo "build_cov.sh: build measurement target"
    "${TARGET}/build.sh"

    [ -x "${COV_BIN}" ] || die "build reported success but ${COV_BIN} is missing"
fi

# --- Smoke: coverage mapping yields nonzero regions on a real PNG seed -----
echo "build_cov.sh: smoke — neutral region replay of one input"
SEED_DIR="${TARGET_SRC}/corpus/libpng_read_fuzzer"
SEED="$(find "${SEED_DIR}" -maxdepth 1 -type f | head -1)"
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

echo "build_cov.sh: OK — ${COV_BIN}"
echo "build_cov.sh:    region replay smoke: ${COVERED}/${TOTAL} regions covered on $(basename "${SEED}")"
