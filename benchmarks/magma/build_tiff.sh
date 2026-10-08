#!/usr/bin/env bash
#
# Canary (ours) racing build of the Magma libtiff harness (ADR 0046 Step 2).
#
# Our pass-instrumented racing binary with the Magma bug oracle ON
# (-DMAGMA_ENABLE_CANARIES), mirroring build.sh (libpng) with TARGET=libtiff and
# program tiff_read_rgba_fuzzer. The stdin shim supplies main(); instrument.sh
# points CC/CXX at our self-injecting wrapper (Branch+Edge passes + libmlfuzzz3_cov).
#
# Discrepancy #3 (ADR 0046 Step 2) — RESOLVED: EVERY arm of BOTH targets,
# INCLUDING this canary and libpng's, builds on a PRIVATE COPY via prep_target —
# the canonical vendor target stays stock. libpng's canary was the last arm
# building in-place on the canonical target (an exception from its own copy-based
# pattern, which forced a defensive `rm -rf repo` in the other arms); task-011
# unified it onto this pattern (benchmarks/magma/build.sh). Here a stock canonical
# is REQUIRED: the Option-2 codec-narrowing patch (PixarLog/LZW/LUV, ADR 0046 Q1)
# is applied to the per-arm copy only — vendor is never modified, and copies never
# double-apply. The codec set comes ONLY from the patch prep_target applies — this
# driver never sets codec flags.
#
# Host-only research tooling (clang-20, fetched Magma + libtiff sources); not a CI
# gate. Run benchmarks/magma/fetch_magma.sh first.
#
# Usage:  benchmarks/magma/build_tiff.sh [--force]
#   --force   rebuild even if vendor/out-tiff/tiff_read_rgba_fuzzer exists.
#
# Env overrides:
#   BUILD_DIR   project build tree holding the passes + runtime (default: build/)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
# shellcheck source=lib/prep_target.sh
source "${SCRIPT_DIR}/lib/prep_target.sh"

export MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libtiff"   # canonical (stays stock)
export TARGET="${VENDOR_DIR}/ours/libtiff"             # private copy (improvement #3)
export FUZZER="${SCRIPT_DIR}/fuzzers/mlfuzzz3"
export OUT="${VENDOR_DIR}/out-tiff"
export SHARED="${VENDOR_DIR}/shared-tiff"
export LD=/usr/bin/ld
PATCH="${SCRIPT_DIR}/patches/libtiff-narrow-codecs.patch"

# --- Project instrumentation artefacts ------------------------------------
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"
export MLFUZZZ3_EDGE_PASS="${BUILD_DIR}/src/instrumentation/edge_coverage_pass/libEdgeCoveragePass.so"
export MLFUZZZ3_BRANCH_PASS="${BUILD_DIR}/src/instrumentation/branch_trace_pass/libBranchTracePass.so"
export MLFUZZZ3_COV_LIB="${BUILD_DIR}/src/runtime/coverage/libmlfuzzz3_cov.so"
export MLFUZZZ3_CLANG=clang-20
export MLFUZZZ3_CLANGXX=clang++-20

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
die() { echo "build_tiff.sh: $*" >&2; exit 1; }

[ -f "${MLFUZZZ3_EDGE_PASS}" ]   || die "EdgeCoveragePass missing: ${MLFUZZZ3_EDGE_PASS} (build the project: cmake --build ${BUILD_DIR})"
[ -f "${MLFUZZZ3_BRANCH_PASS}" ] || die "BranchTracePass missing: ${MLFUZZZ3_BRANCH_PASS} (build the project first)"
[ -f "${MLFUZZZ3_COV_LIB}" ]     || die "libmlfuzzz3_cov missing: ${MLFUZZZ3_COV_LIB} (build the project first)"
[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run benchmarks/magma/fetch_magma.sh first"
command -v clang-20 >/dev/null || die "clang-20 not found on host"

BIN="${OUT}/tiff_read_rgba_fuzzer"
if [ -x "${BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_tiff.sh: ${BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}" "${SHARED}"

    # Private copy + narrowing patch + fetch + apply_patches (one codec source).
    prep_target "${TARGET_SRC}" "${TARGET}" "${MAGMA}" "${PATCH}" \
        || die "prep_target failed (patch drift / fetch?)"

    # prebuild the monitor with PLAIN clang and EMPTY instrumentation env — the
    # docker flow builds it before CFLAGS/LIBS are set (host-side consumer).
    echo "build_tiff.sh: prebuild monitor"
    env CC=clang-20 CFLAGS= CXXFLAGS= LDFLAGS= LIBS= "${MAGMA}/prebuild.sh"

    echo "build_tiff.sh: build stdin shim"
    "${FUZZER}/build.sh"

    # Instrumentation env (mirrors build.sh), canaries ON. Codec set is fixed by
    # the patch already applied to ${TARGET}/build.sh — not touched here.
    echo "build_tiff.sh: instrument + build target"
    export CFLAGS="-include ${MAGMA}/src/canary.h -DMAGMA_ENABLE_CANARIES -g -O0"
    export CXXFLAGS="${CFLAGS}"
    export LIBS="-l:magma.o -lrt"
    export LDFLAGS="-L${OUT} -g"
    "${FUZZER}/instrument.sh"

    [ -x "${BIN}" ] || die "build reported success but ${BIN} is missing"
fi

# --- Smoke: instrumentation alive on a real TIFF seed ---------------------
echo "build_tiff.sh: smoke — instrumentation alive"
SEED_DIR="${TARGET_SRC}/corpus/tiff_read_rgba_fuzzer"
[ -d "${SEED_DIR}" ] || die "missing libtiff corpus: ${SEED_DIR}"
# -print -quit (not `| head -1`): the libtiff corpus has hundreds of seeds, and
# `find | head -1` makes find take SIGPIPE — fatal under `set -o pipefail`.
SEED="$(find "${SEED_DIR}" -maxdepth 1 -type f -print -quit)"
[ -n "${SEED}" ] || die "no seed file under ${SEED_DIR}"

SCRATCH="$(mktemp)"
trap 'rm -f "${SCRATCH}"' EXIT
truncate -s 65536 "${SCRATCH}"
( exec 3<>"${SCRATCH}"; MLFUZZZ3_COV_FD=3 "${BIN}" <"${SEED}" >/dev/null 2>&1 )
NONZERO="$(python3 -c "d=open('${SCRATCH}','rb').read(); print(sum(1 for b in d if b))")"
[ "${NONZERO}" -gt 0 ] || die "smoke failed: ${NONZERO} edges recorded (instrumentation dead)"

echo "build_tiff.sh: OK — ${BIN}"
echo "build_tiff.sh:    instrumentation smoke recorded ${NONZERO} non-zero edge cells on $(basename "${SEED}")"
