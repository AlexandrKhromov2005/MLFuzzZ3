#!/usr/bin/env bash
#
# Host-build driver for the Magma libpng comparative-benchmark slice (ADR 0045
# Step 1). Magma's captain orchestrator is docker-only and its docker pins
# clang-9/11; our EdgeCoveragePass/BranchTracePass require LLVM 20 (ADR
# 0024/0033). So we bypass captain and drive Magma's env-driven build recipe by
# hand on the host under clang-20.1.2 (ADR 0045 Развилка A1), reproducing the
# variable contract the docker flow sets (docker/Dockerfile): CC/CXX/LD,
# CFLAGS/CXXFLAGS (-include canary.h + canaries flag), LIBS (-l:magma.o), OUT,
# SHARED, MAGMA, TARGET, FUZZER.
#
# Flow (mirrors the Dockerfile order): prep_target (private copy of the target
# recipe + fetch + patch libpng) → prebuild monitor (plain clang, BEFORE the
# instrumentation env is set) → build the stdin shim → run
# fuzzers/mlfuzzz3/instrument.sh (sets CC/CXX = our wrapper, appends the shim to
# LIBS, builds magma.o + the target). Canaries are enabled
# (-DMAGMA_ENABLE_CANARIES) so the same racing binary carries the bug oracle
# (ADR 0045 Развилка D); the oracle is orthogonal to our instrumentation.
#
# Discrepancy #3 (ADR 0046 Step 2) — RESOLVED here by task-011: this canary was
# the SOLE arm building in-place on the canonical vendor target, an exception
# from the copy-based pattern its own cov/afl/libfuzzer arms already used (and
# the reason those carried a defensive `repo` wipe, since removed). It now
# builds on a PRIVATE COPY via lib/prep_target.sh, exactly like every libtiff
# arm: TARGET_SRC is the canonical target and stays stock, TARGET is the
# gitignored copy. libpng takes no recipe patch (unlike libtiff's codec
# narrowing, ADR 0046 Q1), so the copy is recipe-identical to the canonical
# target — the ADR-0045 result (513cc03) is not affected; only the path the
# tree is built in moved.
#
# Host-only research tooling (clang-20, the fetched Magma + libpng sources); not
# a CI gate (ADR 0044/0045). Run benchmarks/magma/fetch_magma.sh first.
#
# Usage:  benchmarks/magma/build.sh [--force]
#   --force   rebuild even if vendor/out/libpng_read_fuzzer already exists.
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
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libpng"   # canonical (stays stock)
export TARGET="${VENDOR_DIR}/ours/libpng"             # private copy (Discrepancy #3)
export FUZZER="${SCRIPT_DIR}/fuzzers/mlfuzzz3"
export OUT="${VENDOR_DIR}/out"
export SHARED="${VENDOR_DIR}/shared"
export LD=/usr/bin/ld

# --- Project instrumentation artefacts ------------------------------------
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"
export MLFUZZZ3_EDGE_PASS="${BUILD_DIR}/src/instrumentation/edge_coverage_pass/libEdgeCoveragePass.so"
export MLFUZZZ3_BRANCH_PASS="${BUILD_DIR}/src/instrumentation/branch_trace_pass/libBranchTracePass.so"
export MLFUZZZ3_COV_LIB="${BUILD_DIR}/src/runtime/coverage/libmlfuzzz3_cov.so"
export MLFUZZZ3_CLANG=clang-20
export MLFUZZZ3_CLANGXX=clang++-20

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "build.sh: $*" >&2; exit 1; }

[ -f "${MLFUZZZ3_EDGE_PASS}" ]   || die "EdgeCoveragePass missing: ${MLFUZZZ3_EDGE_PASS} (build the project: cmake --build ${BUILD_DIR})"
[ -f "${MLFUZZZ3_BRANCH_PASS}" ] || die "BranchTracePass missing: ${MLFUZZZ3_BRANCH_PASS} (build the project first)"
[ -f "${MLFUZZZ3_COV_LIB}" ]     || die "libmlfuzzz3_cov missing: ${MLFUZZZ3_COV_LIB} (build the project first)"
[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run benchmarks/magma/fetch_magma.sh first"
command -v clang-20 >/dev/null || die "clang-20 not found on host"

BIN="${OUT}/libpng_read_fuzzer"
if [ -x "${BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build.sh: ${BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}" "${SHARED}"

    # Private copy + fetch + apply_patches. No recipe patch for libpng, so the
    # copy differs from the canonical target only in where it lives. Idempotent
    # by construction: prep_target re-creates the copy and drops its repo/, so a
    # rebuild always starts from a clean checkout (fetch.sh refuses an existing
    # repo and the Magma patches are non-reentrant).
    prep_target "${TARGET_SRC}" "${TARGET}" "${MAGMA}" \
        || die "prep_target failed (fetch?)"

    # prebuild the monitor with PLAIN clang and EMPTY instrumentation env — the
    # docker flow builds it before CFLAGS/LIBS are set, and it is a host-side
    # consumer, not an instrumented target.
    echo "build.sh: prebuild monitor"
    env CC=clang-20 CFLAGS= CXXFLAGS= LDFLAGS= LIBS= "${MAGMA}/prebuild.sh"

    echo "build.sh: build stdin shim"
    "${FUZZER}/build.sh"

    # Instrumentation env (mirrors docker/Dockerfile lines 79-84), canaries ON.
    echo "build.sh: instrument + build target"
    export CFLAGS="-include ${MAGMA}/src/canary.h -DMAGMA_ENABLE_CANARIES -g -O0"
    export CXXFLAGS="${CFLAGS}"
    export LIBS="-l:magma.o -lrt"
    export LDFLAGS="-L${OUT} -g"
    "${FUZZER}/instrument.sh"

    [ -x "${BIN}" ] || die "build reported success but ${BIN} is missing"
fi

# --- Smoke: instrumentation alive on a real PNG seed ----------------------
# Feed a corpus seed on stdin (the shim reads stdin), wire fd 3 to a scratch
# edge bitmap, assert the run recorded edges. Mirrors benchmarks/lava-m/build.sh
# — proves the build is not degenerate (ADR 0044 discipline) before any
# campaign uses it.
echo "build.sh: smoke — instrumentation alive"
SEED_DIR="${TARGET_SRC}/corpus/libpng_read_fuzzer"
[ -d "${SEED_DIR}" ] || die "missing libpng corpus: ${SEED_DIR}"
SEED="$(find "${SEED_DIR}" -maxdepth 1 -type f | head -1)"
[ -n "${SEED}" ] || die "no seed file under ${SEED_DIR}"

SCRATCH="$(mktemp)"
trap 'rm -f "${SCRATCH}"' EXIT
truncate -s 65536 "${SCRATCH}"
( exec 3<>"${SCRATCH}"; MLFUZZZ3_COV_FD=3 "${BIN}" <"${SEED}" >/dev/null 2>&1 )
NONZERO="$(python3 -c "d=open('${SCRATCH}','rb').read(); print(sum(1 for b in d if b))")"
[ "${NONZERO}" -gt 0 ] || die "smoke failed: ${NONZERO} edges recorded (instrumentation dead)"

echo "build.sh: OK — ${BIN}"
echo "build.sh:    instrumentation smoke recorded ${NONZERO} non-zero edge cells on $(basename "${SEED}")"
