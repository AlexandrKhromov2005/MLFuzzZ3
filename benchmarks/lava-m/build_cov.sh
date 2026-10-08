#!/usr/bin/env bash
#
# Build the NEUTRAL measurement binary of coreutils `base64` for the
# comparative-benchmark milestone (ADR 0044, Step 1).
#
# This is the measurement frame, NOT a racing target. Every fuzzer (ours,
# AFL++, later libFuzzer) races base64 on its OWN instrumentation; their
# output corpora are then replayed through THIS single binary, built with
# clang source-based coverage (-fprofile-instr-generate -fcoverage-mapping),
# and scored in llvm-cov region coverage. That neutral unit is what makes the
# cross-fuzzer comparison valid (ADR 0044 Развилка A1 / Инвариант: the
# measurement build defines the unit; self-report and neutral measurement are
# never mixed).
#
# Relationship to build.sh
# -------------------------
# build.sh produces the PASS-instrumented racing binary (EdgeCoveragePass +
# BranchTracePass + libmlfuzzz3_cov). This script produces a SEPARATE,
# standalone binary: same gnulib/clang-20 mitigations (the recipe is
# orthogonal to the instrumentation flavour, ADR 0044 Контекст), but the
# compiler flag is swapped to coverage instrumentation, no pass plugin is
# loaded, and the coverage runtime is NOT linked. It builds in its own tree
# (vendor/cov-build/) so it never clobbers build.sh's vendor/coreutils-8.24.
#
# The source pin (version + SHA256) is the canonical GNU release, identical to
# build.sh; see build.sh's header for the GPG-verified provenance. Kept in
# sync by convention — both name the same upstream tarball.
#
# clang 20 mitigations: see build.sh. Same IOFLAGS + -Wno-implicit-function-
# declaration, same two-phase make (BUILT_SOURCES then src/base64), same
# reason (coreutils 8.24 predates modern glibc/clang).
#
# Output: vendor/base64-cov  (stable path for the replay-measurement module).
#
# Usage:  benchmarks/lava-m/build_cov.sh [--force]
#   --force   re-extract and rebuild even if vendor/base64-cov already exists.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

# --- Pinned source (canonical GNU release; provenance in build.sh) --------
COREUTILS_VERSION="8.24"
TARBALL="coreutils-${COREUTILS_VERSION}.tar.xz"
URL="https://ftp.gnu.org/gnu/coreutils/${TARBALL}"
SHA256="a2d75286a4b9ef3a13039c2da3868a61be4ee9f17d8ae380a35a97e506972170"

COV_BUILD_PARENT="${VENDOR_DIR}/cov-build"
COV_SRC_DIR="${COV_BUILD_PARENT}/coreutils-${COREUTILS_VERSION}"
COV_BIN="${VENDOR_DIR}/base64-cov"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "build_cov.sh: $*" >&2; exit 1; }

# --- Coverage toolchain (bare names absent on host; prefer -20) -----------
LLVM_PROFDATA="$(command -v llvm-profdata-20 || command -v llvm-profdata || true)"
LLVM_COV="$(command -v llvm-cov-20 || command -v llvm-cov || true)"
[ -n "${LLVM_PROFDATA}" ] || die "llvm-profdata-20 not found (need LLVM 20 coverage tools)"
[ -n "${LLVM_COV}" ]      || die "llvm-cov-20 not found (need LLVM 20 coverage tools)"
command -v clang >/dev/null || die "clang not found"

mkdir -p "${VENDOR_DIR}"
cd "${VENDOR_DIR}"

# --- Fetch + verify (STOP on checksum mismatch) ---------------------------
verify() { echo "${SHA256}  ${TARBALL}" | sha256sum -c --status; }

if [ -f "${TARBALL}" ] && verify; then
    echo "build_cov.sh: ${TARBALL} present and checksum OK"
else
    echo "build_cov.sh: downloading ${URL}"
    curl -fSL -o "${TARBALL}.tmp" "${URL}" || die "download failed: ${URL}"
    mv "${TARBALL}.tmp" "${TARBALL}"
    verify || die "SHA256 mismatch for ${TARBALL} — refusing to build an unverified source."
    echo "build_cov.sh: checksum verified"
fi

if [ -x "${COV_BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_cov.sh: ${COV_BIN} already built (use --force to rebuild)"
else
    rm -rf "${COV_BUILD_PARENT}"
    mkdir -p "${COV_BUILD_PARENT}"
    tar xf "${TARBALL}" -C "${COV_BUILD_PARENT}"

    cd "${COV_SRC_DIR}"

    # configure with PLAIN clang (autoconf feature tests must run
    # uninstrumented), same as build.sh.
    echo "build_cov.sh: configure"
    CC=clang CFLAGS="-O1 -g" ./configure --quiet \
        || die "configure failed (see config.log)"

    IOFLAGS="-D_IO_ftrylockfile= -D_IO_IN_BACKUP=0x100 -D_IO_NO_READS=0x4 -D_IO_NO_WRITES=0x8 -D_IO_CURRENTLY_PUTTING=0x800"
    # Neutral measurement instrumentation: clang source-based coverage. No
    # -fpass-plugin, no libmlfuzzz3_cov — a standalone binary that writes a
    # .profraw on exit and carries the coverage mapping for llvm-cov. The
    # profile runtime is pulled in by clang at link because CC is used for the
    # link step too.
    CC_COV="clang -fprofile-instr-generate -fcoverage-mapping -Wno-implicit-function-declaration ${IOFLAGS}"

    echo "build_cov.sh: phase 1 — BUILT_SOURCES"
    BS="$(make --no-print-directory --eval='__pbs: ; @echo $(BUILT_SOURCES)' __pbs 2>/dev/null)"
    # shellcheck disable=SC2086
    make CC="${CC_COV}" ${BS} \
        || die "phase 1 (BUILT_SOURCES) failed"

    echo "build_cov.sh: phase 2 — src/base64"
    make -j"$(nproc)" CC="${CC_COV}" src/base64 \
        || die "phase 2 (src/base64) failed"

    [ -x "${COV_SRC_DIR}/src/base64" ] || die "build reported success but src/base64 is missing"
    cp "${COV_SRC_DIR}/src/base64" "${COV_BIN}"
fi

# --- Smoke: coverage mapping yields nonzero regions on a valid seed -------
# This is the ADR 0044 Step 1 confirm-before-implementation check: prove the
# -fcoverage-mapping build + llvm-profdata/llvm-cov export pipeline works
# end-to-end before any replay-measurement code is written.
echo "build_cov.sh: smoke — coverage export"
SEED="${SCRIPT_DIR}/seeds/hello.b64"
[ -f "${SEED}" ] || die "missing seed corpus: ${SEED}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

LLVM_PROFILE_FILE="${TMP}/run.profraw" "${COV_BIN}" -d <"${SEED}" >/dev/null
[ -f "${TMP}/run.profraw" ] || die "no .profraw written (coverage instrumentation dead)"
"${LLVM_PROFDATA}" merge "${TMP}/run.profraw" -o "${TMP}/cov.profdata" \
    || die "llvm-profdata merge failed"
"${LLVM_COV}" export "${COV_BIN}" -instr-profile="${TMP}/cov.profdata" --summary-only \
    >"${TMP}/summary.json" || die "llvm-cov export failed"

read -r COVERED TOTAL < <(python3 -c "
import json, sys
d = json.load(open('${TMP}/summary.json'))
r = d['data'][0]['totals']['regions']
print(r['covered'], r['count'])
") || die "could not parse llvm-cov export JSON (format changed?)"

[ "${COVERED}" -gt 0 ] || die "smoke failed: ${COVERED}/${TOTAL} regions covered (coverage frame dead)"

echo "build_cov.sh: OK — ${COV_BIN}"
echo "build_cov.sh:    coverage smoke: ${COVERED}/${TOTAL} regions covered on the seed"
