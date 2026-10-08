#!/usr/bin/env bash
#
# libFuzzer racing build of the Magma libtiff harness (ADR 0046 Step 2).
#
# A RACING binary: libFuzzer drives it in-process on its own SanitizerCoverage
# instrumentation; its corpus is replayed post-hoc through the neutral cov
# measurer (build_tiff_cov.sh) and the canary binary (ADR 0044 invariant).
#
# Mirrors build_libfuzzer.sh (libpng) with TARGET=libtiff and program
# tiff_read_rgba_fuzzer. The codec set (PixarLog/LZW/LUV — ADR 0046 Q1) comes
# ONLY from patches/libtiff-narrow-codecs.patch applied by prep_target — this
# driver never sets codec flags. clang-20 -fsanitize=fuzzer-no-link (SanCov) +
# the libFuzzer engine archive (libclang_rt.fuzzer) in $LIBS supplies main().
# No canaries / no our-pass (oracle harvested via the canary binary). Own tree
# (vendor/libfuzzer-tiff, vendor/out-libfuzzer-tiff).
#
# Host-only; not a CI gate. Run benchmarks/magma/fetch_magma.sh first.
# Usage:  benchmarks/magma/build_tiff_libfuzzer.sh [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
# shellcheck source=lib/prep_target.sh
source "${SCRIPT_DIR}/lib/prep_target.sh"

MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libtiff"
TARGET="${VENDOR_DIR}/libfuzzer-tiff/libtiff"
OUT="${VENDOR_DIR}/out-libfuzzer-tiff"
BIN="${OUT}/tiff_read_rgba_fuzzer"
PATCH="${SCRIPT_DIR}/patches/libtiff-narrow-codecs.patch"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
die() { echo "build_tiff_libfuzzer.sh: $*" >&2; exit 1; }

command -v clang-20 >/dev/null || die "clang-20 not found on host"
FUZZER_LIB="$(clang-20 --print-file-name=libclang_rt.fuzzer-x86_64.a)"
[ -f "${FUZZER_LIB}" ] || die "clang-20 libFuzzer engine archive not found: ${FUZZER_LIB} (COMPILER_PATH set?)"
[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run fetch_magma.sh first"

if [ -x "${BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_tiff_libfuzzer.sh: ${BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}"
    # Private copy + narrowing patch + fetch + apply_patches (same codec source).
    prep_target "${TARGET_SRC}" "${TARGET}" "${MAGMA}" "${PATCH}" \
        || die "prep_target failed (patch drift / fetch?)"

    # SanitizerCoverage via -fsanitize=fuzzer-no-link; the libFuzzer engine
    # archive (in LIBS) supplies main(). No canaries / no our pass.
    export CC="clang-20 -fsanitize=fuzzer-no-link"
    export CXX="clang++-20 -fsanitize=fuzzer-no-link"
    export CFLAGS="-g -O0 -Wno-implicit-function-declaration"
    export CXXFLAGS="${CFLAGS}"
    export LIBS="${FUZZER_LIB} -lstdc++"
    export LDFLAGS="-g"
    export OUT TARGET

    echo "build_tiff_libfuzzer.sh: instrument + build target (-fsanitize=fuzzer-no-link)"
    "${TARGET}/build.sh"
    [ -x "${BIN}" ] || die "build reported success but ${BIN} is missing"
fi

# Smoke: a libFuzzer binary accepts -runs=0 and exits cleanly.
file "${BIN}" | grep -q ELF || die "smoke failed: ${BIN} is not an ELF executable"
"${BIN}" -runs=0 -close_fd_mask=3 >/dev/null 2>&1 || die "smoke failed: ${BIN} -runs=0 did not run as a libFuzzer binary"
echo "build_tiff_libfuzzer.sh: OK — ${BIN}"
