#!/usr/bin/env bash
#
# AFL++ racing build of the Magma libtiff harness (ADR 0046 Step 2).
#
# Mirrors build_afl.sh (libpng) with TARGET=libtiff and program
# tiff_read_rgba_fuzzer. A RACING binary: afl-fuzz drives it on AFL's forkserver
# instrumentation; its corpus is replayed post-hoc through the neutral cov
# measurer (build_tiff_cov.sh) and the canary binary for the oracle (ADR 0044
# invariant). AFL++ persistent driver (libAFLDriver.a) supplies main()+__AFL_LOOP.
#
# The codec set (PixarLog/LZW/LUV, zlib+builtin — ADR 0046 Q1) comes ONLY from
# the tracked patches/libtiff-narrow-codecs.patch applied by prep_target. This
# driver sets the instrumentation env and never touches codec flags — one codec
# source shared by every arm.
#
# Two modes (the cmplog fork — ADR 0046 F1 baseline matrix):
#   (default)  plain forkserver binary           -> vendor/out-afl-tiff
#              (the afl-plain arm; also the main binary the cmplog arm drives)
#   --cmplog   CmpLog-instrumented binary (AFL_LLVM_CMPLOG=1) -> vendor/out-afl-cmplog-tiff
#              (the `-c` companion afl-fuzz loads for the cmplog arm)
#
# Host-only; not a CI gate. Run benchmarks/magma/fetch_magma.sh first.
# Usage:  benchmarks/magma/build_tiff_afl.sh [--cmplog] [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
# shellcheck source=lib/prep_target.sh
source "${SCRIPT_DIR}/lib/prep_target.sh"

MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libtiff"
PATCH="${SCRIPT_DIR}/patches/libtiff-narrow-codecs.patch"

CMPLOG=0; FORCE=0
for a in "$@"; do
    case "$a" in
        --cmplog) CMPLOG=1 ;;
        --force)  FORCE=1 ;;
        *) echo "build_tiff_afl.sh: unknown flag: $a" >&2; exit 2 ;;
    esac
done

if [ "${CMPLOG}" -eq 1 ]; then
    TARGET="${VENDOR_DIR}/afl-cmplog-tiff/libtiff"; OUT="${VENDOR_DIR}/out-afl-cmplog-tiff"; LABEL="afl-cmplog"
else
    TARGET="${VENDOR_DIR}/afl-tiff/libtiff";        OUT="${VENDOR_DIR}/out-afl-tiff";        LABEL="afl-plain"
fi
BIN="${OUT}/tiff_read_rgba_fuzzer"
die() { echo "build_tiff_afl.sh: $*" >&2; exit 1; }

AFL_CC="$(command -v afl-clang-fast || true)"
AFL_CXX="$(command -v afl-clang-fast++ || true)"
[ -n "${AFL_CC}" ] && [ -n "${AFL_CXX}" ] || die "afl-clang-fast(++) not found (AFL++ host install required)"
AFL_DRIVER=""
for cand in /usr/local/lib/afl/libAFLDriver.a "$(dirname "$(dirname "${AFL_CC}")")/lib/afl/libAFLDriver.a"; do
    [ -f "${cand}" ] && { AFL_DRIVER="${cand}"; break; }
done
[ -n "${AFL_DRIVER}" ] || die "libAFLDriver.a not found (AFL++ aflpp_driver required)"
[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run fetch_magma.sh first"

if [ -x "${BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_tiff_afl.sh: ${BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}"
    # Private copy + narrowing patch (one codec source for every arm).
    prep_target "${TARGET_SRC}" "${TARGET}" "${MAGMA}" "${PATCH}" \
        || die "prep_target failed (patch drift / fetch?)"

    # AFL forkserver instrumentation; persistent driver supplies main(). No
    # canaries and no our-pass (oracle harvested via the canary binary).
    export CC="${AFL_CC}" CXX="${AFL_CXX}"
    export CFLAGS="-g -O0 -Wno-implicit-function-declaration"
    export CXXFLAGS="${CFLAGS}"
    export LIBS="${AFL_DRIVER} -lstdc++"
    export LDFLAGS="-g"
    export OUT TARGET AFL_QUIET=1
    [ "${CMPLOG}" -eq 1 ] && export AFL_LLVM_CMPLOG=1   # CmpLog comparison instrumentation (ADR 0046 F1)

    echo "build_tiff_afl.sh: build ${LABEL} (afl-clang-fast$([ "${CMPLOG}" -eq 1 ] && echo ' + CmpLog'))"
    "${TARGET}/build.sh"
    [ -x "${BIN}" ] || die "build reported success but ${BIN} is missing"
fi

file "${BIN}" | grep -q ELF || die "smoke failed: ${BIN} is not an ELF executable"
echo "build_tiff_afl.sh: OK — ${BIN} (${LABEL})"
