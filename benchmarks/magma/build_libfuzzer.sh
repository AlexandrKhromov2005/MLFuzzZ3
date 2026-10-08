#!/usr/bin/env bash
#
# libFuzzer racing build of the Magma libpng harness (ADR 0045 Step 6).
#
# A RACING binary: libFuzzer drives it in-process on its own SanitizerCoverage
# instrumentation; its output corpus is later replayed through the neutral
# measurement binary (build_cov.sh) and the canary binary, so libFuzzer's own
# coverage is never the comparison unit (ADR 0044 invariant). On Magma all three
# fuzzers share the SAME in-process LLVMFuzzerTestOneInput harness, which is what
# removes the base64 entry-point asymmetry (ADR 0045 Контекст).
#
# Built via Magma's env-driven recipe with clang-20.1.2 -fsanitize=fuzzer-no-link
# (SanCov on libpng + harness) and the clang libFuzzer engine archive
# (libclang_rt.fuzzer) in $LIBS supplying main()/LLVMFuzzerRunDriver — the
# Magma libfuzzer pattern (engine archive in LIBS), standardised on our clang-20
# rather than Magma's clang-11. No canaries / no our-pass (oracle harvested by
# replaying the corpus through the canary binary). Own tree (vendor/libfuzzer,
# vendor/out-libfuzzer).
#
# Host-only; not a CI gate. Run benchmarks/magma/fetch_magma.sh first.
# Usage:  benchmarks/magma/build_libfuzzer.sh [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libpng"
TARGET="${VENDOR_DIR}/libfuzzer/libpng"
OUT="${VENDOR_DIR}/out-libfuzzer"
BIN="${OUT}/libpng_read_fuzzer"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
die() { echo "build_libfuzzer.sh: $*" >&2; exit 1; }

command -v clang-20 >/dev/null || die "clang-20 not found on host"
FUZZER_LIB="$(clang-20 --print-file-name=libclang_rt.fuzzer-x86_64.a)"
[ -f "${FUZZER_LIB}" ] || die "clang-20 libFuzzer engine archive not found: ${FUZZER_LIB}"
[ -d "${VENDOR_DIR}/magma-src/.git" ] || die "Magma not fetched — run fetch_magma.sh first"

if [ -x "${BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_libfuzzer.sh: ${BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}"
    rm -rf "${TARGET}"; mkdir -p "$(dirname "${TARGET}")"
    cp -a "${TARGET_SRC}" "${TARGET}"

    echo "build_libfuzzer.sh: fetch libpng (pinned a37d4836)"
    TARGET="${TARGET}" "${TARGET}/fetch.sh"
    echo "build_libfuzzer.sh: apply patches (setup + bugs; canary calls compile out)"
    TARGET="${TARGET}" "${MAGMA}/apply_patches.sh"

    # SanitizerCoverage via -fsanitize=fuzzer-no-link; the libFuzzer engine
    # archive (in LIBS) supplies main(). No canaries / no our pass.
    export CC="clang-20 -fsanitize=fuzzer-no-link"
    export CXX="clang++-20 -fsanitize=fuzzer-no-link"
    export CFLAGS="-g -O0 -Wno-implicit-function-declaration"
    export CXXFLAGS="${CFLAGS}"
    export LIBS="${FUZZER_LIB} -lstdc++"
    export LDFLAGS="-g"
    export OUT TARGET

    echo "build_libfuzzer.sh: instrument + build target (-fsanitize=fuzzer-no-link)"
    "${TARGET}/build.sh"
    [ -x "${BIN}" ] || die "build reported success but ${BIN} is missing"
fi

# Smoke: a libFuzzer binary accepts -runs=0 and exits cleanly.
file "${BIN}" | grep -q ELF || die "smoke failed: ${BIN} is not an ELF executable"
"${BIN}" -runs=0 -close_fd_mask=3 >/dev/null 2>&1 || die "smoke failed: ${BIN} -runs=0 did not run as a libFuzzer binary"
echo "build_libfuzzer.sh: OK — ${BIN}"
