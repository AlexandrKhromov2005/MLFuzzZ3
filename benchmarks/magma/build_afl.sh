#!/usr/bin/env bash
#
# AFL++ racing build of the Magma libpng harness (ADR 0045 Step 6).
#
# A RACING binary, not a measurement one: afl-fuzz drives it on AFL's own
# forkserver instrumentation; its output corpus is later replayed through the
# neutral measurement binary (build_cov.sh) for region coverage and through the
# canary binary for the oracle — AFL's self-reported coverage is never the
# comparison unit (ADR 0044 invariant).
#
# Built via Magma's env-driven recipe (like build.sh) with CC/CXX =
# afl-clang-fast (a clang-20.1.2 wrapper, = our toolchain) and the AFL++
# persistent driver (libAFLDriver.a / aflpp_driver) supplying main() +
# __AFL_LOOP for the LLVMFuzzerTestOneInput harness. No canaries and no our-pass
# here (the oracle is harvested by replaying the corpus through the canary
# binary, orthogonally). Own tree (vendor/afl, vendor/out-afl).
#
# Host-only; not a CI gate. Run benchmarks/magma/fetch_magma.sh first.
# Usage:  benchmarks/magma/build_afl.sh [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

MAGMA="${VENDOR_DIR}/magma-src/magma"
TARGET_SRC="${VENDOR_DIR}/magma-src/targets/libpng"
TARGET="${VENDOR_DIR}/afl/libpng"
OUT="${VENDOR_DIR}/out-afl"
BIN="${OUT}/libpng_read_fuzzer"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
die() { echo "build_afl.sh: $*" >&2; exit 1; }

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
    echo "build_afl.sh: ${BIN} already built (use --force to rebuild)"
else
    mkdir -p "${OUT}"
    rm -rf "${TARGET}"; mkdir -p "$(dirname "${TARGET}")"
    cp -a "${TARGET_SRC}" "${TARGET}"

    echo "build_afl.sh: fetch libpng (pinned a37d4836)"
    TARGET="${TARGET}" "${TARGET}/fetch.sh"
    echo "build_afl.sh: apply patches (setup + bugs; canary calls compile out)"
    TARGET="${TARGET}" "${MAGMA}/apply_patches.sh"

    # AFL forkserver instrumentation; persistent driver supplies main(). No
    # canaries (no -include canary.h / -DMAGMA_ENABLE_CANARIES / magma.o).
    export CC="${AFL_CC}" CXX="${AFL_CXX}"
    export CFLAGS="-g -O0 -Wno-implicit-function-declaration"
    export CXXFLAGS="${CFLAGS}"
    export LIBS="${AFL_DRIVER} -lstdc++"
    export LDFLAGS="-g"
    export OUT TARGET AFL_QUIET=1

    echo "build_afl.sh: instrument + build target (afl-clang-fast)"
    "${TARGET}/build.sh"
    [ -x "${BIN}" ] || die "build reported success but ${BIN} is missing"
fi

file "${BIN}" | grep -q ELF || die "smoke failed: ${BIN} is not an ELF executable"
echo "build_afl.sh: OK — ${BIN}"
