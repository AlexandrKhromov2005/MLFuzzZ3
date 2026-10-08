#!/usr/bin/env bash
#
# Build an AFL++-instrumented coreutils `base64` for the comparative
# benchmark (ADR 0044, Step 3) — AFL's racing target.
#
# This is a RACING binary, not a measurement one: AFL fuzzes it on AFL's own
# forkserver instrumentation. Its output corpus is later replayed through the
# neutral measurement binary (build_cov.sh → base64-cov) for scoring, so AFL's
# self-reported coverage is never the comparison unit (ADR 0044 invariant).
#
# afl-clang-fast is a clang 20.1.2 wrapper (= our toolchain), so the same
# gnulib/clang-20 mitigations as build.sh / build_cov.sh apply unchanged:
# configure with PLAIN clang (autoconf feature tests must run uninstrumented),
# then build src/base64 with afl-clang-fast + IOFLAGS + -Wno-implicit-function-
# declaration, two-phase (BUILT_SOURCES then src/base64). Builds in its own
# vendor/afl-build/ tree; output vendor/base64-afl.
#
# The source pin matches build.sh (canonical GNU coreutils 8.24; provenance in
# build.sh's header).
#
# Usage:  benchmarks/lava-m/build_afl.sh [--force]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

COREUTILS_VERSION="8.24"
TARBALL="coreutils-${COREUTILS_VERSION}.tar.xz"
URL="https://ftp.gnu.org/gnu/coreutils/${TARBALL}"
SHA256="a2d75286a4b9ef3a13039c2da3868a61be4ee9f17d8ae380a35a97e506972170"

AFL_BUILD_PARENT="${VENDOR_DIR}/afl-build"
AFL_SRC_DIR="${AFL_BUILD_PARENT}/coreutils-${COREUTILS_VERSION}"
AFL_BIN="${VENDOR_DIR}/base64-afl"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "build_afl.sh: $*" >&2; exit 1; }

AFL_CC="$(command -v afl-clang-fast || true)"
[ -n "${AFL_CC}" ] || die "afl-clang-fast not found (AFL++ host install required)"
command -v clang >/dev/null || die "clang not found"

mkdir -p "${VENDOR_DIR}"
cd "${VENDOR_DIR}"

verify() { echo "${SHA256}  ${TARBALL}" | sha256sum -c --status; }

if [ -f "${TARBALL}" ] && verify; then
    echo "build_afl.sh: ${TARBALL} present and checksum OK"
else
    echo "build_afl.sh: downloading ${URL}"
    curl -fSL -o "${TARBALL}.tmp" "${URL}" || die "download failed: ${URL}"
    mv "${TARBALL}.tmp" "${TARBALL}"
    verify || die "SHA256 mismatch for ${TARBALL} — refusing to build an unverified source."
    echo "build_afl.sh: checksum verified"
fi

if [ -x "${AFL_BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build_afl.sh: ${AFL_BIN} already built (use --force to rebuild)"
else
    rm -rf "${AFL_BUILD_PARENT}"
    mkdir -p "${AFL_BUILD_PARENT}"
    tar xf "${TARBALL}" -C "${AFL_BUILD_PARENT}"

    cd "${AFL_SRC_DIR}"

    echo "build_afl.sh: configure"
    CC=clang CFLAGS="-O1 -g" ./configure --quiet \
        || die "configure failed (see config.log)"

    IOFLAGS="-D_IO_ftrylockfile= -D_IO_IN_BACKUP=0x100 -D_IO_NO_READS=0x4 -D_IO_NO_WRITES=0x8 -D_IO_CURRENTLY_PUTTING=0x800"
    # AFL forkserver instrumentation via afl-clang-fast (default mode). Same
    # gnulib mitigations; no pass plugin, no coverage runtime.
    CC_INSTR="${AFL_CC} -Wno-implicit-function-declaration ${IOFLAGS}"

    echo "build_afl.sh: phase 1 — BUILT_SOURCES"
    BS="$(make --no-print-directory --eval='__pbs: ; @echo $(BUILT_SOURCES)' __pbs 2>/dev/null)"
    # shellcheck disable=SC2086
    AFL_QUIET=1 make CC="${CC_INSTR}" ${BS} \
        || die "phase 1 (BUILT_SOURCES) failed"

    echo "build_afl.sh: phase 2 — src/base64"
    AFL_QUIET=1 make -j"$(nproc)" CC="${CC_INSTR}" src/base64 \
        || die "phase 2 (src/base64) failed"

    [ -x "${AFL_SRC_DIR}/src/base64" ] || die "build reported success but src/base64 is missing"
    cp "${AFL_SRC_DIR}/src/base64" "${AFL_BIN}"
fi

# --- Smoke: AFL instrumentation alive (afl-showmap reports tuples) --------
# afl-showmap runs the target once under the forkserver and prints the edge
# tuples hit. Nonzero tuples prove the binary is AFL-instrumented and the
# forkserver attaches — the ADR 0044 Step 3 confirm that the AFL build works
# beyond the known gnulib mitigations.
echo "build_afl.sh: smoke — afl-showmap"
SEED="${SCRIPT_DIR}/seeds/hello.b64"
[ -f "${SEED}" ] || die "missing seed corpus: ${SEED}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    afl-showmap -o "${TMP}/map.txt" -- "${AFL_BIN}" -d <"${SEED}" >"${TMP}/showmap.log" 2>&1 \
    || die "afl-showmap failed (see output):
$(cat "${TMP}/showmap.log")"
TUPLES="$(wc -l <"${TMP}/map.txt" | tr -d ' ')"
[ "${TUPLES}" -gt 0 ] || die "smoke failed: afl-showmap recorded ${TUPLES} tuples (instrumentation dead)"

echo "build_afl.sh: OK — ${AFL_BIN}"
echo "build_afl.sh:    afl-showmap recorded ${TUPLES} edge tuples on the seed"
