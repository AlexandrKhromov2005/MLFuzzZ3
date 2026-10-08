#!/usr/bin/env bash
#
# Build an edge-instrumented coreutils `base64` for the external-target
# benchmark slice (ADR 0040 / ADR 0041, Step 2a).
#
# This builds the CLEAN GNU coreutils 8.24 `base64` — the same gnulib/autoconf
# base as the LAVA-M target — instrumented with the project's EdgeCoveragePass
# (edge coverage) AND BranchTracePass (the branch-value channel that feeds the
# concolic engine, ADR 0040/0041 Step 4), linked against libmlfuzzz3_cov. Step
# 2a first de-risked the hard part (autoconf + gnulib under clang 20 + our pass)
# edge-only against a source whose authenticity is *verifiable*; the branch pass
# is added here so concolic exercises the target's real comparisons. The LAVA
# injection delta (Step 2b) is layered later on a TOFU source.
#
# Source authenticity
# -------------------
# The tarball is the canonical GNU release. Its SHA256 below was obtained by
# GPG-verifying coreutils-8.24.tar.xz.sig against the GNU keyring (signed by
# Pádraig Brady, the coreutils release manager, key DF6FD971306037D9) and then
# hashing the verified bytes. This is verifiable authenticity, not
# trust-on-first-use. The script re-checks the download against this hash and
# refuses to build a mismatching source.
#
# clang 20 mitigations (ADR 0041 §Risk ladder)
# --------------------------------------------
# coreutils 8.24 (2015) predates modern glibc/clang. The build needs no source
# patches — only compiler-flag mitigations, all documented at CFLAGS below:
#   * -Wno-implicit-function-declaration  (clang 16+ makes this a hard error)
#   * -D_IO_ftrylockfile=                 (glibc 2.28+ dropped this libio
#                                          detection macro; the struct members
#                                          gnulib's glibc branch uses still
#                                          exist, so defining it re-selects the
#                                          correct branch)
#   * -D_IO_IN_BACKUP / _IO_NO_READS / _IO_NO_WRITES / _IO_CURRENTLY_PUTTING
#                                          (canonical libio _flags bit values,
#                                          dropped from public headers but still
#                                          honoured in struct _IO_FILE::_flags)
#
# Targeting base64 only
# ---------------------
# A full `make` builds ~100 utilities, runs the instrumented `make-prime-list`
# build tool, and trips unrelated modern-glibc breakage (e.g. `df`'s makedev,
# a link error independent of instrumentation). We need only base64, so we
# build it in two phases: first the generated BUILT_SOURCES headers, then
# `src/base64`. The two phases are required because on a fresh tree the
# dependency tracking does not yet know base64.o needs the generated headers,
# so they must exist before anything is compiled; and targeting base64 (rather
# than `make all`) sidesteps the df/makedev link error. base64 never pulls the
# broken modules out of libgnu.a, so no source patch is required.
#
# Note: BUILT_SOURCES includes src/primes.h. The release tarball ships it
# pre-generated, so its rule is normally a no-op and the instrumented
# make-prime-list build tool does not run here. Were a build to regenerate it
# (e.g. a source tree without the shipped header), running that instrumented
# helper without a coverage fd is safe since ADR 0042 (the runtime maps a
# fallback bitmap; before 0042 it SIGSEGV'd on its first edge).
#
# Usage:  benchmarks/lava-m/build.sh [--force]
#   --force   re-extract and rebuild even if src/base64 already exists.
#
# Env overrides:
#   BUILD_DIR   project build tree holding the pass + runtime (default: build/)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

# --- Pinned source (verifiable authenticity, see header) ------------------
COREUTILS_VERSION="8.24"
TARBALL="coreutils-${COREUTILS_VERSION}.tar.xz"
URL="https://ftp.gnu.org/gnu/coreutils/${TARBALL}"
SHA256="a2d75286a4b9ef3a13039c2da3868a61be4ee9f17d8ae380a35a97e506972170"

# --- Project instrumentation artefacts ------------------------------------
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"
PASS="${BUILD_DIR}/src/instrumentation/edge_coverage_pass/libEdgeCoveragePass.so"
BRANCH="${BUILD_DIR}/src/instrumentation/branch_trace_pass/libBranchTracePass.so"
COV="${BUILD_DIR}/src/runtime/coverage/libmlfuzzz3_cov.so"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "build.sh: $*" >&2; exit 1; }

[ -f "${PASS}" ]   || die "EdgeCoveragePass not found: ${PASS} (build the project first: cmake --build ${BUILD_DIR})"
[ -f "${BRANCH}" ] || die "BranchTracePass not found: ${BRANCH} (build the project first)"
[ -f "${COV}" ]    || die "libmlfuzzz3_cov not found: ${COV} (build the project first)"
COVDIR="$(cd "$(dirname "${COV}")" && pwd)"

mkdir -p "${VENDOR_DIR}"
cd "${VENDOR_DIR}"

# --- Fetch + verify (STOP on checksum mismatch) ---------------------------
verify() { echo "${SHA256}  ${TARBALL}" | sha256sum -c --status; }

if [ -f "${TARBALL}" ] && verify; then
    echo "build.sh: ${TARBALL} present and checksum OK"
else
    echo "build.sh: downloading ${URL}"
    curl -fSL -o "${TARBALL}.tmp" "${URL}" || die "download failed: ${URL}"
    mv "${TARBALL}.tmp" "${TARBALL}"
    verify || die "SHA256 mismatch for ${TARBALL} — refusing to build an unverified source.
       expected: ${SHA256}
       got:      $(sha256sum "${TARBALL}" | cut -d' ' -f1)"
    echo "build.sh: checksum verified"
fi

SRC_DIR="${VENDOR_DIR}/coreutils-${COREUTILS_VERSION}"
BASE64_BIN="${SRC_DIR}/src/base64"

if [ -x "${BASE64_BIN}" ] && [ "${FORCE}" -eq 0 ]; then
    echo "build.sh: ${BASE64_BIN} already built (use --force to rebuild)"
else
    rm -rf "${SRC_DIR}"
    tar xf "${TARBALL}"

    cd "${SRC_DIR}"

    # configure with PLAIN clang: autoconf feature-test programs must run
    # uninstrumented (an instrumented test program would dereference the
    # unmapped coverage map and crash, breaking detection).
    echo "build.sh: configure"
    CC=clang CFLAGS="-O1 -g" ./configure --quiet \
        || die "configure failed (see config.log)"

    IOFLAGS="-D_IO_ftrylockfile= -D_IO_IN_BACKUP=0x100 -D_IO_NO_READS=0x4 -D_IO_NO_WRITES=0x8 -D_IO_CURRENTLY_PUTTING=0x800"
    # Both passes (ADR 0040/0041 Step 4): the branch-value channel feeds the
    # concolic engine on the target's real comparisons. BranchTracePass is
    # loaded FIRST so its PipelineStartEP callback sees only the program's own
    # icmps, not the saturating compare the edge pass inserts. Both reference
    # symbols defined in libmlfuzzz3_cov (the edge map and
    # fuzzer_rt_log_branch_cmp), so no extra link input is needed.
    CC_INSTR="clang -fpass-plugin=${BRANCH} -fpass-plugin=${PASS} -Wno-implicit-function-declaration ${IOFLAGS}"
    # Coverage runtime goes in LIBS (linked AFTER objects) so the Makefile's
    # -Wl,--as-needed keeps it: by the time the linker sees it there is an
    # unresolved __mlfuzzz3_cov_map reference from the instrumented objects.
    LINK_LIBS="${COV} -Wl,-rpath,${COVDIR}"

    # Phase 1: generate BUILT_SOURCES (gnulib substitute headers, src/primes.h,
    # etc.). On a fresh tree the dependency tracking does not yet know base64.o
    # needs these generated headers, so they must be built first. primes.h is
    # shipped pre-generated so its rule is a no-op here; no special-casing is
    # needed (and were it regenerated, ADR 0042 makes the helper fd-safe).
    echo "build.sh: phase 1 — BUILT_SOURCES"
    BS="$(make --no-print-directory --eval='__pbs: ; @echo $(BUILT_SOURCES)' __pbs 2>/dev/null)"
    # shellcheck disable=SC2086
    make CC="${CC_INSTR}" LIBS="${LINK_LIBS}" ${BS} \
        || die "phase 1 (BUILT_SOURCES) failed"

    # Phase 2: build base64 itself. This builds libgnu.a (every gnulib object
    # compiles; modules base64 never links, e.g. mountlist, are archived but
    # not resolved) and links src/base64 against the coverage runtime.
    echo "build.sh: phase 2 — src/base64"
    make -j"$(nproc)" CC="${CC_INSTR}" LIBS="${LINK_LIBS}" src/base64 \
        || die "phase 2 (src/base64) failed"

    [ -x "${BASE64_BIN}" ] || die "build reported success but ${BASE64_BIN} is missing"
fi

# --- Smoke: instrumentation alive -----------------------------------------
# Run base64 -d on a valid seed with the coverage map fd wired to a scratch
# bitmap and assert the run recorded edges. base64 is DT_NEEDED-linked to the
# runtime, so its constructor maps fd 3 and the inline IR writes the map.
echo "build.sh: smoke — instrumentation alive"
SCRATCH="$(mktemp)"
trap 'rm -f "${SCRATCH}"' EXIT
truncate -s 65536 "${SCRATCH}"
SEED="${SCRIPT_DIR}/seeds/hello.b64"
[ -f "${SEED}" ] || die "missing seed corpus: ${SEED}"

# fd 3 = scratch bitmap; MLFUZZZ3_COV_FD tells the runtime to map it.
( exec 3<>"${SCRATCH}"; MLFUZZZ3_COV_FD=3 "${BASE64_BIN}" -d <"${SEED}" >/dev/null )
NONZERO="$(python3 -c "import sys; d=open('${SCRATCH}','rb').read(); print(sum(1 for b in d if b))")"
[ "${NONZERO}" -gt 0 ] || die "smoke failed: base64 recorded ${NONZERO} edges (instrumentation dead)"

echo "build.sh: OK — ${BASE64_BIN}"
echo "build.sh:    instrumentation smoke recorded ${NONZERO} non-zero edge cells"
