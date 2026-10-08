#!/usr/bin/env bash
#
# Fetch a pinned Magma checkout for the comparative-benchmark milestone
# (ADR 0045). Magma is the env-driven build recipe + bug-oracle source; we drive
# it on the host under clang-20.1.2 (captain is docker-only, ADR 0045 Развилка
# A1). Source handling follows ADR 0044's precedent: the upstream tree is
# fetched into a gitignored vendor/ and pinned; only our integration scripts are
# tracked. (Magma is a git repo, so the commit SHA is itself the cryptographic
# pin — no separate tarball SHA256 is needed, unlike 0044's GNU-tarball path.)
#
# Upstream:  https://github.com/HexHive/magma
# Pinned:    commit 75d1ae7b180443a778b8830c79176ca5f93642ac (tag v1.2)
# License:   per the upstream HexHive/magma repository. The v1.2 tree carries no
#            in-tree LICENSE file; we vendor nothing into git (fetch only).
#
# Usage:  benchmarks/magma/fetch_magma.sh [--force]
#   --force   re-clone even if vendor/magma-src already exists.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
MAGMA_SRC="${VENDOR_DIR}/magma-src"

URL="https://github.com/HexHive/magma.git"
COMMIT="75d1ae7b180443a778b8830c79176ca5f93642ac"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "fetch_magma.sh: $*" >&2; exit 1; }

if [ -d "${MAGMA_SRC}/.git" ] && [ "${FORCE}" -eq 0 ]; then
    have="$(git -C "${MAGMA_SRC}" rev-parse HEAD 2>/dev/null || echo none)"
    if [ "${have}" = "${COMMIT}" ]; then
        echo "fetch_magma.sh: ${MAGMA_SRC} already at ${COMMIT}"
        exit 0
    fi
    echo "fetch_magma.sh: ${MAGMA_SRC} at ${have}, re-pinning to ${COMMIT}"
fi

rm -rf "${MAGMA_SRC}"
mkdir -p "${VENDOR_DIR}"
echo "fetch_magma.sh: cloning ${URL}"
git clone "${URL}" "${MAGMA_SRC}" || die "clone failed: ${URL}"
git -C "${MAGMA_SRC}" checkout --quiet "${COMMIT}" \
    || die "checkout ${COMMIT} failed (pin not found upstream?)"

got="$(git -C "${MAGMA_SRC}" rev-parse HEAD)"
[ "${got}" = "${COMMIT}" ] || die "pin mismatch: HEAD=${got} expected=${COMMIT}"
echo "fetch_magma.sh: OK — ${MAGMA_SRC} pinned at ${COMMIT}"
