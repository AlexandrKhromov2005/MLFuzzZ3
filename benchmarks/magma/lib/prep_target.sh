#!/usr/bin/env bash
#
# Shared per-arm target prep for the Magma comparative arms (ADR 0046 Step 2).
# Sourced by the build_tiff_*.sh drivers. Factors out the cp-a/fetch/apply_patches
# each libpng arm did inline, and adds an OPTIONAL recipe patch applied to the
# per-arm copy. The patch lives in the tracked patches/ dir; it is applied to the
# gitignored per-arm copy only — the canonical vendor source is never modified.
# Single-sourced so every arm (and the cov measurer) shares one codec set.
#
# Usage (sourced):
#   prep_target <TARGET_SRC> <TARGET_COPY> <MAGMA> [<PATCH>]
#     TARGET_SRC  : canonical vendor target (read-only here), e.g. .../targets/libtiff
#     TARGET_COPY : gitignored per-arm copy to build in, e.g. vendor/afl/libtiff
#     MAGMA       : .../magma-src/magma  (for apply_patches.sh)
#     PATCH       : optional recipe patch applied to TARGET_COPY (loud-fail on drift)

prep_target() {
    local src="$1" dst="$2" magma="$3" patch="${4:-}"
    [ -d "${src}" ]   || { echo "prep_target: TARGET_SRC missing: ${src}" >&2; return 1; }
    [ -x "${src}/fetch.sh" ] || { echo "prep_target: ${src}/fetch.sh missing" >&2; return 1; }

    # Fresh per-arm copy (carries build.sh/fetch.sh/configrc/patches; no repo).
    rm -rf "${dst}"; mkdir -p "$(dirname "${dst}")"
    cp -a "${src}" "${dst}"; rm -rf "${dst}/repo"

    # Recipe narrowing patch — applied to the COPY only (vendor source untouched).
    # Loud-fail if it does not apply cleanly: that means the pinned Magma/target
    # build.sh drifted from what the patch was generated against.
    if [ -n "${patch}" ]; then
        [ -f "${patch}" ] || { echo "prep_target: patch missing: ${patch}" >&2; return 1; }
        # --fuzz=0: strict context match — any upstream drift (not just the
        # changed lines) loud-fails instead of applying with an offset.
        patch -p1 --fuzz=0 -d "${dst}" < "${patch}" \
            || { echo "prep_target: FAILED to apply ${patch} on ${dst} — Magma/target pin drift? (loud-fail by design)" >&2; return 1; }
    fi

    # Fetch the target source into the copy's repo/, then apply Magma's
    # setup+bug canary patches to that repo (orthogonal to the recipe patch).
    TARGET="${dst}" "${dst}/fetch.sh"           || { echo "prep_target: fetch.sh failed in ${dst}" >&2; return 1; }
    TARGET="${dst}" "${magma}/apply_patches.sh" || { echo "prep_target: apply_patches.sh failed in ${dst}" >&2; return 1; }
}
