#!/usr/bin/env bash
#
# Fedora-44 toolchain name reconciliation for the CMake/bootstrap probes
# (ADR 0045 deviation; layer-2 task-010).
#
# Fedora's `clang20` / `llvm20` packages install versioned binaries as
# /usr/bin/clang-20, /usr/bin/clang++-20, /usr/bin/clang-format-20,
# /usr/bin/clang-tidy-20, /usr/bin/llvm-config-20, ... which already
# satisfy the LLVM-20 pin (ADR 0024 / 0033 — the instrumentation passes
# probe `llvm-config-20`). What Fedora does NOT ship are the
# *unversioned* names that the project's tooling probes:
#   - `clang` / `clang++`     — find_program(NAMES clang) in the CMake
#                               test fixtures (cov_stdin_build et al.)
#                               and, transitively, the exec-server
#                               integration binary (exec_server_bin);
#   - `clang-format` / `clang-tidy` — bootstrap.sh's hard-fail tool check.
# Without these on PATH the coverage/branch fixtures silently drop out
# (hiding the Magma pre-flight's exec-server-bin) and `ci.sh` fails at
# stage 1 (bootstrap-check).
#
# This script reconciles only the *naming*: it symlinks the four
# unversioned names into the user-writable, on-PATH ~/.local/bin,
# pointing at the already-pinned *-20 binaries. No new compiler is
# installed; the symlinks resolve to the same 20.1.x toolchain the pin
# already requires, so ADR 0024 / 0033 stay intact. It deliberately
# does NOT install any distro package (Fedora's unversioned `clang`
# package tracks a newer major and would break the pin) and does NOT
# touch the pin itself.
#
# It also reconciles one compiler-rt filename difference for the Magma
# libFuzzer arm: Fedora ships the libFuzzer engine as
# libclang_rt.fuzzer.a (per-triple dir, no arch suffix), whereas the
# immutable ADR-0045 build_libfuzzer.sh probes the Debian/upstream
# spelling via `clang-20 --print-file-name=libclang_rt.fuzzer-x86_64.a`.
# We place a same-named symlink (an alias to the very same Fedora .a) in
# a user-owned dir and expose it through COMPILER_PATH — no sudo, no edit
# to the immutable script, no pin change. See the COMPILER_PATH note below.
#
# Go dev tools (golangci-lint, protoc-gen-go) are NOT this script's
# concern: they are installed, version-pinned, by `scripts/bootstrap.sh`
# into $(go env GOPATH)/bin (~/go/bin). This script only ensures the
# PATH wiring those tools need.
#
# PATH requirement (for the build/CI shell, not just interactive):
#   export PATH="$HOME/.local/bin:$(go env GOPATH)/bin:$PATH"
# ~/.local/bin holds the clang-name symlinks created here; ~/go/bin holds
# the bootstrap-installed go tools. Both must be on PATH for `ci.sh`.
#
# COMPILER_PATH requirement (for the Magma libFuzzer build shell):
#   export COMPILER_PATH="$HOME/.local/lib/mlfuzzz3-compiler-rt"
# clang honours COMPILER_PATH when resolving --print-file-name, so this
# makes build_libfuzzer.sh's hard-coded `libclang_rt.fuzzer-x86_64.a`
# probe resolve to the Fedora `libclang_rt.fuzzer.a` archive (same file,
# aliased). pin/immutability intact; full multi-distro compiler-rt
# discovery is deferred to layer-2 task-010.
#
# A complete multi-distro clang / llvm-config / tooling discovery scheme
# is left to a dedicated layer-2 ADR (task-010); this is the minimal
# host-state reconciliation needed to build and pre-flight on Fedora 44.
#
# Idempotent: re-running is a no-op once 20.x tools are already on PATH.
#
# Usage:  scripts/setup-fedora-toolchain.sh
#
set -euo pipefail

BIN_DIR="${HOME}/.local/bin"

log() { echo "setup-fedora-toolchain.sh: $*"; }
die() { echo "setup-fedora-toolchain.sh: $*" >&2; exit 1; }

# major_ver <binary>: print the LLVM major version parsed from the tool's
# --version banner. Handles all the clang-family spellings:
#   "clang version 20.1.8"         (clang, clang++)
#   "clang-format version 20.1.8"  (clang-format)
#   "  LLVM version 20.1.8"        (clang-tidy)
major_ver() {
    "$1" --version 2>/dev/null \
        | grep -oE 'version [0-9]+' | head -1 \
        | grep -oE '[0-9]+'
}

# link <name> <target>: create ~/.local/bin/<name> -> <target> unless an
# acceptable (LLVM 20.x) <name> is already resolvable on PATH. Verifies
# the target is itself LLVM 20 before linking. Never clobbers a
# pre-existing on-PATH tool; only fills the gap.
link() {
    name="$1"; target="$2"
    [ -x "${target}" ] || die "pin target missing: ${target} (install the clang20/llvm20 package)"
    tver="$(major_ver "${target}")"
    [ "${tver}" = "20" ] || die "pin target ${target} is LLVM ${tver:-?}, expected 20 (ADR 0024/0033)"

    if existing="$(command -v "${name}" 2>/dev/null)"; then
        ever="$(major_ver "${existing}")"
        if [ "${ever}" = "20" ]; then
            log "${name} already on PATH at ${existing} (LLVM 20) — leaving as-is"
            return 0
        fi
        die "${name} on PATH at ${existing} is LLVM ${ever:-?}, not 20 — refusing to shadow it (resolve the pin first)"
    fi
    mkdir -p "${BIN_DIR}"
    ln -sf "${target}" "${BIN_DIR}/${name}"
    log "linked ${BIN_DIR}/${name} -> ${target}"
}

link clang        /usr/bin/clang-20
link clang++      /usr/bin/clang++-20
link clang-format /usr/bin/clang-format-20
link clang-tidy   /usr/bin/clang-tidy-20

# compiler-rt libFuzzer engine alias (Fedora name -> Debian name the
# immutable build_libfuzzer.sh probes). We resolve the real Fedora
# archive via clang itself, verify it is an absolute existing path (not
# the bare fallback), then alias it under a user-owned dir exposed via
# COMPILER_PATH. Same archive, just a second name; pin/immutability stay
# intact.
RT_DIR="${HOME}/.local/lib/mlfuzzz3-compiler-rt"
fuzzer_a="$(clang-20 --print-file-name=libclang_rt.fuzzer.a)"
case "${fuzzer_a}" in
    /*) [ -f "${fuzzer_a}" ] || die "Fedora libFuzzer engine not found at ${fuzzer_a}" ;;
    *)  die "clang-20 did not resolve libclang_rt.fuzzer.a (got bare '${fuzzer_a}'; install compiler-rt20)" ;;
esac
mkdir -p "${RT_DIR}"
ln -sf "${fuzzer_a}" "${RT_DIR}/libclang_rt.fuzzer-x86_64.a"
log "aliased ${RT_DIR}/libclang_rt.fuzzer-x86_64.a -> ${fuzzer_a}"
case "${COMPILER_PATH:-}" in
    *"${RT_DIR}"*) ;;
    *) log "NOTE: export COMPILER_PATH=\"${RT_DIR}\" before running build_libfuzzer.sh" ;;
esac

# PATH sanity: warn (do not fail) if the two required dirs are missing.
gobin="$(go env GOPATH 2>/dev/null)/bin"
for d in "${BIN_DIR}" "${gobin}"; do
    case ":${PATH}:" in
        *":${d}:"*) ;;
        *) log "WARNING: ${d} is not on PATH; add it (clang-name symlinks / bootstrap go tools live there)" ;;
    esac
done

log "OK — unversioned clang/clang++/clang-format/clang-tidy resolve to *-20 (pin intact)"
