#!/usr/bin/env bash
# Static analysis for the MLFuzzZ3 tree.
# Runs clang-tidy over the C++ sources (via compile_commands.json) and
# golangci-lint over the Go module. Any diagnostic fails the script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# See scripts/ci.sh for the BUILD_DIR contract.
BUILD_DIR="${BUILD_DIR:-build}"

# See scripts/bootstrap.sh for the rationale.
if command -v go >/dev/null 2>&1; then
    gopath_bin="$(go env GOPATH)/bin"
    if [[ -d "${gopath_bin}" ]]; then
        PATH="${gopath_bin}:${PATH}"
    fi
fi

if [[ ! -f "${BUILD_DIR}/compile_commands.json" ]]; then
    echo "--- configuring ${BUILD_DIR}/ to generate compile_commands.json ---"
    cmake -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null
fi

echo "--- clang-tidy ---"
# Read the actual compile database: optional stages may be disabled independently.
lint_sources="$(cmake -DROOT_DIR="${ROOT_DIR}" -DBUILD_DIR="${BUILD_DIR}" -P "${SCRIPT_DIR}/lint-sources.cmake")"
cpp_sources=()
if [[ -n "${lint_sources}" ]]; then
    mapfile -t cpp_sources <<< "${lint_sources}"
fi
if (( ${#cpp_sources[@]} > 0 )); then
    # clang-tidy prints "N warnings generated." for every TU it parses; that
    # count comes from the underlying clang frontend and mostly reflects
    # system and third-party headers (which we filter via HeaderFilterRegex
    # in .clang-tidy). Project-level diagnostics would still make the tool
    # exit non-zero and surface normally; we just strip the count lines from
    # the log to keep it readable.
    clang_tidy_log="$(mktemp)"
    trap 'rm -f "${clang_tidy_log}"' EXIT
    if ! clang-tidy --quiet -p "${BUILD_DIR}" "${cpp_sources[@]}" >"${clang_tidy_log}" 2>&1; then
        grep -vE '^[0-9]+ warnings? generated\.$' "${clang_tidy_log}" >&2 || true
        echo "clang-tidy: failed" >&2
        exit 1
    fi
    grep -vE '^[0-9]+ warnings? generated\.$' "${clang_tidy_log}" || true
else
    echo "(no C++ sources under src/)"
fi

echo "--- golangci-lint ---"
(
    cd exec-server
    golangci-lint run ./...
)

echo "lint ok"
