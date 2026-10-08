#!/usr/bin/env bash
# Verify that all tools required to build and lint MLFuzzZ3 are available.
# Exits non-zero with install hints if anything is missing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# Tools installed via `go install` land in $(go env GOPATH)/bin, which is
# not always on PATH in non-interactive shells. Extend PATH here so checks
# find those tools without requiring every user to edit their rc files.
if command -v go >/dev/null 2>&1; then
    gopath_bin="$(go env GOPATH)/bin"
    if [[ -d "${gopath_bin}" ]]; then
        PATH="${gopath_bin}:${PATH}"
    fi
fi

missing=()
hints=()

record_missing() {
    missing+=("$1")
    hints+=("$1: $2")
}

check_tool() {
    local name="$1"
    local cmd="$2"
    local hint="$3"
    if command -v "${cmd}" >/dev/null 2>&1; then
        printf 'ok    %-14s %s\n' "${name}" "$(command -v "${cmd}")"
    else
        printf 'miss  %-14s (command "%s" not in PATH)\n' "${name}" "${cmd}"
        record_missing "${name}" "${hint}"
    fi
}

check_min_version() {
    local name="$1"
    local got="$2"
    local min="$3"
    if printf '%s\n%s\n' "${min}" "${got}" | sort -V -C; then
        printf 'ok    %-14s %s (>= %s)\n' "${name} version" "${got}" "${min}"
    else
        printf 'miss  %-14s %s (need >= %s)\n' "${name} version" "${got}" "${min}"
        record_missing "${name} (version too old)" "upgrade ${name} to >= ${min}"
    fi
}

echo "=== MLFuzzZ3 bootstrap tool check ==="

check_tool "git"           "git"           "install via your distro (e.g. apt install git)"
check_tool "cmake"         "cmake"         "apt install cmake   (need >= 3.25)"
check_tool "ninja"         "ninja"         "apt install ninja-build"
check_tool "clang-format"  "clang-format"  "apt install clang-format"
check_tool "clang-tidy"    "clang-tidy"    "apt install clang-tidy"
check_tool "go"            "go"            "https://go.dev/dl/  (need >= 1.23)"
check_tool "golangci-lint" "golangci-lint" 'go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2  (then ensure "$(go env GOPATH)/bin" is in PATH)'
check_tool "protoc-gen-go" "protoc-gen-go" 'go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11  (then ensure "$(go env GOPATH)/bin" is in PATH)'

if command -v c++ >/dev/null 2>&1; then
    printf 'ok    %-14s %s\n' "c++" "$(c++ --version | head -1)"
elif command -v clang++ >/dev/null 2>&1; then
    printf 'ok    %-14s %s\n' "clang++" "$(clang++ --version | head -1)"
else
    printf 'miss  %-14s (neither c++ nor clang++ in PATH)\n' "C++ compiler"
    record_missing "C++ compiler" "apt install g++   or   apt install clang"
fi

if command -v cmake >/dev/null 2>&1; then
    check_min_version "cmake" "$(cmake --version | head -1 | awk '{print $3}')" "3.25"
fi
if command -v go >/dev/null 2>&1; then
    check_min_version "go" "$(go version | awk '{print $3}' | sed 's/^go//')" "1.23"
fi

if (( ${#missing[@]} > 0 )); then
    echo
    echo "Bootstrap failed. Missing: ${missing[*]}"
    echo
    echo "Install hints:"
    for h in "${hints[@]}"; do
        echo "  - ${h}"
    done
    exit 1
fi

echo
echo "Bootstrap OK."
