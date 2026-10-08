#!/usr/bin/env bash
# Idempotent formatter for the MLFuzzZ3 tree.
# Without arguments, formats in place. With --check, only verifies formatting
# (non-zero exit if any file is not already formatted) and changes nothing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

check_mode=false
if [[ "${1:-}" == "--check" ]]; then
    check_mode=true
fi

mapfile -t cpp_files < <(
    find src include tests -type f \
        \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.h' -o -name '*.hpp' \) \
        2>/dev/null | sort
)

cpp_bad=()
if (( ${#cpp_files[@]} > 0 )); then
    for f in "${cpp_files[@]}"; do
        if ! clang-format --dry-run --Werror "${f}" >/dev/null 2>&1; then
            cpp_bad+=("${f}")
        fi
    done
fi

go_bad=()
if [[ -d exec-server ]]; then
    while IFS= read -r f; do
        [[ -n "${f}" ]] && go_bad+=("${f}")
    done < <(gofmt -l exec-server)
fi

if ${check_mode}; then
    if (( ${#cpp_bad[@]} > 0 || ${#go_bad[@]} > 0 )); then
        echo "format --check: files not formatted" >&2
        for f in "${cpp_bad[@]}"; do echo "  cpp: ${f}" >&2; done
        for f in "${go_bad[@]}"; do echo "  go:  ${f}" >&2; done
        exit 1
    fi
    echo "format --check ok (${#cpp_files[@]} C++ file(s) scanned)"
    exit 0
fi

if (( ${#cpp_bad[@]} > 0 )); then
    clang-format -i "${cpp_bad[@]}"
fi
if (( ${#go_bad[@]} > 0 )); then
    gofmt -w "${go_bad[@]}"
fi

echo "format: ${#cpp_bad[@]} C++ file(s) reformatted, ${#go_bad[@]} Go file(s) reformatted"
