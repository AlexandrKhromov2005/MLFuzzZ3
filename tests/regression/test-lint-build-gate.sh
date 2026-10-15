#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Lint must keep optional solver sources out of a Z3-disabled build.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_dir="$(mktemp -d)"
cleanup() {
    rm -f "${test_dir}/clang-tidy" "${test_dir}/go" "${test_dir}/golangci-lint" \
        "${test_dir}/compile_commands.json" "${test_dir}/CMakeCache.txt" "${test_dir}/sources"
    rmdir "${test_dir}"
}
trap cleanup EXIT
cat > "${test_dir}/clang-tidy" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${LINT_GATE_SOURCES}"
SH
cat > "${test_dir}/go" <<'SH'
#!/usr/bin/env bash
[[ "$*" == 'env GOPATH' ]] || exit 1
printf '%s\n' "${LINT_GATE_GOPATH}"
SH
cat > "${test_dir}/golangci-lint" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "${test_dir}/clang-tidy" "${test_dir}/go" "${test_dir}/golangci-lint"
printf '[]\n' > "${test_dir}/compile_commands.json"
export PATH="${test_dir}:${PATH}"
export BUILD_DIR="${test_dir}"
export LINT_GATE_SOURCES="${test_dir}/sources"
export LINT_GATE_GOPATH="${test_dir}/unused-gopath"
for setting in OFF ON; do
    extra=""
    if [[ "${setting}" == ON ]]; then
        extra=",{\"directory\":\"${root_dir}\",\"file\":\"src/concolic/concolic.cpp\"},{\"directory\":\"${root_dir}\",\"file\":\"src/solver/solver_facade.cpp\"}"
    fi
    printf '[{"directory":"%s","file":"src/core/campaign.cpp"},{"directory":"%s","file":"src/composition/components.cpp"},{"directory":"%s","file":"src/concolic/binding_provider.cpp"}%s]\n' "${root_dir}" "${root_dir}" "${root_dir}" "${extra}" > "${test_dir}/compile_commands.json"
    bash "${root_dir}/scripts/lint.sh"
    grep -q '^src/core/campaign.cpp$' "${LINT_GATE_SOURCES}"
    grep -q '^src/concolic/binding_provider.cpp$' "${LINT_GATE_SOURCES}"
    grep -q '^src/composition/components.cpp$' "${LINT_GATE_SOURCES}"
    if [[ "${setting}" == OFF ]]; then
        if grep -Eq '^src/(concolic/(concolic|throttle)\.cpp|solver/)'  "${LINT_GATE_SOURCES}"; then
            echo 'disabled solver sources reached lint' >&2
            exit 1
        fi
    else
        grep -q '^src/concolic/concolic.cpp$' "${LINT_GATE_SOURCES}"
        grep -q '^src/solver/solver_facade.cpp$' "${LINT_GATE_SOURCES}"
    fi
done
