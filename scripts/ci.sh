#!/usr/bin/env bash
# Full local CI run. Intended for pre-push and for mirroring what the
# hosted CI does. Fails fast at the first red stage.
#
# Flags:
#   --no-clean   Skip the `rm -rf build` at stage 2 and reuse the existing
#                build tree. Primary use case is the hosted CI with a warm
#                FetchContent cache; locally it's also convenient for
#                quick pre-push verification after an already-built tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# BUILD_DIR env overrides the C++ build tree location. Default "build"
# preserves historical behavior; Docker CI passes an absolute path into
# a named volume so the source tree can stay read-only.
BUILD_DIR="${BUILD_DIR:-build}"

SKIP_CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --no-clean)
            SKIP_CLEAN=1
            ;;
        *)
            echo "ci.sh: unknown flag: $arg" >&2
            exit 2
            ;;
    esac
done

stage() {
    echo
    echo "=== Stage $1/6: $2 ==="
}

stage 1 "bootstrap-check"
"${SCRIPT_DIR}/bootstrap.sh"

stage 2 "C++ build (Debug)"
if [[ "${SKIP_CLEAN}" -eq 0 ]]; then
    rm -rf "${BUILD_DIR}"
fi
cmake -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
# Параллелизм сборки ограничен. Голое `-j` отдаёт Ninja все ядра и
# игнорирует CMAKE_BUILD_PARALLEL_LEVEL; на 24-ядерной машине разработки
# чистая пересборка Z3 в Debug этим исчерпывала 30 ГБ и клала хост
# (ADR 0032 говорит про воспроизводимость гейта, а не про потолок памяти).
# Потолок: четверть ядер, но не меньше двух; MLFUZZZ3_CI_JOBS переопределяет.
CI_JOBS="${MLFUZZZ3_CI_JOBS:-$(( $(nproc) / 4 ))}"
if (( CI_JOBS < 2 )); then
    CI_JOBS=2
fi
echo "ci.sh: build parallelism -j ${CI_JOBS}"
cmake --build "${BUILD_DIR}" -j "${CI_JOBS}"

stage 3 "ctest"
ctest --test-dir "${BUILD_DIR}" --output-on-failure

stage 4 "Go build+vet+test"
(
    cd exec-server
    go build ./...
    go vet ./...
    go test ./...
)

stage 5 "format (check)"
"${SCRIPT_DIR}/format.sh" --check

stage 6 "lint"
"${SCRIPT_DIR}/lint.sh"

echo
echo "=== CI OK ==="
