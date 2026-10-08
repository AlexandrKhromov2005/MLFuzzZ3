#!/usr/bin/env bash
# Regenerate Go protobuf bindings from proto/ipc.proto.
#
# The protoc binary comes from the FetchContent-built protobuf under
# build/_deps/protobuf-build/; this guarantees that the generator and
# the C++ libprotobuf are from the same pinned version (ADR 0001). The
# generated Go file is committed (ADR 0002), so this script is only
# run when the schema changes, by an explicit developer action.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# See scripts/bootstrap.sh for the rationale.
if command -v go >/dev/null 2>&1; then
    gopath_bin="$(go env GOPATH)/bin"
    if [[ -d "${gopath_bin}" ]]; then
        PATH="${gopath_bin}:${PATH}"
    fi
fi

BUILD_DIR="${ROOT_DIR}/build"
if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "--- configuring build/ ---"
    cmake -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null
fi

echo "--- building protoc ---"
cmake --build "${BUILD_DIR}" --target protoc -j >/dev/null

# Since protobuf v27 the binary is named `protoc-<version>` (e.g.
# protoc-34.1.0); the plain `protoc` symlink is not always emitted.
# Accept both, preferring the top-level entry in protobuf-build/.
PROTOC="$(find "${BUILD_DIR}/_deps/protobuf-build" -maxdepth 1 -type f -executable \
    \( -name 'protoc' -o -name 'protoc-*' \) -print -quit 2>/dev/null || true)"
if [[ -z "${PROTOC:-}" || ! -x "${PROTOC}" ]]; then
    echo "ERROR: protoc binary not found under build/_deps/protobuf-build/" >&2
    echo "  Try a clean build: rm -rf build && cmake -B build && cmake --build build --target protoc" >&2
    exit 1
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
    echo "ERROR: protoc-gen-go not in PATH." >&2
    echo "  Install: go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11" >&2
    echo "  Then ensure \"\$(go env GOPATH)/bin\" is on PATH." >&2
    exit 1
fi

OUT_DIR="exec-server/internal/proto"
mkdir -p "${OUT_DIR}"

echo "--- generating ${OUT_DIR}/ipc.pb.go ---"
"${PROTOC}" \
    --plugin=protoc-gen-go="$(command -v protoc-gen-go)" \
    -I proto \
    --go_out="${OUT_DIR}" \
    --go_opt=paths=source_relative \
    proto/ipc.proto

echo "--- gofmt ---"
gofmt -w "${OUT_DIR}/ipc.pb.go"

echo "proto regenerated ok"
