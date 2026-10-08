// Package ipcv1 contains the generated IPC message types shared between
// the C++ Core and the Go Execution Server.
//
// The wire schema lives in //proto/ipc.proto at the repository root.
// The sibling ipc.pb.go is produced by scripts/gen-proto.sh and is
// committed so `go build ./...` works on a fresh checkout without
// requiring protoc or protoc-gen-go. See docs/DECISIONS/0002 for the
// full rationale.
//
// The package name deliberately differs from the directory name
// ("proto") to avoid collisions with google.golang.org/protobuf/proto
// at every call site. The directory keeps the conventional name so the
// layout matches docs/ARCHITECTURE.md §6.
package ipcv1
