// Package ipc will host the Go side of the IPC server.
//
// It owns the Unix socket, length-prefixed protobuf framing, and the
// command dispatcher that binds Init/RunBatch/Shutdown to the rest of
// the Execution Server. See docs/ARCHITECTURE.md §4.10 and docs/IPC.md
// for the full design. This file is a placeholder for Phase 0; the real
// implementation lands in Phase 1.
package ipc
