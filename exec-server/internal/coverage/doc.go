// Package coverage owns the lifecycle of the edge-coverage
// shared-memory channel announced to the peer (fuzzer-core)
// via SCM_RIGHTS at handshake time.
//
// Stage 1 (Task 8b per ADR 0018) — single-channel,
// single-worker. main.go calls NewChannel at startup,
// defers Close at shutdown, passes the Channel into the
// worker pool's CoverageConfig and the per-Run handler
// wrapper (Reset before dispatch, Read after).
//
// Multi-worker support and protocol channel index — Task 8c.
package coverage
