// Package watchdog is the observability layer of the
// Execution Server. It accumulates per-run outcome counters
// (Runs, OKs, Crashes, Hangs, IPC_ERRORs) and emits
// structured logs: debug for OK runs, warn for CRASH/HANG/
// IPC_ERROR, info summary at shutdown.
//
// This is the Phase 1 baseline per ADR 0013. Per-run timeout
// enforcement lives in worker.Pool (via exec.CommandContext);
// watchdog observes the result, it does not enforce policy.
// Phase 1.5 extends this package with restart-on-crash for
// long-lived persistent-mode workers and OOM detection; the
// current API (Stats, Record, LogSummary) is a stable base
// that those additions will layer on top of.
//
// See docs/DECISIONS/0013-watchdog-as-observability-subsystem.md
// for the full rationale and migration plan.
package watchdog
