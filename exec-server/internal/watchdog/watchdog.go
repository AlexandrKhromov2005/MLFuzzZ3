package watchdog

import (
	"log/slog"
	"sync/atomic"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
	"mlfuzzz3/exec-server/internal/worker"
)

// Stats is a snapshot of cumulative counters. Values are
// non-negative and monotonically increasing over the life of
// the Watchdog. The snapshot is not strictly consistent
// across fields (individual atomic Loads may race with
// concurrent Record calls); this is acceptable for
// diagnostic logging but not for authoritative accounting.
type Stats struct {
	Runs      int64
	OKs       int64
	Crashes   int64
	Hangs     int64
	IPCErrors int64
}

// Watchdog tracks cumulative per-run outcomes and emits
// structured logs. Thread-safe: Record may be called
// concurrently from any number of goroutines.
type Watchdog struct {
	logger *slog.Logger

	runs      atomic.Int64
	oks       atomic.Int64
	crashes   atomic.Int64
	hangs     atomic.Int64
	ipcErrors atomic.Int64
}

// New constructs a Watchdog. logger is used for per-run
// debug lines, per-bad-outcome warn lines, and the shutdown
// summary (emitted by LogSummary). If logger is nil,
// slog.Default() is used.
func New(logger *slog.Logger) *Watchdog {
	if logger == nil {
		logger = slog.Default()
	}
	return &Watchdog{logger: logger}
}

// Record observes one run outcome. Increments counters
// atomically; emits slog.Debug for OK, slog.Warn for
// CRASH/HANG/IPC_ERROR. Unknown status is counted as
// IPC_ERROR (should not normally happen but we defend
// against future additions to ExecStatus).
func (w *Watchdog) Record(result *worker.Result) {
	if result == nil {
		return
	}
	w.runs.Add(1)

	attrs := []any{
		"status", result.Status.String(),
		"duration_ms", result.Duration.Milliseconds(),
	}

	switch result.Status {
	case ipcv1.ExecStatus_EXEC_STATUS_OK:
		w.oks.Add(1)
		w.logger.Debug("run ok", attrs...)

	case ipcv1.ExecStatus_EXEC_STATUS_CRASH:
		w.crashes.Add(1)
		attrs = append(attrs,
			"signal", result.Signal.String())
		w.logger.Warn("run crashed", attrs...)

	case ipcv1.ExecStatus_EXEC_STATUS_HANG:
		w.hangs.Add(1)
		w.logger.Warn("run hung", attrs...)

	case ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR:
		w.ipcErrors.Add(1)
		attrs = append(attrs,
			"error_message", result.ErrorMessage)
		w.logger.Warn("run ipc error", attrs...)

	default:
		// Unknown status — count as IPC_ERROR for
		// accounting, log as warn with verbose context.
		w.ipcErrors.Add(1)
		attrs = append(attrs,
			"error_message",
			"unknown status from worker.Pool")
		w.logger.Warn("run unknown status", attrs...)
	}
}

// Stats returns a snapshot of the current counters. Not
// strictly consistent across fields under concurrent
// Record activity; suitable for diagnostic display.
func (w *Watchdog) Stats() Stats {
	return Stats{
		Runs:      w.runs.Load(),
		OKs:       w.oks.Load(),
		Crashes:   w.crashes.Load(),
		Hangs:     w.hangs.Load(),
		IPCErrors: w.ipcErrors.Load(),
	}
}

// LogSummary emits a slog.Info line summarizing current
// Stats. Intended to be called once at exec-server
// shutdown. Safe to call multiple times (each emits a
// fresh line).
func (w *Watchdog) LogSummary() {
	s := w.Stats()
	w.logger.Info("session summary",
		"runs", s.Runs,
		"oks", s.OKs,
		"crashes", s.Crashes,
		"hangs", s.Hangs,
		"ipc_errors", s.IPCErrors,
	)
}
