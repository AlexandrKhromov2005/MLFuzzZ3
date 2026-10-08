package watchdog

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
	"mlfuzzz3/exec-server/internal/worker"
)

// silentLogger returns a slog.Logger that discards output.
// Use in tests that don't assert log content, to keep
// test output clean.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRecordAllOK: 5 OK runs produce Runs=5, OKs=5,
// everything else zero.
func TestRecordAllOK(t *testing.T) {
	w := New(silentLogger())
	for i := 0; i < 5; i++ {
		w.Record(&worker.Result{
			Status:   ipcv1.ExecStatus_EXEC_STATUS_OK,
			Duration: 10 * time.Millisecond,
		})
	}
	got := w.Stats()
	want := Stats{Runs: 5, OKs: 5}
	if got != want {
		t.Errorf("Stats = %+v, want %+v", got, want)
	}
}

// TestRecordMixed: each status is counted in the correct
// bucket.
func TestRecordMixed(t *testing.T) {
	w := New(silentLogger())
	inputs := []ipcv1.ExecStatus{
		ipcv1.ExecStatus_EXEC_STATUS_OK,
		ipcv1.ExecStatus_EXEC_STATUS_OK,
		ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		ipcv1.ExecStatus_EXEC_STATUS_HANG,
		ipcv1.ExecStatus_EXEC_STATUS_HANG,
		ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR,
	}
	for _, s := range inputs {
		w.Record(&worker.Result{
			Status:   s,
			Signal:   syscall.SIGSEGV,
			Duration: time.Millisecond,
		})
	}
	got := w.Stats()
	want := Stats{
		Runs:      6,
		OKs:       2,
		Crashes:   1,
		Hangs:     2,
		IPCErrors: 1,
	}
	if got != want {
		t.Errorf("Stats = %+v, want %+v", got, want)
	}
}

// TestRecordNilResult: Record(nil) is a no-op — no panic,
// no counter increment.
func TestRecordNilResult(t *testing.T) {
	w := New(silentLogger())
	w.Record(nil)
	got := w.Stats()
	if got != (Stats{}) {
		t.Errorf("Stats after nil = %+v, want zero", got)
	}
}

// TestRecordUnknownStatus: a status value outside the
// known enum is counted as IPC_ERROR (defensive coding
// against future proto additions).
func TestRecordUnknownStatus(t *testing.T) {
	w := New(silentLogger())
	// ExecStatus is an int32 enum; use a value that is
	// not in the known set.
	var bogus ipcv1.ExecStatus = 9999
	w.Record(&worker.Result{Status: bogus})
	got := w.Stats()
	want := Stats{Runs: 1, IPCErrors: 1}
	if got != want {
		t.Errorf("Stats = %+v, want %+v", got, want)
	}
}

// TestRecordThreadSafety: 100 goroutines, each calling
// Record 10 times, produce exactly 1000 total runs. This
// is the canonical atomic-correctness check.
func TestRecordThreadSafety(t *testing.T) {
	w := New(silentLogger())
	const G = 100
	const N = 10
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				w.Record(&worker.Result{
					Status: ipcv1.
						ExecStatus_EXEC_STATUS_OK,
				})
			}
		}()
	}
	wg.Wait()
	got := w.Stats()
	if got.Runs != G*N {
		t.Errorf("Runs = %d, want %d", got.Runs, G*N)
	}
	if got.OKs != G*N {
		t.Errorf("OKs = %d, want %d", got.OKs, G*N)
	}
}

// TestLogSummaryIncludesAllCounters: capture log output
// through a text handler and assert each counter field
// appears.
func TestLogSummaryIncludesAllCounters(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	w := New(logger)

	w.Record(&worker.Result{
		Status: ipcv1.ExecStatus_EXEC_STATUS_OK})
	w.Record(&worker.Result{
		Status: ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		Signal: syscall.SIGSEGV})

	w.LogSummary()

	out := buf.String()
	requiredFragments := []string{
		"session summary",
		"runs=2",
		"oks=1",
		"crashes=1",
		"hangs=0",
		"ipc_errors=0",
	}
	for _, f := range requiredFragments {
		if !strings.Contains(out, f) {
			t.Errorf("summary log missing %q\nfull: %s",
				f, out)
		}
	}
}

// TestNewNilLoggerUsesDefault: passing nil to New does not
// panic and uses slog.Default() transparently.
func TestNewNilLoggerUsesDefault(t *testing.T) {
	w := New(nil)
	// Should not panic on Record.
	w.Record(&worker.Result{
		Status: ipcv1.ExecStatus_EXEC_STATUS_OK})
	if w.Stats().Runs != 1 {
		t.Errorf("expected Runs=1, got %d",
			w.Stats().Runs)
	}
}
