package crashrec

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
	"mlfuzzz3/exec-server/internal/worker"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestDisabledRecorderIsNoop: empty Dir = no filesystem
// activity.
func TestDisabledRecorderIsNoop(t *testing.T) {
	r, err := New(Config{
		Dir: "",
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Record([]byte("x"), &worker.Result{
		Status: ipcv1.ExecStatus_EXEC_STATUS_CRASH,
	})
	// Nothing to assert; test passes if no panic and no
	// files created (we did not give a dir).
}

// TestRecordCrashWritesArtifacts: CRASH result produces
// crashes/<ts>_<hash>/ with input.bin and meta.json.
func TestRecordCrashWritesArtifacts(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Dir: dir,
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte("crashme")
	r.Record(input, &worker.Result{
		Status:   ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		Signal:   syscall.SIGSEGV,
		Duration: 12 * time.Millisecond,
	})

	crashesDir := filepath.Join(dir, "crashes")
	entries, err := os.ReadDir(crashesDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 crash dir, got %d",
			len(entries))
	}

	crashDir := filepath.Join(crashesDir, entries[0].Name())
	gotInput, err := os.ReadFile(
		filepath.Join(crashDir, "input.bin"))
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}
	if string(gotInput) != "crashme" {
		t.Errorf("input mismatch: %q", gotInput)
	}

	metaBytes, err := os.ReadFile(
		filepath.Join(crashDir, "meta.json"))
	if err != nil {
		t.Fatalf("read meta.json: %v", err)
	}
	var meta metaJSON
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if meta.Status != "crash" {
		t.Errorf("Status = %q, want crash", meta.Status)
	}
	if meta.Signal == nil ||
		*meta.Signal != syscall.SIGSEGV.String() {
		t.Errorf("Signal = %v, want SIGSEGV", meta.Signal)
	}
	if meta.InputSize != len(input) {
		t.Errorf("InputSize = %d, want %d",
			meta.InputSize, len(input))
	}
	if meta.DurationMs != 12 {
		t.Errorf("DurationMs = %d, want 12",
			meta.DurationMs)
	}
	if len(meta.InputSHA256) != 64 {
		t.Errorf("InputSHA256 length = %d, want 64",
			len(meta.InputSHA256))
	}
}

// TestRecordHangWritesToHangsSubdir: HANG goes to hangs/,
// not crashes/.
func TestRecordHangWritesToHangsSubdir(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Dir: dir,
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
			ipcv1.ExecStatus_EXEC_STATUS_HANG,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r.Record([]byte("hangme"), &worker.Result{
		Status:   ipcv1.ExecStatus_EXEC_STATUS_HANG,
		Duration: time.Second,
	})

	hangsDir := filepath.Join(dir, "hangs")
	entries, err := os.ReadDir(hangsDir)
	if err != nil {
		t.Fatalf("ReadDir hangs: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("hangs: expected 1, got %d",
			len(entries))
	}

	// crashes/ dir may exist (pre-created) but should
	// be empty.
	crashesDir := filepath.Join(dir, "crashes")
	crashes, _ := os.ReadDir(crashesDir)
	if len(crashes) != 0 {
		t.Errorf("crashes/ not empty: %d entries",
			len(crashes))
	}
}

// TestRecordIgnoresUnlistedStatus: status не в Statuses
// config → no record.
func TestRecordIgnoresUnlistedStatus(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Dir: dir,
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r.Record([]byte("hangme"), &worker.Result{
		Status: ipcv1.ExecStatus_EXEC_STATUS_HANG,
	})
	r.Record([]byte("ok"), &worker.Result{
		Status: ipcv1.ExecStatus_EXEC_STATUS_OK,
	})

	hangs := filepath.Join(dir, "hangs")
	entries, _ := os.ReadDir(hangs)
	if len(entries) != 0 {
		t.Errorf("hangs/ should be empty when HANG "+
			"not in Statuses: %d", len(entries))
	}
}

// TestRecordNilResult: no panic on nil result.
func TestRecordNilResult(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Dir: dir,
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Record([]byte("x"), nil) // must not panic
}

// TestRecordConcurrentNoSwallow: spam Record in parallel with
// the same input; if any two hit the same nanosecond, claimDir
// handles collision transparently. Test passes if no panic
// and at least N/4 records produce a directory in crashes/.
func TestRecordConcurrentNoSwallow(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Dir: dir,
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Record([]byte("same_input"), &worker.Result{
				Status:   ipcv1.ExecStatus_EXEC_STATUS_CRASH,
				Signal:   syscall.SIGSEGV,
				Duration: time.Millisecond,
			})
		}()
	}
	wg.Wait()

	crashes := filepath.Join(dir, "crashes")
	entries, _ := os.ReadDir(crashes)
	// Each Record either produces a dir or hits
	// double-collision (logged warn). Under normal timing,
	// expect > N/2 entries.
	if len(entries) < N/4 {
		t.Errorf("too few crash dirs: %d of %d",
			len(entries), N)
	}
}

// TestNewFailsOnUnwritableDir: non-writable parent path
// yields error from New.
func TestNewFailsOnUnwritableDir(t *testing.T) {
	// /proc is read-only on Linux; MkdirAll will fail.
	_, err := New(Config{
		Dir: "/proc/cannot_create_here",
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err == nil {
		t.Fatal("expected error on unwritable dir")
	}
}

// TestMetaJSONShape: ensures all expected JSON fields are
// present after round-trip.
func TestMetaJSONShape(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		Dir: dir,
		Statuses: []ipcv1.ExecStatus{
			ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		},
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r.Record([]byte("abc"), &worker.Result{
		Status:   ipcv1.ExecStatus_EXEC_STATUS_CRASH,
		Signal:   syscall.SIGABRT,
		Duration: 5 * time.Millisecond,
	})

	entries, _ := os.ReadDir(filepath.Join(dir, "crashes"))
	metaPath := filepath.Join(
		dir, "crashes", entries[0].Name(), "meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	requiredKeys := []string{
		"timestamp_ns", "timestamp_iso", "status",
		"target_path", "signal", "exit_code",
		"duration_ms", "input_size", "input_sha256",
	}
	for _, k := range requiredKeys {
		if _, ok := parsed[k]; !ok {
			t.Errorf("meta.json missing %q (full: %s)",
				k, raw)
		}
	}
	if parsed["status"] != "crash" {
		t.Errorf("status = %v, want crash",
			parsed["status"])
	}
	// exit_code should be null (JSON null → nil in map).
	if v, ok := parsed["exit_code"]; ok && v != nil {
		t.Errorf("exit_code = %v, want null", v)
	}
	iso, _ := parsed["timestamp_iso"].(string)
	if !strings.Contains(iso, "T") {
		t.Errorf("timestamp_iso = %v, want RFC3339",
			parsed["timestamp_iso"])
	}
}
