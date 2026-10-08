package worker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// fixtureBinary builds the given fixture (by directory name
// under testdata/fixtures/) into a temporary binary and
// returns its path. Binary is deleted automatically at end
// of test via t.Cleanup.
func fixtureBinary(t *testing.T, name string) string {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(
		filepath.Dir(thisFile),
		"testdata", "fixtures", name)

	outFile, err := os.CreateTemp("", "fixture-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	t.Cleanup(func() { _ = os.Remove(outPath) })

	cmd := exec.Command("go", "build", "-o", outPath, ".")
	cmd.Dir = fixtureDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", name, err, out)
	}
	return outPath
}

// TestPoolExecuteOK: ok_exit fixture returns Status=OK.
func TestPoolExecuteOK(t *testing.T) {
	bin := fixtureBinary(t, "ok_exit")
	pool, err := NewPool(Config{TargetPath: bin})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	result, err := pool.Execute(
		context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status !=
		ipcv1.ExecStatus_EXEC_STATUS_OK {
		t.Errorf("Status = %v, want OK", result.Status)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
}

// TestPoolExecuteCrash: crash_segv fixture returns
// Status=CRASH with Signal=SIGSEGV.
func TestPoolExecuteCrash(t *testing.T) {
	bin := fixtureBinary(t, "crash_segv")
	pool, err := NewPool(Config{TargetPath: bin})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	result, err := pool.Execute(
		context.Background(), []byte("crash me"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status !=
		ipcv1.ExecStatus_EXEC_STATUS_CRASH {
		t.Errorf("Status = %v, want CRASH", result.Status)
	}
	if result.Signal != syscall.SIGSEGV {
		t.Errorf("Signal = %v, want SIGSEGV", result.Signal)
	}
}

// TestPoolExecuteTargetArgs: the argv_crash fixture crashes
// only when invoked with the "crash" argument, so Config.
// TargetArgs delivery is observable through the run status.
// Without TargetArgs the same fixture exits OK; with it the
// run is a CRASH (ADR 0040).
func TestPoolExecuteTargetArgs(t *testing.T) {
	bin := fixtureBinary(t, "argv_crash")

	noArgs, err := NewPool(Config{TargetPath: bin})
	if err != nil {
		t.Fatalf("NewPool (no args): %v", err)
	}
	defer func() { _ = noArgs.Close() }()
	res, err := noArgs.Execute(context.Background(), []byte("x"))
	if err != nil {
		t.Fatalf("Execute (no args): %v", err)
	}
	if res.Status != ipcv1.ExecStatus_EXEC_STATUS_OK {
		t.Errorf("no TargetArgs: Status = %v, want OK", res.Status)
	}

	withArgs, err := NewPool(Config{
		TargetPath: bin,
		TargetArgs: []string{"crash"},
	})
	if err != nil {
		t.Fatalf("NewPool (with args): %v", err)
	}
	defer func() { _ = withArgs.Close() }()
	res, err = withArgs.Execute(context.Background(), []byte("x"))
	if err != nil {
		t.Fatalf("Execute (with args): %v", err)
	}
	if res.Status != ipcv1.ExecStatus_EXEC_STATUS_CRASH {
		t.Errorf("TargetArgs=[crash]: Status = %v, want CRASH", res.Status)
	}
	if res.Signal != syscall.SIGSEGV {
		t.Errorf("TargetArgs=[crash]: Signal = %v, want SIGSEGV", res.Signal)
	}
}

// TestPoolExecuteHang: hang fixture with tight RunTimeout
// should return Status=HANG.
func TestPoolExecuteHang(t *testing.T) {
	bin := fixtureBinary(t, "hang")
	pool, err := NewPool(Config{
		TargetPath: bin,
		RunTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	result, err := pool.Execute(
		context.Background(), []byte(""))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status !=
		ipcv1.ExecStatus_EXEC_STATUS_HANG {
		t.Errorf("Status = %v, want HANG", result.Status)
	}
}

// TestPoolConcurrency: N=4 workers, 10 parallel Execute
// calls all return OK. Checks pool serializes correctly.
func TestPoolConcurrency(t *testing.T) {
	bin := fixtureBinary(t, "ok_exit")
	pool, err := NewPool(Config{
		TargetPath: bin,
		Workers:    4,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			result, err := pool.Execute(
				context.Background(),
				[]byte("x"))
			if err != nil {
				errs <- err
				return
			}
			if result.Status !=
				ipcv1.ExecStatus_EXEC_STATUS_OK {
				errs <- &testErr{id: id, got: result.Status}
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent Execute: %v", e)
	}
}

// TestPoolClosedRejects: Execute after Close returns
// ErrPoolClosed.
func TestPoolClosedRejects(t *testing.T) {
	bin := fixtureBinary(t, "ok_exit")
	pool, err := NewPool(Config{TargetPath: bin})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = pool.Execute(
		context.Background(), []byte(""))
	if err == nil {
		t.Fatal("Execute after Close: expected error, got nil")
	}
}

// TestPoolEmptyTargetPath: NewPool with no TargetPath fails.
func TestPoolEmptyTargetPath(t *testing.T) {
	_, err := NewPool(Config{})
	if err == nil {
		t.Fatal("expected ErrEmptyTargetPath")
	}
}

// testErr is a helper type for reporting concurrent test
// failures by id.
type testErr struct {
	id  int
	got ipcv1.ExecStatus
}

func (e *testErr) Error() string {
	return "goroutine " +
		(func() string {
			if e.id < 10 {
				return string(rune('0' + e.id))
			}
			return "many"
		})() +
		": Status=" + e.got.String()
}
