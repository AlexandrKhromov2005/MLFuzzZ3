package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/ipc"
	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// testSession bundles a running exec-server subprocess, a
// connected IPC client, and the on-disk crashes dir. All
// resources are cleaned up via t.Cleanup.
type testSession struct {
	t           *testing.T
	binPath     string
	fixturePath string
	crashesDir  string
	cmd         *exec.Cmd
	sess        *ipc.ClientSession
	stderr      *bytes.Buffer
}

// testSessionConfig selects the target fixture and CLI
// parameters for the spawned exec-server.
type testSessionConfig struct {
	// Fixture is the name of a subdirectory in
	// internal/worker/testdata/fixtures/. One of
	// "ok_exit", "crash_segv", "hang".
	Fixture string
	Workers int
	// RunTimeoutMs passed as -run-timeout-ms. Default 5000
	// if zero.
	RunTimeoutMs int
	// RecordStatus passed as -record-status (comma-
	// separated). Empty = server default "crash,hang".
	RecordStatus string
	// EnableCrashesDir creates a temp crashes dir and
	// passes -crashes-dir. If false, recording disabled.
	EnableCrashesDir bool
}

// newTestSession spawns exec-server as a subprocess with the
// given fixture and config. Returns a session ready for
// Run/Shutdown. Test fails fatally on setup errors.
func newTestSession(
	t *testing.T,
	cfg testSessionConfig,
) *testSession {
	t.Helper()

	if testing.Short() {
		t.Skip("integration test, skipping in -short")
	}

	ts := &testSession{t: t}

	ts.fixturePath = buildFixture(t, cfg.Fixture)
	ts.binPath = buildExecServer(t)

	if cfg.EnableCrashesDir {
		ts.crashesDir = t.TempDir()
	}

	fds, err := syscall.Socketpair(
		syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "ipc-parent")
	childFile := os.NewFile(uintptr(fds[1]), "ipc-child")

	netConn, err := net.FileConn(parentFile)
	if err != nil {
		_ = childFile.Close()
		_ = parentFile.Close()
		t.Fatalf("net.FileConn: %v", err)
	}
	_ = parentFile.Close()

	workers := cfg.Workers
	if workers == 0 {
		workers = 1
	}
	runTimeout := cfg.RunTimeoutMs
	if runTimeout == 0 {
		runTimeout = 5000
	}
	args := []string{
		"-target", ts.fixturePath,
		"-workers", fmt.Sprintf("%d", workers),
		"-run-timeout-ms", fmt.Sprintf("%d", runTimeout),
	}
	if ts.crashesDir != "" {
		args = append(args, "-crashes-dir", ts.crashesDir)
	}
	if cfg.RecordStatus != "" {
		args = append(args, "-record-status", cfg.RecordStatus)
	}

	ts.cmd = exec.Command(ts.binPath, args...)
	ts.cmd.ExtraFiles = []*os.File{childFile}
	ts.stderr = &bytes.Buffer{}
	ts.cmd.Stderr = ts.stderr

	if err := ts.cmd.Start(); err != nil {
		_ = childFile.Close()
		_ = netConn.Close()
		t.Fatalf("cmd.Start: %v", err)
	}
	_ = childFile.Close()

	ipcConn := ipc.NewConn(netConn)
	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	ts.sess, err = ipc.Dial(ctx, ipcConn, ipc.ClientConfig{
		RunTimeoutMs:     uint64(runTimeout),
		ExpectedChannels: 0,
	})
	if err != nil {
		_ = netConn.Close()
		_ = ts.cmd.Process.Kill()
		_, _ = ts.cmd.Process.Wait()
		t.Fatalf("ipc.Dial: %v\nstderr: %s",
			err, ts.stderr.String())
	}

	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(
			context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = ts.sess.Shutdown(shutdownCtx)

		done := make(chan error, 1)
		go func() { done <- ts.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = ts.cmd.Process.Kill()
			<-done
		}
	})

	return ts
}

// buildFixture builds a fixture binary from
// internal/worker/testdata/fixtures/<name>/main.go.
func buildFixture(t *testing.T, name string) string {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	// cmd/exec-server/integration_test.go is two levels
	// below the exec-server module root.
	moduleRoot := filepath.Join(
		filepath.Dir(thisFile), "..", "..")
	srcDir := filepath.Join(moduleRoot,
		"internal", "worker", "testdata", "fixtures", name)

	binPath := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture %s: %v\n%s", name, err, out)
	}
	return binPath
}

// TestIntegrationCrashFlow: crash_segv target, one run,
// verify status=CRASH + crashes dir populated + meta.json
// correct.
func TestIntegrationCrashFlow(t *testing.T) {
	ts := newTestSession(t, testSessionConfig{
		Fixture:          "crash_segv",
		Workers:          1,
		RunTimeoutMs:     5000,
		EnableCrashesDir: true,
		RecordStatus:     "crash,hang",
	})

	ctx := context.Background()
	resp, err := ts.sess.Run(ctx, []byte("trigger"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resp.Status != ipcv1.ExecStatus_EXEC_STATUS_CRASH {
		t.Errorf("Status = %v, want CRASH", resp.Status)
	}

	crashesSubdir := filepath.Join(ts.crashesDir, "crashes")
	entries, err := os.ReadDir(crashesSubdir)
	if err != nil {
		t.Fatalf("ReadDir crashes: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("crashes dir: %d entries, want 1",
			len(entries))
	}

	metaPath := filepath.Join(crashesSubdir,
		entries[0].Name(), "meta.json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("ReadFile meta.json: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if meta["status"] != "crash" {
		t.Errorf("meta.status = %v, want crash",
			meta["status"])
	}
	sig, _ := meta["signal"].(string)
	if sig != "segmentation fault" && sig != "SIGSEGV" {
		t.Errorf("meta.signal = %q, want SIGSEGV variant", sig)
	}

	inputPath := filepath.Join(crashesSubdir,
		entries[0].Name(), "input.bin")
	inputBytes, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("ReadFile input.bin: %v", err)
	}
	if string(inputBytes) != "trigger" {
		t.Errorf("input.bin = %q, want trigger", inputBytes)
	}
}

// TestIntegrationHangFlow: hang target, short timeout,
// verify status=HANG + hangs dir populated.
func TestIntegrationHangFlow(t *testing.T) {
	ts := newTestSession(t, testSessionConfig{
		Fixture:          "hang",
		Workers:          1,
		RunTimeoutMs:     100,
		EnableCrashesDir: true,
		RecordStatus:     "crash,hang",
	})

	ctx := context.Background()
	resp, err := ts.sess.Run(ctx, []byte("hang-trigger"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resp.Status != ipcv1.ExecStatus_EXEC_STATUS_HANG {
		t.Errorf("Status = %v, want HANG", resp.Status)
	}

	hangsDir := filepath.Join(ts.crashesDir, "hangs")
	entries, err := os.ReadDir(hangsDir)
	if err != nil {
		t.Fatalf("ReadDir hangs: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("hangs dir: %d entries, want 1",
			len(entries))
	}
}

// TestIntegrationMultiRunStability: ok_exit target, 100
// runs, all OK, no deadlock. Smoke for leaks.
func TestIntegrationMultiRunStability(t *testing.T) {
	ts := newTestSession(t, testSessionConfig{
		Fixture:      "ok_exit",
		Workers:      4,
		RunTimeoutMs: 5000,
	})

	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	const N = 100
	for i := 0; i < N; i++ {
		resp, err := ts.sess.Run(ctx,
			[]byte(fmt.Sprintf("run_%d", i)))
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		if resp.Status != ipcv1.ExecStatus_EXEC_STATUS_OK {
			t.Errorf("Run %d: status = %v, want OK",
				i, resp.Status)
		}
	}
}

// TestIntegrationConcurrentRuns: workers=4, 50 rapid
// sequential runs through a single session. ClientSession
// is not safe for truly concurrent Run (single stream), so
// this verifies that the server-side pool and framing
// remain stable under burst. True multi-session concurrency
// is out of scope for the Phase 1 baseline.
func TestIntegrationConcurrentRuns(t *testing.T) {
	ts := newTestSession(t, testSessionConfig{
		Fixture: "ok_exit",
		Workers: 4,
	})

	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	const N = 50
	var mu sync.Mutex
	var okCount int
	for i := 0; i < N; i++ {
		resp, err := ts.sess.Run(ctx,
			[]byte(fmt.Sprintf("burst_%d", i)))
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		if resp.Status == ipcv1.ExecStatus_EXEC_STATUS_OK {
			mu.Lock()
			okCount++
			mu.Unlock()
		}
	}

	if okCount != N {
		t.Errorf("okCount = %d, want %d", okCount, N)
	}
}

// TestIntegrationCrashesDirectoryStructure: crash_segv, 3
// runs with distinct inputs, verify 3 distinct crash dirs
// under crashes/, each with input.bin + meta.json, each
// with a distinct input_sha256.
func TestIntegrationCrashesDirectoryStructure(t *testing.T) {
	ts := newTestSession(t, testSessionConfig{
		Fixture:          "crash_segv",
		Workers:          1,
		RunTimeoutMs:     5000,
		EnableCrashesDir: true,
		RecordStatus:     "crash,hang",
	})

	ctx := context.Background()
	const N = 3
	for i := 0; i < N; i++ {
		input := []byte(fmt.Sprintf("crash_%d", i))
		resp, err := ts.sess.Run(ctx, input)
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		if resp.Status !=
			ipcv1.ExecStatus_EXEC_STATUS_CRASH {
			t.Fatalf("Run %d: status = %v, want CRASH",
				i, resp.Status)
		}
	}

	crashesSubdir := filepath.Join(ts.crashesDir, "crashes")
	entries, err := os.ReadDir(crashesSubdir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != N {
		t.Errorf("crashes: %d entries, want %d",
			len(entries), N)
	}

	seenHashes := make(map[string]struct{})
	for _, e := range entries {
		dir := filepath.Join(crashesSubdir, e.Name())
		for _, f := range []string{
			"input.bin", "meta.json",
		} {
			if _, err := os.Stat(
				filepath.Join(dir, f)); err != nil {
				t.Errorf("missing %s in %s: %v",
					f, e.Name(), err)
			}
		}

		metaBytes, err := os.ReadFile(
			filepath.Join(dir, "meta.json"))
		if err != nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(metaBytes, &m); err != nil {
			continue
		}
		if h, ok := m["input_sha256"].(string); ok {
			seenHashes[h] = struct{}{}
		}
	}
	if len(seenHashes) != N {
		t.Errorf("distinct hashes: %d, want %d "+
			"(3 different inputs)",
			len(seenHashes), N)
	}
}

// TestIntegrationCleanShutdown: ok_exit target, 5 runs,
// then ShutdownRequest. Verify exec-server exits cleanly
// (wait returns nil error, exit code 0). Does not use
// newTestSession because it needs direct control over
// cmd.Wait to assert the exit code.
func TestIntegrationCleanShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	binPath := buildExecServer(t)
	fixturePath := buildFixture(t, "ok_exit")

	fds, err := syscall.Socketpair(
		syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "ipc-parent")
	childFile := os.NewFile(uintptr(fds[1]), "ipc-child")

	netConn, err := net.FileConn(parentFile)
	if err != nil {
		_ = childFile.Close()
		t.Fatalf("net.FileConn: %v", err)
	}
	_ = parentFile.Close()

	cmd := exec.Command(binPath,
		"-target", fixturePath,
		"-workers", "1",
		"-run-timeout-ms", "5000",
	)
	cmd.ExtraFiles = []*os.File{childFile}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = childFile.Close()

	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		_ = netConn.Close()
	}()

	ipcConn := ipc.NewConn(netConn)
	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	sess, err := ipc.Dial(ctx, ipcConn, ipc.ClientConfig{
		RunTimeoutMs:     5000,
		ExpectedChannels: 0,
	})
	if err != nil {
		t.Fatalf("Dial: %v\nstderr: %s",
			err, stderr.String())
	}

	for i := 0; i < 5; i++ {
		if _, err := sess.Run(ctx,
			[]byte(fmt.Sprintf("pre_shutdown_%d", i))); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}

	if err := sess.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Wait: %v\nstderr: %s",
				err, stderr.String())
		}
		if cmd.ProcessState.ExitCode() != 0 {
			t.Errorf("exit code = %d, want 0",
				cmd.ProcessState.ExitCode())
		}
	case <-time.After(5 * time.Second):
		t.Errorf("exec-server did not exit within 5s " +
			"after Shutdown")
		_ = cmd.Process.Kill()
		<-done
	}
}
