package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/ipc"
	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

func TestVersionConstant(t *testing.T) {
	if version != "0.0.0" {
		t.Fatalf("unexpected version: %q", version)
	}
}

func TestRunVersionFlagExitsZero(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-version"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "exec-server v0.0.0") {
		t.Errorf("stdout missing version banner: %q",
			out.String())
	}
}

// TestRunMissingTargetFails: running without -target should
// exit 2 with a clear error.
func TestRunMissingTargetFails(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run(nil, &out, &errBuf)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if !strings.Contains(errBuf.String(), "-target is required") {
		t.Errorf("stderr missing target-required message: %q",
			errBuf.String())
	}
}

// TestExecServerBinaryMissingIPCFdFails: spawns the actual
// exec-server binary without an IPC socket at fd 3 and
// asserts the binary exits 2 with a canonical error
// message. This is a subprocess test (not in-process)
// because the in-process test binary already owns fd 3
// (testlog), so wrapping it via os.NewFile and then
// closing would break the test harness.
func TestExecServerBinaryMissingIPCFdFails(t *testing.T) {
	binPath := buildExecServer(t)

	cmd := exec.Command(binPath, "-target", "/bin/cat")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	// Expect non-zero exit.
	exitErr := &exec.ExitError{}
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("exit code = %d, want 2",
			exitErr.ExitCode())
	}

	// Expect canonical stderr message.
	es := stderr.String()
	if !strings.Contains(es, "internal subprocess") &&
		!strings.Contains(es, "invalid IPC socket") {
		t.Errorf("stderr missing fd-check message: %q", es)
	}
}

func TestRunReportsMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run(
		[]string{"-config", "/no/such/path.yaml",
			"-target", "/bin/cat"},
		&out, &errBuf,
	)
	if code == 0 {
		t.Fatal("expected non-zero exit for missing config")
	}
	if !strings.Contains(errBuf.String(), "fatal:") {
		t.Errorf("stderr missing fatal prefix: %q",
			errBuf.String())
	}
}

// TestExecServerIntegration: full end-to-end flow.
//
// The test plays the role of the fuzzer core (per ADR 0012):
//   - Build the exec-server binary in a tmpdir.
//   - Create a socketpair.
//   - Spawn exec-server with one end as ExtraFiles[0] (fd 3).
//   - On the other end: ipc.Dial (handshake) + several Run
//     calls + Shutdown.
//   - Assert subprocess exits cleanly.
func TestExecServerIntegration(t *testing.T) {
	// 1. Build exec-server binary in tmpdir.
	binPath := buildExecServer(t)

	// 2. Create connected socketpair.
	fds, err := syscall.Socketpair(
		syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// fds[0]: parent keeps. fds[1]: child inherits.
	parentFile := os.NewFile(
		uintptr(fds[0]), "ipc-parent")
	childFile := os.NewFile(
		uintptr(fds[1]), "ipc-child")
	t.Cleanup(func() {
		_ = parentFile.Close()
		// childFile closed after cmd.Start below.
	})

	// 3. Wrap parent side as net.Conn for ipc.
	netConn, err := net.FileConn(parentFile)
	if err != nil {
		_ = childFile.Close()
		t.Fatalf("net.FileConn parent: %v", err)
	}
	t.Cleanup(func() { _ = netConn.Close() })

	// 4. Spawn exec-server.
	cmd := exec.Command(binPath,
		"-target", "/bin/cat",
		"-workers", "2",
		"-run-timeout-ms", "2000",
	)
	cmd.ExtraFiles = []*os.File{childFile}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = childFile.Close()
		t.Fatalf("cmd.Start: %v", err)
	}
	// Child has the fd now; parent does not need childFile.
	_ = childFile.Close()

	t.Cleanup(func() {
		// Ensure process doesn't leak on test failure.
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("exec-server stderr:\n%s", stderr.String())
		}
	})

	// 5. Client handshake + runs.
	ipcConn := ipc.NewConn(netConn)
	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	sess, err := ipc.Dial(ctx, ipcConn, ipc.ClientConfig{
		RunTimeoutMs:     2000,
		ExpectedChannels: 0,
	})
	if err != nil {
		t.Fatalf("ipc.Dial: %v", err)
	}

	for i := 0; i < 3; i++ {
		resp, err := sess.Run(ctx, []byte("payload"))
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		if resp.Status !=
			ipcv1.ExecStatus_EXEC_STATUS_OK {
			t.Errorf("Run %d: status = %v, want OK",
				i, resp.Status)
		}
		if resp.RunId != uint64(i+1) {
			t.Errorf("Run %d: run_id = %d, want %d",
				i, resp.RunId, i+1)
		}
	}

	// 6. Clean shutdown.
	if err := sess.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// 7. Wait for subprocess exit.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("exec-server wait: %v\nstderr:\n%s",
				err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec-server did not exit within 5s")
	}
}

// buildExecServer builds the exec-server binary in t.TempDir
// and returns its path. Registered with t.Cleanup for
// automatic removal.
func buildExecServer(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "exec-server")
	cmd := exec.Command(
		"go", "build",
		"-o", binPath,
		".",
	)
	// Build from cmd/exec-server directory (test runs there).
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build exec-server: %v\n%s", err, out)
	}
	return binPath
}

// TestRunRejectsRelativeCovLibrary: -cov-library with a
// relative path fails fast with a clear message.
func TestRunRejectsRelativeCovLibrary(t *testing.T) {
	var out, errBuf bytes.Buffer
	rc := run(
		[]string{
			"-target", "/bin/true",
			"-cov-library", "relative/path.so",
		},
		&out, &errBuf)
	if rc == 0 {
		t.Errorf("expected non-zero exit, got 0")
	}
	if !strings.Contains(errBuf.String(), "absolute path") {
		t.Errorf("stderr = %q, want 'absolute path' phrase",
			errBuf.String())
	}
}

// TestRunRejectsMissingCovLibrary: -cov-library pointing to
// a non-existent file fails fast at coverage init.
func TestRunRejectsMissingCovLibrary(t *testing.T) {
	var out, errBuf bytes.Buffer
	rc := run(
		[]string{
			"-target", "/bin/true",
			"-cov-library", "/nonexistent/path/lib.so",
		},
		&out, &errBuf)
	if rc == 0 {
		t.Errorf("expected non-zero exit, got 0")
	}
	if !strings.Contains(errBuf.String(), "coverage init") {
		t.Errorf("stderr = %q, want 'coverage init' phrase",
			errBuf.String())
	}
}
