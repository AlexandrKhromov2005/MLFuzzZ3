package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/ipc"
)

// BenchmarkE2E measures end-to-end Run throughput through a
// spawned exec-server subprocess. Binary is built once in
// benchE2ESetup and reused across b.N iterations.
func BenchmarkE2E(b *testing.B) {
	binPath := benchE2ESetup(b)

	fds, err := syscall.Socketpair(
		syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		b.Fatalf("socketpair: %v", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "ipc-parent")
	childFile := os.NewFile(uintptr(fds[1]), "ipc-child")

	netConn, err := net.FileConn(parentFile)
	if err != nil {
		_ = childFile.Close()
		b.Fatalf("net.FileConn: %v", err)
	}
	_ = parentFile.Close()

	cmd := exec.Command(binPath,
		"-target", "/bin/cat",
		"-workers", "4",
		"-run-timeout-ms", "5000",
	)
	cmd.ExtraFiles = []*os.File{childFile}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = childFile.Close()
		b.Fatalf("Start: %v", err)
	}
	_ = childFile.Close()

	defer func() {
		_ = netConn.Close()
		if cmd.Process != nil {
			_, _ = cmd.Process.Wait()
		}
	}()

	ipcConn := ipc.NewConn(netConn)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	sess, err := ipc.Dial(ctx, ipcConn,
		ipc.ClientConfig{
			RunTimeoutMs:     5000,
			ExpectedChannels: 0,
		})
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}

	input := make([]byte, 1024)
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sess.Run(ctx, input); err != nil {
			b.Fatalf("Run %d: %v", i, err)
		}
	}
	b.StopTimer()

	_ = sess.Shutdown(ctx)
}

// benchE2ESetup builds the exec-server binary once. b.TempDir
// cleans up automatically at end of benchmark.
func benchE2ESetup(b *testing.B) string {
	b.Helper()
	binPath := b.TempDir() + "/exec-server"
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("go build: %v\n%s", err, out)
	}
	return binPath
}
