//go:build linux && amd64

package ipc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// crossLangPayload is the known content the Go driver
// writes into a memfd, sends to the C++ helper, and
// expects to receive back via the helper's stdout.
const crossLangPayload = "scm-rights-crosslang-payload-go-to-cpp"

// resolveRepoRoot resolves the repository root from this
// test file's location. Path:
// exec-server/internal/ipc/scmrights_crosslang_test.go
// → repo root is .. × 3.
func resolveRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..")
}

// buildScmRightsHelper locates or builds the C++ helper
// binary. Returns the absolute path. Calls t.Skip if
// the helper is unavailable (no build dir, cmake fails,
// etc.) — environments without a C++ toolchain skip the
// test rather than failing.
func buildScmRightsHelper(t *testing.T) string {
	t.Helper()
	repoRoot := resolveRepoRoot(t)

	buildDir := os.Getenv("BUILD_DIR")
	if buildDir == "" {
		buildDir = "build"
	}
	absBuildDir := filepath.Join(repoRoot, buildDir)

	binPath := filepath.Join(absBuildDir,
		"tests", "cross", "scm_rights", "scm_rights_helper")

	// Try existing binary first; fast path for warmed
	// CI.
	if info, err := os.Stat(binPath); err == nil &&
		!info.IsDir() {
		return binPath
	}

	// Fallback: build the target. Requires cmake build
	// dir already configured.
	if _, err := os.Stat(absBuildDir); err != nil {
		t.Skipf(
			"scm_rights_helper: build dir %q not found; "+
				"run cmake first or unset BUILD_DIR: %v",
			absBuildDir, err)
	}

	cmd := exec.Command("cmake", "--build", absBuildDir,
		"--target", "scm_rights_helper")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf(
			"scm_rights_helper: cmake build failed "+
				"(no C++ toolchain?): %v\nstderr: %s",
			err, stderr.String())
	}

	if _, err := os.Stat(binPath); err != nil {
		t.Skipf(
			"scm_rights_helper: binary not at %q "+
				"after build: %v",
			binPath, err)
	}
	return binPath
}

// crosslangSocketpair returns a connected *net.UnixConn
// (parent side, used by Go) and an *os.File (child side,
// passed to helper as ExtraFile → fd 3).
func crosslangSocketpair(
	t *testing.T,
) (*net.UnixConn, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(
		syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}

	parentFile := os.NewFile(uintptr(fds[0]), "sp-parent")
	childFile := os.NewFile(uintptr(fds[1]), "sp-child")

	parentConn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		t.Fatalf("FileConn parent: %v", err)
	}

	uc, ok := parentConn.(*net.UnixConn)
	if !ok {
		_ = parentConn.Close()
		_ = childFile.Close()
		t.Fatalf("parent is %T, want *net.UnixConn",
			parentConn)
	}

	return uc, childFile
}

// crosslangMemfd creates a memfd and writes the given
// content. Returns the fd; caller must close.
func crosslangMemfd(
	t *testing.T, content []byte,
) int {
	t.Helper()
	namePtr, err := syscall.BytePtrFromString(
		"crosslang-memfd")
	if err != nil {
		t.Fatalf("BytePtrFromString: %v", err)
	}
	fd, _, errno := syscall.Syscall(
		sysMemfdCreate,
		uintptr(unsafe.Pointer(namePtr)),
		0, 0)
	if errno != 0 {
		t.Fatalf("memfd_create: %v", errno)
	}
	if _, err := syscall.Write(
		int(fd), content); err != nil {
		_ = syscall.Close(int(fd))
		t.Fatalf("write to memfd: %v", err)
	}
	return int(fd)
}

// TestSCMRightsCrossLanguageGoToCpp verifies wire-level
// interoperation of the SCM_RIGHTS path between the Go
// server-side and the C++ client-side. Direction matches
// production: Go sends ChannelAnnouncement+fd, C++
// receives, mmaps, returns content via stdout. The Go
// driver compares stdout with the known payload it wrote
// into the source memfd.
//
// Skip conditions: no build dir, cmake build failure
// (e.g., environment without C++ toolchain).
func TestSCMRightsCrossLanguageGoToCpp(t *testing.T) {
	if testing.Short() {
		t.Skip("crosslang test skipped in short mode")
	}

	helper := buildScmRightsHelper(t)

	parentConn, childFile := crosslangSocketpair(t)
	defer func() {
		_ = parentConn.Close()
	}()

	payload := []byte(crossLangPayload)
	memfd := crosslangMemfd(t, payload)
	defer func() { _ = syscall.Close(memfd) }()

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, helper)
	cmd.ExtraFiles = []*os.File{childFile}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		_ = childFile.Close()
		t.Fatalf("start helper: %v", err)
	}
	// Parent no longer needs the child fd; child has
	// its own copy.
	_ = childFile.Close()

	// Build envelope and send via Go SCM_RIGHTS path.
	env := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_ChannelAnnouncement{
			ChannelAnnouncement: &ipcv1.ChannelAnnouncement{
				Descriptor_: &ipcv1.ChannelAnnouncement_Edge{
					Edge: &ipcv1.EdgeCoverageDescriptor{
						ShmName:       "crosslang-test",
						Offset:        0,
						Length:        uint64(len(payload)),
						SchemaVersion: 1,
					},
				},
			},
		},
	}

	if err := WriteEnvelopeWithFD(
		parentConn, env, memfd); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		t.Fatalf("WriteEnvelopeWithFD: %v", err)
	}

	// Close parent side after sending so helper sees
	// EOF (defensive — ReadEnvelopeWithFd returns
	// before EOF, but stdout flushing on the helper
	// side benefits from socket close ordering).
	_ = parentConn.Close()

	waitErr := cmd.Wait()

	// Always log stderr for debugging; failures below
	// include it in the message.
	if stderr.Len() > 0 {
		t.Logf("helper stderr: %s", stderr.String())
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf(
			"helper timed out after 10s "+
				"(stdout=%q, stderr=%q)",
			stdout.String(), stderr.String())
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			t.Fatalf(
				"helper exited non-zero: code=%d "+
					"stderr=%q",
				exitErr.ExitCode(), stderr.String())
		}
		t.Fatalf("helper Wait: %v", waitErr)
	}

	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Errorf(
			"stdout mismatch:\n got: %q\nwant: %q",
			stdout.Bytes(), payload)
	}

	// Drain any final reads (no-op if already EOF).
	_, _ = io.ReadAll(io.LimitReader(&stdout, 1))
}
