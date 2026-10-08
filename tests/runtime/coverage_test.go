//go:build linux && amd64

package runtime_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	// covMapSize matches COV_MAP_SIZE в
	// src/runtime/coverage/mlfuzzz3_cov.c (64 KiB).
	covMapSize = 1 << 16

	// sysMemfdCreate — memfd_create(2) syscall number
	// на linux/amd64. Duplicate from
	// exec-server/internal/ipc per Stage 1 isolation
	// (no exec-server dependency in tests/runtime).
	sysMemfdCreate = 319
)

// resolveRepoRoot resolves repo root from this test
// file's location: tests/runtime/coverage_test.go →
// .. × 2.
func resolveRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(
		filepath.Dir(thisFile), "..", "..")
}

// resolveBuildDir returns absolute build dir path,
// honouring BUILD_DIR env override.
func resolveBuildDir(t *testing.T, repoRoot string) string {
	t.Helper()
	buildDir := os.Getenv("BUILD_DIR")
	if buildDir == "" {
		buildDir = "build"
	}
	return filepath.Join(repoRoot, buildDir)
}

// ensureLibrary returns absolute path to libmlfuzzz3_cov.so,
// building via cmake if needed. t.Skip's if cmake/build
// unavailable.
func ensureLibrary(t *testing.T) string {
	t.Helper()
	repoRoot := resolveRepoRoot(t)
	buildDir := resolveBuildDir(t, repoRoot)

	libPath := filepath.Join(buildDir,
		"src", "runtime", "coverage", "libmlfuzzz3_cov.so")

	if _, err := os.Stat(libPath); err == nil {
		return libPath
	}

	if _, err := os.Stat(buildDir); err != nil {
		t.Skipf(
			"build dir %q not found; run cmake first: %v",
			buildDir, err)
	}

	cmd := exec.Command("cmake", "--build", buildDir,
		"--target", "mlfuzzz3_cov")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf(
			"cmake build mlfuzzz3_cov failed: %v\n"+
				"stderr: %s",
			err, stderr.String())
	}

	if _, err := os.Stat(libPath); err != nil {
		t.Skipf("library not at %q после build: %v",
			libPath, err)
	}
	return libPath
}

// ensureTarget returns absolute path to cov_simple_target,
// building via cmake if needed. t.Skip's if cmake/build
// unavailable or compiler doesn't support sanitizer flag.
func ensureTarget(t *testing.T) string {
	t.Helper()
	repoRoot := resolveRepoRoot(t)
	buildDir := resolveBuildDir(t, repoRoot)

	targetPath := filepath.Join(buildDir,
		"tests", "fixtures", "cov_simple", "cov_simple_target")

	if _, err := os.Stat(targetPath); err == nil {
		return targetPath
	}

	if _, err := os.Stat(buildDir); err != nil {
		t.Skipf("build dir %q not found: %v",
			buildDir, err)
	}

	cmd := exec.Command("cmake", "--build", buildDir,
		"--target", "cov_simple_build")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf(
			"cmake build cov_simple_build failed "+
				"(toolchain may lack clang or "+
				"-fpass-plugin support): "+
				"%v\nstderr: %s",
			err, stderr.String())
	}

	if _, err := os.Stat(targetPath); err != nil {
		t.Skipf("target not at %q после build: %v",
			targetPath, err)
	}
	return targetPath
}

// createCovMemfd creates a 64 KiB memfd, sized для
// coverage map. Returns fd; caller closes.
func createCovMemfd(t *testing.T) int {
	t.Helper()
	namePtr, err := syscall.BytePtrFromString("cov-test")
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
	if err := syscall.Ftruncate(int(fd), covMapSize); err != nil {
		_ = syscall.Close(int(fd))
		t.Fatalf("ftruncate memfd: %v", err)
	}
	return int(fd)
}

// readBitmap reads the contents of a memfd as raw bytes.
func readBitmap(t *testing.T, fd int) []byte {
	t.Helper()
	data := make([]byte, covMapSize)
	if _, err := syscall.Pread(fd, data, 0); err != nil {
		t.Fatalf("pread cov memfd: %v", err)
	}
	return data
}

// countNonZero returns the number of non-zero bytes
// в bitmap.
func countNonZero(b []byte) int {
	n := 0
	for _, v := range b {
		if v != 0 {
			n++
		}
	}
	return n
}

// runTargetWithCoverage spawns target with LD_PRELOAD
// и MLFUZZZ3_COV_FD set; child fd 3 = peer fd of memfd
// via ExtraFiles. Returns target's combined output.
func runTargetWithCoverage(
	t *testing.T,
	targetPath, libPath, input string,
	memfd int,
) []byte {
	t.Helper()

	memfdFile := os.NewFile(uintptr(memfd), "cov-memfd")
	if memfdFile == nil {
		t.Fatalf("os.NewFile failed for memfd %d", memfd)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, targetPath, input)
	cmd.ExtraFiles = []*os.File{memfdFile}
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+libPath,
		"MLFUZZZ3_COV_FD=3")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf(
			"target run failed: %v\n"+
				"stdout: %s\nstderr: %s",
			err, stdout.String(), stderr.String())
	}

	return stdout.Bytes()
}

// TestCoverageBasicInstrumentation: target compiled with
// sanitizer-coverage runs with library loaded, bitmap
// accumulates non-zero bytes for traversed edges.
func TestCoverageBasicInstrumentation(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage test skipped in short mode")
	}

	libPath := ensureLibrary(t)
	targetPath := ensureTarget(t)

	// Verify target dynamically linked (LD_PRELOAD
	// requires this per ADR 0017 risk).
	lddCmd := exec.Command("ldd", targetPath)
	out, err := lddCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldd %s failed: %v\n%s",
			targetPath, err, out)
	}
	if bytes.Contains(out, []byte("not a dynamic executable")) {
		t.Fatalf("target is not dynamically linked:\n%s", out)
	}

	memfd := createCovMemfd(t)
	defer syscall.Close(memfd)

	stdout := runTargetWithCoverage(t,
		targetPath, libPath, "A", memfd)

	if !bytes.Contains(stdout, []byte("path A")) {
		t.Errorf("target stdout = %q, want \"path A\"",
			stdout)
	}

	bitmap := readBitmap(t, memfd)
	hits := countNonZero(bitmap)

	if hits == 0 {
		t.Fatalf("bitmap empty — coverage не recorded")
	}
	if hits > 1000 {
		t.Errorf(
			"suspicious edge count %d for trivial target",
			hits)
	}

	t.Logf("recorded %d non-zero edges for input A", hits)
}

// TestCoverageDifferentialPaths: different inputs hit
// different edges. "A" vs "B" must produce distinct
// bitmaps (subset/superset relationship not enforced —
// just non-equality).
func TestCoverageDifferentialPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage test skipped in short mode")
	}

	libPath := ensureLibrary(t)
	targetPath := ensureTarget(t)

	memfdA := createCovMemfd(t)
	defer syscall.Close(memfdA)
	runTargetWithCoverage(t, targetPath, libPath, "A", memfdA)
	bitmapA := readBitmap(t, memfdA)

	memfdB := createCovMemfd(t)
	defer syscall.Close(memfdB)
	runTargetWithCoverage(t, targetPath, libPath, "B", memfdB)
	bitmapB := readBitmap(t, memfdB)

	if bytes.Equal(bitmapA, bitmapB) {
		t.Errorf(
			"bitmaps identical for inputs A and B — " +
				"differential coverage не working")
	}

	hitsA := countNonZero(bitmapA)
	hitsB := countNonZero(bitmapB)
	t.Logf("A: %d edges, B: %d edges", hitsA, hitsB)
}

// Stage 1 had a "library inert without env var" target-
// level test here. Stage 2 pass-instrumented binaries
// dereference __mlfuzzz3_cov_map unconditionally (no
// NULL check in inline IR, per ADR 0024 §Runtime), so
// running the target without MLFUZZZ3_COV_FD is invalid
// by design. Library-level inertness (dlopen +
// constructor without env var) is verified separately
// by tests/runtime/coverage/test_mlfuzzz3_cov.cpp
// (MlFuzzz3CovTest.LibraryLoadable).
