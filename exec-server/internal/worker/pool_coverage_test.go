//go:build linux && amd64

package worker_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/coverage"
	"mlfuzzz3/exec-server/internal/worker"
)

// resolveRepoRoot: pool_coverage_test.go is at
// exec-server/internal/worker/, ..×3 = repo root.
func resolveRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..")
}

func resolveBuildDir(t *testing.T, repoRoot string) string {
	t.Helper()
	buildDir := os.Getenv("BUILD_DIR")
	if buildDir == "" {
		buildDir = "build"
	}
	return filepath.Join(repoRoot, buildDir)
}

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
		t.Skipf("build dir %q not found: %v", buildDir, err)
	}
	cmd := exec.Command("cmake", "--build", buildDir,
		"--target", "mlfuzzz3_cov")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("cmake build mlfuzzz3_cov failed: %v\n%s",
			err, stderr.String())
	}
	if _, err := os.Stat(libPath); err != nil {
		t.Skipf("library not at %q: %v", libPath, err)
	}
	return libPath
}

func ensureStdinTarget(t *testing.T) string {
	t.Helper()
	repoRoot := resolveRepoRoot(t)
	buildDir := resolveBuildDir(t, repoRoot)
	targetPath := filepath.Join(buildDir,
		"tests", "fixtures", "cov_stdin", "cov_stdin_target")

	if _, err := os.Stat(targetPath); err == nil {
		return targetPath
	}
	if _, err := os.Stat(buildDir); err != nil {
		t.Skipf("build dir %q not found: %v", buildDir, err)
	}
	cmd := exec.Command("cmake", "--build", buildDir,
		"--target", "cov_stdin_build")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf(
			"cmake build cov_stdin_build failed "+
				"(toolchain may lack clang or "+
				"-fpass-plugin support): "+
				"%v\n%s",
			err, stderr.String())
	}
	if _, err := os.Stat(targetPath); err != nil {
		t.Skipf("target not at %q: %v", targetPath, err)
	}
	return targetPath
}

func countNonZero(b []byte) int {
	n := 0
	for _, v := range b {
		if v != 0 {
			n++
		}
	}
	return n
}

// TestPoolExecuteWithCoverage validates the end-to-end
// pool path with coverage instrumentation: pool spawns
// target with LD_PRELOAD + ExtraFiles + MLFUZZZ3_COV_FD,
// bitmap accumulates non-zero edges, Reset is performed
// pool-internally between runs, differential inputs
// produce different bitmaps. Verified through
// result.Coverage (channel index + hits) and direct
// bitmap inspection between Runs (channel released back
// to set after each Run).
func TestPoolExecuteWithCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage test skipped in short mode")
	}

	libPath := ensureLibrary(t)
	targetPath := ensureStdinTarget(t)

	cs, err := coverage.NewChannelSet(libPath, 1)
	if err != nil {
		t.Fatalf("coverage.NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	cfg := worker.Config{
		TargetPath: targetPath,
		Workers:    1,
		RunTimeout: 5 * time.Second,
		Coverage: &worker.CoverageConfig{
			LibraryPath: libPath,
			Channels:    cs,
		},
	}
	pool, err := worker.NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	result1, err := pool.Execute(ctx, []byte("A"))
	if err != nil {
		t.Fatalf("Execute 1: %v", err)
	}
	if result1.ExitCode != 0 {
		t.Errorf("Run 1 exit = %d, want 0", result1.ExitCode)
	}
	if result1.Coverage == nil {
		t.Fatal("Run 1 Coverage = nil; expected populated")
	}
	if result1.Coverage.ChannelIndex != 0 {
		t.Errorf("Run 1 ChannelIndex = %d, want 0",
			result1.Coverage.ChannelIndex)
	}
	if result1.Coverage.Hits == 0 {
		t.Fatal("Run 1 Hits = 0; coverage not recorded")
	}
	// Channel released back to set; safe to Read directly.
	bitmap1, err := cs.Channels()[0].Read()
	if err != nil {
		t.Fatalf("Read 1: %v", err)
	}
	if countNonZero(bitmap1) != result1.Coverage.Hits {
		t.Errorf("bitmap Hits = %d, result.Coverage.Hits = %d",
			countNonZero(bitmap1), result1.Coverage.Hits)
	}
	t.Logf("Run 1 (input A): %d edges hit",
		result1.Coverage.Hits)

	result2, err := pool.Execute(ctx, []byte("B"))
	if err != nil {
		t.Fatalf("Execute 2: %v", err)
	}
	if result2.ExitCode != 0 {
		t.Errorf("Run 2 exit = %d, want 0", result2.ExitCode)
	}
	if result2.Coverage == nil {
		t.Fatal("Run 2 Coverage = nil; expected populated")
	}
	if result2.Coverage.Hits == 0 {
		t.Fatal("Run 2 Hits = 0")
	}
	bitmap2, err := cs.Channels()[0].Read()
	if err != nil {
		t.Fatalf("Read 2: %v", err)
	}
	t.Logf("Run 2 (input B): %d edges hit",
		result2.Coverage.Hits)

	if bytes.Equal(bitmap1, bitmap2) {
		t.Error(
			"bitmaps identical for inputs A and B; " +
				"differential coverage not working")
	}
}

// TestPoolExecuteMultiWorkerCoverage validates the
// multi-worker coverage path (ADR 0019 Task 8c). 4 workers
// × 8 concurrent Runs over 2 distinct inputs ("A"/"B").
// Verifies all results carry non-nil Coverage with valid
// ChannelIndex in [0, 4) and non-zero Hits, and that the
// pool's Acquire/Release semantics avoid data corruption
// across concurrent Runs.
func TestPoolExecuteMultiWorkerCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage test skipped in short mode")
	}

	libPath := ensureLibrary(t)
	targetPath := ensureStdinTarget(t)

	const workers = 4
	cs, err := coverage.NewChannelSet(libPath, workers)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	cfg := worker.Config{
		TargetPath: targetPath,
		Workers:    workers,
		RunTimeout: 5 * time.Second,
		Coverage: &worker.CoverageConfig{
			LibraryPath: libPath,
			Channels:    cs,
		},
	}
	pool, err := worker.NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	const runs = 8
	inputs := []string{
		"A", "B", "A", "B", "A", "B", "A", "B",
	}
	var wg sync.WaitGroup
	results := make([]*worker.Result, runs)
	errs := make([]error, runs)

	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = pool.Execute(
				ctx, []byte(inputs[i]))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Run %d: %v", i, err)
		}
	}

	for i, r := range results {
		if r == nil {
			t.Errorf("Run %d: result = nil", i)
			continue
		}
		if r.Coverage == nil {
			t.Errorf("Run %d: Coverage = nil", i)
			continue
		}
		if r.Coverage.ChannelIndex < 0 ||
			r.Coverage.ChannelIndex >= workers {
			t.Errorf("Run %d: ChannelIndex = %d, want [0, %d)",
				i, r.Coverage.ChannelIndex, workers)
		}
		if r.Coverage.Hits == 0 {
			t.Errorf("Run %d: Hits = 0", i)
		}
		if r.ExitCode != 0 {
			t.Errorf("Run %d: ExitCode = %d, want 0",
				i, r.ExitCode)
		}
	}

	t.Logf("8 runs across 4 channels completed; all "+
		"non-nil Coverage with valid ChannelIndex in [0, %d)",
		workers)
}

// TestPoolExecuteCoverageNewEdges validates the end-to-end
// new-edge tracking semantics from ADR 0021 Task 8d under a
// multi-worker pool: Run "A" against a freshly-created
// Bucketizer must report new_edges > 0; an immediate repeat
// of Run "A" must report new_edges == 0 (monotonic seen-map,
// every bucket already attributed); Run "B" must report
// new_edges > 0 again because different input traverses a
// different bucket path. Verifies the Bucketizer instance is
// shared correctly across workers — a per-worker map would
// re-trigger new edges on the second "A".
func TestPoolExecuteCoverageNewEdges(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage test skipped in short mode")
	}

	libPath := ensureLibrary(t)
	targetPath := ensureStdinTarget(t)

	const workers = 4
	cs, err := coverage.NewChannelSet(libPath, workers)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	bkt := coverage.NewBucketizer()

	cfg := worker.Config{
		TargetPath: targetPath,
		Workers:    workers,
		RunTimeout: 5 * time.Second,
		Coverage: &worker.CoverageConfig{
			LibraryPath: libPath,
			Channels:    cs,
			Bucketizer:  bkt,
		},
	}
	pool, err := worker.NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	runA1, err := pool.Execute(ctx, []byte("A"))
	if err != nil {
		t.Fatalf("Execute A first: %v", err)
	}
	if runA1.Coverage == nil {
		t.Fatal("Run A1: Coverage = nil")
	}
	if runA1.Coverage.NewEdges == 0 {
		t.Fatalf("Run A1: NewEdges = 0; expected > 0 on "+
			"first observation (hits=%d)",
			runA1.Coverage.Hits)
	}
	t.Logf("Run A1: hits=%d new=%d",
		runA1.Coverage.Hits, runA1.Coverage.NewEdges)

	// Repeat input "A" — every bucketized bit was already
	// merged into the seen-map; new_edges must be zero.
	runA2, err := pool.Execute(ctx, []byte("A"))
	if err != nil {
		t.Fatalf("Execute A second: %v", err)
	}
	if runA2.Coverage == nil {
		t.Fatal("Run A2: Coverage = nil")
	}
	if runA2.Coverage.NewEdges != 0 {
		t.Errorf("Run A2: NewEdges = %d, want 0 "+
			"(monotonic seen-map violated)",
			runA2.Coverage.NewEdges)
	}
	t.Logf("Run A2: hits=%d new=%d",
		runA2.Coverage.Hits, runA2.Coverage.NewEdges)

	// Differential input "B" — fixture takes a different
	// branch (validated by TestPoolExecuteWithCoverage
	// where bitmap1 != bitmap2 for A/B). Some buckets are
	// new relative to whatever "A" populated.
	runB, err := pool.Execute(ctx, []byte("B"))
	if err != nil {
		t.Fatalf("Execute B: %v", err)
	}
	if runB.Coverage == nil {
		t.Fatal("Run B: Coverage = nil")
	}
	if runB.Coverage.NewEdges == 0 {
		t.Errorf("Run B: NewEdges = 0; expected > 0 on "+
			"differential path (hits=%d)",
			runB.Coverage.Hits)
	}
	t.Logf("Run B: hits=%d new=%d",
		runB.Coverage.Hits, runB.Coverage.NewEdges)
}

// TestPoolExecuteWithoutCoverage verifies that a pool
// configured without Coverage runs unchanged.
func TestPoolExecuteWithoutCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}

	targetPath := ensureStdinTarget(t)

	cfg := worker.Config{
		TargetPath: targetPath,
		Workers:    1,
		RunTimeout: 5 * time.Second,
	}
	pool, err := worker.NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	result, err := pool.Execute(ctx, []byte("A"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", result.ExitCode)
	}
}
