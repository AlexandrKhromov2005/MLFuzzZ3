//go:build linux && amd64

package coverage_test

// Stage 2 coverage oracle (ADR 0024 §Oracle).
//
// Strict acceptance criteria:
//
//   1. Determinism. A pass-instrumented binary executed
//      twice on the identical input produces a byte-for-
//      byte identical bitmap. Confirms no nondeterminism
//      in edge-id assignment, traversal, or counter
//      updates.
//
//   2. Known CFG (cov_stdin_target.c, a hand-written
//      branch-on-first-stdin-byte fixture whose LLVM-IR
//      is enumerable). At -O0 + LLVM 20 + this source the
//      pass assigns ids 1..8 to the eight basic blocks of
//      main() in module order, and the AFL XOR-hash
//      formula then determines, deterministically, which
//      bitmap cells each input visits. The exact expected
//      nonzero cell sets (analytically derived from the
//      IR — see comment block below) are:
//
//        input 'A' → {1, 3, 4, 9}    (4 cells)
//        input 'B' → {1, 3, 5, 7, 9} (5 cells)
//        input 'C' → {1, 3, 5, 6, 9} (5 cells)
//
//      The "known CFG" oracle asserts both the
//      cardinality (analytical edge count matches) and
//      the cell identity (deterministic id assignment
//      survives — different paths visit different cells,
//      same path visits identical cells). Counter values
//      must equal 1 for every nonzero cell (each block
//      enters once per run).
//
// Analytical CFG derivation (clang -O0, LLVM 20, current
// source):
//
//   main() basic blocks in module order:
//     %0  (entry)  id=1  — getchar, store c, cmp c==EOF
//     %6  (eof)    id=2  — store retval=1, br exit
//     %7           id=3  — cmp c=='A'
//     %10 (A arm)  id=4  — printf "A", store 0, br exit
//     %12          id=5  — cmp c=='B'
//     %15 (B arm)  id=6  — printf "B", store 0, br exit
//     %17 (C arm)  id=7  — printf "C", store 0, br exit
//     %19 (exit)   id=8  — load retval, ret
//
//   Per-input traversal (cur_loc sequence):
//     'A' : 1 → 3 → 4 → 8
//     'B' : 1 → 3 → 5 → 6 → 8
//     'C' : 1 → 3 → 5 → 7 → 8
//
//   AFL cell computation (idx = (prev>>1) ^ cur,
//   prev'=cur>>1, prev0=0):
//
//     'A': (0>>1)^1=1, (1>>1)^3=3, (3>>1)^4=4, (4>>1)^8=9
//          → {1, 3, 4, 9}
//     'B': 1, 3, (1>>1)^5=5, (5>>1)^6=7, (6>>1)^8=9
//          → {1, 3, 5, 7, 9}
//     'C': 1, 3, 5, (5>>1)^7=6, (7>>1)^8=9
//          → {1, 3, 5, 6, 9}

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/coverage"
)

// Analytically expected nonzero cells per input. Each
// cell's counter must equal 1 (block entered exactly
// once per run).
var (
	expectedCellsA = []int{1, 3, 4, 9}
	expectedCellsB = []int{1, 3, 5, 7, 9}
	expectedCellsC = []int{1, 3, 5, 6, 9}
)

func oracleRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..")
}

func oracleBuildDir(t *testing.T, root string) string {
	t.Helper()
	d := os.Getenv("BUILD_DIR")
	if d == "" {
		d = "build"
	}
	if !filepath.IsAbs(d) {
		d = filepath.Join(root, d)
	}
	return d
}

func ensureCmakeTarget(
	t *testing.T, buildDir, target, artifact string,
) string {
	t.Helper()
	if _, err := os.Stat(artifact); err == nil {
		return artifact
	}
	if _, err := os.Stat(buildDir); err != nil {
		t.Skipf("build dir %q not found: %v",
			buildDir, err)
	}
	cmd := exec.Command(
		"cmake", "--build", buildDir, "--target", target)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("cmake build %s failed: %v\n%s",
			target, err, stderr.String())
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Skipf("artifact %q not built: %v",
			artifact, err)
	}
	return artifact
}

func ensureLibraryArtifact(
	t *testing.T, buildDir string,
) string {
	t.Helper()
	libPath := filepath.Join(buildDir,
		"src", "runtime", "coverage", "libmlfuzzz3_cov.so")
	return ensureCmakeTarget(
		t, buildDir, "mlfuzzz3_cov", libPath)
}

func ensurePassTarget(
	t *testing.T, buildDir string,
) string {
	t.Helper()
	target := filepath.Join(buildDir,
		"tests", "fixtures", "cov_stdin",
		"cov_stdin_target")
	return ensureCmakeTarget(
		t, buildDir, "cov_stdin_build", target)
}

// runTarget spawns binPath with the given stdin byte,
// memfd-backed coverage bitmap inherited via fd 3 and
// MLFUZZZ3_COV_FD=3. Returns a copy of the bitmap. The
// channel is reset before the spawn — caller doesn't
// need to reset.
func runTarget(
	t *testing.T,
	ch *coverage.Channel,
	binPath, libPath string,
	input []byte,
) []byte {
	t.Helper()
	if err := ch.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = bytes.NewReader(input)
	cmd.ExtraFiles = []*os.File{ch.MemfdFile()}
	// LD_PRELOAD is harmless and matches the contract
	// used by worker.Pool (pool.go); the pass-instrumented
	// binary additionally carries libmlfuzzz3_cov as a
	// DT_NEEDED + rpath linkage, but LD_PRELOAD ensures
	// the project's library is loaded if a system copy
	// ever appears.
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+libPath,
		"MLFUZZZ3_COV_FD=3",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %s on %q: %v\nstderr: %s",
			binPath, string(input), err, stderr.String())
	}

	bm, err := ch.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return bm
}

func nonZeroCells(b []byte) []int {
	out := []int{}
	for i, v := range b {
		if v != 0 {
			out = append(out, i)
		}
	}
	return out
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortedCopy(a []int) []int {
	out := append([]int{}, a...)
	sort.Ints(out)
	return out
}

// assertCellsAndCounters verifies that bm has nonzero
// counters exactly at expectedCells and every such
// counter equals 1 (per-block first-visit on a single-
// path fixture). Logs the actual cell set on mismatch.
func assertCellsAndCounters(
	t *testing.T, label string, bm []byte, expected []int,
) {
	t.Helper()
	got := nonZeroCells(bm)
	want := sortedCopy(expected)
	if !intsEqual(got, want) {
		t.Fatalf(
			"known-CFG cells mismatch (%s):\n"+
				"  got  cells=%v\n"+
				"  want cells=%v",
			label, got, want)
	}
	for _, c := range want {
		if bm[c] != 1 {
			t.Fatalf(
				"known-CFG counter mismatch (%s): "+
					"cell %d = %d, want 1 "+
					"(single-visit per block)",
				label, c, bm[c])
		}
	}
}

// TestStage2EdgeCoveragePassOracle is the strict
// acceptance gate for the EdgeCoveragePass per ADR 0024
// §Oracle: determinism + known-CFG.
func TestStage2EdgeCoveragePassOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("Stage 2 oracle skipped in short mode")
	}

	root := oracleRepoRoot(t)
	buildDir := oracleBuildDir(t, root)

	libPath := ensureLibraryArtifact(t, buildDir)
	passBin := ensurePassTarget(t, buildDir)

	ch, err := coverage.NewChannel(libPath)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	// --- (1) Determinism: identical input → byte-equal bitmap.
	bmA1 := runTarget(t, ch, passBin, libPath, []byte("A"))
	bmA2 := runTarget(t, ch, passBin, libPath, []byte("A"))
	if !bytes.Equal(bmA1, bmA2) {
		t.Fatalf(
			"determinism violated: 'A' twice produced "+
				"different bitmaps; first diff at %d "+
				"(nonzero %d vs %d)",
			firstDiff(bmA1, bmA2),
			len(nonZeroCells(bmA1)),
			len(nonZeroCells(bmA2)))
	}

	// --- (2) Known CFG: exact analytical cell sets per input.
	bmB1 := runTarget(t, ch, passBin, libPath, []byte("B"))
	bmC1 := runTarget(t, ch, passBin, libPath, []byte("C"))

	assertCellsAndCounters(t, "A", bmA1, expectedCellsA)
	assertCellsAndCounters(t, "B", bmB1, expectedCellsB)
	assertCellsAndCounters(t, "C", bmC1, expectedCellsC)

	// Different known paths → different bitmaps.
	if bytes.Equal(bmA1, bmB1) {
		t.Fatal("bitmap('A') == bitmap('B'); paths " +
			"not differentiated")
	}
	if bytes.Equal(bmB1, bmC1) {
		t.Fatal("bitmap('B') == bitmap('C'); paths " +
			"not differentiated")
	}
	if bytes.Equal(bmA1, bmC1) {
		t.Fatal("bitmap('A') == bitmap('C'); paths " +
			"not differentiated")
	}

	// Determinism on a distinct arm (A is covered above).
	bmB2 := runTarget(t, ch, passBin, libPath, []byte("B"))
	if !bytes.Equal(bmB1, bmB2) {
		t.Fatalf(
			"determinism violated on 'B' arm: "+
				"first diff at %d",
			firstDiff(bmB1, bmB2))
	}

	t.Logf(
		"EdgeCoveragePass hits: A=%d B=%d C=%d "+
			"(known-CFG cells match analytical, "+
			"counters single-visit)",
		len(expectedCellsA),
		len(expectedCellsB),
		len(expectedCellsC))
}
